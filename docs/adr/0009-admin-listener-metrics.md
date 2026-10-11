# ADR 0009: Admin listener, metrics and health checks

- **Status:** proposed, 2026-10-11
- **Context:** ROADMAP M4 (M4-06) asks for an optional HTTP admin listener
  with `/metrics`, `/healthz` and `/readyz` (optionally `/debug/pprof`), the
  metrics of §11.2, and `gosftpd healthcheck` for the distroless image's
  `HEALTHCHECK`. Decision D12 (the metrics library) was left to the owner:
  `prometheus/client_golang` (+2.6 MB), `VictoriaMetrics/metrics`
  (+0.44 MB), or none. The owner chose **none**: gosftpd writes the
  Prometheus text format itself.

## Decision

### Configuration

```toml
[metrics]
listen = ""        # empty: no HTTP listener; e.g. "127.0.0.1:9090"
pprof = false      # /debug/pprof on the same listener
```

Both are restart-only (like `server.listen`). The listener is bound at
start with the SSH listeners; failing to bind fails the start. It has no
authentication: `config validate` warns when `listen` is not a loopback
address, and more strongly when `pprof` is on there (heap dumps hold
secrets).

The server is a separate `http.Server` with `ReadHeaderTimeout` 5 s,
`ReadTimeout` 10 s, `WriteTimeout` 30 s (70 s with `pprof`, whose CPU
profile runs 30 s by default), `IdleTimeout` 60 s, `MaxHeaderBytes` 8 KiB,
GET and HEAD only, and a limit of 16 concurrent requests. It stops with the
server, after the drain.

### Endpoints

- `/healthz`: 200 `ok` while the process serves HTTP (liveness).
- `/readyz`: 200 `ready` once the SSH listeners are bound and the server
  serves (the moment of `READY=1`); 503 with the reason before that, during
  the shutdown drain (after SIGTERM), and while `audit.on_error =
  "fail-closed"` refuses connections because the audit log cannot be
  written (D20). It reads the audit state without probing it, so scrapes
  have no side effects.
- `/metrics`: the text exposition format 0.0.4 (`text/plain;
  version=0.0.4; charset=utf-8`).
- `/debug/pprof/` with `pprof = true`.
- Anything else: 404.

### Metrics

`internal/obs` holds a small registry: counters, gauges (set or computed
at scrape) and histograms, each with a fixed list of label names and label
values from closed sets that the code defines (no user names, paths,
addresses or key fingerprints, so cardinality is bounded). Output: one
`# HELP` and `# TYPE` per family, families sorted by name, series sorted by
labels, label values escaped (`\\`, `\"`, `\n`), floats in Go's shortest
form, histograms as cumulative `_bucket{le}` with `+Inf`, `_sum`,
`_count`. Updates are atomic; a scrape does not block the server.

The metrics of §11.2, defined precisely:

| Metric | Type | Labels | Counts |
|---|---|---|---|
| `gosftpd_build_info` | gauge (1) | `version`, `goversion` | |
| `gosftpd_connections_active` | gauge | | open TCP connections being served (pre- and post-login) |
| `gosftpd_connections_total` | counter | `result` | finished connections: `ok`, `error`, `idle_timeout`, `keepalive_timeout`, `revoked` (as `conn.close`), `refused` (refused before the handshake: bans and limits, as `conn.reject`), `no_version` (closed before sending an SSH version line: health checks and port scanners, which the audit log leaves out) |
| `gosftpd_auth_attempts_total` | counter | `method` (`publickey`, `password`, `other`), `result` (`success`, `failure`) | authentication requests, as x/crypto reports them (an offered public key without a signature counts); `none` requests are not counted |
| `gosftpd_sftp_requests_total` | counter | `op` (`upload`, `download`, `rename`, `mkdir`, `rmdir`, `remove`, `setstat`, `list`, `stat`), `result` (`ok`, `denied`, `error`, `aborted`) | the actions the audit log records, also when its category is off |
| `gosftpd_sftp_request_duration_seconds` | histogram | `op` (`upload`, `download`) | open to close of a transfer |
| `gosftpd_transfer_bytes_total` | counter | `direction` (`upload`, `download`) | bytes as they are written or read, not at the end, so rates show long transfers |
| `gosftpd_upload_conflicts_total` | counter | `action` (`renamed`, `overwritten`, `versioned`, `rejected`) | uploads and renames onto an existing name, by the conflict policy's outcome |
| `gosftpd_bans_active` | gauge | | sources banned now (computed at scrape) |
| `gosftpd_config_reloads_total` | counter | `result` (`ok`, `error`) | |
| `gosftpd_config_last_reload_success_timestamp_seconds` | gauge | | the start, then each successful reload |
| `gosftpd_audit_write_errors_total` | counter | | audit events that could not be written |

Duration buckets (seconds): 0.01, 0.1, 0.5, 1, 5, 15, 60, 300, 1800, 7200.

Process and runtime metrics, with client_golang's names so that existing
dashboards work: `go_info{version}`, `go_goroutines`, `go_threads`,
`go_memstats_heap_alloc_bytes`, `go_memstats_sys_bytes`,
`go_gc_cycles_total` (from `runtime/metrics`, which does not stop the
world), `process_start_time_seconds`, and on Linux
`process_cpu_seconds_total`, `process_resident_memory_bytes`,
`process_virtual_memory_bytes`, `process_open_fds`, `process_max_fds` (from
`/proc/self`). A metric that cannot be read is left out, never reported as
0.

Code updates typed handles (`obs.Metrics`), passed to the server and the
SFTP handlers; a nil `*obs.Metrics` does nothing, so tests and the library
users need nothing. There is no global registry.

`promlinter` (a client_golang linter) does not apply; instead a unit test
checks names (`gosftpd_` prefix, `_total` on counters, base units), the
format is checked with a parser in the tests, and CI runs `promtool check
metrics` against a live server in the interop job.

### `gosftpd healthcheck`

`gosftpd healthcheck [--config FILE] [--url URL] [--timeout 5s]`, exit 0
when healthy, 1 otherwise, one line on stderr saying why:

- Without `--url`: connects to the first `server.listen` address of the
  configuration found as `serve` finds it (or `GOSFTPD_LISTEN`, or `:2022`
  without a file), using `127.0.0.1` (or `::1`) for an unspecified host,
  reads at most 255 bytes until a line starting with `SSH-2.0-`, and closes
  without sending its own version. The server writes `conn.accept` only
  once a client sent its version, so the probe is not audited; it counts as
  `gosftpd_connections_total{result="no_version"}`. It works without the
  admin listener, which is off by default.
- With `--url`: `GET URL` (e.g. `http://127.0.0.1:9090/readyz`); a 2xx
  status is healthy. Redirects are not followed.

## Consequences

- No new dependency; the exposition code (a few hundred lines) is ours to
  keep correct, checked by tests and `promtool`.
- The admin listener has no TLS or authentication: bind it to loopback or a
  private network, or put it behind a proxy.
- Scrapes and health checks do not appear in the audit log.
