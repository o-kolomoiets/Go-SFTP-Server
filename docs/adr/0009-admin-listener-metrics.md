# ADR 0009: Admin listener, metrics and health checks

- **Status:** accepted, 2026-10-11; amends ADR 0005 (restart-only list)
- **Context:** ROADMAP M4 (M4-06) asks for an optional HTTP admin listener
  with `/metrics`, `/healthz` and `/readyz` (optionally `/debug/pprof`), the
  metrics of §11.2, and `gosftpd healthcheck` for the distroless image's
  `HEALTHCHECK`. Decision D12 (the metrics library) was left to the owner:
  `prometheus/client_golang` (+2.6 MB), `VictoriaMetrics/metrics`
  (+0.44 MB), or none. The owner chose **none**: gosftpd writes the
  Prometheus text format itself. Three adversarial reviews of a first draft
  (exposition format, operability and security, integration with the code),
  with experiments against promtool 3.5, Prometheus 3.5's parser, x/crypto
  and go-proxyproto, shaped the decisions below.

## Decision

### Configuration

```toml
[metrics]
listen = ""        # empty: no HTTP listener; e.g. "127.0.0.1:9090"
pprof = false      # /debug/pprof; only in binaries built with -tags pprof
```

`metrics.listen` is restart-only, like `server.listen`; it is bound at
start with the SSH listeners, and failing to bind fails the start. The
banner prints `metrics: http://ADDR` and `server.start` gets `metrics_listen`.
`metrics.pprof` is reloadable (a flag the handlers check), so a running
process can be profiled without a restart.

Release binaries do not contain pprof: `net/http/pprof` costs 0.6 MB, the
HTTP server itself 2.2 MB and the HTTP client of `healthcheck --url` 0.5 MB,
against the 10 MiB budget of §11.1 (linux/amd64 7.27 MB before, 9.96 MB
after; darwin/amd64 10.17 MB, 9.70 MiB). The webhooks of M4-07 need the same
client. `pprof = true` in a binary built without `-tags pprof` is a
configuration error that says so.

The listener has no authentication or TLS. `config validate` and `serve`
warn when `listen` is not a loopback address (an IP literal for which
`IsLoopback` holds, or `localhost`; for another host name `serve` checks the
bound address): `/metrics` reveals the exact gosftpd and Go versions, which
the SSH banner withholds, and the load; pprof reveals process internals and
lets a client stop the world or keep profilers running. A `unix:` address is
refused (not supported). In Docker the listener must bind `0.0.0.0`; publish
it as `-p 127.0.0.1:9090:9090`.

### HTTP server

A separate `http.Server`: `ReadHeaderTimeout` 5 s, `ReadTimeout` 10 s,
`WriteTimeout` 30 s (net/http/pprof extends its own deadline for profiles),
`IdleTimeout` 60 s, `MaxHeaderBytes` 8 KiB, at most 64 open connections
(further ones wait in the backlog). Routes use method patterns, so other
methods get 405 with `Allow: GET, HEAD`; unknown paths 404. `/metrics` and
pprof share a limit of 4 concurrent requests (pprof alone 2), answered at
once with 503 and `Retry-After: 1` when full; `/healthz` and `/readyz` are
never limited. pprof's `seconds` is capped at 60 (400 above), `cmdline` is
not served (it holds host paths), every pprof request is logged at info
level, and turning pprof on logs a warning. When `listen` is a loopback
address, a request whose `Host` is not a loopback IP or `localhost` gets
421, so that a web page cannot reach it through DNS rebinding.

The admin server starts before the SSH listeners accept and stops last:
after the drain, `Shutdown` with a 1 s deadline, then `Close`. A `Serve`
error after start is logged and does not stop the SSH server.

### Endpoints

- `/healthz`: 200 `ok` while the process serves HTTP. This is the liveness
  check (Kubernetes `livenessProbe`, Docker `HEALTHCHECK --url`).
- `/readyz`: 200 `ready`, or 503 with one fixed token:
  - `starting`: before the SSH listeners accept (the moment of `READY=1`);
  - `stopping`: from SIGTERM on (the SSH listeners close at once, so this
    is informational; see Consequences);
  - `audit_unavailable`: `audit.on_error = "fail-closed"` refuses
    connections because the audit log cannot be written (D20).

  It stays 200 when `max_connections` is reached, after a failed reload,
  with fail-open write errors and with mounts unavailable: restarting or
  taking the instance out of rotation fixes none of these, and they show in
  metrics. It must not be used for liveness: a full audit disk would then
  become a restart loop.
- `/metrics`: the text format 0.0.4, `Content-Type: text/plain;
  version=0.0.4; charset=utf-8`, whatever the `Accept` header (never 406);
  HEAD gets the headers without collecting.
- `/debug/pprof/` with `pprof = true` (and the build tag).

**Audit recovery.** `internal/audit` gains `Available() bool` and
`Failing() bool`, which read the sink's state without writing, and
`WriteErrors() uint64`. `/readyz` reads `Available`. Recovery used to depend
on traffic (`Healthy()` probes only when called); a background goroutine in
`serve` now calls `Healthy()` every 5 s while the log fails, so the server
recovers, and `/readyz` returns to 200, without connections, as ROADMAP
§6.4 and docs/audit-log.md already say.

### Exposition

`internal/obs` writes the format itself:

- one `# HELP` and one `# TYPE` per family, families sorted by name;
- within a family, series ordered by their label values compared in the
  family's label-name order; a histogram or summary series is one block:
  `_bucket` lines in ascending numeric `le` (the declared bounds, then
  `+Inf`), then `_sum`, then `_count` (summaries: `quantile` lines, `_sum`,
  `_count`); `le` is never sorted as a string;
- HELP text escapes `\` and line feed only; label values escape `\`, `"`
  and line feed; floats in Go's shortest form (`+Inf`, `-Inf`, `NaN`);
- every valid combination of label values of every counter and histogram
  exists from the start with value 0, so each family always has samples and
  `increase()` sees the first event; only process and runtime values that
  cannot be read are left out, never reported as 0;
- counters and gauges are atomic; a histogram takes a per-histogram mutex
  (observations happen once per transfer, not per packet), so a scrape sees
  cumulative buckets and `_count` equal to the `+Inf` bucket;
- label values come from closed sets that the code defines, never from
  clients: no user names, paths, addresses or fingerprints.

### Metrics

Counted once per event at its final outcome; "as `conn.close`" names the
audit result of the same connection.

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `gosftpd_build_info` | gauge, 1 | `version`, `goversion` | |
| `gosftpd_connections_active` | gauge | | admitted connections being served, before and after login |
| `gosftpd_connections_total` | counter | `result` | admitted connections when they end, exactly one result each: `ok`, `error`, `idle_timeout`, `keepalive_timeout`, `revoked` (as `conn.close`); `no_version` (the client sent no byte: health checks, port scanners); `handshake_failed` (bytes arrived, but the key exchange or the start of authentication failed or timed out: no common algorithm, scanners such as ssh-keyscan); every other end without `conn.close` is `error` |
| `gosftpd_connections_refused_total` | counter | `reason` | connections refused before the handshake: `banned`, `max_connections`, `max_connections_per_ip`, `max_preauth_connections`, `audit_unavailable`; counted before the 10/s limit of `conn.reject`, so exact |
| `gosftpd_logins_total` | counter | `result` | connections that reached authentication: `success` (`auth.success`) or `failure` (`auth.failure`, including a login refused after the handshake) |
| `gosftpd_auth_attempts_total` | counter | `method` (`publickey`, `password`, `other`), `result` (`success`, `failure`) | authentication requests as x/crypto reports them: every request except `none`; a refused key offer counts as a failure (an SSH agent offering several keys makes several), an accepted offer is not reported, a bad signature ends the connection uncounted; `success` is x/crypto's, before gosftpd's final check |
| `gosftpd_sftp_operations_total` | counter | `op` (`upload`, `download`, `rename`, `mkdir`, `rmdir`, `remove`, `setstat`, `list`, `stat`, `other`), `result` (`ok`, `denied`, `not_found`, `error`, `aborted`) | one per SFTP action at its end: a transfer at close, or when its open fails; anything else when it returns; `other` is symlink, link, readlink and statvfs; `aborted` only for transfers; counted whether or not the audit category is on |
| `gosftpd_transfer_bytes_total` | counter | `direction` (`upload`, `download`) | bytes as they are written or read, not at the end, so rates show long transfers |
| `gosftpd_transfer_duration_seconds` | histogram | `direction` | open to close of a transfer that got a handle, any result; buckets 0.01, 0.1, 0.5, 1, 5, 15, 60, 300, 1800, 7200 |
| `gosftpd_conflicts_total` | counter | `op` (`upload`, `rename`), `conflict` (`renamed`, `overwritten`, `versioned`, `rejected`) | an upload or posix-rename onto an existing name, by the conflict policy's outcome: the `conflict` of `fs.upload` (known at close for atomic and version uploads) or `fs.rename`; `rejected` is `on_conflict = "reject"` only (an `O_EXCL` create or an SFTP v3 RENAME onto an existing name is an error, not a conflict) |
| `gosftpd_bans_active` | gauge | | sources banned now: entries not expired and not exempt, counted at scrape under the ban table's lock (at most 65 536), pruning expired ones; 0 with bans off |
| `gosftpd_bans_total` | counter | | bans imposed (`auth.ban`), so bans shorter than the scrape interval show |
| `gosftpd_mounts_unavailable` | gauge | | mounts left out by the last reload |
| `gosftpd_config_reloads_total` | counter | `result` (`ok`, `error`) | |
| `gosftpd_config_last_reload_successful` | gauge | | 1 at start and after a successful reload, 0 after a failed one |
| `gosftpd_config_last_reload_success_timestamp_seconds` | gauge | | the start, then each successful reload |
| `gosftpd_audit_write_errors_total` | counter | | failed writes to the audit output, recovery probes included |
| `gosftpd_audit_log_failing` | gauge | | 1 while writes to the audit output fail (either `on_error`), else 0 |

Runtime and process metrics, with client_golang's names so that dashboards
work, all without `runtime.ReadMemStats` (which stops the world):

| Metric | Source |
|---|---|
| `go_info{version}` | `runtime.Version()` |
| `go_goroutines` | `runtime.NumGoroutine()` |
| `go_threads` | `runtime.ThreadCreateProfile(nil)`: threads created, as client_golang reports it (Go 1.26 has no `runtime/metrics` value for it) |
| `go_memstats_heap_alloc_bytes` | `/memory/classes/heap/objects:bytes` |
| `go_memstats_sys_bytes` | `/memory/classes/total:bytes` |
| `go_gc_duration_seconds` (summary: quantiles 0, 0.25, 0.5, 0.75, 1) | `debug.ReadGCStats`: pause quantiles, `_sum` total pause, `_count` cycles |
| `process_start_time_seconds` | the time the process started, taken when `obs` is initialized (no `/proc/stat`, which the systemd sandbox hides) |
| `process_cpu_seconds_total` | `getrusage` (Unix) |
| `process_max_fds` | `RLIMIT_NOFILE` soft limit (Unix) |
| `process_resident_memory_bytes`, `process_virtual_memory_bytes` | `/proc/self/statm` (Linux) |
| `process_open_fds` | entries of `/proc/self/fd` (Linux) |

### Code

`internal/obs` imports no internal package (a leaf); the new edges are
`cli → obs`, `server → obs` and `sftpd → obs`. It holds the registry
(counters, gauges, histograms, and functions read at scrape for counters,
gauges and the GC summary), the writer, the HTTP handlers and the typed
`obs.Metrics`. `Metrics` exposes only methods that do nothing on a nil
receiver, so tests and builds without the listener pass nil. The server
takes it in `server.Config`, fixed by `New` like `Audit` (Reload ignores
it); `sftpd.New` takes it. Values owned elsewhere are read at scrape:
`audit.Logger.WriteErrors/Failing`, `Server.ActiveBans` (the current
snapshot's ban table, via a new `BanTable.Active`), mounts unavailable from
`serve`. There is no global registry.

### `gosftpd healthcheck`

`gosftpd healthcheck [--config FILE] [--address HOST:PORT] [--url URL]
[--timeout 5s] [--ready]`. It exits 0 when healthy and 1 otherwise, also
for usage and configuration errors (Docker reserves exit 2 for HEALTHCHECK,
an exception to §6.7), with exactly one line on stderr.

- **TCP (default).** The address: `--address`, else `GOSFTPD_LISTEN`, else
  the first `server.listen` of the file `serve` would find (`--config`,
  `GOSFTPD_CONFIG`, the search path), read leniently (only that key: no
  includes, no validation, unknown keys ignored, so an invalid value that a
  reload refused does not fail the check; a file that is not TOML does,
  since the address cannot be known), else `:2022`. Port 0 is refused.
  A wildcard host is dialed as `127.0.0.1`, then `::1`. Only that one
  address is probed. The probe reads at most 255 bytes up to a line
  starting with `SSH-2.0-` and closes without sending a version. Outcomes:
  - banner: healthy;
  - not listening, or no banner within the timeout: unhealthy;
  - accepted, then closed without a banner: the server is alive but refuses
    new connections (limits, a ban, the audit log); healthy, with a note,
    unless `--ready` asks for readiness.

  A probe that is admitted writes nothing to the audit log (`conn.accept`
  is written only after the key exchange) and counts as `no_version`; a
  refused one is a `conn.reject` and a refusal in metrics. If `serve` uses
  `--listen` or `--dir`, pass `--address`; a changed `server.listen` is
  probed before a restart applies it.
- **HTTP (`--url`).** `GET URL` with no proxy (HTTP_PROXY is ignored), no
  redirects and the timeout; a 2xx status is healthy. Use `/healthz` for
  liveness, `/readyz` for readiness.

## Consequences

- No new dependency. The exposition code is ours to keep correct: a unit
  test parses the output with a parser written for the test and checks the
  structure (one block per series, numeric `le`, cumulative buckets,
  `+Inf` equal to `_count`, escaping, unique series) and a golden file;
  the interop job runs `promtool check metrics` (pinned, checksummed)
  against a live server. `promlinter` (a client_golang linter) does not
  apply; a test checks the names (prefix, `_total` on counters, base
  units). CI also checks the release binary against the 10 MB budget.
- The admin listener has no authentication or TLS: keep it on loopback or a
  private network, or put it behind a proxy. The threat model gains it as
  an entry point.
- `/readyz` turns 503 at SIGTERM, but the SSH listeners close at the same
  moment, so a load balancer still sending new connections gets them
  refused. In Kubernetes use `lifecycle.preStop.sleep` and
  `terminationGracePeriodSeconds` ≥ sleep + `shutdown_timeout` + 5 s; a
  `server.shutdown_delay` that keeps accepting may come later.
- PROXY protocol (M4-08) must not break the TCP probe: for sources outside
  `trusted_proxies` the server writes its banner without reading a header
  first; when the probe's own source is trusted, `healthcheck` sends a
  PROXY v2 LOCAL header. M4-08 tests both.
- Scrapes and health checks do not appear in the audit log; `conn.accept`
  is written after the key exchange, as docs/audit-log.md now says.
- ROADMAP: D12 decided (no library); the metrics library leaves A9, the
  dependency table and docs/DEPENDENCIES.md; promlinter (§9.2) gives way to
  the name test and promtool; §11.2 takes the names above; §6.4's
  `no_handshake` becomes `no_version` and `handshake_failed`; the package
  graph (§4.2) gains `cli → obs`. `metrics.listen` joins the restart-only
  list (ADR 0005, docs/configuration.md); `[metrics]` joins
  example-full.toml.
