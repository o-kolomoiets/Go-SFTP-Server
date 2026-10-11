# Metrics and health checks

gosftpd can serve Prometheus metrics and health checks on a separate HTTP
listener, the admin listener (ADR 0009). It is off by default. Without it,
`gosftpd healthcheck` still checks the SSH listener.

```toml
[metrics]
listen = "127.0.0.1:9090"
```

`metrics.listen` changes only at restart. The banner shows
`metrics: http://127.0.0.1:9090/metrics`, and the `server.start` audit event
has `metrics_listen`.

## Security

The admin listener has no authentication and no TLS. `/metrics` shows the
exact gosftpd and Go versions, which the SSH banner withholds, and the load
of the server; pprof shows process internals. Keep it on loopback or a
private network, or put it behind a proxy that authenticates. `config
validate` and `serve` warn when it is not on loopback.

- When gosftpd binds a loopback address, a request whose `Host` header is
  not a loopback address or `localhost` gets 421, so that a web page cannot
  reach the listener through DNS rebinding. A reverse proxy in front of it
  must therefore send a loopback `Host` upstream: nginx and Apache do by
  default; Caddy needs `header_up Host {upstream_hostport}`, Traefik
  `passHostHeader: false`, HAProxy `http-request set-header Host
  127.0.0.1:9090`.
- In Docker, the listener must bind `0.0.0.0` inside the container; publish
  it on the host's loopback only: `-p 127.0.0.1:9090:9090`. The `Host` check
  is then off, since gosftpd does not bind loopback itself: a web page in a
  browser on the Docker host can read `/metrics` through DNS rebinding.
  Never turn pprof on there.
- Requests are limited: headers 8 KiB and 5 s, at most 64 open connections,
  at most 4 concurrent `/metrics` and pprof requests (503 with
  `Retry-After: 1` beyond that). `/healthz` and `/readyz` are exempt from
  the request limits but share the 64 connections: whoever can reach the
  listener can hold all of them and make HTTP health checks time out. Use
  the SSH check of `gosftpd healthcheck` for liveness.
- Methods other than GET and HEAD get 405; unknown paths 404.

Scrapes and health checks do not appear in the audit log.

## Endpoints

| Path | Answer |
|---|---|
| `/healthz` | 200 `ok` while the process serves HTTP. |
| `/readyz` | 200 `ready`, or 503 with one word: `starting` (before the SSH listeners accept), `stopping` (from SIGTERM on), `audit_unavailable` (with `audit.on_error = "fail-closed"`, while the audit log cannot be written and new connections are refused). |
| `/metrics` | The Prometheus text format 0.0.4, whatever the `Accept` header asks for. |
| `/debug/pprof/` | Go profiles, with `pprof = true` in a binary built with `-tags pprof`. |

`/readyz` stays 200 when `max_connections` is reached, after a failed
reload, while a fail-open audit log fails and while mounts are unavailable:
neither a restart nor taking the server out of rotation fixes those, and
they show in the metrics. Never use `/readyz` for liveness: a full audit disk
would turn into a restart loop.

While the audit log fails, gosftpd retries it every 5 seconds, in either
`on_error` mode, so it recovers, `/readyz` turns ready again and
`gosftpd_audit_log_failing` returns to 0 without waiting for a client.

## Metrics

Every label has a fixed set of values; none holds a user name, a path, an
address or a key fingerprint (those are in the audit log). Every combination
exists from the start with the value 0, so `increase()` sees the first
event.

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `gosftpd_build_info` | gauge | `version`, `goversion` | Always 1. |
| `gosftpd_connections_active` | gauge | | Admitted connections being served, before and after login. |
| `gosftpd_connections_total` | counter | `result` | Admitted connections when they end, one result each: `ok`, `error`, `idle_timeout`, `keepalive_timeout`, `revoked` (the `result` of `conn.close`); `no_version` (the client sent nothing: health checks, port scanners); `handshake_failed` (it sent something but never reached authentication: no common algorithm, `ssh-keyscan`, a bad version line). |
| `gosftpd_connections_refused_total` | counter | `reason` | Connections refused before the handshake: `banned`, `max_connections`, `max_connections_per_ip`, `max_preauth_connections`, `audit_unavailable`. Exact, unlike the `conn.reject` events, which are limited to 10 per second. |
| `gosftpd_logins_total` | counter | `result` | Connections that reached authentication: `success` or `failure` (as `auth.success` and `auth.failure`). |
| `gosftpd_auth_attempts_total` | counter | `method` (`publickey`, `password`, `other`), `result` (`success`, `failure`) | Authentication requests other than `none`. A key the server does not accept counts as a failure: an SSH agent that offers several keys makes several. |
| `gosftpd_sftp_operations_total` | counter | `op`, `result` | One per SFTP operation when it ends; a transfer when it is closed, or when its open fails. `op`: `upload`, `download`, `rename`, `mkdir`, `rmdir`, `remove`, `setstat`, `list`, `stat`, `other` (symlink, link, readlink, statvfs). `result`: `ok`, `denied`, `not_found`, `error`, `aborted` (a transfer cut off by the end of the session). Counted whatever `audit.events` records. |
| `gosftpd_transfer_bytes_total` | counter | `direction` (`upload`, `download`) | Bytes as they are transferred, so the rate shows long transfers. |
| `gosftpd_transfer_duration_seconds` | histogram | `direction` | Open to close of a transfer, any result. Buckets 0.01, 0.1, 0.5, 1, 5, 15, 60, 300, 1800, 7200 s. |
| `gosftpd_conflicts_total` | counter | `op` (`upload`, `rename`), `conflict` (`renamed`, `overwritten`, `versioned`, `rejected`) | Uploads and posix-renames onto an existing name, by the outcome of `on_conflict`. `rejected` is `on_conflict = "reject"`; an exclusive create or an SFTP v3 RENAME onto an existing name is an error, not a conflict. |
| `gosftpd_bans_active` | gauge | | Sources banned now. |
| `gosftpd_bans_total` | counter | | Bans imposed (`auth.ban`), also those shorter than the scrape interval. |
| `gosftpd_mounts_unavailable` | gauge | | Mounts the last reload left out because their directory cannot be used. |
| `gosftpd_config_reloads_total` | counter | `result` (`ok`, `error`) | Configuration reloads. |
| `gosftpd_config_last_reload_successful` | gauge | | 1 at start and after a successful reload, 0 after a failed one. |
| `gosftpd_config_last_reload_success_timestamp_seconds` | gauge | | The start, then each successful reload. |
| `gosftpd_audit_write_errors_total` | counter | | Failed writes to the audit output, recovery probes included. |
| `gosftpd_audit_log_failing` | gauge | | 1 while writes to the audit output fail (either `on_error`), else 0. |

Go runtime and process metrics have the names of the Prometheus Go client,
so existing dashboards work. None of them stops the world to be read.

| Metric | Meaning |
|---|---|
| `go_info{version}`, `go_goroutines`, `go_threads` | Go version, goroutines, OS threads created. |
| `go_memstats_heap_alloc_bytes`, `go_memstats_sys_bytes` | Heap in use; memory obtained from the OS. |
| `go_gc_duration_seconds` | Summary of recent GC pauses (quantiles 0, 0.25, 0.5, 0.75, 1). |
| `process_start_time_seconds` | When the process started. |
| `process_cpu_seconds_total`, `process_max_fds` | CPU time and the open file limit (Unix). |
| `process_resident_memory_bytes`, `process_virtual_memory_bytes`, `process_open_fds` | From `/proc/self` (Linux). |

A value that cannot be read on a platform is left out, never reported as 0.

### Scrape configuration

```yaml
scrape_configs:
  - job_name: gosftpd
    static_configs:
      - targets: ["127.0.0.1:9090"]
```

### Queries and alerts

```promql
# Failed logins per second, and the share of failures
rate(gosftpd_logins_total{result="failure"}[5m])
sum(rate(gosftpd_logins_total{result="failure"}[5m])) / sum(rate(gosftpd_logins_total[5m]))

# Upload throughput
rate(gosftpd_transfer_bytes_total{direction="upload"}[5m])

# Connections refused because a limit was reached
sum by (reason) (rate(gosftpd_connections_refused_total{reason=~"max_.*"}[5m]))

# 95th percentile transfer time
histogram_quantile(0.95, sum by (le, direction) (rate(gosftpd_transfer_duration_seconds_bucket[1h])))
```

```yaml
groups:
  - name: gosftpd
    rules:
      - alert: GosftpdAuditLogFailing
        expr: gosftpd_audit_log_failing == 1
        for: 1m
      - alert: GosftpdReloadFailed
        expr: gosftpd_config_last_reload_successful == 0
        for: 5m
      - alert: GosftpdMountsUnavailable
        expr: gosftpd_mounts_unavailable > 0
        for: 5m
```

## Kubernetes

```yaml
containers:
  - name: gosftpd
    ports:
      - containerPort: 2022
      - containerPort: 9090
    livenessProbe:
      exec: { command: ["/usr/bin/gosftpd", "healthcheck"] }
    readinessProbe:
      httpGet: { path: /readyz, port: 9090 }
    lifecycle:
      preStop:
        sleep: { seconds: 10 }
terminationGracePeriodSeconds: 45 # at least preStop + shutdown_timeout + 5 s
```

The liveness probe checks the SSH listener, which the admin listener's
connection limit cannot block; a failed readiness probe takes the pod out
of the Service without restarting it. The kubelet connects to the pod's
address, so the admin listener must listen on it (`listen =
"0.0.0.0:9090"`); keep port 9090 out of the Service and restrict it with a
NetworkPolicy.

At SIGTERM gosftpd closes its SSH listeners and lets transfers finish for up
to `server.shutdown_timeout`; `/readyz` says `stopping`, but a load balancer
that still sends new connections gets them refused. The `preStop` sleep
keeps the server accepting until the endpoint is removed.

## `gosftpd healthcheck`

For `HEALTHCHECK` in Docker and similar checks. It exits with 0 when the
server answers and with 1 otherwise, also for a usage error (Docker reserves
2), and prints one line.

```dockerfile
HEALTHCHECK CMD ["/usr/bin/gosftpd", "healthcheck"]
```

Without `--url` it connects to the SSH listener, waits for the server's
`SSH-2.0-` line and closes the connection without sending its own version.
The server writes nothing to the audit log for such a probe; it counts as
`gosftpd_connections_total{result="no_version"}`. The address is, in this
order: `--address`, `$GOSFTPD_LISTEN`, the first `server.listen` of the
configuration file that `serve` would read (`--config`, `$GOSFTPD_CONFIG`,
the search path), `:2022`. Only `server.listen` is read from the file, so an
invalid value elsewhere that a reload refused does not fail the check; a
file that is not valid TOML does, as the address cannot be known: pass
`--address` or set `GOSFTPD_LISTEN` to be independent of the file. A
wildcard address (`:2022`, `0.0.0.0`, `[::]`) is checked on `127.0.0.1`,
then on `::1`. When `serve` runs with `--listen` or `--dir`, pass
`--address`.

| Server | Result |
|---|---|
| Sends its SSH banner | healthy |
| Not listening, or no banner within `--timeout` (5 s) | unhealthy |
| Accepts and closes the connection at once | healthy, with a note: the server runs but refuses new connections (connection limits, a ban, or an unavailable audit log); unhealthy with `--ready` |

With `--url URL` it sends `GET URL` instead, without a proxy and without
following redirects; any 2xx status is healthy:

```dockerfile
HEALTHCHECK CMD ["/usr/bin/gosftpd", "healthcheck", "--url", "http://127.0.0.1:9090/healthz"]
```

## pprof

Release binaries do not contain pprof (it costs 0.6 MB). Build with
`go build -tags pprof ./cmd/gosftpd`, set `pprof = true` and reload; turn it
off again when done.

```sh
go tool pprof http://127.0.0.1:9090/debug/pprof/heap
go tool pprof 'http://127.0.0.1:9090/debug/pprof/profile?seconds=30'
```

At most two profiles run at a time, and `seconds` is at most 60.
`/debug/pprof/cmdline` is not served (it holds host paths). Every pprof
request is logged.
