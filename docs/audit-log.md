# Audit log

gosftpd writes one JSON line per action, not per packet. Transfers are logged
when they end. The operational log (stderr) is separate.

```json
{"time":"2026-10-08T11:20:42Z","level":"INFO","msg":"audit","schema":1,"event":"fs.upload","conn_id":"4b1d0c9e2f7a8b36","remote_addr":"203.0.113.7:53122","local_addr":"192.0.2.10:2022","user":"partner","session_id":"9f3c2a17d0b4e6a1","path":"/inbox/report.pdf","final_path":"/inbox/report (1).pdf","conflict":"renamed","open_flags":"WRITE+CREAT+TRUNC","bytes":300000,"duration_ms":412,"result":"ok"}
```

Configure it in `[audit]` ([configuration.md](configuration.md#audit)):
`output` (stdout or a file), `events` (categories) and `on_error`.

## Stability

The `schema` field is the format version. Within schema 1 fields are only
added; renaming, removing or retyping a field means schema 2. The test
`TestAuditSchema` checks every line of a session that uses every operation
against [`internal/server/testdata/audit.schema.json`](../internal/server/testdata/audit.schema.json).

## Fields

Every line has `time`, `level`, `msg` (`"audit"`), `schema` and `event`, and,
once known, the context fields:

| Field | Meaning |
|---|---|
| `conn_id` | Random ID of the SSH connection (16 hex digits). |
| `remote_addr`, `local_addr` | Client and server address. |
| `user` | Authenticated user. |
| `session_id` | Random ID of the SFTP session within the connection. |

Paths are always virtual paths as the client sees them (`/inbox/report.pdf`),
never host paths. Strings from clients are JSON-escaped.

## Events

| Event | Category | Fields |
|---|---|---|
| `server.start` | server | `version`, `listen` |
| `server.stop` | server | |
| `server.audit_recovered` | server | written when the log works again after a failure |
| `conn.reject` | conn | `reason`: `banned`, `max_connections`, `max_connections_per_ip` or `max_preauth_connections`; `suppressed` (see below) |
| `conn.accept` | conn | `client_version` (after the client sent its version line) |
| `conn.close` | conn | `duration_ms`, `result` (`ok`, `error`, `idle_timeout`, `keepalive_timeout`) |
| `auth.success` | auth | `auth_method` (`publickey` or `password`), `key_fp` (SHA256 fingerprint, public keys only), `failed_attempts` |
| `auth.failure` | auth | `attempts`, `user` (the last name tried); written when a connection ends without login |
| `auth.ban` | auth | `source` (IPv4 address or IPv6 /64), `duration_ms` |
| `session.start` | session | |
| `session.end` | session | `duration_ms`, `exit_status` |
| `fs.upload` | transfer | `path` (requested), `final_path`, `conflict` (`none`, `renamed`, `overwritten`), `open_flags`, `bytes`, `start_offset` (resumed uploads), `duration_ms`, `result` |
| `fs.download` | transfer | `path`, `bytes`, `duration_ms`, `result` |
| `fs.rename` | modify | `path`, `target_path`, `final_path`, `conflict` (moves), `result` |
| `fs.mkdir`, `fs.rmdir`, `fs.remove`, `fs.setstat` | modify | `path`, `result` |
| `fs.denied` | denied | `reason`, `result`, and `op` and `path`, or `mount` for an unavailable home |
| `fs.list` | list (opt-in) | `path`, `result` |
| `fs.stat` | stat (opt-in) | `path`, `result` |

`result` is `ok`, `denied`, `error` or `aborted` (the connection ended during
the transfer; an empty file the upload created is removed). An upload with a
refused write (append-only guard) ends with `denied`.

Connections that close before sending an SSH version line (health checks,
port scanners) are not audited. Refused connections (`conn.reject`) are
logged at most 10 per second; the next `conn.reject` written reports how
many were left out in `suppressed`.

## When the log cannot be written

With `on_error = "fail-closed"` (default), a write error (disk full, closed
pipe) makes gosftpd refuse new connections and every changing operation until
a probe write succeeds; it tries every 5 seconds and then writes
`server.audit_recovered`. Transfers already running finish, and their events
go to stderr. With `on_error = "fail-open"` gosftpd keeps serving and writes
every event that could not be stored to stderr.

## Rotation

There is no built-in rotation yet. Use journald or Docker logging with
`output = "stdout"`, or logrotate with `copytruncate` for a file (SIGHUP does
not reopen the file before v0.4). The file is opened with `O_APPEND`, so
`copytruncate` leaves no hole.
