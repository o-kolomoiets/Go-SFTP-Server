# ADR 0010: Hooks (exec and webhook)

- **Status:** draft, 2026-10-11
- **Context:** ROADMAP M4 (M4-07) asks for `[[hooks]]`: filters `on`,
  `mounts`, `glob`; `exec` (argv without a shell, `GOSFTPD_*` environment,
  a timeout); `webhook` (POST of the audit event as JSON, an HMAC-SHA256
  signature in `X-Gosftpd-Signature`, retries with backoff, a bounded
  queue); asynchronous by default. The persona U2 (a team receiving files
  from partners) wants "a webhook on upload completion"; the retention
  recipe moves uploaded files with an exec hook. The M4 definition of done:
  a webhook on `fs.upload` arrives with `final_path` and a valid signature,
  and a file named `$(rm -rf x)` makes an exec hook execute nothing.
  Hooks are the only way gosftpd starts processes or makes outgoing
  connections (design principle 2).

## Decision

### Configuration

```toml
[[hooks]]
name = "notify"                  # unique; in logs
on = ["fs.upload"]               # event names, at least one
mounts = ["inbox"]               # optional: only these mounts
glob = "*.pdf"                   # optional: on the file name (path.Match)
webhook = { url = "https://example.internal/hooks/sftp", secret_file = "/etc/gosftpd/hook.secret", timeout = "10s" }

[[hooks]]
name = "archive"
on = ["fs.upload"]
exec = { argv = ["/usr/local/bin/on-upload"], timeout = "30s" }
concurrency = 1                  # deliveries at a time, 1 to 16
queue = 1000                     # events waiting, 1 to 100 000
```

A hook has exactly one of `exec` and `webhook`. Hooks are reloadable.

- `on`: `fs.upload`, `fs.download`, `fs.rename`, `fs.remove`, `fs.mkdir`,
  `fs.rmdir`, `fs.setstat`. A hook fires only for an event with
  `"result":"ok"`: an aborted, denied or failed upload never fires one.
- `mounts`: mount names; a name that is not configured is an error.
- `glob`: matched with `path.Match` against the last element of the event's
  file: `final_path` for `fs.upload` and `fs.rename`, `path` otherwise. An
  invalid pattern is an error.

### Events and payload

A hook gets the event as the audit log writes it: the same JSON object,
with `conn_id`, `session_id`, `user`, `remote_addr`, `key_fp` and the
event's fields, also when `audit.events` leaves the event's category out.
It never contains a host path. sftpd passes each event that has a hook
to the dispatcher with two values that are not in the payload: the mount
name and the host path of the file (for exec).

### exec

- `argv` is run directly, never through a shell; `argv[0]` must be an
  absolute path, checked like a trusted file (not inside a mount, not
  writable by others). Nothing from a client is ever an argument.
- Environment: only `PATH` from gosftpd's environment, plus
  `GOSFTPD_EVENT`, `GOSFTPD_USER`, `GOSFTPD_MOUNT`, `GOSFTPD_PATH`,
  `GOSFTPD_FINAL_PATH` (uploads and renames), `GOSFTPD_TARGET_PATH`
  (renames), `GOSFTPD_HOST_PATH` (the file on the host) and
  `GOSFTPD_CONN_ID`. Names are passed as they are; they can contain
  spaces, newlines, quotes, `$(...)` and a leading `-`.
- stdin is the event JSON; stdout and stderr are read (at most 4 KiB each)
  into the operational log when the hook fails.
- `timeout` (default 30 s, at most 1 h): the process, and on Unix its
  process group, is killed when it runs out.
- An exit status other than 0 is a failure, logged with the status and the
  output; exec hooks are not retried (the script may not be idempotent).

### webhook

- `POST url` with the event JSON, `Content-Type: application/json`,
  `User-Agent: gosftpd/VERSION`, and:
  - `X-Gosftpd-Event`: the event name;
  - `X-Gosftpd-Delivery`: a random ID, the same in every retry;
  - `X-Gosftpd-Timestamp`: Unix seconds of this attempt;
  - `X-Gosftpd-Signature: sha256=HEX` of HMAC-SHA256 with the secret over
    `TIMESTAMP + "." + BODY`, so a receiver can refuse replays older than
    a few minutes.
- `secret_file`: at least 32 bytes after trimming white space; checked like
  a trusted file (owner, mode 0600 or 0640, not inside a mount); read again
  on reload. No inline secret.
- `url`: `https`, or `http` with a warning unless the host is loopback.
  User info in the URL is refused; the URL path may hold a token (Slack,
  n8n), so logs show only the scheme and host.
- Proxies from the environment (`HTTPS_PROXY`, `NO_PROXY`) are used;
  redirects are not followed (a 3xx is a failure). TLS uses the system
  roots (`SSL_CERT_FILE` and `SSL_CERT_DIR` for a private CA).
- `timeout` per attempt (default 10 s, at most 60 s).
- A 2xx is delivered. A network error, a timeout, 408, 429 and 5xx are
  retried: at most 5 attempts after 1, 5, 30 and 120 s (± 20 % jitter),
  honoring `Retry-After` up to 120 s. Other statuses are permanent
  failures.

### Queue and delivery

- Every hook has its own bounded queue (`queue`, default 1000) and
  `concurrency` workers (default 1, so events of a hook run in order).
  Enqueueing never blocks an SFTP request: when the queue is full, the new
  event is dropped and a warning is logged at most once a minute with the
  count.
- Delivery is at most once per attempt and best effort: the queue lives in
  memory, so events still queued are lost on a crash or after the shutdown
  grace below. The audit log stays the complete record; a receiver that
  must not miss uploads reconciles against it or the directory.
- A reload builds new hooks; events already queued are delivered by the
  hooks of the configuration they were queued under.
- At shutdown, after the SFTP drain, hooks get up to 10 s more to deliver
  what is queued and finish running processes; then running processes are
  killed, pending retries dropped, and the count logged.

### Logging and metrics

- Each failure is logged at warn level with the hook name, the event and
  the reason (status code, exit status, error); successes at debug.
- Metrics (ADR 0009): `gosftpd_hook_deliveries_total{type, result}` with
  `type` `exec` or `webhook` and `result` `ok`, `failed`, `retried`,
  `dropped`; `gosftpd_hook_queue_length` (all hooks). Hook names are not
  labels.
- Hook runs are not audit events: they are operational, and the event that
  fired them is already in the audit log.

### Not in this ADR

- A synchronous hook that can refuse an upload before it is published
  (virus scanning): it needs `atomic_uploads` and its own design. ROADMAP's
  "asynchronous by default" becomes "asynchronous" for v0.4; the backlog
  gets the synchronous pre-publish hook.
- Events other than file events (`auth.*`, `conn.*`, `server.*`).
- Custom headers, mutual TLS, a persistent queue.

### Code

`internal/hooks` holds the dispatcher, the exec and webhook runners and
their tests; it imports `obs` for metrics and nothing that imports it. The
cli converts `config.Hook` into `hooks.Spec` (so `hooks` does not import
`config`), builds the dispatcher at start and on reload, and drains it at
shutdown. `sftpd` gets a nil-safe `*hooks.Dispatcher` (through
`server.Config`, reloadable like the mount table) and, after each audited
file event with result ok, calls `Notify` with the payload from a new
`audit.Logger.Render(event, attrs...)`, which formats the line exactly as
the audit output would.

## Consequences

- An exec hook runs with gosftpd's user and sandbox (systemd, Landlock in
  M4-08): its program and what it touches must be allowed there.
- File names from clients reach scripts in environment variables and JSON:
  docs/hooks.md shows safe handling (`"$GOSFTPD_HOST_PATH"`, `--`), and the
  interop test uploads `$(rm -rf x)`.
- A webhook sends user names, addresses and paths to its receiver.
- Lost events (queue full, shutdown, crash) are possible by design and
  visible in metrics and the log.
