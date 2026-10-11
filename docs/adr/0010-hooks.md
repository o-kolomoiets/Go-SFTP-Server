# ADR 0010: Hooks (exec and webhook)

- **Status:** draft 2, 2026-10-11; amends ADR 0005 (state that outlives
  snapshots) and the audit schema (additive)
- **Context:** ROADMAP M4 (M4-07) asks for `[[hooks]]`: filters `on`,
  `mounts`, `glob`; `exec` (argv without a shell, `GOSFTPD_*` environment,
  a timeout); `webhook` (POST of the audit event as JSON, an HMAC-SHA256
  signature in `X-Gosftpd-Signature`, retries with backoff, a bounded
  queue); asynchronous. The persona U2 (a team receiving files from
  partners) wants "a webhook on upload completion", with WinSCP and rclone
  temp-file uploads; the retention recipe moves uploaded files with an exec
  hook. Hooks are the only way gosftpd starts processes or makes outgoing
  connections (design principle 2). Three reviews of draft 1 (operations,
  security, integration with the code), each finding checked by a second
  reviewer, confirmed 29 findings; this draft answers all of them.

## Decision

### Configuration

```toml
[[hooks]]
name = "notify"                       # unique; in logs, never in metric labels
on = ["fs.upload"]                    # event names, at least one
mounts = ["inbox"]                    # optional: only these mounts
glob = ["*.pdf", "*.PDF"]             # optional: base name matches any (path.Match)
exclude = ["*.filepart", "*.partial"] # optional: base name matches none
webhook = { url = "https://example.internal/hooks/sftp", secret_file = "/etc/gosftpd/hook.secret" }

[[hooks]]
name = "archive"
on = ["fs.upload"]
exclude = ["*.filepart", "*.partial"]
delay = "2m"                          # let the client finish its checks first
exec = { argv = ["/usr/local/bin/archive-upload"], timeout = "30s" }
concurrency = 1                       # deliveries at a time, 1 to 16
queue = 1000                          # events waiting, 1 to 10 000
```

A hook has exactly one of `exec` and `webhook`. Hooks are reloadable (see
Reload).

- `on`: `fs.upload`, `fs.download`, `fs.rename`, `fs.remove`, `fs.mkdir`,
  `fs.rmdir`, `fs.setstat`. A hook fires only for an event with
  `"result":"ok"`: an aborted, denied or failed operation never fires one.
- **`fs.upload` means "a file arrived".** WinSCP (files over 100 KiB) and
  rclone upload to a temporary name (`NAME.filepart`, `NAME.XXXX.partial`)
  and then rename it, often from another connection. vfs already knows such
  a rename: it moves a regular file that this user created and nobody
  changed since (`own` in `Session.Move`, the rule that lets the `upload`
  preset finish temp uploads). Such an `fs.rename` gets `"uploaded":true`
  in the audit log, and hooks with `fs.upload` in `on` fire for it as well,
  with the rename's line as payload. The `fs.upload` of the temporary name
  fires too; `exclude` (or `glob`) on the final name leaves it out, so a
  hook with the `exclude` above fires once per file for OpenSSH, WinSCP and
  rclone alike.
- `mounts`: mount names; a name that is not configured is an error.
- `glob` and `exclude`: lists of `path.Match` patterns, matched against the
  base name of the event's file: `final_path` for `fs.upload` and
  `fs.rename`, `path` otherwise. Matching is case-sensitive. An invalid
  pattern is an error.
- `on`, `mounts`, `glob` and `exclude` select events; they are **not a
  security filter**: a rename changes which event carries the final name,
  and case-insensitive file systems accept `X.EXE` for `*.exe`.
- `delay` (default 0, at most 1 h): an event is not delivered before the
  time it was queued plus `delay`. Clients check a file right after
  uploading it (paramiko `put(confirm=True)` and rclone stat it; WinSCP and
  rclone set its times; `stat_redirect` lasts 60 s), so a hook
  that moves or deletes the file must wait: at least `"1m"`, `"2m"` in the
  docs. The delay is the same for every event of a hook, so order is kept.

### Events and payload

A hook gets the event as the audit log renders it: the same JSON line with
the session context (`conn_id`, `remote_addr`, `local_addr`, `user`,
`session_id`) and the event's fields, also when `audit.events` leaves the
event's category out. It never contains a host path. The bytes rendered are
the webhook body and the exec stdin, unchanged.

Two additions to the audit schema, additive within schema 1 (ROADMAP §6.4
already lists the first):

- every `fs.*` event gets `mount`, the mount's name. With `flatten` (the
  default) a user with one mount sees `/report.pdf`, so without it a
  receiver could not tell inboxes apart;
- `fs.rename` gets `"uploaded":true` for the rename that completes a
  temp-file upload, as above.

sftpd first asks the dispatcher whether any hook wants the event
(`Wants(event, mount, name)`, nil-safe and allocation-free) and renders the
line only then. Out of band, for exec only, it passes the host path of the
file and its identity (see exec).

### exec

- `argv[0]` must be absolute. Nothing from a client is ever an argument.
- **Trusted files.** Every absolute argv element that is not an existing
  directory (argv[0], a script given to an interpreter such as
  `["/bin/sh", "/opt/hooks/archive.sh"]`, a file that does not exist yet) is
  checked like a trusted file: not inside any mount (also the mounts of
  live generations on reload), and if it exists, owned by root or
  gosftpd's user and not writable by group or others. `["/bin/sh",
  "<mount>/x.sh"]` is refused whether or not `x.sh` exists;
  `["/usr/bin/find", "<mount>"]` is accepted.
- **Environment:** gosftpd's `PATH` without empty or relative elements,
  plus `GOSFTPD_EVENT`, `GOSFTPD_USER`, `GOSFTPD_MOUNT`, `GOSFTPD_PATH`,
  `GOSFTPD_FINAL_PATH` (uploads and renames), `GOSFTPD_TARGET_PATH`
  (renames), `GOSFTPD_HOST_PATH` and `GOSFTPD_CONN_ID`. Values are passed
  as they are; names can contain spaces, newlines, quotes, `*`, `$(...)`
  and a leading `-`.
- **`GOSFTPD_HOST_PATH`** is the host path of `final_path` for `fs.upload`
  and `fs.rename`, of `path` otherwise: the mount root's host path (for a
  home mount, the user's directory) joined with the relative name. For
  `fs.upload`, `fs.rename` and `fs.mkdir` sftpd passes the file's identity
  (`os.FileInfo` from the closed handle or an `Lstat` after the operation).
  Just before starting the process, the runner `Lstat`s the host path and
  requires `os.SameFile` with that identity. If the file is gone or another
  file is there (a symlink swapped in by a local user, a mount repointed
  under an old connection, a later upload), the run is skipped with the
  warning "file changed before the hook ran" and counted as `failed`.
  Nothing can close the race after that check: a hook must not follow
  symlinks (`mv -T`, `cp -P`), must not run as root, and must treat a
  missing file as normal.
- **Working directory** `/` (on Windows `%SystemRoot%`). stdin is the event
  line.
- **Lifetime.** On Unix the process gets its own process group. When the
  `timeout` (default 30 s, at most 1 h) runs out, at shutdown, and also
  when the leader exits, the whole group is killed with SIGKILL: a hook
  cannot leave processes behind (to start long work, use `systemd-run
  --no-block` or a queue). `WaitDelay` is 2 s, so pipes held by a process
  that left the group (`setsid`) cannot block a worker. The result is the
  leader's exit status; `ErrWaitDelay` after exit 0 is a success, logged.
  On Windows only the process is killed. If exec hooks are configured and
  gosftpd is PID 1, a warning says that orphans are not reaped (use
  `docker run --init`).
- **Output.** stdout and stderr are always read to EOF; the first 4 KiB of
  each is kept, the rest discarded (a writer that refused more would kill
  a chatty script with SIGPIPE). The kept output is logged when the hook
  fails.
- An exit status other than 0 is a failure; exec hooks are not retried
  (the script may not be idempotent): at most once.

### webhook

- `POST url` with the event line, `Content-Type: application/json`,
  `User-Agent: gosftpd` (no version, as in the SSH banner), and:
  - `X-Gosftpd-Event`: the event name;
  - `X-Gosftpd-Delivery`: 32 lowercase hex characters, random, the same in
    every attempt;
  - `X-Gosftpd-Timestamp`: Unix seconds of this attempt;
  - `X-Gosftpd-Signature: sha256=HEX`: lowercase hex of HMAC-SHA256 with
    the secret over `DELIVERY + "." + TIMESTAMP + "." + BODY`, where BODY
    is exactly the bytes sent (with the final newline). The delivery ID is
    signed, so a receiver can deduplicate on it and refuse replays.
- **Secret.** `secret_file`: the HMAC key is the file's content with
  leading and trailing ASCII white space removed, used as bytes and never
  decoded; at least 32 bytes (`openssl rand -hex 32`). The file is checked
  like a trusted secret: refused inside any mount; owner root or gosftpd's
  user; no permissions for others and no write for group (0400, 0440, 0600
  and 0640 pass; symlinks are followed, so Kubernetes secret volumes work;
  no mode check on Windows). It is read again on reload. No inline secret.
  docs/hooks.md publishes a test vector (secret, delivery, timestamp, body,
  signature), checked by a golden test, and the receiver's duties: verify
  over the raw body, compare in constant time, refuse timestamps more than
  5 minutes off, remember delivery IDs for that window plus the retry span.
  Rotation: add the new secret to the receiver, reload gosftpd, then remove
  the old one.
- `url`: `https`, or `http` with a warning unless the host is loopback. User
  info in the URL is refused.
- **No token in logs.** The URL path may hold a token (Slack, n8n): a
  failure is logged with the hook name, `scheme://host` and the unwrapped
  cause (`url.Error.Err`), never the URL or `err.Error()` of the client
  call. At most 4 KiB of a response body is read, never logged. A test
  checks that a failed delivery to `https://127.0.0.1:1/secret-token` logs
  no `secret-token`.
- Proxies from the environment (`HTTPS_PROXY`, `NO_PROXY`) are used;
  redirects are not followed (a 3xx is a failure). TLS uses the system
  roots: on Linux and the BSDs `SSL_CERT_FILE` or `SSL_CERT_DIR` add a
  private CA; macOS and Windows use the system store. Roots are read once,
  so a new CA needs a restart.
- `timeout` per attempt (default 10 s, at most 60 s).
- A 2xx is delivered. A network error, a timeout, 408, 429 and 5xx are
  retried: at most 5 attempts, after 1, 5, 30 and 120 s (± 20 % jitter);
  `Retry-After` is honored and clamped to 120 s. Other statuses are
  permanent failures. Failed attempts are logged at debug, the final
  failure once at warn with the attempt count.

### Queue and delivery

- Every hook has a bounded queue: `queue` events (default 1000, at most
  10 000) and at most 64 MiB of rendered lines (a line can reach about
  75 KB with long, escaped names). Enqueueing never blocks an SFTP request:
  when either bound is reached, the new event is dropped. A warning at most
  once a minute gives the count per user.
- `concurrency` workers (default 1). A worker keeps its event through every
  attempt and its `delay`, so with one worker the events of a hook run in
  order, and queued plus in-flight events are at most `queue +
  concurrency`. One failing webhook event holds a worker for about 3
  minutes (up to about 13 with `Retry-After` and attempt timeouts).
- **Guarantees.** Webhook: at least once while gosftpd runs, so duplicates
  are possible; receivers deduplicate on `X-Gosftpd-Delivery`. Exec: at most
  once. Any event can be lost: a full queue, exhausted retries, a permanent
  status, a skipped run, a removed hook, shutdown, a crash. The queue lives
  in memory. The audit log stays the complete record; a receiver that must
  not miss a file reconciles against it or the directory.
- **Shutdown.** Hooks keep delivering during the SFTP drain. When it ends,
  pending delays are skipped (no client can race any more), and hooks get
  what is left of `server.shutdown_timeout`, at least 5 s. Then running
  processes are killed and what is still queued or waiting for a retry is
  counted as `dropped` and logged. A stop takes at most `shutdown_timeout`
  + 5 s + 1 s (the admin listener). docs/metrics.md's budget becomes
  preStop + `shutdown_timeout` + 10 s, and the M4-08 unit gets
  `KillMode=mixed`, so that systemd signals only gosftpd and SIGKILLs left
  over hook processes at `TimeoutStopSec`.

### Reload

Hooks are server-side settings, not client permissions, so ADR 0005's "a
connection keeps its snapshot" does not apply to them: removing a hook or
rotating a secret must reach connections that stay open for days.

- One `*hooks.Dispatcher` lives for the process, fixed by `server.New`
  like Audit and Metrics. It always exists (empty without hooks), so a
  reload can add the first hook.
- Reload step 3 calls `Update([]Spec)`, which cannot fail and swaps the
  hook set atomically. `Wants` and `Notify` always use the current set, for
  old and new connections alike. Per hook name:
  - kept: its queue and workers stay; pending events are delivered with the
    new spec (URL, secret, argv, timeout, delay, filters apply to new
    events); `queue` and `concurrency` are resized, events above a smaller
    queue are dropped;
  - removed: it takes no more events, an in-flight delivery finishes, its
    queued events are dropped with one warning;
  - renamed: a removal and an addition.
- Queues are never closed under a sender: a `Notify` that races `Update` or
  comes after `Close` drops the event and counts it, and never panics.
- New row in ADR 0005's "State that outlives snapshots": *Hooks: one
  dispatcher; the hook set is replaced in place; queued events of a kept
  hook use its new spec, those of a removed hook are dropped.*
- **Checks.** `Validate` checks what needs no file system: names unique and
  non-empty, `on` and `mounts` values known, patterns valid, exactly one of
  `exec` and `webhook`, argv[0] absolute, the URL scheme and no user info,
  ranges. `CheckFS` and `CheckFSReload` add `secret_file` and the argv
  files to the trusted files, as secrets (refused in any mount, also of
  live generations): a location error fails start and reload, as for any
  trusted file. Content and permission problems (missing, mode, owner, a
  secret under 32 bytes, not executable) fail at start; on reload the
  running hook of that name keeps its spec, or a new hook is left out, with
  a warning in the reload result, and the reload succeeds (as host keys,
  ADR 0008: a broken hook file must not block revoking a user). Secrets
  are read in step 2; `Update` runs in step 3. `config validate
  --check-fs` runs the same checks.
- **Landlock (M4-08).** The ruleset is fixed at start and cannot grow. In
  v0.4, while exec hooks are configured, Landlock is not applied and the
  log says `landlock: not applied: exec hooks configured`; a reload that
  adds an exec hook while Landlock is applied is reported in
  `restart_required`. Webhooks need nothing beyond the existing rules.

### Logging and metrics

- Failures are logged at warn with the hook name, the event, the user and
  the reason (status code, exit status, unwrapped error); successes at
  debug.
- Metrics (ADR 0009), counted once per event per hook at its final
  outcome: `gosftpd_hook_deliveries_total{type, result}` with `type`
  `exec` or `webhook` and `result` `ok`, `failed` or `dropped` (a full
  queue, a removed hook, shutdown); `gosftpd_hook_retries_total` (webhook
  attempts after the first); `gosftpd_hook_queue_length`, queued plus
  in-flight events of all hooks. Hook names are not labels.
- Hook runs are not audit events: they are operational, and the event that
  fired them is in the audit log.

### Not in this ADR

- A synchronous hook that can refuse an upload before it is published
  (virus scanning): it needs `atomic_uploads` and its own design; the
  backlog gets it.
- Events other than file events (`auth.*`, `conn.*`, `server.*`).
- Custom headers, mutual TLS, a per-hook CA file, a persistent queue, a
  Windows job object.

### Code

`internal/hooks` holds the dispatcher, the exec and webhook runners and
their tests; it imports `obs` and nothing that imports it. The import
edges are `cli`, `server` and `sftpd` → `hooks`, `hooks` → `obs`, and
`config` → `hooks` for the list of event names (ROADMAP §4.2 is corrected:
no `hooks` → `config`). The cli converts `config.Hook` into `hooks.Spec`,
reading secrets, builds the dispatcher at start, calls `Update` on reload
and `Close` at shutdown. `audit.Logger.Render(event, attrs...)` formats an
event as the audit output would, with the logger's context, whatever
`audit.events` says. sftpd calls `Wants` and then `Notify` after each
audited file event with result ok.

Tests: `internal/hooks` has goleak in `TestMain` and a coverage floor in
test/coverage.sh; the signature test vector is a golden test; backoff and
`Retry-After` run under synctest with a fake transport; exec tests cover a
background child, a `setsid` grandchild, 1 MiB of output and the timeout
(Linux and macOS). An in-process test in `internal/cli` uploads with a
real SSH client to an `httptest` receiver that recomputes the signature
over the raw body, for `on_conflict = "rename"` (final_path differs from
path), atomic uploads and a `.filepart` upload plus rename (exactly one
delivery). The interop test adds a python3 receiver for OpenSSH sftp and
rclone (one delivery per file, with the final name) and a `/bin/sh` hook
from docs/hooks.md that receives the names `*`, `a b`, a name with a
newline, `-rf`, `$(touch pwned)` and a backtick name: each run acts on
exactly the uploaded file, nothing else moves, and no `pwned` appears.

## Consequences

- An exec hook runs with gosftpd's user; under Landlock it cannot run in
  v0.4 (see Reload). docs/hooks.md shows safe scripts: always `"$VAR"`,
  `--` before derived names, no `eval` or strings built for `sh -c`, and
  on Windows `"%GOSFTPD_HOST_PATH%"` or PowerShell's
  `$env:GOSFTPD_HOST_PATH`.
- The host path is a name the script resolves outside `os.Root`; the
  identity check narrows but cannot close the window.
- A webhook sends user names, addresses and paths to its receiver.
- Lost and duplicated events are possible by design and visible in the
  metrics and the log; the audit log is the record.
- The stop budget grows by up to 5 s.
