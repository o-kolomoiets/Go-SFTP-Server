# ADR 0010: Hooks (exec and webhook)

- **Status:** draft 3, 2026-10-11; amends ADR 0005 (state that outlives
  snapshots), the audit schema (additive) and vfs's owned-file rule
- **Context:** ROADMAP M4 (M4-07) asks for `[[hooks]]`: filters `on`,
  `mounts`, `glob`; `exec` (argv without a shell, `GOSFTPD_*` environment,
  a timeout); `webhook` (POST of the audit event as JSON, an HMAC-SHA256
  signature in `X-Gosftpd-Signature`, retries with backoff, a bounded
  queue); asynchronous. The persona U2 (a team receiving files from
  partners) wants "a webhook on upload completion", with WinSCP and rclone
  temp-file uploads; the retention recipe moves uploaded files with an exec
  hook. Hooks are the only way gosftpd starts processes or makes outgoing
  connections (design principle 2). Three reviews of draft 1 (operations,
  security, integration with the code) confirmed 29 findings; three
  reviews of draft 2 (coverage of those, implementability, new risks)
  confirmed 36 more. Every finding was checked by a second reviewer.

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
# queue: events waiting, 1 to 10 000; default 1000, or 10 000 with a delay
```

A hook has exactly one of `exec` and `webhook`. Hooks are reloadable (see
Reload).

- `on`: `fs.upload`, `fs.download`, `fs.rename`, `fs.remove`, `fs.mkdir`,
  `fs.rmdir`, `fs.setstat`. A hook fires only for an event with
  `"result":"ok"`: an aborted, denied or failed operation never fires one.
  `fs.download` with result ok means the client closed its handle, not that
  it read the whole file (a cancelled transfer closes normally): a hook
  that removes or moves a downloaded file first compares `bytes` with the
  file's size.
- **`fs.upload` means "a file arrived".** WinSCP (files over 100 KiB) and
  rclone upload to a temporary name (`NAME.filepart`, `NAME.XXXX.partial`)
  and then rename it, often from another connection. vfs already keeps,
  for an hour (`OwnTTL`), the files each user created, so that the `upload`
  preset can finish such renames. It now also keeps whether the file's
  last upload was closed with result ok. The first rename of such a file
  after that close, while no upload of it is open, gets `"uploaded":true`
  in the audit log and clears the flag (a setstat by the owner keeps it); a
  later rename of the same file is a plain `fs.rename`. An aborted or
  refused upload, or one still being written, keeps the rename permission
  but not the mark.
  - A resume (APPEND, or WRITE without CREAT and TRUNC) of a file that is
    the user's when the resume opens keeps it the user's: its close records
    the file again, as a new upload's does. A resumed `.filepart` can then
    be renamed under `upload` (refused today, a vfs bug since M3), and the
    rename is marked if the resume closed ok.
  - Hooks with `fs.upload` in `on` fire for a marked rename too. The
    `fs.upload` of the temporary name fires as well; `exclude` (or `glob`)
    leaves it out, so the hooks above fire once per temp-file upload for
    OpenSSH, WinSCP and rclone alike. A hook whose filters accept the name
    a file was uploaded to (a plain `put`) sees the file again, once, if
    its uploader renames it.
- `mounts`: mount names, compared as mount names are (case-insensitively);
  a name that is not configured is an error.
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
  rclone set its times; `stat_redirect` lasts 60 s), so a hook that moves
  or deletes the file must wait: at least `"1m"`, `"2m"` in the docs. The
  delay is the same for every event of a hook, so order is kept. **A
  delayed hook holds every event of the last `delay` in its queue**:
  `queue` must be at least the peak events per second times the delay (a
  queue of 1000 with `"2m"` overflows above about 8 files a second), so
  with a delay `queue` defaults to 10 000.

### Events and payload

A hook gets the event as the audit log renders it: the same JSON line with
the session context (`conn_id`, `remote_addr`, `local_addr`, `user`,
`session_id`) and the event's fields, also when `audit.events` leaves the
event's category out. It never contains a host path. The bytes rendered are
the webhook body and the exec stdin, unchanged.

Two additions to the audit schema, additive within schema 1 (ROADMAP §6.4
already lists the first), both optional in `audit.schema.json`:

- every `fs.*` event whose path lies in a mount gets `mount`, the mount's
  name. With `flatten` (the default) a user with one mount sees
  `/report.pdf`, so without it a receiver could not tell inboxes apart. An
  event on the virtual root of a session with several mounts (`fs.list /`)
  or on a path that names no mount has none;
- `fs.rename` gets `"uploaded":true` as above.

A hook gets each event once, even when it matches several `on` values. A
marked rename keeps its own name: `X-Gosftpd-Event` and `GOSFTPD_EVENT`
are `fs.rename`, and `path` is the temporary name. A file arrived when
`event` is `fs.upload`, or `fs.rename` with `uploaded`; the file is always
`final_path` (`GOSFTPD_FINAL_PATH`, `GOSFTPD_HOST_PATH`), and docs/hooks.md
says so.

sftpd first asks the dispatcher whether any hook wants the event
(`Wants(event, uploaded, mount, name)`, nil-safe and allocation-free) and
renders the line only then. Out of band, for exec only, it passes the host
path of the file and its identity, both returned by vfs with the operation
(see exec), and the connection's `conn_id`, which `server` passes to
`sftpd.New`.

### exec

- `argv[0]` must be absolute, exist and be executable. Nothing from a
  client is ever an argument.
- **Trusted files.** Every absolute argv element that is not an existing
  directory (argv[0], a script given to an interpreter such as
  `["/bin/sh", "/opt/hooks/archive.sh"]`, a file that does not exist yet)
  is checked for location like a trusted file: not inside any mount, also
  the mounts of live generations on reload. If it exists and is a regular
  file, it must also be owned by root or gosftpd's user and not writable by
  group or others; devices such as `/dev/null` are not checked further.
  Elements other than argv[0] may be missing and need not be executable.
  `["/bin/sh", "<mount>/x.sh"]` is refused whether or not `x.sh` exists;
  `["/usr/bin/find", "<mount>"]` is accepted.
- **Environment:** gosftpd's `PATH` without empty or relative elements,
  plus `GOSFTPD_EVENT`, `GOSFTPD_USER`, `GOSFTPD_MOUNT`, `GOSFTPD_PATH`,
  `GOSFTPD_FINAL_PATH` (uploads and renames), `GOSFTPD_TARGET_PATH`
  (renames), `GOSFTPD_HOST_PATH` and `GOSFTPD_CONN_ID`. Values are passed
  as they are; names can contain spaces, newlines, quotes, `*`, `$(...)`
  and a leading `-`.
- **`GOSFTPD_HOST_PATH`** is the host path of `final_path` for `fs.upload`
  and `fs.rename`, of `path` otherwise: the mount root's host path (for a
  home mount, the user's directory) joined with the relative name.
- **Identity check.** For every event except `fs.remove` and `fs.rmdir`,
  vfs returns the file's identity with the operation, taken through the
  mount's `os.Root` and without permission checks: `Stat` of the open file
  before an upload or download handle is closed, the `Lstat` that `Move`
  makes before renaming (the inode survives the rename), an `Lstat` of the
  directory `Mkdir` made or of the file a setstat changed; never
  `Session.Lstat`, which needs `list` and follows stat redirects. Just
  before starting the process, the runner `Lstat`s the host path and
  requires `os.SameFile` with that identity and the same file type. If the
  file is gone, has another type (a symlink swapped in by a local user) or
  is another file (a mount repointed under an old connection, a later
  upload under `version`), the run is skipped, logged at info as "file
  changed before the hook ran" and counted as `skipped`. A file deleted
  and created again under the same name can get the same inode number
  (ext4 reuses it at once), so a regular file that replaced the upload
  passes; the change time is not compared, because clients set times and
  rename within the delay. Nothing closes the race after the check: a hook
  must not follow symlinks (`mv -T`, `cp -P`), must not run as root, and
  must treat a missing file as normal. Hooks on the same event run
  independently and in no defined order; when one moves or deletes the
  file, the others skip it, so chain such steps in one hook.
- **Working directory** `/` (on Windows `%SystemRoot%`). stdin is the event
  line.
- **Lifetime.** On Unix the process gets its own process group. When the
  `timeout` (default 30 s, at most 1 h) runs out, at shutdown, and also
  when the leader exits, the whole group is killed with SIGKILL. A process
  that calls `setsid` leaves the group, so a hook must not do that;
  `WaitDelay` is 2 s, so pipes held by such a process cannot block a
  worker. To start long work, hand it to another service, for example a
  job file in a spool directory that a systemd `.path` unit watches
  (`systemd-run` would need a polkit rule that lets gosftpd's user start
  units as root: do not add one). The result is the leader's exit status;
  `ErrWaitDelay` after exit 0 is a success, logged. On Windows only the
  process is killed. If exec hooks are configured and gosftpd is PID 1, a
  warning says that orphans are not reaped (use `docker run --init`).
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
  decoded. It must then be printable ASCII (0x21 to 0x7E) and at least 32
  bytes (`openssl rand -hex 32`); anything else, such as a BOM or UTF-16,
  is refused with the hint "saved as UTF-16 or with a BOM?". The file is
  checked like a trusted secret: refused inside any mount; owner root or
  gosftpd's user; no permissions for others and no write for group (0400,
  0440, 0600 and 0640 pass; symlinks are followed, so Kubernetes secret
  volumes work; no mode check on Windows). It is read again on reload. No
  inline secret. docs/hooks.md publishes a test vector (secret, delivery,
  timestamp, body, signature), checked by a golden test, and the
  receiver's duties: verify over the raw body, compare in constant time,
  refuse timestamps more than 5 minutes off, remember delivery IDs for
  that window plus the retry span. Rotation: add the new secret to the
  receiver; write the new `secret_file`; run `gosftpd config validate
  --check-fs`; reload and check that `gosftpd_hooks_not_updated` is 0;
  only then remove the old secret from the receiver.
- `url`: `https`, or `http` with a warning unless the host is loopback. User
  info in the URL is refused.
- **No token in logs.** The URL path or query may hold a token (Slack,
  n8n): a failure is logged with the hook name, `scheme://host` and the
  unwrapped cause (`url.Error.Err`), never the URL or `err.Error()` of the
  client call. At most 4 KiB of a response body is read, never logged. A
  test sends deliveries to `https://HOST:PORT/secret-token?k=secret-query`
  that fail by a refused connection, a TLS error, a timeout and a 500, and
  checks that the log contains neither `secret-token` nor `secret-query`.
- Proxies from the environment (`HTTPS_PROXY`, `NO_PROXY`) are used;
  redirects are not followed (a 3xx is a failure). TLS uses the system
  roots: on Linux and the BSDs `SSL_CERT_FILE` or `SSL_CERT_DIR` add a
  private CA; macOS and Windows use the system store. gosftpd loads the
  roots at start (`x509.SystemCertPool`), also without webhooks since a
  reload can add one, so a new CA needs a restart.
- `timeout` per attempt (default 10 s, at most 60 s).
- A 2xx is delivered. A network error, a timeout, 408, 429 and 5xx are
  retried: at most 5 attempts, after 1, 5, 30 and 120 s (± 20 % jitter);
  `Retry-After` is honored and clamped to 120 s. Other statuses are
  permanent failures. Failed attempts are logged at debug, the final
  failure once at warn with the attempt count.

### Queue and delivery

- Every hook has a bounded queue: `queue` events (see `delay`; at most
  10 000) and at most 64 MiB of rendered lines (a line can reach about
  100 KB: an `fs.rename` with four long, escaped paths). Enqueueing never
  blocks an SFTP request: when either bound is reached, the new event is
  dropped. A warning at most once a minute gives the count per user and
  the hook's `delay` and `queue`.
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
  not miss a file reconciles against it or the directory, and a hook that
  moves or deletes files is paired with a periodic sweep.
- **Shutdown.** Hooks keep delivering during the SFTP drain. When it ends,
  pending delays are skipped (no client can race any more), and hooks get
  what is left of `server.shutdown_timeout`, at least 5 s. Then running
  processes are killed and their workers return within `WaitDelay` (2 s);
  what is still queued or waiting for a retry is counted as `dropped` and
  logged, each at warn with the hook name, user, mount and `final_path`
  (or `path`), so it can be replayed. A restart can drop up to rate ×
  `delay` events of a delayed hook. A stop takes at most
  `shutdown_timeout` + 5 s + 2 s + 1 s (the admin listener). With hooks,
  `shutdown_timeout` + 10 s must stay at or below `TimeoutStopSec` and
  `stop_grace_period` (docs/configuration.md and ROADMAP §7.5 say so), and
  docs/metrics.md's budget becomes preStop + `shutdown_timeout` + 10 s.
  The M4-08 unit gets `KillMode=mixed`, so that systemd sends SIGTERM only
  to gosftpd and SIGKILLs left-over hook processes once gosftpd has
  exited.

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
  - kept: its queue and workers stay. A pending event is delivered only if
    it still matches the new `on`, `mounts`, `glob` and `exclude` (the
    others are counted as `dropped`, with one warning), and it uses the new
    url, secret, argv, timeout and delay. `queue` and `concurrency` are
    resized; events above a smaller queue are dropped;
  - removed: it takes no more events, an in-flight delivery finishes, its
    queued events are dropped with one warning;
  - renamed, or changed between `exec` and `webhook`: a removal and an
    addition (pending events of a webhook carry no host path or identity).
- Queues are never closed under a sender. A `Notify` for a hook that a
  concurrent `Update` removed, or one after `Close`, drops the event,
  counts it and never panics; a kept hook's events are not affected.
- New row in ADR 0005's "State that outlives snapshots": *Hooks: one
  dispatcher; the hook set is replaced in place; pending events of a kept
  hook are filtered again and use its new spec, those of a removed hook are
  dropped.*
- **Checks.** `Validate` checks what needs no file system: names unique and
  non-empty, `on` and `mounts` values known, patterns valid, exactly one of
  `exec` and `webhook`, argv[0] absolute, the URL scheme and no user info,
  ranges. `CheckFS` and `CheckFSReload` add `secret_file` and the argv
  files to the trusted files, as secrets (refused in any mount, also of
  live generations): a location error fails start and reload, as for any
  trusted file. Content and permission problems (argv[0] missing or not
  executable; `secret_file` missing, not printable ASCII, under 32 bytes;
  a bad owner or mode of `secret_file` or of an existing argv file) fail at
  start. On reload the reload succeeds, with a warning in the operational
  log (a broken hook file must not block revoking a user; `server.reload`
  gets no new field):
  - a `secret_file` problem keeps the running secret, which is held in
    memory (as host keys keep theirs, ADR 0008);
  - an argv problem leaves the hook out, so a running hook of that name is
    removed as above: its files run as they are at each run, so an
    untrusted one must not run (as an untrusted `authorized_keys` file
    gives no keys, ADR 0005);
  - a new hook with either problem is left out;
  - the gauge `gosftpd_hooks_not_updated` counts the hooks the last reload
    kept at their running secret or left out (alert when above 0, as for
    `gosftpd_mounts_unavailable`).

  Hook specs are built and secrets read in step 2, before `CheckFSReload`;
  `Update` runs in step 3. `config validate --check-fs` runs the same
  checks.
- **Landlock (M4-08).** The ruleset is fixed at start and cannot grow. In
  v0.4, while exec hooks are configured, Landlock is not applied and the
  log says `landlock: not applied: exec hooks configured`; a reload that
  adds an exec hook while Landlock is applied is reported in
  `restart_required`. Webhooks need nothing beyond the existing rules,
  since the TLS roots are loaded at start, before the ruleset.

### Logging and metrics

- Failures are logged at warn with the hook name, the event, the user and
  the reason (status code, exit status, unwrapped error); skipped runs at
  info, successes at debug.
- Metrics (ADR 0009), counted once per event per hook at its final
  outcome: `gosftpd_hook_deliveries_total{type, result}` with `type`
  `exec` or `webhook` and `result` `ok`, `failed`, `skipped` (exec: the
  identity check) or `dropped` (a full queue, a removed hook or one whose
  filters no longer match, shutdown); `gosftpd_hook_retries_total`
  (webhook attempts after the first); `gosftpd_hook_queue_length`, queued
  plus in-flight events of all hooks; `gosftpd_hooks_not_updated` (see
  Reload). Hook names are not labels.
- Hook runs are not audit events: they are operational, and the event that
  fired them is in the audit log.

### Not in this ADR

- A synchronous hook that can refuse an upload before it is published
  (virus scanning): it needs `atomic_uploads` and its own design; the
  backlog gets it.
- Events other than file events (`auth.*`, `conn.*`, `server.*`).
- Custom headers, mutual TLS, a per-hook CA file, a persistent queue, a
  Windows job object.
- Under `on_conflict = "rename"`, renaming a fixed temporary name after a
  retried upload moves the earlier, partial file, not the retry's copy (vfs
  since M3). With this ADR that rename is not marked (the partial upload
  was aborted), so no hook fires on the partial file; vfs fixes the move
  separately (TASKS).

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
audited file event with result ok. vfs returns, with each operation, the
mount name, the host path and the identity (`vfs.Moved` gets `Uploaded`,
`Mount`, `HostPath` and `Info`; uploads, downloads, mkdir and setstat get
the same through their handles or results).

Tests: `internal/hooks` has goleak in `TestMain` and a coverage floor in
test/coverage.sh; the signature test vector is a golden test; backoff and
`Retry-After` run under synctest with a fake transport; exec tests cover a
background child, a `setsid` grandchild, 1 MiB of output and the timeout
(Linux and macOS); the URL-token test above; a reload that narrows `mounts`
while delayed events are pending delivers none of the removed mount's
events. vfs tests: an aborted `.filepart` upload with bytes written, a
retry and the client's rename give no mark; a reput after an interrupted
upload and the rename, as an `upload` user, succeed and give one mark; an
upload to `x.filepart` and 100 renames back and forth give one mark. An
in-process test in `internal/cli` uploads with a real SSH client to an
`httptest` receiver that recomputes the signature over the raw body, for
`on_conflict = "rename"` (final_path differs from path), atomic uploads and
a `.filepart` upload plus rename (exactly one delivery), and checks that
the webhook of a flattened single-mount user carries `"mount":"inbox"` and
`final_path` `/report.pdf`. The interop test adds a python3 receiver for
OpenSSH sftp and rclone (one delivery per file, with the final name) and a
`/bin/sh` hook from docs/hooks.md that receives the names `*`, `a b`, a
name with a newline, `-rf`, `$(touch pwned)` and a backtick name: each run
acts on exactly the uploaded file, nothing else moves, and no `pwned`
appears.

## Consequences

- An exec hook runs with gosftpd's user and inherits its systemd sandbox.
  Under the M4-08 unit (`ProtectSystem=strict`, `ReadWritePaths=-/srv/sftp`,
  `PrivateTmp`, `ProtectHome`, no capabilities, `NoNewPrivileges`,
  `MemoryDenyWriteExecute`), it can write only /srv/sftp and gosftpd's
  state and log directories, has a private /tmp, cannot see /home, can
  neither use sudo nor chown, and cannot run a JIT runtime such as node or
  java. A destination elsewhere (the retention recipe's archive) needs a
  drop-in `ReadWritePaths=`, which docs/hooks.md and the recipe show.
  Under Landlock an exec hook cannot run in v0.4 (see Reload).
- docs/hooks.md shows safe scripts: always `"$VAR"`, `--` before derived
  names, no `eval` or strings built for `sh -c`, and on Windows
  `"%GOSFTPD_HOST_PATH%"` or PowerShell's `$env:GOSFTPD_HOST_PATH`.
- The host path is a name the script resolves outside `os.Root`; the
  identity check narrows but cannot close the window, and it does not tell
  a regular file created again under the same name from the uploaded one.
- A webhook sends user names, addresses and paths to its receiver.
- Lost and duplicated events are possible by design and visible in the
  metrics and the log; the audit log is the record.
- A hook that moves or deletes uploads empties the inbox. Sync-style
  clients (`rclone copy` or `sync`, WinSCP Synchronize, `lftp mirror -R`)
  then upload those files again on their next run. The retention recipe
  says so and points such partners to `rclone move` or `--max-age`, or
  uses age-based retention (systemd-tmpfiles).
- The stop budget grows by up to 7 s.
