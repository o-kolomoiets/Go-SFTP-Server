# Hooks

A hook runs a program or calls a webhook when a file event succeeds: a
file arrives, is downloaded, renamed or removed. Hooks run asynchronously,
after the event; an SFTP request never waits for one, and a hook cannot
refuse an upload. The design is in [ADR 0010](adr/0010-hooks.md); the keys
are in [configuration.md](configuration.md#hooks).

```toml
# Tell a receiver about every file that arrives.
[[hooks]]
name = "notify"
on = ["fs.upload"]
exclude = ["*.filepart", "*.partial"]   # WinSCP's and rclone's temporary names
webhook = { url = "https://example.internal/hooks/sftp", secret_file = "/etc/gosftpd/hook.secret" }

# Move each file to an archive two minutes after it arrives.
[[hooks]]
name = "archive"
on = ["fs.upload"]
exclude = ["*.filepart", "*.partial"]
delay = "2m"
exec = { argv = ["/usr/local/bin/archive-upload"], timeout = "30s" }
```

## Events

`on` lists events: `fs.upload`, `fs.download`, `fs.rename`, `fs.remove`,
`fs.mkdir`, `fs.rmdir`, `fs.setstat`. A hook fires only when the event's
result is `ok`: an aborted, denied or failed operation never fires one.

- `fs.download` with result `ok` means that the client closed its handle,
  not that it read the whole file: a GUI client that cancels closes
  normally too. A hook that moves or removes a downloaded file compares
  `bytes` with the file's size first.
- `fs.setstat` fires only when gosftpd set the times of the file that
  `path` names. A chmod or chown (which gosftpd answers without changing
  anything), a SETSTAT that `setstat_mode = "ignore"` drops, and one that
  lands on a stat redirect or an open upload are audited but fire no
  hook.

`mounts`, `glob` and `exclude` narrow the events further. `glob` and
`exclude` are `path.Match` patterns, matched case-sensitively against the
base name of the event's file: `final_path` for uploads and renames, `path`
otherwise. `*.pdf` does not match `REPORT.PDF`; list both. These filters
select events; they are not a security control.

### A file arrived

An upload's result is `ok` when the client closed the file, which a client
that cancels a transfer does as well. A client that uploads to a temporary
name says more: it renames the file only when the transfer is complete.
WinSCP (files over 100 KiB) uploads `NAME.filepart`, rclone
`NAME.XXXX.partial`, and both rename it to `NAME`, rclone often from
another connection.

So a hook with `fs.upload` in `on` fires for two events:

- an `fs.upload`;
- an `fs.rename` with `"uploaded":true`: the first rename of a file the
  same user uploaded within the last hour, whose upload was closed without
  an error or a refused write and nobody changed since, while no upload of
  it is open.

The `fs.upload` of the temporary name fires as well; `exclude =
["*.filepart", "*.partial"]` leaves it out. With that, a hook fires once
per file for OpenSSH `put`, WinSCP and rclone. A file uploaded under its
own name and renamed later by its uploader fires once more.

A hook gets each event once, also when it matches several values of
`on`. The rename keeps its own name: `X-Gosftpd-Event` and `GOSFTPD_EVENT`
are `fs.rename`, and `path` is the temporary name. The file is always
`final_path`.

No hook fires for a rename that is not marked:

- the rename, or a resume before it, comes more than an hour after the
  uploader last changed the file, or after gosftpd restarted (what each
  user uploaded is kept in memory); for a user with the `upload` preset
  such a rename is refused;
- another user renames the file;
- an upload to the same name started again in between (a retry gives up
  what is there);
- WinSCP resumed the upload under `on_conflict = "rename"` or `"version"`
  or with `atomic_uploads`: the resume goes to a new file, and gosftpd
  never marks a file that a resume wrote into from the middle.

Some uploads fire no hook at all, also under their own name:

- an upload that opened an existing file without truncating it (a resume,
  or a WinSCP-style overwrite in place under `on_conflict = "overwrite"`)
  and changed nothing;
- an append-only resume of a file that is not the uploader's: another
  user's file, or the uploader's own more than an hour after they last
  changed it or after gosftpd restarted. Append-only resume needs only the
  `write` permission, so in a shared mount anyone could otherwise make a
  hook act on someone else's file;
- an upload whose result is not `ok`: a write refused (`max_file_size`,
  the append-only guard) or failed in the file system (a full disk).

## Payload

A hook gets the event as the audit log renders it (see
[audit-log.md](audit-log.md)), also when `audit.events` does not record its
category. It never contains a host path. Every `fs.*` event on a path in a
mount has `mount`, so a receiver can tell inboxes apart even when a user
with one mount sees `/report.pdf`:

```json
{"time":"2026-10-11T18:26:17.822637092Z","level":"INFO","msg":"audit","conn_id":"1a8db46260eb8b37","remote_addr":"203.0.113.7:51090","local_addr":"192.0.2.10:2022","user":"partner","session_id":"ce06b100c8cd0685","schema":1,"event":"fs.upload","mount":"inbox","path":"/report.pdf","final_path":"/report (1).pdf","conflict":"renamed","open_flags":"WRITE+CREAT+TRUNC","bytes":48000,"duration_ms":1,"result":"ok"}
```

The line, with its final newline, is the webhook body and the exec stdin.

## exec

```toml
exec = { argv = ["/usr/local/bin/archive-upload", "--quiet"], timeout = "30s" }
```

`argv` is run directly, never through a shell, and nothing from a client
is ever an argument. The program must be an absolute path that exists and
is executable: on Unix a regular file with an execute bit, on Windows a
file whose extension is in `PATHEXT` (`.exe`, `.com`, `.bat`, `.cmd`).
Every absolute element that is not a directory (the
program, a script given to an interpreter such as `["/bin/sh",
"/opt/hooks/archive.sh"]`) must lie outside every mount, and, if it is a
regular file, belong to root or to gosftpd's user and not be writable by
group or others; symlinks are followed, so `/bin/sh` is checked at its
target. That is checked at start and on reload, and the owner and mode
again just before each run: a script that became writable by others is not
run, and the run counts as failed. On Windows only the location is
checked.

The program gets:

| Variable | Value |
|---|---|
| `GOSFTPD_EVENT` | The event, such as `fs.upload`. |
| `GOSFTPD_USER` | The user name. |
| `GOSFTPD_MOUNT` | The mount's name. |
| `GOSFTPD_PATH` | The client path of the event (`path`). |
| `GOSFTPD_FINAL_PATH` | Uploads and renames: where the file is now. |
| `GOSFTPD_TARGET_PATH` | Renames: the name the client asked for. |
| `GOSFTPD_HOST_PATH` | The file on the host: of `final_path` for uploads and renames, of `path` otherwise. |
| `GOSFTPD_CONN_ID` | The connection's `conn_id` in the audit log. |
| `PATH` | gosftpd's `PATH` without empty or relative elements. |

Nothing else of gosftpd's environment is passed. stdin is the event line;
the working directory is `/` (on Windows, `%SystemRoot%`).

**Names come from clients.** They can hold spaces, newlines, quotes, `*`,
`$(...)` and a leading `-`. In a shell script:

- always quote: `"$GOSFTPD_HOST_PATH"`, never `$GOSFTPD_HOST_PATH`
  (unquoted, a file named `*` expands to every file in the directory);
- put `--` before names: `mv -- "$src" "$dst/"`;
- never build a command string from a name (`eval`, `sh -c "..."`,
  `xargs` without `-0`);
- get the base name with `${GOSFTPD_HOST_PATH##*/}`, not `$(basename ...)`,
  which drops trailing newlines;
- do not follow symlinks (`mv` renames a link itself; prefer it to `cp`),
  and treat a missing file as normal.

On Windows, quote `"%GOSFTPD_HOST_PATH%"` in batch files (NTFS names cannot
hold `"`) and keep delayed expansion off. In PowerShell, pass names with
`-LiteralPath $env:GOSFTPD_HOST_PATH`, never with `-Path` or as a
positional argument: those treat `[` and `]`, which Windows names may
contain, as wildcards, so `report[1].pdf` would name `report1.pdf`.

**The file is checked before the run.** gosftpd records the file's
identity when the event happens and, just before starting the program,
checks that `GOSFTPD_HOST_PATH` still names that file, of the same type,
and that it is a regular file or a directory. If the file is gone, a
symlink took its place or was what the client renamed, or another file is
there (a later upload under `version`, a mount repointed), the run is
skipped,
logged at info and counted as `skipped`. A file deleted and created again
under the same name can get the same inode and pass. Nothing closes the
race after the check: the script resolves the path with gosftpd's
privileges, so never run gosftpd, or its hooks, as root. Hooks on the same
event run independently and in no defined order; when one moves the file,
the others skip it, so chain such steps in one hook.

**Lifetime.** On Unix the program runs in a process group of its own. When
`timeout` runs out, at shutdown, and as soon as the program exits, the
whole group is killed: a hook cannot leave processes behind. Do not use
`setsid` to escape it (what still holds the program's output is cut off
2 s after it exits). For long work, hand the job to another service, for
example by writing a file into a spool directory that a systemd `.path`
unit watches. On Windows only the program itself is killed.

**Result.** Exit status 0 is a success. Any other status is a failure,
logged at warn with the first 4 KiB of stdout and stderr; the rest of the
output is read and discarded. An exec hook is not retried: it runs at most
once per event.

A safe archive script, for `delay = "2m"`:

```sh
#!/bin/sh
# archive-upload: move an arrived file to /srv/archive/USER/.
set -eu
src=$GOSFTPD_HOST_PATH
[ -f "$src" ] || exit 0            # moved or removed meanwhile
dest=/srv/archive/$GOSFTPD_USER    # user names come from the configuration
mkdir -p -- "$dest"
mv -n -- "$src" "$dest/"
```

## webhook

```toml
webhook = { url = "https://example.internal/hooks/sftp", secret_file = "/etc/gosftpd/hook.secret", timeout = "10s" }
```

gosftpd sends `POST url` with the event line as the body and these
headers:

| Header | Value |
|---|---|
| `Content-Type` | `application/json` |
| `User-Agent` | `gosftpd` |
| `X-Gosftpd-Event` | The event name. |
| `X-Gosftpd-Delivery` | 32 lowercase hex characters, the same in every attempt of one delivery. |
| `X-Gosftpd-Timestamp` | Unix seconds of this attempt. |
| `X-Gosftpd-Signature` | `sha256=` and the lowercase hex HMAC-SHA256, keyed with the secret, of `DELIVERY` `.` `TIMESTAMP` `.` `BODY`. |

The secret is the content of `secret_file` with leading and trailing white
space removed, used as bytes, never hex- or base64-decoded. It must be at
least 32 printable ASCII characters:

```sh
openssl rand -hex 32 > /etc/gosftpd/hook.secret
chown gosftpd: /etc/gosftpd/hook.secret && chmod 0600 /etc/gosftpd/hook.secret
```

On Windows, write it with `Set-Content -Encoding ascii`: a file saved as
UTF-16 or with a byte order mark is refused.

**Test vector.** With the secret
`3f9a1c6e2b7d4f8a0c5e9b1d6a3f7c2e8b4d0a6f1c9e5b7a2d8f4c0e6b3a9d1f`, the
delivery `0123456789abcdef0123456789abcdef`, the timestamp `1760000000` and
the 49-byte body `{"event":"fs.upload","final_path":"/report.pdf"}` with
a final newline, the signature is
`sha256=123e292743c83aa82711008c58844636b1744dd867f0e811a24154cc4f3b2f41`.

**A receiver** must verify the signature over the raw body, before parsing
it, and compare in constant time; refuse timestamps more than 5 minutes
off; and remember delivery IDs for at least 20 minutes (the 5 minutes plus
the retry span, which reaches about 13 minutes with `timeout = "60s"` and
`Retry-After`), so that it handles
a retry, or a replayed request, only once. In Python:

```python
import hashlib, hmac, time

def accept(secret: bytes, headers, body: bytes, seen: set[str]) -> int:
    delivery = headers["X-Gosftpd-Delivery"]
    timestamp = headers["X-Gosftpd-Timestamp"]
    mac = hmac.new(secret, f"{delivery}.{timestamp}.".encode() + body, hashlib.sha256)
    if not hmac.compare_digest("sha256=" + mac.hexdigest(), headers["X-Gosftpd-Signature"]):
        return 401
    if abs(time.time() - int(timestamp)) > 300:
        return 401
    if delivery in seen:
        return 200  # a retry of something already handled
    seen.add(delivery)
    # ... handle the event: the file is body["final_path"] in body["mount"]
    return 200
```

**Rotating the secret.** Add the new secret to the receiver next to the old
one; write the new `secret_file` (0600 owned by gosftpd's user, or 0640
`root:gosftpd`); check it as the service's user, `sudo -u gosftpd gosftpd
config validate --check-fs` (run as root, the check would pass a root-owned
0600 file that gosftpd cannot read); reload gosftpd and check that
`gosftpd_hooks_not_updated` is 0, or, without the admin listener, that the
reload logged no warning for the hook (a secret file that cannot be used
keeps the old secret, with a warning); then remove the old secret from the
receiver.

**URL.** `https`, or `http` with a warning unless the host is loopback. User
info in the URL is refused. The URL's path or query may hold a token (Slack,
n8n): logs show only `scheme://host`, never the path or query. Proxies from
the environment (`HTTPS_PROXY`, `NO_PROXY`) are used; redirects are not
followed (a 3xx is a failure). TLS verifies against the system roots, which
gosftpd loads at start: on Linux and the BSDs, `SSL_CERT_FILE` or
`SSL_CERT_DIR` add a private CA; macOS and Windows use the system store. A
new CA needs a restart.

**Retries.** A 2xx is a success. A network error, a timeout, 408, 429 and
5xx are retried: at most 5 attempts, after 1, 5, 30 and 120 seconds
(± 20 %); a `Retry-After` is honored up to 120 seconds. Other statuses fail
at once. Failed attempts are logged at debug, the final failure once at
warn. A failing event holds its worker for about 3 minutes.

## Queue and delivery

Each hook has its own queue of `queue` events (default 1000) and at most
64 MiB; enqueueing never blocks an SFTP request. When the queue is full,
new events are dropped, with a warning at most once a minute that counts
them per user. `concurrency` workers (default 1) deliver the events; a
worker keeps an event through its delay and every attempt, so with one
worker the events of a hook run in order.

`delay` holds each event for that long before its first attempt. Events
wait in the queue meanwhile, so a delayed hook holds every event of the
last `delay`: size `queue` for the peak rate times the delay (2 minutes at
10 files a second is 1200 events). With a delay, `queue` defaults to
10000.

**Guarantees.** A webhook is delivered at least once while gosftpd runs:
retries can deliver it twice, so receivers deduplicate on
`X-Gosftpd-Delivery`. An exec hook runs at most once. Any event can be
lost: a full queue, exhausted retries, a permanent status, a skipped run,
a hook removed by a reload, shutdown, a crash; and a temporary-name upload
whose rename is not marked fires no hook at all (see
[A file arrived](#a-file-arrived)). The queue lives in memory.
The audit log is the complete record: a receiver that must not miss a file
reconciles against it or the directory, and a hook that moves or deletes
files is paired with a periodic sweep for those it missed.

### Shutdown

On SIGTERM, hooks keep delivering while transfers finish. When the drain
ends, pending delays are skipped (no client can race any more), and hooks
get what is left of `server.shutdown_timeout`, at least 5 seconds. Then
running programs are killed and webhook attempts cancelled; what was not
delivered is counted as `dropped` and logged at warn with the hook, user,
mount and path, so that it can be replayed. A restart can drop up to rate ×
`delay` events of a delayed hook.

A stop then takes up to `shutdown_timeout` + 8 seconds. With hooks, keep
`shutdown_timeout` at least 10 seconds below systemd's `TimeoutStopSec` and
Docker's `stop_grace_period`. A systemd unit should set `KillMode=mixed`,
so that only gosftpd gets SIGTERM and what hooks left is killed once it has
exited.

## Reload

A reload replaces the hooks in place, for open connections too: removing a
hook or rotating its secret takes effect at once, also for a client that
stays connected for days.

- A hook that keeps its name and kind keeps its queue. Its events that have
  not been attempted yet, also those waiting out their delay, are checked
  against the new `on`, `mounts`, `glob` and `exclude` when their delay
  ends, and every attempt uses the URL, secret, program and timeout
  current when it starts; a retry after a secret rotation is signed with
  the new secret. A smaller `queue` refuses new events until the queue is
  below it and drops none that wait.
- A removed hook takes no more events; an attempt or run in progress
  finishes, and everything else of it is dropped.
- A hook renamed, or changed between `exec` and `webhook`, is removed and
  added.
- A hook whose program fails its checks is left out until a reload fixes
  it. One whose `secret_file` cannot be used keeps its running secret. Both
  give a warning, are counted in `gosftpd_hooks_not_updated`, and do not
  fail the reload. A hook file inside a mount fails the reload, as every
  file gosftpd trusts does.

## Logs and metrics

Failures are logged at warn with the hook name, the event, the user and the
reason (status, exit status, error); skipped runs at info; successes at
debug. Hook runs are not audit events: the event that fired them is in the
audit log.

With the admin listener on ([metrics.md](metrics.md)):

| Metric | Meaning |
|---|---|
| `gosftpd_hook_deliveries_total{type, result}` | Once per event and hook, at its final outcome: `type` is `exec` or `webhook`, `result` is `ok`, `failed`, `skipped` (exec: the file changed) or `dropped`. |
| `gosftpd_hook_retries_total` | Webhook attempts after the first. |
| `gosftpd_hook_queue_length` | Events queued or being delivered, of all hooks; with a delay, normally rate × delay. |
| `gosftpd_hooks_not_updated` | Hooks the last reload left out or kept at their running secret. Alert when above 0. |

## Sandboxes and containers

An exec hook runs as gosftpd's user and inherits its sandbox. Under a
systemd unit with `ProtectSystem=strict`, it can write only the paths the
unit allows (`ReadWritePaths=`, the state and log directories); `PrivateTmp`
gives it a private `/tmp`, `ProtectHome` hides `/home`,
`MemoryDenyWriteExecute=yes` stops JIT runtimes such as node or java, and
`NoNewPrivileges` stops sudo. A hook that writes elsewhere needs a drop-in:

```ini
# /etc/systemd/system/gosftpd.service.d/archive.conf
[Service]
ReadWritePaths=/srv/archive
```

In a container without an init, gosftpd is PID 1 and does not reap what an
exec hook leaves; it warns about it. Run the container with `docker run
--init` (or `init: true` in Compose).

## Recipes

- **Notify a receiver of each arrived file:** the `notify` hook above.
- **Archive arrived files:** the `archive` hook above with the script under
  [exec](#exec). A hook that moves or deletes uploads empties the inbox,
  and sync-style clients (`rclone copy` or `sync`, WinSCP Synchronize,
  `lftp mirror -R`) then upload those files again on their next run: point
  such partners to `rclone move`, or keep files and expire them by age
  (systemd-tmpfiles) instead.
- **Process downloads:** `on = ["fs.download"]`, and compare `bytes` with
  the file's size before acting.
