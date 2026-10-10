# ADR 0005: Configuration reload on SIGHUP

- **Status:** accepted, 2026-10-09
- **Context:** ROADMAP M4 asks for a reload without restart: validate the new
  configuration first, then switch to it; new sessions use the new
  configuration, existing ones keep the old. Until v0.3 the server read its
  configuration from a plain struct, bound the public-key callback to the
  startup authenticator, kept bans, connection counts, upload registries
  and the audit file in objects built once, and ignored SIGHUP. Three
  adversarial reviews of a first draft (lifetime, security, operability)
  shaped the decisions below; their findings are noted where they changed
  the design.

## Decision

**Snapshots.** The server keeps the reloadable configuration in an
immutable snapshot behind `atomic.Pointer`: authenticator, mount table,
grants, methods, bans, timeouts and limits. A connection uses three
snapshots, each for one purpose:

1. the one current at accept, for its transport: handshake timeout,
   `MaxAuthTries`, the methods it offers;
2. the current one at every authentication attempt (the callbacks load it);
3. after the handshake, the then current one, if the login passes it. The
   connection holds that snapshot, and a reference to its mount table, for
   the rest of its life, for every SFTP session it opens.

Step 3 re-runs the login decision (`auth.Recheck`) against the snapshot it
pins, without verifying a password again: the user still exists, is not
disabled or expired and may log in from that address, and still has the
key the login used, unexpired and with the same options, or the same
password hash. x/crypto caches the result of a public-key query and does not
call the callback again for the signed request, so a key removed between
the two (a passphrase prompt, a security key touch) needs another check
(review finding). Since M4b, `VerifiedPublicKeyCallback` checks the account
and the key against the current snapshot once the client has proved that
it holds the key, which refuses such a login with `reason = "removed"`;
step 3 still catches a reload that lands after that. A refused login is audited as `auth.failure` and
`conn.close` with `result = "revoked"`, and counts toward bans.

**Removed users.** With `reload.disconnect_removed_users = true`, a reload
closes the connections whose login the new snapshot would refuse (the same
`Recheck`, so a removed key, a changed password or a narrowed `allow_from`
count too, not only removed users). A connection registers before it reads
the current snapshot in step 3, and a reload stores the new snapshot before
it scans the registered connections, both under one lock: every connection
is either scanned or pins the new snapshot (review finding).

**Mount table generations.** A reload builds a new table from the old one
(`vfs.Table.Reload`). A mount whose host directory is open in any generation
still in use (same path, and `os.SameFile` of the path against the opened
root) shares that directory, also when a generation in between left the
mount out; a mount whose directory changed, for example because a disk was
mounted over the path, opens it anew. A home mount does not share the
directory of a plain mount (the parent of `{user}`), since registry entries
are relative to a session's root (review finding). Directories are
reference-counted by the tables that use them, and tables by the
connections that pin them (`Acquire`, `Close`). A pin is taken with a
compare-and-swap that fails once the count is zero, and the server then
reads the pointer again, so a pin can never revive a closed table
(review finding: counting SFTP sessions instead of connections, or a load
followed by an increment, could close a directory still in use). The
caller (`cli`) holds the reference of the current table and drops the old
one after the switch. A build that fails drops only the references it took.

Generations share one registry of uploads (one writer per file) and of
users' files (ownership, stat redirects). Its entries name a directory, not
a mount: a repointed mount does not inherit the entries of its old
directory, and nothing has to be dropped on reload (review finding). An
uploader may set the times of its own uploads without `setstat` only while
it still has `write`, so a reload that takes `write` away ends that too.

**Unavailable mounts.** On reload, a mount that fails its checks
(`require_mountpoint`, a missing directory) or cannot be opened is left out
as unavailable, with a warning, instead of failing the reload: users granted
it see it as unavailable, and their other mounts keep their paths (a
flattened single mount is not flattened while another is unavailable, so an
upload meant for `/disk/x` cannot land in another mount). At start, these
are still errors.

**State that outlives snapshots** is changed in place:

| State | On reload |
|---|---|
| Ban table | kept, with the new options (set under its lock); turning bans off drops it; it lives in the snapshot, so readers load it once |
| Connection limiter | kept; limits are plain counters under a lock (the pre-authentication limit was a channel whose capacity cannot change); connections above a lowered limit stay |
| Password hashing slots | one object (slots and the mutex for multi-lane hashes) shared by every authenticator generation; sharing only the slots could deadlock two generations hashing at once (review finding) |
| Password padding | kept while the kinds and costs of hashes are unchanged; rebuilt otherwise, so that a new costlier hash cannot reveal its users |
| VFS registry | shared, see above |
| Audit output | one writer whose file is reopened or switched under its lock |
| Log level | a `slog.LevelVar` |

**The reload procedure** (`cli`), serialized by one mutex:

1. Reopen the audit file at its current path, before anything else and
   whatever the reload's result: logrotate moved it. If it cannot be
   opened, the rotated file is closed anyway and every write fails, and
   retries, until it can: fail-closed engages instead of writing into a
   file that logrotate will compress and delete (review finding). Then
   probe the audit log at once, so that a fixed log recovers without
   waiting for the next probe.
2. Read the same file as at start (its absolute path, not a new search),
   with the same flags and environment (`--read-only` keeps working);
   `Validate`; `CheckFSReload`; build the authenticator with `Reload`
   (below); open the new mount table; open a changed `audit.output`.
3. Switch: `server.Reload` (stores the snapshot, carries state over, closes
   revoked connections), switch the audit output, set the log level, drop
   the old table.
4. Audit `server.reload` with `result`, `duration_ms`, and `reason`
   (`config`, `mounts`, `audit_output`) or `restart_required` and
   `disconnected`. The error text goes only to the operational log: it can
   name host paths, which the audit log never does.

Everything that can fail happens in step 2, and nothing in step 2 changes
running state; step 3 cannot fail.

**Revocation does not depend on unrelated files.** On reload, an
`authorized_keys` file that is missing, not a regular file, not trusted or
without usable keys gives no keys, with a warning, instead of failing the
reload: deleting a file, or linking it to `/dev/null`, revokes its keys, and
one user's broken file does not block another user's revocation (review
finding). Only a pipe (the one of `--authorized-keys <(...)`), which can be
read once, keeps the keys read from it before. With `--dir`, a missing
directory is unavailable on reload, as a mount is. Host keys are read again
on reload since ADR 0008, and one that cannot be used keeps the running host
keys instead of failing the reload.

**Restart-only settings** keep their running value; a change is logged as a
warning and listed in `restart_required`: `server.listen`,
`server.host_key_auto_generate`, `server.crypto_policy`, `log.format`,
`audit.events` and `audit.on_error`. (`server.host_keys` was on this list
until ADR 0008 made host keys reloadable.) A value of the file hidden by a flag or the environment
(`log.level`, `audit.output`) is reported on reload. With Landlock (M4d), a
mount path outside the ruleset will be restart-only too.

**Trusted files outside mounts.** Reload makes files that clients could
write take effect at the next routine HUP. So `CheckFS` (at start and on
reload) refuses the configuration, included files, `authorized_keys` files,
host keys and the audit log inside a mount clients can write, and host keys
and configuration files (password hashes) inside any mount; an audit log in
a read-only mount gives a warning (review finding). On reload, the mounts of
every generation that connections still use count too: a connection of an
earlier configuration may still write a directory the new one made
read-only. "Inside" follows symlinks and, on Linux, bind mounts
(`/proc/self/mountinfo`: one directory shown at two paths).

**Signals and systemd.** SIGHUP is caught from the start of `serve` with a
buffer of one: a HUP during startup waits for the loop, and a HUP during a
reload triggers exactly one more. Once serving: `READY=1`. For every reload:
`RELOADING=1` with `MONOTONIC_USEC` taken after the signal, then always
`READY=1` with `STATUS=` saying whether it worked (a failed reload is still
finished). At shutdown: `STOPPING=1` first, then the reload loop is stopped
and waited for, connections drain (`shutdown_timeout` of the current
configuration), the current table is released, and the audit output is
closed last; SIGHUP is ignored, not reset, so a reload sent during the drain
cannot kill the process. Tests trigger reloads through a channel.

## Consequences

- Revoking a permission or changing a mount does not affect open
  connections; `disconnect_removed_users` closes connections whose login is
  revoked, not those whose permissions shrank.
- A connection opened before a disk was mounted over a mount's path keeps
  using the old directory until it ends, and keeps that filesystem busy.
- Each generation that still has connections holds one file descriptor per
  changed mount.
- Serving a home directory that contains `~/.ssh/authorized_keys` or the
  state directory with the host key is now refused (`--dir ~`); serve a
  subdirectory.
- An audit file that logrotate recreates with the wrong owner stops the
  server from accepting changes (fail-closed) until it is fixed; the events
  go to stderr meanwhile.
