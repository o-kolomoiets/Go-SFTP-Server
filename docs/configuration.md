# Configuration

gosftpd reads one TOML file. `gosftpd config example` prints a minimal working
configuration, `gosftpd config example --full` a reference with every key and
its default, and `gosftpd init` writes a commented starting point.

```sh
gosftpd config validate --check-fs   # every problem at once, exit code 2 if invalid
gosftpd config show                  # the effective configuration with all defaults
```

Unknown keys are an error, and keys are case-sensitive (`Path` is not
`path`): a typo never silently falls back to a default.

## Where the file comes from

`gosftpd serve` (and `config`, `user list`) use the first of:

1. `--config FILE`;
2. `$GOSFTPD_CONFIG` (must exist if set);
3. `./gosftpd.toml`;
4. `/etc/gosftpd/config.toml` (not on Windows);
5. `<user config dir>/gosftpd/config.toml` (`~/.config/gosftpd/` on Linux).

With `--dir`, no file is read: see [Zero-config](#zero-config).

Precedence, highest first: command-line flags that were given explicitly, the
environment (`GOSFTPD_LISTEN` with comma-separated addresses,
`GOSFTPD_LOG_LEVEL`, `GOSFTPD_LOG_FORMAT`), the file, the defaults. With a
file, `serve --read-only` makes every mount read-only, `--on-conflict` sets
the policy of every mount, `--host-key` replaces `server.host_keys`, and
`--listen`, `--log-level`, `--log-format`, `--audit-output` replace their keys.

Relative paths in the file (host keys, `authorized_keys_file`, `audit.output`,
`include`) are relative to the directory of the file. Mount paths must be
absolute.

### File permissions

Like sshd's `StrictModes`, gosftpd refuses to start if the configuration file,
an included file, a host key or an `authorized_keys` file is writable by group
or others, or belongs to anyone but root or the user running gosftpd. Host keys
must also not be readable by others (`chmod 600`). A configuration readable by
everyone gives a warning. `gosftpd init` writes its file with mode 0600.

## Top level

| Key | Default | Meaning |
|---|---|---|
| `config_version` | required | Schema version; this release understands `1`. |
| `include` | none | Glob patterns of files with `[users.NAME]` tables only, e.g. `["users.d/*.toml"]`. Relative patterns must stay inside the configuration directory. A user may be defined once. |

## `[server]`

| Key | Default | Meaning |
|---|---|---|
| `listen` | `[":2022"]` | Addresses to listen on; `:2022` is IPv4 and IPv6. |
| `host_keys` | required | Host private key files (OpenSSH format). RSA keys sign with SHA-2 only. |
| `host_key_auto_generate` | `false` | Create a missing host key as ed25519 (0600) on start. |
| `crypto_policy` | `"modern"` | Algorithm set: `modern` or `compat`, see below. |
| `handshake_timeout` | `"30s"` | Time a client has to finish the SSH handshake and authentication (1s–10m). |
| `idle_timeout` | `"15m"` | Close a connection that has moved no SFTP data for this long; `"0s"` turns it off (otherwise 1s–168h). |
| `keepalive_interval` | `"30s"` | Send `keepalive@openssh.com` this often and close the connection after 3 unanswered ones; `"0s"` turns it off (otherwise 1s–1h). |
| `shutdown_timeout` | `"30s"` | On SIGTERM/SIGINT, how long running transfers may finish before connections are closed (1s–1h). Keep it below systemd's `TimeoutStopSec` or Docker's `stop_grace_period`. |

The crypto policies offer these algorithms; there is no way to list
algorithms one by one.

| | `modern` | `compat` adds |
|---|---|---|
| Key exchange | `mlkem768x25519-sha256`, `curve25519-sha256` | `ecdh-sha2-nistp256`, `-nistp384`, `-nistp521`, `diffie-hellman-group16-sha512`, `diffie-hellman-group14-sha256` |
| Ciphers | ChaCha20-Poly1305, AES-GCM, AES-CTR | — |
| MACs | `hmac-sha2-256-etm`, `hmac-sha2-512-etm` | `hmac-sha2-256`, `hmac-sha2-512` |

Use `compat` only for clients that cannot connect otherwise; ssh-audit and
similar scanners flag its additions. SHA-1, CBC and DSA are never offered.

## `[limits]`

Connections over a limit are closed right after they are accepted, before
the SSH handshake, and logged as `conn.reject`. Behind a TCP proxy or load
balancer every client has the proxy's address, so per-address limits and
bans apply to all of them together; raise `max_connections_per_ip` and add
the proxy to `auth.ban.exempt`.

| Key | Default | Meaning |
|---|---|---|
| `max_connections` | `256` | Open connections in total (1–100000). |
| `max_connections_per_ip` | `16` | Open connections from one IPv4 address or one IPv6 /64 (1–100000). Each `rclone --transfers`/`--checkers` worker is a connection. |
| `max_preauth_connections` | `64` | Connections that have not logged in yet (1–10000), like sshd's `MaxStartups`. |
| `max_sessions_per_conn` | `4` | SFTP sessions (channels) per SSH connection (1–64). |
| `max_open_handles` | `64` | Open files and directories per SFTP session (1–4096). |
| `max_auth_tries` | `6` | Authentication attempts per connection (1–20). Lower values break SSH agents that offer many keys. |

## `[auth]`

| Key | Default | Meaning |
|---|---|---|
| `methods` | `["publickey"]` | Login methods: `publickey`, and `password` for users with `password_hash`. Either one is enough to log in; a method that is not listed is refused. Without a configuration file only `publickey` is possible. |

A connection keeps the user name of its first authentication request, as
sshd does: a client cannot try one user's password and then log in as
another user.

### `[auth.ban]`

Failures count against the source, the IPv4 address or the IPv6 /64:
every wrong password is one failure as soon as it is refused, also in a
connection that then logs in; a connection that closes without logging in
after rejected keys is one failure, however many keys an SSH agent offered.
Once a source is banned, its open connections get no further password
checks. A source with
`after_failures` failures within `within` is refused right after accept for
`duration` (`conn.reject` with `reason=banned`; the ban itself is logged as
`auth.ban`). Bans are kept in memory, for at most 65 536 sources.

| Key | Default | Meaning |
|---|---|---|
| `after_failures` | `10` | Failures that start a ban (0 turns bans off, at most 100). |
| `within` | `"10m"` | Window in which they must happen (1s–24h). |
| `duration` | `"30m"` | Length of a ban (1s–720h). |
| `exempt` | `["127.0.0.0/8", "::1/128"]` | Addresses and CIDR blocks that are never banned. |

## Mounts

A mount is a host directory shown to users as a top-level directory:
`[mounts.inbox]` appears as `/inbox`. A user who can access only one mount sees
it as `/` (see `flatten`). Mount names use letters, digits, `.`, `_`, `-` and
spaces (64 at most), are unique ignoring case and cannot be Windows device
names such as `NUL`.

Every file operation goes through an `os.Root` of the mount: `..`, absolute
paths and symlinks cannot leave it. Clients cannot create symlinks or hard
links.

### `[mounts.NAME]`

| Key | Default | Meaning |
|---|---|---|
| `path` | required | Absolute host directory. If its last component is `{user}`, every user gets their own subdirectory (a home mount, see below). Mounts may not overlap. |
| `create` | `false` | Create the directory (or, for a home mount, the parent and each user's directory) if missing. |
| `read_only` | `false` | Allow only listing and reading, whatever the users' permissions. |

A mount also takes every option from `[defaults]` below; a value set on the
mount wins.

**Home mounts.** With `path = "/srv/sftp/home/{user}"`, user `alice` gets
`/srv/sftp/home/alice` (created as 0750 with `create = true`). The directory
must be a real directory: if it is a symlink (even to another user's home) or
a file, the mount is unavailable for that session and an `fs.denied` event
with `reason = "home_not_dir"` is written.

### `[defaults]`

| Key | Default | Meaning |
|---|---|---|
| `flatten` | `true` | A user who can access exactly one mount sees it as `/`. Only in `[defaults]`. |
| `on_conflict` | `"rename"` | Upload to an existing file: `rename`, `reject`, `overwrite` or `version`, see below. |
| `rename_template` | `"{stem} ({n}){ext}"` | Name of the copy with `rename`. Must contain `{n}` once; may contain `{stem}` and `{ext}`; no slashes; at most 64 bytes. |
| `max_rename_attempts` | `100` | Numbered names tried before `{n}` becomes a UTC timestamp with a random suffix (1–10000). |
| `compound_extensions` | `[".tar.gz", ".tar.bz2", ".tar.xz", ".tar.zst"]` | Extensions kept whole: `a.tar.gz` becomes `a (1).tar.gz`. |
| `resume` | `"append-only"` | Continuing an upload into an existing file (OpenSSH `reput`, paramiko mode `a`): `append-only` or `off`. |
| `stat_redirect` | `true` | After an upload or move went to another name, STAT and SETSTAT of the requested name answer for the new one, see below. |
| `setstat_mode` | `"times"` | What SETSTAT may change: `times` (access and modification time), `ignore` (accept and do nothing) or `deny`. |
| `symlinks` | `"inside-only"` | Existing symlinks on the host: `inside-only` follows those that stay inside the mount; `deny` refuses every path through a symlink and hides them from listings. |
| `umask` | `"0027"` | Removed from the mode of new files (0666) and directories (0777); a quoted octal string. |
| `require_mountpoint` | `false` | Refuse to start unless the path is a mount point (on another filesystem than its parent): protects against writing to the root disk when a disk is not mounted. |
| `max_file_size` | `"0"` | Largest file an upload may write, e.g. `"10GiB"`; `"0"` means no limit. Units: B, kB, MB, GB, TB, KiB, MiB, GiB, TiB, or a plain number of bytes. |
| `min_free_space` | `"1GiB"` | Refuse to open files for writing while the mount's filesystem has less free space (`"0"` turns the check off). Not checked on Windows or on filesystems that report no size (some FUSE filesystems). |
| `atomic_uploads` | `false` | Write each upload to a hidden temporary file and give it its name only when the client closes it, see below. |
| `fsync` | `false` | Flush an upload through a temporary file (`atomic_uploads`, or a conflict under `version`) to disk before it gets its name. |
| `versions` | see below | Where and how long `on_conflict = "version"` keeps old versions. |

### `[defaults.versions]`

Also `[mounts.NAME.versions]`, or inline: `versions = { keep = 5 }`.

| Key | Default | Meaning |
|---|---|---|
| `dir` | `".versions"` | Directory at the top of the mount that holds old versions, as `<dir>/<path of the file>/<stem>.<UTC time><ext>`, e.g. `.versions/docs/report.pdf/report.20261009T114500Z.pdf`. It is not listed, so that sync tools do not try to delete it; users with `list` and `read` open it by path (`cd .versions`) and download versions. Nobody but the server can change it. |
| `keep` | `10` | Old versions kept per file, newest first; `0` keeps all (at most 10000). Extra versions are removed only when a user with the `delete` or `overwrite` permission saves a version: a user who may only write cannot push older versions out. |
| `max_age` | `"720h"` | Versions older than this are removed when the next version of the file is saved; `"0s"` keeps them forever. |

### Upload conflicts

What happens when an upload targets an existing file (`on_conflict`):

| Policy | The upload… | The original |
|---|---|---|
| `rename` | goes to a free name from `rename_template`, e.g. `report (1).pdf` | untouched |
| `reject` | fails with "file exists (on_conflict=reject)" | untouched |
| `overwrite` | replaces the content (needs the `overwrite` permission) | replaced |
| `version` | is written to a temporary file and takes the name when it is closed (needs only `write`) | moved to the versions directory |

- An exclusive create (`O_EXCL`) of an existing file always fails.
- SFTP cannot tell the client the name it got; the audit event `fs.upload`
  records `path` and `final_path`.
- **Moves** (`posix-rename@openssh.com`, used by OpenSSH `rename`, rclone and
  WinSCP) onto an existing name follow the same policy (with `version` the
  target is versioned first); the classic SFTP RENAME never replaces a
  file.
- **Resume** (OpenSSH `reput`, paramiko `open(…, "a")`, Cyberduck) writes into
  the existing file. With `resume = "append-only"` the bytes it had when it
  was opened can neither be changed nor truncated ("existing data is
  immutable"). Only with `overwrite`, the `overwrite` permission and an open
  without APPEND is it a plain write.
- While an upload has a file open, other uploads cannot write it in place
  ("file is busy").
- **stat_redirect**: tools check an upload by its name. After an upload or move
  went to `report (1).pdf`, STAT, LSTAT and SETSTAT of `report.pdf` by the
  same user answer for `report (1).pdf` for 60 seconds, in all of the user's
  connections (rclone uses several). Listing, opening, removing and renaming
  are never redirected, with one exception: a resume (APPEND, or WRITE
  without CREAT and TRUNC, as OpenSSH `reput` sends after the redirected
  STAT gave it the copy's size) continues the copy and renews the redirect.
  Any other open, a remove or a rename of the name ends the redirect.
  Without it, paramiko `put(confirm=True)` reports a size mismatch and rclone
  may delete what it takes for a failed copy: the original.
- `rename` plus a sync tool (`rclone sync`, `rsync`-like clients) creates a
  copy on every run; use `on_conflict = "version"` for synced folders: the
  file keeps its name and the previous content goes to the versions
  directory (`fs.upload` and `fs.rename` record it in `version_path`).
- An upload that is aborted (the connection breaks) under `version` or with
  `atomic_uploads` leaves no trace: the temporary file is removed and the
  original stays. Temporary files (`.gosftpd-*.part`) are hidden from
  listings, and names starting with `.gosftpd-` (in any case) cannot be used
  by clients. Those left by a crash are removed at start and every 6 hours
  once they are 24 hours old, and when a client removes their directory.

### Atomic uploads

With `atomic_uploads = true` every upload is written to a temporary file in
the same directory and appears under its name only when the client closes
it, by a rename that never replaces a file by accident: other users never
see a partial file, and a client killed mid-upload leaves nothing under the
name. The conflict policy is applied when the upload is closed, to whatever
has the name by then (with `reject`, the upload that closes second fails and
its data is discarded). Resuming an upload is not possible
(there is nothing to continue): clients get "resume is disabled". An upload
always starts from an empty file: a client that opens an existing file
without truncating it to change a few bytes in place (sshfs, `dd
conv=notrunc`) replaces the whole file with what it writes. Serve such
clients from a mount with `overwrite` and without `atomic_uploads`.

### Size limits

`max_file_size` is checked on every write against its end offset, so a
client cannot create a larger sparse file by writing far past the end, and
on truncation (SETSTAT size). A refused write ends the upload with
`result = "denied"` and one `fs.denied` event; what was written stays, except
for an upload through a temporary file, which is discarded. `min_free_space` is checked
when a file is opened for writing: an upload that has started is not
stopped when space runs low.

## Users

### `[users.NAME]`

User names use lowercase letters, digits, `.`, `_` and `-` (32 at most,
starting with a letter or digit). An SSH login with an unknown name fails the
same way as a wrong key.

| Key | Default | Meaning |
|---|---|---|
| `authorized_keys` | none | Public keys, one OpenSSH `authorized_keys` line each. |
| `authorized_keys_file` | none | A file with more keys, read at start. |
| `password_hash` | none | argon2id (or imported bcrypt) hash from `gosftpd user hash-password`; used only when `auth.methods` includes `password`. |
| `allow_from` | any | Client addresses or CIDR blocks the user may log in from. |
| `expires` | never | TOML date-time after which logins are refused, e.g. `2026-12-31T23:59:59Z`. |
| `disabled` | `false` | Refuse all logins of this user. |
| `access` | none | Mount name to permissions, e.g. `{ inbox = "upload", home = "full" }`. |

Supported key types: ed25519, ECDSA (P-256, P-384, P-521), RSA with at least
2048 bits, and the security-key variants `sk-ssh-ed25519@openssh.com` and
`sk-ecdsa-sha2-nistp256@openssh.com`. Supported `authorized_keys` options:
`from=` (IP addresses and CIDR blocks only), `expiry-time=`,
`no-touch-required`, and `restrict`, `no-pty`, `no-port-forwarding`,
`no-agent-forwarding`, `no-x11-forwarding`, `no-user-rc` (always in effect).
A line with any other option, such as `command=`, `cert-authority` or
`verify-required`, is skipped with a warning naming the file and line.

Passwords are off unless `auth.methods` includes `password`. Prefer keys:
a password can be guessed, and every attempt costs the server one hash
check (about 19 MiB and tens of milliseconds of CPU with the default
parameters). New hashes use argon2id with m=19456, t=2, p=1. Imported
hashes may use argon2id with up to 64 MiB, t ≤ 10 and p ≤ 8, or bcrypt with
cost 10 to 14 (`$2a$`, `$2b$`, `$2y$`). So that the response time does not
tell which users exist, unknown users and users without a password are
checked against a stand-in of the costliest hash in the configuration, and
every failed attempt then waits, without using the CPU, until checking that
hash would have finished. With hashes of one kind and cost (all made by
`gosftpd user hash-password`) unknown and real users do exactly the same
work, under any load. With several kinds or costs, attempts made one at a
time still take equally long, but parallel attempts can tell users of the
cheaper hashes apart, and every failed attempt takes as long as the
costliest hash; `config validate` warns about this. Re-hash imported
passwords with `gosftpd user hash-password` when you can.

### Permissions

`access` values are a preset or a comma-separated list of flags.

| Preset | Flags | Typical use |
|---|---|---|
| `read` | `list,read` | public downloads |
| `upload` | `list,write,mkdir` | partner drop-box: no reading, deleting or overwriting |
| `readwrite` | `list,read,write,overwrite,rename,mkdir,setstat` | shared work folder |
| `full` | all flags | personal home |

| Flag | Allows |
|---|---|
| `list` | listing directories, STAT |
| `read` | downloading |
| `write` | creating new files, resuming append-only, and renaming and setting times on files the user created (temporary upload names such as WinSCP's `.filepart` or rclone's `.partial`) |
| `overwrite` | changing existing files, including truncation and replacing them by a move |
| `delete` | removing files |
| `rename` | renaming any file or directory |
| `mkdir` | creating directories |
| `rmdir` | removing empty directories |
| `setstat` | setting times of any file |

"Files the user created" means: created by the same user, in any of the
user's connections, within the last hour, and not changed by anyone else
since. A size change through SETSTAT is allowed on a file the session is
uploading (OpenSSH `scp` truncates that way), under the permission the upload
was opened with. Permission and ownership changes are always ignored. A
refused operation returns "permission denied" and writes an `fs.denied` audit
event.

## `[log]`

The operational log goes to stderr.

| Key | Default | Meaning |
|---|---|---|
| `level` | `"info"` | `debug`, `info`, `warn` or `error`. |
| `format` | `"text"` | `text` or `json`. |

## `[audit]`

See [audit-log.md](audit-log.md) for the format.

| Key | Default | Meaning |
|---|---|---|
| `output` | `"stdout"` | `stdout` or a file, opened for appending (mode 0600). |
| `events` | `["conn", "auth", "session", "transfer", "modify", "denied"]` | Categories to record; also `list` and `stat`. `server` events are always recorded. |
| `on_error` | `"fail-closed"` | When the audit log cannot be written: `fail-closed` refuses new connections and changes until it works again; `fail-open` keeps serving and writes the events to stderr. |

## Zero-config

`gosftpd serve --dir [NAME=]PATH...` runs without a file. It behaves like a
configuration with one mount per `--dir` (named after the last path component
unless `NAME=` is given) and one implicit user: every SSH user name (or only
`--user`) is accepted with the keys of `--authorized-keys` (default
`~/.ssh/authorized_keys`) and has full access. The host key is generated in
`--state-dir` (default `<user config dir>/gosftpd`). `--read-only` and
`--on-conflict` apply to every mount. Every other setting has its default.

`gosftpd serve` refuses to run as root (exit code 2) unless `--allow-root`
is given: run it as a dedicated user.

## Commands

| Command | What it does |
|---|---|
| `gosftpd init` | Writes `./gosftpd.toml` (0600) and a host key; never overwrites without `--force`. |
| `gosftpd config validate [--check-fs]` | Checks the configuration; with `--check-fs` also paths, keys and file permissions. |
| `gosftpd config show` | Prints the effective configuration. |
| `gosftpd config example [--full]` | Prints an example. |
| `gosftpd user add NAME --key FILE\|KEY --access MOUNT=PERMISSIONS…` | Prints a `[users.NAME]` block to append; writes nothing. `--password-hash` adds a password. |
| `gosftpd user hash-password [--stdin]` | Asks for a password twice (or reads one line with `--stdin`) and prints its argon2id hash. |
| `gosftpd user list` | Lists users with access, key count, password, expiry and status (`off` when `auth.methods` leaves the method out). |
| `gosftpd hostkey generate [--type ed25519\|ecdsa\|rsa]` | Creates a host key; never overwrites. |
| `gosftpd hostkey show [--known-hosts HOST:PORT]` | Prints the fingerprint and a `known_hosts` line. |

Exit codes: 0 success, 1 runtime error, 2 invalid usage or configuration.
