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

Relative paths in the file (host keys, `authorized_keys_file`,
`auth.trusted_user_ca_keys_file`, `auth.revoked_keys_file`, `audit.output`,
`include`) are relative to the directory of the file. Mount paths must be
absolute.

### File permissions

Like sshd's `StrictModes`, gosftpd refuses to start if the configuration file,
an included file, a host key, an `authorized_keys` file, the trusted CA keys
or the revocation list is writable by group or others, or belongs to anyone
but root or the user running gosftpd. Host keys
must also not be readable by others (`chmod 600`). A configuration readable by
everyone gives a warning. `gosftpd init` writes its file with mode 0600.

None of these files, nor the audit log, may lie inside a mount that clients
can write to: a client could add itself a key or a user, which a reload would
then apply. On reload that includes the mounts that connections opened
under an earlier configuration still use. Host keys and configuration files
(which may hold password hashes) may not lie inside any mount, since clients
could read them. An audit log inside a read-only mount gives a warning. The
check follows symlinks and, on Linux, bind mounts.

## Top level

| Key | Default | Meaning |
|---|---|---|
| `config_version` | required | Schema version; this release understands `1`. |
| `include` | none | Glob patterns of files with `[users.NAME]` tables only, e.g. `["users.d/*.toml"]`. Relative patterns must stay inside the configuration directory. A user may be defined once. Names that start with a dot are skipped; a directory that exists but cannot be read is an error. |

## `[server]`

| Key | Default | Meaning |
|---|---|---|
| `listen` | `[":2022"]` | Addresses to listen on; `:2022` is IPv4 and IPv6. |
| `host_keys` | required | Host private key files (OpenSSH format), at most one per key type. RSA keys sign with SHA-2 only. Next to each, `KEY.next` and `KEY.old` are a rotation's next and previous keys, see [Host keys](#host-keys). |
| `host_key_auto_generate` | `false` | Create a missing host key as ed25519 (0600) at start, never on reload, and not when `KEY.next` or `KEY.old` exists. |
| `host_certificates` | `false` | Serve the certificate `KEY-cert.pub` with each host key `KEY`, see [Host certificates](#host-certificates). |
| `announce_host_keys` | `true` | After login, announce the host keys with their next and previous keys to OpenSSH clients, which then learn new keys (`UpdateHostKeys`); see [Host keys](#host-keys). |
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
| `trusted_user_ca_keys` | none | CA public keys, one per entry, whose user certificates log in as any configured user whose `principals` they carry. See [Certificates](#certificates). |
| `trusted_user_ca_keys_file` | none | A file of CA public keys, one per line. At start a missing or unsafe file, or no usable CA key at all, refuses the configuration; on reload it trusts no CA, with a warning. |
| `revoked_keys` | none | Revoked public keys or certificates, one per entry. A certificate revokes its key. |
| `revoked_keys_file` | none | A file of revoked keys or certificates, one per line (at most 1 MiB, like every file gosftpd reads; a plain public key is the shortest entry). It fails closed: a line that is not a key, a KRL, or a missing or unsafe file is an error at start and fails a reload. |

The certificate settings are read only when `methods` includes `publickey`.

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
| `principals` | the user name | A certificate from a trusted CA (`auth.trusted_user_ca_keys` or `trusted_user_ca_keys_file`) must carry one of these principals to log in as this user, e.g. `["alice@corp.example"]`; `[]` keeps those CAs away from the user. |
| `access` | none | Mount name to permissions, e.g. `{ inbox = "upload", home = "full" }`. |

Supported key types: ed25519, ECDSA (P-256, P-384, P-521), RSA with at least
2048 bits, and the security-key variants `sk-ssh-ed25519@openssh.com` and
`sk-ecdsa-sha2-nistp256@openssh.com`. Supported `authorized_keys` options:
`from=` (IP addresses and CIDR blocks only), `expiry-time=`,
`no-touch-required`, `cert-authority` with `principals=` (see
[Certificates](#certificates)), `command="internal-sftp"` (or a path to
`sftp-server`, without arguments: gosftpd serves only SFTP anyway), and
`restrict`, `no-pty`, `no-port-forwarding`, `no-agent-forwarding`,
`no-x11-forwarding`, `no-user-rc` (always in effect). A line with any other
option, such as another `command=` or `verify-required`, is skipped with a
warning naming the file and line.

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

### Certificates

Instead of collecting every user's key, the server can trust a certificate
authority (CA): a key that signs users' keys into OpenSSH certificates.
Create a CA once, keep its private key off the server, and sign a key per
user:

```sh
ssh-keygen -t ed25519 -f user_ca                    # the CA, once
ssh-keygen -s user_ca -I alice-laptop -n alice -V +52w id_ed25519.pub
ssh-keygen -L -f id_ed25519-cert.pub                # inspect the certificate
```

`-I` is the key ID (`cert_key_id` in the audit log), `-n` the principals
(names) the certificate is valid for, `-V` its validity period (`-V
-5m:+8h` allows for clock skew), `-z` a serial number. An RSA CA must sign
with SHA-2: `ssh-keygen -t rsa-sha2-512 -s user_ca.rsa …`. OpenSSH's `ssh`
and `sftp` pick up `id_ed25519-cert.pub` automatically when it sits next to
the key; otherwise use `-o CertificateFile=…`.

Trust the CA in one of two ways:

- **For every configured user**: `auth.trusted_user_ca_keys` (or
  `trusted_user_ca_keys_file`). A certificate logs in as a user when one of
  its principals is in the user's `principals`, by default the user name;
  `principals = ["alice@corp.example"]` maps a corporate name, `[]` keeps
  the user out. Such a user needs no keys of its own.
- **For one user**: a line `cert-authority ssh-ed25519 AAAA… ca` in the
  user's `authorized_keys`, optionally with `principals="a,b"` (a principal
  of the certificate must be in the list; without it, a principal must be
  the user name), `from=`, `expiry-time=` and `no-touch-required`, which
  then apply to the certificates the line accepts. A plain key line never
  accepts a certificate, and a `cert-authority` line never accepts the CA
  key itself as a plain key.

A certificate is refused when it is not a user certificate, has no
principals, is outside its validity period, is signed with SHA-1
(`ssh-rsa`), or carries a critical option other than `source-address`
(enforced) and `force-command` with `internal-sftp` or a path to
`sftp-server` without arguments (gosftpd serves only SFTP); `verify-required`
cannot be enforced and is refused. A security-key certificate with the
extension `no-touch-required` needs `no-touch-required` on the
`cert-authority` line that accepts it; for a CA in `trusted_user_ca_keys`,
the certificate's own extension applies. The audit log records the key ID, serial and CA of every
certificate login, and the reason of a refusal (see the
[audit log](audit-log.md)).

**Revoking.** Add the user's key or certificate to `auth.revoked_keys_file`
and reload. The entry takes effect only after a successful reload: check
the file first, and the result after (the reload's status line, or the
latest `server.reload` event with `"result":"ok"`). Open connections with
the key stay unless `reload.disconnect_removed_users = true`.

```sh
{ echo; cat id_ed25519-cert.pub; } >> /etc/gosftpd/revoked_keys   # echo: in case the file lacks a final newline
gosftpd config validate --check-fs --config /etc/gosftpd/config.toml && systemctl reload gosftpd
systemctl status gosftpd | grep Status
```

As in sshd, a revoked certificate revokes its key, and with it every
certificate of that key and the key itself; listing a CA key revokes every
certificate it signed. The list is read only at start and on reload, not at
every login. Revoking one certificate by serial or key ID needs a KRL
(`ssh-keygen -k`), which gosftpd does not read yet.

Differences from sshd:

| | sshd | gosftpd |
|---|---|---|
| Certificate without principals | accepted through a `cert-authority` line | refused |
| `force-command` | runs the command | only an SFTP server, without arguments; else refused |
| `AuthorizedPrincipalsFile` | a file per user | `users.NAME.principals` |
| `RevokedKeys` | text list or KRL, re-read at every login | text list, read on reload |
| An unreadable revocation list | refuses every public-key login | refused at start; fails a reload, the running list stays |
| Zero-config | — | a `cert-authority` line without `principals=` is ignored unless `--user` is given; no revocation list |

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

## `[reload]`

`kill -HUP` (or `systemctl reload gosftpd`) applies the configuration again
without a restart; see [Reload](#reload).

| Key | Default | Meaning |
|---|---|---|
| `disconnect_removed_users` | `false` | After a reload, close the connections whose login the new configuration would refuse: the user was removed, disabled or has expired, the key, certificate CA or password used was removed, revoked or changed, or `allow_from` no longer matches. A certificate whose validity period has passed since the login does not count: sshd checks it only at login, and certificates often last hours. Otherwise open connections keep the configuration they logged in under. |

## Host keys

`server.host_keys` lists the host private keys, at most one per key type
(clients choose among the types; with two keys of one type only one would
ever be used, so that is refused). Each key `KEY` may have, in the same
directory:

| File | What it is |
|---|---|
| `KEY.pub` | Its public key, for people and tools; gosftpd reads it only when the private key is not readable (`hostkey show`, `user add`). |
| `KEY.next` | The next key of a rotation: announced to clients, not used for key exchange. |
| `KEY.old` | The previous key after a rotation: announced until it is retired. |
| `KEY-cert.pub` | Its certificate, served with `host_certificates = true`. |

Private keys must have mode 0600, belong to root or to the user running
gosftpd, and lie outside every mount. A reload reads them all again.

After a login, gosftpd announces the host keys with their next and previous
keys to OpenSSH clients (`hostkeys-00@openssh.com`, once per connection).
OpenSSH 8.5 and later then add keys they do not know to `known_hosts`, after
asking gosftpd to prove that it holds them, and remove keys of the host that
were not announced (`UpdateHostKeys`). Each proof is audited as
`conn.hostkeys_proved`. It is sent only to OpenSSH clients;
`announce_host_keys = false` turns it off.

### Rotation

`gosftpd hostkey rotate` replaces a host key without breaking OpenSSH
clients. Run it as the owner of the key or as root, and reload gosftpd after
each step:

1. `gosftpd hostkey rotate --config /etc/gosftpd/config.toml` creates
   `KEY.next` (of `KEY`'s type, or `--type`). After the reload it is
   announced. Give its fingerprint, which the command prints, to users of
   clients that do not update `known_hosts`.
2. When clients have connected once (the transition period; the audit log
   shows who learned the key), `rotate --finish` makes `KEY.next` the host
   key; the previous key is kept as `KEY.old` and stays announced, so
   clients keep it and `rotate --rollback` can return to it.
3. `rotate --retire` deletes `KEY.old`; after the reload clients forget it.

`rotate --abort` deletes a `KEY.next` that is no longer wanted. `KEY` always
exists; a step that was interrupted is completed by running it again.
`--finish` and `--rollback` refuse a key or certificate that the server would
not use (a certificate of another key, a key of another owner).

OpenSSH 8.5 and later update `known_hosts` by default only when
`UserKnownHostsFile` is the default one (with another file, set
`UpdateHostKeys yes`; new keys go to the first file). It never updates a key
found through a `GlobalKnownHostsFile` or `KnownHostsCommand`, nor
for a host verified by a certificate or with a `@cert-authority` or
`@revoked` line, and not when an announced key is also known under another
name or address: a `known_hosts` line must use exactly the name and port
that clients connect with (`[sftp.example.org]:2022` for a port other than
22). `UpdateHostKeys ask` never applies to sftp. Before 8.5 it is off unless
`UpdateHostKeys yes` is set. A connection opened before the reload that
started the announcement learns nothing until it reconnects.

Other clients (PuTTY, WinSCP, FileZilla, paramiko, rclone and other Go
programs) see the new key at the cutover. paramiko and the PuTTY family keep
one key per type and host, so for them a rotation to another key type
(`--type`) helps: they keep using the type they know until the cutover.
WinSCP scripts can list both fingerprints in `-hostkey`.

Servers reached under one name must announce the same keys, or clients
remove each other's: create `KEY.next` once, copy it and `KEY.next.pub` to
every server (same owner and mode), check with `gosftpd hostkey show` that
every server shows the same fingerprints, and take each step on all of them
before the next.

If a host key may be compromised, do not rely on the announcement, since
whoever holds the key can announce a key of their own. Run `rotate`, `rotate
--finish` and `rotate --retire`, then reload once, so the old key is never
announced again; send users the new fingerprint by another channel, and the
old key as a `@revoked` line for `known_hosts` (or OpenSSH's
`RevokedHostKeys`).

### Host certificates

With `host_certificates = true`, gosftpd serves `KEY-cert.pub` with each
host key: clients that trust the CA (`@cert-authority [sftp.example.org]:2022
ssh-ed25519 AAAA...` in `known_hosts`) accept the key without knowing it.
Sign the public key as a host certificate with the names clients connect
with:

```sh
ssh-keygen -s ca_key -h -I sftp-host -n sftp.example.org -V -5m:+52w /var/lib/gosftpd/ssh_host_ed25519_key.pub
```

A certificate must certify its key, be a host certificate (`-h`) with at
least one principal (`-n`) and no critical options, and be signed with
SHA-2 (an RSA CA needs `-t rsa-sha2-512`; OpenSSH refuses `ssh-rsa`
signatures), else gosftpd refuses to start; on reload it is left out with a
warning. A certificate is offered only while it is valid; OpenSSH clients
that also know the plain key fall back to it. gosftpd warns from 30 days
(or a third of the lifetime, if shorter) before expiry, at start, on reload
and once a day. To renew, replace the file and reload. In a rotation, certify
`KEY.next.pub` too: `KEY.next-cert.pub` becomes `KEY-cert.pub` at `rotate
--finish`.

Serving a certificate breaks Go programs (x/crypto, such as rclone) that
pin the plain host key: they prefer the certificate and do not fall back
("ssh: no authorities for hostname" or "host key mismatch"). Have them list
plain host key algorithms (rclone: `host_key_algorithms = ssh-ed25519`) or
trust the CA. paramiko does not support host certificates; it keeps using
the plain key.

## Reload

On SIGHUP gosftpd first reopens the audit log file (for logrotate), then
reads the same configuration file as at start again, with the same
command-line flags and environment, and checks it like `config validate
--check-fs`. Only if that succeeds does it switch:

- **New logins** use the new users, keys, passwords, mounts, permissions,
  limits, bans settings and log level. Every login is checked against the
  configuration current when it completes, so a key removed by a reload is
  refused even for a client that was half-way through logging in.
- **Open connections** keep the configuration they logged in under, for all
  their sessions, unless `disconnect_removed_users` closes them. A changed or
  remounted mount directory is opened anew for new logins; old connections
  keep the old directory until they end.
- **Carried over:** bans (with the new `[auth.ban]` settings; turning bans off
  drops them), connection counts (connections above a lowered limit stay; new
  ones are refused, as `conn.reject`, until the count is below it) and
  running transfers.
- **Host keys** (`server.host_keys`, next and previous keys, certificates)
  are read again: new connections use them, open ones keep theirs, also when
  they re-key. A reload never generates a key. If a host key cannot be used
  (missing, unreadable, unsafe, two of one type), the running host keys stay,
  with a warning; a next or previous key or a certificate that cannot be
  used is left out, with a warning. A key or certificate file inside a mount
  fails the reload, as every file gosftpd trusts does (for the running keys
  too, when they stay). A change of the host keys is logged with the
  fingerprints.
- **Restart only:** `server.listen`, `server.host_key_auto_generate`,
  `server.crypto_policy`, `log.format`, `audit.events` and
  `audit.on_error`. A change is logged as a warning and listed in the
  `server.reload` audit event; the running value stays.

Problems that concern one user or one mount do not stop a reload: an
`authorized_keys_file` that is missing, unsafe, empty or not a regular file
gives that user no keys (so deleting the file, or linking it to `/dev/null`,
revokes them), and a mount that fails its checks (a disk that is not
mounted with `require_mountpoint`, a missing directory, a missing `--dir`)
is unavailable until the next reload. Only a pipe, such as that of
`--authorized-keys <(...)`, which can be read once, keeps the keys read
from it before. Likewise a missing or unsafe `auth.trusted_user_ca_keys_file`
trusts no CA. The revocation list is the exception: a
`revoked_keys_file` that cannot be read or parsed fails the reload, since
reading less of it would un-revoke keys.
Anything else (a syntax error, an invalid value, an unsafe configuration
file) keeps the running configuration; the error goes to the log, and the
audit log gets `server.reload` with `"result":"error"`.

A value that a flag or the environment sets (`--log-level`,
`GOSFTPD_LOG_LEVEL`, `--audit-output`, `--host-key`) keeps overriding the
file; a reload warns when the file says otherwise. With zero-config (`--dir`), a reload
reads `--authorized-keys` again and reopens the audit log.

Under systemd, gosftpd reports `RELOADING=1` and then `READY=1` with a status
line that says whether the reload worked (`Type=notify-reload`).

## Zero-config

`gosftpd serve --dir [NAME=]PATH...` runs without a file. It behaves like a
configuration with one mount per `--dir` (named after the last path component
unless `NAME=` is given) and one implicit user: every SSH user name (or only
`--user`) is accepted with the keys of `--authorized-keys` (default
`~/.ssh/authorized_keys`) and has full access. The host key is generated in
`--state-dir` (default `<user config dir>/gosftpd`). `--read-only` and
`--on-conflict` apply to every mount. Every other setting has its default.
`--authorized-keys` may hold `cert-authority` lines. Without `--user`, any
user name is accepted, so a line needs `principals=` (one without is ignored
with a warning), and the login name must be one of the line's principals
and of the certificate's. With `--user NAME` the usual rules apply: a
principal of the certificate must be in `principals=`, or be `NAME` when the
line has none.

`gosftpd serve` refuses to run as root (exit code 2) unless `--allow-root`
is given: run it as a dedicated user.

## Commands

| Command | What it does |
|---|---|
| `gosftpd init` | Writes `./gosftpd.toml` (0600) and a host key; never overwrites without `--force`. |
| `gosftpd config validate [--check-fs]` | Checks the configuration; with `--check-fs` also paths, keys and file permissions. |
| `gosftpd config show` | Prints the effective configuration. |
| `gosftpd config example [--full]` | Prints an example. |
| `gosftpd user add NAME --key FILE\|KEY --access MOUNT=PERMISSIONS…` | Prints a `[users.NAME]` block to append. `--password-hash` adds a password, `--expires` an expiry (`720h` or a date). `--principal` sets `principals`. With `--write` it checks the configuration with the new user, writes `users.d/NAME.toml` (the directory of an `include` pattern; mode and group like the configuration file) and prints the connection details for the user: host, port, host key fingerprint, `sftp` command (`--host` sets the host name), and the `ssh-keygen` command to sign a certificate when CAs are trusted. A user that could not log in (disabled, expired, no key, password or certificate principal that `auth.methods` allows) is refused unless `--force`; with trusted CAs, a user needs no key. |
| `gosftpd user disable\|enable\|remove NAME` | Changes a user defined in an included file, keeping the rest of the file and its comments; `remove` deletes a file left without users. The main configuration file is never rewritten. A reload applies the change. |
| `gosftpd user hash-password [--stdin]` | Asks for a password twice (or reads one line with `--stdin`) and prints its argon2id hash. |
| `gosftpd user list` | Lists users with access, key count, certificate principals for trusted CAs, password, expiry and status (`off` when `auth.methods` leaves the method out). |
| `gosftpd hostkey generate [--type ed25519\|ecdsa\|rsa]` | Creates a host key; never overwrites. |
| `gosftpd hostkey show [--config FILE] [--known-hosts HOST:PORT]` | Prints the fingerprint, public key and `known_hosts` line of the host key (`--host-key`, `--state-dir`) or, with `--config`, of every configured one; then its next and previous keys and the certificate files that exist. The first lines describe the current key. |
| `gosftpd hostkey rotate [--type T] \| --finish \| --rollback \| --retire \| --abort` | Rotates a host key in steps, see [Rotation](#rotation). Selects the key like `show`; with `--config`, `--host-key` picks one of several. |

Exit codes: 0 success, 1 runtime error, 2 invalid usage or configuration.
