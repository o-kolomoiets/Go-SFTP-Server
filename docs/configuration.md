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
| `shutdown_timeout` | `"30s"` | On SIGTERM/SIGINT, how long running transfers may finish before connections are closed (1s–1h). Keep it below Docker's `stop_grace_period`; with hooks, at least 10 s below, since hooks get up to 5 s more after the drain (see [Hooks](hooks.md#shutdown)). Under systemd, gosftpd extends `TimeoutStopSec` to this + 10 s when it stops (`EXTEND_TIMEOUT_USEC`), also after a reload raised it. |
| `trusted_proxies` | `[]` | Load balancers that send a PROXY protocol header (v1 or v2), as addresses or CIDR blocks such as `["10.0.0.5", "10.0.1.0/28"]`; `/0` is refused. A connection from one of them must begin with a header, which names the client for bans, limits, `allow_from` and the audit log; a header from any other peer is refused. Reloadable. See [Behind a load balancer](#behind-a-load-balancer). |
| `landlock` | `"auto"` | Linux only: after binding its listeners, gosftpd confines itself with Landlock to its mounts, its configuration and key files, its audit log, `/proc/self` and the name-resolution files. `auto` applies it where the kernel allows it and logs why not elsewhere; `required` makes that an error at start (exit status 2); `off` never applies it. Landlock is not applied while exec hooks are configured, and `required` with an exec hook is an error. Changes only at restart; see [Landlock](#landlock) for the directory layout it needs. |

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

Connections over a limit are closed before the SSH handshake, and logged as
`conn.reject`: right after they are accepted, or, from a load balancer in
`server.trusted_proxies`, once its PROXY protocol header has named the
client. Behind a TCP proxy or load balancer that sends no such header, every
client has the proxy's address, so per-address limits and bans apply to all
of them together. Let the load balancer send PROXY protocol and list it in
`server.trusted_proxies` ([Behind a load balancer](#behind-a-load-balancer));
where it cannot, raise `max_connections_per_ip` and add it to
`auth.ban.exempt`.

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

A mount that is not `read_only` but whose directory is on a read-only file
system gives a warning at start, at reload and in `config validate
--check-fs` ("PATH is on a read-only file system; uploads will fail"):
under systemd, the unit's `ProtectSystem=strict` makes every path outside
`ReadWritePaths=` read-only (see [install.md](install.md#another-data-path)).

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
  same user answer for `report (1).pdf` for 60 seconds after the upload ended
  or the move, in all of the user's connections (rclone uses several).
  Listing, opening, removing and renaming are never redirected, with one
  exception: a resume (APPEND, or WRITE without CREAT and TRUNC, as OpenSSH
  `reput` sends after the redirected STAT gave it the copy's size) continues
  the copy and renews the redirect. Any other open, a remove or a rename of
  the name ends the redirect.
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

## `[metrics]`

The admin listener: an HTTP server with `/metrics` (Prometheus), `/healthz`
and `/readyz`. See [metrics.md](metrics.md) for the endpoints, the metrics
and examples.

| Key | Default | Meaning |
|---|---|---|
| `listen` | `""` | `HOST:PORT` of the admin listener, for example `"127.0.0.1:9090"`; empty means none. Restart only. It has no authentication or TLS: an address that is not loopback gets a warning. A failure to bind fails the start. |
| `pprof` | `false` | Serves `/debug/pprof` there (Go profiles), in binaries built with `-tags pprof` only; release binaries refuse it as a configuration error. A reload turns it on and off. |

## `[[hooks]]`

Programs and webhooks that run when files arrive, are downloaded, renamed
or removed (ADR 0010). Each `[[hooks]]` table is one hook with exactly one
of `exec` and `webhook`. Hooks run asynchronously: an SFTP request never
waits for one. [hooks.md](hooks.md) explains the events, the payload, the
signature and safe scripts. Hooks are reloadable; a reload reaches open
connections too (see [Reload](#reload)).

```toml
[[hooks]]
name = "notify"
on = ["fs.upload"]
exclude = ["*.filepart", "*.partial"]
webhook = { url = "https://example.internal/hooks/sftp", secret_file = "/etc/gosftpd/hook.secret" }
```

| Key | Default | Meaning |
|---|---|---|
| `name` | required | Unique; it names the hook in the log. |
| `on` | required | Events: `fs.upload`, `fs.download`, `fs.rename`, `fs.remove`, `fs.mkdir`, `fs.rmdir`, `fs.setstat`. A hook fires only for a result of `ok`. `fs.upload` also fires for the first rename of a file its uploader just uploaded, which completes a temp-file upload (`"uploaded":true`, see [hooks.md](hooks.md#a-file-arrived)). |
| `mounts` | all | Only events in these mounts (names compared case-insensitively). |
| `glob` | all | File name patterns (`path.Match`, case-sensitive) matched against the base name of the event's file (`final_path` for uploads and renames); the hook fires if one matches. |
| `exclude` | none | Patterns like `glob`; the hook does not fire if one matches. `["*.filepart", "*.partial"]` leaves out WinSCP's and rclone's temporary names. |
| `delay` | `"0s"` | Wait this long after the event before running (at most 1h). A hook that moves or deletes the file needs at least `"1m"`: clients check a file right after uploading it. Events wait in the queue meanwhile. |
| `concurrency` | `1` | Deliveries at a time (1–16). With 1, the events of a hook run in order. |
| `queue` | `1000`, or `10000` with a `delay` | Events that may wait (1–10000), and at most 64 MiB of them; beyond that new events are dropped, with a warning. With a delay, the queue holds every event of the last `delay`. |

`on`, `mounts`, `glob` and `exclude` select events; they are not a security
filter.

### `[hooks.exec]`

| Key | Default | Meaning |
|---|---|---|
| `argv` | required | The program (an absolute path) and its arguments; never run through a shell, and nothing from a client is an argument. Every absolute element that is not a directory must lie outside every mount; an existing regular file among them must belong to root or to gosftpd's user and not be writable by group or others. |
| `timeout` | `"30s"` | The program and its process group are killed when it runs out (1s–1h). |

The program gets the event line on stdin and `GOSFTPD_*` variables; see
[hooks.md](hooks.md#exec).

### `[hooks.webhook]`

| Key | Default | Meaning |
|---|---|---|
| `url` | required | `https`, or `http` (a warning unless the host is loopback). No user info. |
| `secret_file` | required | The HMAC key: at least 32 printable ASCII bytes after trimming white space (`openssl rand -hex 32`). Mode 0400, 0440, 0600 or 0640, owned by root or gosftpd's user, outside every mount. Read again on reload. |
| `timeout` | `"10s"` | Per attempt (1s–60s). |

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

`rotate --abort` deletes a `KEY.next` that is no longer wanted. `KEY`
always exists, and a step that was interrupted is completed by running it
again. Each step puts the `.pub` files and certificates with the keys they
belong to, and removes those of keys that are gone. `--finish` refuses a
next key of another owner (as root, it gives the key the owner of `KEY`,
unless the file has other hard links), of the type of another host key, or
with a certificate the server would refuse (with `--config` and
`host_certificates` off, only a warning).

OpenSSH 8.5 and later update `known_hosts` by default only when
`UserKnownHostsFile` is the default one and `VerifyHostKeyDNS` is off (else, set
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

## Behind a load balancer

Behind HAProxy, nginx or a cloud load balancer, every connection comes from
the load balancer. gosftpd then sees one address for all clients: one
client's failed logins ban them all, and `max_connections_per_ip` counts
them as one. With the PROXY protocol the load balancer names the client at
the start of each connection. List the load balancers' own addresses in
`server.trusted_proxies` and turn the protocol on there:

```toml
[server]
listen = [":2022"]
trusted_proxies = ["10.0.0.5", "10.0.1.0/28"]
```

```
# HAProxy
listen sftp
    mode tcp
    bind :22
    server gosftpd 10.0.0.20:2022 send-proxy-v2 check

# nginx (stream module)
stream {
    server {
        listen 22;
        proxy_pass 10.0.0.20:2022;
        proxy_protocol on;
    }
}
```

- A connection from an address in `trusted_proxies` must begin with a
  header, v1 (text; nginx sends only this) or v2 (binary). gosftpd reads it
  before it sends its banner. The header must be complete within
  `handshake_timeout`, and at most 10 s, of the accept; the SSH handshake
  keeps its own deadline, also counted from the accept. `config validate`
  warns when `handshake_timeout` is below 3 s, the least the protocol asks
  for.
- A connection from a trusted address that sends nothing before it ends or
  the deadline passes (a TCP health check) is not audited;
  `gosftpd_connections_total` counts it as `no_version`. Anything else that
  is not a valid header (an SSH version line, a header cut short, a header
  for a client over UDP or a Unix socket) closes the connection:
  `conn.reject` with `reason=proxy_header`, and a warning in the log, at
  most once a minute, that names the load balancer and what it sent
  instead.
- A connection from any other address must not begin with a header. gosftpd
  checks the first bytes each client sends after the server's banner, and
  closes the connection when they are a header: `conn.reject` with
  `reason=untrusted_proxy`, and a warning, at most once a minute. This holds
  also when `trusted_proxies` is empty, and for a second header after a
  trusted one (a client that sends its own, or two proxies in a row). No SSH
  client starts with these bytes.
- The client the header names is `remote_addr` in the audit log and in hook
  events. Bans, `max_connections_per_ip`, `allow_from`, `from=` in
  `authorized_keys` and a certificate's `source-address` apply to it, also
  when a reload checks open connections again. `local_addr` is the address
  the client connected to, and `proxy_addr` the load balancer, on every
  event of the connection. Until the header is read, the connection counts
  against `max_connections` and `max_preauth_connections` only: a load
  balancer is never banned or limited for the clients it names.
- `LOCAL` (v2) and `UNKNOWN` (v1), which load balancers send for their own
  health checks and for clients that reached them over a Unix socket, make
  the connection the load balancer's own, with its address. These
  connections share the load balancer's ban entry and its
  `max_connections_per_ip`: one client of a Unix socket front end can get
  the load balancer banned, and then its health checks refused. Pass the
  client on with PROXY protocol on every hop instead (HAProxy:
  `accept-proxy` on the socket's `bind` line). `config validate` warns when
  `trusted_proxies` overlaps `auth.ban.exempt` (by default loopback): such
  connections are then never banned.
- A header whose client is a loopback or unspecified address (`127.0.0.1`,
  `::1`, `0.0.0.0`, `::`) is refused as `proxy_header` unless the load
  balancer runs on this host: it connects from loopback, or from the very
  address it connects to. In `allow_from`, `from=`, `source-address` and
  `auth.ban.exempt`, loopback keeps meaning this host.
- TLVs, such as a load balancer's unique ID or a CRC32C checksum, are
  ignored.

### What trust means

Whoever can connect to gosftpd from a trusted address chooses the client
address that bans, limits, `allow_from`, `from=`, `source-address` and the
audit log see. List only addresses that never carry direct client traffic:
the load balancers' own, not a NAT gateway or Docker's userland proxy that
clients also come through. The setting applies to every listener, so such
an address cannot be trusted at all. Keep everyone else from reaching
gosftpd's port directly, with a firewall or a security group that admits
only the load balancers.

- **A load balancer on the same host.** A loopback entry, or one of the
  host's own addresses, trusts every local user and every container of a
  Kubernetes pod. Let only the load balancer's user, and the user that runs
  `gosftpd healthcheck` (root, or gosftpd's own user), connect to the port
  over loopback; connections to the host's own addresses go over loopback
  too. With nftables, for HAProxy running as `haproxy`:

  ```
  table inet gosftpd_loopback {
      chain output {
          type filter hook output priority filter; policy accept;
          oifname "lo" tcp dport 2022 ct state new meta skuid != { haproxy, gosftpd, root } reject with tcp reset
      }
  }
  ```

  Load it with `nft -f FILE`; the users must exist then.
- **AWS Network Load Balancer.** With instance targets it keeps the client's
  address by default, and gosftpd sees the client itself. Leave proxy
  protocol off there and `trusted_proxies` empty. Where you turn it on
  (proxy protocol v2 on the target group), list the load balancer's private
  addresses.
- **Kubernetes.** Never trust node or pod ranges: every pod, and every node
  that forwards a Service's traffic, could then name any client. Set
  `externalTrafficPolicy: Local` on the Service, so that connections reach
  gosftpd from the load balancer's own addresses instead of through another
  node, and list those.

A header from an address that is not trusted is refused with a warning that
names the peer. If that is a client's address, the load balancer already
keeps client addresses: turn PROXY protocol off there.

### Turning it on, and health checks

`trusted_proxies` is reloadable. Each connection is classified by the
configuration current at its accept, so a reload does not affect open
connections. The two sides cannot switch at the same moment: reload
gosftpd first, then the load balancer. In between, the load balancer's
connections without a header are refused as `proxy_header`.

The load balancer's health checks work when they send the header (HAProxy's
`check` does) or nothing at all (a bare TCP connect); see
[interop.md](interop.md#load-balancers) for HAProxy's check options.
`gosftpd healthcheck` reads `server.trusted_proxies` from the configuration
file and, when its own address is trusted, sends a `LOCAL` header before it
waits for the banner. A probe from a trusted address that sends no header
gets no banner; see [metrics.md](metrics.md#gosftpd-healthcheck).

## Landlock

On Linux, `serve` confines itself with Landlock once its listeners are bound
(`server.landlock`; what it protects against is in
[security.md](security.md#landlock)). The rules are computed once, at start,
from the configuration, and a reload cannot widen them. So the way the files
are laid out decides what a reload can change without a restart.

A directory gets a rule of its own only when it is dedicated to gosftpd: at
start it can be listed, and every entry in it is a file the configuration
names (the configuration and included files, `authorized_keys` files, the CA
file, the revocation list, host keys with their `.pub`, `.next`, `.old` and
certificate files, webhook `secret_file`s), a name derived from one (a
backup such as `config.toml~`, an editor's swap file, the temporary files of
`user add --write` and `hostkey rotate`), or a subdirectory such as
`users.d` that is dedicated itself. The full rule is in
[security.md](security.md#which-files-are-covered). In a dedicated directory
files may be replaced by rename (editors, `sed -i`, `user add --write`,
`hostkey rotate --finish`) and added later: a reload reads them. Elsewhere
each file gets a rule of its own, which belongs to the file, not to its
name: replaced by rename, the file cannot be read until a restart.

Keep in directories of their own, as the packaged layout does:

- the configuration file, `users.d/` (or the other include directories),
  the CA file, the revocation list and webhook secret files:
  `/etc/gosftpd`;
- the host keys: `/var/lib/gosftpd`;
- the audit log with its rotated copies: `/var/log/gosftpd`. Its directory
  gets write rights only when it holds nothing else, so that no
  configuration or key file is ever writable; next to other files, the
  audit log cannot be rotated by rename (logrotate's `create`) without a
  restart. Use a directory of its own or `copytruncate` (see
  [Rotation](audit-log.md#rotation)).

A `.ssh` directory, `/` and the home directory of the user running gosftpd
are never dedicated: in zero-config mode the default
`~/.ssh/authorized_keys` gets a rule on the file only, and the private keys
next to it stay unreadable. Create `users.d/` before the first start
(`gosftpd init` does): an include directory that does not exist at start
needs a restart for its first file. Files created later in a dedicated
directory are readable to gosftpd, so keep nothing else there.

At start gosftpd warns about each file that got a rule of its own, naming
its directory and up to three of the entries that make the directory
shared, or the symlink whose target lies in another directory (a NixOS
generation, an `ln -sfn` deployment: re-pointed, the link cannot be read
until a restart). `gosftpd config validate --check-fs` prints the same
warnings before the first start; run it as the user that runs gosftpd.

Under Landlock a restart is needed for (the reload names each in
`restart_required`, see [Reload](#reload)):

- a new mount, a mount moved outside the rules, and a mount directory that
  was recreated or had a disk mounted on it since the start; the mount is
  unavailable until then;
- `read_only = false` or `create = true` that the rules do not allow; the
  mount keeps its running value;
- a new `audit.output` outside the rules (the running output stays), and an
  audit log next to other files once it was rotated by rename;
- an exec hook added by a reload: Landlock is applied only without exec
  hooks, so the hook is left out (with `server.landlock = "required"` such
  a configuration is invalid, and the reload fails);
- a key, CA or secret file in a shared directory replaced by rename, or a
  re-pointed link to one. An include file, a revocation list or the
  configuration file itself that the rules do not cover (in a shared
  directory, replaced by rename: `sed -i`, most editors) fails the reload
  instead, until a restart.

`server.landlock = "off"` turns Landlock off, also for these cases; it takes
effect at the next restart.

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
  remounted mount directory is opened anew for new logins (without
  Landlock, and a remounted or recreated one is logged as `mount reopened`;
  under Landlock a recreated or remounted mount directory is unavailable
  until a restart, see [Landlock](#landlock)); old connections keep the old
  directory until they end.
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
- **Hooks** are replaced in place, for open connections too: removing a
  hook or rotating its secret takes effect at once. A kept hook's pending
  events are filtered again and use its new settings. A hook whose program
  fails its checks (missing, not executable, writable by others) is left
  out until a reload fixes it; one whose `secret_file` cannot be used keeps
  its running secret. Both give a warning, count in
  `gosftpd_hooks_not_updated`, and do not fail the reload. That gauge also
  counts, under Landlock, the exec hooks a reload added and left out (see
  below); for them the remedy is a restart.
- **Trusted proxies** (`server.trusted_proxies`) apply to connections
  accepted after the reload; open connections keep the classification they
  got at accept (see [Turning it on](#turning-it-on-and-health-checks)).
- **Restart only:** `server.listen`, `server.host_key_auto_generate`,
  `server.crypto_policy`, `server.landlock`, `log.format`, `audit.events`,
  `audit.on_error` and `metrics.listen`. A change is logged as a warning and listed in the
  `server.reload` audit event; the running value stays.
- **Under Landlock** (Linux) the ruleset applied at start stays as it is,
  and a reload cannot reach beyond it ([Landlock](#landlock)). A mount, a
  mount directory recreated or remounted since the start (unavailable), a
  mount's new rights, a new `audit.output` or an exec hook that the ruleset
  does not cover keeps its running value or is left out, and is named in
  `restart_required` (`mounts.NAME.path`, `mounts.NAME.read_only`,
  `mounts.NAME.create`, `audit.output`, `hooks`); with `server.landlock =
  "required"` a configuration with an exec hook is invalid, and the reload
  fails. A key, CA or secret file it does not cover is left out as an
  unreadable one is, and its key is listed too; an include file, a
  revocation list or the configuration file itself that it does not cover
  (in a shared directory, replaced by rename: `sed -i`, most editors)
  fails the reload, until a restart. Every such error in the log adds
  "outside the Landlock ruleset applied at start; restart gosftpd".

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
line that `systemctl status gosftpd` shows (`Type=notify-reload`):
`configuration reloaded`, `configuration reloaded; restart needed for:
KEYS` (the settings above that keep their running value, at most five,
then "and N more; see the log") or `configuration reload failed, see the
log`. `systemctl reload` itself succeeds either way; see
[install.md](install.md#the-result-of-a-reload).

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
| `gosftpd init` | Writes `./gosftpd.toml` (0600), a host key and an empty `users.d/` next to the file, for `user add --write`; never overwrites without `--force`. |
| `gosftpd config validate [--check-fs]` | Checks the configuration; with `--check-fs` also paths, keys and file permissions, and on Linux it prints the warnings serve gives when it applies Landlock (files that need a restart once replaced by rename, an audit log that cannot be rotated by rename). |
| `gosftpd config show` | Prints the effective configuration. |
| `gosftpd config example [--full]` | Prints an example. |
| `gosftpd user add NAME --key FILE\|KEY --access MOUNT=PERMISSIONS…` | Prints a `[users.NAME]` block to append. `--password-hash` adds a password, `--expires` an expiry (`720h` or a date). `--principal` sets `principals`. With `--write` it checks the configuration with the new user, writes `users.d/NAME.toml` (the directory of an `include` pattern; mode and group like the configuration file) and prints the connection details for the user: host, port, host key fingerprint, `sftp` command (`--host` sets the host name), and the `ssh-keygen` command to sign a certificate when CAs are trusted. A user that could not log in (disabled, expired, no key, password or certificate principal that `auth.methods` allows) is refused unless `--force`; with trusted CAs, a user needs no key. |
| `gosftpd user disable\|enable\|remove NAME` | Changes a user defined in an included file, keeping the rest of the file and its comments; `remove` deletes a file left without users. The main configuration file is never rewritten. A reload applies the change. |
| `gosftpd user hash-password [--stdin]` | Asks for a password twice (or reads one line with `--stdin`) and prints its argon2id hash. |
| `gosftpd user list` | Lists users with access, key count, certificate principals for trusted CAs, password, expiry and status (`off` when `auth.methods` leaves the method out). |
| `gosftpd hostkey generate [--type ed25519\|ecdsa\|rsa]` | Creates a host key; never overwrites. |
| `gosftpd hostkey show [--config FILE] [--known-hosts HOST:PORT]` | Prints the fingerprint, public key and `known_hosts` line of the host key (`--host-key`, `--state-dir`) or, with `--config`, of every configured one; then its next and previous keys and the certificate files that exist. The first lines describe the current key. |
| `gosftpd hostkey rotate [--type T] \| --finish \| --rollback \| --retire \| --abort` | Rotates a host key in steps, see [Rotation](#rotation). Selects the key like `show`; with `--config`, `--host-key` picks one of several. |
| `gosftpd healthcheck [--config FILE] [--address HOST:PORT \| --url URL] [--ready] [--timeout 5s]` | Checks that the server answers, for container health checks; see [metrics.md](metrics.md#gosftpd-healthcheck). |

Exit codes: 0 success, 1 runtime error, 2 invalid usage or configuration.
`gosftpd healthcheck` exits with 0 or 1 only: Docker reserves 2.
