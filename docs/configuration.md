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
| `handshake_timeout` | `"30s"` | Time a client has to finish the SSH handshake and authentication (1s–10m). |
| `shutdown_timeout` | `"30s"` | On SIGTERM/SIGINT, how long running transfers may finish before connections are closed (1s–1h). Keep it below systemd's `TimeoutStopSec` or Docker's `stop_grace_period`. |

## `[limits]`

| Key | Default | Meaning |
|---|---|---|
| `max_sessions_per_conn` | `4` | SFTP sessions (channels) per SSH connection (1–64). |
| `max_open_handles` | `64` | Open files and directories per SFTP session (1–4096). |
| `max_auth_tries` | `6` | Authentication attempts per connection (1–20). Lower values break SSH agents that offer many keys. |

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
| `on_conflict` | `"rename"` | Upload to an existing file: `rename`, `reject` or `overwrite`, see below. |
| `rename_template` | `"{stem} ({n}){ext}"` | Name of the copy with `rename`. Must contain `{n}`; may contain `{stem}` and `{ext}`; no slashes. |
| `max_rename_attempts` | `100` | Numbered names tried before `{n}` becomes a UTC timestamp with a random suffix (1–10000). |
| `compound_extensions` | `[".tar.gz", ".tar.bz2", ".tar.xz", ".tar.zst"]` | Extensions kept whole: `a.tar.gz` becomes `a (1).tar.gz`. |
| `resume` | `"append-only"` | Continuing an upload into an existing file (OpenSSH `reput`, paramiko mode `a`): `append-only` or `off`. |
| `stat_redirect` | `true` | After an upload or move went to another name, STAT and SETSTAT of the requested name answer for the new one, see below. |
| `setstat_mode` | `"times"` | What SETSTAT may change: `times` (access and modification time), `ignore` (accept and do nothing) or `deny`. |
| `symlinks` | `"inside-only"` | Existing symlinks on the host: `inside-only` follows those that stay inside the mount; `deny` refuses every path through a symlink and hides them from listings. |
| `umask` | `"0027"` | Removed from the mode of new files (0666) and directories (0777); a quoted octal string. |
| `require_mountpoint` | `false` | Refuse to start unless the path is a mount point (on another filesystem than its parent): protects against writing to the root disk when a disk is not mounted. |

### Upload conflicts

What happens when an upload targets an existing file (`on_conflict`):

| Policy | The upload… | The original |
|---|---|---|
| `rename` | goes to a free name from `rename_template`, e.g. `report (1).pdf` | untouched |
| `reject` | fails with "file exists (on_conflict=reject)" | untouched |
| `overwrite` | replaces the content (needs the `overwrite` permission) | replaced |

- An exclusive create (`O_EXCL`) of an existing file always fails.
- SFTP cannot tell the client the name it got; the audit event `fs.upload`
  records `path` and `final_path`.
- **Moves** (`posix-rename@openssh.com`, used by OpenSSH `rename`, rclone and
  WinSCP) onto an existing name follow the same policy; the classic SFTP
  RENAME never replaces a file.
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
  are never redirected; opening, removing or renaming the name ends the
  redirect. Without it, paramiko `put(confirm=True)` reports a size mismatch
  and rclone may delete what it takes for a failed copy: the original.
- `rename` plus a sync tool (`rclone sync`, `rsync`-like clients) creates a
  copy on every run; `on_conflict = "version"` (planned for v0.3) is meant
  for that.

## Users

### `[users.NAME]`

User names use lowercase letters, digits, `.`, `_` and `-` (32 at most,
starting with a letter or digit). An SSH login with an unknown name fails the
same way as a wrong key.

| Key | Default | Meaning |
|---|---|---|
| `authorized_keys` | none | Public keys, one OpenSSH `authorized_keys` line each. |
| `authorized_keys_file` | none | A file with more keys, read at start. |
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
`--on-conflict` apply to every mount.

## Commands

| Command | What it does |
|---|---|
| `gosftpd init` | Writes `./gosftpd.toml` (0600) and a host key; never overwrites without `--force`. |
| `gosftpd config validate [--check-fs]` | Checks the configuration; with `--check-fs` also paths, keys and file permissions. |
| `gosftpd config show` | Prints the effective configuration. |
| `gosftpd config example [--full]` | Prints an example. |
| `gosftpd user add NAME --key FILE\|KEY --access MOUNT=PERMISSIONS…` | Prints a `[users.NAME]` block to append; writes nothing. |
| `gosftpd user list` | Lists users with access, key count, expiry and status. |
| `gosftpd hostkey generate [--type ed25519\|ecdsa\|rsa]` | Creates a host key; never overwrites. |
| `gosftpd hostkey show [--known-hosts HOST:PORT]` | Prints the fingerprint and a `known_hosts` line. |

Exit codes: 0 success, 1 runtime error, 2 invalid usage or configuration.
