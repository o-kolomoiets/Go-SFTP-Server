# gosftpd

[![CI](https://github.com/o-kolomoiets/go-sftp-server/actions/workflows/ci.yml/badge.svg)](https://github.com/o-kolomoiets/go-sftp-server/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

> **Status: alpha.** `gosftpd serve` works with the OpenSSH `sftp` and `scp`
> clients, with a configuration file, several users and per-mount
> permissions. Hardening for public servers (rate limits, bans) is not there
> yet — see the [plan](#plan).

gosftpd aims to be a single static binary that turns any directory into a
secure SFTP drop-box:

- public-key login only by default;
- every mount is confined with Go's `os.Root`: no escapes via `..`, absolute
  paths or symlinks;
- uploads never silently overwrite an existing file (rename, reject, overwrite
  or keep versions, per mount);
- every action is written to a JSON audit log;
- no root, no database, no web UI.

What it will deliberately **not** do: shell or exec access, port forwarding,
legacy SCP, FTP/WebDAV, a web interface, object-storage backends. See
[docs/adr/0002-non-goals.md](docs/adr/0002-non-goals.md).

## Plan

The full plan, milestones and design decisions are in [ROADMAP.md](ROADMAP.md)
(in Russian); progress is tracked in [TASKS.md](TASKS.md). Next up (v0.2):
resumable uploads, `statvfs` (`df`), virtual file owners, interop with
paramiko, rclone and lftp, release binaries.

## Quick start

Requires Go 1.26.5 or newer.

```sh
go install github.com/o-kolomoiets/go-sftp-server/cmd/gosftpd@latest
```

**One directory, no configuration** — every SSH user name is accepted with
the keys from `~/.ssh/authorized_keys`:

```sh
mkdir share
gosftpd serve --dir ./share
sftp -P 2022 "$USER@localhost"
```

On first start gosftpd generates an ed25519 host key in the user config
directory (`~/.config/gosftpd/` on Linux) and prints its fingerprint and a
`known_hosts` line.

**With a configuration file** — users, permissions and several directories:

```sh
gosftpd init                         # writes ./gosftpd.toml and a host key
gosftpd user add partner --key partner.pub --access share=upload >> gosftpd.toml
gosftpd config validate --check-fs
gosftpd serve                        # finds ./gosftpd.toml
```

## Configuration

`gosftpd config example` prints a minimal working configuration and
`gosftpd config example --full` a reference of every key. A small one:

```toml
config_version = 1

[server]
listen = [":2022"]
host_keys = ["/var/lib/gosftpd/ssh_host_ed25519_key"]
host_key_auto_generate = true

[mounts.inbox]
path = "/srv/sftp/inbox"
on_conflict = "rename"       # rename | reject | overwrite

[mounts.home]
path = "/srv/sftp/home/{user}"  # one directory per user
create = true

[users.alice]
authorized_keys_file = "/etc/gosftpd/keys/alice.pub"
access = { inbox = "full", home = "full" }

[users.partner]
authorized_keys = ["ssh-ed25519 AAAA... partner@laptop"]
allow_from = ["203.0.113.0/24"]
expires = 2026-12-31T23:59:59Z
access = { inbox = "upload" }
```

| Preset | Flags | Typical use |
|---|---|---|
| `read` | list, read | public downloads |
| `upload` | list, write, mkdir | partner drop-box: no reading, deleting or overwriting |
| `readwrite` | list, read, write, overwrite, rename, mkdir, setstat | shared work folder |
| `full` | all of the above plus delete, rmdir | personal home |

Unknown keys are an error, and `gosftpd config validate` prints every problem
with its key path (exit code 2). The configuration file is found via
`--config`, `$GOSFTPD_CONFIG`, `./gosftpd.toml`, `/etc/gosftpd/config.toml` or
the user configuration directory; flags override the environment
(`GOSFTPD_LISTEN`, `GOSFTPD_LOG_LEVEL`, `GOSFTPD_LOG_FORMAT`), which overrides
the file. Like sshd, gosftpd refuses configuration, key and `authorized_keys`
files that are writable by group or others.

| `serve` flag | Default | Meaning |
|---|---|---|
| `--config FILE` | search order above | configuration file |
| `--dir [NAME=]PATH` | — | serve without a configuration file (repeatable); several dirs appear as `/NAME` |
| `--authorized-keys FILE` | `~/.ssh/authorized_keys` | with `--dir`: accepted public keys |
| `--user NAME` | any | with `--dir`: accept only this SSH user name |
| `--listen ADDR` | `:2022` | listen address |
| `--on-conflict MODE` | `rename` | upload over an existing file: `rename` to `name (1).ext`, `reject`, or `overwrite` |
| `--read-only` | off | refuse all modifications |
| `--audit-output DEST` | `stdout` | JSON audit log: `stdout` or a file |
| `--host-key PATH` | generated | host private key (repeatable) |

What you get today:

- public-key authentication only; `authorized_keys` options other than
  `from=`, `expiry-time=` and `restrict`-style flags make a line be skipped;
- every mount is an `os.Root`: `..`, absolute paths and symlinks cannot leave
  it; creating symlinks or hard links is refused;
- shell, exec and port forwarding are refused;
- one JSON audit line per action (`fs.upload` records the requested and the
  final path); if the audit log cannot be written, uploads and new
  connections are refused;
- resuming an upload into an existing file is refused for now.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Security issues: see [SECURITY.md](SECURITY.md).

## License

[Apache License 2.0](LICENSE). Versions of this repository before the 2026
restart were published under GPL-3.0.
