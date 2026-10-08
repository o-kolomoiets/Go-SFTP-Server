# gosftpd

[![CI](https://github.com/o-kolomoiets/go-sftp-server/actions/workflows/ci.yml/badge.svg)](https://github.com/o-kolomoiets/go-sftp-server/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/o-kolomoiets/go-sftp-server?include_prereleases)](https://github.com/o-kolomoiets/go-sftp-server/releases)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

**gosftpd is a single static binary that turns any directory into a secure
SFTP drop-box: key-only login, confinement with Go's `os.Root`, uploads that
never silently overwrite a file, and a JSON audit log of every action. No
root, no database, no web UI.**

> **Status: alpha.** It works with OpenSSH, paramiko, rclone and lftp, with
> several users and per-folder permissions. Hardening for servers exposed to
> the internet (rate limits, bans) is not there yet: see the [plan](#plan).

## What it is, and what it is not

gosftpd serves SFTP and nothing else: no shell or exec, no port forwarding,
no legacy SCP (`scp` over SFTP works), no FTP or WebDAV, no web interface, no
cloud storage backends. It is not a replacement for OpenSSH; it is a file
exchange point that you can run next to it as an ordinary user. See
[docs/adr/0002-non-goals.md](docs/adr/0002-non-goals.md).

## Features

| Feature | Status |
|---|---|
| Public-key login, OpenSSH `authorized_keys` with `from=` and `expiry-time=` | beta |
| Mounts confined with `os.Root`, per-user home directories (`{user}`) | beta |
| Users and permissions in one TOML file (`read`, `upload`, `readwrite`, `full`) | beta |
| Upload conflicts: `rename` (default), `reject`, `overwrite` | beta |
| Resumable uploads that can only append | beta |
| JSON audit log with a stable schema, fail-closed | beta |
| `df` over SFTP, virtual file owners | beta |
| Password login, rate limits and bans, `version` conflict mode | planned (v0.3) |
| Reload on SIGHUP, metrics, hooks, systemd integration, SSH certificates | planned (v0.4) |
| Docker image, deb/rpm packages, signed releases | planned (v0.5) |

## Quick start

Download a release archive or build with Go 1.26.5+:

```sh
go install github.com/o-kolomoiets/go-sftp-server/cmd/gosftpd@latest
```

Serve one directory to yourself, with the keys from `~/.ssh/authorized_keys`:

```sh
mkdir share
gosftpd serve --dir ./share
sftp -P 2022 "$USER@localhost"
```

Or set up users with a configuration file:

```sh
gosftpd init --user alice --authorized-keys ~/.ssh/id_ed25519.pub
gosftpd user add partner --key partner.pub --access share=upload >> gosftpd.toml
gosftpd config validate --check-fs
gosftpd serve
```

[docs/quickstart.md](docs/quickstart.md) walks through both, including host
key verification.

## Configuration

```toml
config_version = 1

[server]
listen = [":2022"]
host_keys = ["/var/lib/gosftpd/ssh_host_ed25519_key"]
host_key_auto_generate = true

[mounts.inbox]
path = "/srv/sftp/inbox"
on_conflict = "rename"          # rename | reject | overwrite

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
access = { inbox = "upload" }   # list and upload; no reading, deleting or overwriting
```

Every key is described in [docs/configuration.md](docs/configuration.md);
`gosftpd config example --full` prints them all with their defaults. Unknown
keys are an error, and `gosftpd config validate` reports every problem with
its key path.

## Security model in short

- Login by public key only; an unknown user fails exactly like a wrong key.
- Each mount is an `os.Root`: `..`, absolute paths and symlinks cannot leave
  it, clients cannot create links, and host paths and accounts never reach
  clients.
- Uploads never replace a file unless the mount says `overwrite` and the user
  has that permission; resumed uploads can only append.
- Configuration and key files are checked like sshd's `StrictModes`.
- If the audit log cannot be written, gosftpd stops accepting changes.

`os.Root` does not cover bind mounts or hard links made on the host, and
symlinks that local users create can race checks. Read
[docs/security.md](docs/security.md) before exposing a server.

## Why not…

| | Trade-off |
|---|---|
| OpenSSH `internal-sftp` + `ChrootDirectory` | System accounts, root-owned chroot paths, syslog only, uploads overwrite. |
| SFTPGo | A platform (FTP, WebDAV, HTTP, cloud backends, web admin) with a large surface, AGPL. |
| `atmoz/sftp` | OpenSSH in Docker; no longer maintained, chroot limits. |
| `rclone serve sftp` | Built to expose a backend, effectively one user. |

gosftpd is for the narrow case of "partners and devices drop files into
folders, and I want to know who did what": one binary, a TOML file, a JSON
log.

## Documentation

- [Quick start](docs/quickstart.md)
- [Configuration](docs/configuration.md)
- [Audit log](docs/audit-log.md)
- [Security model](docs/security.md)
- [Client compatibility](docs/interop.md)
- [Release checklist](docs/release-checklist.md)
- [Design decisions](docs/adr/)

## Plan

The plan, milestones and design decisions are in [ROADMAP.md](ROADMAP.md) (in
Russian); progress is tracked in [TASKS.md](TASKS.md). Next (v0.3): password
login, connection limits and bans, atomic uploads and a `version` conflict
mode, fuzzing.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Security issues: see
[SECURITY.md](SECURITY.md).

## License

[Apache License 2.0](LICENSE). Versions of this repository before the 2026
restart were published under GPL-3.0.
