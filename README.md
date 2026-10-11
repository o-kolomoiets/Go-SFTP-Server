# gosftpd

[![CI](https://github.com/o-kolomoiets/go-sftp-server/actions/workflows/ci.yml/badge.svg)](https://github.com/o-kolomoiets/go-sftp-server/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/o-kolomoiets/go-sftp-server?include_prereleases)](https://github.com/o-kolomoiets/go-sftp-server/releases)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

**Turn a folder into an SFTP drop-box.**

gosftpd is an SFTP server in a single binary, for receiving files from
people, devices and backup jobs. Run `gosftpd serve --dir ./share` as an
ordinary user and it accepts the keys in your `~/.ssh/authorized_keys`; for
more users, write one TOML file.

- **No root, no system accounts, no database.** Users and per-folder
  permissions live in that file, not `/etc/passwd`.
- **Users stay where you put them.** Each sees only the folders you grant,
  nothing outside them ([limits](docs/security.md#limits-of-the-protection)).
- **No surprise overwrites.** By default a second `report.pdf` arrives as
  `report (1).pdf`; overwriting or keeping old versions is set per folder.
- **You know who did what.** Every login, transfer and change goes to a JSON
  audit log. By default, if the log cannot be written, gosftpd refuses changes
  and new connections.

> **Status: alpha.** It works, and CI tests it with OpenSSH `sftp` and `scp`,
> paramiko, rclone and lftp. Read the
> [hardening guide](docs/security/hardening.md) before exposing it to the
> internet, and see the [plan](#plan) for v1.0.

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
| `user add --write`, `user disable`, `enable`, `remove` (files in `users.d/`) | alpha |
| Upload conflicts: `rename` (default), `reject`, `overwrite`, `version` (keeps old versions) | beta |
| Resumable uploads that can only append | beta |
| JSON audit log with a stable schema, fail-closed | beta |
| `df` over SFTP, virtual file owners | beta |
| Connection limits, bans after failed logins, idle and keepalive timeouts | alpha |
| Opt-in password login (argon2id) | alpha |
| Atomic uploads, file size and free space limits | alpha |
| Reload on SIGHUP without dropping connections, `sd_notify` | alpha |
| OpenSSH user certificates (trusted CAs, `cert-authority`), revoked keys | alpha |
| Metrics, hooks, systemd unit | planned (v0.4) |
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
gosftpd user add partner --key partner.pub --access share=upload --write
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

- Login by public key (passwords only if enabled); an unknown user fails
  exactly like a wrong key or password.
- Connection limits before the handshake, and bans for sources that keep
  failing to log in.
- Each mount is an `os.Root`: `..`, absolute paths and symlinks cannot leave
  it, clients cannot create links, and host paths and accounts never reach
  clients.
- Uploads never replace a file unless the mount says `overwrite` and the user
  has that permission (or `version`, which keeps the old file); resumed
  uploads can only append. Optional atomic uploads never show partial
  files.
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
- [Security model](docs/security.md), [threat model](docs/security/threat-model.md)
  and [hardening guide](docs/security/hardening.md)
- [Client compatibility](docs/interop.md)
- [Release checklist](docs/release-checklist.md)
- [Design decisions](docs/adr/)

## Plan

The plan, milestones and design decisions are in [ROADMAP.md](ROADMAP.md);
progress is tracked in [TASKS.md](TASKS.md). Done for v0.4: reload on
SIGHUP, user management commands, SSH user certificates, host key rotation
and host certificates. Next: metrics, hooks and systemd integration.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Security issues: see
[SECURITY.md](SECURITY.md).

## License

[Apache License 2.0](LICENSE). Versions of this repository before the 2026
restart were published under GPL-3.0.
