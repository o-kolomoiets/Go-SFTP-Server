# gosftpd

[![CI](https://github.com/o-kolomoiets/go-sftp-server/actions/workflows/ci.yml/badge.svg)](https://github.com/o-kolomoiets/go-sftp-server/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

> **Status: alpha.** `gosftpd serve` works with the OpenSSH `sftp` and `scp`
> clients. Configuration files, multiple users and hardening for public
> servers (rate limits, bans) are not there yet — see the [plan](#plan).

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
a TOML config file, multiple users with per-mount permissions, resumable
uploads.

## Quick start

Requires Go 1.26.5 or newer.

```sh
go install github.com/o-kolomoiets/go-sftp-server/cmd/gosftpd@latest
mkdir share
gosftpd serve --dir ./share          # keys from ~/.ssh/authorized_keys
sftp -P 2022 "$USER@localhost"
```

On first start gosftpd generates an ed25519 host key in the user config
directory (`~/.config/gosftpd/` on Linux) and prints its fingerprint and a
`known_hosts` line.

| Flag | Default | Meaning |
|---|---|---|
| `--dir [NAME=]PATH` | — | directory to serve (repeatable); several dirs appear as `/NAME` |
| `--authorized-keys FILE` | `~/.ssh/authorized_keys` | accepted public keys |
| `--listen ADDR` | `:2022` | listen address |
| `--on-conflict MODE` | `rename` | upload over an existing file: `rename` to `name (1).ext`, `reject`, or `overwrite` |
| `--read-only` | off | refuse all modifications |
| `--user NAME` | any | accept only this SSH user name |
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
