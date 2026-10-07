# gosftpd

[![CI](https://github.com/o-kolomoiets/go-sftp-server/actions/workflows/ci.yml/badge.svg)](https://github.com/o-kolomoiets/go-sftp-server/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

> **Status: pre-alpha. It does not serve files yet.** The project was restarted
> from scratch in October 2026; the current code is only the foundation
> (build, CI, `gosftpd version`). Do not use it for anything real yet.

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
(in Russian); progress is tracked in [TASKS.md](TASKS.md). The first usable
release is the M1 milestone: `gosftpd serve --dir ./share` working with the
OpenSSH `sftp` and `scp` clients.

## Building

Requires Go 1.26.5 or newer.

```sh
go install github.com/o-kolomoiets/go-sftp-server/cmd/gosftpd@latest
gosftpd version
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Security issues: see [SECURITY.md](SECURITY.md).

## License

[Apache License 2.0](LICENSE). Versions of this repository before the 2026
restart were published under GPL-3.0.
