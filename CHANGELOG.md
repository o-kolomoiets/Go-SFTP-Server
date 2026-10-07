# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Incompatible changes are prefixed with **BREAKING:**.

## [Unreleased]

### Added

- `gosftpd serve`: serves one or more directories over SFTP with public-key
  authentication from an `authorized_keys` file; every mount is confined with
  `os.Root`; shell, exec, forwarding, symlink and hard-link creation are
  refused.
- Upload conflict policy `--on-conflict rename|reject|overwrite` (default
  `rename`: the upload goes to `name (1).ext` and the original is untouched).
- JSON audit log (`--audit-output`), fail-closed when it cannot be written.
- Host key generation on first start; `gosftpd hostkey show`.
- Graceful shutdown on SIGINT/SIGTERM; SIGHUP is ignored.
- Interop tests with OpenSSH `sftp`, `scp` and `ssh` in CI.
- `gosftpd version [--json]`.
- CI: lint, tests on Linux/macOS/Windows with Go 1.26 and 1.27, minimum Go
  version build, govulncheck; Dependabot.
- Project roadmap (`ROADMAP.md`), task tracker (`TASKS.md`), ADRs in `docs/adr/`.

### Changed

- **BREAKING:** the project was restarted from scratch. Module path is now
  `github.com/o-kolomoiets/go-sftp-server`, the binary is `gosftpd`.
- Relicensed from GPL-3.0 to Apache-2.0 as of this release; earlier commits
  remain available under GPL-3.0.

### Removed

- The non-functional 2023 skeleton (`main.go`, `cmd/server`, `pkg/`).
- The JSON configuration promised by the old README; configuration will use TOML.
