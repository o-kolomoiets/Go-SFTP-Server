# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Incompatible changes are prefixed with **BREAKING:**.

## [Unreleased]

### Added

- Configuration file (TOML, `config_version = 1`): found via `--config`,
  `$GOSFTPD_CONFIG`, `./gosftpd.toml`, `/etc/gosftpd/config.toml` or the user
  configuration directory. Unknown keys are an error; every problem is
  reported at once with its key path. `include` merges `[users.NAME]` tables
  from other files.
- Multiple users (`[users.NAME]`): inline `authorized_keys` and
  `authorized_keys_file`, `allow_from`, `expires`, `disabled`.
- Per-mount permissions: presets `read`, `upload`, `readwrite`, `full` or
  flags (`list`, `read`, `write`, `overwrite`, `delete`, `rename`, `mkdir`,
  `rmdir`, `setstat`). Uploaders may rename and set times on files they
  created in the same session (WinSCP `.filepart`, rclone `.partial`).
- Per-user home directories: a mount path ending in `{user}`. A home that is
  a symlink or not a directory makes the mount unavailable (audited as
  `fs.denied` with `reason=home_not_dir`).
- Mount options: `create`, `read_only`, `on_conflict`, `rename_template`,
  `max_rename_attempts`, `compound_extensions`, `setstat_mode`, `umask`,
  `require_mountpoint`; `[defaults]` for all mounts and `flatten`.
- Server options: several `listen` addresses, `host_keys` with
  `host_key_auto_generate`, `handshake_timeout`, `shutdown_timeout`;
  `[limits]` `max_sessions_per_conn`, `max_open_handles`, `max_auth_tries`.
- Commands: `init`, `config validate [--check-fs]`, `config show`,
  `config example [--full]`, `user add`, `user list`, `hostkey generate`,
  `completion`.
- Startup checks like sshd's StrictModes: configuration, `authorized_keys`
  and host key files must not be writable by group or others and must
  belong to root or to the user running gosftpd.
- Resumable uploads (OpenSSH `reput`, paramiko mode `a`, Cyberduck) with an
  append-only guard: the bytes a file had when it was opened cannot be
  changed or truncated (`resume = "append-only"`, the default, or `"off"`).
  With `on_conflict = "overwrite"` and the `overwrite` permission a resume
  is a plain write. `fs.upload` records `start_offset`.
- `stat_redirect` (default on): after an upload or rename went to a new name
  under the rename policy, STAT, LSTAT and SETSTAT of the requested name in
  the same session answer for the new one for 60 seconds, so paramiko
  `put(confirm=True)` and rclone's size check work and never touch the
  original.
- `statvfs@openssh.com` (`df` in sftp) on Linux, macOS and FreeBSD; mounts
  the user cannot change are reported read-only.
- Listings show a virtual owner (uid/gid 1000, the user's own name in
  `ls -l`) instead of host accounts.
- `symlinks = "deny"` refuses paths through existing symlinks and hides them
  from listings; the default `"inside-only"` follows links that stay inside
  the mount.
- `[audit]` `events` selects categories (`conn`, `auth`, `session`,
  `transfer`, `modify`, `denied`, opt-in `list` and `stat`; `server` is
  always on) and `on_error = "fail-open"` keeps serving when the audit log
  cannot be written. The format is pinned by a schema test.

### Changed

- New files are created with mode `0666 &^ umask` and directories with
  `0777 &^ umask`; the default `umask` is `0027` (was a fixed 0644/0755).
- `serve` without `--dir` now reads a configuration file instead of failing.
  `--authorized-keys`, `--user` and `--state-dir` only apply with `--dir`.

## [0.1.0-alpha] - 2026-10-08

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

[Unreleased]: https://github.com/o-kolomoiets/go-sftp-server/compare/v0.1.0-alpha...HEAD
[0.1.0-alpha]: https://github.com/o-kolomoiets/go-sftp-server/releases/tag/v0.1.0-alpha
