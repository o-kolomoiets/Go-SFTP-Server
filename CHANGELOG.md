# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Incompatible changes are prefixed with **BREAKING:**.

## [Unreleased]

### Added

- Connection limits checked right after accept, before the SSH handshake:
  `limits.max_connections` (256), `max_connections_per_ip` (16, per IPv4
  address or IPv6 /64) and `max_preauth_connections` (64). Refused
  connections are audited as `conn.reject`, at most 10 per second.
- Bans (`[auth.ban]`): a source with 10 failures within 10 minutes is
  refused at accept for 30 minutes, and its open connections get no further
  password checks. Every wrong password is a failure at once; rejected keys
  count once per connection, not per offered key; loopback is exempt by
  default; the table is bounded. New audit event `auth.ban`.
- `server.idle_timeout` (15m) closes connections without SFTP traffic;
  `server.keepalive_interval` (30s) closes connections that leave 3
  `keepalive@openssh.com` requests unanswered. `conn.close` reports
  `idle_timeout` or `keepalive_timeout`.
- Opt-in password login: `auth.methods = ["publickey", "password"]` and
  `password_hash` (argon2id; bcrypt accepted for imported accounts). Each
  attempt checks one hash; unknown users are checked against a stand-in of
  the costliest configured hash, and failures wait until it would have
  finished, so the response time does not reveal which users exist (fully
  with one kind of hash; `config validate` warns about mixed ones). Checks
  run at most one per available CPU. A method missing from `auth.methods` is
  refused, and its keys or passwords are not loaded. `gosftpd user hash-password [--stdin]` prints a hash, and
  `user add --password-hash` adds it to a user.
- `server.crypto_policy`: `modern` (default, as before) or `compat`, which
  adds NIST curve and SHA-2 Diffie-Hellman key exchange and non-ETM MACs for
  old clients.
- `on_conflict = "version"`: an upload or posix-rename onto an existing file
  replaces it and moves the old file to
  `.versions/<path>/<stem>.<UTC time><ext>`, keeping `versions.keep` (10)
  versions per file for at most `versions.max_age` (30 days); only users who
  may delete or overwrite files make older versions drop out. The versions
  directory is not listed (sync tools would delete it); clients can open it
  by path and read it, but not change it. Replacing a file this way
  needs only the `write` permission. `fs.upload` and `fs.rename` get
  `conflict = "versioned"` and `version_path`.
- `atomic_uploads`: uploads are written to a hidden temporary file
  (`.gosftpd-*.part`) and take their name only when closed, by the conflict
  policy at that moment; an aborted upload leaves nothing. Resume is not
  possible then. `fsync` flushes such uploads before they are published.
  Temporary files left by a crash are removed once 24 hours old (checked at
  start and every 6 hours) and when their directory is removed.
- `max_file_size` (off by default), checked against the end of every write
  and on truncation, and `min_free_space` (1 GiB), checked when a file is
  opened for writing. Sizes accept units such as `"10GiB"`.
- Fuzzing: six targets (path resolution, confinement on a tree with
  symlinks, conflict copy names, the configuration, `authorized_keys`, and
  arbitrary SFTP packets against the real handlers) run 60 seconds each on
  every change and 10 minutes each night.
- CI checks coverage floors of the security packages (unit and interop
  coverage merged), audits `crypto_policy = "modern"` with ssh-audit, and
  runs OpenSSF Scorecard weekly; all actions are pinned by commit SHA.
- Documents: [threat model](docs/security/threat-model.md),
  [hardening guide](docs/security/hardening.md), a manual WinSCP checklist,
  and [ADR 0004](docs/adr/0004-limits-extension.md) on
  `limits@openssh.com`.

### Changed

- **BREAKING:** `gosftpd serve` refuses to run as root unless `--allow-root`
  is given.
- A connection keeps the user name of its first authentication request, as
  sshd does; attempts with another name are refused.
- `auth.success` has `key_fp` only for public-key logins.
- Uploads are refused while the mount's filesystem has less than 1 GiB free
  (`min_free_space`; `"0"` turns the check off).
- `fs.rename` for a posix-rename that replaced its target under
  `on_conflict = "overwrite"` reports `conflict = "overwritten"` instead of
  `"none"`.
- Names starting with `.gosftpd-` (in any case) are reserved: hidden from
  listings and refused in paths.
- **BREAKING:** `rename_template` must contain `{n}` exactly once and be
  valid UTF-8 of at most 64 bytes, so that copy names always fit 255 bytes;
  `config validate` names a template that does not.

### Fixed

- A client that disconnected right after logging in left no `auth.success`
  and `conn.close` events.
- A client that sent READ or WRITE with a guessed handle before the answer
  to its OPEN raced with the OPEN inside `pkg/sftp`, which could crash the
  server; such requests now wait for the answer (found by fuzzing).
- Copy names under `on_conflict = "rename"` could exceed 255 bytes for
  names with a very long extension; a shortened name could equal the
  original.

## [0.2.0] - 2026-10-09

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
  without `APPEND` is a plain write; with `APPEND` the old end is always
  kept (offsets are used as sent, so a client that appends at offset 0 gets
  "existing data is immutable"). `fs.upload` records `start_offset`; a
  refused write is audited as `fs.denied` and the upload as `denied`.
  After a renamed `put`, a `reput` of the same name continues the copy.
- A file that an upload has open cannot be opened for writing in place by
  another upload (overwrite or resume) until it is closed: "file is busy".
- `stat_redirect` (default on): after an upload or rename went to a new name
  under the rename policy, STAT, LSTAT and SETSTAT of the requested name by
  the same user answer for the new one for 60 seconds, in all of the user's
  connections, so paramiko `put(confirm=True)` and rclone's size check work
  and never touch the original.
- Uploaders may rename and set times on files they created with only the
  `write` permission in any of their connections (rclone uploads on one
  connection and moves the file on another), for an hour after their last
  change and only while nobody else changed the file.
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
- Release binaries for Linux and macOS (amd64, arm64) with `checksums.txt`,
  built by GoReleaser when a release is published.
- Interop tests with OpenSSH 10.6p1, paramiko 5.0.0, rclone v1.75.0 and lftp
  in CI.
- Documentation: `docs/quickstart.md`, `configuration.md` (every key),
  `audit-log.md`, `security.md`, `interop.md`, `release-checklist.md`.

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

[Unreleased]: https://github.com/o-kolomoiets/go-sftp-server/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/o-kolomoiets/go-sftp-server/compare/v0.1.0-alpha...v0.2.0
[0.1.0-alpha]: https://github.com/o-kolomoiets/go-sftp-server/releases/tag/v0.1.0-alpha
