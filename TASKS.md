# TASKS: ROADMAP progress tracker

The plan, rationale and acceptance criteria are in [ROADMAP.md](ROADMAP.md). This file tracks only the status of the work. Detailed tasks are written out for the current and the next milestone; the rest are listed as large blocks for now and are broken down when work reaches them.

**Legend:** ✅ done · 🔄 in progress · ⬜ not started · 👤 owner action needed (GitHub settings and the like; this cannot be done from a session)

## Summary

| Milestone | Version | Status | Done |
|---|---|---|---|
| M0 Foundation | — | 🔄 | 18 / 21 |
| M1 Vertical slice | v0.1.0-alpha | ✅ | 19 / 19 |
| M2 MVP | v0.2.0 | ✅ | 18 / 18 |
| M3 Hardening | v0.3.0 | ✅ | 12 / 12 |
| M3b Windows | — | ⬜ | 0 / 3 |
| M4 Multi-user and Ops | v0.4.0 | 🔄 | 3 / 9 |
| M5 Distribution | v0.5.0 | ⬜ | 0 / 7 |
| M6 v1.0 | v1.0.0 | ⬜ | 0 / 8 |

## M0: Foundation and cleanup

| ID | Task | Status | Where / note |
|---|---|---|---|
| M0-01 | D1 license (Apache-2.0), D2 names (`go-sftp-server` / `gosftpd`) | ✅ | Confirmed by the owner; `docs/adr/0001-foundation.md` |
| M0-02 | D3, D4, D14, D16, D17, D19 per the recommendations in §13 | ✅ | ADR 0001; can be revisited |
| M0-03 | Remove the old code (`main.go`, `cmd/server`, `pkg/`) | ✅ | |
| M0-04 | Module path `github.com/o-kolomoiets/go-sftp-server`, `go 1.26.5` | ✅ | `go.mod` |
| M0-05 | Skeleton: `cmd/gosftpd`, `internal/cli` (cobra, `version [--json]`, exit codes 0/1/2), `internal/version` | ✅ | With unit tests |
| M0-06 | `.gitattributes` (LF), `.gitignore`, `.editorconfig` | ✅ | |
| M0-07 | `LICENSE` → Apache-2.0, SPDX headers in `.go` files | ✅ | CHANGELOG entry |
| M0-08 | Honest README in English | ✅ | |
| M0-09 | CI `ci.yml`: lint, test (Linux amd64/arm64, macOS, Windows × Go 1.26/1.27), min-go, govulncheck, `ci-ok` | ✅ | |
| M0-10 | `.golangci.yml` (§9.2) | ✅ | `config verify` and `run` are clean |
| M0-11 | `tools/go.mod` (govulncheck, staticcheck, gotestsum, actionlint), `Makefile` | ✅ | go-licenses will be added in M5 |
| M0-12 | `.github/dependabot.yml` (gomod `/` and `/tools`, github-actions) | ✅ | |
| M0-13 | `SECURITY.md`, `CONTRIBUTING.md`, `CHANGELOG.md`, issue and PR templates, `CODEOWNERS` | ✅ | |
| M0-14 | `docs/adr/0001-foundation.md`, `docs/adr/0002-non-goals.md`, `docs/DEPENDENCIES.md` | ✅ | |
| M0-15 | Task tracker | ✅ | This file instead of GitHub milestones and issues; move to issues once contributors appear |
| M0-16 | `CODE_OF_CONDUCT.md` (Contributor Covenant 3.0) | ⬜ 👤 | Needs a contact for complaints (email): the owner provides it, and I will add the text |
| M0-17 | Rename the repository to `go-sftp-server` | ⬜ 👤 | Settings → General → Repository name. Not required: GitHub URLs are case-insensitive |
| M0-18 | Enable private vulnerability reporting, secret scanning + push protection, CodeQL default setup | ✅ | PVR (verified via the API), Secret Protection, push protection, Dependabot alerts and security updates, CodeQL (the `Analyze (go)` check in PR #3) |
| M0-19 | Ruleset on `main`: PR required (approvals: 0), required check `ci-ok`, no deletion or force-push | ✅ | Verified via the API on 2026-10-08: `deletion`, `non_fast_forward`, `pull_request`, `required_status_checks: ci-ok`. Linear history and code scanning are not enabled: merge commits are allowed, and CodeQL runs on every PR anyway |
| M0-20 | DoD: `go install github.com/o-kolomoiets/go-sftp-server/cmd/gosftpd@latest` works | ✅ | Verified on 2026-10-07 with a clean GOBIN |
| M0-21 | DoD: the Community Standards page is fully complete | ⬜ | After M0-16 |

## M1: Vertical slice (v0.1.0-alpha)

Goal: `gosftpd serve --dir ./share` → OpenSSH `sftp`/`scp` do list/get/put/mkdir/rm/rename inside `os.Root`, with an audit entry for every operation and a clean shutdown. Details: ROADMAP §5 M1.

| ID | Task | Status | Where / note |
|---|---|---|---|
| M1-01 | Spike: handshake + subsystem `sftp` + `exit-status` in an in-process test; dependencies x/crypto v0.57.0, pkg/sftp v1.13.11 | ✅ | Done as part of M1: test `TestExitStatus` |
| M1-02 | `internal/hostkey`: ed25519 generation (`O_EXCL`, 0600), loading with a permission check, RSA with SHA-2 only, fingerprint and known_hosts | ✅ | `internal/hostkey` |
| M1-03 | `internal/server`: `ServerConfig` (`modern` profile, `MaxAuthTries 6`, `ServerVersion`, `AuthLogCallback`) | ✅ | `internal/server`, `modern` profile |
| M1-04 | Accept loop: 30 s handshake deadline, `recover`, connection accounting, backoff | ✅ |  |
| M1-05 | Channels: only `session` (≤ 4 per connection), subsystem via `ssh.Unmarshal`, everything else gets `Reply(false)` | ✅ | direct-tcpip, exec, shell and other subsystems are rejected (tests) |
| M1-06 | `RequestServer` + `exit-status` (0 on `nil`/`io.EOF`, otherwise 1) | ✅ | T1 closed: `scp` exits with 0 (interop) |
| M1-07 | Graceful shutdown (SIGINT/SIGTERM, `shutdown_timeout`), SIGHUP is ignored | ✅ | Verified in interop: SIGHUP does not stop the server, SIGTERM → exit 0 |
| M1-08 | `ServeConn` for tests | ✅ | `testutil.AsyncConn` moved to M3-12 (needed for synctest timeout tests) |
| M1-09 | `internal/auth`: `--authorized-keys`, option allowlist, pure lookup, identity only from `Permissions`, `--user` | ✅ | `internal/auth`; `from=` → `source-address`, `expiry-time=`, `cert-authority`/`verify-required` are rejected |
| M1-10 | `internal/vfs`: mount table from `--dir [NAME=]PATH`, `os.OpenRoot`, synthetic root, `resolve()` | ✅ | `internal/vfs` |
| M1-11 | VFS operations: open (`O_NONBLOCK`, regular files only), write (without `O_APPEND`), stat/lstat, listing, mkdir, remove, rename no-clobber, symlink/link → unsupported, setstat | ✅ | Rename without overwrite: `renameat2(RENAME_NOREPLACE)` on Linux, otherwise `Link`+`Remove` |
| M1-12 | Conflict policy `rename\|reject\|overwrite`: `O_EXCL` reservation, remap of `r.Filepath`, posix-rename, cleanup of interrupted uploads; resume is rejected | ✅ | 50 parallel uploads → 50 files, the original is intact |
| M1-13 | `internal/sftpd`: `SetSFTPExtensions` once, error mapping (`sftpStatus`), limit of 64 handles, byte counting, `TransferError` | ✅ | `internal/sftpd` |
| M1-14 | `internal/audit`: JSON via slog, a sink that catches write errors (fail-closed), events from §6.4 | ✅ | `internal/audit` |
| M1-15 | CLI `serve` (M1 flags), `hostkey show`, first-run output | ✅ | `gosftpd serve`, `gosftpd hostkey show` |
| M1-16 | Integration tests: ST-1…5, 7, 9…11, 50 parallel uploads, goleak | ✅ | ST-1…5, 7, 9…11 + fail-closed audit; goleak, `-race`; `internal/vfs` coverage 81% |
| M1-17 | Interop: `test/interop/run.sh` + `basic.batch` (`sftp -b`, `scp`), a CI job, add it to `ci-ok` | ✅ | `test/interop/run.sh` (26 checks, OpenSSH 9.6p1), `interop` job in CI |
| M1-18 | `docs/adr/0003-sftp-library.md` | ✅ |  |
| M1-19 | M1 DoD check, tag `v0.1.0-alpha` | ✅ | [Release v0.1.0-alpha](https://github.com/o-kolomoiets/Go-SFTP-Server/releases/tag/v0.1.0-alpha) (pre-release, 533795c); `go list -m …@v0.1.0-alpha` finds it via proxy.golang.org. The check against OpenSSH 10.x moved to M2-15 |

## M2: MVP (v0.2.0)

| ID | Task | Status | Where / note |
|---|---|---|---|
| **M2a** | **Config, users, permissions, CLI** | | |
| M2-01 | `internal/config`: types, `Default()`, TOML loading (an unknown key is an error with its position), `FileMode`, `config_version`, `include` | ✅ | `internal/config`; `ByteSize` comes in M3 together with `max_file_size`. `include` accepts only `[users.NAME]` |
| M2-02 | Sources: config file search order, precedence flags > env > file > defaults; zero-config `--dir` without a config file search | ✅ | `config.Find`, `cli.buildConfig`; `--authorized-keys`, `--user`, `--state-dir` only with `--dir` |
| M2-03 | `Validate()` (all errors at once, with the key path) and `CheckFS()` (mount paths, file permissions per §6.5) | ✅ | File permissions as with StrictModes in sshd: the server does not start if the config, keys or `authorized_keys` are group-writable |
| M2-04 | Mount options: `create`, `read_only`, `on_conflict`, `rename_template`, `max_rename_attempts`, `compound_extensions`, `umask`, `require_mountpoint`, `setstat_mode`, `flatten` | ✅ | `symlinks`, `resume`, `stat_redirect` come in M2b |
| M2-05 | Users `[users.NAME]`: `authorized_keys`, `authorized_keys_file`, `allow_from`, `expires`, `disabled`, `access`; an unknown user takes the same path as a wrong key | ✅ | `auth.NewUsers` |
| M2-06 | Permissions: flags and presets from §6.3, temp uploads via `write`, `size` on this session's writer, `read_only` | ✅ | `vfs/perm.go`; interop: users `read`, `upload`, `full` with OpenSSH |
| M2-07 | `{user}` home: safe creation and opening (ST-12) | ✅ | `Mount.openHome`: `Lstat` + `OpenRoot` + `os.SameFile`; a symlink `alice → bob` or one pointing outside → the mount is unavailable, `fs.denied reason=home_not_dir` |
| M2-08 | CLI: `init`, `config validate\|show\|example`, `user add\|list`, `hostkey generate`, `completion`; golden tests | ✅ | golden test for `user add`; `completion` is a built-in cobra command |
| M2-09 | Config examples via go:embed; a `Validate()` test and an e2e test of the minimal example | ✅ | `TestExamples`, `TestExampleFullCoversEveryKey`, `TestServeMinimalExample` |
| **M2b** | **Protocol** | | |
| M2-10 | Resume: append-only guard, `resume = "append-only"\|"off"` | ✅ | `WriteAt` and `FSETSTAT size` below the original size → `PERMISSION_DENIED` "existing data is immutable"; interop: `reput` produces an identical file |
| M2-11 | `stat_redirect` (session-scoped, TTL 60 s, posix-rename target) | ✅ | STAT, LSTAT, SETSTAT; cleared on open, remove or rename of this path |
| M2-12 | `statvfs@openssh.com` (Linux, darwin, freebsd) | ✅ | `df -h` in interop; a mount without permission to modify is read-only |
| M2-13 | Virtual owners in listings, `Readlink` → unsupported, policy `symlinks = "inside-only"\|"deny"` | ✅ | uid/gid 1000, `ls -l` shows the user name |
| M2-14 | Audit: `audit.events` filter, `audit.on_error`, golden schema `testdata/audit.schema.json` | ✅ | `internal/server/testdata/audit.schema.json` + `TestAuditSchema`; events `fs.list`, `fs.stat` (opt-in) |
| **M2c** | **Interop, documentation, release** | | |
| M2-15 | Interop: OpenSSH 10.x, paramiko, rclone, lftp | ✅ | CI: interop matrix (OpenSSH 9.6p1 + paramiko 5.0.0, rclone v1.75.0, lftp; OpenSSH 10.6p1 built from source); 62 checks locally. Found and fixed: rclone works over several connections → "own" files and `stat_redirect` now apply per user |
| M2-16 | Documentation: README, quickstart, configuration (a test for every key), audit-log, security, interop, release-checklist | ✅ | `docs/*.md`; tests `TestConfigurationDocCoversEveryKey`, `TestAuditDocCoversSchema` |
| M2-17 | Minimal GoReleaser, `release.yml`, job `goreleaser-check` | ✅ | `.goreleaser.yaml` (linux, darwin × amd64, arm64), `release.yml` runs when a release is published, job `goreleaser-check` in `ci-ok` |
| M2-18 | M2 DoD, release `v0.2.0` | ✅ | DoD verified (coverage: 87% total, vfs 88.9%, auth 91.7%, config 87.1%, sftpd 82.9%). Release published by the owner on 2026-10-09: 4 archives and `checksums.txt` match, `gosftpd version` = `v0.2.0` (commit `ae4b125`), the version is in the Go proxy, a test upload via OpenSSH `sftp` |

## M3: Hardening (v0.3.0)

Three PRs: M3a — network and login (01–03, 07, 10, 12), M3b — disk and uploads (04–06), M3c — fuzzing, CI, documents and release (08, 09, 11).

| ID | Block | Status | Details |
|---|---|---|---|
| M3-01 | Connection limits, idle timeout, keepalive | ✅ | `max_connections`, `max_connections_per_ip` (IPv6 by /64), `max_preauth_connections` are checked right after accept; `conn.reject` at most 10/s; `idle_timeout` counts only SFTP traffic; keepalive: 3 misses close the connection; TCP keepalive on the listener; a test with 1000 "silent" connections |
| M3-02 | Ban table | ✅ | Sliding window; every wrong password counts as a failure immediately (even in a connection that later logs in), open connections of a banned source no longer check passwords; rejected keys count as one failure per connection; LRU of 65 536 entries each for failures and bans, `exempt` by address; `auth.ban`, `conn.reject reason=banned`; a test with 1 million sources |
| M3-03 | Opt-in passwords (argon2id), `user hash-password` | ✅ | `auth.methods` enables and disables both methods; `password_hash` (argon2id; bcrypt 10–14 for import; limits m ≤ 64 MiB, t ≤ 10, p ≤ 8); an attempt checks one hash (unknown users get a stand-in of the most expensive class), a failure is padded with a pause up to its time without spending CPU; with hashes of one class, the timing does not depend on the user name under any load, and with mixed classes `config validate` warns; a semaphore sized by `GOMAXPROCS` that accounts for argon2id threads, a test of timing medians; the user name is pinned to the connection, as in sshd; `user add --password-hash`; interop: OpenSSH (SSH_ASKPASS) and paramiko |
| M3-04 | `max_file_size`, `min_free_space` | ✅ | `ByteSize` in the config (`"10GiB"`); `max_file_size` is checked against the end of every write (the sparse trick is closed) and on truncate, a refusal is `result=denied`; `min_free_space` (1 GiB) via statfs when opening for writing |
| M3-05 | `atomic_uploads`, janitor | ✅ | A temporary file `.gosftpd-<16hex>.part` (0600) next to the target, hidden from listings, `.gosftpd-*` names are inaccessible to clients (case-insensitive); published on `Close` by a rename without overwrite, with the conflict policy applied at that moment; on a dropped connection or a failed write, the file is removed; FSTAT/FSETSTAT reach the temporary file; `fsync`; resume is disabled; the janitor runs at startup and every 6 h (files older than 24 h, skipping read-only mounts), RMDIR removes orphaned temp files; interop: `kill -9` of the client leaves no file behind |
| M3-06 | `on_conflict = "version"` | ✅ | The old file moves to `.versions/<rel>/<stem>.<UTC>[-N]<ext>`, `keep` and `max_age` (excess versions are evicted only by a user with `delete` or `overwrite`); posix-rename versions the target the same way; the `write` permission is enough; `.versions` is not listed (sync tools do not try to delete it), can be read by path and cannot be modified; audit `conflict=versioned`, `version_path`; interop: `rclone sync` ×5 without extra files |
| M3-07 | `compat` profile and a test of the crypto profiles | ✅ | `server.crypto_policy`; test: every name is in `SupportedAlgorithms` and is not in `InsecureAlgorithms` or in the "never" list; a client with only compat algorithms logs in only with `compat` |
| M3-08 | Fuzzing (≥ 5 targets), `fuzz.yml`, `fuzz-smoke`, coverage thresholds | ✅ | 6 targets: `FuzzResolve`, `FuzzResolveInRoot`, `FuzzConflictName`, `FuzzParseConfig` (with an Encode → Load check), `FuzzAuthorizedKeys`, `FuzzRequestServer` (a stream of SFTP packets into the real handlers); `fuzz-smoke` 60 s per target in PRs, `fuzz.yml` nightly for 10 min each, with an issue on failure. Found and fixed: a race in `pkg/sftp` (READ/WRITE with a guessed handle before the reply to OPEN could crash the process) closed by `sftpd.Gate`; copy names longer than 255 bytes; `rename_template` is restricted. Unit + interop coverage is merged via `covdata`, thresholds: vfs, config, sftpd ≥ 85%, auth ≥ 90% (`test/coverage.sh`) |
| M3-09 | ssh-audit in CI, Scorecard, actions pinned by SHA | ✅ | `test/ssh-audit.sh` (ssh-audit 3.9.0): `modern` has no fails, `compat` fails only on NIST curves; `scorecard.yml` weekly; all actions are pinned by commit SHA |
| M3-10 | Refusal to run as uid 0 without `--allow-root`; manual WinSCP testing; investigation of `limits@openssh.com` | ✅ | `--allow-root` (M3a); ADR 0004 (`limits@openssh.com`: no changes for now, propose it upstream, revisit with benchmarks); WinSCP checklist in `docs/interop.md`. By owner decision, the manual WinSCP run is deferred until it is automated in CI (M3b-02) |
| M3-11 | Threat model and hardening documents, M3 DoD, release `v0.3.0` | ✅ | `docs/security/threat-model.md`, `docs/security/hardening.md`; M3 DoD met, except the manual WinSCP check (deferred until M3b-02); release `v0.3.0` (owner) verified: archives, `checksums.txt`, `gosftpd version`, Go proxy, binary behavior |
| M3-12 | `testutil.AsyncConn` and synctest timeout tests (moved from M1-08) | ✅ | `internal/testutil.AsyncConn`; idle and keepalive are tested in `testing/synctest` on `net.Pipe` |

## M3b: Windows (can come after v1.0)

| ID | Block | Status |
|---|---|---|
| M3b-01 | Isolation test suite on `windows-latest` | ⬜ |
| M3b-02 | WinSCP interop in CI | ⬜ |
| M3b-03 | `windows/amd64` in releases (experimental) | ⬜ |

## M4: Multi-user and Operations (v0.4.0)

| ID | Block | Status | Details |
|---|---|---|---|
| M4-01 | Reload on SIGHUP, reopening mounts | ✅ | ADR 0005 after three design reviews; configuration snapshots, mount table generations, login re-check after the handshake, `reload.disconnect_removed_users`, `server.reload` event |
| M4-02 | sd_notify, drop-in for systemd < 253 | ✅ | `READY`/`RELOADING`+`MONOTONIC_USEC`/`STOPPING`; the `legacy-notify.conf` drop-in is installed with the packages (M4-08) |
| M4-03 | `user add --write`, `disable`, `remove` | ✅ | `users.d/NAME.toml` with a config check and instructions for the partner; `disable`/`enable`/`remove` without losing comments; `reason=expired` (and others) in `auth.failure`; a key of such an account is rejected as soon as it is offered (without an "oracle"), `VerifiedPublicKeyCallback` re-checks after the signature |
| M4-04 | SSH user certificates | 🔄 | ADR 0007 after three design reviews; `auth.trusted_user_ca_keys[_file]` with `users.NAME.principals`, `cert-authority` lines with `principals=`, `auth.revoked_keys[_file]` (fails closed; a certificate revokes its key); checks in gosftpd's own order with reasons `key_revoked`, `cert_principal`, `cert_expired`, `cert_not_yet_valid`, `cert_invalid`; `cert_key_id`, `cert_serial`, `cert_ca_fp` in the audit log; interop with OpenSSH certificates; awaiting a PR |
| M4-05 | Host key rotation, host certificates | ⬜ |
| M4-06 | Admin listener (`/metrics`, `/healthz`, `/readyz`), `healthcheck` | ⬜ |
| M4-07 | Hooks (exec, webhook with HMAC) | ⬜ |
| M4-08 | PROXY protocol v2, systemd unit, sysusers, tmpfiles, Landlock | ⬜ |
| M4-09 | Documents: operations, metrics, recipes; M4 DoD, release `v0.4.0` | ⬜ |

## M5: Distribution (v0.5.0)

| ID | Block | Status |
|---|---|---|
| M5-01 | Full `.goreleaser.yaml`, reproducible builds | ⬜ |
| M5-02 | Docker image (distroless, GHCR) | ⬜ |
| M5-03 | deb/rpm/apk/archlinux packages | ⬜ |
| M5-04 | cosign signatures, SBOM, attestations, `THIRD_PARTY_LICENSES` | ⬜ |
| M5-05 | Man pages and completions | ⬜ |
| M5-06 | `--ephemeral`, migration from atmoz | ⬜ |
| M5-07 | `docs/install.md`, M5 DoD, release `v0.5.0` | ⬜ |

## M6: v1.0.0

| ID | Block | Status |
|---|---|---|
| M6-01 | `docs/compatibility.md`: contract freeze | ⬜ |
| M6-02 | Benchmarks against OpenSSH | ⬜ |
| M6-03 | Coverage ≥ 80% / ≥ 90% for security packages | ⬜ |
| M6-04 | Fuzz ≥ 2 weeks, interop ≥ 1 month, manual client checklists | ⬜ |
| M6-05 | OpenSSF Best Practices, Scorecard ≥ 7, Immutable Releases | ⬜ |
| M6-06 | Self-check against §7.2, external review | ⬜ |
| M6-07 | RC ≥ 4 weeks, `v1.0.0` | ⬜ |
| M6-08 | Architecture and development documents, launch (HN, r/selfhosted, awesome-selfhosted) | ⬜ |

## Log

| Date | What was done | Where |
|---|---|---|
| 2026-10-07 | Roadmap | [o-kolomoiets/Go-SFTP-Server#1](https://github.com/o-kolomoiets/Go-SFTP-Server/pull/1) |
| 2026-10-07 | M0: cleanup, skeleton, CI, hygiene, documents, ADR; CI green (12/12) | [o-kolomoiets/Go-SFTP-Server#2](https://github.com/o-kolomoiets/Go-SFTP-Server/pull/2) |
| 2026-10-07 | M1: `gosftpd serve` — SSH/SFTP, keys, `os.Root` isolation, conflict policy, audit, interop with OpenSSH | [o-kolomoiets/Go-SFTP-Server#3](https://github.com/o-kolomoiets/Go-SFTP-Server/pull/3) |
| 2026-10-08 | Ruleset on `main` and release `v0.1.0-alpha` (owner); M1 closed, M2 broken down into tasks | this file |
| 2026-10-08 | M2a: TOML config, users and permissions, `{user}` home, commands `init`, `config`, `user`, `hostkey generate`; review (22 findings, fixed) | [o-kolomoiets/Go-SFTP-Server#4](https://github.com/o-kolomoiets/Go-SFTP-Server/pull/4) |
| 2026-10-08 | M2b: append-only resume, `stat_redirect`, `statvfs`, virtual owners, audit category filter; review (9 findings, fixed) | [o-kolomoiets/Go-SFTP-Server#5](https://github.com/o-kolomoiets/Go-SFTP-Server/pull/5) |
| 2026-10-08 | M2c: interop with OpenSSH 10.6, paramiko, rclone, lftp; documentation; GoReleaser; review (7 findings, fixed) | [o-kolomoiets/Go-SFTP-Server#6](https://github.com/o-kolomoiets/Go-SFTP-Server/pull/6) |
| 2026-10-09 | Release `v0.2.0` (owner), verified; M2 closed | [v0.2.0](https://github.com/o-kolomoiets/Go-SFTP-Server/releases/tag/v0.2.0) |
| 2026-10-09 | M3a: connection limits, bans, timeouts, password login, `crypto_policy`, `--allow-root`; review and two verification passes (all findings fixed) | [o-kolomoiets/Go-SFTP-Server#8](https://github.com/o-kolomoiets/Go-SFTP-Server/pull/8) |
| 2026-10-09 | M3b: `atomic_uploads`, `on_conflict = "version"`, `max_file_size`, `min_free_space`; review (8 findings, fixed) | [o-kolomoiets/Go-SFTP-Server#9](https://github.com/o-kolomoiets/Go-SFTP-Server/pull/9) |
| 2026-10-09 | M3c: 6 fuzz targets and `fuzz-smoke`/`fuzz.yml`, race in `pkg/sftp` closed by `sftpd.Gate`, coverage thresholds, ssh-audit, Scorecard, actions pinned by SHA, threat model, hardening, ADR 0004; review (5 findings, fixed) | [o-kolomoiets/Go-SFTP-Server#10](https://github.com/o-kolomoiets/Go-SFTP-Server/pull/10) |
| 2026-10-09 | CHANGELOG for `v0.3.0` | [o-kolomoiets/Go-SFTP-Server#11](https://github.com/o-kolomoiets/Go-SFTP-Server/pull/11) |
| 2026-10-09 | Panic in `config validate`/`serve` on a config whose first line is cut off inside an escape sequence (found by `FuzzParseConfig` in CI) | [o-kolomoiets/Go-SFTP-Server#12](https://github.com/o-kolomoiets/Go-SFTP-Server/pull/12) |
| 2026-10-09 | Release `v0.3.0` (owner), verified; M3 closed. Loose ends for M4: in the message of that error, TOML prints "line 0" and a control character; in zero-config mode, the error about keys is shown before the refusal to run as root | [v0.3.0](https://github.com/o-kolomoiets/Go-SFTP-Server/releases/tag/v0.3.0) |
| 2026-10-10 | M4a: reload on SIGHUP (configuration snapshots, mount generations, login re-check), `sd_notify`, trusted files are not allowed inside mounts; three design reviews and four implementation reviews (all findings fixed) | [o-kolomoiets/Go-SFTP-Server#13](https://github.com/o-kolomoiets/Go-SFTP-Server/pull/13) |
| 2026-10-10 | M4-03: `user add --write`, `user disable`/`enable`/`remove`, refusal reasons in `auth.failure`, key re-check after the signature; review from three angles (all findings fixed) | [o-kolomoiets/Go-SFTP-Server#14](https://github.com/o-kolomoiets/Go-SFTP-Server/pull/14) |
| 2026-10-10 | The whole project in English (ADR 0006): ROADMAP.md and TASKS.md translated line by line and reviewed against the original | [o-kolomoiets/Go-SFTP-Server#15](https://github.com/o-kolomoiets/Go-SFTP-Server/pull/15) |
