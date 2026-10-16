# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Incompatible changes are prefixed with **BREAKING:**.

## [Unreleased]

## [0.4.0] - 2026-10-16

Multi-user operation: reload on SIGHUP, users in `users.d`, SSH
certificates, host key rotation, Prometheus metrics, hooks, PROXY protocol,
a systemd unit and Landlock on Linux. It also fixes a crash that an
authenticated client could cause (see Fixed). Read
[docs/operations.md](docs/operations.md#upgrades) before upgrading; five
changes need attention: headers from load balancers not in
`server.trusted_proxies` are refused; `serve` refuses trusted files inside
mounts and two host keys of one type; on Linux Landlock is on by default,
so some changes need a restart instead of a reload; and `cert-authority`
and `command="internal-sftp"` lines in `authorized_keys`, which v0.3
skipped with a warning, now take effect.

When upgrading a server behind a load balancer that sends PROXY protocol
headers, add the load balancer to `server.trusted_proxies` together with
the new binary (v0.3 refuses the key), or turn PROXY protocol off on the
load balancer before the upgrade: headers from any other address are now
refused (see Changed).

### Upgrading

- A systemd unit with its own `SystemCallFilter=` must allow the three
  system calls of Landlock: `landlock_create_ruleset`, `landlock_add_rule`
  and `landlock_restrict_self` (`@system-service` has none of them, and
  `@sandbox` exists only from systemd 254). Without them gosftpd runs
  without Landlock and logs `landlock: not available` with the reason
  "blocked by a seccomp filter" (with `SystemCallErrorNumber=`) or "killed
  by a seccomp filter" (a filter that kills, such as the one of the
  interim unit of the v0.3 hardening guide); `server.start` records
  `landlock` = `blocked` in both cases. The shipped unit allows them; to
  move to it from the interim unit, see
  [docs/install.md](docs/install.md#upgrade-from-the-quickstart-or-the-interim-unit).
- Check the `authorized_keys` files for `cert-authority` lines and lines
  with `command="internal-sftp"` (or a path to `sftp-server`). v0.3
  skipped them with a warning; v0.4 uses them, so a `cert-authority` line
  lets in the certificates its CA signs for the user (see Changed). Remove
  the lines that should not grant logins before upgrading.

### Added

- Reload on SIGHUP (`systemctl reload`): the audit log file is reopened
  first (for logrotate), then the configuration file is read and checked
  again and applied to new logins: users, keys, passwords, mounts,
  permissions, limits, bans settings and the log level. Open connections
  keep the configuration they logged in under; with the new
  `reload.disconnect_removed_users` they are closed when the new
  configuration would refuse their login. An invalid file keeps the running
  configuration. A key file that is missing or unsafe on reload revokes its
  keys instead of failing the reload, and a mount that is unavailable is
  left out until the next reload. A remounted mount directory is opened
  anew for new logins, with `mount reopened` in the log (under Landlock:
  after a restart, see Changed). See
  [docs/configuration.md](docs/configuration.md#reload)
  and [ADR 0005](docs/adr/0005-reload.md).
- Audit event `server.reload`; `conn.close` result `revoked`.
- `sd_notify`: `READY=1`, `RELOADING=1` with `MONOTONIC_USEC`, `STOPPING=1`
  (`Type=notify-reload`).
- `user add --write` writes `users.d/NAME.toml` after checking the
  configuration with the new user, and prints the connection details for
  the user (host, port, host key fingerprint, `sftp` command). `user
  disable`, `enable` and `remove` change a user's file without touching the
  rest of it; the main configuration file is never rewritten. `gosftpd init`
  includes `users.d/*.toml`.
- `auth.failure` has a `reason` when the login was refused although the key
  offered is one of the user's or the password is right: `disabled`,
  `expired`, `address`, `key_expired` or `removed`. The client is told
  nothing more, and the key of such an account is refused already when
  offered, as before. A key is checked again once the client has proved
  that it holds it (`VerifiedPublicKeyCallback`), against the configuration
  current then.
- `user add --write` prints the warnings about the new user and refuses one
  that could not log in (for example a password while `auth.methods` has
  only `publickey`) unless `--force`.
- OpenSSH user certificates ([ADR 0007](docs/adr/0007-user-certificates.md)):
  CAs trusted for every user (`auth.trusted_user_ca_keys`,
  `trusted_user_ca_keys_file`), with `users.NAME.principals` to map
  certificate principals to users, and `cert-authority` lines with
  `principals=` in `authorized_keys`. Certificates without principals, with
  SHA-1 CA signatures or with critical options other than `source-address`
  and an SFTP-only `force-command` are refused. See
  [docs/configuration.md](docs/configuration.md#certificates).
- Revoked keys and certificates (`auth.revoked_keys`, `revoked_keys_file`):
  a certificate revokes its key, as in sshd. The list fails closed: a line
  that is not a key, or a KRL, is an error at start and fails a reload.
- `auth.success` names a certificate login (`cert_key_id`, `cert_serial` as
  a decimal string, `cert_ca_fp`; `key_fp` is the certified key's);
  `auth.failure` gets `key_fp` and these fields with a reason, and the
  reasons `key_revoked`, `cert_principal`, `cert_expired`,
  `cert_not_yet_valid` and `cert_invalid`.
- `user add` takes `--principal`; with `--write` and trusted CAs a user
  needs no key, and the connection details show the `ssh-keygen` command to
  sign its certificate. `user list` shows the principals.
- `command="internal-sftp"` (or a path to `sftp-server`, without arguments)
  is accepted in `authorized_keys`, since gosftpd serves only SFTP.
- Host key rotation without breaking clients
  ([ADR 0008](docs/adr/0008-host-key-rotation.md)): after login, gosftpd
  announces its host keys to OpenSSH clients, with a next key `KEY.next`
  and a previous key `KEY.old` (`hostkeys-00@openssh.com`), and proves that
  it holds them (`hostkeys-prove-00@openssh.com`), so that OpenSSH 8.5 and
  later add the next key to `known_hosts` before it is used and drop retired
  keys. `gosftpd hostkey rotate` creates the next key; `--finish`,
  `--rollback`, `--retire` and `--abort` take the further steps. New setting
  `server.announce_host_keys` (on by default); new audit event
  `conn.hostkeys_proved`. See
  [docs/configuration.md](docs/configuration.md#host-keys).
- Host certificates: with `server.host_certificates = true`, `KEY-cert.pub`
  is served with each host key while it is valid, after the checks OpenSSH
  applies; warnings before expiry. Go clients that pin the plain host key
  (rclone) then need `host_key_algorithms`, see
  [Host certificates](docs/configuration.md#host-certificates).
- `hostkey show --config` shows every configured host key with its next and
  previous keys and certificates; the start banner and `user add --write`
  show the next key. During a rotation, or with a certificate, `hostkey
  show` prints more lines after those of the current key: a script that
  takes its last line should take the third.
- Admin listener ([ADR 0009](docs/adr/0009-admin-listener-metrics.md)):
  `[metrics] listen` serves `/metrics` (Prometheus text format, written by
  gosftpd itself, without a new dependency), `/healthz` and `/readyz`
  (`starting`, `stopping`, `audit_unavailable`). Metrics count connections
  by result (including health probes and scanners, which the audit log
  leaves out), refusals, logins, authentication attempts, SFTP operations,
  bytes, transfer times, conflicts, bans, reloads and audit write errors,
  with labels from fixed sets only. `metrics.pprof` serves `/debug/pprof` in
  binaries built with `-tags pprof`. See [docs/metrics.md](docs/metrics.md).
- `gosftpd healthcheck` for container health checks: without `--url` it
  waits for the SSH banner of `server.listen` and leaves no trace in the
  audit log; with `--url` it checks the admin listener. It exits with 0 or
  1 only.
- `server.start` has `metrics_listen` with an admin listener.
- Hooks ([ADR 0010](docs/adr/0010-hooks.md), [docs/hooks.md](docs/hooks.md)):
  `[[hooks]]` run a program (`exec`, argv without a shell, `GOSFTPD_*`
  variables, the event on stdin) or call a webhook (the audit line, signed
  with HMAC-SHA256 over the delivery ID, timestamp and body, with retries)
  when a file event succeeds, filtered by `on`, `mounts`, `glob` and
  `exclude`, optionally after a `delay`. Asynchronous, with a bounded queue
  per hook; a reload updates hooks in place, for open connections too. An
  exec hook runs only if its file is still the one of the event, and its
  program still belongs to root or gosftpd's user; its process group is
  killed when it ends or times out. New metrics
  `gosftpd_hook_deliveries_total`, `gosftpd_hook_retries_total`,
  `gosftpd_hook_queue_length` and `gosftpd_hooks_not_updated`.
- Audit: every `fs.*` event on a path in a mount has `mount`; `fs.rename`
  has `"uploaded":true` for the first rename by its uploader, within an
  hour, of a file whose upload closed ok: the rename that completes a
  temp-file upload (WinSCP's `.filepart`, rclone's `.partial`), or a plain
  upload renamed later. `fs.upload` hooks fire for it.
- PROXY protocol v1 and v2 behind a load balancer
  ([ADR 0011](docs/adr/0011-proxy-systemd-landlock.md)): a connection from
  an address in the new `server.trusted_proxies` must begin with a PROXY
  protocol header, which names the client. Bans, `max_connections_per_ip`,
  `allow_from`, `from=`, certificate `source-address` and the audit log's
  `remote_addr` and `local_addr` then see the client, and the new context
  field `proxy_addr` names the load balancer. `LOCAL` and `UNKNOWN` headers
  (health checks, clients of a Unix socket front end) are the load
  balancer's own connections. A trusted peer that sends no valid header is
  refused (`conn.reject` with `reason=proxy_header`,
  `gosftpd_connections_refused_total{reason="proxy_header"}`); one that sends
  nothing at all, as a TCP health check, is not audited. The setting is
  reloadable, and `server.start` and `server.reload` record it.
  `gosftpd healthcheck` sends a `LOCAL` header when its own address is
  trusted. Tested with HAProxy and nginx. See
  [docs/configuration.md](docs/configuration.md#behind-a-load-balancer).
- A systemd unit, `packaging/systemd/gosftpd.service`, with sysusers and
  tmpfiles files and a drop-in for systemd before 253, in the Linux release
  archives ([ADR 0011](docs/adr/0011-proxy-systemd-landlock.md)):
  `Type=notify-reload`, a sandbox that `systemd-analyze security` scores
  1.2 on systemd 255 (CI checks it), and no restart after a configuration
  error (exit status 2). [docs/install.md](docs/install.md) installs it in
  the layout of the coming packages and covers another data path, mounts
  under `/home`, port 22, older systemd and the upgrade from the interim
  unit.
- After a reload, the status line of `systemctl status` names the settings
  that need a restart (`configuration reloaded; restart needed for:
  server.listen`, at most five), besides `configuration reloaded` and
  `configuration reload failed, see the log`.
- At stop, gosftpd asks systemd for `shutdown_timeout` + 10 s
  (`EXTEND_TIMEOUT_USEC`), so that `TimeoutStopSec` does not cut off a
  drain that a reload made longer.
- A warning at start, at reload and in `config validate --check-fs` when a
  writable mount is on a read-only file system (under systemd: outside
  `ReadWritePaths=`). Uploads there failed with a bare "Failure" and
  nothing in the log.
- Landlock on Linux ([ADR 0011](docs/adr/0011-proxy-systemd-landlock.md),
  [docs/security.md](docs/security.md#landlock)): once its listeners are
  bound, `serve` can open only its mounts, its configuration and key files,
  its audit log, `/proc/self` and the files name resolution reads.
  `server.landlock` (restart-only) is `"auto"`, the default: applied where
  it can be, and the log says why not elsewhere (no Landlock in the kernel,
  a seccomp filter that blocks it, ABI 1, exec hooks, a mount at `/`);
  `"required"`, which makes each of these an error at start (exit status
  2); or `"off"`. Any other failure to apply it fails the start (exit
  status 1). The log says `landlock: ABI vN applied`, and `server.start`
  records `landlock` (`v2` to `v5`, `off`, `unavailable`, `blocked`,
  `not_applied`). A directory gets a rule only when every entry in it is a
  file the configuration names; elsewhere the files get rules of their
  own, with a warning at start, which `config validate --check-fs` prints
  too. `config validate` refuses `required` with exec hooks. New
  dependency `github.com/landlock-lsm/go-landlock` v0.10.1 (MIT).
- An operations guide, [docs/operations.md](docs/operations.md): reload
  and its result, stop and restart with interrupted uploads, log rotation,
  backups and restore, upgrades, and a disk mounted on a mount directory.
  Recipes for retention ([docs/recipes/retention.md](docs/recipes/retention.md):
  systemd-tmpfiles, a timer, hooks) and volume encryption
  ([docs/recipes/volume-encryption.md](docs/recipes/volume-encryption.md):
  LUKS2, fscrypt, ZFS, cloud disks). More alert rules in
  [docs/metrics.md](docs/metrics.md): target down, failed reloads,
  connection limits, PROXY protocol on one side only, bursts of bans. CI
  checks the units and tmpfiles files of the documentation offline, tests
  the alert rules with `promtool`, and fails when the documentation names
  a metric that does not exist.

### Changed

- A failing audit log is retried every 5 seconds also while no client
  connects, in either `on_error` mode, so the server recovers on its own.
- Host keys are read again on reload (they were restart-only): new
  connections use the new keys, open ones keep theirs. A reload never
  generates a key, and a host key that cannot be used keeps the running
  keys instead of failing the reload. A host key, next or previous key or
  host certificate inside a mount fails the reload, as every file gosftpd
  trusts does (also the running keys, when they stay). Configuration
  management that edits `server.host_keys` changes the server's identity at
  the next reload.
- **BREAKING:** two host keys of one type are refused (only one of them was
  used), and `host_key_auto_generate` no longer creates a key next to an
  existing `KEY.next` or `KEY.old`.
- **BREAKING:** `serve` refuses a configuration where the configuration
  file, an included file, an `authorized_keys` file, a host key or the
  audit log lies inside a mount clients can write, or a host key or
  configuration file inside any mount: a client could add itself a key, or
  read the host key. Symlinks and, on Linux, bind mounts are followed. `serve
  --dir ~` is refused for that reason; serve a subdirectory.
- `serve` checks for root before anything else, so running as root without
  `--allow-root` is reported first.
- An uploader without the `setstat` permission may set the times of its own
  uploads only while it still has the `write` permission.
- Every login is checked once more after the SSH handshake against the
  configuration current then: a key removed by a reload while a client was
  logging in is refused.
- `cert-authority` lines in `authorized_keys` files, and lines with
  `command="internal-sftp"` (or a path to `sftp-server`), which were skipped
  with a warning, now take effect: check existing files before upgrading. In
  zero-config mode without `--user`, a `cert-authority` line needs
  `principals=`.
- **BREAKING:** a connection that begins with a PROXY protocol header (v1 or
  v2) from a peer that is not in `server.trusted_proxies` is closed after
  the server's banner, also when no proxy is trusted: `conn.reject` with
  `reason=untrusted_proxy`, `gosftpd_connections_total{result="untrusted_proxy"}`
  and a warning in the log. Before, a v1 header, and a v2 header whose last
  byte is a line feed, were skipped, and every client was logged, banned and
  limited with the load balancer's address; other v2 headers failed the
  handshake.
  If a load balancer sends PROXY protocol to gosftpd, list it in
  `server.trusted_proxies` (reload gosftpd first, then the load balancer),
  or turn PROXY protocol off on the load balancer.
- `conn.reject` means a connection refused before the SSH handshake: for
  `untrusted_proxy` that is after the server's banner, and from a trusted
  load balancer after its header.
- On Linux, with Landlock applied (the default where the kernel offers
  it), a reload cannot reach beyond the rules applied at start
  ([docs/configuration.md](docs/configuration.md#landlock)): a new or moved
  mount, or a mount directory recreated or remounted since the start, is
  unavailable; `read_only = false`, `create = true` and a new
  `audit.output` that the rules do not allow keep their running values; an
  exec hook added by the reload is left out; a key, CA or secret file in a
  shared directory replaced by rename is left out as an unreadable one is.
  Each is named in `restart_required`; such an include file, revocation
  list or the configuration file itself (`sed -i`, most editors) fails the
  reload instead, until a restart. The log adds "outside the Landlock
  ruleset applied at start; restart gosftpd". An audit log that shares its
  directory with other files cannot be rotated by rename without a
  restart: give it a directory of its own or use `copytruncate`. An
  `audit.output` on `/dev/stderr` is no longer reopened at reload. Keep the
  configuration, `users.d` and key files in directories of their own, as
  the packaged layout does, or set `server.landlock = "off"`.
- `gosftpd init` also creates an empty `users.d/` next to the file: under
  Landlock an include directory that is missing at start needs a restart
  for its first file.
- Exec hooks no longer inherit ambient capabilities: once its listeners
  are bound, before any hook can run, `serve` clears the ambient set on
  every thread (with `AmbientCapabilities=CAP_NET_BIND_SERVICE` for port
  22 a hook inherited the capability).
- Dependencies: `golang.org/x/crypto` v0.58.0, `golang.org/x/sys` v0.49.0,
  `golang.org/x/term` v0.47.0 and `github.com/spf13/pflag` v1.0.10.
- `server-sig-algs` lists only the signature algorithms of key types that
  gosftpd accepts. Built with Go 1.27, as the release binaries are, x/crypto
  v0.58.0 supports ML-DSA (`ssh-mldsa-44`, `-65`, `-87`), which gosftpd
  would have announced and then refused, as it refuses ML-DSA keys in
  `authorized_keys`, as CAs and in certificates.

### Fixed

- An authenticated client could crash the server: `pkg/sftp` serves READ
  and WRITE requests with the handle of a directory in parallel, and the
  directory was listed concurrently. A directory is now listed for one
  request at a time. A READ or WRITE sent after the CLOSE of its handle
  was also served during the CLOSE: WRITEs sent after the CLOSE of an
  atomic upload could still reach the published file, and a published
  upload could be audited as `error`, without its hooks. Such a request
  now waits for the CLOSE's answer, and fails. Both were data races; the
  nightly fuzzing found the second.
- After an interrupted upload to a temporary name was resumed (OpenSSH
  `reput`), the client's rename was refused for a user with the `upload`
  preset; likewise after a retry in place under `on_conflict =
  "overwrite"` for a user with `write` and `overwrite` but not `rename`.
  The file was no longer counted as the user's own.
- An upload whose write failed in the file system (a full disk, an I/O
  error) was audited with `result` `ok`; it is now `error`, and an atomic
  upload with a failed write is not published. A truncation refused by the
  append-only guard now makes the upload `denied`, as a refused write
  does.
- `known_hosts` lines for IPv6 addresses (`serve` banner, `hostkey show`,
  `user add --write`) are written as `[addr]:port`, which OpenSSH matches.
- An `include` whose directory exists but cannot be read is an error
  instead of silently adding no users; names that start with a dot are
  skipped (editor and temporary files).
- TOML errors no longer print control characters or "line 0" for an escape
  cut off at the end of the file.
- A data race between an upload being opened and another session checking
  whether a file is its own upload.
- A client path of 4096 bytes without a leading `/` was accepted, although
  the path the server returned for it (REALPATH) was one byte too long and
  refused; the limit now applies to the cleaned path (found by fuzzing).

### Security

- Developer tools: `tools/go.mod` requires `golang.org/x/text` v0.41.0
  instead of the v0.17.0 that gotestsum asks for (GO-2026-5970,
  GO-2026-6629). This does not change the gosftpd binary. CI and `make
  vuln` scan the tools module with govulncheck too.
- `osv-scanner.toml` ignores GO-2026-5932 (`golang.org/x/crypto/openpgp`,
  which has no fixed version) for osv-scanner and the OpenSSF Scorecard:
  gosftpd never imports openpgp. See
  [docs/DEPENDENCIES.md](docs/DEPENDENCIES.md#go-2026-5932-and-osv-scannertoml).

## [0.3.0] - 2026-10-09

Hardening for servers exposed to the internet. Read
[docs/security/hardening.md](docs/security/hardening.md) before upgrading a
public server; two changes need attention: `serve` refuses to run as root
without `--allow-root`, and uploads stop below 1 GiB of free space unless
`min_free_space` says otherwise.

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
- A client that sent requests with a guessed handle while an OPEN was in
  progress raced with the OPEN inside `pkg/sftp`, which could crash the
  server; gosftpd now passes an OPEN on only after the earlier requests are
  answered, and requests with a handle only after the OPEN is (found by
  fuzzing).
- Copy names under `on_conflict = "rename"` could exceed 255 bytes for
  names with a very long extension; a shortened name could equal the
  original.
- A configuration file whose first line ended inside an escape sequence
  (`a = "C:\`) made `serve` and `config validate` panic instead of
  reporting the error (found by fuzzing).

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

[Unreleased]: https://github.com/o-kolomoiets/go-sftp-server/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/o-kolomoiets/go-sftp-server/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/o-kolomoiets/go-sftp-server/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/o-kolomoiets/go-sftp-server/compare/v0.1.0-alpha...v0.2.0
[0.1.0-alpha]: https://github.com/o-kolomoiets/go-sftp-server/releases/tag/v0.1.0-alpha
