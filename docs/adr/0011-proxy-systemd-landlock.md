# ADR 0011: PROXY protocol, the systemd unit and Landlock

- **Status:** draft 1, 2026-10-12; amends ADR 0005 (restart-only list),
  ADR 0009 (connection metrics), the audit schema (additive) and ROADMAP
  §4.5, §6.1, §7.4 and §9.4
- **Context:** ROADMAP M4 (M4-08) asks for three things that together make
  gosftpd fit for production behind a load balancer and under systemd:
  PROXY protocol v2 from `server.trusted_proxies`
  (`github.com/pires/go-proxyproto` v0.15.0), the systemd unit with its
  sysusers and tmpfiles files, and Landlock on Linux
  (`github.com/landlock-lsm/go-landlock` v0.10.1). The persona U2 runs
  gosftpd behind HAProxy, nginx or a cloud load balancer, where today every
  client has the proxy's address: one client's failed logins ban everybody,
  and `max_connections_per_ip` counts all clients as one. The M4 Definition
  of Done asks for `systemd-analyze security` ≤ 2.0 and a log line
  `landlock: ABI vN applied` under the unit. Three research tracks
  (PROXY protocol, Landlock, systemd) checked the libraries' source, ran
  HAProxy 2.8 and nginx 1.24, systemd 255 and EL9's 252 in containers and
  Landlock ABI 7 in a VM; a second researcher re-checked each track.

## Decision

### PROXY protocol

```toml
[server]
listen = [":2022"]
trusted_proxies = ["10.0.0.5", "10.0.1.0/28"]   # load balancers; reloadable
```

- **Trust is decided by the TCP peer.** A connection whose peer address is
  in `trusted_proxies` must begin with a PROXY protocol header; one from any
  other peer must not. This is HAProxy's own model
  (`expect-proxy layer4 if { src ... }`) and the specification's ("only
  trusted proxies are allowed to use this protocol"); gosftpd never guesses
  whether a header is present. Entries are addresses or prefixes, parsed as
  `allow_from` is (4in6 unmapped); `/0` is an error. The peer address is
  unmapped before matching: on a dual-stack listener IPv4 peers arrive as
  `::ffff:a.b.c.d`.
- **Versions.** Both v1 (text) and v2 (binary) are accepted, with no
  setting: nginx's stream module sends only v1, HAProxy sends either, and
  the specification recommends that v2 receivers accept v1. This widens
  the ROADMAP's "v2". The v1 parser of v0.15.0 is strict and bounded (107
  bytes, one read, exact tokens). gosftpd sets the library's
  `V1AcceptIPv4InTCP6` at init, so that nginx's `TCP6` lines with IPv4
  addresses are read.
- **Commands and families.** `PROXY` with TCP over IPv4 or IPv6 gives the
  client's address and the address it connected to. `LOCAL` (v2) and
  `UNKNOWN` (v1), which proxies send for their own health checks and for
  clients on a Unix socket, are accepted: the connection then is the
  proxy's own, with its TCP addresses. Any other family (UDP, Unix,
  unspecified) is refused: UDP addresses would pass bans and per-IP limits
  but fail `from=` and certificate `source-address`, and a Unix "address"
  is free text. TLVs are ignored (CRC32C checking is optional for
  receivers).
- **The library is used as a parser only.** gosftpd calls
  `proxyproto.Read` on a `bufio.Reader` over the raw connection and wraps
  the connection itself (`proxiedConn`: buffered bytes first, then the
  socket; `RemoteAddr` and `LocalAddr` from the header). It does not use
  `proxyproto.Listener`, `Conn` or `ReadHeaderTimeout`: they read the
  header lazily on the first `RemoteAddr`, `LocalAddr`, `Read` or `Write`,
  so gosftpd's accept loop, which calls `RemoteAddr`, would wait for one
  slow proxy before accepting anyone else (measured: 1.95 s with a 2 s
  timeout), the banner write would wait for the header, and a deadline set
  on the raw connection is cleared by the header read. The header is read
  in the connection's goroutine, under a deadline set on the raw
  connection and never reset in between. Versions before v0.15.0 return a
  nil address for undefined v2 family bytes (a remotely triggerable panic);
  go.mod requires v0.15.0 or later.
- **Header deadline:** the header must be complete within
  min(`handshake_timeout`, 10 s) of the accept; the handshake keeps its
  own deadline, counted from the accept as today. The specification asks
  for at least 3 s: `config validate` warns when `trusted_proxies` is set
  and `handshake_timeout` is below 3 s.
- **Headers from untrusted peers are refused, also when
  `trusted_proxies` is empty.** Today x/crypto silently skips any line that
  does not start with `SSH-`: a v1 header, and a v2 header whose bytes end
  in a line feed, pass unnoticed, and the client is logged with the
  proxy's address. gosftpd checks the first bytes a client sends, after its
  banner (a client that waits for the banner never waits): the moment they
  differ from both `PROXY` and the 12-byte v2 signature the check is done,
  so a short client version line is not held back; a match closes the
  connection. The same check runs after a trusted header, which catches a
  second header (a client that sends its own, or two proxies in a row). No
  SSH client starts with these bytes (RFC 4253 allows lines before the
  version only from the server). This is a behaviour change for every
  deployment, not an opt-in: a proxy that sends headers to a gosftpd that
  was not told about it now gets its connections refused instead of
  silently mis-attributed (CHANGELOG, Changed).

### Admission

Admission runs in two phases, so that per-address rules see the client.

- **Phase 1, in the accept loop, without I/O** (as today): audit health,
  `max_connections`, `max_preauth_connections`. For an untrusted peer also
  the ban and `max_connections_per_ip` on the peer address. A trusted peer
  is never banned or per-IP limited for the clients it relays.
- **Phase 2, in the connection's goroutine, for trusted peers only,** once
  the header is read: the ban and `max_connections_per_ip` on the
  effective client (the header's source; for `LOCAL`/`UNKNOWN` the proxy's
  own address), then the SSH handshake. The limiter's per-address slot is
  taken in phase 2; `release` frees what was taken.
- `auth.ban.exempt` is matched against the effective client, except that
  a loopback address taken from a header (a process on the proxy's host)
  is never exempt. `config validate` warns when `trusted_proxies` overlaps
  `auth.ban.exempt` (the proxy's own `LOCAL` connections, and clients it
  relays from a Unix socket, are then never banned).
- **Accounting.** A connection from a trusted peer counts as admitted
  (`gosftpd_connections_active`, `gosftpd_connections_total`) only after
  phase 2. Before that it ends in one of:
  - nothing sent, then EOF or the deadline (a TCP health check):
    `connections_total{result="no_version"}`, not audited, as a scanner is
    today;
  - bytes that are not a valid header (a missing, malformed, partial or
    unsupported header): refused, `conn.reject` with `reason=proxy_header`,
    `gosftpd_connections_refused_total{reason="proxy_header"}`;
  - a ban or the per-IP limit on the client: refused with the existing
    reason, `conn.reject` with the client's `remote_addr`.
  A header from an untrusted peer is found after the connection was
  admitted: it ends with `connections_total{result="untrusted_proxy"}`
  and is audited as `conn.reject` with `reason=untrusted_proxy`, rate-
  limited as every `conn.reject` is; a warning in the operational log
  names the peer and `server.trusted_proxies`, at most once a minute.
  `conn.reject` is now documented as "refused before the SSH handshake";
  for `untrusted_proxy` the server's banner has been sent.

### Addresses in the audit log, logs, hooks and auth

- `remote_addr` is the client: the header's source for `PROXY`, else the
  TCP peer. `local_addr` is the address the client connected to: the
  header's destination, else the socket's.
- A new context field `proxy_addr`, the TCP peer, is on every event of a
  connection whose peer is trusted, phase-1 and phase-2 refusals included
  (with `LOCAL`, `remote_addr` equals `proxy_addr`). It is optional in the
  schema and reaches hook payloads with the other context fields. The
  operational log gets the same fields.
- Everything in `internal/auth` reads the client from
  `ssh.ConnMetadata.RemoteAddr`, which is the wrapped connection's: bans,
  `allow_from`, `from=` and certificate `source-address`, and the re-check
  at reload (`reload.disconnect_removed_users`) apply to the client with no
  change there.
- Metrics carry no addresses (ADR 0009):
  `gosftpd_connections_refused_total` gains `reason="proxy_header"`,
  `gosftpd_connections_total` gains `result="untrusted_proxy"`.
- `server.start` and `server.reload` record `trusted_proxies`.

### Reload and the health check

- `trusted_proxies` is reloadable. It lives in the configuration snapshot
  and is read at accept, so every connection keeps the classification it
  got. Turning PROXY on is never atomic between the proxy and gosftpd:
  reload gosftpd first, then the proxy; meanwhile header-less connections
  from the proxy are refused as `proxy_header`. docs/configuration.md says
  so.
- `gosftpd healthcheck` reads `server.trusted_proxies` from the
  configuration file (found as today), also when the address comes from
  `--address` or `$GOSFTPD_LISTEN`. When its own source address is
  trusted it sends a v2 `LOCAL` header after connecting (16 bytes) and then
  waits for the banner. Without a configuration file it sends none; a probe
  from a trusted address then gets no banner, and is unhealthy, which
  docs/metrics.md states. This is the promise of ADR 0009.

### The systemd unit, sysusers and tmpfiles

New files, shipped in the Linux release archives now and installed by the
M5 packages:

- `packaging/systemd/gosftpd.service`: the unit of ROADMAP §9.4 with these
  changes, all checked on systemd 255 and on EL9's 252:
  - `Documentation=` points to docs/install.md on GitHub until the man page
    exists (M5): `systemd-analyze verify` fails on a missing man page;
  - `StateDirectoryMode=0700` (host keys) and `LogsDirectoryMode=0750`;
  - `SystemCallFilter=~@privileged @resources`: Go raises `RLIMIT_NOFILE`
    with `prlimit64`, which is in `@default`, not with `setrlimit`, so the
    ROADMAP's reason for leaving out `@resources` does not hold; exec
    hooks then cannot use `nice`, `ionice`, `taskset`, `chown` or
    `chgrp` (docs/hooks.md);
  - `RestartSec=2s`, `StartLimitIntervalSec=60`, `StartLimitBurst=5` and
    `RestartPreventExitStatus=2`: exit 2 is a configuration or
    file-system-state error (also a mount that cannot be opened), which a
    restart does not fix; a late data disk is therefore not retried, which
    docs/install.md says;
  - the three `landlock_*` system calls stay allowed by name: `@sandbox`
    exists only from systemd 254, and 252 warns about the unknown group;
  - kept from §9.4: `Type=notify-reload`, `KillMode=mixed` (ADR 0010),
    `TimeoutStopSec=45`, `UMask=0027`, `LimitNOFILE=131072`,
    `ReadWritePaths=-/srv/sftp`, `RequiresMountsFor=/srv/sftp`.
  `systemd-analyze security` scores it 1.2 on 255 (the §9.4 unit: 1.4).
  `PrivateUsers=yes` (1.1) and `IPAddressDeny=` are not defaults: the first
  breaks binding port 22, the second webhooks; docs/install.md shows them
  as options.
- `packaging/systemd/legacy-notify.conf`: a drop-in with `Type=notify` and
  `ExecReload=/bin/kill -HUP $MAINPID` for systemd without
  `Type=notify-reload` (upstream before 253: Debian 12; Ubuntu 22.04;
  EL9 before 252-21). Whether it is needed is decided by testing the
  feature offline, not by the version number (EL9 backported it): a probe
  unit with `Type=notify-reload` run through
  `systemd-analyze verify --man=no` prints "Failed to parse service type"
  only where the type is unknown. docs/install.md gives the commands; the
  M5 postinstall uses the same probe and removes the drop-in when it is no
  longer needed.
- `packaging/gosftpd.sysusers`:
  `u gosftpd - "gosftpd SFTP server" /var/lib/gosftpd`.
- `packaging/gosftpd.tmpfiles`: `d /srv/sftp 0750 gosftpd gosftpd -` and
  `d /var/log/gosftpd 0750 gosftpd gosftpd -` (so that
  `config validate --check-fs` passes before the first start).
- `packaging/config.toml`: the minimal configuration of §9.4 (no users,
  `include = ["users.d/*.toml"]`, `listen = [":2022"]`, the host key in
  `/var/lib/gosftpd` with `host_key_auto_generate`, `[mounts.inbox]` under
  `/srv/sftp` with `create = true`, the audit log in `/var/log/gosftpd`).
  A test on every platform loads and validates it, and checks that it and
  the unit agree (the audit directory is `LogsDirectory=`, the mount lies
  under `ReadWritePaths=`, `TimeoutStopSec` ≥ the default
  `shutdown_timeout` + 10 s, the three Landlock system calls).

Two code changes come with the unit:

- At stop gosftpd sends `EXTEND_TIMEOUT_USEC=` with its
  `shutdown_timeout` + 10 s, after it has read the final value (a reload
  can raise `shutdown_timeout`, while `TimeoutStopSec` is fixed).
- With `AmbientCapabilities=CAP_NET_BIND_SERVICE` (port 22) the capability
  would pass to exec hooks; gosftpd clears the ambient set after binding
  its listeners (`prctl(PR_CAP_AMBIENT_CLEAR_ALL)`, allowed by the unit).

`systemctl reload` cannot report a failed reload under `notify-reload`;
docs/install.md shows `systemctl status` (the `Status:` line), the journal
and `gosftpd_config_reloads_total{result="error"}`. `config validate
--check-fs` must run as the service user (`runuser -u gosftpd --`): as
root it refuses the host key that belongs to gosftpd.

### Landlock

```toml
[server]
landlock = "auto"   # "auto" (default), "off", "required"; restart-only
```

- **Modes.** `auto` applies a ruleset when the kernel offers Landlock ABI 2
  or later and no exec hook is configured, and logs why not otherwise.
  `required` makes every such case an error at start (with exec hooks an
  error of `config validate`). `off` never applies. The setting is
  restart-only, also in zero-configuration mode, where `auto` applies.
- **When.** After the listeners and the admin listener are bound, the host
  keys loaded or generated, the mounts opened (directories created for
  `create = true`), the audit output opened and the TLS roots loaded
  (ADR 0010), and before any background goroutine starts and before
  `READY=1`. `time.Local` is initialised before (a later first use falls
  back to UTC silently: `expiry-time` in `authorized_keys` uses it).
- **ABI.** gosftpd queries the ABI itself (`landlock_create_ruleset` with
  the version flag, through `golang.org/x/sys/unix`), because go-landlock's
  `BestEffort` silently applies nothing in four cases (no Landlock,
  Landlock disabled at boot, a seccomp filter returning `EPERM`, a rule
  needing `refer` on ABI 1) and reports nothing. ABI 1 is not used: without
  `refer` every rename between directories (versions, client renames)
  fails with `EXDEV`. gosftpd asks go-landlock for ABI 5 with `BestEffort`
  (truncate from ABI 3, `ioctl_dev` from 5): later ABIs add only
  `resolve_unix` (9), which would cut off the `sd_notify` socket, and a
  change of the pinned ABI is a conscious one. The `landlocktsync` build
  tag is never used (it disables Landlock below Linux 7.0). Network rules
  and scopes are not used: listeners are bound before, Go's default
  listeners use MPTCP, which TCP rules do not cover, and an abstract
  `NOTIFY_SOCKET` would be cut off by scoping.
- **Self-check.** After applying, `open("/", O_RDONLY|O_DIRECTORY)` must
  fail with `EACCES` (`O_PATH` is not checked by Landlock); otherwise
  `auto` logs an error and `required` exits. A rule on `/` itself is
  refused at start.
- **Log lines:** `landlock: ABI v5 applied (kernel ABI v7)`;
  `landlock: not available: <reason>` (no Landlock; disabled at boot;
  blocked by a seccomp filter, naming the unit's `SystemCallFilter=`);
  `landlock: not applied: kernel ABI v1 cannot allow renames between
  directories`; `landlock: not applied: exec hooks configured`;
  `landlock: off`. `server.start` gets the field `landlock` (`v5`, `off`,
  `unavailable`, `not_applied`). Landlock's kernel audit records (ABI 7)
  stay at their defaults; docs/security.md says where denials show up.

**Rules** are computed from the configuration, on directories wherever
gosftpd re-reads a file (editors and `user add --write` replace files by
rename, and a rule on a file is lost with its inode). Every rule is
`IgnoreIfMissing`; rights are chosen by the type found (directory rights on
a file make the whole ruleset fail).

| What | Path | Rights |
|---|---|---|
| A writable mount | the mount directory; for a `{user}` home, its parent | read file, read dir, write file, truncate, make reg, make dir, remove file, remove dir, refer |
| A read-only mount | the same | read file, read dir (+ make dir for a home with `create = true`) |
| Configuration | the directory of the main file and of every include pattern | read file, read dir |
| Trusted files | the directories of `authorized_keys_file`s, CA files, the revocation list, host keys with their `.next`, `.old` and `-cert.pub`, hook `secret_file`s; also the target's directory of a symlink | read file |
| Audit log | the directory of `audit.output` (a new file is created after logrotate) | write file, make reg |
| Process metrics, mountinfo | `/proc/self`, held open with an `O_PATH` descriptor (a rule on it is lost when the kernel reclaims the dentry) | read file, read dir |
| Name resolution (webhooks) | `/etc/hosts`, `/etc/nsswitch.conf`, `/etc/resolv.conf` and its target's directory when that is under `/run` | read file |
| `GOCOVERDIR` (coverage builds only) | the directory | read file, write file, make reg, remove file |

- Paths under `/dev` and `/proc` other than `/proc/self` never get a rule
  (an `authorized_keys` link to `/dev/null`, a pipe, `audit.output` on
  stderr); such files stay usable through descriptors opened before.
- The ROADMAP's `/etc/ssl/certs`, `/etc/pki` and `/usr/share/zoneinfo`
  are not needed (roots and the local zone are loaded before), and
  `/var/lib/gosftpd` needs read only.
- A file placed directly in `/etc` (a configuration `/etc/gosftpd.toml`)
  opens `/etc` for reading; gosftpd warns at start, since `/etc/passwd`
  then is readable.
- Not handled by Landlock, and stated in docs/security.md and the threat
  model (correcting ROADMAP §7.4 item 9): hard links and bind mounts
  inside a mount reach what they point to; `stat`, `chmod`, `chown`,
  `utimes` and `readlink` are not checked, so the `os.Root` chmod race is
  not covered either; a mount rule does not follow a file system mounted
  on the mount directory later.

**Exec hooks.** While exec hooks are configured, Landlock is not applied
(ADR 0010): a hook needs the loader, libraries and whatever it touches. A
reload that adds an exec hook while Landlock is applied leaves the hook
out with a warning and lists `hooks` in `restart_required`.

**Reload.** gosftpd keeps the applied rules with each path's (device,
inode). After validating a new configuration it computes the rules the new
configuration would need and checks that each is covered: an applied rule
on the same path or an ancestor, with at least the rights, whose path
still has the recorded (device, inode).

- A new or moved mount that is not covered is left out as unavailable,
  with `restart_required` naming `mounts.NAME.path`. A mount whose
  directory was recreated or had a file system mounted on it since the
  start is unavailable too (it fails closed instead of writing to the
  hidden directory), with `restart_required`. So under Landlock the M4 DoD
  "mount a new disk, SIGHUP, new files land on the new disk" needs a
  restart; the DoD is amended to say so.
- A new `audit.output` directory that is not covered keeps the running
  audit output, with `restart_required` (`audit.output`).
- A configuration file, include or trusted file in a directory that is not
  covered fails as an unreadable file does today (keys not loaded, a
  revocation list failing the reload), with the hint "outside the Landlock
  ruleset applied at start; restart gosftpd" and `restart_required`.
- ADR 0005's restart-only list gains `server.landlock`;
  `restart_required` keeps its format.

### Dependencies

- `github.com/pires/go-proxyproto` v0.15.0 (Apache-2.0), parser only; its
  `x/net` requirement does not enter the build. Binary: +4 KiB.
- `github.com/landlock-lsm/go-landlock` v0.10.1 (MIT), with
  `kernel.org/pub/linux/libs/security/libcap/psx` (BSD-3-Clause, dual
  licensed). On Linux, psx applies the ruleset to every thread through
  `syscall.AllThreadsSyscall` in release builds (`CGO_ENABLED=0`) and
  through libpsx with cgo; from ABI 8 the kernel's TSYNC flag does it.
  Binary: about +45 KiB on amd64. Writing the ~100 lines over `x/sys`
  ourselves was considered; the ROADMAP pins go-landlock, which handles the
  thread synchronisation in all three cases, so it stays.
- docs/DEPENDENCIES.md lists both; govulncheck covers them.

### Not in this ADR

- A per-listener PROXY setting (a listener only for the load balancer, as
  nginx, HAProxy and Dovecot offer). With one global set an address in
  `trusted_proxies` must send a header on every connection; an address
  that also makes direct connections (a NAT gateway shared with the
  proxy, Docker's userland proxy) cannot be trusted. Later, if asked for.
- Logging TLVs (a load balancer's unique ID), checking CRC32C.
- Landlock for exec hooks (an allowlist for the loader and the hook's
  paths); Landlock network rules; scoping.
- nfpm packages, the man page and `docs/operations.md` (M5, M4-09).

### Code

- `internal/server`: `proxy.go` (the header read, `proxiedConn`, the
  first-bytes check), admission in two phases (`limits.go` splits the
  per-address slot from the total and pre-authentication slots),
  `proxy_addr` in the contexts. The accept loop stays free of I/O.
- `internal/config`: `server.trusted_proxies`, `server.landlock`, their
  checks and warnings.
- `internal/sandbox` (new, Linux build tags with a stub elsewhere): the
  ABI query, the rules from a `*config.Config` and the mount table (a pure
  function with an injected `stat`, testable on every platform), applying
  them through go-landlock, the self-check, the coverage check for reload.
  `internal/cli` calls it in `serve` through a package variable that tests
  replace, so that `go test` never sandboxes its own process.
- `internal/sdnotify`: `EXTEND_TIMEOUT_USEC`.
- `internal/cli`: `healthcheck` sends `LOCAL` when its source is trusted;
  the ambient capability set is cleared after binding.
- `packaging/`: the files above; `.goreleaser.yaml` adds them to the Linux
  archives.

**Tests.**

- PROXY, on every platform (a connection wrapper presents any peer
  address; the existing pipe and synctest harness gives fake time): v2 and
  v1 headers (TCP4, TCP6, mapped addresses) and the audit fields; `LOCAL`
  and `UNKNOWN`; refused families, lengths and split v1 headers; a header
  and the client's first bytes arriving together beyond the 256-byte
  buffer; a silent trusted peer (no audit, `no_version`, at the header
  deadline); a client that stops after a valid header is cut at the
  handshake deadline (the deadline is not cleared); a silent trusted peer
  does not delay another connection's banner; per-IP limits and bans on
  the client through one proxy, and never on the proxy; IPv6 /64 grouping
  and a mapped client keyed as IPv4; `allow_from`, `from=`, certificate
  `source-address` and the reload re-check on the client; a header from an
  untrusted peer (also with `trusted_proxies` empty, and after a trusted
  header) refused after the banner; a client that sends exactly its version
  line is not held back; reload of `trusted_proxies`. `FuzzProxyHeader`
  joins the fuzz targets (CI smoke and nightly). On Linux, real sockets
  with 127.0.0.2 as the trusted source. Interop (ubuntu-24.04): OpenSSH
  sftp, paramiko and rclone through HAProxy (`send-proxy`,
  `send-proxy-v2`, TLVs, a Unix-socket front end) and nginx
  (`proxy_protocol on`), the audit fields checked; HAProxy health checks
  stay out of the audit log; direct headers refused; `healthcheck` from a
  trusted loopback.
- Landlock: the rule computation and the reload coverage check run on
  every platform with an injected `stat` (writable, read-only and home
  mounts, includes, symlinked and `/dev` trusted files, host key siblings,
  audit on a file or stderr, `GOCOVERDIR`, deduplication); mode and
  reporting with an injected ABI query (no Landlock, disabled, seccomp,
  ABI 1, ABI 7). On Linux the test binary re-executes itself for each
  sandboxed test: under the real ruleset every vfs operation works (upload,
  atomic and resumed uploads, every conflict policy with versions,
  rename, remove, mkdir, setstat, statvfs, home creation) and
  `/etc/passwd` is unreadable through every path (a symlink planted before
  start, `/proc/self/root`, an `os.Root` opened before); the hard-link
  limitation is asserted as a documented gap; reload coverage (a new
  mount, a recreated mount, a replaced `users.d` file, a new audit
  directory). These run with `CGO_ENABLED=0` (the release path) and with
  cgo and `-race`, on ubuntu-24.04, ubuntu-24.04-arm and ubuntu-26.04
  (kernel 7.0, the TSYNC path). CI fails instead of skipping when these
  kernels report no Landlock. The interop binary is built with
  `CGO_ENABLED=0`, and every server's log is checked for
  `landlock: ABI v5 applied` (the hooks server:
  `not applied: exec hooks configured`).
- systemd: the lint job runs `systemd-analyze security --offline=true
  --threshold=12` (pinned to ubuntu-24.04, since scores differ between
  versions), `systemd-analyze verify --man=no` against a controlled root
  (any output fails: verify exits 0 on unknown keys), and
  `systemd-sysusers`/`systemd-tmpfiles --root` with absolute paths. A new
  `systemd` job on ubuntu-24.04 installs the files and a binary built with
  the `landlockprobe` tag (which logs the result of
  `os.Open("/etc/passwd")` after applying), starts the unit, checks the
  journal for `landlock: ABI v5 applied` and the probe's `permission
  denied`, uploads with sftp, adds a user and reloads, checks the
  `Status:` line after a failed reload, runs an exec hook whose `setsid`
  child systemd kills at stop, checks `CapEff`, `NoNewPrivs` and seccomp,
  and stops within `TimeoutStopSec`; a drop-in without the `landlock_*`
  system calls gives `landlock: not available: blocked by a seccomp
  filter`. The legacy drop-in's probe is checked against a unit with an
  unknown type.

## Consequences

- Behind a trusted proxy, bans, per-IP limits, `allow_from` and the audit
  log see the client; the proxy is recorded as `proxy_addr`.
- Headers from proxies gosftpd does not trust are refused everywhere,
  which can break a setup that worked by accident (with wrong addresses).
- On Linux with Landlock (Ubuntu 24.04 and later, Debian 12, EL9 where
  enabled), a compromised gosftpd process cannot read or write outside its
  mounts, configuration and log, unless exec hooks are configured.
- Under Landlock a reload cannot add mounts or directories that the
  ruleset does not cover, and a remounted mount needs a restart; the
  server says so in `restart_required`.
- Two new dependencies (nine direct in total, within the budget of ten).
- The unit is stricter than the one docs/security/hardening.md shows
  today; docs/install.md replaces it and tells how to remove an old unit
  in `/etc/systemd/system`, which would override the shipped one.
- ROADMAP: §4.5 notes v1 and the parser-only use; §6.1 item 9, §7.4 item 9
  and the risk table no longer claim that Landlock covers hard links, bind
  mounts or the chmod race; §9.4 takes the unit's changes, the offline
  probe for the legacy drop-in, and the corrected `@sandbox` note; the M4
  DoD notes the restart under Landlock.
