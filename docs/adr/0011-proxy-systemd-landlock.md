# ADR 0011: PROXY protocol, the systemd unit and Landlock

- **Status:** draft 2, 2026-10-12; amends ADR 0005 (restart-only list,
  `STATUS=` after a reload), ADR 0009 (connection metrics), the audit
  schema (additive) and ROADMAP §4.5, §6.1, §7.4 and §9.4
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
  Landlock ABI 7 in a VM; a second researcher re-checked each track. Three
  reviews of draft 1 (operations, security, implementability) confirmed 32
  findings, each checked by a second reviewer.

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
  `allow_from` is (4in6 unmapped). After parsing and unmapping, a prefix of
  length 0 (also `::ffff:0:0/96`) and an invalid prefix are errors. The
  peer address is unmapped before matching: on a dual-stack listener IPv4
  peers arrive as `::ffff:a.b.c.d`.
- **What trust means.** Every host, and every local process, that can
  connect from a trusted address chooses the client address that bans,
  per-IP limits, `allow_from`, `from=`, certificate `source-address` and
  the audit log see. Trust only addresses that never carry direct client
  traffic. A loopback entry or one of the host's own addresses trusts all
  local users and all containers of a pod; docs/configuration.md shows an
  nftables rule that lets only the proxy's user reach the port over
  loopback. Where the load balancer already preserves client addresses
  (AWS NLB with instance targets by default), PROXY is not used; on
  Kubernetes node or pod ranges are never trusted
  (`externalTrafficPolicy: Local` with the load balancer's own addresses).
  The threat model gains this entry.
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
  is free text. A header whose source is a loopback or unspecified address,
  from a peer that is not loopback, is refused too, with a warning naming
  the proxy: loopback in `allow_from`, `from=`, `source-address` and
  `auth.ban.exempt` keeps meaning this host. TLVs are ignored (CRC32C
  checking is optional for receivers).
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
  the ban and `max_connections_per_ip` on the peer address.
- **Phase 2, in the connection's goroutine, for trusted peers only,** once
  the header is read: the ban and `max_connections_per_ip` on the
  effective client, then the SSH handshake. The limiter's per-address slot
  is taken in phase 2; `release` frees what was taken.
- **Whose address.** A trusted peer is never banned or per-IP limited for
  the clients it names in a header. Connections it sends as `LOCAL` or
  `UNKNOWN` (its health checks, clients of a Unix-socket front end) are its
  own: they share its ban entry and per-IP bucket, so one client of a
  Unix-socket front end can get the proxy banned and its checks refused;
  docs/configuration.md says to pass the client with PROXY on such hops.
  `config validate` warns when `trusted_proxies` overlaps
  `auth.ban.exempt` (those connections are then never banned).
- **Accounting.** A connection from a trusted peer is counted in
  `gosftpd_connections_active` from its accept, as today: it holds
  `max_connections` and `max_preauth_connections` slots. Before the
  handshake it ends in one of:
  - nothing received before the connection ends (EOF or reset) or the
    deadline (a TCP health check): `connections_total{result="no_version"}`,
    not audited, as a scanner is today. The case is chosen by the bytes
    received, never by the parser's error (`proxyproto.Read` returns the
    same error for a close without bytes and for a client without a
    header);
  - bytes that are not a valid header (missing, malformed, partial,
    unsupported, a loopback source from a remote proxy): refused,
    `conn.reject` with `reason=proxy_header`;
  - a ban or the per-IP limit on the client: refused with the existing
    reason, `conn.reject` with the client's `remote_addr`.
  A refusal in phase 2 decrements `connections_active` and is counted only
  in `gosftpd_connections_refused_total{reason}`, not in
  `connections_total`. A `proxy_header` refusal also logs a warning at most
  once a minute, naming the peer and what arrived instead ("peer 10.0.0.5
  is in server.trusted_proxies but sent no PROXY header (an SSH version
  line): enable send-proxy or proxy_protocol on the load balancer, or
  remove the address").
  A header from an untrusted peer is found after the connection was
  admitted and its banner sent: it ends with
  `connections_total{result="untrusted_proxy"}` and is audited as
  `conn.reject` with `reason=untrusted_proxy`, rate-limited as every
  `conn.reject` is; a warning in the operational log names the peer and
  `server.trusted_proxies`, at most once a minute, and adds "if this is a
  client's address, the load balancer already preserves client addresses:
  turn PROXY protocol off there". `conn.reject` is now documented as
  "refused before the SSH handshake"; docs/metrics.md no longer says that
  `connections_refused_total` counts every `conn.reject`.

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
  at reload (`reload.disconnect_removed_users`) apply to the client without
  a change in that package.
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
  `--address` or `$GOSFTPD_LISTEN`; there a configuration file that is
  missing, unreadable or invalid makes the probe send no header, with a
  note on stderr, never a failure (`--address` stays the way around an
  unreadable file). When its own source address is trusted it sends a v2
  `LOCAL` header after connecting (16 bytes) and then waits for the banner.
  Without a header, a probe from a trusted address gets no banner: it is
  unhealthy when its `--timeout` ends first, and when the server's header
  deadline ends first the close is reported as for a refused connection
  (healthy unless `--ready`). docs/metrics.md states both. This is the
  promise of ADR 0009.

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
    `ProtectHome=yes`, `ReadWritePaths=-/srv/sftp`,
    `RequiresMountsFor=/srv/sftp`, `SystemCallErrorNumber=EPERM`.
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
  only where the type is unknown. The probe works without systemd as PID 1
  (image builds) and is not fooled by the drop-in itself. docs/install.md
  gives the commands; the M5 postinstall uses the same probe and removes
  the drop-in when it is no longer needed.
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

**docs/install.md** (new) installs from the archive in the package layout:
`/usr/bin/gosftpd`, the unit in `/usr/lib/systemd/system`, sysusers and
tmpfiles in `/usr/lib/{sysusers,tmpfiles}.d`, which the M5 packages take
over. The Quickstart's install line uses `/usr/bin` too. Upgrading from
the interim unit in docs/security/hardening.md: remove
`/usr/local/bin/gosftpd` and the old unit in `/etc/systemd/system` (it
overrides the shipped one; checked with `systemctl cat`). It also covers:
the legacy drop-in; validating as the service user
(`runuser -u gosftpd -- gosftpd config validate --check-fs`: as root the
check refuses the host key that belongs to gosftpd, and it runs outside the
unit's `ProtectSystem=`/`ProtectHome=` namespace, so it cannot see paths
the unit hides or makes read-only); another data path (drop-in with
`ReadWritePaths=` and `RequiresMountsFor=`, an `/etc/tmpfiles.d` override);
mounts or key files under `/home` (`ProtectHome=read-only` with
`ReadWritePaths=`, or `ProtectHome=tmpfs` with `BindPaths=`;
`ReadWritePaths=` alone does not work with `ProtectHome=yes`); port 22;
a data disk mounted later (run tmpfiles again); a manual `umount` does not
stop the service (`BindsTo=` drop-in if wanted); and how a reload's result
is seen. The interim unit in hardening.md is replaced by a link to the
shipped unit and a table of what its directives cost.

Code changes that come with the unit:

- At stop gosftpd sends `EXTEND_TIMEOUT_USEC=` with its
  `shutdown_timeout` + 10 s, in a datagram of its own after it has read the
  final value (a reload can raise `shutdown_timeout`, while
  `TimeoutStopSec` is fixed).
- With `AmbientCapabilities=CAP_NET_BIND_SERVICE` (port 22) the capability
  would pass to exec hooks. After binding its listeners, and before the
  hook dispatcher starts, gosftpd clears the ambient set on every thread
  with go-landlock's `landlock/syscall.AllThreadsPrctl`
  (`PR_CAP_AMBIENT_CLEAR_ALL`): capabilities are per thread and a child
  inherits the forking thread's, so a plain `prctl` clears one thread only.
  A failure fails the start. gosftpd's own effective set keeps the
  capability (`capset` is in `@privileged`).
- At start, at reload and in `config validate --check-fs`, a writable
  mount whose directory is on a read-only file system (`statfs`
  `ST_RDONLY`) gives the warning "mounts.NAME.path: PATH is on a read-only
  file system; uploads will fail (under systemd: add it to
  ReadWritePaths=, docs/install.md)". Today such uploads fail with a bare
  "Failure" and nothing in the log.

**Reload results.** `systemctl reload` cannot report a failed reload under
`notify-reload`. After a reload `STATUS=` reads "configuration reloaded",
"configuration reloaded; restart needed for: KEYS" (the keys of
`restart_required`) or "configuration reload failed, see the log" (this
amends ADR 0005). docs/install.md shows `systemctl status`, the journal and
`gosftpd_config_reloads_total{result="error"}`.

### Landlock

```toml
[server]
landlock = "auto"   # "auto" (default), "off", "required"; restart-only
```

- **Modes.** `off` never applies. `auto` skips Landlock, logs why and
  serves on, only for these reasons: the kernel has no Landlock or has it
  disabled at boot; a seccomp filter blocks or kills the Landlock calls;
  the kernel offers ABI 1 only; exec hooks are configured; a rule would
  have to be placed on `/` (`--dir /`). `required` makes each of these an
  error at start (with exec hooks an error of `config validate`). Once the
  ABI query gives 2 or more and no exec hook is configured, every later
  failure (computing or adding the rules, restricting, the self-check)
  fails the start in `auto` as in `required`, with
  "landlock: failed: ERROR" (exit 1): the default mode never runs
  unsandboxed because of an error. The setting is restart-only, also in
  zero-configuration mode, where `auto` applies.
- **When.** After the listeners and the admin listener are bound, the
  ambient capabilities cleared, the host keys loaded or generated, the
  mounts opened (directories created for `create = true`), the audit
  output opened and the TLS roots loaded (ADR 0010), and before any
  background goroutine starts and before `READY=1`. `time.Local` is
  initialised before (a later first use falls back to UTC silently:
  `expiry-time` in `authorized_keys` uses it).
- **ABI.** gosftpd queries the ABI itself (`landlock_create_ruleset` with
  the version flag, through `golang.org/x/sys/unix`), because go-landlock's
  `BestEffort` silently applies nothing in four cases (no Landlock,
  Landlock disabled at boot, a seccomp filter returning `EPERM`, a rule
  needing `refer` on ABI 1) and reports nothing. When `/proc/self/status`
  shows a seccomp filter (`Seccomp: 2`), the calls are first tried in a
  child (`/proc/self/exe` with an internal argument: query, create a
  ruleset, add a rule, restrict the child): a filter that kills unlisted
  system calls, as `SystemCallFilter=` does without
  `SystemCallErrorNumber=`, would otherwise kill gosftpd at start. The
  interim unit in hardening.md is such a unit; its update and a CHANGELOG
  "Upgrading" note list the three calls. ABI 1 is not used: without
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
  fail with `EACCES` (`O_PATH` is not checked by Landlock).
- **Reporting.** Only after the self-check: "landlock: ABI vN applied
  (kernel ABI vK)" with N = min(5, K), at info, and `server.start` gets
  `landlock` = `v2` … `v5`. Otherwise `server.start` records `off`,
  `unavailable` (no Landlock, disabled at boot), `blocked` (a seccomp
  filter) or `not_applied` (ABI 1, exec hooks, a rule on `/`), and the log
  says why: "landlock: not available: blocked by a seccomp filter (allow
  landlock_create_ruleset, landlock_add_rule and landlock_restrict_self in
  SystemCallFilter=, or set server.landlock = \"off\")" at warn, the other
  reasons at info. docs/security.md says to alert on values other than
  `vN` and `off`, and lists what ABI 2 to 4 leave out (truncate by path on
  ABI 2, device ioctls below ABI 5). Landlock's kernel audit records
  (ABI 7) stay at their defaults; docs/security.md says where denials
  show up.

**Rules** are computed from the configuration. Landlock rules cover a
directory's whole tree, so a directory gets a rule only when it is
dedicated: at start, every entry in it is named by the configuration (the
main file, include matches, host keys with their `.next`, `.old` and
`-cert.pub` files, hook secrets, the audit file, subdirectories that get
rules themselves) or begins with a named file's name (`config.toml~`,
`audit.jsonl.1`). Otherwise the rule goes on the file itself and on its
symlink target, and a start warning names the key and the directory: such
a file replaced by rename (editors, `user add --write`, a logrotate
without `copytruncate`) is not readable or writable any more until a
restart. So in zero-configuration mode the default `~/.ssh/authorized_keys`
gets a rule on the file only, and the user's private keys next to it stay
unreadable. Every rule is `IgnoreIfMissing`; rights are chosen by the type
found (directory rights on a file make the whole ruleset fail).

| What | Path | Rights |
|---|---|---|
| A writable mount | the mount directory; for a `{user}` home, its parent | read file, read dir, write file, truncate, make reg, make dir, remove file, remove dir, refer |
| A read-only mount | the same | read file, read dir (+ make dir for a home with `create = true`) |
| Configuration | the main file's directory, if dedicated; for each absolute include pattern its longest leading directory without `*`, `?` or `[` (relative patterns lie under the first) | read file, read dir |
| Trusted files | `authorized_keys_file`s and the zero-configuration `--authorized-keys` file, CA files, the revocation list, host keys with their siblings, hook `secret_file`s: their directory if dedicated, else the file and its symlink target | read file |
| Audit log | the directory of `audit.output` if dedicated (logrotate creates a new file), else the file | write file, make reg (on a file: write file) |
| Process metrics, mountinfo | `/proc/self`, held open with an `O_PATH` descriptor (a rule on it is lost when the kernel reclaims the dentry) | read file, read dir |
| Name resolution (webhooks) | `/etc/hosts`, `/etc/nsswitch.conf`, `/etc/resolv.conf` and its target's directory when that is under `/run` | read file |
| Coverage data (`-cover` builds only) | `$GOCOVERDIR`, or `-test.gocoverdir` in a test child | read file, read dir, write file, make reg, remove file |

- Mount directories and home parents get their rules through the
  directory the mount holds open: gosftpd opens an `O_PATH|O_DIRECTORY`
  descriptor with the `os.Root`, checks that it is the same directory as
  `root.Stat(".")`, and gives go-landlock `/proc/self/fd/N`. A mount
  directory swapped for a symlink after it was opened cannot redirect the
  rule; a mismatch fails the start. The (device, inode) kept for reload
  comes from that descriptor.
- The coverage rule is added only when the build information says
  `-cover=true`, never because `GOCOVERDIR` is set, never on `/` and never
  on a directory that gets another rule.
- Paths under `/dev` and `/proc` other than `/proc/self` never get a rule
  (an `authorized_keys` link to `/dev/null`, a pipe, `audit.output` on
  stderr); such files stay usable through descriptors opened before.
- The name-resolution files are file rules (a rule on `/etc` would open
  it). A file replaced by rename after start (NetworkManager or dhclient
  rewriting `/etc/resolv.conf`, `sed -i` on `/etc/hosts`) is no longer
  readable, and Go's resolver then silently asks 127.0.0.1:53. gosftpd
  keeps their (device, inode); when a webhook fails on name resolution, and
  at every reload, a changed one gives the warning "landlock:
  /etc/resolv.conf was replaced after start; webhooks resolve names again
  after a restart". docs/hooks.md and docs/security.md say so.
- The ROADMAP's `/etc/ssl/certs`, `/etc/pki` and `/usr/share/zoneinfo`
  are not needed (roots and the local zone are loaded before), and
  `/var/lib/gosftpd` needs read only.

**What Landlock does not stop** (docs/security.md and the threat model,
correcting ROADMAP §7.4 item 9): hard links and bind mounts inside a mount
reach what they point to; `stat`, `chmod`, `chown`, `utimes` and
`readlink` are not checked (the `os.Root` chmod race stays); a mount rule
does not follow a file system mounted on the mount directory later;
connecting to pathname Unix sockets (an `ssh-agent` or a user's session bus
in zero-configuration mode would let a compromised process act outside the
ruleset); the network; signals to processes of the same user; and on ABI 2
kernels (Debian 12) truncating files.

**Exec hooks.** While exec hooks are configured, Landlock is not applied
(ADR 0010): a hook needs the loader, libraries and whatever it touches. A
reload that adds an exec hook while Landlock is applied leaves the hook
out with a warning and lists `hooks` in `restart_required`.

**Reload.** gosftpd keeps the applied rules with each path resolved by
`filepath.EvalSymlinks` and its (device, inode). After validating a new
configuration it computes the rules the new configuration would need,
resolves each path the same way, and checks that each is covered: an
applied rule on the same path or an ancestor, with at least the rights,
whose path still has the recorded (device, inode). A path that cannot be
resolved is not covered.

- A new or moved mount that is not covered is left out as unavailable,
  with `restart_required` naming `mounts.NAME.path`. A mount whose
  directory was recreated or had a file system mounted on it since the
  start is unavailable too (it fails closed instead of writing to the
  hidden directory), with `restart_required`. So under Landlock the M4 DoD
  "mount a new disk, SIGHUP, new files land on the new disk" needs a
  restart; the DoD is amended to say so.
- A mount whose new rights are not covered (`read_only` from true to false,
  `create = true` added to a read-only `{user}` mount) keeps its running
  `read_only` and `create`, with `restart_required` naming
  `mounts.NAME.read_only` or `mounts.NAME.create`.
- A new `audit.output` that is not covered keeps the running audit output,
  with `restart_required` (`audit.output`).
- A configuration file, include or trusted file that is not covered fails
  as an unreadable file does today: an `authorized_keys`, CA, host key or
  secret file is left out with a warning, and the successful reload lists
  its key in `restart_required`; a revocation list or an include fails the
  reload (`result=error`, `reason=config`). In every case a permission
  error on a path the start's rules do not cover carries the hint "outside
  the Landlock ruleset applied at start; restart gosftpd" in the
  operational log, also when it is raised while the file is loaded, before
  validation.
- ADR 0005's restart-only list gains `server.landlock`;
  `restart_required` keeps its format.

### Dependencies

- `github.com/pires/go-proxyproto` v0.15.0 (Apache-2.0), parser only; its
  `x/net` requirement does not enter the build. Binary: +4 KiB.
- `github.com/landlock-lsm/go-landlock` v0.10.1 (MIT), with
  `kernel.org/pub/linux/libs/security/libcap/psx` (BSD-3-Clause, dual
  licensed). On Linux, psx applies the ruleset (and the ambient capability
  clear) to every thread through `syscall.AllThreadsSyscall` in release
  builds (`CGO_ENABLED=0`) and through libpsx with cgo; from ABI 8 the
  kernel's TSYNC flag applies the ruleset. Binary: about +45 KiB on amd64.
  Writing the ~100 lines over `x/sys` ourselves was considered; the
  ROADMAP pins go-landlock, which handles the thread synchronisation in all
  three cases, so it stays.
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
  `proxy_addr` in the contexts, the accounting above (`internal/obs`
  gets a call that ends an admitted connection as refused). The accept
  loop stays free of I/O.
- `internal/config`: `server.trusted_proxies`, `server.landlock`, their
  checks and warnings, the read-only file system warning.
- `internal/sandbox` (new, Linux build tags with a stub elsewhere): the
  ABI query and the seccomp probe child, the rules from a `*config.Config`
  and the mount table (a pure function with injected `stat` and
  directory listing, testable on every platform), applying them through
  go-landlock, the self-check, the coverage check for reload, the ambient
  capability clear. `internal/vfs` exposes each open mount's `O_PATH`
  descriptor. `internal/cli` calls the sandbox in `serve` through a
  package variable that tests replace, so that `go test` never sandboxes
  its own process.
- `internal/sdnotify`: `EXTEND_TIMEOUT_USEC`; `STATUS=` texts.
- `internal/cli`: `healthcheck` sends `LOCAL` when its source is trusted.
- `packaging/`: the files above; `.goreleaser.yaml` adds them to the Linux
  archives only.

**Tests.**

- PROXY, on every platform (a connection wrapper presents any peer
  address; the existing pipe and synctest harness gives fake time): v2 and
  v1 headers (TCP4, TCP6, mapped addresses) and the audit fields; `LOCAL`
  and `UNKNOWN`, which share the proxy's ban entry; refused families,
  lengths, split v1 headers and loopback sources from a remote peer; a
  header and the client's first bytes arriving together beyond the
  256-byte buffer; a trusted peer that closes with FIN, one that closes
  with RST and one that stays silent, all before a byte (no audit,
  `no_version`); a client that stops after a valid header is cut at the
  handshake deadline (the deadline is not cleared); a silent trusted peer
  does not delay another connection's banner; per-IP limits and bans on
  the client through one proxy, and never on the proxy; IPv6 /64 grouping
  and a mapped client keyed as IPv4; `allow_from` (also `127.0.0.1` behind
  a remote proxy), `from=`, certificate `source-address` and the reload
  re-check on the client; a header from an untrusted peer (also with
  `trusted_proxies` empty, and after a trusted header) refused after the
  banner; a client that sends exactly its version line is not held back;
  `connections_active` returns to 0 after each ending and each adds
  exactly one counter; `/0`, `::ffff:0:0/96` and invalid prefixes refused;
  reload of `trusted_proxies`; healthcheck with both orders of the two
  timeouts and an unreadable file with `--address`. `FuzzProxyHeader`
  joins the fuzz targets (CI smoke and nightly). On Linux, real sockets
  with 127.0.0.2 as the trusted source. Interop (ubuntu-24.04): OpenSSH
  sftp, paramiko and rclone through HAProxy (`send-proxy`,
  `send-proxy-v2`, TLVs, a Unix-socket front end) and nginx
  (`proxy_protocol on`), the audit fields checked; HAProxy health checks
  stay out of the audit log; direct headers refused; `healthcheck` from a
  trusted loopback.
- Landlock: the rule computation and the reload coverage check run on
  every platform with injected `stat` and listings (writable, read-only and
  home mounts; includes, also an absolute pattern with a wildcard
  directory; dedicated and shared directories, the zero-configuration
  `~/.ssh` and a configuration in `$HOME`; symlinked and `/dev` trusted
  files; host key siblings; audit on a file, in a shared directory and on
  stderr; the coverage rule only in `-cover` builds; deduplication); mode
  and reporting with an injected ABI query and probe result (no Landlock,
  disabled, seccomp `EPERM`, seccomp kill, ABI 1, ABI 7, a rule on `/`, a
  `Restrict` error and a failed self-check in `auto`). On Linux the test
  binary re-executes itself for each sandboxed test (coverage builds pass
  `-test.gocoverdir` on, which gets its rule; children never use
  `t.TempDir`): under the real ruleset every vfs operation works (upload,
  atomic and resumed uploads, every conflict policy with versions,
  rename, remove, mkdir, setstat, statvfs, home creation) and nothing
  outside is reachable (`/etc/passwd` through a planted symlink,
  `/proc/self/root` and an `os.Root` opened before; `~/.ssh/id_ed25519`
  next to a zero-configuration `authorized_keys`; a sibling of an audit
  file in a shared directory); a mount swapped for a symlink before the
  rules are added; the hard-link limitation is asserted as a documented
  gap; reload coverage (a new mount, one that is a symlink out of a
  covered directory, a recreated mount, `read_only` turned off, a replaced
  `users.d` file, a new audit directory, a new team directory under a
  wildcard include); a seccomp filter that kills `landlock_create_ruleset`
  is survived; the ambient capability set is empty in children started from
  many goroutines (under `setpriv --ambient-caps +net_bind_service`). These
  run with `CGO_ENABLED=0` (the release path) and with cgo and `-race`, on
  ubuntu-24.04, ubuntu-24.04-arm and ubuntu-26.04 (kernel 7.0, the TSYNC
  path). CI fails instead of skipping when these kernels report no
  Landlock. The interop binary is built with `CGO_ENABLED=0`, and every
  server's log is checked for `landlock: ABI v[2-5] applied` (the hooks
  server: `not applied: exec hooks configured`). An internal/cli test
  checks every audit line of a serve run with a reload (`server.start`,
  `server.reload`, `server.stop`) against the audit schema.
- systemd: the lint job runs `systemd-analyze security --offline=true
  --threshold=12` (pinned to ubuntu-24.04, since scores differ between
  versions), `systemd-analyze verify --man=no` against a controlled root
  (any output fails: verify exits 0 on unknown keys), and
  `systemd-sysusers`/`systemd-tmpfiles --root` with absolute paths. A new
  `systemd` job on ubuntu-24.04 installs the files and a binary built with
  the `landlockprobe` tag (which logs the result of
  `os.Open("/etc/passwd")` after applying), starts the unit, checks the
  journal for `landlock: ABI v[2-5] applied` and the probe's `permission
  denied`, uploads with sftp, adds a user and reloads, checks the
  `Status:` line after a failed reload and after one that needs a restart,
  runs an exec hook whose `setsid` child systemd kills at stop, checks
  `CapEff`, `NoNewPrivs` and seccomp, and stops within `TimeoutStopSec`. A
  port-22 drop-in with an exec hook that records its own `CapAmb` and
  `CapEff` (both 0). A drop-in without the `landlock_*` system calls gives
  "blocked by a seccomp filter" with `SystemCallErrorNumber=EPERM`, and the
  unit stays active with the kill action too. The old hardening.md unit
  starts the new binary. The legacy drop-in's probe is checked against a
  unit with an unknown type.

## Consequences

- Behind a trusted proxy, bans, per-IP limits, `allow_from` and the audit
  log see the client; the proxy is recorded as `proxy_addr`. Whoever can
  connect from a trusted address can choose the client address.
- Headers from proxies gosftpd does not trust are refused everywhere,
  which can break a setup that worked by accident (with wrong addresses).
- On Linux with Landlock (Ubuntu 24.04 and later, Debian 12, EL9 where
  enabled), a compromised gosftpd cannot open files outside its mounts,
  its configuration and trusted-file rules, its audit rule, `/proc/self`
  and the name-resolution files, unless exec hooks are configured. It can
  still use pathname Unix sockets, the network and signals, change modes,
  owners and times of files its user may change, and on ABI 2 truncate
  them.
- Under Landlock a reload cannot add mounts or directories that the
  ruleset does not cover, and a remounted mount needs a restart; the
  server says so in `restart_required` and in `systemctl status`. A
  configuration or key file in a shared directory, replaced by rename,
  needs a restart too.
- Two new dependencies (nine direct in total, within the budget of ten).
- The unit is stricter than the one docs/security/hardening.md shows
  today; docs/install.md replaces it and tells how to remove an old unit
  in `/etc/systemd/system`, which would override the shipped one.
- ROADMAP: §4.5 notes v1 and the parser-only use; §6.1 item 9, §7.4 item 9
  and the risk table no longer claim that Landlock covers hard links, bind
  mounts or the chmod race; §9.4 takes the unit's changes, the offline
  probe for the legacy drop-in, and the corrected `@sandbox` note; the M4
  DoD notes the restart under Landlock.
