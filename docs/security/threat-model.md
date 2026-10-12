# Threat model

What gosftpd defends, against whom, and where. The controls are described
in [../security.md](../security.md); how to deploy them is in
[hardening.md](hardening.md). Report vulnerabilities as described in
[SECURITY.md](../../SECURITY.md).

## Assets

| ID | Asset |
|---|---|
| AS1 | Files in the mounts: their content, names and existence |
| AS2 | Private host keys |
| AS3 | Credentials: `authorized_keys`, password hashes, trusted CA keys, the revocation list |
| AS4 | The rest of the host's filesystem |
| AS5 | Availability: CPU, memory, file descriptors, disk |
| AS6 | Integrity and completeness of the audit log |
| AS7 | The configuration |

## Adversaries

| ID | Adversary | Can |
|---|---|---|
| N1 | Unauthenticated attacker on the network | Connect, scan, brute-force, send malformed SSH and SFTP data before login |
| N2 | Man in the middle | Read and change traffic between client and server |
| N3 | Authenticated user, malicious or compromised | Send any SFTP request, in any order, within its permissions |
| N4 | Local user of the host who can write to served directories | Plant symlinks, hard links, FIFOs; replace directories |
| N5 | Supply-chain attacker | Tamper with dependencies, CI or release artifacts |

The administrator who writes the configuration and runs the server is
trusted.

## Entry points and trust boundaries

- TCP listener and SSH version exchange; key exchange; user authentication
  (N1 → pre-auth).
- PROXY protocol headers from the load balancers in
  `server.trusted_proxies` (ADR 0011), which name the client address that
  bans, limits, `allow_from` and the audit log use (load balancer →
  pre-auth).
- Connection layer: channels and global requests (pre-auth → session).
- SFTP packets, including extensions (session → `internal/sftpd` →
  `internal/vfs` → `os.Root`).
- The admin listener (`[metrics] listen`, off by default): HTTP requests
  to `/metrics`, `/healthz`, `/readyz` and, in binaries built with
  `-tags pprof`, `/debug/pprof` (whoever can reach it → process).
- Configuration, host keys, `authorized_keys` files, CLI flags and
  environment (administrator → process).
- Hooks (`[[hooks]]`, ADR 0010): exec hooks receive client-chosen names in
  their environment and stdin (session → a program gosftpd starts);
  webhooks send audit events to a receiver (process → network).
- The process and the operating system; CI and the release artifacts.

## Threats and controls

| STRIDE | Threat | Control | Verified by |
|---|---|---|---|
| Spoofing | Authentication bypass through state captured in callbacks (CVE-2024-45337) | Identity only from `ssh.Permissions`; `x/crypto` ≥ v0.57.0 | auth tests |
| Spoofing | Guessing passwords of one user under another user's connection | The user name is pinned to the connection | server tests, paramiko interop |
| Spoofing | Enumerating users by response time | One hash checked per attempt; unknown users against a stand-in of the costliest hash; failures padded | timing test (medians within 10%) |
| Spoofing | A certificate logging in as a user its CA did not name, or with restrictions gosftpd cannot enforce (no principals, a SHA-1 CA signature, `force-command`, `verify-required`) | gosftpd checks certificates itself (ADR 0007): at least one principal, matched against the user's `principals` or the `cert-authority` line; SHA-2 CA signatures only; critical options limited to `source-address` and an SFTP-only `force-command`; the CA signature verified before the user is looked up, so unknown users cost the same | auth tests, interop with OpenSSH certificates |
| Spoofing | A key, password or user revoked by a reload still logging in, or staying logged in | Every login is rechecked after the handshake against the configuration current then (x/crypto caches accepted keys); `reload.disconnect_removed_users` closes open connections whose login is revoked; a deleted `authorized_keys` file revokes its keys on reload; the revocation list fails closed (an invalid list fails the reload, and a revoked certificate revokes its key) | server and cli reload tests, interop |
| Spoofing | MITM on first connection (N2) | Host key fingerprint and `known_hosts` line printed at start; SHA-2 signatures only; host certificates for clients that trust a host CA (ADR 0008) | interop with `@cert-authority` |
| Spoofing | Users trained to accept a changed host key after a rotation (N2) | `hostkey rotate`: OpenSSH clients learn the next key before it is used (`UpdateHostKeys`); the previous key stays announced until it is retired, so a rollback goes unnoticed; a compromised key is retired at once and revoked out of band (ADR 0008) | server and cli tests, interop with OpenSSH (ed25519 and RSA with `rsa-sha2-256`) |
| Spoofing | Making the server sign chosen data with its host key | Proofs sign only `hostkeys-prove-00@openssh.com`, the session identifier and an announced key; one proof request per connection, after login | `FuzzHostKeyProof`, server tests |
| Spoofing | Choosing the client address that bans, per-address limits, `allow_from`, `from=`, certificate `source-address` and the audit log see, with a PROXY protocol header (N1), or from a host or local process that can connect from a trusted address | Headers are read only from TCP peers in `server.trusted_proxies` (`/0` refused) and refused from every other peer, also with the list empty and after a trusted header; only TCP clients can be named; a loopback or unspecified client only from a proxy on this host; the proxy recorded as `proxy_addr`; docs: trust only the load balancers' own addresses, an nftables rule for a proxy on loopback, never Kubernetes node or pod ranges (ADR 0011) | server tests over pipes and real sockets, `FuzzProxyHeader`, interop with HAProxy and nginx |
| Repudiation | Clients logged with a load balancer's address, because x/crypto skips a PROXY header it was not told about | A header from a peer that is not trusted ends the connection after the banner (`untrusted_proxy`) | server tests, interop |
| Tampering | Leaving a mount through `..`, absolute paths, symlinks (N3) | One `resolve` for every path; `os.Root` per mount; links cannot be created | `FuzzResolve`, `FuzzResolveInRoot`, `FuzzRequestServer`, interop |
| Tampering | Swapping a `{user}` home or a mount for a symlink or another mount (N4) | Parent `os.Root`, `Lstat` and `os.SameFile` for homes; `require_mountpoint` | vfs tests |
| Tampering | A client writing a file gosftpd trusts (a key, an included user file, the configuration, the audit log), which a reload would apply (N3) | `CheckFS` refuses trusted files inside writable mounts, including those that connections of an earlier configuration still use, and host keys and configuration files inside any mount, at start and on reload; symlinks and Linux bind mounts are followed | config tests |
| Tampering | Overwriting other people's data (N3) | Conflict policy (`rename` by default), `overwrite` permission, append-only resume, one writer per file | vfs tests, interop |
| Tampering | Destroying versions under `on_conflict = "version"` (N3) | `.versions` read-only for clients, also on case-insensitive filesystems; count-based pruning only for users who may delete or overwrite | vfs tests |
| Tampering | A crafted packet stream corrupting server state (N3) | `pkg/sftp` request server behind `sftpd.Gate`, which keeps OPEN and requests with a handle apart (a data race in `pkg/sftp` v1.13) | `FuzzRequestServer` with the race detector (seeds on every test run, fuzzing in CI and nightly), gate tests |
| Repudiation | "I did not upload that" | Audit log with `user`, `key_fp`, `session_id`, `path`, `final_path`, `version_path` | audit schema test |
| Repudiation | Acting while the audit log cannot be written | `audit.on_error = "fail-closed"`; a file that cannot be reopened after rotation fails writes instead of filling the rotated file | server and cli tests |
| Information disclosure | Host paths in errors, host accounts in listings | Fixed client messages; virtual owners | protocol tests |
| Information disclosure | Reading through planted hard links or bind mounts (N4) | Not prevented by `os.Root`, nor by Landlock, which checks paths: a hard link or a bind mount inside a mount is a path inside it; documented limit | a sandboxed cli test asserts the hard-link gap |
| Information disclosure, Tampering | A compromised gosftpd process (a bug in gosftpd or a library) reading or changing the rest of the host (AS4), other users' private keys or its own configuration and keys (AS2, AS3, AS7) | Landlock on Linux (ADR 0011): once the listeners are bound, the process can open only its mounts, its configuration and key files (read only), its audit log (writing it, and creating files next to it only when its directory holds nothing else), `/proc/self` and the name-resolution files; `auto` by default, the audit event `server.start` records whether it applied; computing or applying the rules fails the start rather than running without them | sandbox and cli tests that re-execute the test binary under the real ruleset, in CI with and without cgo; interop checks every server's log |
| Elevation of privilege | Landlock skipped without notice: a seccomp filter that refuses or kills its calls, a kernel without it | gosftpd queries the ABI itself and probes the calls in a child under a seccomp filter; every reason not to apply it is logged and recorded in `server.start` (`unavailable`, `blocked`, `not_applied`); `server.landlock = "required"` makes it an error | sandbox tests with seccomp filters that kill, trap or refuse the calls |
| Elevation of privilege | An exec hook inheriting `CAP_NET_BIND_SERVICE` from `AmbientCapabilities=` (port 22) | The ambient set is cleared on every thread once the listeners are bound, before any hook can run | cli test under `sudo setpriv` with the capability in the ambient set |
| Elevation of privilege | Commands typed into the shell that started `serve`, through an inherited terminal (`TIOCSTI`) | Landlock checks a descriptor only when it is opened; gosftpd gives up its controlling terminal after applying the ruleset. That holds only without `CAP_SYS_ADMIN`: as root (`--allow-root`) `TIOCSTI` works on any terminal, so a root `serve` is started detached from the shell (systemd, or `setsid` with stdio redirected) | sandbox test under a pty |
| Information disclosure | Learning versions, users or load from the admin listener (N1) | Off by default; a warning when it is not on loopback; when gosftpd binds loopback, requests must name a loopback host (DNS rebinding gets 421; not with Docker's `0.0.0.0` bind); labels hold no user, path, address or fingerprint; pprof only in binaries built for it, off by default, without `cmdline` (ADR 0009) | obs and cli tests, interop with promtool |
| Denial of service | Connection floods, slow handshakes (N1) | Connection limits before the handshake; handshake, idle and keepalive timeouts; bans | 1000-connection test, synctest timeouts |
| Denial of service | Getting a load balancer banned or limited for its clients, or stalling the accept loop with a slow PROXY header (N1) | Bans and `max_connections_per_ip` apply to the client the header names, never to the load balancer for them; the header is read in the connection's goroutine within `handshake_timeout`, at most 10 s; `config validate` warns when `trusted_proxies` overlaps `auth.ban.exempt` | server tests under synctest |
| Denial of service | Password hashing exhaustion (N1) | Opt-in passwords, bounded hash costs, one check per CPU, 1024-byte limit | auth tests |
| Denial of service | File descriptor or memory exhaustion through handles (N3) | 64 handles per session | handle limit test |
| Denial of service | Filling the disk, sparse writes (N3) | `max_file_size` on the end of every write, `min_free_space` | vfs tests |
| Denial of service | Crashing the process through a library race (N3) | `sftpd.Gate` | see above |
| Denial of service | Exhausting the process through the admin listener (N1) | Header size and time limits, at most 64 connections (Shutdown is not held up by them) and 4 concurrent scrapes or profiles (503 beyond), profiles of at most 60 s; its failure does not stop the SFTP server, unless an HTTP liveness probe on `/healthz` turns held connections into restarts: liveness uses the SSH check of `gosftpd healthcheck` | obs tests |
| Elevation of privilege | Shell, exec, forwarding, PTY | Only the `sftp` subsystem is accepted | server tests, interop |
| Elevation of privilege | A client's file name run as a command or option by an exec hook (N3) | argv without a shell, never an argument from a client; names only in `GOSFTPD_*` and stdin; docs/hooks.md shows quoting and `--` | hooks tests with hostile names, cli test, interop with a `/bin/sh` hook |
| Elevation of privilege | Running a hook program a client or a local user can change (N3, N4) | argv files refused inside any mount; owner root or gosftpd's user and not writable by group or others, checked at start, on reload and before each run | config and hooks tests |
| Tampering | An exec hook acting on another file than the event's: a symlink or another file swapped in before it runs (N4), a symlink renamed by a client | The file's identity is recorded with the operation and checked (`os.SameFile`, same type, a regular file or directory) just before the run; the race after the check is a documented limit | hooks and vfs tests |
| Spoofing | A forged or replayed webhook delivery (N2) | HMAC-SHA256 over delivery ID, timestamp and body; receivers refuse old timestamps and repeated IDs (docs/hooks.md); TLS with the system roots, no redirects | golden test vector, cli test with a verifying receiver |
| Spoofing | Making hooks act on another user's file as one's own upload (N3) | An append-only resume of a file that is not the user's, or an upload in place that changed nothing, fires no hook; the rename mark needs the user's own upload closed ok | vfs tests |
| Information disclosure | A webhook token in the URL leaking into logs | Failures log `scheme://host` and the unwrapped cause, never the URL; response bodies are not logged | hooks test with a token URL |
| Denial of service | Flooding hooks with events, or a hook that hangs (N3) | A bounded queue per hook (events and 64 MiB), enqueueing never blocks a request; exec timeout kills the process group; webhook attempt timeouts and at most 5 attempts; shutdown bounded | hooks tests under synctest |
| Elevation of privilege | A confinement bug while running as root | `serve` refuses root without `--allow-root` | cli tests |
| Supply chain (N5) | Compromised dependency or action | Minimal dependencies, `govulncheck`, CodeQL, actions pinned by commit SHA, Dependabot, OpenSSF Scorecard; checksums for releases | CI |

## Residual risks

- Hard links and bind mounts created on the host inside a served directory
  give access to what they point to; a local user who can create symlinks
  may race `symlinks = "deny"` and SETSTAT (see
  [../security.md](../security.md#limits-of-the-protection)). Landlock
  does not change this: it checks paths, and it does not check `chmod`,
  `chown`, `utimes` or `stat`.
- Landlock leaves a compromised process its Unix sockets (by path and
  abstract), descriptors opened before the ruleset, the network, signals to
  processes of the same user and files created later in a dedicated
  directory; on ABI 2 it does not restrict truncation. It is not applied
  while exec hooks are configured, nor where the kernel or a seccomp filter
  does not allow it; `server.start` says so (see
  [../security.md](../security.md#what-landlock-does-not-stop)).
- Bans are per process and in memory; a restart clears them, and a burst
  over many parallel connections gets a few more attempts than
  `after_failures`.
- Mixed password hash kinds or costs can reveal which users exist to an
  attacker who measures many parallel attempts (`config validate` warns).
- gosftpd limits concurrent pre-authentication connections, not their rate:
  key exchange CPU (CVE-2002-20001, "DHEat") is bounded by
  `max_preauth_connections`, not prevented. With `crypto_policy = "compat"`
  the Diffie-Hellman groups make each exchange costlier; rate-limit new
  connections in the firewall for servers on the internet (see
  [hardening.md](hardening.md)).
- Whoever can connect from an address in `server.trusted_proxies` can name
  any client address; gosftpd cannot tell the load balancer from another
  process or host that uses that address (see
  [What trust means](../configuration.md#what-trust-means)). The clients of
  a load balancer's Unix socket front end arrive as its own connections and
  share its ban entry: one of them can get the load balancer banned.
- The admin listener has no authentication or TLS; who can reach it can
  read the metrics, and with pprof on, profile the process (see
  [hardening.md](hardening.md#admin-listener)).
- An exec hook resolves the host path itself, outside `os.Root`: after the
  identity check a local user who can write the directory can still swap
  the file (see [../hooks.md](../hooks.md#exec)). Hook events can be lost
  (a full queue, shutdown, a crash); the audit log is the record.
- Release artifacts are not signed yet (planned for v0.5).
