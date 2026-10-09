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
| AS3 | Credentials: `authorized_keys`, password hashes |
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
- Connection layer: channels and global requests (pre-auth → session).
- SFTP packets, including extensions (session → `internal/sftpd` →
  `internal/vfs` → `os.Root`).
- Configuration, host keys, `authorized_keys` files, CLI flags and
  environment (administrator → process).
- The process and the operating system; CI and the release artifacts.

## Threats and controls

| STRIDE | Threat | Control | Verified by |
|---|---|---|---|
| Spoofing | Authentication bypass through state captured in callbacks (CVE-2024-45337) | Identity only from `ssh.Permissions`; `x/crypto` ≥ v0.57.0 | auth tests |
| Spoofing | Guessing passwords of one user under another user's connection | The user name is pinned to the connection | server tests, paramiko interop |
| Spoofing | Enumerating users by response time | One hash checked per attempt; unknown users against a stand-in of the costliest hash; failures padded | timing test (medians within 10%) |
| Spoofing | MITM on first connection (N2) | Host key fingerprint and `known_hosts` line printed at start; SHA-2 signatures only | — |
| Tampering | Leaving a mount through `..`, absolute paths, symlinks (N3) | One `resolve` for every path; `os.Root` per mount; links cannot be created | `FuzzResolve`, `FuzzResolveInRoot`, `FuzzRequestServer`, interop |
| Tampering | Swapping a `{user}` home or a mount for a symlink or another mount (N4) | Parent `os.Root`, `Lstat` and `os.SameFile` for homes; `require_mountpoint` | vfs tests |
| Tampering | Overwriting other people's data (N3) | Conflict policy (`rename` by default), `overwrite` permission, append-only resume, one writer per file | vfs tests, interop |
| Tampering | Destroying versions under `on_conflict = "version"` (N3) | `.versions` read-only for clients, also on case-insensitive filesystems; count-based pruning only for users who may delete or overwrite | vfs tests |
| Tampering | A crafted packet stream corrupting server state (N3) | `pkg/sftp` request server behind `sftpd.Gate`, which keeps OPEN and requests with a handle apart (a data race in `pkg/sftp` v1.13) | `FuzzRequestServer` with the race detector (seeds on every test run, fuzzing in CI and nightly), gate tests |
| Repudiation | "I did not upload that" | Audit log with `user`, `key_fp`, `session_id`, `path`, `final_path`, `version_path` | audit schema test |
| Repudiation | Acting while the audit log cannot be written | `audit.on_error = "fail-closed"` | server tests |
| Information disclosure | Host paths in errors, host accounts in listings | Fixed client messages; virtual owners | protocol tests |
| Information disclosure | Reading through planted hard links or bind mounts (N4) | Not prevented by `os.Root`; documented limit | — |
| Denial of service | Connection floods, slow handshakes (N1) | Connection limits before the handshake; handshake, idle and keepalive timeouts; bans | 1000-connection test, synctest timeouts |
| Denial of service | Password hashing exhaustion (N1) | Opt-in passwords, bounded hash costs, one check per CPU, 1024-byte limit | auth tests |
| Denial of service | File descriptor or memory exhaustion through handles (N3) | 64 handles per session | handle limit test |
| Denial of service | Filling the disk, sparse writes (N3) | `max_file_size` on the end of every write, `min_free_space` | vfs tests |
| Denial of service | Crashing the process through a library race (N3) | `sftpd.Gate` | see above |
| Elevation of privilege | Shell, exec, forwarding, PTY | Only the `sftp` subsystem is accepted | server tests, interop |
| Elevation of privilege | A confinement bug while running as root | `serve` refuses root without `--allow-root` | cli tests |
| Supply chain (N5) | Compromised dependency or action | Minimal dependencies, `govulncheck`, CodeQL, actions pinned by commit SHA, Dependabot, OpenSSF Scorecard; checksums for releases | CI |

## Residual risks

- Hard links and bind mounts created on the host inside a served directory
  give access to what they point to; a local user who can create symlinks
  may race `symlinks = "deny"` and SETSTAT (see
  [../security.md](../security.md#limits-of-the-protection)).
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
- Release artifacts are not signed yet (planned for v0.5).
