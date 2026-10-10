# Security model

What gosftpd protects, how, and where its protection ends. The
[threat model](security/threat-model.md) maps threats to these controls; the
[hardening guide](security/hardening.md) says how to deploy them. Report
vulnerabilities as described in [SECURITY.md](../SECURITY.md).

## What a client can do

- **Authenticate** with a public key, an OpenSSH certificate from a trusted
  CA, or a password where `auth.methods` allows it. Unknown users, wrong
  keys or passwords, disabled or expired accounts, revoked keys and
  disallowed addresses all fail the same way (the key of a disabled account
  is not accepted even as a query, so holding a public key or certificate
  reveals nothing), and an unknown user takes as long to refuse as a wrong
  password or a certificate of a known user (its CA signature is verified
  either way). Only the audit log says why (`auth.failure` `reason`).
  Identity flows only through the SSH library's permissions, never through
  state captured during authentication (CVE-2024-45337). They are built
  afresh for a certificate: of its options only `source-address` is
  carried over, so that the SSH library enforces it.
- **Open SFTP sessions**, nothing else: shell, exec, PTY, environment, agent
  and port forwarding requests are refused.
- **Work inside its mounts** with the permissions of its user, see
  [configuration.md](configuration.md#permissions).

## Brute force and floods

- Connections are counted right after accept, before the SSH handshake: at
  most `max_connections` in total, `max_connections_per_ip` per IPv4 address
  or IPv6 /64, and `max_preauth_connections` that have not logged in yet.
  With the defaults (16 per address, 64 before login, 256 in total) one
  source cannot take all pre-authentication slots; `config validate` warns
  when the per-address limit is not below the other two.
- A source with 10 failures within 10 minutes is refused at accept for 30
  minutes (`[auth.ban]`). Every wrong password counts at once, and
  connections the source still has open get no further password checks;
  rejected keys count once per connection, so an SSH agent offering many
  keys does not ban its owner. A connection cannot switch to another user
  name after a failed attempt.
  Loopback is exempt by default. The ban list lives in memory and is bounded
  (65 536 sources); a restart clears it.
- The handshake must finish within `handshake_timeout`; a connection without
  SFTP traffic for `idle_timeout` is closed, and so is one that leaves 3
  keepalive requests unanswered.
- A password attempt checks one hash, at most one per available CPU at a
  time, so pre-authentication memory and CPU stay bounded (19 MiB per
  check with the default parameters). Passwords over 1024 bytes are refused
  without hashing. Unknown users are checked against a stand-in of the
  costliest configured hash, and failures wait until that check would have
  finished. With one kind and cost of hash (the default) the response time
  does not show which users exist; with several, parallel attempts can
  still show it (see [configuration.md](configuration.md#usersname)).
- Bans are a soft limit: a burst over many parallel connections can get
  up to about `max_connections_per_ip` more password checks than
  `after_failures` before the ban stops it.
- Refused connections are logged at most 10 per second.

## Protocol robustness

The SFTP protocol is served by `pkg/sftp`'s request server; gosftpd's
handlers see only parsed requests. The parsers that face clients and
administrators are fuzzed in CI on every change and nightly: path
resolution inside and outside a tree with symlinks, names of conflict
copies, the configuration, `authorized_keys`, certificates offered at
login, and a stream of arbitrary SFTP packets against the real handlers,
with the race detector. Fuzzing
found a data race in `pkg/sftp` v1.13: a request with a guessed handle that
is processed while an OPEN is in progress races with it, which could crash
the server. gosftpd keeps them apart: an OPEN is passed on once every
earlier request is answered, and a request with a handle once the latest
OPEN is answered. Clients learn handles from that answer, so they are not
slowed down.

## Confinement

Each mount is opened as an `os.Root` at start. Every operation resolves the
client path once (cleaned, at most 4096 bytes and 64 levels, valid UTF-8, no
NUL) and passes only a relative name to the `os.Root`, which refuses `..`,
absolute paths and symlinks leading out of the mount. Clients cannot create
symlinks or hard links. FIFOs, sockets and devices are hidden from listings
and refused for transfers; their type is checked before a file is opened.
No response, listing or error message contains a host path, and listings
show a virtual owner instead of host accounts.

Home mounts (`{user}`) open the user's directory only if it is a real
directory, and check that the opened directory is the one inspected; a
symlink planted in its place, even to another user's home, makes the mount
unavailable.

## Upload integrity

- Uploads never replace an existing file unless the mount's policy is
  `overwrite` and the user has the `overwrite` permission. With `version`
  the replaced file is kept in the versions directory, which clients can
  read but not change, for `versions.max_age`; a user who may only write
  cannot push it out by uploading many versions.
- A resumed upload can only append; the bytes the file had are immutable.
- While an upload has a file open, nobody else can write it in place.
- An aborted upload removes only the empty file it created itself, after
  checking that it is still that file. With `atomic_uploads` (and for
  conflicts under `version`) an upload is written to a hidden temporary
  file and takes its name only when the client closes it; an aborted one
  leaves nothing.
- `max_file_size` bounds every write by its end offset, so sparse writes far
  past the end are refused; `min_free_space` (1 GiB by default) refuses new
  writes on a nearly full filesystem, which also keeps room for the audit
  log.

## Limits of the protection

`os.Root` does not protect against everything on the host:

- **Bind mounts and other mounts inside a served directory** are followed.
- **Hard links created on the host** to files outside the mount give access
  to those files.
- **Symlinks created by local users**: with `symlinks = "deny"`, paths through
  existing symlinks are refused, but a local user who can create symlinks in
  a served directory may race the check.
- **A directory replaced after start**: a mount keeps the directory it opened.
  If a disk is mounted over the path later, gosftpd keeps writing to the old
  directory; `require_mountpoint = true` refuses to start without the mount.
- **Times and sizes** set through SETSTAT act on a path and can, like
  `chmod` in other servers, race with a local user who swaps a file for a
  symlink.

So: run gosftpd as a dedicated unprivileged user, serve directories that only
that user and gosftpd's clients write to, and do not serve trees that contain
mounts or hard links you do not control.

## Running as root

`gosftpd serve` refuses to start as root without `--allow-root`. A
confinement bug would then expose the whole host; run it as a dedicated
user that owns only the served directories.

## Files gosftpd trusts

The configuration, included files, host keys, `authorized_keys` files, the
trusted CA keys and the revocation list must not be writable by group or
others and must belong to root or to the user running gosftpd (like sshd's
`StrictModes`); host keys must be private (`chmod 600`). None of them may
lie inside a mount clients can write.

## Certificates

gosftpd checks OpenSSH user certificates itself rather than with the SSH
library's checker, which accepts a certificate without principals for every
user and SHA-1 CA signatures ([ADR 0007](adr/0007-user-certificates.md)).
A certificate needs at least one principal that the user allows, a CA
signature with SHA-2 that verifies, a validity period that includes now, and
no critical option but `source-address` (enforced) and an SFTP-only
`force-command`. The revocation list fails closed: a list that cannot be
read or parsed is an error at start and fails a reload. A revoked
certificate revokes its key, as in sshd.

## Cryptography

The default `crypto_policy = "modern"` offers key exchange
`mlkem768x25519-sha256` and `curve25519-sha256`; ciphers ChaCha20-Poly1305,
AES-GCM and AES-CTR; MACs HMAC-SHA2 with encrypt-then-MAC. `compat` adds NIST
curve and SHA-2 Diffie-Hellman key exchange and MACs without
encrypt-then-MAC, for old clients; scanners such as ssh-audit flag those (see
[hardening.md](security/hardening.md#cryptography) for the expected findings;
CI checks that `modern` has none that fail).
SHA-1, CBC and DSA are never offered. Host and user RSA keys sign with SHA-2
only, and user RSA keys need at least 2048 bits; CA keys and certified keys
follow the same rules, and CA signatures with SHA-1 (`ssh-rsa`) are refused.
`verify-required` in `authorized_keys` or in a certificate is refused,
because the SSH library does not check the user-verification flag of
security keys.

## Audit

Every login, transfer and change is logged ([audit-log.md](audit-log.md)).
By default the log is fail-closed: if it cannot be written, gosftpd refuses
new connections and changes instead of working unaudited.
