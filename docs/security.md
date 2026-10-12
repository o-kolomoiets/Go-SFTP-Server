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
mounts or hard links you do not control. Landlock (below) does not change
this: it checks paths, and a hard link or a bind mount inside a mount is a
path inside the mount.

## Landlock

On Linux, once its listeners are bound and the files it needs are open,
gosftpd confines itself with Landlock
([ADR 0011](adr/0011-proxy-systemd-landlock.md)). The process can then open
only its mounts, its configuration and key files, its audit log,
`/proc/self` and the files name resolution reads (`/etc/hosts`,
`/etc/nsswitch.conf`, `/etc/resolv.conf`). A compromised gosftpd cannot read
`/etc/shadow`, the private keys in a user's `~/.ssh` or anything else of
the host, and cannot write outside its mounts and its audit log. The
ruleset cannot be lifted, also not by root.

`server.landlock` chooses ([configuration.md](configuration.md#server)):

- `auto` (the default) applies Landlock where it can be used and logs why
  not elsewhere: no Landlock in the kernel or disabled at boot, a seccomp
  filter that blocks or kills the Landlock calls, a kernel with ABI 1 only
  (it cannot allow renames between directories), exec hooks configured (a
  hook needs the loader, its libraries and whatever it touches), or a mount
  at `/`.
- `required` makes each of these reasons an error at start (exit status 2).
- `off` never applies it.

Once Landlock can be used, every other failure (a rule that cannot be
added, a ruleset the kernel refuses, a self-check that can still open `/`)
fails the start with exit status 1, in `auto` too: the default never runs
unconfined because of an error. Under systemd, `SystemCallFilter=` must
allow `landlock_create_ruleset`, `landlock_add_rule` and
`landlock_restrict_self`, which are not in `@system-service`; without them
the log says "blocked by a seccomp filter". gosftpd tries these calls in a
child process first when a seccomp filter is installed, so a filter that
kills the process instead of refusing the call does not stop the server.

The log says what happened: `landlock: ABI v5 applied` (with `kernel_abi`),
`landlock: not applied` or `landlock: not available` with a `reason`.
`server.start` in the audit log has `landlock`: `v2` to `v5`, `off`,
`unavailable`, `blocked` (a seccomp filter) or `not_applied`. Alert on
values other than `vN` and `off`. On ABI 2 (Debian 12) Landlock does not
restrict truncating a file by path, and below ABI 5 it does not restrict
`ioctl` on devices. A denied access is an ordinary `permission denied` in
gosftpd's log; on kernels with ABI 7 and the audit subsystem on, the kernel
also writes an `AUDIT_LANDLOCK_ACCESS` record to its audit log, as Landlock
does by default.

### Which files are covered

A Landlock rule on a directory covers its whole tree, while a rule on a
file is lost when the file is replaced by rename (editors, `user add
--write`, logrotate). So a directory gets a rule only when it is dedicated
to gosftpd: it can be listed, and every entry in it is a file the
configuration names (the configuration and included files, key and
certificate files, the audit log), a name derived from one (`config.toml~`,
an editor's swap file, a temporary file of `user add --write` or of
`hostkey rotate`, a host key's `.pub`), an entry of a Kubernetes ConfigMap or
Secret volume, `lost+found` at the root of a file system, or a subdirectory
that is dedicated itself and that an include pattern goes through or that
holds a named file. A `.ssh` directory, `/` and the home directory of the
user running gosftpd are never dedicated. The audit log's directory gets
its write rule only when it holds nothing but the audit log and its rotated
copies, so that no configuration or key file is ever writable.

Elsewhere each file gets a rule of its own, and a warning at start names
it and why its directory is shared. Such a file replaced by rename, or a
symlink to a file outside its directory re-pointed, cannot be read until a
restart. An include directory that does not exist at start and that no
rule covers gets a warning too: the first file added there needs a
restart (`gosftpd init` therefore creates `users.d/`). Keep the
configuration, `users.d` and key files in directories of their own, as the
packaged layout does (`/etc/gosftpd`, `/var/lib/gosftpd`,
`/var/log/gosftpd`; see [configuration.md](configuration.md#landlock)).
`gosftpd config validate --check-fs` prints the same warnings before the
first start (run it as the user that runs gosftpd). Dedication is decided
at start: a file created later in a dedicated directory is readable to
gosftpd, so keep nothing else there.

A mount's rule is added through the directory the mount holds open, so a
mount directory swapped for a symlink before the rules are added cannot
redirect it: the start fails instead.

### Reload

A reload checks what the new configuration uses against the rules applied
at start; it does not compute them again, since a directory may have
become shared or dedicated since. What the rules do not cover needs a
restart, and `server.reload` names its key in `restart_required`
([configuration.md](configuration.md#reload)):

- a new or moved mount outside the rules is unavailable, and so is a mount
  directory recreated, or with a file system mounted on it, since the start
  (gosftpd does not write to the directory below);
- a mount whose new `read_only = false` or `create = true` the rules do not
  allow keeps its running value;
- a new `audit.output` outside the rules keeps the running one; an audit
  log next to other files, rotated by rename, cannot be created again
  ([audit-log.md](audit-log.md#rotation));
- an exec hook added by the reload is left out;
- a key or CA file the rules do not cover is left out as an unreadable file
  is, a host key keeps the running host keys, and a webhook's
  `secret_file` keeps the running secret (a new hook is left out); an
  include file or the revocation list the rules do not cover fails the
  reload, without `restart_required`.

Every permission error on a path the rules do not cover adds "outside the
Landlock ruleset applied at start; restart gosftpd" in the operational log,
also when the configuration file itself is read. An audit log on `stderr`
(`/dev/stderr`) has no rule and is not opened again at reload: the
descriptor opened at start stays. When `/etc/resolv.conf` or `/etc/hosts`
was replaced by rename after the start, webhooks resolve names again only
after a restart; each reload, and each webhook that fails on name
resolution, warns about it ([hooks.md](hooks.md#sandboxes-and-containers)).

### What Landlock does not stop

- hard links and bind mounts inside a mount, which reach what they point
  to;
- `stat`, `chmod`, `chown`, `utimes` and `readlink`, which it does not
  check (the race of SETSTAT with a swapped symlink stays);
- a file system mounted on a mount directory after the start: the rule
  stays with the directory below it;
- connecting to Unix sockets, by path (an `ssh-agent`, a session bus in
  zero-configuration mode) or abstract;
- descriptors opened before the ruleset; gosftpd gives up its controlling
  terminal, so that `TIOCSTI` on an inherited terminal cannot type commands
  into the shell that started it;
- the network, and signals to processes of the same user;
- files created later in a dedicated directory;
- on ABI 2 (Debian 12) truncating files, and below ABI 5 `ioctl` on
  devices;
- anything while exec hooks are configured: Landlock is not applied then.

## Running as root

`gosftpd serve` refuses to start as root without `--allow-root`. A
confinement bug would then expose the whole host; run it as a dedicated
user that owns only the served directories.

## Files gosftpd trusts

The configuration, included files, host keys (with their next and previous
keys and certificates), `authorized_keys` files, the trusted CA keys and
the revocation list must not be writable by group or others and must belong
to root or to the user running gosftpd (like sshd's `StrictModes`); host
keys must be private (`chmod 600`). None of them may lie inside a mount
clients can write.

Hook files follow the same rules, stricter: a webhook's `secret_file` and
every file an exec hook runs may lie inside no mount at all; a secret file
must also have no permissions for others and no write for group, and an
exec hook's files are checked again just before each run. Hooks never get
a client's name as an argument or through a shell
([hooks.md](hooks.md)).

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

## Host keys

A host key can be replaced without teaching every user to ignore "REMOTE
HOST IDENTIFICATION HAS CHANGED" ([ADR 0008](adr/0008-host-key-rotation.md)):
gosftpd announces a next key to OpenSSH clients after login and proves that
it holds it, and they add it to `known_hosts` before it is used. The
announcement is sent once per connection, only to OpenSSH, and only after
the login is accepted; proofs sign a string bound to the connection, so
they cannot be replayed or used as a signing oracle. This does not help
after a key is compromised: whoever holds the old key can announce a key of
their own. Then retire the old key at once and distribute the new
fingerprint by another channel, with a `@revoked` line for the old key (see
[Rotation](configuration.md#rotation)). Host certificates are checked as
OpenSSH checks them (host type, principals, no critical options, SHA-2 CA
signature) and offered only while valid.

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
