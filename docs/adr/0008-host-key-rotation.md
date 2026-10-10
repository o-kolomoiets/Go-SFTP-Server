# ADR 0008: Host key rotation and host certificates

- **Status:** proposed, 2026-10-10
- **Context:** ROADMAP M4 (M4-05) asks for host key rotation and host
  certificates. Clients pin a server's host key in `known_hosts`; a new key
  makes them refuse to connect ("REMOTE HOST IDENTIFICATION HAS CHANGED")
  until each user fixes the file by hand. OpenSSH (since 6.8, on by
  default since 8.5 for the default `known_hosts`) can learn new host keys
  ahead of a change: after login the server announces all its host keys
  (`hostkeys-00@openssh.com`), and the client asks it to prove that it
  holds the ones it does not know yet (`hostkeys-prove-00@openssh.com`),
  then updates `known_hosts` (`UpdateHostKeys`). x/crypto implements
  neither, and its `ServerConfig.AddHostKey` keeps one key per key type, so
  two keys of one type cannot both be used for key exchange. Host keys are
  restart-only (ADR 0005). Host certificates let clients that trust a host
  CA (`@cert-authority` in `known_hosts`) accept any key the CA signed.

## Decision

**Next keys.** For every host key file `P` in `server.host_keys` (or the
zero-config key in `--state-dir`), a file `P.next`, if present, is a next
key: not used for key exchange, but announced to clients. Same checks as
host keys (mode 0600, owner, not inside any mount).

**Announcement** (implemented on top of x/crypto's global requests,
following OpenSSH's PROTOCOL, section 2.5):

- After a login succeeds, the server sends `hostkeys-00@openssh.com`
  (want-reply false) with the plain public keys of all host keys and all
  next keys, never certificates.
- On `hostkeys-prove-00@openssh.com` (want-reply true) the server replies
  with one signature per requested key, in order, over
  `string "hostkeys-prove-00@openssh.com", string session identifier,
  string key`; RSA keys sign with `rsa-sha2-512`. A request naming a key
  the server does not hold, or more keys than it has, fails. Other global
  requests are refused, as now.

OpenSSH clients with `UpdateHostKeys` then add the next key to
`known_hosts` while the old key still works, and remove keys the server no
longer announces.

**Rotation command.** `gosftpd hostkey rotate` (with `--config` or
`--host-key`, like `hostkey show`):

1. `rotate [--type ed25519|ecdsa|rsa]` creates `P.next` (never
   overwriting) and prints its fingerprint and `known_hosts` line, for
   clients that do not update themselves. A reload starts announcing it.
2. After a transition period (as long as clients take to connect once),
   `rotate --finish` renames `P` to `P.old` (kept for a rollback, not
   served) and `P.next` to `P`. A reload switches key exchange to it.

The key type may change in a rotation (RSA to ed25519).

**Reloadable host keys.** A reload reads the host keys again (generating a
missing one when `host_key_auto_generate` is on) and checks them like at
start; new connections use the new keys, open ones keep theirs (including
for re-keying). A host key that cannot be read fails the reload. Host keys
leave ADR 0005's restart-only list.

**Host certificates.** `server.host_certificates = ["…-cert.pub"]`: each
must be a host certificate whose key is one of the host keys, else the
configuration is refused. It is served next to the plain key
(`ssh.NewCertSigner`; certificate and plain key have different algorithm
names, so x/crypto offers both). A certificate outside its validity period
is not offered: each connection's configuration takes the certificates
valid at accept. Expiry is logged as a warning from 30 days before, at
start, on reload and once a day; an expired one as an error. `hostkey show`
prints certificates with their principals and validity.

## Consequences

- Clients without `UpdateHostKeys` (paramiko, WinSCP, rclone, older
  OpenSSH, OpenSSH with a custom `UserKnownHostsFile`) see the new key only
  at the cutover; give their users the fingerprint that `rotate` prints, or
  use host certificates.
- A connection's configuration is built at accept from the host keys and
  certificates of the current snapshot.
