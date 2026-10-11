# ADR 0008: Host key rotation and host certificates

- **Status:** accepted, 2026-10-10; amends ADR 0005 (host keys reload)
- **Context:** ROADMAP M4 (M4-05) asks for host key rotation and host
  certificates. Clients pin a server's host key in `known_hosts`; a new key
  makes them refuse to connect ("REMOTE HOST IDENTIFICATION HAS CHANGED")
  until each user fixes the file by hand. OpenSSH can learn new host keys
  ahead of a change (`UpdateHostKeys`, on by default since 8.5 for the
  default `known_hosts`): after login the server announces all its host
  keys (`hostkeys-00@openssh.com`), the client asks it to prove that it
  holds the ones it does not know (`hostkeys-prove-00@openssh.com`), adds
  them, and removes the keys of that host the server did not announce. The
  wire format is in OpenSSH 9.6's `PROTOCOL` (section 2.5), `serverloop.c`
  and `clientloop.c`, and in draft-miller-sshm-hostkey-update. x/crypto
  implements neither request, and its `ServerConfig.AddHostKey` keeps one
  key per key type, so two keys of one type cannot both be used for key
  exchange. Host keys are restart-only (ADR 0005). Host certificates let
  clients that trust a host CA (`@cert-authority` in `known_hosts`) accept
  any key the CA signed. Three adversarial reviews of a first draft
  (protocol, operability, integration), with experiments against OpenSSH
  9.6, paramiko and x/crypto clients, shaped the decisions below.

## Decision

### Key files

For every host key file `P` (in `server.host_keys`, `--host-key`, or the
zero-config key in the state directory), gosftpd also reads, when present:

| File | Role |
|---|---|
| `P` | current key: used for key exchange and announced |
| `P.next` | next key: announced, not used for key exchange |
| `P.old` | previous key, after a cutover: announced, not used for key exchange |
| `P-cert.pub`, `P.next-cert.pub` | certificates (below) |

`ssh-keygen -s CA -h P.next.pub` writes `P.next-cert.pub`, so the names
follow ssh-keygen and no setting changes during a rotation. Every private
key is checked like a host key: mode 0600, owner root or the user running
gosftpd, not inside any mount. A key that appears twice (a next key equal
to a current key, say) is refused, since OpenSSH abandons an update with a
duplicate key. Two current keys of one type are refused: x/crypto would
silently use only one of them.

### Announcement and proofs

- After a login passes the final check (step 3 of ADR 0005) and is audited,
  and before any channel is served, gosftpd sends `hostkeys-00@openssh.com`
  (want-reply false) once per connection, never again, also not after a
  reload: OpenSSH ends the connection on a second one. The payload is the
  concatenation of `string(key)` for the plain public keys of the current,
  next and old keys, never certificates. It is the key set taken at accept,
  which also chose the key exchange key.
- It goes only to clients whose version starts with `SSH-2.0-OpenSSH`: only
  OpenSSH uses it, and sshd itself skips clients that break on it (Cisco,
  TeraTerm). `server.announce_host_keys = false` turns it off.
- The first `hostkeys-prove-00@openssh.com` on the connection, after the
  announcement, gets one signature per requested key, in order, each
  `string(signature)`, over `string("hostkeys-prove-00@openssh.com") ||
  string(session identifier) || string(key)`. Every requested key must be
  one of the announced keys, at most once, and the payload must parse
  exactly; otherwise, and for any later prove request, the reply is a
  failure. An RSA key signs with the RSA algorithm negotiated for the
  connection's key exchange (`rsa-sha2-256` or `rsa-sha2-512`, also when
  the `-cert-v01` form was negotiated), as sshd does, since the client
  verifies with that algorithm; after a non-RSA key exchange it signs with
  `rsa-sha2-512`. Global requests are handled in order by one goroutine;
  every other one is refused, as now.
- An answered proof is audited as `conn.hostkeys_proved` with `key_fps`, so
  operators can see who learned the next key.
- The OpenSSH client exits when its session closes, without waiting for a
  pending proof; RSA proofs often lost that race in tests. Before an SFTP
  session sends `exit-status`, it waits up to one second for a proof in
  progress.

### Rotation

`gosftpd hostkey rotate` takes `--host-key P`, `--state-dir DIR` (like
`hostkey show`) or `--config FILE` (which needs `--host-key` when several
host keys are configured), and one step:

1. `rotate [--type T]` creates `P.next` (type: `P`'s by default) and
   `P.next.pub`. It refuses when `P.next` or `P.old` exists, and, with
   `--config`, a type that another host key has (retire a key type by
   removing that key from `host_keys` instead). The key is written to a
   temporary file and linked into place, so a reload never reads half a
   key, and gets the owner and group of `P` (as root); a user other than
   `P`'s owner is refused. It prints the fingerprint, `known_hosts` lines
   (`--known-hosts HOST:PORT`), the `ssh-keygen` command to certify it when
   `P-cert.pub` exists, and the next steps. A reload starts announcing it.
2. `rotate --finish`, after the transition period: `P.old` becomes a hard
   link to `P`, then `P.next` is renamed over `P`, an atomic replace, so
   `P` always exists; the same for the `.pub` and certificate files; then
   the directory is synced. A repeated `--finish` completes an interrupted
   one. It prints how long `P.next` has existed. A reload switches key
   exchange to the new key; the old one stays announced.
3. `rotate --retire` deletes `P.old` and its files. After a reload the old
   key is no longer announced, and OpenSSH clients remove it.

`rotate --rollback` (after `--finish`, before `--retire`) swaps back: the
new key becomes `P.next` again and `P.old` becomes `P`; clients keep both,
since both stay announced. `rotate --abort` deletes `P.next` and its files.
Until `--retire`, every step can be undone without a client noticing.

Every step decides by what the key files hold, never by which other files
exist, and can be run again after an interruption. The key files are
linked and renamed so that `P` always exists; a half-done `--finish` or
`--rollback` (one of `P.next`, `P.old` holding `P`'s key) is completed by
running it again, and `--retire` and `--abort` refuse to run in between.
Then every step puts each `.pub` file and certificate with the key it
belongs to (a certificate with the key it certifies) and removes those of
keys that are gone, so an interrupted step never leaves a certificate that
a later one takes for another key's. `--finish` refuses a next key of
another owner (as root it first gives it `P`'s owner, since gosftpd must
read it), of the type of another host key, or with a certificate the
server would refuse; `--rollback` only warns about a bad certificate, since
it is the way back.

**Several servers under one name.** A client takes the announcement as the
complete key set of the host name and removes every other key. Servers
behind one name must announce the same keys: create `P.next` once and copy
it (with `.pub`) to every server, check with `hostkey show` that all show
the same fingerprints, and start each step only when every server finished
the previous one.

**Compromised key.** UpdateHostKeys must not be relied on: whoever holds the
old key can impersonate the server and announce a key of their own. Run
`rotate`, `rotate --finish` and `rotate --retire` before one reload, so the
old key is never announced again; distribute the new fingerprint out of
band, and the old key as `@revoked` in `known_hosts` (or OpenSSH's
`RevokedHostKeys`).

### Reload

Host keys leave ADR 0005's restart-only list. A reload reads every key and
certificate file again; new connections use the result, open ones keep
theirs, also for re-keying. A reload never generates a key: generation
(`host_key_auto_generate`, zero-config) happens only at a start where `P`,
`P.next` and `P.old` are all missing, so an interrupted rotation is not
turned into a new random identity.

Revocation must not depend on host key files (ADR 0005). On reload:

- if a current key cannot be used (missing, unreadable, unsafe, two of one
  type), the running host keys stay, with their next and old keys and
  certificates, with a warning;
- a next or old key, or a certificate, that cannot be used is left out
  with a warning;
- the rest of the reload applies either way. At start and in `config
  validate --check-fs` these are errors.

The location is another matter: `CheckFS` adds `P.next` and `P.old`
(secrets) and the certificates (trusted files) to the mount checks, also on
reload, and a key file inside a mount fails the reload, as every trusted
file does (ADR 0005). When the running host keys stay, the check covers
them, not the files the new configuration names. A change of the host key set is
logged at info level with the fingerprints. With `--host-key`, a
`server.host_keys` in the file that differs is reported as having no effect.

### Host certificates

`server.host_certificates = true` serves `P-cert.pub` with `P` (built with
`ssh.NewCertSigner` over the SHA-2-only RSA signer, so `ssh-rsa-cert` is
never offered). A certificate must: be a host certificate, certify `P`'s
key, have at least one principal and no critical option, be signed with a
SHA-2 algorithm (OpenSSH refuses `ssh-rsa` CA signatures by default) by a CA
key of a supported type, and verify. `P.next-cert.pub` is checked against
`P.next` and served after `--finish`. A key without a certificate is a
warning.

A certificate is offered only while valid: each connection's configuration
takes the certificates valid at accept. It is built afresh per connection
from a base without host keys, never by `AddHostKey` on a copy of a shared
`ServerConfig` (the copy shares its key array: a data race, and a
connection's re-key could pick another connection's certificate). OpenSSH
falls back to the plain key when a certificate is missing or invalid; a
client that knows only the CA then fails either way. From
min(30 days, a third of the certificate's lifetime) before expiry, a warning
is logged at start, on reload and once a day; at expiry, an error. Renewal:
replace the file, then reload.

### Commands and output

`hostkey show` gains `--config` and shows, for each host key, its next and
old keys and certificates (principals, validity, CA fingerprint), from the
`.pub` files when the private key is not readable. The start banner shows
next and old keys and certificates. `user add --write` lists the next key
with its `known_hosts` line, so a partner set up during a transition is not
cut off at the cutover.

## Consequences

- OpenSSH updates `known_hosts` by default only from 8.5, and only with the
  default `UserKnownHostsFile` and without `VerifyHostKeyDNS` (otherwise
  with `UpdateHostKeys yes`), and skips the update when:
  `GlobalKnownHostsFile` or `KnownHostsCommand` matched the key; the host was verified by a
  certificate or has a `@cert-authority` or `@revoked` line, a wildcard or a
  long host list; an announced key is known under another name or address
  (a `known_hosts` line must use exactly the name and port clients connect
  with, `[host]:2022` for a non-default port); or `UpdateHostKeys ask`
  (always off for sftp). A connection open before the reload learns nothing
  until it reconnects. The transition period is as long as clients take to
  connect once; `conn.hostkeys_proved` shows which users' clients did.
- Clients without UpdateHostKeys (paramiko, PuTTY, WinSCP, FileZilla, Go
  programs, older OpenSSH) see the new key at the cutover. paramiko and the
  PuTTY family keep one key per type, so a same-type rotation cannot be
  pre-trusted there; changing the key type helps (they keep using the type
  they know until the cutover). WinSCP scripts can list both fingerprints.
  `rotate` prints them.
- Serving a host certificate breaks x/crypto clients that pin the plain key
  (rclone with `known_hosts_file`, `ssh.FixedHostKey`): x/crypto prefers
  certificate algorithms and does not fall back ("ssh: no authorities for
  hostname", "host key mismatch"). Such clients must list plain host key
  algorithms (rclone `host_key_algorithms`) or trust the CA. Hence opt-in.
- Host keys now change at a reload: configuration management that edits
  `host_keys` changes the server's identity at the next HUP.
- A rotation leaves a key of a new type in a file named after the old type;
  the name is only a name.
