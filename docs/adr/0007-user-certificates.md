# ADR 0007: SSH user certificates and revoked keys

- **Status:** accepted, 2026-10-10
- **Context:** ROADMAP M4 (M4-04) asks for OpenSSH user certificates: a
  certificate authority (CA) signs users' keys, and the server trusts the CA
  instead of every key. Until v0.4 a `cert-authority` line in
  `authorized_keys` is rejected. x/crypto offers `ssh.CertChecker`, but it
  does not fit: `CheckCert` accepts a certificate without principals for
  every user, accepts CA signatures made with SHA-1 (`ssh-rsa`), checks one
  principal name, verifies the signature last (so its errors say nothing
  about a forged certificate), and `Authenticate` returns the certificate's
  own option maps as the login's `Permissions`. x/crypto also waives the
  security-key touch when either the login's `Permissions` or the
  certificate carries `no-touch-required`, where OpenSSH requires both for
  a `cert-authority` line. Three adversarial reviews of a first draft
  (security, OpenSSH compatibility, integration) shaped the decisions
  below; most of them follow sshd(8).

## Decision

### Trust

Two sources, as in sshd:

1. **Trusted CAs** for every configured user: `auth.trusted_user_ca_keys`
   (inline lines) and `auth.trusted_user_ca_keys_file` (a file of lines),
   like `authorized_keys` and `authorized_keys_file`. A line is a bare
   public key; options, markers and certificates are skipped with a
   `file:line` warning. A certificate from such a CA logs in as user `NAME`
   when one of its principals is in `users.NAME.principals`, which defaults
   to `["NAME"]` (sshd's `AuthorizedPrincipalsFile`). `principals = []`
   keeps the user away from these CAs; `principals = ["alice@corp"]` maps a
   corporate principal to the account.
2. **`cert-authority` lines** in a user's `authorized_keys`, inline, in
   `authorized_keys_file`, or in `--authorized-keys` in zero-config mode,
   with optional `principals="a,b"`, `from=`, `expiry-time=` and
   `no-touch-required`. Without `principals=`, a principal must equal the
   login name; with it, a principal must be in the list. An empty
   `principals=` or an empty entry, and `principals=` without
   `cert-authority`, skip the line with a warning.

A plain key line never accepts a certificate, and a `cert-authority` line
never accepts its CA key as a plain key: the lines are kept apart, and
every `cert-authority` line of a user is tried in order. A login is
accepted if any source accepts it, with that source's restrictions.

**Zero-config mode.** With `--user NAME` the rules above apply to `NAME`.
Without it any login name is accepted, so a `cert-authority` line without
`principals=` is skipped with a warning: the user's own
`~/.ssh/authorized_keys` often trusts a company CA, and that must not let
every colleague in. With `principals=`, the login name must be one of the
line's principals and one of the certificate's. Zero-config has no
revocation list; remove the key or the CA line instead.

### Checks

A certificate is checked in this order, when the client offers it and
again when it has signed and after the handshake (ADR 0005). Steps 1 and 2
give no reason, as a wrong key; later steps record one.

1. It is a user certificate; its CA is trusted for the user by some source;
   the CA key and the certified key pass the `authorized_keys` key checks
   (no DSA, RSA ≥ 2048 bits).
2. The CA signature verifies. gosftpd verifies it before it looks up the
   user, for any certificate whose CA is trusted anywhere, so a user that
   does not exist costs the same work, and keeps a bounded cache of
   verified certificates so that alternating queries cannot make it verify
   again and again. The signature is checked with `CheckCert`, with its
   other checks neutralized, so that x/crypto's handling of security-key
   CAs applies.
3. `key_revoked`: the certified key or the CA is in the revocation list.
4. `disabled`, `expired`: the account.
5. `cert_invalid`: the CA signed with `ssh-rsa` (SHA-1); a critical option
   other than `source-address`, and `force-command` other than an SFTP
   server (`internal-sftp`, or a path ending in `sftp-server`, without
   arguments: gosftpd serves only SFTP); an empty principal. The
   operational log says which.
6. `cert_not_yet_valid`, `cert_expired`: `valid_after ≤ now < valid_before`
   fails.
7. `address`: `allow_from`, or the certificate's `source-address`.
8. Per source, in order: `cert_principal` (no principal allowed for this
   login; also no principals at all, which x/crypto would take as "every
   principal"); `address` (the line's `from=`); `cert_invalid` (a
   security-key certificate with `no-touch-required` under a line without
   it); `key_expired` (the line's `expiry-time`). The first source that
   passes accepts the login; if none does, the reason is that of the
   source that got furthest, the first on a tie.

**Permissions** are built afresh, never copied from the certificate: user,
method, `pubkey-fp` of the certified key, the certificate blob, and the
certificate's `source-address` as a critical option, which x/crypto
enforces, also on queries. `no-touch-required` is never put into them for
a certificate: x/crypto honors the certificate's extension, which is the
rule for trusted CAs, and step 8 refuses it where a line does not allow
it, so the effective rule is sshd's (both must allow it).

**Plain keys** gain `key_revoked` (step 3 before the account checks).
`command="internal-sftp"` (and an `sftp-server` path) is accepted on a key
line, as `force-command` is in a certificate.

### Revocation

`auth.revoked_keys` (inline lines) and `auth.revoked_keys_file`: public keys
or certificates, one per line, with or without `authorized_keys` options,
any key type. As in sshd, an entry revokes a key: a certificate entry
revokes its certified key, so every certificate of that key and the key
itself; a login is refused when its key, its certified key or its CA is
listed. Keys are compared by their parsed form, so re-encoding a signature
does not escape. Revoking one certificate of a key, by serial or key ID,
needs a KRL, which is not supported yet: a file that starts with the KRL
magic is an error.

The list fails closed. Any line that is not a key or certificate is an
error. At start a missing, unreadable, unsafe (owner, mode) or invalid
file refuses the configuration. On reload it fails the reload: the running
configuration, with its list, stays, and `server.reload` says `error`. sshd
refuses every public-key login instead; failing the reload keeps the
server usable and is as visible.

### Reload

Both files are trusted files (CheckFS: owner and mode, not inside a mount
clients can write) and are read only when `publickey` is enabled. Relative
paths are relative to the file that sets them. On reload:

- the CA file, if missing, unsafe or without usable keys, trusts no CA,
  with a warning, as a deleted `authorized_keys_file` revokes its keys;
- the revocation file must be valid (above);
- edits take effect only on reload; open connections stay unless
  `reload.disconnect_removed_users` is on.

`disconnect_removed_users` closes connections whose certificate is now
revoked, no longer trusted for the user, or whose principal or line no
longer allows the login. It does not close a connection because its
certificate's validity period has passed since: certificates often last
minutes or hours, and sshd checks validity only at login.

### Audit

`auth.success` for a certificate: `key_fp` is the certified key's
fingerprint (what `ssh-keygen -lf` prints for the user's key), plus
`cert_key_id` (at most 256 bytes), `cert_serial` (a decimal string: CAs use
random 64-bit serials, which JSON numbers do not keep) and `cert_ca_fp`.
`auth.failure` with a reason for a certificate carries the same fields, and
`key_fp` for a refused plain key. The reason `key_revoked` is distinct from
`conn.close` `result = "revoked"`.

### Validation and commands

`config validate` warns when certificate settings are set but `publickey`
is not enabled and when `users.NAME.principals` is set without trusted CAs;
an inline `authorized_keys` entry that holds a certificate is an error
("trust its CA instead"), and a file line is skipped with that warning.
Reading the files, `config validate --check-fs`, `serve` and a reload also
warn when a trusted CA, a user's CA or a user's key is revoked, and when a
`cert-authority` CA is also trusted for every user (its line then restricts
nothing). A user
without keys or password can log in by certificate when trusted CAs are set
and its principals are not empty, so it gets no "cannot log in" warning;
`user add --write` accepts such a user and prints the principal to sign.

## Consequences

- Revoking a certificate revokes its key; per-certificate revocation waits
  for KRL support.
- A trusted CA grants every configured user whose principals it signs;
  restrict a CA with `principals` or with `cert-authority` lines.
- Certificates without principals are refused, also through
  `cert-authority` lines, where sshd accepts them.
- Host certificates and host key rotation are a separate decision
  ([ADR 0008](0008-host-key-rotation.md)).
