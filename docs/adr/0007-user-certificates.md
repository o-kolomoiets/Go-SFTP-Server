# ADR 0007: SSH user certificates and revoked keys

- **Status:** proposed, 2026-10-10
- **Context:** ROADMAP M4 (M4-04) asks for OpenSSH user certificates: a
  certificate authority (CA) signs users' keys, and the server trusts the CA
  instead of every key. Until v0.4 a `cert-authority` line in
  `authorized_keys` is rejected. x/crypto offers `ssh.CertChecker`, but its
  defaults do not match OpenSSH where it matters: `CheckCert` accepts a
  certificate without principals for every user, accepts CA signatures made
  with SHA-1 (`ssh-rsa`), and checks only one principal name. Revocation
  needs a list the server can re-read on reload.

## Decision

**Where trust comes from.** Two sources, as in OpenSSH:

1. `auth.trusted_user_ca_keys = "FILE"`: CA public keys, one per line (`#`
   comments, no options). A certificate signed by one of them logs in as a
   configured user whose name is one of its principals.
2. A `cert-authority` line in a user's `authorized_keys` (inline,
   `authorized_keys_file`, or `--authorized-keys` in zero-config mode),
   optionally with `principals="a,b"`, `from=`, `expiry-time=` and
   `no-touch-required`. Without `principals=`, a principal must equal the
   login name; with it, a principal of the certificate must be in the list
   (so `principals="alice@corp"` lets that certificate log in as `alice`).
   In zero-config mode without `--user`, where any login name is accepted,
   the login name must also be one of the certificate's principals, so a
   certificate cannot pick an arbitrary name.

Both may apply to one user; a login is accepted if either accepts it. The
options of a `cert-authority` line apply only to logins it accepts. A plain
key line never accepts a certificate, even of the same key.

**What a certificate must satisfy** (checked when the client offers it,
again after it signs, and again after the handshake; see ADR 0005):

- type user certificate; at least one principal (x/crypto treats none as
  "every principal");
- signed by a trusted CA, with a signature that verifies and is not
  `ssh-rsa` (SHA-1); CA keys and certified keys pass the same key checks as
  `authorized_keys` (no DSA, RSA ≥ 2048 bits);
- valid now (`valid_after ≤ now < valid_before`);
- critical options: only `source-address` (enforced, together with the
  line's `from=`); `force-command`, `verify-required` and unknown ones
  refuse the certificate. Extensions are ignored, except `no-touch-required`,
  which x/crypto honors for security-key certificates as OpenSSH does;
- neither the certificate, its key nor its CA is revoked;
- the account rules as for keys: not disabled or expired, `allow_from`, and
  the line's `expiry-time`.

**Revocation.** `auth.revoked_keys = "FILE"`: public keys or certificates,
one per line. It applies to every public-key login: a plain key in it is
refused, and so is a certificate whose key, CA or itself is in it. KRL
(binary revocation lists with serial ranges) is not supported yet (ROADMAP
§5 backlog); a certificate is revoked by listing it or its key.

**Failure reasons.** As for keys (`RefusedError`), a reason is recorded
only when the certificate is the user's: trusted for that user, with a
matching principal and a CA signature that verifies. New reasons:
`revoked`, `cert_expired`, `cert_not_yet_valid` and `cert_option`. A
certificate that is not the user's fails like a wrong key, without a
reason. The client is told nothing more in any case, and the check is the
same when the client only asks whether a key would be accepted, so the
query reveals nothing.

**Identity and audit.** The login records the certificate in the
connection's `Permissions` (ADR 0005's recheck parses it back). `auth.success`
gets `key_fp` (the fingerprint of the certified key, the one
`ssh-keygen -lf` prints for the user's key), `cert_key_id`, `cert_serial`
and `cert_ca_fp`.

**Files and reload.** Both files are trusted files (owner and mode checks;
not inside a mount clients can write, CheckFS). At start a missing or
unreadable file is an error. On reload:

- a missing, unsafe or empty `trusted_user_ca_keys` trusts no CA, with a
  warning (deleting the file revokes the CA, as for `authorized_keys`);
- a `revoked_keys` file that cannot be read keeps the list read before,
  with a warning: failing the reload would block unrelated revocations,
  and an empty list would un-revoke keys.

`disconnect_removed_users` closes connections whose certificate is now
revoked, expired, or no longer trusted for the user.

**Validation.** `config validate` warns when `trusted_user_ca_keys` is set
but `publickey` is not in `auth.methods`, and when a trusted CA is also
revoked. A user without keys or password can log in when
`trusted_user_ca_keys` is set, so it no longer gets the "cannot log in"
warning, and `user add --write` accepts it.

## Consequences

- Revoking one certificate of a key that has several needs the certificate
  itself in `revoked_keys`; listing the key revokes all of them.
- A CA trusted in `trusted_user_ca_keys` grants every configured user whose
  name it signs; restrict a CA to some users with `cert-authority` lines
  instead.
- Host certificates and host key rotation are a separate decision (M4-05).
