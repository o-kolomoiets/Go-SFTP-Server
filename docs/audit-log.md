# Audit log

gosftpd writes one JSON line per action, not per packet. Transfers are logged
when they end. The operational log (stderr) is separate.

```json
{"time":"2026-10-08T11:20:42Z","level":"INFO","msg":"audit","schema":1,"event":"fs.upload","conn_id":"4b1d0c9e2f7a8b36","remote_addr":"203.0.113.7:53122","local_addr":"192.0.2.10:2022","user":"partner","session_id":"9f3c2a17d0b4e6a1","path":"/inbox/report.pdf","final_path":"/inbox/report (1).pdf","conflict":"renamed","open_flags":"WRITE+CREAT+TRUNC","bytes":300000,"duration_ms":412,"result":"ok"}
```

Configure it in `[audit]` ([configuration.md](configuration.md#audit)):
`output` (stdout or a file), `events` (categories) and `on_error`.

## Stability

The `schema` field is the format version. Within schema 1 fields are only
added; renaming, removing or retyping a field means schema 2. The test
`TestAuditSchema` checks every line of a session that uses every operation
against [`internal/server/testdata/audit.schema.json`](../internal/server/testdata/audit.schema.json).

## Fields

Every line has `time`, `level`, `msg` (`"audit"`), `schema` and `event`, and,
once known, the context fields:

| Field | Meaning |
|---|---|
| `conn_id` | Random ID of the SSH connection (16 hex digits). |
| `remote_addr`, `local_addr` | Client and server address. |
| `user` | Authenticated user. |
| `session_id` | Random ID of the SFTP session within the connection. |

Paths are always virtual paths as the client sees them (`/inbox/report.pdf`),
never host paths. Strings from clients are JSON-escaped.

## Events

| Event | Category | Fields |
|---|---|---|
| `server.start` | server | `version`, `listen` |
| `server.reload` | server | `result` (`ok` or `error`), `duration_ms`; on error `reason`: `config` (the configuration cannot be read or is invalid), `mounts` or `audit_output` (the new `audit.output` cannot be opened); on success `restart_required` (comma-separated keys that changed but apply only at restart) and `disconnected` (connections closed by `reload.disconnect_removed_users`). The error itself goes to the operational log, since it can name host paths |
| `server.stop` | server | |
| `server.audit_recovered` | server | written when the log works again after a failure |
| `conn.reject` | conn | `reason`: `banned`, `max_connections`, `max_connections_per_ip` or `max_preauth_connections`; `suppressed` (see below) |
| `conn.accept` | conn | `client_version` (after the client sent its version line) |
| `conn.close` | conn | `duration_ms`, `result` (`ok`, `error`, `idle_timeout`, `keepalive_timeout`, `revoked`: a reload refused the login, or closed the connection with `reload.disconnect_removed_users`) |
| `conn.hostkeys_proved` | conn | `key_fps` (comma-separated SHA256 fingerprints): the client asked the server to prove that it holds these host keys, which it did not know, and it now adds them to `known_hosts` (OpenSSH `UpdateHostKeys`; see [Host keys](configuration.md#host-keys)). During a rotation, it shows which users' clients learned the next key |
| `auth.success` | auth | `auth_method` (`publickey` or `password`), `key_fp` (SHA256 fingerprint, public keys only; for a certificate, of the certified key, as `ssh-keygen -lf` prints it for the user's key), `failed_attempts`; for a certificate also `cert_key_id` (its key ID, `ssh-keygen -I`, at most 256 bytes), `cert_serial` (a decimal string: serials are 64-bit, more than many JSON parsers keep exactly, above 2^53) and `cert_ca_fp` (the SHA256 fingerprint of its CA) |
| `auth.failure` | auth | `attempts`, `user` (the last name tried); `reason` when the login was refused although the key offered is one of the user's, or a certificate a trusted CA signed for the user, or the password is right: `disabled`, `expired`, `address` (`allow_from`, a `cert-authority` line's `from=` or the certificate's `source-address`), `key_expired` (`expiry-time=` of the key or `cert-authority` line), `key_revoked` (the key, the certified key or the CA is in the revocation list), `cert_principal` (no principal of the certificate may log in as the user), `cert_not_yet_valid`, `cert_expired`, `cert_invalid` (a SHA-1 CA signature, an unsupported critical option or `force-command`, an empty principal; the operational log says which) or `removed` (a reload removed or changed the user, the key, the CA or the password during the login). With a reason, also `key_fp` for a key or certificate login, and the `cert_*` fields for a certificate. For a key, the client may only have offered it without proving that it holds it: public keys and certificates are often public. Written when a connection ends without login. The client is never told the reason |
| `auth.ban` | auth | `source` (IPv4 address or IPv6 /64), `duration_ms` |
| `session.start` | session | |
| `session.end` | session | `duration_ms`, `exit_status` |
| `fs.upload` | transfer | `path` (requested), `final_path`, `conflict` (`none`, `renamed`, `overwritten`, `versioned`), `version_path` (where the replaced file was kept, with `versioned`), `open_flags`, `bytes`, `start_offset` (resumed uploads), `duration_ms`, `result` |
| `fs.download` | transfer | `path`, `bytes`, `duration_ms`, `result` |
| `fs.rename` | modify | `path`, `target_path`, `final_path`, `conflict` (posix-rename: `none`, `renamed`, `overwritten`, `versioned`), `version_path` (with `versioned`), `result` |
| `fs.mkdir`, `fs.rmdir`, `fs.remove`, `fs.setstat` | modify | `path`, `result` |
| `fs.denied` | denied | `reason`, `result`, and `op` and `path`, or `mount` for an unavailable home |
| `fs.list` | list (opt-in) | `path`, `result` |
| `fs.stat` | stat (opt-in) | `path`, `result` |

`result` is `ok`, `denied`, `error` or `aborted` (the connection ended during
the transfer; an empty file the upload created is removed). An upload with a
refused write (append-only guard, `max_file_size`) ends with `denied`, and so
does an upload through a temporary file that the conflict policy refuses when
it is closed (see [Atomic uploads](configuration.md#atomic-uploads)); its
temporary file is removed.

Connections that close before sending an SSH version line (health checks,
port scanners) are not audited. Refused connections (`conn.reject`) are
logged at most 10 per second; the next `conn.reject` written reports how
many were left out in `suppressed`.

## When the log cannot be written

With `on_error = "fail-closed"` (default), a write error (disk full, closed
pipe) makes gosftpd refuse new connections and every changing operation until
a probe write succeeds; it tries every 5 seconds and then writes
`server.audit_recovered`. Transfers already running finish, and their events
go to stderr. With `on_error = "fail-open"` gosftpd keeps serving and writes
every event that could not be stored to stderr.

## Rotation

There is no built-in rotation. Use journald or Docker logging with
`output = "stdout"`, or logrotate for a file. SIGHUP reopens the file before
anything else in a reload, whether the reload succeeds or not, and then
writes `server.reload` into the new file:

```
/var/log/gosftpd/audit.jsonl {
    daily
    rotate 30
    compress
    delaycompress
    create 0600 gosftpd gosftpd
    postrotate
        systemctl reload gosftpd
    endscript
}
```

If the file cannot be opened again (for example because logrotate created it
with the wrong owner), gosftpd closes the rotated file and every write fails
until the file can be opened: with `on_error = "fail-closed"` it refuses
connections and changes, and the events go to stderr. It retries every 5
seconds and recovers on its own. `copytruncate` works too: the file is opened
with `O_APPEND`, so truncating it leaves no hole.
