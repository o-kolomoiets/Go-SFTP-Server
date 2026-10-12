# Client compatibility

`test/interop/run.sh` runs real clients against a fresh build in CI on every
change. Tested:

| Client | Version | What is checked |
|---|---|---|
| OpenSSH `sftp`, `scp` | 9.6p1 (Ubuntu 24.04), 10.6p1 (built from source) | put, get, `put -p`, mkdir, rename, rm, rmdir, `reput`, `df -h`, `ls -l`; scp both ways; password login; `on_conflict = "version"`; `kill -9` of the client during an atomic upload; user certificates from `ssh-keygen -s` (trusted CA, `force-command=internal-sftp`, another principal refused, revoked after a reload, a KRL refused); host key rotation with `UpdateHostKeys` (the next key learned before `--finish`, the previous key forgotten after `--retire`; RSA with `HostKeyAlgorithms=rsa-sha2-256` and a one-command session); a host certificate with `@cert-authority`; refused: symlink escape, `ln`, `ln -s`, shell and exec |
| paramiko | 5.0.0 | `put(confirm=True)` over an existing file, append mode, refused overwrite of existing bytes, owners in listings, read-only and upload-only users, password login, user name change within a connection refused; the plain host key while a host certificate is served |
| rclone | v1.75.0 | `copy` into an upload-only mount, `copy` of a changed file with full access, `about`, `sync` five times into a `version` mount; with a host certificate served, `known_hosts_file` with the plain key fails and `host_key_algorithms` fixes it |
| lftp | 4.9.2 | put, get, listing |
| promtool | 3.5.0 | `promtool check metrics` on the `/metrics` output of a server that served the clients above |
| HAProxy | 2.8.16 (Ubuntu 24.04) | As a load balancer that sends PROXY protocol headers ([below](#load-balancers)): OpenSSH `sftp`, paramiko and rclone through `send-proxy` (v1), `send-proxy-v2`, `send-proxy-v2` with TLVs (`unique-id`, `ssl`, `crc32c`) and Unix socket front ends (`UNKNOWN`, `LOCAL`), with `remote_addr`, `local_addr` and `proxy_addr` checked in the audit log; health checks (with a v1 or `LOCAL` header, one that waits for the banner, a bare connect) pass and leave no audit event; a proxy that is not trusted, and a trusted one without `send-proxy`, are refused |
| nginx | 1.24.0 (Ubuntu 24.04) | The stream module with `proxy_protocol on` (v1): OpenSSH `sftp`, paramiko and rclone, with the audit fields checked |

The same run sends v1 and v2 headers straight to gosftpd from an address it
does not trust (refused after the banner, `untrusted_proxy`), and runs
`gosftpd healthcheck` from a trusted loopback address (it sends a `LOCAL`
header) and from one that is not trusted.

WinSCP, FileZilla and Cyberduck are not tested automatically yet; WinSCP has
a manual checklist below.

## Notes per client

### OpenSSH

- Key exchange is `mlkem768x25519-sha256` with OpenSSH 9.9 and newer, and
  `curve25519-sha256` otherwise. There is no SHA-1, CBC or DSA.
- `scp` uses the SFTP protocol (OpenSSH 9.0 and newer, or `scp -s`); legacy
  SCP (`scp -O`) is not supported.
- `reput` continues an interrupted upload; the part already on the server is
  never rewritten.
- `ls -l` shows the logged-in user as owner and group of every file.

### rclone

Use `--sftp-shell-type none` (or `shell_type = none` in the remote): gosftpd
runs no commands, so rclone cannot compute remote hashes and checks sizes and
times instead.

```sh
rclone copy ./reports :sftp,host=sftp.example.org,port=2022,user=partner,key_file=~/.ssh/id_ed25519,shell_type=none:
```

rclone uploads to a temporary `NAME.XXXX.partial` and then moves it into
place, over several connections; the `upload` permission covers this. Each
transfer and checker is a connection: keep `limits.max_connections_per_ip`
above `--transfers` plus `--checkers` (4 + 8 by default). With
`on_conflict = "rename"` a changed file becomes a copy (`a (1).txt`) and the
original stays; `rclone sync` and repeated `copy` runs therefore add a copy
each time the content differs. For folders that are synced, use
`on_conflict = "version"`: the file keeps its name and the previous content
goes to `.versions`, which `rclone sync` does not see and so does not try to
delete. Use `--inplace` to upload directly to the final name.

With `server.host_certificates = true`, rclone (like other Go programs)
prefers the certificate and fails with "ssh: no authorities for hostname"
when `known_hosts_file` holds only the plain host key. Add
`host_key_algorithms = ssh-ed25519` (the type of the key it knows), or a
`@cert-authority` line for the CA.

### paramiko

`SFTPClient.put(..., confirm=True)` checks the size of the uploaded file by
name; with the rename policy the check is answered for the copy
(`stat_redirect`), so it passes. `open(name, "a")` resumes a file.

paramiko keeps one host key per type and host, and does not learn new keys
from the server. During a host key rotation, it sees the new key at
`rotate --finish`; replace its `known_hosts` line then, or rotate to another
key type ([Rotation](configuration.md#rotation)).

### WinSCP

WinSCP uploads files larger than 100 KiB to a temporary `NAME.filepart` and
renames it; the `upload` permission covers that. If you prefer direct
uploads, disable "Transfer to temporary filename" in the transfer settings.

WinSCP is not tested automatically yet (planned with the Windows track).
Before a release, check it by hand: gosftpd on Linux, WinSCP 6.x on Windows
with default settings, SFTP protocol, a user with the `upload` preset on
mount `inbox` and one with `full` on mount `files`.

| # | Step | Expected |
|---|---|---|
| 1 | First connection | The host key fingerprint WinSCP shows matches the one gosftpd printed at start. |
| 2 | Upload a 50 KiB file as `upload` | It appears under its name, without a `.filepart` (direct upload). |
| 3 | Upload a 5 MiB file as `upload` | WinSCP uses `.filepart` and renames it; no error, the file is complete, its time is the local one. |
| 4 | Upload the same 5 MiB file again (`rename`) | WinSCP asks to overwrite; on "Yes" the upload succeeds and lands as `file (1).ext`; the original is unchanged. |
| 5 | Delete, rename, download as `upload` | Refused with "Permission denied"; the session stays usable. |
| 6 | Upload into `files` with `on_conflict = "version"` as `full`, twice | The name keeps the new content; the old one is under `.versions/`, readable by typing the path. |
| 7 | Cancel a 1 GiB upload halfway, with `atomic_uploads = true` | No file under the final name. WinSCP's Cancel closes the file normally, so gosftpd cannot tell it from a finished upload: a `.filepart` with the part sent may remain, with `result = "ok"`; a `fs.upload` hook that excludes `*.filepart` does not fire. |
| 8 | Disconnect and reconnect during a large upload with `resume = "append-only"` | WinSCP offers to resume; the result is identical to the source. |
| 9 | Synchronize a local folder to `files` (Commands → Synchronize) | Runs without errors; a second run finds nothing to do. |
| 10 | Check the audit log | Every step is there with `user`, `path` and `final_path`. |

### Load balancers

gosftpd reads the PROXY protocol header of the load balancers listed in
`server.trusted_proxies` and refuses headers from anyone else; see
[Behind a load balancer](configuration.md#behind-a-load-balancer).

- **HAProxy**: add `send-proxy-v2` (or `send-proxy` for v1) to the `server`
  line. Its default health check (`check`) sends a header too, `LOCAL` for
  v2 and a v1 line with HAProxy's own addresses for v1, and passes. A check
  that waits for the banner (`option tcp-check` with `tcp-check expect
  rstring ^SSH-2\.0-`) passes as long as HAProxy opens its connection
  itself; with `check port N` add `check-send-proxy`. An explicit
  `tcp-check connect` sends no header, so such a check times out: write
  `tcp-check connect send-proxy`. A check that only connects passes without
  a header, and gosftpd counts it as `no_version`.
- **HAProxy with a Unix socket front end**: its clients have no TCP address,
  so HAProxy sends `UNKNOWN` (v1) or `LOCAL` (v2), and gosftpd sees them as
  the proxy's own connections, with the proxy's address. If the hop before
  the socket knows the client, pass it on with PROXY protocol as well
  (`accept-proxy` on the `bind` line).
- **nginx**: the stream module (on Debian and Ubuntu the package
  `libnginx-mod-stream`) with `proxy_protocol on;` in the `server` block. It
  sends v1 only; gosftpd accepts both versions.

### Clients that append at offset 0

A client that opens a file with APPEND but writes at offset 0 (the Go
`pkg/sftp` client with `os.O_APPEND`) gets "existing data is immutable":
gosftpd serves writes in parallel and uses the offsets the client sends, so it
cannot move such writes to the end of the file.
