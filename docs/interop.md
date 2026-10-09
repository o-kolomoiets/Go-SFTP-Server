# Client compatibility

`test/interop/run.sh` runs real clients against a fresh build in CI on every
change. Tested:

| Client | Version | What is checked |
|---|---|---|
| OpenSSH `sftp`, `scp` | 9.6p1 (Ubuntu 24.04), 10.6p1 (built from source) | put, get, `put -p`, mkdir, rename, rm, rmdir, `reput`, `df -h`, `ls -l`; scp both ways; password login; refused: symlink escape, `ln`, `ln -s`, shell and exec |
| paramiko | 5.0.0 | `put(confirm=True)` over an existing file, append mode, refused overwrite of existing bytes, owners in listings, read-only and upload-only users, password login, user name change within a connection refused |
| rclone | v1.75.0 | `copy` into an upload-only mount, `copy` of a changed file with full access, `about` |
| lftp | 4.9.2 | put, get, listing |

WinSCP, FileZilla and Cyberduck are not tested automatically yet.

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
each time the content differs. Use `--inplace` to upload directly to the
final name.

### paramiko

`SFTPClient.put(..., confirm=True)` checks the size of the uploaded file by
name; with the rename policy the check is answered for the copy
(`stat_redirect`), so it passes. `open(name, "a")` resumes a file.

### WinSCP

WinSCP uploads files larger than 100 KiB to a temporary `NAME.filepart` and
renames it; the `upload` permission covers that. If you prefer direct
uploads, disable "Transfer to temporary filename" in the transfer settings.

### Clients that append at offset 0

A client that opens a file with APPEND but writes at offset 0 (the Go
`pkg/sftp` client with `os.O_APPEND`) gets "existing data is immutable":
gosftpd serves writes in parallel and uses the offsets the client sends, so it
cannot move such writes to the end of the file.
