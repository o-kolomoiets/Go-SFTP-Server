# ADR 0003: SFTP library

- **Status:** accepted, 2026-10-07
- **Context:** gosftpd needs an SFTP v3 server implementation that lets it
  confine every file operation to a mount, and that works with real clients
  (OpenSSH sftp/scp, WinSCP, rclone, paramiko).

## Options

| Option | Notes |
|---|---|
| `github.com/pkg/sftp` v1 `NewServer` | Serves the host filesystem directly; with `WithServerWorkingDirectory` a client can still `get /etc/hostname`. Not a jail. |
| `github.com/pkg/sftp` v1 `RequestServer` (v1.13.11) | Calls our handlers (`FileReader`, `FileWriter`, `FileCmder`, `FileLister` and optional extensions) for every request, so the filesystem is ours to confine. Stable, widely used. |
| `github.com/pkg/sftp/v2` | Still alpha; its `localfs` is documented as not safe to expose. |
| Own SFTP packet layer | Months of protocol work and a large attack surface for a single maintainer. |

## Decision

Use `pkg/sftp` v1 `RequestServer`, isolated behind `internal/sftpd`: no other
package imports `pkg/sftp`. All file access goes through `internal/vfs`,
which uses one `os.Root` per mount.

## Consequences and pitfalls (pinned by tests)

- `FSTAT`/`FSETSTAT` reach the handlers as `Stat`/`Setstat` on the request's
  `Filepath`. When an upload is redirected to `name (1).ext`, `Filewrite`
  rewrites `r.Filepath`, so `put -p` and scp's truncation hit the copy. This
  relies on undocumented behaviour and is covered by an integration test.
- `sftp.SetSFTPExtensions` mutates a package global; it is called once
  (`sync.Once`) before the first request server, advertising only
  `posix-rename@openssh.com`.
- `pkg/sftp` sends `err.Error()` to clients; handlers return a status type
  with a fixed message that wraps an `sftp.ErrSSHFx*` code, so host paths
  never reach clients.
- The request server has no handle limit; `internal/sftpd` enforces 64 per
  session.
- The server must send `exit-status` before closing the channel, or OpenSSH
  scp reports failure.
- Revisit when `pkg/sftp/v2` ships a non-alpha release: only `internal/sftpd`
  would change.
