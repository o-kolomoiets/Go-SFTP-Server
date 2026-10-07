# ADR 0002: Non-goals before 1.0

- **Status:** accepted, 2026-10-07
- **Context:** the biggest risk for a small, single-maintainer SFTP server is
  scope creep into "another SFTPGo". Issues that ask for these features are
  closed with a link to this document.

| Not doing                                                       | Why                                                                                                   | Use instead                              |
|-----------------------------------------------------------------|-------------------------------------------------------------------------------------------------------|------------------------------------------|
| Web UI, share links, admin REST API with RBAC                   | The main attack surface of file-transfer products (CrushFTP, GoAnywhere, MOVEit, SFTPGo web CVEs)     | SFTPGo                                   |
| FTP/FTPS, WebDAV, HTTP                                          | Outside the niche                                                                                     | SFTPGo, copyparty                        |
| S3, GCS, Azure backends                                         | SFTP random-offset writes map poorly to object stores; one maintainer. The VFS interface stays open   | `rclone serve sftp`, SFTPGo              |
| Shell, exec, port/agent forwarding, legacy SCP (`scp -O`), rsync, git | Extra attack surface; OpenSSH ≥ 9.0 runs `scp` over SFTP by default                             | OpenSSH                                  |
| Client-created symlinks and hard links                          | Breaks confinement                                                                                    | —                                        |
| Encryption at rest, retention of incoming files                 | Belongs to the volume/filesystem and to a scheduler; recipes will be documented                       | LUKS, ZFS encryption, fscrypt, systemd-tmpfiles, hooks |
| LDAP, OIDC, MFA in 1.x                                          | Complexity; SSH certificates cover the corporate case                                                 | SSH CA                                   |
| Database, HA, clustering                                        | Contradicts "one binary"                                                                              | —                                        |
