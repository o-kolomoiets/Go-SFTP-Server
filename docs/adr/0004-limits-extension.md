# ADR 0004: `limits@openssh.com`

- **Status:** accepted, 2026-10-09
- **Context:** OpenSSH `sftp` (8.6 and newer) asks the server for
  `limits@openssh.com` and, when the server answers, sizes its reads and
  writes by the answer: up to 261 120 bytes against OpenSSH's own
  `sftp-server`. A server that does not offer the extension gets the
  client's default of 32 KiB per request. gosftpd uses `pkg/sftp` v1
  `RequestServer` (ADR 0003), which neither offers nor answers the
  extension, and `sftp.SetSFTPExtensions` refuses names outside its own
  list (`hardlink`, `posix-rename`, `statvfs`).

## Measurement

One run each, OpenSSH 10.6p1 `sftp` against gosftpd on loopback,
`aes128-gcm@openssh.com`, a 256 MiB file:

| Client options | Upload | Download |
|---|---|---|
| default (32 KiB, 64 requests) | 101 MiB/s | 78 MiB/s |
| `-B 261120 -R 64` | 81 MiB/s | 182 MiB/s |
| `-B 32768 -R 64` | 73 MiB/s | 89 MiB/s |

These numbers are indicative only (a shared machine, no repetitions); the
benchmarks of ROADMAP §8.6 (W1) will measure against OpenSSH's
`internal-sftp` properly. They suggest that larger requests matter for
downloads, which are the case the extension would change by default.

## Options

| Option | Notes |
|---|---|
| Upstream: a `pkg/sftp` v1 pull request that adds the extension to `RequestServer`, answering from its `maxTxPacket` and the packet limit | Fixes it for every user of the library; needs a review cycle and a release. |
| `pkg/sftp/v2` | Still alpha (ADR 0003). |
| Answer in gosftpd's connection wrapper (`internal/sftpd.Gate`): add the name to the server's VERSION packet, answer the request, and raise `WithRSMaxTxPacket` | Possible today, since the gate already parses the packet framing; but it is protocol code of our own on the pre-handler path, and it rewrites a packet that `pkg/sftp` produced. |
| Do nothing; document `sftp -B 261120 -R 64` | No code; only users who read the documentation benefit. |

## Decision

- v0.3 changes nothing in the protocol. Clients that need throughput can
  pass `-B 261120 -R 64` (OpenSSH) today: the server accepts write packets up
  to 256 KiB.
- Propose the extension upstream to `pkg/sftp` v1, together with a raised
  default for `WithRSMaxTxPacket`.
- Revisit with the benchmarks (M4/M5). If upstream has not shipped it by
  then and the numbers show a real gap to OpenSSH, implement the gate option
  with its own fuzz seeds, behind the same per-session handle and memory
  limits.

## Consequences

- OpenSSH `sftp` without options downloads in 32 KiB requests from gosftpd.
- Advertising the extension later is compatible: clients that do not ask
  for it are unaffected.
- A larger `maxTxPacket` raises the memory a session can hold in flight
  (one buffer per outstanding read); that bound has to be part of the
  decision.
