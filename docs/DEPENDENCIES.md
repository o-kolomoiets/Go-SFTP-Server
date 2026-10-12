# Dependencies

Principle: at most 10 direct runtime dependencies, including `golang.org/x/*`.
A new dependency requires removing another one or revisiting this rule.

## Runtime

| Module                           | Version  | Purpose                                  | Since |
|----------------------------------|----------|------------------------------------------|-------|
| `github.com/spf13/cobra`         | v1.10.2  | CLI                                      | M0    |
| `golang.org/x/crypto`            | v0.57.0  | `ssh`; later `argon2`, `bcrypt`          | M1    |
| `github.com/pkg/sftp`            | v1.13.11 | SFTP `RequestServer`                     | M1    |
| `golang.org/x/sys`               | v0.48.0  | `unix.Renameat2` (atomic no-replace rename); later `unix.Fstatfs` | M1    |
| `github.com/BurntSushi/toml`     | v1.6.0   | configuration                            | M2    |
| `golang.org/x/term`              | v0.46.0  | password input without echo              | M3    |
| `github.com/pires/go-proxyproto` | v0.15.0  | PROXY protocol v1 and v2 header parser (Apache-2.0) | M4    |

Planned later (see ROADMAP.md §4.5): `go-landlock` (M4);
`golang.org/x/time` for bandwidth limits, if they come.
Metrics need no library: gosftpd writes the Prometheus text format itself
(decision D12, ADR 0009).

### Why `golang.org/x/crypto` is a direct dependency

`github.com/pkg/sftp` v1.13.11 requires x/crypto v0.54.0, which is affected by
GO-2026-6303, GO-2026-6354 and GO-2026-6355 (fixed in v0.55.0 and v0.56.0).
gosftpd therefore requires x/crypto ≥ v0.56.0 itself, as a direct (not
`// indirect`) requirement, and Dependabot keeps it current.

### Why `go-proxyproto` is used only as a parser

`server.trusted_proxies` ([ADR 0011](adr/0011-proxy-systemd-landlock.md))
needs a parser for PROXY protocol headers, v1 and v2. gosftpd calls only
`proxyproto.Read` and the header types; it reads the header itself in the
connection's goroutine and wraps the connection itself. The library's
`Listener` and `Conn` read the header lazily, on the first `RemoteAddr`,
`Read` or `Write`: in gosftpd's accept loop one silent proxy would delay
every other connection, the banner would wait for the header, and a
deadline set on the connection would be cleared. Versions before v0.15.0
return a nil address for undefined v2 address families (a panic a remote
peer can trigger), so go.mod requires v0.15.0.

The module requires `golang.org/x/net`, but only its `helper/http2`
package imports it, so x/net is not in gosftpd's build (`go version -m`).
The library's own code is about 9 KB of the binary; the PROXY protocol
support as a whole added 72 KiB (73 728 bytes, linux/amd64,
`CGO_ENABLED=0`, `-trimpath -ldflags='-s -w'`, Go 1.26.5).

## Test-only

| Module               | Version | Purpose               | Since |
|----------------------|---------|-----------------------|-------|
| `go.uber.org/goleak` | v1.3.0  | goroutine leak checks | M1    |

## Developer tools (`tools/go.mod`)

govulncheck v1.8.0, staticcheck v0.8.1, gotestsum v1.13.0, actionlint v1.7.12.
golangci-lint v2.14.0 is installed as a binary (CI uses
`golangci/golangci-lint-action`).
