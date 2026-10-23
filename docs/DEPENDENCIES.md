# Dependencies

Principle: at most 10 direct runtime dependencies, including `golang.org/x/*`.
A new dependency requires removing another one or revisiting this rule.

## Runtime

| Module                           | Version  | Purpose                                  | Since |
|----------------------------------|----------|------------------------------------------|-------|
| `github.com/spf13/cobra`         | v1.10.2  | CLI                                      | M0    |
| `golang.org/x/crypto`            | v0.58.0  | `ssh`; later `argon2`, `bcrypt`          | M1    |
| `github.com/pkg/sftp`            | v1.13.11 | SFTP `RequestServer`                     | M1    |
| `golang.org/x/sys`               | v0.49.0  | `unix.Renameat2` (atomic no-replace rename); later `unix.Fstatfs` | M1    |
| `github.com/BurntSushi/toml`     | v1.6.0   | configuration                            | M2    |
| `github.com/spf13/pflag`         | v1.0.10  | flags of `serve` that override the file  | M2    |
| `golang.org/x/term`              | v0.47.0  | password input without echo              | M3    |
| `github.com/pires/go-proxyproto` | v0.15.0  | PROXY protocol v1 and v2 header parser (Apache-2.0) | M4    |
| `github.com/landlock-lsm/go-landlock` | v0.10.1 | Landlock on Linux ([below](#go-landlock-and-psx)) | M4 |

Planned later (see ROADMAP.md §4.5):
`golang.org/x/time` for bandwidth limits, if they come.
Metrics need no library: gosftpd writes the Prometheus text format itself
(decision D12, ADR 0009).

### go-landlock and psx

`github.com/landlock-lsm/go-landlock` (MIT) applies the Landlock ruleset that
gosftpd computes from its configuration, on Linux only
([ADR 0011](adr/0011-proxy-systemd-landlock.md)). It brings
`kernel.org/pub/linux/libs/security/libcap/psx` v1.2.77 (BSD-3-Clause or
GPL-2.0-only; gosftpd uses it under BSD-3-Clause), which makes one system
call on every thread of the process: the kernel applies a ruleset, and the
ambient capabilities that gosftpd clears, per thread. Release binaries
(`CGO_ENABLED=0`) reach the threads through the Go runtime's
`syscall.AllThreadsSyscall`, a build with cgo through libpsx, and from
Landlock ABI 8 (Linux 7.0) the kernel's own TSYNC flag applies the ruleset.
Writing the ~100 lines of system calls over `golang.org/x/sys` ourselves was
considered; go-landlock handles the threads in all three cases, so it stays.
The `landlocktsync` build tag is never used: it disables Landlock below
Linux 7.0.

Landlock adds 220 KiB to a release binary on amd64 and 192 KiB on arm64
(`CGO_ENABLED=0 go build -trimpath -ldflags="-s -w"`): go-landlock is about
15 KiB of it and psx less than 1 KiB; the rest is gosftpd's own code
(`internal/sandbox` and its use in `serve` and reload), which computes the
rules and checks reloads against them.

### Why `golang.org/x/crypto` is a direct dependency

`github.com/pkg/sftp` v1.13.11 requires x/crypto v0.54.0, which is affected by
GO-2026-6303, GO-2026-6354 and GO-2026-6355 (fixed in v0.55.0 and v0.56.0).
gosftpd therefore requires x/crypto ≥ v0.56.0 itself, as a direct (not
`// indirect`) requirement, and Dependabot keeps it current.

### GO-2026-5932 and `osv-scanner.toml`

GO-2026-5932 marks `golang.org/x/crypto/openpgp` as unmaintained and
unsafe. It matches every x/crypto version and has no fix, so scanners that
read `go.mod` report it. gosftpd never imports openpgp: `go list -deps
-test ./...` has no openpgp package with any build tag, on any system, and
govulncheck reports the advisory for the module only, not for code that
gosftpd calls. `osv-scanner.toml` next to `go.mod` therefore ignores it,
with that reason, for osv-scanner and for the OpenSSF Scorecard check that
runs it, until 2027-04-16; review the entry by then. The file ignores
nothing else: a vulnerability with a fix is fixed by an update instead.

`govulncheck -mode binary` on a release binary does report GO-2026-5932
as affecting the code. Release binaries are stripped (`-ldflags="-s -w"`),
so govulncheck can match them by module only, and it names the openpgp
packages although the binary has none of their code. Scan the source
(`make vuln`) instead.

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

## Man pages

`internal/cli/gendocs`, which `make generate` runs, writes the man pages
with `github.com/spf13/cobra/doc` ([ADR 0012](adr/0012-distribution.md)).
That package brings `github.com/cpuguy83/go-md2man/v2` v2.0.6,
`github.com/russross/blackfriday/v2` v2.1.0 and `go.yaml.in/yaml/v3`
v3.0.4, and the tests of yaml/v3 `github.com/kr/text` v0.2.0: indirect
requirements of `go.mod`. None of them is linked into gosftpd (`go
version -m`), but govulncheck scans them with the rest of the module.

## Developer tools (`tools/go.mod`)

govulncheck v1.8.0, staticcheck v0.8.1, gotestsum v1.13.0, actionlint v1.7.12,
go-licenses v2.0.1 (`github.com/google/go-licenses/v2`, which writes
`THIRD_PARTY_LICENSES` in `make generate`; it brings
`github.com/google/licenseclassifier/v2`, klog, OpenCensus and cobra v1.7.0
and raises `golang.org/x/net` to v0.61.0). golangci-lint v2.14.0 is
installed as a binary (CI uses `golangci/golangci-lint-action`).

The `tool` directive marks every requirement in `tools/go.mod` as
`// indirect`, so a module stays at the version the tools ask for until it
is raised by hand or by Dependabot, which is configured to update these
too. gotestsum asks for `golang.org/x/text` v0.17.0, which is affected by
GO-2026-5970 and GO-2026-6629; `tools/go.mod` requires v0.41.0.
`go.yaml.in/yaml/v4` stays at v4.0.0-rc.3: actionlint v1.7.12 does not
build with a later one. CI and `make vuln` scan this module with
govulncheck too. None of it is part of the gosftpd binary.
