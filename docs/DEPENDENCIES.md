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
| `github.com/landlock-lsm/go-landlock` | v0.10.1 | Landlock on Linux ([below](#go-landlock-and-psx)) | M4 |

Planned later (see ROADMAP.md §4.5): `go-proxyproto` (M4);
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

## Test-only

| Module               | Version | Purpose               | Since |
|----------------------|---------|-----------------------|-------|
| `go.uber.org/goleak` | v1.3.0  | goroutine leak checks | M1    |

## Developer tools (`tools/go.mod`)

govulncheck v1.8.0, staticcheck v0.8.1, gotestsum v1.13.0, actionlint v1.7.12.
golangci-lint v2.14.0 is installed as a binary (CI uses
`golangci/golangci-lint-action`).
