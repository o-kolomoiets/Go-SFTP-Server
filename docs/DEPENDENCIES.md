# Dependencies

Principle: at most 10 direct runtime dependencies, including `golang.org/x/*`.
A new dependency requires removing another one or revisiting this rule.

## Runtime

| Module                           | Version  | Purpose                                  | Since |
|----------------------------------|----------|------------------------------------------|-------|
| `github.com/spf13/cobra`         | v1.10.2  | CLI                                      | M0    |
| `golang.org/x/crypto`            | v0.57.0  | `ssh`; later `argon2`, `bcrypt`          | M1    |
| `github.com/pkg/sftp`            | v1.13.11 | SFTP `RequestServer`                     | M1    |
| `golang.org/x/sys`               | via x/crypto | `unix.Renameat2`, `unix.Fstatfs`     | M1    |
| `github.com/BurntSushi/toml`     | v1.6.0   | configuration                            | M2    |

Planned later (see ROADMAP.md §4.5): `golang.org/x/time`, `golang.org/x/term`
(M3), Prometheus `client_golang`, `go-landlock`, `go-proxyproto` (M4).

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
