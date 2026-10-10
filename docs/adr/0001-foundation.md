# ADR 0001: Project foundation

- **Status:** accepted, 2026-10-07
- **Context:** the 2023 skeleton did not compile, had no SSH handshake and
  depended on a 2021 `golang.org/x/crypto` affected by 23 advisories in
  `ssh/*`. The project is restarted from scratch following
  [ROADMAP.md](../../ROADMAP.md) (§13 lists the decisions in full).

## Decisions

| #   | Decision                | Choice                                                                                                   | Source                        |
|-----|-------------------------|----------------------------------------------------------------------------------------------------------|-------------------------------|
| D1  | License                 | **Apache-2.0** (was GPL-3.0). Earlier commits remain available under GPL-3.0.                            | confirmed by the owner        |
| D2  | Names                   | Module `github.com/o-kolomoiets/go-sftp-server`, binary `gosftpd`                                        | confirmed by the owner        |
| D3  | Niche and scope         | Rootless, secure-by-default SFTP drop-box in a single binary; not a platform (that is SFTPGo)            | roadmap recommendation        |
| D4  | Config format           | TOML (`github.com/BurntSushi/toml`), one format; the JSON config promised by the old README is dropped   | roadmap recommendation        |
| D14 | Minimum Go version      | `go 1.26.5`: required by x/crypto ≥ v0.56.0 and by the `os.Root` escape fix GO-2026-4970                 | roadmap recommendation        |
| D16 | Contributor terms       | DCO (`git commit -s`), no CLA                                                                            | roadmap recommendation        |
| D17 | Time budget             | ~12 hours per week; the estimates in ROADMAP.md §5 assume this                                           | assumed, owner may correct    |
| D19 | Language                | English everywhere, ROADMAP.md and TASKS.md included (until 2026-10-10 those two were in Russian)        | owner decision, ADR 0006      |

Decisions marked "roadmap recommendation" were adopted by default and can be
revisited by the owner; record any change as a new ADR.

## Technical decisions (summary of ROADMAP.md §4.4)

| #   | Topic                 | Choice                                                                                                   |
|-----|-----------------------|----------------------------------------------------------------------------------------------------------|
| A1  | SSH layer             | `golang.org/x/crypto/ssh` directly (not gliderlabs/ssh or charm ssh)                                     |
| A2  | SFTP library          | `github.com/pkg/sftp` v1 `RequestServer` behind an `internal/sftpd` adapter (see ADR 0003, M1)           |
| A3  | Confinement           | one `os.Root` per mount, plus process sandboxing (systemd, Landlock)                                     |
| A4  | Config format         | TOML with `BurntSushi/toml`; unknown keys are errors                                                     |
| A5  | CLI                   | `spf13/cobra` without viper                                                                              |
| A6  | Logging               | `log/slog`: operational log to stderr, separate JSON audit stream                                        |
| A7  | User model            | virtual users under one unprivileged service account                                                     |
| A8  | Default auth          | public key; passwords opt-in (argon2id); SSH certificates later                                          |
| A9  | Metrics               | opt-in Prometheus endpoint; no OpenTelemetry before 1.0                                                  |
| A10 | Go version policy     | the two latest Go releases; floor `go 1.26.5`                                                            |
| A11 | Upload conflicts      | `O_CREATE\|O_EXCL` reservation of the final name; temp file + `Root.Link` for atomic uploads             |
| A12 | Storage               | local filesystem only before 1.0                                                                         |
| A13 | Errors to clients     | mapped to fixed `SSH_FX_*` messages; host paths never leave the server                                   |

## Consequences

- The module path is lowercase; renaming the GitHub repository from
  `Go-SFTP-Server` to `go-sftp-server` is cosmetic (GitHub URLs are
  case-insensitive) and does not break `go install`.
- All code lives under `internal/`; the public contract is the CLI, the config
  schema, the audit schema, metric names and exit codes.
