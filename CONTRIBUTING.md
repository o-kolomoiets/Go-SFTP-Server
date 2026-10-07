# Contributing

Thanks for your interest in gosftpd. The project is pre-alpha; please read
[ROADMAP.md](ROADMAP.md) and the [non-goals](docs/adr/0002-non-goals.md)
before proposing larger changes, and open an issue first to discuss them.

## Development setup

- Go 1.26.5 or newer.
- [golangci-lint](https://golangci-lint.run/welcome/install/) v2.14 as a
  binary (its docs advise against `go install`).
- Other tools (govulncheck, staticcheck, gotestsum, actionlint) live in
  `tools/go.mod` and run via `go tool -modfile=tools/go.mod <tool>`.

| Command      | What it does                                   |
|--------------|------------------------------------------------|
| `make test`  | unit tests with `-race`                        |
| `make lint`  | gofmt, go vet, golangci-lint, actionlint       |
| `make fmt`   | apply gofumpt and goimports                    |
| `make vuln`  | govulncheck                                    |
| `make build` | build `bin/gosftpd`                            |
| `make tidy`  | `go mod tidy` for both modules                 |

## Pull requests

- Every bug fix comes with a regression test.
- All code lives under `internal/`; there is no public Go API before 1.0.
- Each `.go` file starts with `// SPDX-License-Identifier: Apache-2.0`.
- Commit messages and PR titles follow
  [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/)
  (`feat:`, `fix:`, `docs:`, `ci:`, `chore(deps):` …) and are written in English.
- Sign off your commits (`git commit -s`) to certify the
  [Developer Certificate of Origin](https://developercertificate.org/).
- Update the `Unreleased` section of [CHANGELOG.md](CHANGELOG.md).
- CI must be green: the `ci-ok` check aggregates lint, tests, the minimum Go
  version build and govulncheck.
