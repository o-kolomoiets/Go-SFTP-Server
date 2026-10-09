# Release checklist

Releases are made from `main`. Version numbers follow SemVer; while the
configuration schema is still settling they are `0.y.z`, and a minor release
may break the configuration only with a **BREAKING:** entry and a migration
note in the CHANGELOG.

## Before

1. All work for the release is merged and CI is green on `main`, including
   both interop jobs (OpenSSH 9.6 with paramiko, rclone and lftp; OpenSSH
   10.6).
2. Optional until WinSCP runs in CI (M3b-02): the manual WinSCP checklist
   in [interop.md](interop.md#winscp).
3. `CHANGELOG.md`: move the `Unreleased` entries into
   `## [X.Y.Z] - YYYY-MM-DD`, keep an empty `Unreleased`, and update the
   comparison links at the bottom. Merge that change through a pull request.
4. Locally on the merged `main`:

   ```sh
   make lint test interop
   go tool -modfile=tools/go.mod govulncheck ./...
   goreleaser check
   goreleaser release --snapshot --clean   # builds every archive into dist/
   ```

## Publish

5. On GitHub: **Releases → Draft a new release**.
   - **Choose a tag**: type `vX.Y.Z`, then "Create new tag on publish";
     target `main`.
   - **Title**: `vX.Y.Z`.
   - **Notes**: the CHANGELOG section of the version.
   - Mark it as a pre-release for `-alpha`, `-beta` and `-rc` versions.
   - **Publish release**.
6. Publishing starts the **Release** workflow, which builds the binaries with
   GoReleaser and attaches the archives and `checksums.txt` to the release.
   Wait for it to finish.

## After

7. Download one archive and check it:

   ```sh
   sha256sum --check --ignore-missing checksums.txt
   tar xzf gosftpd_X.Y.Z_linux_amd64.tar.gz gosftpd && ./gosftpd version
   ```

   `gosftpd version` must print `vX.Y.Z` and the commit of the tag.
8. `go list -m github.com/o-kolomoiets/go-sftp-server@vX.Y.Z` finds the
   version through the Go module proxy.
9. Update `TASKS.md` (and `ROADMAP.md` if the plan changed).

## Patch releases

A patch release is due within 7 days when `govulncheck -mode=binary` on the
latest release finds a reachable vulnerability in a dependency or the Go
standard library; otherwise fixes ship with the next planned release.
