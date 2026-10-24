# Release checklist

Releases are made from `main` by workflows
([ADR 0012](adr/0012-distribution.md)): **Tag release** tags the version
and starts **Release**, which builds, signs and verifies a draft release;
the owner checks the draft and publishes it, and publishing starts **Verify
release**. Version numbers follow SemVer; while the configuration schema is
still settling they are `0.y.z`, and a minor release may break the
configuration only with a **BREAKING:** entry and a migration note in the
CHANGELOG. A pre-release is `X.Y.Z-alpha.N`, `-beta.N` or `-rc.N`.

## Before

1. All work for the release is merged and the `ci-ok` check is green on
   `main`: it needs every CI job, among them both interop jobs (OpenSSH
   9.6 with paramiko, rclone and lftp; OpenSSH 10.6), the `systemd` job
   (the packaged unit under systemd), `goreleaser-check`, `reproducible`,
   `packages` and `docker`. **Tag release** refuses a commit whose `ci-ok`
   did not pass. The nightly **Fuzz** workflow is green on the commit to
   tag, and no `fuzz: ... failed` issue is open; if the commit is newer
   than the last nightly run, start the workflow by hand (**Actions → Fuzz
   → Run workflow**) and wait for it.
2. Optional until WinSCP runs in CI (M3b-02): the manual WinSCP checklist
   in [interop.md](interop.md#winscp).
3. `CHANGELOG.md`: for a release, move the `Unreleased` entries into
   `## [X.Y.Z] - YYYY-MM-DD`, keep an empty `Unreleased`, and update the
   comparison links at the bottom. A pre-release without a section of its
   own takes the `Unreleased` entries as its notes, which must not be
   empty then. Merge the change through a pull request: the draft's notes
   are that section, as `.github/scripts/release-notes.sh` extracts it.
4. Locally on the merged `main`, with GoReleaser v2.19.0 (the version
   `release.yml` names), syft and a Docker daemon with buildx:

   ```sh
   make lint test interop
   go tool -modfile=tools/go.mod govulncheck ./...
   goreleaser check
   goreleaser release --snapshot --clean --skip=sign   # dist/, and both images in Docker
   ```

   A snapshot skips publishing, and with it the signatures of the images,
   but not the signature of `checksums.txt`, which needs the release's
   OIDC token: `--skip=sign` leaves it out. Without syft or Docker, pass
   `--skip=sign,sbom,docker`. Delete `dist/` and the two images
   afterwards.
5. The versions that Dependabot does not update are current, and the same
   in every file that names them:

   | Tool | Where |
   |---|---|
   | GoReleaser | `version:` of the GoReleaser steps in `release.yml` and `ci.yml` |
   | cosign | `cosign-release:` in `release.yml` and `verify-release.yml` |
   | syft | `syft-version:` in `release.yml` and `ci.yml` |
   | BuildKit | `image=moby/buildkit:VERSION@sha256:DIGEST` in the `driver-opts:` of `release.yml` and `ci.yml` |
   | SBOM scanner | `generator=docker.io/docker/buildkit-syft-scanner:VERSION@sha256:DIGEST` in the `flags` of `dockers_v2` in `.goreleaser.yaml`, and its copy in ADR 0012 |

   Update one in a pull request of its own, with `goreleaser-check` green,
   before the release rather than with it: a new GoReleaser or cosign
   changes how the release is built and verified. Pin BuildKit and the
   SBOM scanner by the digest of their multi-platform index, which `docker
   buildx imagetools inspect IMAGE:VERSION` prints (`moby/buildkit`,
   `docker/buildkit-syft-scanner`). A test (`TestChecklistPins` in
   `test/release`) fails when a file pins one that this table does not
   name.

## Tag and build

6. **Actions → Tag release → Run workflow**, on `main`, with the version
   without the `v`: `0.5.0`, or `0.5.0-rc.1`. The run checks that the
   version is higher than every release tag, that CHANGELOG.md has its
   notes and that `ci-ok` passed on the commit the run started on; then it
   creates the annotated tag `vX.Y.Z` on that commit and starts
   **Release** on the tag. Start one release at a time: wait until the
   Release run of the previous one has finished.
7. Wait for the **Release** run on `vX.Y.Z` to go green. Its `generate`
   job builds the man pages, the completions and the license file without
   credentials; its `release` job builds and pushes the archives, packages
   and images, signs and attests them, adds the provenance bundle and
   `digests.txt` to the draft, and runs the verification of
   [install.md](install.md#verify-a-release) against what it built ("The
   documented verification"). For a stable version its last step then
   moves `latest` to the verified image; a pre-release never does. A red
   run leaves a draft and the image tag `vX.Y.Z` at most: fix the cause
   and re-run it (**Re-run failed jobs**), which replaces the draft and
   its image, or give the version up ([An abandoned draft](#an-abandoned-draft)).

## Publish

8. Check the draft on the **Releases** page:
   - its tag and title `vX.Y.Z`, marked as a pre-release for `-alpha`,
     `-beta` and `-rc`;
   - its notes, the CHANGELOG section of step 3;
   - its 22 assets: 6 archives (`linux`, `darwin` and `freebsd`, each
     `amd64` and `arm64`), 6 packages (`.deb`, `.rpm` and `.pkg.tar.zst`,
     each for both), 6 SBOMs (`.sbom.json`), `checksums.txt`,
     `checksums.txt.sigstore.json`, `digests.txt` and
     `gosftpd_X.Y.Z.intoto.jsonl`;
   - the image `ghcr.io/o-kolomoiets/gosftpd:vX.Y.Z` on the package's page.
9. **Publish release**. Publishing starts **Verify release**, which runs
   the same verification against the published assets and pulls the image
   anonymously, by its digest.
10. Wait for **Verify release** to pass. It fails while the GHCR package
    is private: after the first release with an image, set the package
    `gosftpd` to **Public** in its settings and re-run it (or **Actions →
    Verify release → Run workflow** with the tag).

## After

11. The smoke tests, by hand, of what users get, with Docker, `REPO` a
    checkout of the tag and `export V=X.Y.Z`:
    - the verification, as users run it, with your cosign and gh, in an
      empty directory; it downloads the assets. Then `gosftpd version` of
      the extracted archive prints `vX.Y.Z` and the commit of the tag:

      ```sh
      "$REPO/test/docs/run-block.sh" verify
      tar xzf "gosftpd_${V}_linux_amd64.tar.gz" gosftpd && ./gosftpd version
      ```

    - the deb on Debian 12 and 13 and the rpm on EL9, under systemd, as the
      `packages` CI job runs them (privileged containers, a host with
      cgroup v2):

      ```sh
      mkdir "release-$V"
      (cd "release-$V" && gh release download "v$V" -R o-kolomoiets/Go-SFTP-Server -p "gosftpd_${V}_linux_*" -p checksums.txt &&
        sha256sum --check --ignore-missing checksums.txt)
      EXPECT_LEGACY_DROPIN=1 "$REPO/test/packages/container.sh" debian-12 deb "release-$V" "$V"
      "$REPO/test/packages/container.sh" debian-13 deb "release-$V" "$V"
      "$REPO/test/packages/container.sh" el9 rpm "release-$V" "$V"
      ```

    - the Docker Quickstart of install.md, in an empty directory, until
      the container is `healthy`, and a login:

      ```sh
      "$REPO/test/docs/run-block.sh" quickstart
      until [ "$(docker inspect -f '{{.State.Health.Status}}' gosftpd)" = healthy ]; do sleep 1; done
      sftp -P 2022 alice@localhost
      docker rm -f gosftpd && sudo rm -r gosftpd data state
      ```

12. `go list -m github.com/o-kolomoiets/go-sftp-server@vX.Y.Z` finds the
    version through the Go module proxy.
13. In `README.md`, replace every mention of the previous release and of the
    next one (`grep -n 'v0\.[0-9]' README.md`): the install commands and the
    quick-start comment, the "Released and on its way" and Roadmap tables,
    what the page says is only on `main` or comes "from" this version, the
    links to the docs at the release tag (`blob/vX.Y.Z/docs/...`), and "to
    hear when vX ships". In the docs, the examples name the version too
    (`V=X.Y.Z`, `gosftpd:vX.Y.Z`): the blocks of install.md, with the
    copies of its Quickstart in README.md and docs/quickstart.md, which a
    test compares, and migrate-from-atmoz.md. With the binary from the
    release archive, capture the banner, the partner-inbox `sftp`
    transcript and its audit event again, and record `docs/assets/demo.gif`
    again with `docs/assets/record-demo.py` and `agg`, as its docstring
    says.
14. Update `TASKS.md` (and `ROADMAP.md` if the plan changed).

## When something goes wrong

### A tag whose release did not start

If **Tag release** created the tag but did not start **Release** (its log
ends with a failed `gh workflow run`), re-run that Tag release run: it
finds its own tag on the commit it started on and only starts Release. Or
start Release yourself, on the tag:

```sh
gh workflow run release.yml --ref vX.Y.Z -R o-kolomoiets/Go-SFTP-Server
```

or **Actions → Release → Run workflow** with the tag chosen under **Use
workflow from**. A tag made another way, signed and pushed by the owner or
created by hand, is released the same way; Tag release's checks are then
yours: the version is higher than every release tag (the release guard
stops the run otherwise), CHANGELOG.md has its notes, and `ci-ok` passed on
the tag's commit.

### An abandoned draft

A version given up after its Release run, red or not, leaves a draft and
image versions in GHCR, which are public once the package is. Delete the
draft on the **Releases** page. If the run moved `latest` (a stable
version whose verification passed), point it back to the image of the
previous stable release first, by the digest in that release's
`digests.txt`, logged in to `ghcr.io` (`docker login ghcr.io`) with a token
that may write packages:

```sh
PREV=X.Y.Z   # the previous stable release
DIGEST=$(gh release download "v$PREV" -R o-kolomoiets/Go-SFTP-Server -p digests.txt -O - |
  awk -v t="ghcr.io/o-kolomoiets/gosftpd:v$PREV" '$2 == t { print $1 }')
docker buildx imagetools create --tag ghcr.io/o-kolomoiets/gosftpd:latest "ghcr.io/o-kolomoiets/gosftpd@sha256:$DIGEST"
```

Then delete the abandoned version's image on the package's page, with the
untagged versions pushed with it. Deleting a version deletes every tag on
it, which is why `latest` moves first; without a previous stable image,
`latest` goes with it. The tag `vX.Y.Z` stays, protected by the tag
ruleset, so the next version must be higher: the next patch, or the next
pre-release.

### A tag made by mistake

A tag in release format created by mistake, such as `v5.0.0` for `v0.5.0`,
outranks every later version: Tag release refuses any version below it,
and the release guard every other tag. Only the owner can remove it, by
bypassing the `v*` tag ruleset (**Settings → Rules → Rulesets**): delete
the tag (`git push --delete origin v5.0.0`), and the draft and the image
versions its Release run made, as for an abandoned draft. A tag that is
not in release format, such as `vtest`, counts for neither.

## Patch releases

A patch release is due within 7 days when `govulncheck -mode=binary` on the
latest release finds a reachable vulnerability in a dependency or the Go
standard library; otherwise fixes ship with the next planned release.

Release binaries are stripped, so binary mode matches them by module only.
It always reports GO-2026-5932 (`golang.org/x/crypto/openpgp`, no fix) as
affecting the code: a known false positive
([DEPENDENCIES.md](DEPENDENCIES.md#go-2026-5932-and-osv-scannertoml)). A
finding counts as reachable only when a source scan of the tag reports it
as called: `go tool -modfile=tools/go.mod govulncheck ./...` on a checkout
of `vX.Y.Z`, with the Go version that built the release (`go version
./gosftpd`).
