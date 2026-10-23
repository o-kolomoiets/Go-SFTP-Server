# ADR 0012: Distribution: releases, signatures, image, packages, ephemeral mode and atmoz compatibility

- **Status:** proposed, 2026-10-23; amends ROADMAP §4.5 (tool versions),
  §5 M5 (items, Definition of Done, estimate), §6.1 item 4 (`{user}`
  before the last path component), §6.7 (the root-level spec form), §9.1,
  §9.3, §9.4, §9.5, §9.6 (the local snapshot), §10 (the Docker
  Quickstart mounts a directory) and decision D13, ADR 0011 (the unit's
  `Documentation=`; the packages remove the legacy drop-in only once the
  unit is gone; the Landlock rules of a mount with `{user}` before the last
  component) and docs/release-checklist.md
- **Context:** ROADMAP M5 asks for a full `.goreleaser.yaml`, a distroless
  image in GHCR, deb, rpm, apk and Arch packages, keyless cosign
  signatures, SBOMs, attestations, signed git tags, `THIRD_PARTY_LICENSES`,
  man pages and completions, `serve --ephemeral` and migration from
  atmoz/sftp. Today `release.yml` runs when the owner publishes a release in
  the web interface (`on: release: published`, `contents: write` only), and
  GoReleaser v2.18.2 attaches linux and darwin archives and `checksums.txt`
  to it (`release.mode: keep-existing`); the v0.4.0 tag was created by that
  interface and is lightweight and unsigned. `.github/dependabot.yml` has no
  `docker` entry and SECURITY.md says nothing about verifying a release.
  Three research tracks (a gap analysis against origin/main, the external
  tools at their latest versions, and what this environment can build and
  run) read the source of GoReleaser v2.19.0, nfpm v2.48.0, cosign v3.1.4,
  go-licenses v2.0.1, cobra v1.10.2, Scorecard v5.6.0 and atmoz/sftp, the
  `action.yml` of every action below and the distroless registry
  manifests, and ran prototypes: GoReleaser snapshots, the image and the
  Quickstart, deb, rpm and Arch packages under systemd as PID 1, and
  reproducibility across two clones. The configuration in this ADR passed
  `goreleaser check` and the v2.19.0 JSON schema; a snapshot of it (man
  pages and licenses stubbed) built 6 archives, 6 packages and both images,
  and a second build in a clone made with umask 002 at another path gave
  the same 12 checksums. Its deb, rpm and Arch packages were installed,
  reinstalled as an upgrade and removed under systemd 252 (Debian 12, Rocky
  9) and 262 (Arch), and its image came up `healthy` in 3 s with named
  volumes and with `--user 1000:1000` and accepted an sftp upload. The owner
  decided two questions: tags are created by a workflow, not signed (Q1),
  and the repository keeps its name `o-kolomoiets/Go-SFTP-Server` (Q2).
  Three design reviews (supply chain, operations and packaging, CLI and UX)
  confirmed 31 findings, each checked by a second reviewer; this version
  takes them in.

## Decision

### How a release is made

- **The owner starts a workflow, reviews a draft and publishes it.**
  **Actions → Tag release → Run workflow** with the version (`0.5.0`,
  `0.5.0-rc.1`). `tag.yml` checks the version and the commit the run
  started on (`github.sha`, `main`'s head at that moment), creates the
  annotated tag `vX.Y.Z` on that commit and starts `release.yml` on the
  tag's ref. `release.yml` checks the tag again, generates the man pages,
  completions and license file in a job without credentials, and runs
  GoReleaser, which creates a **draft** release and uploads the assets;
  the attestations follow, their provenance file and the image digests are
  added to the draft, and the job runs the verification commands of
  docs/install.md against what it built and pushed. The owner checks the
  draft and presses **Publish**; publishing starts `verify-release.yml`,
  which runs the same commands against the published assets and pulls the
  image anonymously.
- **Tags are not signed.** A tag created through the API with
  `GITHUB_TOKEN` cannot carry the owner's signature. What a signed tag was
  meant to give comes from elsewhere: a `v*` tag ruleset that blocks
  updates and deletions (an owner action), Immutable Releases from M6-05,
  and cosign signatures and attestations whose identity names the workflow
  file and `refs/tags/vX.Y.Z`. This replaces ROADMAP M5's "signed git
  tags".
- **A signed tag still works.** `release.yml` also runs on a pushed `v*`
  tag, so `git tag -s vX.Y.Z && git push origin vX.Y.Z` from a machine with
  a signing key registered on GitHub runs the same pipeline with the same
  identity. `release.yml` repeats the checks for a pushed tag (`verify-tag`
  under Workflows): such a tag never passes through `tag.yml`, and the
  certificate binds only the tag name, so a build of a commit that is not
  on `main`, whose `ci-ok` failed or that has no CHANGELOG section would
  verify like a real one. These checks guard against mistakes, not against
  a holder of write access: `release.yml` is read from the tagged commit,
  which such a person can change, so who may create `v*` tags is what
  protects the release identity.
- **Why a workflow dispatch.** Events caused by `GITHUB_TOKEN` start no
  workflows, except `workflow_dispatch` and `repository_dispatch` (GitHub's
  documented exception; docs.github.com was not reachable from the
  research environment). So `tag.yml` starts `release.yml` explicitly with
  `gh workflow run release.yml --ref vX.Y.Z`. On that ref the OIDC
  `job_workflow_ref`, and with it the certificate identity, should be
  `o-kolomoiets/Go-SFTP-Server/.github/workflows/release.yml@refs/tags/vX.Y.Z`,
  as for a pushed tag; this is inferred, and the verification step of the
  rc release checks it before anything is published.
- **Why a draft.** GoReleaser always creates a release as a draft, uploads,
  then publishes it unless `release.draft` is true; a release that already
  exists keeps its draft state, and once a release is immutable GoReleaser
  fails with "already exists and is immutable" (internal/client/github.go).
  Today's flow (publish first, upload after) therefore stops working with
  Immutable Releases. With `draft: true` the provenance file can be added
  after GoReleaser and the result verified, and the owner publishes a
  release that is complete and checked.
- **Release notes** come from CHANGELOG.md: a step extracts the section
  `## [X.Y.Z]` (for a pre-release without its own section, `## [Unreleased]`)
  into a file and passes it with `goreleaser release --release-notes FILE`
  (the flag exists in v2.19.0). `changelog.disable: true` stays.
- **Images are public before the release is.** `release.yml` pushes the
  image tags while the release is still a draft. `latest` moves only to
  the highest stable version (see the next section), and a run for a tag
  whose release is already published stops before building (`verify-tag`).
  Otherwise a re-run or a dispatch for a published release would push and
  sign a rebuilt image (images are not reproducible) under its tags, and a
  run on an older tag would move `latest` backwards. A re-run while the
  release is still a draft replaces the draft and its images, which is
  what a re-run is for. The first run is `v0.5.0-rc.1`: a pre-release gets no
  `latest` tag. A draft that is deleted instead of published leaves its
  image versions in GHCR; the owner deletes them by hand.

### GoReleaser configuration

GoReleaser **v2.19.0** (2026-10-22, commit
`00139d15712716a3a2f21eb4d533f231ff19b9c5`) in `ci.yml` and `release.yml`.
v2.18.2, pinned today, reports the image config digest instead of the
manifest digest for `dockers_v2` (upstream #7180, fixed in v2.18.3), so
`docker_signs` `${artifact}@${digest}` and `digests.txt` would name an
object that cannot be pulled. The fallback is v2.18.3 (2026-10-09,
`1942d44355492f44cd3774c57bd3c27fe544dfe9`). Dependabot does not update
the `version:` input, `cosign-release:` or `syft-version:`; the release
checklist names them. nfpm v2.48.0 is built into v2.19.0. The file, shortened
where a comment says so (the full `nfpms` block is under Packages):

```yaml
version: 2
project_name: gosftpd

# CI and local snapshots run the hooks; release.yml runs them in its
# generate job, without credentials, and passes --skip=before (Workflows).
before:
  hooks:
    - go mod tidy -diff
    # Man pages and completions into out/ (ignored by git), dated by the commit.
    - sh -c 'SOURCE_DATE_EPOCH={{ .CommitTimestamp }} go generate ./...'
    - sh -c 'mkdir -p out && GOOS=linux GOROOT="$(go env GOROOT)" go tool -modfile=tools/go.mod go-licenses report ./cmd/gosftpd --ignore github.com/o-kolomoiets/go-sftp-server --template=packaging/third_party_licenses.tpl > out/THIRD_PARTY_LICENSES'
    # Empty directories that the Dockerfile copies with their owner and mode.
    - mkdir -p out/docker/empty out/docker/home-root/home

# Linux apart, so that only the Linux archives carry the packaging files.
builds:
  - &build
    id: gosftpd
    main: ./cmd/gosftpd
    binary: gosftpd
    env: [CGO_ENABLED=0]
    goos: [linux]
    goarch: [amd64, arm64]
    flags: [-trimpath]
    ldflags:
      - -s -w
      - -X github.com/o-kolomoiets/go-sftp-server/internal/version.Version={{ .Tag }}
      - -X github.com/o-kolomoiets/go-sftp-server/internal/version.Commit={{ .FullCommit }}
      - -X github.com/o-kolomoiets/go-sftp-server/internal/version.Date={{ .CommitDate }}
    mod_timestamp: "{{ .CommitTimestamp }}"
  - <<: *build
    id: gosftpd-other
    goos: [darwin, freebsd]

archives:
  - id: gosftpd
    ids: [gosftpd]
    formats: [tar.gz]
    name_template: "{{ .ProjectName }}_{{ .Version }}_{{ .Os }}_{{ .Arch }}"
    builds_info: { owner: root, group: root, mode: 0755, mtime: "{{ .CommitDate }}" }
    files:
      - { src: LICENSE, info: &info { owner: root, group: root, mode: 0644, mtime: "{{ .CommitDate }}" } }
      - { src: README.md, info: *info }
      - { src: CHANGELOG.md, info: *info }
      - { src: out/THIRD_PARTY_LICENSES, strip_parent: true, info: *info }
      - { src: "out/man/*.1.gz", dst: man, strip_parent: true, info: *info }
      - { src: "out/completions/*", dst: completions, strip_parent: true, info: *info }
      - { src: packaging/config.toml, info: *info }
      - { src: packaging/gosftpd.sysusers, info: *info }
      - { src: packaging/gosftpd.tmpfiles, info: *info }
      - { src: packaging/systemd/gosftpd.service, info: *info }
      - { src: packaging/systemd/legacy-notify.conf, info: *info }
  - id: gosftpd-other
    ids: [gosftpd-other]
    formats: [tar.gz]
    name_template: "{{ .ProjectName }}_{{ .Version }}_{{ .Os }}_{{ .Arch }}"
    builds_info: { owner: root, group: root, mode: 0755, mtime: "{{ .CommitDate }}" }
    files:   # the first six entries of the Linux archive

checksum: { name_template: checksums.txt, algorithm: sha256 }

sboms:
  - artifacts: archive

signs:
  - cmd: cosign
    artifacts: checksum
    signature: "${artifact}.sigstore.json"
    args: [sign-blob, "--bundle=${signature}", "${artifact}", --yes]

nfpms: # see Packages

dockers_v2:
  - id: image
    ids: [gosftpd]
    dockerfile: packaging/docker/Dockerfile
    extra_files: [out/docker]
    images: [ghcr.io/o-kolomoiets/gosftpd]
    tags:
      - "v{{ .Version }}"
      # Only for the highest stable tag; IS_LATEST is set by release.yml.
      - '{{ if and (not .Prerelease) (eq (index .Env "IS_LATEST") "true") }}latest{{ end }}'
    platforms: [linux/amd64, linux/arm64]
    labels:
      org.opencontainers.image.source: https://github.com/o-kolomoiets/Go-SFTP-Server
      org.opencontainers.image.revision: "{{ .FullCommit }}"
      org.opencontainers.image.version: "{{ .Version }}"
      org.opencontainers.image.created: "{{ .CommitDate }}"
      org.opencontainers.image.licenses: Apache-2.0

docker_signs:
  - cmd: cosign
    args: [sign, "${artifact}@${digest}", --yes]

docker_digest: { name_template: digests.txt }

release:
  draft: true
  replace_existing_draft: true   # a re-run replaces its own draft
  prerelease: auto
  preflight: { fail_on_error: true }

changelog: { disable: true }
```

- What it keeps from today's file, against the ROADMAP §9.3 fragment:
  `go mod tidy -diff`, which never changes the tree (the fragment's
  `go mod tidy` can); `version.Version={{ .Tag }}`, so that `gosftpd
  version` prints `vX.Y.Z` as the release checklist expects; named
  documents instead of the fragment's `"*.md"`, which would ship ROADMAP.md
  (195 KB) and TASKS.md; one build per group so that the CI check "only the
  Linux archives hold the systemd files" keeps working. `mode:
  keep-existing` is dropped (it only says how notes are merged).
- **FreeBSD** amd64 and arm64 join darwin in the non-Linux group: Tier 2,
  cross-built and not tested (ROADMAP §9.4); both build cleanly. The CI
  archive check covers `*_freebsd_*` as it covers `*_darwin_*`.
- **`latest` only for the highest stable tag.** The tag renders only for a
  version that is not a pre-release and when `IS_LATEST` is `true`: a step
  of the release job sets it when the tag equals `git tag -l 'v*' | grep -v
  -- - | sort -V | tail -1`, so a patch for an older minor (after 1.0,
  ROADMAP §9.6) or a run on an older tag never moves `latest` backwards.
  `dockers_v2` drops tags that render empty (`tpl.Slice` with
  `tmpl.NonEmpty()`). Templates run with `missingkey=error`, and `index`
  keeps this one valid when the variable is unset: a local snapshot builds
  only the version tags, and the CI `goreleaser-check` job sets
  `IS_LATEST=true` so that `latest-amd64` and `latest-arm64`, which the
  `docker` job runs, are built locally (never pushed). In a snapshot
  `.Prerelease` is empty.
- `docker_signs` sets its own `args`: the default is `sign
  --key=cosign.key ...`. With the tags `vX.Y.Z` and `latest` the same
  digest is signed twice, which is harmless.
- `preflight.fail_on_error` (since v2.18) stops the run before building
  only when the tag's release is already immutable; it does not check that
  the token can publish (`CanRelease` only reads the repository and the
  release by tag). A published but still mutable release is caught by
  `verify-tag`.

### Reproducible builds

- **Archives** set owner, group, mode and `mtime` on every entry
  (`files[].info`, `builds_info`). The ROADMAP fragment set only `mtime`;
  with a checkout made under umask 002 all six archives then differed,
  because the files kept mode 0664.
- **Packages** take `mtime: "{{ .CommitDate }}"` and a fixed
  `rpm.buildhost` (nfpm uses the host name otherwise). The apk scripts kept
  their file's mtime whatever `mtime` said; apk is not built (see
  Packages), so no hook touches them.
- **Toolchain.** Releases keep `go-version: stable` with `check-latest`,
  in line with the monthly toolchain refresh of ROADMAP §9.6.
  "Reproducible" means: the same tag built with the same Go version, which
  `go version -m gosftpd` prints, and the same GoReleaser version, the
  `version:` input of `.github/workflows/release.yml` at that tag. Archives
  and packages are written by GoReleaser's own archive code and its
  built-in nfpm (zstd for Arch), so the Go version alone does not fix their
  bytes.
- **Rebuilding a release** (docs/install.md): a fresh clone of the tag,
  with that Go and that GoReleaser installed; `goreleaser release --clean
  --skip=publish,sign,sbom,docker`; then `cd dist && sha256sum --check
  --ignore-missing CHECKSUMS`, where CHECKSUMS is the release's own
  `checksums.txt` after `cosign verify-blob`. Not `--snapshot`: it renames
  every file to `X.Y.Z-SNAPSHOT-<commit>`, so nothing would match.
  `--skip=publish` needs no token (GoReleaser skips the token check then).
- **CI job `reproducible`:** two checkouts of the commit at different
  paths, the second under umask 002, each running `goreleaser release
  --snapshot --clean --skip=sign,sbom,docker` with its own `GOCACHE` and
  `GOMODCACHE` (under `$RUNNER_TEMP`) and setup-go's `cache: false`: with
  one shared build cache and `-trimpath`, the second build would reuse the
  first one's compiled packages and prove only that packaging is
  deterministic. `dist/checksums.txt` must be identical (12 entries:
  archives and packages). Signatures, SBOMs (syft's default `--enrich all`
  goes online) and images are out of scope, as the DoD allows.

### Signatures, SBOM and provenance

- **cosign v3.1.4** (2026-10-20), installed by `sigstore/cosign-installer`
  v4.1.2 (`6f9f17788090df1f26f669e9d70d6ae9567deba6`) with
  `cosign-release: v3.1.4`; the installer's default is v3.0.6, and it has
  no floating `v4` tag (the repository pins by commit anyway). Keyless,
  through GitHub's OIDC token; v3 writes the new bundle format and stores
  image signatures as OCI 1.1 referrers by default.
- **Verifiers need cosign v3.0 or later.** v3 signs images into the new
  bundle format, stored as OCI 1.1 referrers (or the referrers fallback
  tag), not as the legacy `sha256-<digest>.sig` tag, and the blob bundle
  is in the protobuf bundle format (`--new-bundle-format` defaults to true
  for `sign` and `verify` in v3.1.4). cosign v2.6 verifies them only with
  `--new-bundle-format` on `verify` and `verify-blob`; older v2 releases,
  still common in distribution packages, report no signature. Admission
  controllers need Sigstore bundle and OCI referrer support. The failure is
  a false negative, which `verify-release` (cosign v3.1.4) cannot notice,
  so docs/install.md and SECURITY.md state these minimums, and the gh
  release whose `attestation verify` has the flags of "Verification by
  users"; the rc confirms the exact versions.
- **`checksums.txt.sigstore.json`** signs `checksums.txt`, which lists every
  archive, package and SBOM: one signature covers them all.
- **The image** is signed by digest (`docker_signs` above).
- **The identity is matched exactly, case included** (cosign compares the
  certificate's SAN with `--certificate-identity` as strings; a wrong case
  was reproduced failing). The documentation uses the repository's real
  name, `o-kolomoiets/Go-SFTP-Server`, never `--certificate-identity-regexp`.
- **SBOM:** syft v1.55.0 through `anchore/sbom-action/download-syft`
  v0.24.3 (`66cbf4bc1f1c0d2edc94016e65bc221b6bb0ad6c`) with `syft-version:
  v1.55.0` (the action's default is v1.54.0, and its `v0` tag is stale);
  one SPDX JSON per archive (`sboms: [{artifacts: archive}]`, default
  arguments). `dockers_v2` keeps `sbom: true`, so buildx adds an SBOM
  attestation to each image.
- **Attestations:** `actions/attest` v4.2.2
  (`1e69f48acb82d1966a394da916b4c1698aa569d6`, also the `v4` tag) in **two
  steps**, `subject-checksums: dist/checksums.txt` and `subject-checksums:
  dist/digests.txt`: the action takes only one subject input. Without a
  predicate it produces SLSA build provenance. Storage records need
  `push-to-registry` and an organization owner (src/attest.ts creates one
  only for a single subject pushed to a registry, and returns early for a
  user's repository), so none are created: both steps set
  `create-storage-record: false` to say so, and the job has no
  `artifact-metadata` permission.
- **`.intoto.jsonl`.** Scorecard's Signed-Releases check scores 8 for a
  `*.sigstore.json` asset and 10 for a `*.intoto.jsonl` asset, by file
  suffix only, as the floor of the average over the last five releases. The
  first attest step's `bundle-path` output (the Sigstore bundle of the
  provenance) is uploaded to the draft as `gosftpd_X.Y.Z.intoto.jsonl`,
  which `gh attestation verify --bundle` reads without the attestations API.
  The file stays whatever Scorecard does: it is the release's own
  provenance bundle. Whether Scorecard counts it is checked after the rc;
  if not, the score stays at 8. v0.1.0-alpha to v0.4.0 have neither file,
  so the score stays low until they leave the window.
- **`digests.txt`** (`<hex>  ghcr.io/o-kolomoiets/gosftpd:<tag>` per image
  tag, the subjects of the second attest step) is uploaded to the draft in
  the same step: GoReleaser writes it but registers no artifact, so it
  would not be uploaded otherwise, and nothing else in the release names
  the image digest. Users verify and run the image by that digest (see
  Verification by users). It is not in `checksums.txt`, which is written
  before the images are pushed; `cosign verify` with the exact identity,
  which names the tag, is what vouches for the digest it names.

### Workflows

All actions are pinned by commit with a version comment, as today. Every
workflow has `permissions: contents: read` at the top level and widens
permissions only at the job level, as ROADMAP §9.1 requires.

```yaml
# .github/workflows/release.yml
on:
  push:
    tags: ["v*"]                 # a signed tag pushed by the owner
  workflow_dispatch:             # tag.yml, on the tag's ref
permissions:
  contents: read
concurrency:
  group: release-${{ github.ref }}
jobs:
  verify-tag:                    # tag.yml's checks again, for any tag
    if: startsWith(github.ref, 'refs/tags/v')
    runs-on: ubuntu-24.04
    permissions:
      contents: read
      checks: read               # ci-ok on the tagged commit
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with: { fetch-depth: 0, persist-credentials: false }
      - run: ...                 # version format, on main, ci-ok green, CHANGELOG section, no published release
        env: { GH_TOKEN: "${{ github.token }}" }
  generate:                      # third-party tool code, without credentials
    needs: verify-tag
    runs-on: ubuntu-24.04
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with: { persist-credentials: false }
      - uses: actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e # v7.0.0
        with: { go-version: stable, check-latest: true, cache: false }
      - run: ...                 # go mod tidy -diff; SOURCE_DATE_EPOCH=$(git log -1 --format=%ct) go generate ./...; go-licenses
      - uses: actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9 # v7.0.2
        with: { name: out, path: out/ }
  release:
    needs: [verify-tag, generate]
    runs-on: ubuntu-24.04
    permissions:
      contents: write            # the draft release and its assets
      packages: write            # ghcr.io/o-kolomoiets/gosftpd
      id-token: write            # keyless cosign and actions/attest
      attestations: write
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with: { fetch-depth: 0, persist-credentials: false }
      - uses: actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e # v7.0.0
        with: { go-version: stable, check-latest: true, cache: false }   # no Actions cache
      - uses: actions/download-artifact@9000827ccba6bdab643e8b6fd33ac0654aef8333 # v8.0.2
        with: { name: out, path: out/ }
      - run: ...                 # mkdir -p out/docker/empty out/docker/home-root/home; go mod tidy -diff; go mod verify;
                                 # git status --porcelain empty; IS_LATEST into $GITHUB_ENV; CHANGELOG section > $RUNNER_TEMP/notes.md
      - uses: sigstore/cosign-installer@6f9f17788090df1f26f669e9d70d6ae9567deba6 # v4.1.2
        with: { cosign-release: v3.1.4 }
      - uses: anchore/sbom-action/download-syft@66cbf4bc1f1c0d2edc94016e65bc221b6bb0ad6c # v0.24.3
        with: { syft-version: v1.55.0 }
      - uses: docker/setup-buildx-action@f87e5991a6d7451dcb8d9637bfbc97413f497069 # v4.4.1
      - uses: docker/login-action@dbcb813823bdd20940b903addbd779551569679f # v4.6.0
        with: { registry: ghcr.io, username: "${{ github.actor }}", password: "${{ secrets.GITHUB_TOKEN }}" }
      - uses: goreleaser/goreleaser-action@a4f02ab5355a589de60d917a659ce617ed19b3de # v7.3.0
        with: { version: v2.19.0, args: "release --clean --skip=before --release-notes ${{ runner.temp }}/notes.md" }
        env: { GITHUB_TOKEN: "${{ secrets.GITHUB_TOKEN }}" }
      - id: attest
        uses: actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6 # v4.2.2
        with: { subject-checksums: dist/checksums.txt, create-storage-record: false }
      - uses: actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6 # v4.2.2
        with: { subject-checksums: dist/digests.txt, create-storage-record: false }
      - run: ...                 # copy the bundle to gosftpd_X.Y.Z.intoto.jsonl; gh release upload "$GITHUB_REF_NAME" it and dist/digests.txt
        env: { BUNDLE: "${{ steps.attest.outputs.bundle-path }}", GH_TOKEN: "${{ github.token }}", GH_REPO: "${{ github.repository }}" }
      - run: ...                 # the commands of docs/install.md against dist/ and the pushed image (below)
        env: { GH_TOKEN: "${{ github.token }}" }
```

- **No QEMU.** The Dockerfile has no `RUN`, so the arm64 image builds on
  an amd64 runner without emulation (verified with an empty
  `binfmt_misc`); `docker/setup-qemu-action` leaves the ROADMAP's list.
- **No Actions cache where a release is built.** setup-go v7.0.0 caches
  `go env GOMODCACHE` and `go env GOCACHE` by default (`cache: true`) under
  the key `setup-go-<OS>-<arch>-<ImageOS>-go-<version>-<hash of go.mod>`,
  without restore keys, and a run on a tag may restore the entries written
  on the default branch. That is exactly the entry of the `main` CI jobs on
  the same runner image and Go version (lint, interop, systemd, ssh-audit,
  goreleaser-check, test on 1.27.x) or of `fuzz.yml`, jobs that run
  third-party code: the golangci-lint binary, actionlint, pip, rclone and
  OpenSSH built from git, and from M5 go-licenses and gendocs. A build
  cache poisoned there would be compiled into binaries that are then
  signed and attested with the release identity; `go mod verify` notices a
  changed module cache, not a build cache. So the `generate` and `release`
  jobs set `cache: false`, as does the CI job `reproducible`, and the
  release job also runs `go mod verify`. `tag.yml` and
  `verify-release.yml` install no Go; a setup-go step added to either
  takes `cache: false` too. The switch is the setup-go input: actionlint
  v1.7.12 rejects the workflow key `cache-mode`.
- **`verify-tag`** (`contents: read`, `checks: read`; checkout with
  `fetch-depth: 0`) runs for every tag, however it arrived, and stops the
  run before anything is built when: `GITHUB_REF_NAME` does not match
  `^v[0-9]+\.[0-9]+\.[0-9]+(-(alpha|beta|rc)(\.[0-9]+)?)?$`; `git
  merge-base --is-ancestor "$GITHUB_SHA" origin/main` fails; the `ci-ok`
  check run on `$GITHUB_SHA` did not conclude `success` (`gh api
  "repos/$GITHUB_REPOSITORY/commits/$GITHUB_SHA/check-runs?check_name=ci-ok"`);
  CHANGELOG.md has no section for the version (a pre-release may use a
  non-empty Unreleased section instead); or `gh api
  "repos/$GITHUB_REPOSITORY/releases/tags/$GITHUB_REF_NAME"` returns 200.
  That endpoint returns only published releases, so a re-run onto the
  run's own draft still works (`replace_existing_draft`), while a re-run or
  a dispatch on a published release, which would push and sign a rebuilt
  image under `vX.Y.Z` (and `latest`) and then fail at upload, before the
  attest steps, stops here.
- **`generate`** (`contents: read` only, no `id-token`; setup-go `cache:
  false`) runs the before hooks: `go mod tidy -diff`,
  `SOURCE_DATE_EPOCH=$(git log -1 --format=%ct) go generate ./...` and the
  go-licenses command, and uploads `out/` as an artifact. GoReleaser runs
  hooks with the job's whole environment (`ctx.Env` from `os.Environ()`:
  `GITHUB_TOKEN`, the job-wide OIDC request variables, the GHCR login in
  `~/.docker/config.json`) and after its dirty-tree check, so a hook in
  the signing job could sign or alter the release, and stripping its
  environment would not help. go-licenses brings licenseclassifier/v2,
  klog, opencensus, groupcache, logr, otiai10/copy, sergi/go-diff and cobra
  v1.7.0, updated weekly by Dependabot; gendocs brings cobra/doc,
  go-md2man and blackfriday. None of it is needed to sign. The limit: man
  pages, the license file and the completions still go into the signed
  archives and packages, and completions are shell code that users run.
  They stay trusted output of those modules; the split protects the
  binary, the image and the release credentials.
- **`release`** (`needs: [verify-tag, generate]`) downloads `out/`,
  recreates `out/docker/empty` and `out/docker/home-root/home` (artifacts
  drop empty directories), runs `go mod tidy -diff` and `go mod verify`,
  checks that `git status --porcelain` is empty (`out/` is ignored), sets
  `IS_LATEST`, writes the notes and runs `goreleaser release --clean
  --skip=before` (`before` is a release skip key in v2.19.0). After the
  attest steps it uploads `.intoto.jsonl` and `digests.txt`.
- **Verification before Publish.** The last step runs the commands of
  "Verification by users" against local files: `cosign verify-blob` of
  `dist/checksums.txt` with `--certificate-identity
  "https://github.com/o-kolomoiets/Go-SFTP-Server/.github/workflows/release.yml@$GITHUB_REF"`
  (the literal repository name, not `$GITHUB_REPOSITORY`, so that the case
  is tested), `cosign verify` of `ghcr.io/o-kolomoiets/gosftpd@sha256:`
  and the digest from `dist/digests.txt` with the same identity, and `gh
  attestation verify` of the Linux amd64 archive and of `oci://` that
  digest with `--repo`, `--signer-workflow` and `--source-ref`. The job's
  GHCR login lets cosign read the package while it is still private. A
  wrong identity (the case, `job_workflow_ref` under a dispatch), a broken
  attest step or a regression in a GoReleaser or cosign upgrade (such as
  #7180's wrong digest) turns the run red before the owner publishes; once
  Immutable Releases are on (M6-05), a published release can no longer be
  repaired.
- **`tag.yml`** (`workflow_dispatch`, input `version`; the job runs only
  on `refs/heads/main`; top-level `permissions: contents: read`, the job
  `contents: write`, `actions: write`, `checks: read`). Every check runs
  before anything is created, because the tag ruleset makes a wrong tag
  permanent: the version matches
  `^[0-9]+\.[0-9]+\.[0-9]+(-(alpha|beta|rc)(\.[0-9]+)?)?$`; the tag does not
  exist yet; CHANGELOG.md has the version's section (a pre-release: or a
  non-empty Unreleased section); the `ci-ok` check run succeeded on
  `github.sha`, the commit the run started on. It then creates the
  annotated tag on that same commit, never on `main`'s head read again,
  which a merge in between could have moved to a commit whose `ci-ok` was
  not checked. It does so through the API (`git/tags`, then `git/refs`,
  tagger `github-actions[bot]`), so no credentials are persisted in a
  checkout, and runs `gh workflow run release.yml --ref vX.Y.Z`. Inputs
  reach the script through `env:`, never through `${{ }}` inside `run:`.
- **`verify-release.yml`** (`release: published`, and `workflow_dispatch`
  with a tag; top-level `permissions: contents: read`, the job adds
  `attestations: read`) installs cosign as above, downloads the release
  with `gh release download`, runs the commands of "Verification by users"
  with the literal identities and the digest from `digests.txt`, pulls the
  image anonymously by that digest (this fails while the GHCR package is
  still private) and checks that `docker run --rm IMAGE version` prints the
  tag. It sees what users see: the published assets and an anonymous pull.
- **`ci.yml`:**
  - `goreleaser-check` moves to v2.19.0, installs syft as above and runs
    `release --snapshot --clean --skip=sign` with `IS_LATEST=true`:
    snapshot mode skips publishing but not signing (`signs` and
    `docker_signs` run unless skipped), and `sboms` needs syft. It keeps
    the version check and the 12 MiB budget and adds: the archive check
    for `*_freebsd_*`; `dpkg-deb -c` and the conffiles (the needrestart
    file included), `dpkg-deb -f ... Depends` naming procps, `rpm -qp
    --configfiles`; `docker image inspect` for `User 65532:65532`, the
    health check, ports 2022 and 9090, `Cmd` `["serve"]` and
    `GOSFTPD_ATMOZ_IMAGE=1`; the compressed image size ≤ 15 MB; `git
    status --porcelain` empty after the hooks (a dirty tree shows as
    `+dirty` in the SBOM); the packages and `docker save` tarballs uploaded
    for the jobs below.
  - `reproducible` (Reproducible builds above).
  - `packages`: the DoD verbatim (`apt install`, `systemctl enable --now`,
    `is-active`, `sudo -u gosftpd gosftpd config validate --check-fs` run
    from `/` and from `/root`, `systemctl reload`) on the ubuntu-24.04 and
    ubuntu-24.04-arm runners themselves (systemd 255 is PID 1); in Debian
    12 and 13 containers built from `test/packages/` Dockerfiles with only
    systemd, systemd-sysv and sudo, so that `apt install ./gosftpd_*.deb`
    has to resolve `Depends: procps` (with procps in the image the check
    could not fail); on Debian 12 it also asserts that `dpkg -s procps`
    shows it installed, that the legacy drop-in is present and that
    `systemctl reload gosftpd` succeeds with the status "configuration
    reloaded"; in EL9 (`rockylinux/rockylinux:9-ubi-init`) and, optionally,
    Arch, also built from `test/packages/` Dockerfiles. An upgrade keeps
    the drop-in and a removal deletes it. On Ubuntu with needrestart
    installed (a standard server has it), an `apt install` upgrade leaves
    the service's `MainPID` unchanged. Per format, the archive layout of
    docs/install.md with an edited `config.toml`, followed by the package
    install as "From the archive install to a package" says, ends with the
    package configured (deb: `ii`), `config.toml` root:gosftpd still
    holding the edit and the service active. The job prints `stat -fc %T
    /sys/fs/cgroup`, since cgroup v2 on the runners is assumed.
  - `docker` on ubuntu-24.04 and ubuntu-24.04-arm (arm64 with real Landlock,
    no QEMU): the Quickstart verbatim under umask 002 as a non-root user,
    `healthy`, an sftp upload, the host key fingerprint after recreating
    the container; a reload: the configuration edited with `sed -i` (a new
    inode), `docker kill -s HUP`, and a user removed from it refused; exit
    2 and the hint without a configuration, then the hint's own commands
    followed to a working start; the compose example with `read_only`; the
    atmoz example, with a second upload of the same name that overwrites
    the file.
  - The three new jobs join `ci-ok`'s needs; stream C adds one fuzz-smoke
    entry (`FuzzAtmozSpec`).
- **Dependabot** gets `package-ecosystem: docker` with `directories:
  [/packaging/docker, /test/packages, /test/docker]`: the base image digest
  and the test images' digests. Every `FROM` under `test/` is pinned by
  digest (`debian:12@sha256:…`, `debian:13@sha256:…`, the EL9 and Arch
  images): Scorecard v5.6.0's Pinned-Dependencies matches `*Dockerfile*`
  anywhere in the repository but vendor directories and counts each `FROM`
  without `@sha256:` as an unpinned image, the criterion this ADR uses
  against slsa-github-generator. The score is already below 10 because of
  the `pip install` lines in ci.yml; this adds no new miss.

### Container image

`packaging/docker/Dockerfile`, not a root `Dockerfile`: it builds only from
GoReleaser's context (`$TARGETPLATFORM/gosftpd` and `extra_files`), so a
root file would mislead anyone running `docker build .`.

```dockerfile
FROM gcr.io/distroless/static-debian13:nonroot@sha256:d62067879de890a1def9da0e7766b7d20810a5e5555cef8506b752437d7a3e88
ARG TARGETPLATFORM
COPY --chmod=0755 $TARGETPLATFORM/gosftpd /usr/bin/gosftpd
# Owned by 65532, so that named volumes start with that owner and mode.
COPY --chown=65532:65532 --chmod=0700 out/docker/empty/ /var/lib/gosftpd/
COPY --chmod=0755 out/docker/empty/ /srv/
COPY --chown=65532:65532 --chmod=0750 out/docker/empty/ /srv/sftp/
# /home as an entry of the copied tree: COPY keeps the owner of a target
# directory that exists. For atmoz compatibility (/home/<user>/<dir>).
COPY --chown=65532:65532 --chmod=0755 out/docker/home-root/ /
# atmoz mode's container conventions: /home discovery, /etc/ssh host keys.
ENV GOSFTPD_ATMOZ_IMAGE=1
WORKDIR /
USER 65532:65532
EXPOSE 2022 9090
HEALTHCHECK --start-period=10s --start-interval=2s CMD ["/usr/bin/gosftpd","healthcheck"]
ENTRYPOINT ["/usr/bin/gosftpd"]
CMD ["serve"]
```

- **Base:** `gcr.io/distroless/static-debian13:nonroot`, pinned by its
  index digest of 2026-10-23 (amd64, arm64 and four other platforms). Its
  layers are 855,302 bytes compressed on amd64 (about 0.82 MiB) and
  3.3 MiB uncompressed, not the "about 2 MiB" of ROADMAP §9.4. The image is
  5.25 MB compressed on amd64 and 4.84 MB on arm64, against the 15 MB DoD.
- **`CMD ["serve"]`:** the search finds `/etc/gosftpd/config.toml`; when it
  finds no file, the atmoz sources are the only fallback (see atmoz
  compatibility). `--config` would make a missing file exit 2 and could
  not tell the image's own `CMD` from an operator's flag. `healthcheck`
  uses the same search.
- **`WORKDIR /`:** the base image's working directory `/home/nonroot` is
  0700 65532. With `--user "$(id -u):$(id -g)"`, which the ROADMAP offers,
  `healthcheck` failed on `./gosftpd.toml` with "permission denied" and the
  container was never healthy; with `WORKDIR /` it is healthy in
  3 s. The CLI fix below covers the same case outside Docker.
- **Directories owned by 65532:** a named volume starts with the
  owner and mode of the image's directory. Checked on Docker 29.8.2: a new
  volume on `/var/lib/gosftpd` was 0700 and on `/srv/sftp` 0750, both
  65532, so with named volumes the Quickstart needs no `chown` of the data
  and state directories; bind mounts still do. BuildKit gives the owner and mode of `COPY` to the parent
  directories it creates, so `/srv` is copied first as root 0755, and it
  leaves an existing target directory as it is, so `/home` comes as an
  entry of a tree. GoReleaser's `extra_files` carries the empty directories
  into the context (checked with a v2.19.0 snapshot).
- **The configuration is mounted as a directory**, `-v
  ./gosftpd:/etc/gosftpd:ro`, in the Quickstart, `docs/examples/compose.yaml`,
  install.md and the CLI hint. A single-file bind mount pins the host
  file's inode, and `sed -i`, or vim's default write, replaces the file
  with a new one: after `docker kill -s HUP` gosftpd parses the old
  content, logs "configuration reloaded" and keeps a user removed from the
  file able to log in (the mount reproduced with alpine:3.22, the stale
  reload end to end with gosftpd). With a directory mount the container
  sees the new file. The owner check reads only the file, not its
  directory, and under Landlock a directory that holds only `config.toml`
  stays dedicated. A missing host directory gives an empty `/etc/gosftpd`
  and so the "no configuration file found" hint, not the directory case.
- **No `VOLUME`:** an anonymous volume would hide a forgotten `-v`, and the
  host key would change with every new container; the documentation mounts
  both directories explicitly.
- **Health:** `--start-interval=2s` makes the container `healthy` within
  seconds instead of after the 30 s interval (3 s measured on Docker 29).
  Older engines are not checked: the documentation states Docker 25 or
  later.
- **Stop:** no `STOPSIGNAL`. `docker stop` waits 10 s, less than the 30 s
  `shutdown_timeout`; the documentation uses `--stop-timeout 40` and
  compose `stop_grace_period: 40s`.
- **Landlock** applies in the container: Docker's default seccomp profile
  allows the three `landlock_*` calls, and the log showed `landlock: ABI
  v5 applied`. Engines older than Docker 29 are not checked.
- **Port 2022** stays. Port 22 is mapped by the host (`-p 22:2022`); an
  image that relied on `net.ipv4.ip_unprivileged_port_start=0` would fail
  on Kubernetes.

### Packages

- **Formats: deb, rpm, archlinux.** apk is not built in v0.5.0:
  Alpine has no systemd, so the unit, sysusers and tmpfiles files do
  nothing there, and in the prototype apk installed without creating the
  user and left `config.toml` root:root. An apk package needs its own
  scripts (`addgroup -S`, `adduser -S`) and an OpenRC service, about 0.5–1
  person-day, and can come later. Alpine users take the archive or the
  image.
- **Maintainer:** the literal `gosftpd maintainers`, with no email
  address and no repository variable (the `NFPM_MAINTAINER` variable of
  ROADMAP §9.3 is dropped). `dpkg -i` accepts it (Debian 12 and 13);
  lintian was not run.

```yaml
nfpms:
  - id: packages
    ids: [gosftpd]
    package_name: gosftpd
    formats: [deb, rpm, archlinux]
    maintainer: gosftpd maintainers
    vendor: gosftpd
    homepage: https://github.com/o-kolomoiets/go-sftp-server
    license: Apache-2.0
    description: SFTP drop-box server with an audit log
    section: net
    bindir: /usr/bin
    mtime: "{{ .CommitDate }}"
    contents:   # the table below; every entry has file_info { mode, mtime: "{{ .CommitDate }}" }
    scripts:
      postinstall: packaging/scripts/postinstall.sh
      preremove: packaging/scripts/preremove.sh
      postremove: packaging/scripts/postremove.sh
    archlinux:
      packager: gosftpd maintainers
      scripts:
        postupgrade: packaging/scripts/postinstall.sh   # pacman runs post_upgrade, not post_install, on an upgrade
    rpm:
      buildhost: gosftpd
    overrides:
      deb:
        dependencies: [procps]
```

| Path | Source and notes |
|---|---|
| `/usr/bin/gosftpd` | the build, 0755 |
| `/usr/lib/systemd/system/gosftpd.service` | `packaging/systemd/gosftpd.service` |
| `/usr/lib/sysusers.d/gosftpd.conf` | `packaging/gosftpd.sysusers` |
| `/usr/lib/tmpfiles.d/gosftpd.conf` | `packaging/gosftpd.tmpfiles` |
| `/usr/share/gosftpd/legacy-notify.conf` | `packaging/systemd/legacy-notify.conf`, an inactive template that postinstall copies |
| `/etc/gosftpd/config.toml` | `packaging/config.toml`, `type: config\|noreplace`, 0640 (a conffile in deb, `%config(noreplace)` in rpm, `backup` in Arch). Packages carry owner names, and the group does not exist at unpack time, so the file lands root:root and postinstall changes the group |
| `/etc/gosftpd/users.d/` | `type: dir`, 0750, group changed by postinstall. Without it the first `user add --write` needs a restart under Landlock, because the include directory did not exist at start (reproduced) |
| `/etc/needrestart/conf.d/gosftpd.conf` (deb only, `packager: deb`) | `packaging/needrestart.conf`, `type: config\|noreplace`, 0644: `$nrconf{override_rc}{qr(^gosftpd\.service$)} = 0;` (see below) |
| `/usr/share/doc/gosftpd/config.example.toml` | `internal/config/example-full.toml` (§6.6) |
| `/usr/share/doc/gosftpd/LICENSE`, `THIRD_PARTY_LICENSES` | `LICENSE`, `out/THIRD_PARTY_LICENSES` |
| `/usr/share/man/man1/*.1.gz` | `out/man/*.1.gz` (nfpm expands the glob) |
| `/usr/share/bash-completion/completions/gosftpd` | `out/completions/gosftpd.bash` |
| `/usr/share/fish/vendor_completions.d/gosftpd.fish` | `out/completions/gosftpd.fish` |
| `/usr/share/zsh/vendor-completions/_gosftpd` (deb), `/usr/share/zsh/site-functions/_gosftpd` (rpm, Arch) | `out/completions/_gosftpd`, one entry per `packager`; that each distribution's zsh searches these is not checked |

- **postinstall** (deb `postinst`, rpm `%post`, Arch `post_install` and
  `post_upgrade`), `set -e`, each tool guarded by `command -v` so that the
  script never fails where systemd is missing (containers, image
  builds): `systemd-sysusers gosftpd.conf`; `systemd-tmpfiles --create
  gosftpd.conf`; when the group `gosftpd` exists, `chgrp gosftpd` on
  `/etc/gosftpd/config.toml` and `/etc/gosftpd/users.d` if their group is
  still root (an administrator's choice of group is kept); the offline
  `Type=notify-reload` probe of ADR 0011 (`systemd-analyze verify
  --man=no`), which installs `/usr/share/gosftpd/legacy-notify.conf` as
  `/etc/systemd/system/gosftpd.service.d/legacy-notify.conf` where the type
  is unknown and removes it elsewhere (also after systemd was upgraded);
  `systemctl daemon-reload || true` when `/run/systemd/system` exists.
- **The scripts never enable, start or restart the service.** The operator
  enables it (the DoD runs `systemctl enable --now gosftpd`) and restarts
  it after an upgrade (docs/operations.md): a restart ends every session,
  and a new version that rejects the configuration exits 2, which systemd
  does not retry.
- **needrestart (Ubuntu).** On Ubuntu 24.04, one of the DoD platforms, a
  standard server has needrestart (ubuntu-server recommends it). Its apt
  hook (`DPkg::Post-Invoke`, `apt-pinvoke -m u`) runs in mode `u`, which
  restarts every service whose binary was replaced unless the
  administrator chose another mode (needrestart 3.6-7ubuntu4.5, read from
  the noble package). So `apt install ./gosftpd_*.deb` of a new version
  would restart gosftpd at once, which the decision above rules out; a
  plain `dpkg -i` does not run the hook. The deb ships
  `/etc/needrestart/conf.d/gosftpd.conf`, which needrestart reads after
  its main configuration: `override_rc` = 0 puts `gosftpd.service` on its
  skip list. The file does nothing where needrestart is not installed, and
  an operator who wants the restart edits or deletes it (a conffile, so an
  upgrade keeps that choice). docs/operations.md names it in the Ubuntu
  notes.
- **preremove** stops and disables the service on a removal, not on an
  upgrade: deb passes `upgrade` and rpm passes `1` then, and pacman runs
  `pre_remove` only for a removal.
- **postremove** deletes the drop-in (and its directory when empty) only
  when `/usr/lib/systemd/system/gosftpd.service` no longer exists, then
  reloads systemd. The test is on the file, not on `$1`: on an upgrade rpm
  runs the new package's `%post`, then the old one's `%preun` and
  `%postun` (seen with `rpm -vv` on EL9), so an unconditional postremove
  (ROADMAP §9.4) would delete the drop-in the new postinstall just
  installed; and nfpm pastes the script verbatim into the Arch package's
  `post_remove()`, which pacman calls with the old version, so a `case
  "$1" in remove|purge|0` would never match there. Checked: on Debian 12
  the drop-in survived a reinstall as an upgrade and was gone after
  `dpkg -r`, with the service stopped; on Rocky 9 and Arch the service
  survived the upgrade and was stopped on removal, which also deleted a
  drop-in placed there by hand (on Arch the `multi-user.target.wants` link
  was gone too).
- **What a removal keeps differs by format.** The data, the host keys and
  the audit log (`/srv/sftp`, `/var/lib/gosftpd`, `/var/log/gosftpd`)
  belong to no package and stay everywhere. deb: `apt remove` keeps
  `config.toml` and `users.d` until `apt purge`. rpm and Arch: a removal
  renames an edited `config.toml` to `config.toml.rpmsave` or
  `config.toml.pacsave` (rpm and pacman print a warning) and deletes an
  unedited one; `users.d` stays while it holds files, and Arch removes it
  when empty. After a removal and a new install the packaged default is
  back, so the saved file is moved back before the service starts. An
  upgrade or downgrade done as one transaction (`rpm -U`, `dnf`, `pacman
  -U`) keeps the edited file. docs/install.md states this per format and
  what to delete for a complete removal.
- **From the archive install to a package.** docs/install.md promises
  that the packages take over the v0.4 archive layout; as files that no
  package owned, the move needs one step per format (reproduced with the
  prototype packages):
  - deb: `sudo apt-get -o Dpkg::Options::=--force-confold install
    ./gosftpd_*.deb`, or answer N at the prompt. Without it, an edited
    `config.toml` makes dpkg prompt ("File on system created by you or by
    a script"), and without a terminal (CI scripts; `DEBIAN_FRONTEND` does
    not affect this prompt) the install fails with the package unpacked
    and postinst not run. `--force-confold` keeps the administrator's file
    and leaves `config.toml.dpkg-dist`; after a failed run, `sudo dpkg
    --force-confold --configure -a` finishes it. An unedited file causes
    no prompt (`packaging/config.toml` has not changed since v0.4.0), but a
    later release that changes it prompts in the same way for an edited
    file. Ansible's apt module passes `force-confdef,force-confold` by
    default.
  - rpm: no flag; rpm replaces the unowned files in `/usr`, keeps the
    edited `config.toml` and writes `config.toml.rpmnew`.
  - Arch: `pacman -U` refuses the unowned files ("conflicting files");
    `sudo pacman -U --overwrite /usr/bin/gosftpd --overwrite
    /usr/lib/systemd/system/gosftpd.service --overwrite
    /usr/lib/sysusers.d/gosftpd.conf --overwrite
    /usr/lib/tmpfiles.d/gosftpd.conf gosftpd-*.pkg.tar.zst`, or delete
    those four files first; it keeps the edited `config.toml` and writes
    `config.toml.pacnew`.
  - All formats: `sudo rm /usr/local/bin/gosftpd` if it exists (it comes
    first in `PATH`); the legacy drop-in stays, since postinstall manages
    it.
- **Leftover configuration files.** Upgrades can leave
  `config.toml.dpkg-dist`, `.dpkg-old`, `.rpmnew` or `.pacnew`, and
  removals `.rpmsave` or `.pacsave`, in `/etc/gosftpd`. Their names begin
  with `config.toml`, so Landlock counts them as named entries (ADR 0011:
  "beginning with it, as config.toml~") and they do no harm. They hold the
  package's newer defaults or the saved configuration; docs/operations.md
  says to merge and delete them.
- **deb `Depends: procps`:** the legacy drop-in's `ExecReload` calls
  `/bin/kill`, which minimal Debian 12 lacks: `reload` failed with
  203/EXEC. The lint job stubs `/usr/bin/kill` and did not catch it; the
  `packages` job's Debian images therefore lack procps, and
  `goreleaser-check` reads the deb's `Depends`.
- **The unit** gets `Documentation=man:gosftpd(1)` before the install.md
  URL, now that the page is installed (amends ADR 0011; the lint passes
  `--man=no`).

### Man pages, completions and licenses

- **Generator:** `internal/cli/gendocs`, a `package main` in the main
  module that imports the root command, exported as `cli.NewRootCommand()`
  (today `newRootCmd`). A generator under `tools/` cannot import
  `internal/`. `internal/cli/doc.go` holds `//go:generate go run ./gendocs
  ../../out`; the before-hook runs `go generate ./...` with
  `SOURCE_DATE_EPOCH`, which cobra's `GenManTree` uses for the page date
  (the hook string is templated and split with shellwords, hence `sh -c`).
  In a release the `generate` job runs the same commands.
- **Output:** `out/man/*.1.gz` (one page per command, 20 in the prototype),
  compressed with `compress/gzip` with no name and a zero time, so no
  external `gzip -n`; `out/completions/gosftpd.bash`, `_gosftpd` and
  `gosftpd.fish` from cobra's `Gen*Completion` functions, not by running a
  binary of the host's architecture. `DisableAutoGenTag` is set. Output is
  deterministic for a fixed date.
- **Cost:** go.mod gains go-md2man/v2 v2.0.6, blackfriday/v2 v2.1.0,
  go.yaml.in/yaml/v3 v3.0.4 and kr/text v0.2.0 as indirect requirements;
  none is linked into gosftpd (`go version -m` is unchanged), but they
  enter govulncheck's source scan.
- **`THIRD_PARTY_LICENSES`:** `go get -tool
  github.com/google/go-licenses/v2@v2.0.1` in tools/go.mod (it brings
  licenseclassifier/v2, klog and others and raises x/net to v0.61.0). The
  template `packaging/third_party_licenses.tpl` prints each module's name,
  version, license name and `.LicenseText`, never `.LicenseURL`: the URL
  lookup goes online (20 s timeout) and writes "Unknown" when it fails.
  go-licenses lists libcap/psx twice, as BSD-3-Clause and as GPL-2.0; the
  template prints it once, under BSD-3-Clause, the choice docs/DEPENDENCIES.md
  records. The hook sets `GOOS=linux`, so that the file is the same on
  every host (on darwin, go-landlock and psx drop out), and `GOROOT`, without
  which an installed go-licenses failed on every standard-library package.
  One file serves every archive: for darwin and FreeBSD it lists two
  modules too many, which is harmless. Output is deterministic.

### CLI changes

- **`config.Find` and an unreadable working directory.** Today any `stat`
  error other than "not found" on a search path candidate is fatal. A
  permission error (`EACCES`, `EPERM`) on the relative `./gosftpd.toml`
  now counts as "not found", and the search goes on to
  `/etc/gosftpd/config.toml`. `--config`, `$GOSFTPD_CONFIG` and the
  absolute candidates stay strict. This fixes `healthcheck` under `--user`
  and the DoD command `sudo -u gosftpd gosftpd config validate
  --check-fs`, which exits 2 with "stat gosftpd.toml: permission denied"
  when run from `/root` (reproduced on Debian 12).
- **A missing configuration file gets a hint, still with exit 2.** When
  `--config` or `$GOSFTPD_CONFIG` names a path that does not exist, or a
  directory, or a search finds no file (and atmoz mode has no users), the
  error says what to do instead of only "stat ...: no such file or
  directory". The hint leads to a working start, not to the next exit 2:
  it names the key placeholder and the owner and mode the §6.5 check
  wants, mounts a directory (see Container image) and links the Docker
  section of docs/install.md, which has the whole Quickstart:

  ```text
  Error: no configuration file found (./gosftpd.toml, /etc/gosftpd/config.toml, ~/.config/gosftpd/config.toml)
  Create one with 'gosftpd config example > config.toml' and replace the key placeholder.
  With Docker, keep it in a directory and mount the directory:
    mkdir gosftpd && docker run --rm ghcr.io/o-kolomoiets/gosftpd:v0.5.0 config example > gosftpd/config.toml
    sudo chown root:65532 gosftpd/config.toml && sudo chmod 0640 gosftpd/config.toml
    docker run ... -v ./gosftpd:/etc/gosftpd:ro ...
  See https://github.com/o-kolomoiets/Go-SFTP-Server/blob/v0.5.0/docs/install.md#docker
  ```

  For `--config` the first line reads "--config: /etc/gosftpd/config.toml
  does not exist". For a directory: "... is a directory: Docker creates one
  when the host file of a bind mount does not exist. Remove it on the host
  (`sudo rmdir ./config.toml`) and mount a directory instead", followed by
  the same lines (the directory case was reproduced). The image tag and
  the link name the binary's own version, or `latest` and `main` for a
  development build. The `docker` CI job follows the hint's commands.
- **`cli.NewRootCommand()`** is exported for the generator.

### `serve --ephemeral`

For persona U3: a throwaway server for tests, with the details on stdout.

- **Flags.** `--ephemeral` conflicts with `--config`, `--users-conf`,
  `--authorized-keys`, `--user`, `--host-key` and `--state-dir`.
  `$GOSFTPD_CONFIG` and `$GOSFTPD_LISTEN` are ignored with a warning, and
  `SFTP_USERS` and `/etc/sftp/users.conf` are not read (see atmoz
  compatibility). `--listen` may be given once and defaults to
  `127.0.0.1:0`; the JSON describes exactly that listener. One `--dir
  PATH` may name the data directory; without it the data lives in
  `DIR/data` of a new `os.MkdirTemp` directory. `--read-only`,
  `--on-conflict`, the log flags and `--audit-output` (a path; `stdout` is
  refused) work as for `serve`.
- **Credentials.** One user, `test`, with `full` access to the single mount
  (flattened: the data directory is `/`). Both a random password (24 random
  bytes, base64url; its argon2id hash only in memory) and a generated
  ed25519 client key, written 0600 as `DIR/id_ed25519`: OpenSSH `sftp` in
  CI needs the key, libraries prefer the password. The host key is
  generated in memory and never written.
- **Output.** Exactly one JSON line on stdout, printed after the sandbox
  step and once the listener serves, just before the server reports ready
  (`health.SetReady`); a failure before that exits 1 without printing it.
  Then nothing else on stdout:

  ```json
  {"host":"127.0.0.1","port":40123,"user":"test","password":"…","private_key_path":"/tmp/gosftpd-ephemeral-123/id_ed25519","dir":"/tmp/gosftpd-ephemeral-123/data","host_key_fingerprint":"SHA256:…","known_hosts":"[127.0.0.1]:40123 ssh-ed25519 AAAA…","pid":4242,"version":"v0.5.0"}
  ```

  `host` is the listen address's host, or `127.0.0.1` when it is
  unspecified; `port` and `pid` are numbers; `dir` is the host path of the
  mount; `known_hosts` is a line for `UserKnownHostsFile`. Fields may be
  added later, never removed or renamed (the M6 compatibility contract).
- **Logs** and the audit log go to stderr; today audit defaults to stdout,
  which would mix with the JSON.
- **Reload.** SIGHUP is logged and otherwise ignored: building the
  configuration again would generate a new password, client key and host
  key, which breaks connected clients and their known_hosts line.
- **Stop.** On SIGINT or SIGTERM gosftpd stops as `serve` does and deletes
  the client key and the data directory (never a `--dir` directory).
  Under Landlock (Linux, `landlock = "auto"` by default) that needs a rule:
  removing an entry is a right of the directory that holds it, so the
  planner adds the remove-file and remove-dir rights on `DIR`, which
  gosftpd created and which holds only `data/` and the key. `DIR` itself
  then stays, empty: removing it would need remove-dir on `$TMPDIR`, which
  would let gosftpd remove other empty directories there. Without Landlock
  `DIR` is removed too. A killed process leaves everything in `$TMPDIR`.
  An e2e test on Linux checks that the key and `data/` are gone after
  SIGTERM; docs/security.md lists the rule.
- **Root.** The refusal to run as root stays; its hint names
  `--allow-root`, which CI containers running as root need.
- **Docs** show a GitHub Actions step that waits for the line and passes
  the password through `::add-mask::`. **In a container** `127.0.0.1:0` is
  unreachable from outside and `private_key_path` is a container path: the
  docs show the atmoz specs for testcontainers and similar tools, or
  `--ephemeral --listen 0.0.0.0:2022` with the port mapped (the JSON's
  `port` is the container's) and the key read with `docker exec` or
  through a bind-mounted `$TMPDIR`.

### atmoz compatibility

For persona U1 moving from atmoz/sftp, whose image takes users as arguments,
from `SFTP_USERS` and from `/etc/sftp/users.conf`.

- **Sources.** Specs given as arguments to the root command (what `docker
  run IMAGE foo:pass:::upload` passes: the arguments replace `CMD`), the
  space-separated `$SFTP_USERS`, and a users file (`--users-conf FILE`,
  default `/etc/sftp/users.conf` when it exists; blank lines and `#`
  comments skipped), combined in atmoz's order: the users file, the
  arguments, then `SFTP_USERS`. The root command treats its arguments as
  specs when the first matches atmoz's own test `^[^:[:space:]]+:.*$`; then
  every argument must be a valid spec. Anything else stays an unknown
  command with exit 2 (today the root command accepts no arguments). The
  root form is `serve` with these users and takes the flags that apply in
  atmoz mode (below).
- **Mode selection.** `--config` and `$GOSFTPD_CONFIG` stay strict
  everywhere: a path that does not exist always exits 2 with the hint
  above, never atmoz mode, so a mistyped path cannot start the old
  plaintext-password users. Atmoz mode starts in two cases only:
  - specs are given as arguments; a configuration file that the search
    finds or `$GOSFTPD_CONFIG` names is then ignored, with a warning that
    names it;
  - `serve` finds no configuration file, neither `--dir` nor `--ephemeral`
    is given, and `--users-conf`, `SFTP_USERS` or `/etc/sftp/users.conf`
    provides users; with none, it exits 2 with the hint.

  The image's `CMD ["serve"]` uses the search, so a mounted
  `/etc/gosftpd/config.toml` wins and its absence is the only way into
  atmoz mode. The implicit sources (`SFTP_USERS`, the default
  `/etc/sftp/users.conf`) are read only in atmoz mode; when a
  configuration file is used, or `--dir` or `--ephemeral` is given, they
  are ignored with a warning that names the source and never prints its
  value. `--users-conf` with a configuration file, `--dir` or
  `--ephemeral` is an error (exit 2), as are `--authorized-keys` and
  `--user` in atmoz mode. In atmoz mode `--listen`, `--host-key`,
  `--state-dir`, `--read-only`, `--on-conflict`, `--allow-root` and the log
  and audit flags apply. gosftpd logs that it runs in atmoz mode, with the
  number of users per source.
- **Image conventions.** Two of atmoz's container conventions apply only
  in the image, which sets `ENV GOSFTPD_ATMOZ_IMAGE=1`: directories that
  exist under `/home/<user>` at start become that user's mounts, and
  `/etc/ssh/ssh_host_ed25519_key` and `/etc/ssh/ssh_host_rsa_key` are used
  as host keys. On a host with real home directories, the first would
  expose a home's subdirectories over password logins on all interfaces,
  and the second would serve sshd's own identity as root or fail as
  anyone else (those keys are root's, 0600). Outside the image atmoz specs
  mount only the directories they name, and host keys come from
  `--host-key` or the state directory as usual. The packaged unit never
  reaches atmoz mode: it passes `--config` (and `ProtectHome=yes` hides
  `/home`). docs/migrate-from-atmoz.md says so.
- **Syntax:** `user:pass[:e][:uid[:gid[:dir1[,dir2]...]]]`, split as
  atmoz's `create-sftp-user` splits it.
  - **user** must be a gosftpd name, `^[a-z0-9][a-z0-9._-]{0,31}$`; atmoz
    also accepts upper case and a leading `.` or `_`, which are refused. A
    user given twice is skipped with a warning, as atmoz skips it: the
    first definition wins, in the source order above.
  - **pass:** up to 255 characters without `:`; empty means no password
    login for that user (keys only). A plain password is hashed with
    argon2id at start, in memory.
  - **`:e`** marks a hash. Accepted are the hashes gosftpd verifies:
    argon2id (`$argon2id$`) and bcrypt (`$2a$`, `$2b$`, `$2y$`, cost 10 to
    14). MD5-crypt (`$1$`, the atmoz README's example), SHA-crypt (`$5$`,
    `$6$`, Python's `crypt` default) and yescrypt are refused with "create
    a hash with 'gosftpd user hash-password'".
  - **uid and gid** are ignored, with one info line: the users are
    virtual, and files belong to the user gosftpd runs as.
  - **dirs:** each must be a valid mount name (§6.1 item 3), not `.ssh`;
    nested directories (`a/b`), which atmoz creates, are refused.
  - **Errors and warnings never print a password.** They name the source
    and position (argument 2, `SFTP_USERS` entry 3, `/etc/sftp/users.conf`
    line 4), the user name when it parses, and the field that is wrong;
    never the pass field or the raw spec, which atmoz itself logs
    ("Parsing user data"). stderr reaches `docker logs`, log shippers and
    journald, a wider audience than `docker inspect`. The same holds for
    the warnings about ignored sources and plain passwords.
- **Layout as in atmoz:** user `foo` with directory `upload` sees
  `/upload`, stored in `/home/foo/upload`, so atmoz-style volumes
  (`-v ./upload:/home/foo/upload`) work unchanged. A user's directories are
  those its spec names plus, in the image, every directory that exists
  directly under `/home/<user>` at start, other than `.ssh`: atmoz's own
  volume examples (`foo:pass:1001` with `-v <host-dir>/upload:/home/foo/upload`)
  name no directory. Each directory name becomes one mount, `[mounts.upload]
  path = "/home/{user}/upload"` with `create = true`; each user that has the
  directory gets `full` on it, and `flatten = false`, so the top level is
  the synthetic read-only root, as atmoz's root-owned home is, and
  `/home/<user>/.ssh` is never reachable. The image's `/home` belongs to
  65532 so that `foo:pass:::upload` works without a volume. The edge
  cases, each with a table or e2e test:
  - **A user without directories** (atmoz's users-file example,
    `foo:123:1001:100` with `-v mySftpVolume:/home`, on a fresh volume) is
    allowed with a warning and logs in to an empty read-only root, as in
    atmoz. In atmoz mode no mount at all is not the "no mounts configured"
    error.
  - **Names.** An auto-discovered directory whose name is not a valid
    mount name (`_data`, `lost+found`, a dot name, a non-ASCII or device
    name) is skipped with a warning; an invalid name in a spec is an error
    that names the user and the directory. Mount names are unique ignoring
    case, so `Upload` for one user and `upload` for another, from specs or
    from the disk, are an error that names both.
  - **A directory that cannot be created** is logged at start with the
    user, the directory and the fix, and that mount is unavailable for the
    user; the others work. Docker creates the parent of a volume mount
    point (`/home/foo`) as root 0755, so a second spec directory without a
    volume of its own cannot be created by 65532: the fix is a volume for
    it, or `chown 65532` of `/home/foo`.
- **`{user}` before the last path component.** Today `{user}` may only be
  the whole last component of a mount path, and mount names are global, so
  `/home/{user}/upload` cannot be written. `{user}` may now also be a whole
  earlier component. It is an ordinary configuration feature, documented in
  docs/configuration.md, since atmoz mode builds an ordinary configuration.
  The path splits into a prefix (the components before `{user}`, `/home`)
  and a suffix (those after it, `upload`); an empty suffix is today's home
  mount, whose rules do not change.
  - **One helper.** `vfs.SplitUserPath(p) (prefix, suffix string, ok
    bool)` replaces every `filepath.Base(p) == vfs.UserPlaceholder`
    comparison (seven today: sandbox/reload.go, sandbox/rules.go,
    sandbox/preview.go, config/checkfs.go twice, cli/serve.go and
    vfs/mounts.go). A site that is missed would treat
    `/home/{user}/upload` as a literal path: `PathsOverlap` misses it, and
    `insideMount`, whose `EvalSymlinks` fails on the literal path, would
    silently accept a key file inside a writable mount. A test fails when
    a raw comparison with `UserPlaceholder` appears outside the helper.
    `--dir` refuses `{user}` anywhere in its path.
  - **Opening.** For a session, `<prefix>/<user>/<suffix>` is opened one
    component at a time, as a home mount's directory is today: each a real
    directory, not a symlink, else the mount is unavailable with
    `home_not_dir`; created 0750 with `create = true`.
  - **State per mount.** Mounts with the same prefix share no state: the
    open directory (`t.dirs`, today shared by path) and the per-user
    registry entries (`userKey{dir, rel}`, with `rel` relative to the
    user's directory: owned uploads, `stat_redirect` targets) are keyed by
    mount, so that `foo`'s `upload/report.pdf` and `data/report.pdf` never
    collide. Today this cannot happen, because two mounts on one path are
    refused as overlapping.
  - **Overlap.** Two `{user}` mounts with the same prefix overlap when
    their suffixes overlap: equal, or one inside the other; an empty
    suffix overlaps every suffix. So `/home/{user}/a` and `/home/{user}/b`
    do not overlap, while `/home/{user}` with `/home/{user}/x` and
    `/home/{user}/a` with `/home/{user}/a/b` do. Mounts with different
    prefixes, and a plain mount against a `{user}` mount, keep today's rule
    against the directory a `{user}` mount occupies, its prefix. Nested
    mounts stay an error because each has its own `read_only`,
    `on_conflict`, `atomic_uploads` and permissions, which the outer one
    would bypass. `PathsOverlap` gets table and fuzz cases for these.
  - **Trusted files.** The rule that trusted files may not lie inside a
    mount compares against the per-user paths `<prefix>/<user>/<suffix>`,
    so `/home/<user>/.ssh/keys/*` stays allowed.
  - **Landlock.** Such a mount gets rules per user known at start, not a
    rule on its prefix: a rule with the mount's rights on `/home` would
    make every key file under it writable to gosftpd, against ADR 0011's
    "no configuration or key file is ever writable". The rules are the
    mount's rights on `<prefix>/<user>/<suffix>` and read-dir on the
    directories from `<prefix>/<user>` down to it (`os.Root` opens each
    component as a directory, which Landlock checks as read-dir; read-dir
    alone lists names but reads and writes no file). A rule needs an
    existing path, so with `create = true` these directories are created
    at start for the users known then, before the sandbox, as atmoz
    creates them at container start. A user added by a reload gets the
    mount only after a restart (`restart_required` names it); atmoz itself
    creates users only at start. This amends ADR 0011's rule table, and
    docs/security.md describes it.
- **Keys:** every file in `/home/<user>/.ssh/keys/` is read as an
  `authorized_keys` file, after the usual permission check (§6.5:
  owned by root or by the user gosftpd runs as, not writable by group or
  others), as for the users file; a key bind-mounted from a host user's
  home must be `chown root` first. The guide says so. A user has one
  `authorized_keys_file` in the configuration, so the atmoz loader inlines
  the keys and lists the files in an internal list of trusted files that
  `checkTrusted` and the Landlock planner read: the "not inside a mount"
  rule and a read rule apply to them as to any key file, and none is
  writable. The users file joins the configuration's own files (`c.Files`)
  in the same way, so it has a rule too.
- **Host keys:** in the image, `/etc/ssh/ssh_host_ed25519_key` and
  `/etc/ssh/ssh_host_rsa_key` are used when they exist, so clients keep
  their known_hosts entry after the migration; like every host key they
  must belong to the user gosftpd runs as (65532) with mode 0600 (the
  guide shows the `chown`). Otherwise the key is
  `/var/lib/gosftpd/ssh_host_ed25519_key`, generated on first start as in
  the Quickstart.
- **An upload to an existing name overwrites it**, as OpenSSH's `put`
  does: atmoz mode sets `on_conflict = "overwrite"` (`full` includes the
  overwrite permission). gosftpd's default, `rename`, would turn a nightly
  backup or a scanner that writes the same name into numbered copies until
  `min_free_space` stops them. `--on-conflict` and `--read-only` change it
  as they would with a file.
- **Warnings at start:** a plain password from the arguments or from
  `SFTP_USERS` is visible to anyone who can run `docker inspect` or read
  the process's command line or environment (ROADMAP §6.7 never takes
  a password as an argument): a warning names the source and position and
  points to `:e` with an argon2id hash or to keys. When plain and hashed
  passwords are mixed, the warning `config validate` gives for hashes of
  different classes is logged too.
- **Port 2022:** the container listens on 2022, so atmoz's `-p 22:22`
  becomes `-p 22:2022` and `-p 2222:22` becomes `-p 2222:2022`. The DoD
  says "the user spec `foo:pass:::upload` works unchanged".
- **Ownership:** files on host volumes belong to 65532, not to the spec's
  uid; the guide shows `chown 65532` of the host directory, or
  `--user UID:GID` with a state volume that UID can write, which gives
  atmoz's ownership back.
- **Audit and reload.** Audit goes to stdout, as with `config example`. A
  reload (SIGHUP) reads the users file and the key directories again.
  `.ssh/keys` holds only key files, so under ADR 0011's rules it is a
  dedicated directory with a read rule, and a new key file there needs no
  restart. A new user, a new directory, or a users file replaced by rename
  in a shared directory needs one (`restart_required`).
- **Tests:** `FuzzAtmozSpec` on the parser (CI smoke and nightly), which
  also asserts that no error or warning contains the pass field; the
  `PathsOverlap`, `checkTrusted` (keys inside and outside
  `/home/<user>/<dir>`) and helper tests above; a vfs test that uploads
  the same name to two `{user}` sibling mounts under `rename` and
  `stat_redirect`; e2e tests with the README examples (arguments,
  `SFTP_USERS`, users file, a user without directories, `:e` with bcrypt,
  keys, an existing volume directory), a user given twice and a second
  upload of the same name; and the `docker` CI job.
  docs/migrate-from-atmoz.md maps every atmoz example. It also shows `$$`
  for each `$` of an `$argon2id$` or `$2b$` hash in compose `command:` and
  `environment:`, and `htpasswd -bnBC 10 "" PASS` (htpasswd's default
  bcrypt cost, 5, is below gosftpd's minimum of 10) or `gosftpd user
  hash-password`.

### Verification by users

docs/install.md, linked from SECURITY.md ("Verifying releases"), gives
these commands; `release.yml` runs them before the owner publishes and
`verify-release.yml` on every published release.

```sh
V=0.5.0
ID="https://github.com/o-kolomoiets/Go-SFTP-Server/.github/workflows/release.yml@refs/tags/v$V"
gh release download "v$V" -R o-kolomoiets/Go-SFTP-Server -p checksums.txt \
  -p checksums.txt.sigstore.json -p digests.txt -p "gosftpd_${V}_linux_amd64.tar.gz"
cosign verify-blob --certificate-identity "$ID" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --bundle checksums.txt.sigstore.json checksums.txt
sha256sum --check --ignore-missing checksums.txt
gh attestation verify "gosftpd_${V}_linux_amd64.tar.gz" --repo o-kolomoiets/Go-SFTP-Server \
  --signer-workflow o-kolomoiets/Go-SFTP-Server/.github/workflows/release.yml --source-ref "refs/tags/v$V"
IMAGE="ghcr.io/o-kolomoiets/gosftpd@sha256:$(awk -v t="ghcr.io/o-kolomoiets/gosftpd:v$V" '$2 == t { print $1 }' digests.txt)"
cosign verify --certificate-identity "$ID" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com "$IMAGE"
gh attestation verify "oci://$IMAGE" --repo o-kolomoiets/Go-SFTP-Server \
  --signer-workflow o-kolomoiets/Go-SFTP-Server/.github/workflows/release.yml --source-ref "refs/tags/v$V"
# then run "$IMAGE", the reference just verified, not the tag
```

- The identity must be typed exactly: `o-kolomoiets/go-sftp-server` (the
  spelling ROADMAP §9.5 and SECURITY.md use) fails. Packages are covered
  by `checksums.txt` like archives.
- **gh is pinned like cosign.** `--repo` alone accepts a provenance signed
  by any workflow on any ref of the repository (gh 2.89.0's help says to
  add `--signer-workflow` or `--cert-identity`): `scorecard.yml` has
  `id-token: write` and runs `ossf/scorecard-action`'s image by the mutable
  tag `v2.5.0`, so that image could mint a certificate for
  `.../scorecard.yml@refs/heads/main` and sign a bundle that `--bundle
  ... --repo` accepts. `--signer-workflow` and `--source-ref` bind the
  attestation to `release.yml` and the tag, as the cosign identity does.
- **Without the attestations API**, `gh attestation verify FILE --bundle
  gosftpd_${V}.intoto.jsonl` with the same `--repo`, `--signer-workflow`
  and `--source-ref` uses the release's own provenance file. It still fetches Sigstore's trust root; for an
  air-gapped host, `gh attestation trusted-root > trusted_root.jsonl`
  beforehand and `--custom-trusted-root trusted_root.jsonl`.
- **Verification covers a digest, not a tag.** A tag resolves again at
  every pull and can move (a re-run, the owner, any token with
  `packages: write`), so a check by tag does not bind what runs later. The
  documented flow verifies `ghcr.io/o-kolomoiets/gosftpd@sha256:<digest>`
  from `digests.txt` (or `docker buildx imagetools inspect`) and runs that
  same reference; the compose example shows `image:
  ghcr.io/o-kolomoiets/gosftpd:v0.5.0@sha256:<digest>` as the production
  form. The Quickstart keeps the tag for readability.
- **Minimum versions** (see Signatures): cosign v3.0 or later, or v2.6
  with `--new-bundle-format`; a gh release whose `attestation verify` has
  `--signer-workflow`, `--source-ref` and `--custom-trusted-root`;
  admission controllers with Sigstore bundle and OCI referrer support.
- **Rebuilding** a release and comparing it with `checksums.txt` is
  described under Reproducible builds.
- **install.md** also gets sections for the packages (with "From the
  archive install to a package" and what a removal keeps per format), the
  archive, Docker (the Quickstart with a configuration directory, named
  volumes as the variant without `chown`, `--stop-timeout 40`, a reload
  with `docker kill -s HUP`) and compose (`docs/examples/compose.yaml`:
  the image by digest, the configuration directory, `read_only: true`,
  `cap_drop: [ALL]`, `security_opt: [no-new-privileges:true]`,
  `stop_grace_period: 40s`, `init: true` when exec hooks are used).
  docs/quickstart.md and the README stop calling packages and Docker
  future work.
- **The release checklist** describes the flow above, runs the local
  snapshot as `goreleaser release --snapshot --clean --skip=sign` (with
  syft installed and a Docker daemon; else `--skip=sign,sbom,docker`),
  checks the draft's assets and the green verification step before
  publishing, adds the M5 smoke steps of ROADMAP §9.6, waits for
  `verify-release`, and lists the version strings Dependabot does not
  update (GoReleaser, cosign, syft).

### Owner actions

1. Add a tag ruleset for `v*` that blocks updates and deletions. Creation
   stays allowed, for `tag.yml` and for a signed tag the owner may push;
   who may create `v*` tags is what protects the release identity.
2. After `v0.5.0-rc.1` has pushed the image, set the GHCR package
   `gosftpd` to **Public**: a package of a personal account starts private,
   and anonymous `docker run` fails until then. The
   `org.opencontainers.image.source` label links it to the repository.
3. For each release: run **Tag release**, check the draft and the green
   run, press **Publish**, and see `verify-release` pass.
4. Immutable Releases stays in M6-05.

No repository variable, secret or signing key is needed.

### Definition of Done

| M5 DoD item | Checked by |
|---|---|
| The tag produces archives, packages, `checksums.txt` with `.sigstore.json`, SBOMs, a multi-arch image in GHCR, attestations and a `.intoto.jsonl`; the documented verification succeeds | `v0.5.0-rc.1`, then `v0.5.0`, each verified by `release.yml` before publishing and by `verify-release` after; Scorecard after the rc |
| Two builds of the same tag (same Go and GoReleaser versions) give identical binaries, archives and packages | the `reproducible` job (two cold builds), and the rebuild procedure of docs/install.md once against the rc |
| Quickstart (a) verbatim on a clean Ubuntu 24.04 (umask 002), without root, amd64 and arm64; fingerprint kept; `healthy`; ≤ 15 MB | the `docker` job on both architectures, and once by hand on a clean Ubuntu 24.04 VM with the rc |
| `apt install` and `enable --now` on Debian 12, 13 and Ubuntu 24.04; `is-active`; `config validate --check-fs` as gosftpd returns 0 | the `packages` job, from `/` and from `/root` |
| The atmoz user spec `foo:pass:::upload` works unchanged (with `-p 22:2022`) | stream C's e2e test and the `docker` job |

### Not verified yet

The rc release, the first runs of the new CI jobs and the implementation
settle these:

- that GitHub's OIDC token carries the casing `Go-SFTP-Server`, and that a
  `workflow_dispatch` run on a tag ref has `job_workflow_ref`
  `.../release.yml@refs/tags/vX.Y.Z` (the verification step checks both
  before the rc is published);
- that `tag.yml` can create the tag through the API with `GITHUB_TOKEN`
  on a commit whose history changes workflow files, and start
  `release.yml`; that `gh release upload` finds the draft by its tag;
- how `gh attestation verify` treats case in `--repo` and
  `--signer-workflow` (the documentation uses the exact case either way);
- the minimum verifier versions: cosign v2.6 with `--new-bundle-format`,
  the first gh release with the flags used, admission controllers;
- whether GHCR stores cosign's OCI 1.1 referrers or cosign falls back to
  a tag, and that `cosign verify` finds the signature either way;
- that the health check survives in the pushed multi-arch index;
- that Scorecard counts the attest bundle named `.intoto.jsonl`, and that
  `gh attestation verify --bundle` reads a file with that suffix;
- that the runners' default Docker driver builds the `dockers_v2`
  snapshot, and that their cgroups are v2;
- that Dependabot updates a `gcr.io` digest;
- that the per-user Landlock rules (read-dir on `/home/<user>`, the
  mount's rights below it) let `os.Root` open `/home/<user>/<dir>`, which
  the sandboxed tests check;
- `--start-interval` on engines before Docker 25, and Landlock under the
  seccomp profiles of engines before Docker 29;
- the zsh completion paths in each distribution's `fpath`, and lintian on
  a maintainer without an email address;
- govulncheck on tools/go.mod once go-licenses is added.

### Not in this ADR

- apk and Alpine (OpenRC); Homebrew (ROADMAP backlog 9); windows/amd64
  (M3b); signing the packages themselves (deb, rpm); an APT or RPM
  repository.
- SLSA level claims beyond the provenance `actions/attest` produces.
- Reproducible images and SBOMs.

### Code

The work splits into the TASKS rows M5-02 to M5-13 and four streams:

- **A, CLI groundwork** (first): `internal/config/find.go`;
  `internal/cli/serve.go` (`loadConfig` and the hint only), `cli.go` (the
  export), `doc.go`, `gendocs/`; go.mod; tools/go.mod;
  `packaging/third_party_licenses.tpl`; a `generate` Makefile target.
- **B, pipeline and packaging:** `.goreleaser.yaml`;
  `packaging/docker/Dockerfile`; `packaging/scripts/*.sh`;
  `packaging/needrestart.conf`; the unit's `Documentation=` and its check
  in `internal/config/packaging_test.go`;
  `.github/workflows/{release,ci,tag,verify-release}.yml`;
  `.github/dependabot.yml`; `test/packages/`, `test/docker/` (every `FROM`
  pinned by digest).
- **C, ephemeral and atmoz:** `internal/atmoz` (parser and fuzz target),
  `internal/cli/ephemeral.go` and `atmoz.go`, flags and mode selection in
  `serve.go` and the root command's arguments in `cli.go`; `{user}`
  before the last path component in `internal/vfs` (`SplitUserPath`, state
  per mount, the overlap rule), `internal/config` (`checkTrusted`, the
  internal list of trusted files) and the Landlock rules of
  `internal/sandbox` (per-user rules, the ephemeral directory);
  docs/migrate-from-atmoz.md.
- **D, documentation:** docs/install.md, quickstart.md, README, SECURITY.md
  (verification and the minimum versions), operations.md (leftover files,
  needrestart, a Docker reload), configuration.md (the search order with
  the permission-error skip and the atmoz fallback, password logins
  without a file in ephemeral and atmoz mode, the `{user}` rule),
  security.md (the Landlock rules in atmoz and ephemeral mode),
  release-checklist.md, `docs/examples/compose.yaml`, CHANGELOG.

## Consequences

- A release needs no local tools: the owner starts a workflow and
  publishes a draft that the workflow has already verified. A signed tag
  pushed instead runs the same pipeline, and `release.yml` applies
  `tag.yml`'s checks to it.
- Tags carry no signature. Trust rests on the tag ruleset, the workflow
  identity in every certificate and attestation, and Immutable Releases
  once M6-05 turns them on; until then a published release's assets can
  still be replaced by someone with write access.
- Image tags are public before the release is published; `latest` moves
  only to the highest stable version, and a run for a published release
  stops before building.
- The signing job runs no generator and restores no Actions cache. Man
  pages, completions and `THIRD_PARTY_LICENSES` come from a job without
  credentials and stay trusted output of go-licenses, cobra/doc and their
  dependencies.
- The verification identity contains the repository's exact name. If the
  repository is renamed later (M0-17), new releases get the new identity;
  the documentation then gives both. ADR 0001 calls a rename cosmetic; for
  signatures it no longer is, which this ADR records instead of amending
  ADR 0001. `gh attestation verify` is pinned to `release.yml` and the tag,
  as cosign is, and users verify and run the image by digest. Verifiers
  need cosign v3.0 or later.
- Rebuilding a release bit for bit needs the Go version it was built with
  and the GoReleaser version its `release.yml` names; releases do not pin
  Go.
- Scorecard's Signed-Releases score stays low until the releases before
  v0.5.0 leave its five-release window.
- go.mod gains four indirect modules and tools/go.mod go-licenses with its
  dependencies; govulncheck covers more code, gosftpd's binary does not
  change.
- The package scripts never start or restart gosftpd, and the deb keeps
  needrestart from restarting it on Ubuntu: after an upgrade the operator
  restarts it. Debian packages depend on procps. Alpine has no package.
- Moving from the v0.4 archive install to a package takes a flag or a
  merge per format, which docs/install.md gives. On rpm and Arch a removal
  renames an edited `config.toml` to `.rpmsave` or `.pacsave`.
- The image's `/home` belongs to 65532, its `CMD` is `serve` without
  `--config`, and it sets `GOSFTPD_ATMOZ_IMAGE=1`. Docker users mount a
  configuration directory, not a file.
- `serve --ephemeral` under Landlock leaves its empty temporary directory
  behind; a reload does nothing in ephemeral mode.
- atmoz users change the port mapping, use argon2id or bcrypt hashes
  instead of MD5 or SHA-crypt, `chown` key and users files to root, and
  get files owned by 65532 unless they run with `--user`; upper-case names
  and nested directories are refused. As in atmoz, an upload overwrites an
  existing name, a user given twice is skipped, and a new user needs a
  restart.
- A mount with `{user}` before the last component gets Landlock rules per
  user known at start, so a user added by a reload needs a restart for it;
  key files under its prefix stay unwritable.
- The estimate grows from 6–9 to 10–14 person-days: 8.5–12 from the
  research, plus about 1.5–2 for the design review (the `verify-tag` and
  `generate` jobs and the verification step, the CI cases, per-user
  Landlock rules and state per mount, the atmoz edge cases).
- ROADMAP: §4.5 takes the tool versions; the M5 items and DoD take the
  decisions above (the release flow instead of signed tags, no apk, two
  attest steps, the `.intoto.jsonl`, reproducibility with the same Go and
  GoReleaser versions, the atmoz port, the DoD command from any directory,
  the estimate); §6.1 item 4 allows `{user}` before the last path
  component, with the overlap rule and per-user Landlock rules; §6.7 gets
  the root-level spec form; §9.1 drops the `NFPM_MAINTAINER` variable and
  lists `tag.yml`, `verify-release.yml` and the Dependabot directories;
  §9.3 takes the flow, the `verify-tag` and `generate` jobs, `cache:
  false`, the permissions without `artifact-metadata`, the verification
  before Publish, the pinned tools without QEMU and a corrected fragment;
  §9.4 the image's size, Dockerfile and `CMD`, the configuration
  directory, the package formats, scripts, needrestart file and
  `Documentation=`; §9.5 cosign v3.1.4, the exact identities, the pinned
  `gh attestation verify`, verification by digest and the `.intoto.jsonl`;
  §9.6 skips signing in the local snapshot; §10 mounts a configuration
  directory in the Docker Quickstart; D13 is decided.

## Alternatives considered

- **Keep publishing in the web interface** and upload afterwards: breaks
  with Immutable Releases, and the tag stays unsigned anyway.
- **A signed tag and a draft written in the web interface**, filled with
  `release.use_existing_draft`: keeps the owner's habit of writing notes in
  the interface, but needs a signing key and the most steps. The notes come
  from CHANGELOG.md instead.
- **Signed tags only** (`git tag -s`): needs a local git with a key
  registered on GitHub for every release; the owner chose the workflow.
  The pipeline accepts signed tags, so this can change without a change
  here.
- **release-please:** its tags are made with `GITHUB_TOKEN` too, it would
  need GoReleaser in the same workflow, and it adds a bot's pull requests.
- **GoReleaser v2.18.2:** wrong image digest (#7180). v2.18.3 is the
  fallback.
- **The before hooks in the release job**, GoReleaser's default: they
  would run third-party code with the release token, the OIDC token and
  the GHCR login, after the dirty-tree check.
- **The checks only in `tag.yml`:** a pushed signed tag, or a tag created
  through the API and dispatched by hand, would skip them.
- **`latest` moved only after publication** (`docker buildx imagetools
  create` in a workflow on `release: published`): keeps `latest` off
  drafts, but needs `packages: write` in a second workflow; the
  highest-stable rule and the published-release guard already stop the
  backwards moves.
- **`--certificate-identity-regexp`** or a repository rename before
  v0.5.0: a pattern loosens what is checked; the owner chose no rename.
  For the same reason `gh attestation verify` does not rely on `--repo`
  alone.
- **`slsa-github-generator` v2.1.0** for the `.intoto.jsonl`: it must be
  referenced by tag, not by commit, which Scorecard's Pinned-Dependencies
  counts as unpinned; and it duplicates what `actions/attest` produces.
- **Dropping the `.intoto.jsonl`** if Scorecard does not count it: it is
  also the documented provenance bundle for `gh attestation verify
  --bundle`.
- **Pinning the Go toolchain for releases:** works against the monthly
  toolchain refresh; the Go version is recorded in every binary instead.
- **A `VOLUME` instruction, a root `Dockerfile`, QEMU, a `RUN` step** to
  create directories: see Container image; a `RUN` would need a shell in a
  builder stage or emulation for arm64.
- **`CMD ["serve","--config","/etc/gosftpd/config.toml"]`** with atmoz mode
  for a missing `--config` file: a mistyped path would then start the
  plaintext-password users instead of exiting 2.
- **A single-file configuration mount:** a reload after `sed -i` or a vim
  write keeps the old content and reports success; documenting `docker
  restart` instead of a reload would hide the trap, not remove it.
- **Port 22 in the image:** needs `ip_unprivileged_port_start`, which
  Kubernetes does not set.
- **apk with OpenRC now:** 0.5–1 person-day for a platform without systemd;
  later if asked for.
- **Package scripts that enable and restart the service** (debhelper's
  default): an upgrade would end every session at a time the operator did
  not choose. Leaving needrestart alone and documenting it would do the
  same on Ubuntu.
- **A docs generator in `tools/`** (needs a `replace` of the main module and
  still cannot import `internal/`) or completions from running the built
  binary (wrong architecture when cross-building).
- **One license file per platform:** the Linux file is a superset; three
  files would add a hook and archive rules for no reader.
- **`--ephemeral` with only a password or only a key:** OpenSSH `sftp` in
  CI needs a key, most libraries take a password; both cost one line.
- **`--ephemeral` without Landlock**, or as a child of an unsandboxed
  parent that removes the directory: the first drops the sandbox for every
  test run, the second adds a pair of processes and signal forwarding to
  remove one empty directory.
- **atmoz: SHA-crypt support** (needs code outside x/crypto and a security
  review), **one flattened home mount `/home/{user}`** (no vfs change, but
  the user would see and could change `.ssh` and the top level of the home,
  and the key files would lie inside a mount, which gosftpd refuses),
  **relaxing the ownership check for atmoz files** (§6.5 stays
  one rule), and **only positional specs** (atmoz's `SFTP_USERS` and
  users-file examples would need a changed command).
- **atmoz: a Landlock rule on `/home`** for `{user}` mounts: simpler, and a
  user added by a reload would work at once, but every key file under
  `/home` would be writable to gosftpd, which ADR 0011 and docs/security.md
  rule out.
- **atmoz: `on_conflict = "rename"`**, gosftpd's default: OpenSSH
  overwrites, and jobs that write the same name would pile up copies.
- **atmoz: a user given twice as an error:** stricter, but atmoz skips it
  with a warning, and a migrated setup may rely on that.
- **atmoz's container conventions everywhere:** on a host, `/home`
  discovery would expose real home directories and `/etc/ssh` would hand
  out sshd's identity.
