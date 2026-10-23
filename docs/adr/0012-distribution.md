# ADR 0012: Distribution: releases, signatures, image, packages, ephemeral mode and atmoz compatibility

- **Status:** proposed, 2026-10-23; amends ROADMAP §5 M5 (items,
  Definition of Done, estimate), §6.1 item 4 (`{user}` before the last
  path component), §9.1, §9.3, §9.4, §9.5, §9.6 (the local snapshot) and
  decision D13, ADR 0011 (the unit's `Documentation=`; the packages remove
  the legacy drop-in only once the unit is gone) and
  docs/release-checklist.md
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
  and the repository keeps its name `o-kolomoiets/Go-SFTP-Server` (Q2). A
  design review (three reviewers, as for ADR 0010 and 0011) comes before
  this ADR is accepted.

## Decision

### How a release is made

- **The owner starts a workflow, reviews a draft and publishes it.**
  **Actions → Tag release → Run workflow** with the version (`0.5.0`,
  `0.5.0-rc.1`). `tag.yml` checks the version, creates the annotated tag
  `vX.Y.Z` on `main`'s head and starts `release.yml` on the tag's ref.
  `release.yml` runs GoReleaser, which creates a **draft** release and
  uploads the assets; the attestations follow and their provenance file is
  added to the draft. The owner checks the draft and presses **Publish**;
  publishing starts `verify-release.yml`, which runs the verification
  commands of docs/install.md against the published assets.
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
  identity. Nothing else changes.
- **Why a workflow dispatch.** Events caused by `GITHUB_TOKEN` start no
  workflows, except `workflow_dispatch` and `repository_dispatch` (GitHub's
  documented exception; docs.github.com was not reachable from the
  research environment). So `tag.yml` starts `release.yml` explicitly with
  `gh workflow run release.yml --ref vX.Y.Z`. On that ref the OIDC
  `job_workflow_ref`, and with it the certificate identity, should be
  `o-kolomoiets/Go-SFTP-Server/.github/workflows/release.yml@refs/tags/vX.Y.Z`,
  as for a pushed tag; this is inferred, and the rc release checks it.
- **Why a draft.** GoReleaser always creates a release as a draft, uploads,
  then publishes it unless `release.draft` is true; a release that already
  exists keeps its draft state, and once a release is immutable GoReleaser
  fails with "already exists and is immutable" (internal/client/github.go).
  Today's flow (publish first, upload after) therefore stops working with
  Immutable Releases. With `draft: true` the provenance file can be added
  after GoReleaser, and the owner publishes a release that is complete.
- **Release notes** come from CHANGELOG.md: a step extracts the section
  `## [X.Y.Z]` (for a pre-release without its own section, `## [Unreleased]`)
  into a file and passes it with `goreleaser release --release-notes FILE`
  (the flag exists in v2.19.0). `changelog.disable: true` stays.
- **Images are public before the release is.** `release.yml` pushes the
  image tags, `latest` included for a stable version, while the release is
  still a draft. The first run is therefore `v0.5.0-rc.1`: a pre-release
  gets no `latest` tag. A draft that is deleted instead of published leaves
  its image versions in GHCR; the owner deletes them by hand.

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
    tags: ["v{{ .Version }}", "{{ if not .Prerelease }}latest{{ end }}"]
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
- `latest` renders empty for a pre-release, and `dockers_v2` drops tags
  that render empty (`tpl.Slice` with `tmpl.NonEmpty()`), so an rc pushes
  no `latest`. In a snapshot `.Prerelease` is empty and
  `latest-amd64`/`latest-arm64` are built locally, never pushed.
- `docker_signs` sets its own `args`: the default is `sign
  --key=cosign.key ...`. With the tags `vX.Y.Z` and `latest` the same
  digest is signed twice, which is harmless.
- `preflight.fail_on_error` (since v2.18) stops the run before building
  when the token cannot publish or the release is already immutable.

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
  in line with the monthly toolchain refresh of ROADMAP §9.6. "Reproducible"
  means: the same tag built with the same Go version, which `go version -m
  gosftpd` prints. docs/install.md says how to rebuild a release with that
  version and compare it with `checksums.txt`.
- **CI job `reproducible`:** two checkouts of the commit at different
  paths, the second under umask 002, each running `goreleaser release
  --snapshot --clean --skip=sign,sbom,docker`; `dist/checksums.txt` must be
  identical (12 entries: archives and packages). Signatures, SBOMs (syft's
  default `--enrich all` goes online) and images are out of scope, as the
  DoD allows.

### Signatures, SBOM and provenance

- **cosign v3.1.4** (2026-10-20), installed by `sigstore/cosign-installer`
  v4.1.2 (`6f9f17788090df1f26f669e9d70d6ae9567deba6`) with
  `cosign-release: v3.1.4`; the installer's default is v3.0.6, and it has
  no floating `v4` tag (the repository pins by commit anyway). Keyless,
  through GitHub's OIDC token; v3 writes the new bundle format and stores
  image signatures as OCI 1.1 referrers by default.
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
  predicate it produces SLSA build provenance. The job needs
  `artifact-metadata: write` besides `id-token` and `attestations`
  (actionlint v1.7.12 knows it).
- **`.intoto.jsonl` for Scorecard.** Scorecard's Signed-Releases check
  scores 8 for a `*.sigstore.json` asset and 10 for a `*.intoto.jsonl`
  asset, by file suffix only, as the floor of the average over the last
  five releases. The first attest step's `bundle-path` output (the Sigstore
  bundle of the provenance) is uploaded to the draft as
  `gosftpd_X.Y.Z.intoto.jsonl`, which `gh attestation verify --bundle`
  should read offline. Whether Scorecard counts it is checked after the rc;
  if not, the file is dropped and the score stays at 8. v0.1.0-alpha to
  v0.4.0 have neither file, so the score stays low until they leave the
  window.

### Workflows

All actions are pinned by commit with a version comment, as today.

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
  release:
    if: startsWith(github.ref, 'refs/tags/v')
    runs-on: ubuntu-24.04
    permissions:
      contents: write            # the draft release and its assets
      packages: write            # ghcr.io/o-kolomoiets/gosftpd
      id-token: write            # keyless cosign and actions/attest
      attestations: write
      artifact-metadata: write   # actions/attest storage records
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with: { fetch-depth: 0, persist-credentials: false }
      - uses: actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e # v7.0.0
        with: { go-version: stable, check-latest: true }
      - uses: sigstore/cosign-installer@6f9f17788090df1f26f669e9d70d6ae9567deba6 # v4.1.2
        with: { cosign-release: v3.1.4 }
      - uses: anchore/sbom-action/download-syft@66cbf4bc1f1c0d2edc94016e65bc221b6bb0ad6c # v0.24.3
        with: { syft-version: v1.55.0 }
      - uses: docker/setup-buildx-action@f87e5991a6d7451dcb8d9637bfbc97413f497069 # v4.4.1
      - uses: docker/login-action@dbcb813823bdd20940b903addbd779551569679f # v4.6.0
        with: { registry: ghcr.io, username: "${{ github.actor }}", password: "${{ secrets.GITHUB_TOKEN }}" }
      - run: ...                 # CHANGELOG section of $GITHUB_REF_NAME > $RUNNER_TEMP/notes.md
      - uses: goreleaser/goreleaser-action@a4f02ab5355a589de60d917a659ce617ed19b3de # v7.3.0
        with: { version: v2.19.0, args: "release --clean --release-notes ${{ runner.temp }}/notes.md" }
        env: { GITHUB_TOKEN: "${{ secrets.GITHUB_TOKEN }}" }
      - id: attest
        uses: actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6 # v4.2.2
        with: { subject-checksums: dist/checksums.txt }
      - uses: actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6 # v4.2.2
        with: { subject-checksums: dist/digests.txt }
      - run: ...                 # copy the bundle to gosftpd_X.Y.Z.intoto.jsonl; gh release upload "$GITHUB_REF_NAME" it
        env: { BUNDLE: "${{ steps.attest.outputs.bundle-path }}", GH_TOKEN: "${{ github.token }}", GH_REPO: "${{ github.repository }}" }
```

- **No QEMU.** The Dockerfile has no `RUN`, so the arm64 image builds on
  an amd64 runner without emulation (verified with an empty
  `binfmt_misc`); `docker/setup-qemu-action` leaves the ROADMAP's list.
- **`tag.yml`** (`workflow_dispatch`, input `version`; the job runs only
  on `refs/heads/main`; permissions `contents: write`, `actions: write`,
  `checks: read`). Every check runs before anything is created, because the
  tag ruleset makes a wrong tag permanent: the version matches
  `^[0-9]+\.[0-9]+\.[0-9]+(-(alpha|beta|rc)(\.[0-9]+)?)?$`; the tag does not
  exist yet; CHANGELOG.md has the version's section (a pre-release: or a
  non-empty Unreleased section); the `ci-ok` check run succeeded on the
  commit. It then creates the annotated tag through the API (`git/tags`,
  then `git/refs`, tagger `github-actions[bot]`), so no credentials are
  persisted in a checkout, and runs `gh workflow run release.yml --ref
  vX.Y.Z`. Inputs reach the script through `env:`, never through `${{ }}`
  inside `run:`.
- **`verify-release.yml`** (`release: published`, and `workflow_dispatch`
  with a tag; permissions `contents: read`, `attestations: read`) installs
  cosign as above, downloads the release with `gh release download`, runs
  the commands of "Verification by users" with the literal identities,
  pulls the image anonymously (this fails while the GHCR package is still
  private) and checks that `docker run --rm IMAGE version` prints the tag.
- **`ci.yml`:**
  - `goreleaser-check` moves to v2.19.0, installs syft as above and runs
    `release --snapshot --clean --skip=sign`: snapshot mode skips publishing
    but not signing (`signs` and `docker_signs` run unless skipped), and
    `sboms` needs syft. It keeps the version check and the 12 MiB budget
    and adds: the archive check for `*_freebsd_*`; `dpkg-deb -c` and the
    conffiles, `rpm -qp --configfiles`; `docker image inspect` for
    `User 65532:65532`, the health check and ports 2022 and 9090; the
    compressed image size ≤ 15 MB; `git status --porcelain` empty after
    the hooks (a dirty tree shows as `+dirty` in the SBOM); the packages
    and `docker save` tarballs uploaded for the jobs below.
  - `reproducible` (above).
  - `packages`: the DoD verbatim (`apt install`, `systemctl enable --now`,
    `is-active`, `sudo -u gosftpd gosftpd config validate --check-fs` run
    from `/` and from `/root`, `systemctl reload`) on the ubuntu-24.04 and
    ubuntu-24.04-arm runners themselves (systemd 255 is PID 1), in Debian 12
    and 13 containers built `FROM debian` with systemd, systemd-sysv, procps
    and sudo (Debian 12 also checks the legacy drop-in and `reload`), EL9
    (`rockylinux/rockylinux:9-ubi-init`) and, optionally, Arch; an upgrade
    keeps the drop-in and a removal deletes it; the job prints
    `stat -fc %T /sys/fs/cgroup`, since cgroup v2 on the runners is assumed.
  - `docker` on ubuntu-24.04 and ubuntu-24.04-arm (arm64 with real Landlock,
    no QEMU): the Quickstart verbatim under umask 002 as a non-root user,
    `healthy`, an sftp upload, the host key fingerprint after recreating
    the container, exit 2 and the hint without a config, the compose
    example with `read_only` and the atmoz example.
  - The three new jobs join `ci-ok`'s needs; stream C adds one fuzz-smoke
    entry (`FuzzAtmozSpec`).
- **Dependabot** gets `package-ecosystem: docker` for `/packaging/docker`
  (the base image digest).

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
WORKDIR /
USER 65532:65532
EXPOSE 2022 9090
HEALTHCHECK --start-period=10s --start-interval=2s CMD ["/usr/bin/gosftpd","healthcheck"]
ENTRYPOINT ["/usr/bin/gosftpd"]
CMD ["serve","--config","/etc/gosftpd/config.toml"]
```

- **Base:** `gcr.io/distroless/static-debian13:nonroot`, pinned by its
  index digest of 2026-10-23 (amd64, arm64 and four other platforms). Its
  layers are 855,302 bytes compressed on amd64 (about 0.82 MiB) and
  3.3 MiB uncompressed, not the "about 2 MiB" of ROADMAP §9.4. The image is
  5.25 MB compressed on amd64 and 4.84 MB on arm64, against the 15 MB DoD.
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
  it after an upgrade (docs/operations.md): a restart ends every session.
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
- **`/etc/gosftpd`, users and data stay** after a removal (dpkg removes the
  conffile on purge only); docs/install.md says what to delete.
- **deb `Depends: procps`:** the legacy drop-in's `ExecReload` calls
  `/bin/kill`, which minimal Debian 12 lacks: `reload` failed with
  203/EXEC. The lint job stubs `/usr/bin/kill` and did not catch it.
- **The unit** gets `Documentation=man:gosftpd(1)` before the install.md
  URL, now that the page is installed (amends ADR 0011; the lint passes
  `--man=no`).
- **Upgrades leave `config.toml.dpkg-dist`, `.dpkg-old` or `.rpmnew`** in
  `/etc/gosftpd`; under Landlock any file the configuration does not name
  makes the directory shared (ADR 0011), with the start warning.
  docs/operations.md says to merge and delete them.

### Man pages, completions and licenses

- **Generator:** `internal/cli/gendocs`, a `package main` in the main
  module that imports the root command, exported as `cli.NewRootCommand()`
  (today `newRootCmd`). A generator under `tools/` cannot import
  `internal/`. `internal/cli/doc.go` holds `//go:generate go run ./gendocs
  ../../out`; the before-hook runs `go generate ./...` with
  `SOURCE_DATE_EPOCH`, which cobra's `GenManTree` uses for the page date
  (the hook string is templated and split with shellwords, hence `sh -c`).
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
  directory, the error says what to do instead of only "stat ...: no such
  file or directory":

  ```text
  Error: --config: /etc/gosftpd/config.toml does not exist
  Create one with 'gosftpd config example > config.toml'. With Docker:
    docker run --rm ghcr.io/o-kolomoiets/gosftpd:v0.5.0 config example > config.toml
  and mount it with -v ./config.toml:/etc/gosftpd/config.toml:ro (docs/install.md).
  ```

  For a directory: "... is a directory: Docker creates one when the host
  file of a bind mount does not exist; create config.toml on the host
  first" (the directory case was reproduced). The image tag is the binary's own version, or
  `latest` for a development build. The "no configuration file found"
  error of a search gets the same two lines.
- **`cli.NewRootCommand()`** is exported for the generator.

### `serve --ephemeral`

For persona U3: a throwaway server for tests, with the details on stdout.

- **Flags.** `--ephemeral` conflicts with `--config`, `--users-conf`,
  `--authorized-keys`, `--user`, `--host-key` and `--state-dir`;
  `$GOSFTPD_CONFIG` is ignored. `--listen` defaults to `127.0.0.1:0`. One
  `--dir PATH` may name the data directory; without it the data lives in
  `DIR/data` of a new `os.MkdirTemp` directory. `--read-only`,
  `--on-conflict`, the log flags and `--audit-output` (a path; `stdout` is
  refused) work as for `serve`.
- **Credentials.** One user, `test`, with `full` access to the single mount
  (flattened: the data directory is `/`). Both a random password (24 random
  bytes, base64url; its argon2id hash only in memory) and a generated
  ed25519 client key, written 0600 as `DIR/id_ed25519`: OpenSSH `sftp` in
  CI needs the key, libraries prefer the password. The host key is
  generated in memory and never written.
- **Output.** Exactly one JSON line on stdout, once every listener is bound,
  then nothing else on stdout:

  ```json
  {"host":"127.0.0.1","port":40123,"user":"test","password":"…","private_key_path":"/tmp/gosftpd-ephemeral-123/id_ed25519","dir":"/tmp/gosftpd-ephemeral-123/data","host_key_fingerprint":"SHA256:…","known_hosts":"[127.0.0.1]:40123 ssh-ed25519 AAAA…","pid":4242,"version":"v0.5.0"}
  ```

  `host` is the listen address's host, or `127.0.0.1` when it is
  unspecified; `port` and `pid` are numbers; `dir` is the host path of the
  mount; `known_hosts` is a line for `UserKnownHostsFile`. Fields may be
  added later, never removed or renamed (the M6 compatibility contract).
- **Logs** and the audit log go to stderr; today audit defaults to stdout,
  which would mix with the JSON.
- **Stop.** On SIGINT or SIGTERM gosftpd stops as `serve` does and removes
  the temporary directory (never a `--dir` directory). A killed process
  leaves it in `$TMPDIR`.
- **Root.** The refusal to run as root stays; its hint names
  `--allow-root`, which CI containers running as root need.
- **Docs** show a GitHub Actions step that waits for the line and passes
  the password through `::add-mask::`.

### atmoz compatibility

For persona U1 moving from atmoz/sftp, whose image takes users as arguments,
from `SFTP_USERS` and from `/etc/sftp/users.conf`.

- **Sources.** Specs given as arguments to the root command (what `docker
  run IMAGE foo:pass:::upload` passes: the arguments replace `CMD`), the
  space-separated `$SFTP_USERS`, and a users file (`serve --users-conf
  FILE`, default `/etc/sftp/users.conf` when it exists; blank lines and
  `#` comments skipped), combined as atmoz combines them. The root command
  treats its arguments as specs when the first matches atmoz's own test
  `^[^:[:space:]]+:.*$`; then every argument must be a valid spec. Anything
  else stays an unknown command with exit 2 (today the root command accepts
  no arguments). `serve` with no configuration file, either none found or
  a `--config` file that does not exist (the image's `CMD`), uses these
  sources when there are any, and logs that it runs in atmoz mode;
  otherwise it exits 2 with the hint above. When a configuration file
  exists, `--users-conf` is an error (exit 2), `SFTP_USERS` is ignored with
  a warning and `/etc/sftp/users.conf` is not read; specs given as
  arguments always mean atmoz mode, and `$GOSFTPD_CONFIG` is then ignored.
  `--dir`, `--authorized-keys`, `--user` and `--ephemeral` conflict with
  atmoz mode; with `serve`, `--listen`, `--host-key`, `--state-dir`, the
  log and audit flags apply.
- **Syntax:** `user:pass[:e][:uid[:gid[:dir1[,dir2]...]]]`, split as
  atmoz's `create-sftp-user` splits it.
  - **user** must be a gosftpd name, `^[a-z0-9][a-z0-9._-]{0,31}$`; atmoz
    also accepts upper case and a leading `.` or `_`, which are refused
    with an error that names the spec. A name given twice is an error.
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
  - **dirs:** each must be a valid mount name, with no `/`, no `..`, not
    empty and not `.ssh`; nested directories (`a/b`) are refused.
- **Layout as in atmoz:** user `foo` with directory `upload` sees
  `/upload`, stored in `/home/foo/upload`, so atmoz-style volumes
  (`-v ./upload:/home/foo/upload`) work unchanged. A user's directories are
  those its spec names plus every directory that exists directly under
  `/home/<user>` at start, other than `.ssh`: atmoz's own volume examples
  (`foo:pass:1001` with `-v <host-dir>/upload:/home/foo/upload`) name no
  directory. Each directory name becomes one mount, `[mounts.upload] path
  = "/home/{user}/upload"` with `create = true`; each user that has the
  directory gets `full` on it, and `flatten = false`, so the top level is
  the synthetic read-only root, as atmoz's root-owned home is, and
  `/home/<user>/.ssh` is never reachable. The image's `/home` belongs to
  65532 so that `foo:pass:::upload` works without a volume.
- **One vfs extension.** Today `{user}` may only be the whole last
  component of a mount path, and mount names are global, so
  `/home/{user}/upload` cannot be written. `{user}` may now also be a whole
  earlier component. For a session the components from `{user}` on are
  opened as a home mount's directory is today (each a real directory, not a
  symlink, else the mount is unavailable with `home_not_dir`; created 0750
  with `create = true`). Such a mount occupies the parent of `{user}`
  (`/home`), as a home mount does, for overlaps with other mounts and for
  its Landlock rule; two mounts whose paths differ only after `{user}` do
  not overlap. The rule that trusted files may not lie inside a mount
  compares against the per-user paths, so `/home/<user>/.ssh/keys/*` stays
  allowed; under Landlock gosftpd itself can write them (clients cannot:
  they reach only the mounts). It is an ordinary configuration feature,
  documented in docs/configuration.md, since atmoz mode builds an ordinary
  configuration. The research did not cover this; it is the main point of
  the design review for atmoz mode.
- **Keys:** every file in `/home/<user>/.ssh/keys/` is read as an
  `authorized_keys` file, with the usual permission check (§6.5:
  owned by root or by the user gosftpd runs as, not writable by group or
  others), as for the users file; a key bind-mounted from a host user's
  home must be `chown root` first. The migration guide says so.
- **Host keys:** `/etc/ssh/ssh_host_ed25519_key` and
  `/etc/ssh/ssh_host_rsa_key` are used when they exist, so clients keep
  their known_hosts entry after the migration; like every host key they
  must belong to the user gosftpd runs as (65532) with mode 0600 (the
  guide shows the `chown`). Otherwise the key
  is `/var/lib/gosftpd/ssh_host_ed25519_key`, generated on first start as
  in the Quickstart.
- **Warnings at start:** a plain password from the arguments or from
  `SFTP_USERS` is visible to anyone who can run `docker inspect` or read
  the process's command line or environment (ROADMAP §6.7 never takes
  a password as an argument): a warning names the source and points to
  `:e` with an argon2id hash or to keys. When plain and hashed passwords
  are mixed, the warning `config validate` gives for hashes of different
  classes is logged too.
- **Port 2022:** the container listens on 2022, so atmoz's `-p 22:22`
  becomes `-p 22:2022` and `-p 2222:22` becomes `-p 2222:2022`. The DoD
  says "the user spec `foo:pass:::upload` works unchanged".
- **Ownership:** files on host volumes belong to 65532, not to the spec's
  uid; the guide shows `chown 65532` of the host directory, or
  `--user UID:GID` with a state volume that UID can write, which gives
  atmoz's ownership back.
- **Audit** goes to stdout, as with `config example`. A reload (SIGHUP)
  reads the users file and the key directories again; under Landlock, new
  key files need a restart (ADR 0011: `.ssh` is never a dedicated
  directory).
- **Tests:** `FuzzAtmozSpec` on the parser (CI smoke and nightly), e2e
  tests with the README examples (arguments, `SFTP_USERS`, users file,
  `:e` with bcrypt, keys, an existing volume directory), and the `docker`
  CI job. docs/migrate-from-atmoz.md maps every atmoz example.

### Verification by users

docs/install.md, linked from SECURITY.md ("Verifying releases"), gives
these commands; `verify-release.yml` runs them on every published release.

```sh
V=0.5.0
gh release download "v$V" -R o-kolomoiets/Go-SFTP-Server \
  -p checksums.txt -p checksums.txt.sigstore.json -p "gosftpd_${V}_linux_amd64.tar.gz"
sha256sum --check --ignore-missing checksums.txt
cosign verify-blob \
  --certificate-identity "https://github.com/o-kolomoiets/Go-SFTP-Server/.github/workflows/release.yml@refs/tags/v$V" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --bundle checksums.txt.sigstore.json checksums.txt
cosign verify \
  --certificate-identity "https://github.com/o-kolomoiets/Go-SFTP-Server/.github/workflows/release.yml@refs/tags/v$V" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  "ghcr.io/o-kolomoiets/gosftpd:v$V"
gh attestation verify "gosftpd_${V}_linux_amd64.tar.gz" --repo o-kolomoiets/Go-SFTP-Server
gh attestation verify "oci://ghcr.io/o-kolomoiets/gosftpd:v$V" --repo o-kolomoiets/Go-SFTP-Server
```

- The identity must be typed exactly: `o-kolomoiets/go-sftp-server` (the
  spelling ROADMAP §9.5 and SECURITY.md use) fails. Packages are covered
  by `checksums.txt` like archives. Offline, `gh attestation verify FILE
  --bundle gosftpd_${V}.intoto.jsonl --repo ...` uses the release's own
  provenance file.
- **install.md** also gets sections for the packages, the archive, Docker
  (the Quickstart, named volumes as the variant without `chown`,
  `--stop-timeout 40`) and compose (`docs/examples/compose.yaml`:
  `read_only: true`, `cap_drop: [ALL]`, `security_opt:
  [no-new-privileges:true]`, `stop_grace_period: 40s`, `init: true` when
  exec hooks are used). docs/quickstart.md and the README stop calling
  packages and Docker future work.
- **The release checklist** describes the flow above, runs the local
  snapshot as `goreleaser release --snapshot --clean --skip=sign` (with
  syft installed and a Docker daemon; else `--skip=sign,sbom,docker`),
  checks the draft's assets before publishing, adds the M5 smoke steps of
  ROADMAP §9.6, waits for `verify-release`, and lists the version strings
  Dependabot does not update (GoReleaser, cosign, syft).

### Owner actions

1. Add a tag ruleset for `v*` that blocks updates and deletions. Creation
   stays allowed, for `tag.yml` and for a signed tag the owner may push.
2. After `v0.5.0-rc.1` has pushed the image, set the GHCR package
   `gosftpd` to **Public**: a package of a personal account starts private,
   and anonymous `docker run` fails until then. The
   `org.opencontainers.image.source` label links it to the repository.
3. For each release: run **Tag release**, check the draft, press
   **Publish**, and see `verify-release` pass.
4. Immutable Releases stays in M6-05.

No repository variable, secret or signing key is needed.

### Definition of Done

| M5 DoD item | Checked by |
|---|---|
| The tag produces archives, packages, `checksums.txt` with `.sigstore.json`, SBOMs, a multi-arch image in GHCR, attestations; the documented verification succeeds | `v0.5.0-rc.1`, then `v0.5.0`, each with `verify-release` green; Scorecard after the rc |
| Two builds of the same tag (same Go version) give identical binaries, archives and packages | the `reproducible` job |
| Quickstart (a) verbatim on a clean Ubuntu 24.04 (umask 002), without root, amd64 and arm64; fingerprint kept; `healthy`; ≤ 15 MB | the `docker` job on both architectures, and once by hand on a clean Ubuntu 24.04 VM with the rc |
| `apt install` and `enable --now` on Debian 12, 13 and Ubuntu 24.04; `is-active`; `config validate --check-fs` as gosftpd returns 0 | the `packages` job, from `/` and from `/root` |
| The atmoz user spec `foo:pass:::upload` works unchanged (with `-p 22:2022`) | stream C's e2e test and the `docker` job |

### Not verified yet

The rc release, the first runs of the new CI jobs and the design review
settle these:

- that GitHub's OIDC token carries the casing `Go-SFTP-Server`, and that a
  `workflow_dispatch` run on a tag ref has `job_workflow_ref`
  `.../release.yml@refs/tags/vX.Y.Z`;
- that `tag.yml` can create the tag through the API with `GITHUB_TOKEN`
  on a commit whose history changes workflow files, and start
  `release.yml`; that `gh release upload` finds the draft by its tag;
- whether `gh attestation verify --repo` ignores case (the documentation
  uses the exact case either way);
- whether GHCR stores cosign's OCI 1.1 referrers or cosign falls back to
  a tag, and that `cosign verify` finds the signature either way;
- that the health check survives in the pushed multi-arch index;
- that Scorecard counts the attest bundle named `.intoto.jsonl`, and that
  `gh attestation verify --bundle` reads a file with that suffix;
- that the runners' default Docker driver builds the `dockers_v2`
  snapshot, and that their cgroups are v2;
- that Dependabot updates a `gcr.io` digest;
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
  `internal/cli/serve.go` (`loadConfig` only), `cli.go` (the export),
  `doc.go`, `gendocs/`; go.mod; tools/go.mod;
  `packaging/third_party_licenses.tpl`; a `generate` Makefile target.
- **B, pipeline and packaging:** `.goreleaser.yaml`;
  `packaging/docker/Dockerfile`; `packaging/scripts/*.sh`; the unit's
  `Documentation=` and its check in `internal/config/packaging_test.go`;
  `.github/workflows/{release,ci,tag,verify-release}.yml`;
  `.github/dependabot.yml`; `test/packages/`, `test/docker/`.
- **C, ephemeral and atmoz:** `internal/atmoz` (parser and fuzz target),
  `internal/cli/ephemeral.go` and `atmoz.go`, flags in `serve.go` and the
  root command's arguments in `cli.go`; `{user}` before the last path
  component in `internal/vfs`, `internal/config` and the Landlock rules of
  `internal/sandbox`; docs/migrate-from-atmoz.md.
- **D, documentation:** docs/install.md, quickstart.md, README, SECURITY.md,
  operations.md, release-checklist.md, `docs/examples/compose.yaml`,
  CHANGELOG.

## Consequences

- A release needs no local tools: the owner starts a workflow and
  publishes a draft. The pipeline is the same if a signed tag is pushed
  instead.
- Tags carry no signature. Trust rests on the tag ruleset, the workflow
  identity in every certificate and attestation, and Immutable Releases
  once M6-05 turns them on; until then a published release's assets can
  still be replaced by someone with write access.
- Image tags, `latest` included for stable versions, are public before the
  release is published.
- The verification identity contains the repository's exact name. If the
  repository is renamed later (M0-17), new releases get the new identity;
  the documentation then gives both.
- Rebuilding a release bit for bit needs the Go version it was built with;
  releases do not pin one.
- Scorecard's Signed-Releases score stays low until the releases before
  v0.5.0 leave its five-release window.
- go.mod gains four indirect modules and tools/go.mod go-licenses with its
  dependencies; govulncheck covers more code, gosftpd's binary does not
  change.
- Packages never start or restart gosftpd: after an upgrade the operator
  restarts it. Debian packages depend on procps. Alpine has no package.
- The image's `/home` belongs to 65532.
- atmoz users change the port mapping, use argon2id or bcrypt hashes
  instead of MD5 or SHA-crypt, `chown` key and users files to root, and
  get files owned by 65532 unless they run with `--user`; upper-case names
  and nested directories are refused.
- The estimate grows from 6–9 to 8.5–12 person-days.
- ROADMAP: the M5 items and DoD take the decisions above (the release flow
  instead of signed tags, no apk, two attest steps, the atmoz port, the
  DoD command from any directory, the estimate); §9.1 drops the
  `NFPM_MAINTAINER` variable and lists `tag.yml` and `verify-release.yml`;
  §9.3 takes the flow, the permissions with `artifact-metadata`, the
  pinned tools without QEMU and a corrected fragment; §9.4 the image's
  size and Dockerfile, the package formats, scripts and `Documentation=`;
  §9.5 cosign v3.1.4, the exact identities and the `.intoto.jsonl`; §9.6
  skips signing in the local snapshot; §6.1 item 4 allows `{user}` before
  the last path component; D13 is decided.

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
- **`--certificate-identity-regexp`** or a repository rename before
  v0.5.0: a pattern loosens what is checked; the owner chose no rename.
- **`slsa-github-generator` v2.1.0** for the `.intoto.jsonl`: it must be
  referenced by tag, not by commit, which Scorecard's Pinned-Dependencies
  counts as unpinned; and it duplicates what `actions/attest` produces.
- **Pinning the Go toolchain for releases:** works against the monthly
  toolchain refresh; the Go version is recorded in every binary instead.
- **A `VOLUME` instruction, a root `Dockerfile`, QEMU, a `RUN` step** to
  create directories: see Container image; a `RUN` would need a shell in a
  builder stage or emulation for arm64.
- **Port 22 in the image:** needs `ip_unprivileged_port_start`, which
  Kubernetes does not set.
- **apk with OpenRC now:** 0.5–1 person-day for a platform without systemd;
  later if asked for.
- **Package scripts that enable and restart the service** (debhelper's
  default): an upgrade would end every session at a time the operator did
  not choose.
- **A docs generator in `tools/`** (needs a `replace` of the main module and
  still cannot import `internal/`) or completions from running the built
  binary (wrong architecture when cross-building).
- **One license file per platform:** the Linux file is a superset; three
  files would add a hook and archive rules for no reader.
- **`--ephemeral` with only a password or only a key:** OpenSSH `sftp` in
  CI needs a key, most libraries take a password; both cost one line.
- **atmoz: SHA-crypt support** (needs code outside x/crypto and a security
  review), **one flattened home mount `/home/{user}`** (no vfs change, but
  the user would see and could change `.ssh` and the top level of the home,
  and the key files would lie inside a mount, which gosftpd refuses),
  **relaxing the ownership check for atmoz files** (§6.5 stays
  one rule), and **only positional specs** (atmoz's `SFTP_USERS` and
  users-file examples would need a changed command).
