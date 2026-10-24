# Security Policy

## Supported versions

gosftpd has no stable release yet. While the project is in 0.x, only the
latest minor release receives security fixes.

## Verifying releases

From v0.5.0, the release workflow signs every release with keyless
[cosign](https://github.com/sigstore/cosign): `checksums.txt`, which lists
every archive, package and SBOM, and the container image
`ghcr.io/o-kolomoiets/gosftpd`, by digest. GitHub build provenance
attestations cover the same files and the image. The commands are in
[docs/install.md](docs/install.md#verify-a-release); the release workflow
runs them before a release is published, and again once it is.

- The certificate identity is
  `https://github.com/o-kolomoiets/Go-SFTP-Server/.github/workflows/release.yml@refs/tags/vX.Y.Z`
  with the issuer `https://token.actions.githubusercontent.com`. Type it
  exactly, capitals included: cosign compares it as a string, so
  `o-kolomoiets/go-sftp-server` fails. Do not loosen it with
  `--certificate-identity-regexp`.
- `gh attestation verify` needs `--signer-workflow
  o-kolomoiets/Go-SFTP-Server/.github/workflows/release.yml` and
  `--source-ref refs/tags/vX.Y.Z` next to `--repo`, which alone accepts a
  provenance signed by any workflow of the repository.
- Verify the image by the digest in the release's `digests.txt`, and run
  that digest: a tag can move.
- You need cosign v3.0 or later (v2.6 only with `--new-bundle-format`;
  older versions find no signature) and gh 2.68.0 or later.

Releases before v0.5.0 carry only an unsigned `checksums.txt`. Git tags
are not signed; the signatures and attestations name the tag instead.

## Reporting a vulnerability

Please **do not** open a public issue. Report vulnerabilities privately through
GitHub: [Security → Report a vulnerability](https://github.com/o-kolomoiets/go-sftp-server/security/advisories/new).

What to expect (best effort, single maintainer):

- acknowledgement within 72 hours;
- a fix and coordinated disclosure within 90 days;
- a GitHub Security Advisory and, where applicable, a CVE.

## Scope

Especially interesting: escaping a mount (path traversal, symlinks, races),
authentication or authorization bypass, information disclosure such as host
paths, and denial of service that a single client can trigger.
