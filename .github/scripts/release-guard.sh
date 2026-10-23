#!/usr/bin/env bash
# The release guard (ADR 0012), which release.yml runs first in both of its
# jobs. It stops the run unless:
# - GITHUB_REF is a release tag, refs/tags/vX.Y.Z with an optional -alpha,
#   -beta or -rc and .N (a dispatch on a branch fails);
# - that tag is the highest release tag of GITHUB_REPOSITORY;
# - it has no published release: releases/tags answers 404, as it does for
#   a draft, so that a re-run replaces its own draft. Any other answer
#   fails.
# Otherwise a re-run, or a dispatch for a published release, would push and
# sign a rebuilt image under its tag, and a run on an older tag would move
# latest backwards. The release job repeats the guard because re-running
# only that job reuses the generate job's earlier success.
# Needs gh with GH_TOKEN (contents: read), and GITHUB_REF, GITHUB_REF_NAME
# and GITHUB_REPOSITORY as GitHub Actions sets them.
set -euo pipefail

me=${0##*/}
# shellcheck source-path=SCRIPTDIR source=release-tags.sh
. "$(dirname "$0")/release-tags.sh"

fail() {
	echo "$me: $*" >&2
	exit 1
}

: "${GITHUB_REF:?}" "${GITHUB_REF_NAME:?}" "${GITHUB_REPOSITORY:?}"
tag=${GITHUB_REF#refs/tags/}
if [[ $GITHUB_REF != refs/tags/* ]] || ! [[ $tag =~ $release_tag_re ]]; then
	fail "$GITHUB_REF is not a release tag (refs/tags/vX.Y.Z, optionally with -alpha, -beta or -rc and .N): run release.yml on the tag"
fi
if [ "$GITHUB_REF_NAME" != "$tag" ]; then
	fail "GITHUB_REF_NAME $GITHUB_REF_NAME is not the tag of $GITHUB_REF"
fi

tags=$(release_tags) || fail "cannot list the tags of $GITHUB_REPOSITORY"
if ! grep -qxF -- "$tag" <<<"$tags"; then
	fail "$GITHUB_REPOSITORY has no tag $tag"
fi
highest=$(tail -n 1 <<<"$tags")
if [ "$highest" != "$tag" ]; then
	fail "$tag is not the highest release tag of $GITHUB_REPOSITORY: $highest is"
fi

# gh exits 1 on any HTTP error; the status line of --include tells a 404
# from the rest.
err=$(mktemp)
trap 'rm -f "$err"' EXIT
answer=$(gh api --include "repos/$GITHUB_REPOSITORY/releases/tags/$tag" 2>"$err") || true
status=$(sed -n '1s/^HTTP\/[0-9.]* \([0-9][0-9][0-9]\)\([^0-9].*\)\{0,1\}$/\1/p' <<<"$answer")
case $status in
404) ;;
200) fail "$tag has a published release: release.yml runs only for a tag whose release is not published yet" ;;
*) fail "cannot tell whether $tag has a published release (${status:-no answer}): $(tr '\n' ' ' <"$err")" ;;
esac
echo "$me: $tag is the highest release tag of $GITHUB_REPOSITORY and has no published release"
