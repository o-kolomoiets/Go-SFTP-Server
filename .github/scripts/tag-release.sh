#!/usr/bin/env bash
# Tags a release and starts release.yml on the tag (ADR 0012): tag.yml runs
# it with the version the owner typed. Every check runs before anything is
# created, because the v* tag ruleset makes a tag permanent:
# - the run is on main, and VERSION is X.Y.Z, optionally with -alpha, -beta
#   or -rc and .N, without the v;
# - vVERSION is higher than every other release tag, in the order
#   release.yml's guard uses (release-tags.sh);
# - CHANGELOG.md has the notes release.yml will publish (release-notes.sh);
# - the check run ci-ok of GitHub Actions succeeded on GITHUB_SHA, the commit
#   the run started on;
# - the tag does not exist, unless it is this script's annotated tag on
#   GITHUB_SHA, left by a run whose dispatch failed: then a re-run only
#   dispatches.
# It creates the annotated tag on GITHUB_SHA, never on main's head read
# again, through the API (git/tags, then git/refs), so that no credentials
# are kept in a checkout, and runs gh workflow run release.yml --ref vVERSION:
# events caused by GITHUB_TOKEN start no workflows, workflow_dispatch apart.
# Usage: .github/scripts/tag-release.sh VERSION, from the top of a checkout
# of GITHUB_SHA. Needs gh with GH_TOKEN (contents: write, actions: write,
# checks: read), and GITHUB_REF, GITHUB_REPOSITORY and GITHUB_SHA as GitHub
# Actions sets them.
set -euo pipefail

me=${0##*/}
dir=$(dirname "$0")
# shellcheck source-path=SCRIPTDIR source=release-tags.sh
. "$dir/release-tags.sh"

tagger_name='github-actions[bot]'
tagger_email='41898282+github-actions[bot]@users.noreply.github.com'

fail() {
	echo "$me: $*" >&2
	exit 1
}

if [ $# -ne 1 ]; then
	echo "usage: $me VERSION" >&2
	exit 2
fi
version=$1
tag=v$version
if ! [[ $tag =~ $release_tag_re ]]; then
	echo "$me: $version is not a release version: X.Y.Z, optionally with -alpha, -beta or -rc and .N, without the v" >&2
	exit 2
fi
: "${GITHUB_REF:?}" "${GITHUB_REPOSITORY:?}" "${GITHUB_SHA:?}"
if [ "$GITHUB_REF" != refs/heads/main ]; then
	fail "run on $GITHUB_REF: tag releases from main only"
fi

# The version goes up: every other release tag is lower.
tags=$(release_tags) || fail "cannot list the tags of $GITHUB_REPOSITORY"
others=$(grep -vxF -- "$tag" <<<"$tags" || true)
highest=$(printf '%s\n%s\n' "$others" "$tag" | sed '/^$/d' | release_order | tail -n 1)
if [ "$highest" != "$tag" ]; then
	fail "$tag is not higher than every release tag: $highest exists"
fi

# A tag of that name exists: it must be the one a run of this script made
# on this commit.
existing=
if grep -qxF -- "$tag" <<<"$tags"; then
	object=$(gh api "repos/$GITHUB_REPOSITORY/git/ref/tags/$tag" --jq '.object.type + " " + .object.sha') ||
		fail "cannot read the tag $tag"
	made_here=
	if [[ $object == "tag "* ]]; then
		annotated=$(gh api "repos/$GITHUB_REPOSITORY/git/tags/${object#tag }" \
			--jq '[.tag, .tagger.name, .tagger.email, .object.type, .object.sha] | join(" ")') ||
			fail "cannot read the tag object of $tag"
		if [ "$annotated" = "$tag $tagger_name $tagger_email commit $GITHUB_SHA" ]; then
			made_here=1
		fi
	fi
	if [ -z "$made_here" ]; then
		fail "$tag exists already, and is not the annotated tag of $tagger_name on $GITHUB_SHA that a run whose dispatch failed leaves"
	fi
	existing=1
fi

# The notes release.yml will take from CHANGELOG.md.
"$dir/release-notes.sh" "$version" >/dev/null ||
	fail "CHANGELOG.md has no release notes for $version (see above)"

# ci-ok, the required status check, on the commit to tag.
runs=$(gh api "repos/$GITHUB_REPOSITORY/commits/$GITHUB_SHA/check-runs?check_name=ci-ok&filter=latest" \
	--jq '.check_runs[] | [.app.slug, .status, .conclusion // "none"] | join(" ")') ||
	fail "cannot read the check runs of $GITHUB_SHA"
if [ -z "$runs" ]; then
	fail "ci-ok has not run on $GITHUB_SHA: wait for CI on main"
fi
if grep -vqxF 'github-actions completed success' <<<"$runs"; then
	fail "ci-ok did not succeed on $GITHUB_SHA: $(tr '\n' ';' <<<"$runs")"
fi

if [ -n "$existing" ]; then
	echo "$me: $tag exists on $GITHUB_SHA from an earlier run; starting release.yml only"
else
	message="gosftpd $tag"
	if [ -n "${GITHUB_RUN_ID:-}" ]; then
		message+=$'\n\n'"Tagged by ${GITHUB_SERVER_URL:-https://github.com}/$GITHUB_REPOSITORY/actions/runs/$GITHUB_RUN_ID"
	fi
	object=$(gh api --method POST "repos/$GITHUB_REPOSITORY/git/tags" \
		-f tag="$tag" -f message="$message" -f object="$GITHUB_SHA" -f type=commit \
		-f "tagger[name]=$tagger_name" -f "tagger[email]=$tagger_email" --jq .sha) ||
		fail "cannot create the tag object of $tag"
	gh api --method POST "repos/$GITHUB_REPOSITORY/git/refs" \
		-f ref="refs/tags/$tag" -f sha="$object" --silent ||
		fail "cannot create the tag $tag"
	echo "$me: tagged $GITHUB_SHA as $tag"
fi
gh workflow run release.yml --ref "$tag" --repo "$GITHUB_REPOSITORY" ||
	fail "cannot start release.yml on $tag: run this workflow again, which then only starts it, or gh workflow run release.yml --ref $tag"
echo "$me: started release.yml on $tag"
