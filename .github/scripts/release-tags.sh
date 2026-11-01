# The release tags of $GITHUB_REPOSITORY and their order, for
# release-guard.sh and tag-release.sh, which source this file (ADR 0012):
# tag.yml accepts only a version that release.yml's guard will then run.
# Needs gh with GH_TOKEN, and GNU sort.

# A release tag: vX.Y.Z, optionally with -alpha, -beta or -rc and .N.
release_tag_re='^v[0-9]+\.[0-9]+\.[0-9]+(-(alpha|beta|rc)(\.[0-9]+)?)?$'

# release_tags prints the release tags of $GITHUB_REPOSITORY in release
# order, one per line; other tags that start with v, such as vtest, do not
# count. A failed request fails, rather than giving a shorter list.
release_tags() {
	local refs ref tag
	refs=$(gh api --paginate "repos/$GITHUB_REPOSITORY/git/matching-refs/tags/v" --jq '.[].ref') || return
	while IFS= read -r ref; do
		tag=${ref#refs/tags/}
		if [[ $ref == refs/tags/* && $tag =~ $release_tag_re ]]; then
			printf '%s\n' "$tag"
		fi
	done <<<"$refs" | release_order
}

# release_order sorts release tags from the lowest version to the highest:
# sort -V with the pre-release's "-" turned into "~", which sorts before
# the end of a string, so that v0.5.0-rc.1 comes before v0.5.0, rc before
# rc.1 and rc.9 before rc.10.
release_order() {
	sed 's/-/~/' | LC_ALL=C sort -V | sed 's/~/-/'
}
