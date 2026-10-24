#!/usr/bin/env bash
# Prints the release notes of a version: its section of CHANGELOG.md
# without the heading. A pre-release without a section of its own gets the
# Unreleased section. Fails when that leaves no notes (ADR 0012).
# Usage: .github/scripts/release-notes.sh VERSION [CHANGELOG]
# VERSION is X.Y.Z with an optional -alpha, -beta or -rc and .N, with or
# without a leading v; CHANGELOG defaults to CHANGELOG.md. The release
# workflow passes the output to goreleaser release --release-notes.
set -euo pipefail

me=${0##*/}
if [ $# -lt 1 ] || [ $# -gt 2 ]; then
	echo "usage: $me VERSION [CHANGELOG]" >&2
	exit 2
fi
version=${1#v}
changelog=${2:-CHANGELOG.md}
release='^[0-9]+\.[0-9]+\.[0-9]+(-(alpha|beta|rc)(\.[0-9]+)?)?$'
if ! [[ $version =~ $release ]]; then
	echo "$me: $1 is not a release version (X.Y.Z, optionally with -alpha, -beta or -rc and .N)" >&2
	exit 2
fi
if ! [ -r "$changelog" ]; then
	echo "$me: cannot read $changelog" >&2
	exit 1
fi

# section NAME prints the lines under the heading "## [NAME]" (alone or
# followed by " - DATE") up to the next "## " heading or the link
# definitions at the end of the file, without leading and trailing blank
# lines. It exits 3 when there is no such heading.
section() {
	awk -v heading="## [$1]" '
		/^## / {
			if (inside) exit
			if (substr($0, 1, length(heading)) == heading) {
				rest = substr($0, length(heading) + 1)
				if (rest == "" || substr(rest, 1, 1) == " ") found = inside = 1
			}
			next
		}
		inside && /^\[.*\]: / { exit }
		inside && NF == 0 { blank++; next }
		inside {
			if (started) for (; blank > 0; blank--) print ""
			blank = 0
			started = 1
			print
		}
		END { exit found ? 0 : 3 }
	' "$changelog"
}

name=$version
status=0
notes=$(section "$name") || status=$?
if [ "$status" -eq 3 ] && [[ $version == *-* ]]; then
	name=Unreleased
	status=0
	notes=$(section "$name") || status=$?
fi
if [ "$status" -eq 3 ]; then
	if [ "$name" = Unreleased ]; then
		echo "$me: $changelog has neither a section [$version] nor [Unreleased]" >&2
	else
		echo "$me: $changelog has no section [$version]: move the Unreleased entries under \"## [$version] - YYYY-MM-DD\" (docs/release-checklist.md)" >&2
	fi
	exit 1
fi
[ "$status" -eq 0 ] || exit "$status"
if [ -z "$notes" ]; then
	if [ "$name" = Unreleased ]; then
		echo "$me: $changelog has no section [$version], and its section [Unreleased] is empty" >&2
	else
		echo "$me: the section [$version] of $changelog is empty" >&2
	fi
	exit 1
fi
printf '%s\n' "$notes"
