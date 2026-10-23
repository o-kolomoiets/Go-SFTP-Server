#!/usr/bin/env bash
# Runs a command block of docs/install.md, so that CI tests the documented
# commands themselves, not copies of them (ADR 0012). The block is the one
# fenced sh or bash block between the lines <!-- ci:NAME --> and
# <!-- /ci -->; it runs with bash -euo pipefail in the current directory,
# with standard input from /dev/null.
# - V, the version under test, comes from the caller's environment: the
#   block's own V= line, which names a release for readers, is dropped.
# - gh release download is skipped when every file it names with -p is
#   present already (release.yml runs the verify block in dist/).
# Usage: test/docs/run-block.sh [--print] NAME [MARKDOWN]
# --print writes the block as it would run instead of running it. MARKDOWN
# defaults to this repository's docs/install.md.
set -euo pipefail

me=${0##*/}
print=
if [ "${1:-}" = --print ]; then
	print=1
	shift
fi
if [ $# -lt 1 ] || [ $# -gt 2 ] || ! [[ $1 =~ ^[a-z0-9][a-z0-9-]*$ ]]; then
	echo "usage: $me [--print] NAME [MARKDOWN]" >&2
	exit 2
fi
name=$1
doc=${2:-$(cd "$(dirname "$0")/../.." && pwd)/docs/install.md}
if ! [ -r "$doc" ]; then
	echo "$me: cannot read $doc" >&2
	exit 2
fi

# The block's lines, or an error on standard error and exit 2: exactly one
# marker for NAME, followed by one fenced sh or bash block that is not
# empty and then the closing marker, with nothing but blank lines between
# them.
block=$(awk -v opening="<!-- ci:$name -->" -v closing="<!-- /ci -->" -v doc="$doc" '
	function fail(msg) { printf "%s:%d: %s\n", doc, NR, msg > "/dev/stderr"; failed = 1; exit 2 }
	state == 0 && $0 == opening {
		if (++markers > 1) fail("a second " opening)
		state = 1; fences = 0; next
	}
	state == 1 && $0 == closing {
		if (fences == 0) fail(opening " holds no fenced block")
		state = 0; next
	}
	state == 1 && /^```(sh|bash)$/ {
		if (++fences > 1) fail(opening " holds more than one fenced block")
		state = 2; lines = 0; next
	}
	state == 1 && /^```/ { fail(opening " holds a block that is not sh or bash: " $0) }
	state == 1 && NF > 0 { fail("text outside the fenced block of " opening ": " $0) }
	state == 2 && $0 == "```" {
		if (lines == 0) fail("the block of " opening " is empty")
		state = 1; next
	}
	state == 2 { lines++; print }
	END {
		if (failed) exit 2
		if (markers == 0) { printf "%s: no block %s\n", doc, opening > "/dev/stderr"; exit 2 }
		if (state != 0) { printf "%s: %s is not closed by %s\n", doc, opening, closing > "/dev/stderr"; exit 2 }
	}
' "$doc") || exit 2

# The V= line names a release for readers; the caller's V replaces it.
if grep -q '^V=[^[:space:]]*$' <<<"$block"; then
	block=$(grep -v '^V=[^[:space:]]*$' <<<"$block")
	if [ -z "${V:-}" ]; then
		echo "$me: the $name block uses V: set V to the version under test" >&2
		exit 2
	fi
fi

if [ -n "$print" ]; then
	printf '%s\n' "$block"
	exit 0
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
printf '%s\n' "$block" >"$tmp/block.sh"
# Sourced before the block: gh release download is skipped when every
# pattern it is given matches a file in its directory (-D, else the
# current one); everything else goes to gh. The ERR trap names the line
# of the block that failed.
cat >"$tmp/prelude.sh" <<'EOF'
gh() {
	if [ "${1:-}" = release ] && [ "${2:-}" = download ]; then
		local dir=. args=("${@:3}") patterns=() i=0 p
		while [ "$i" -lt "${#args[@]}" ]; do
			case ${args[i]} in
			-p | --pattern) patterns+=("${args[i + 1]:-}") && i=$((i + 1)) ;;
			--pattern=*) patterns+=("${args[i]#--pattern=}") ;;
			-D | --dir) dir=${args[i + 1]:-} && i=$((i + 1)) ;;
			--dir=*) dir=${args[i]#--dir=} ;;
			esac
			i=$((i + 1))
		done
		local present=${#patterns[@]}
		for p in "${patterns[@]}"; do
			compgen -G "$dir/$p" >/dev/null || present=0
		done
		if [ "$present" -gt 0 ]; then
			echo "run-block.sh: skipped gh release download: ${patterns[*]} present in $dir" >&2
			return 0
		fi
	fi
	command gh "$@"
}
trap 'echo "run-block.sh: the $RUN_BLOCK block failed at line $LINENO with exit status $?" >&2' ERR
EOF
{
	echo "$me: the $name block of $doc${V:+, with V=$V}:"
	sed 's/^/    /' "$tmp/block.sh"
} >&2
RUN_BLOCK=$name bash -Eeuo pipefail -c '. "$1"; . "$2"' "$me" "$tmp/prelude.sh" "$tmp/block.sh" </dev/null
