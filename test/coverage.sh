#!/usr/bin/env bash
# Checks the coverage floors of the security packages (ROADMAP §8.5) in Go
# coverage directories, e.g. from
#   go test -cover -coverpkg=./... ./... -args -test.gocoverdir=$PWD/coverage/unit
#   GOCOVERDIR=$PWD/coverage/e2e test/interop/run.sh
# Usage: test/coverage.sh DIR... Writes a summary to $GITHUB_STEP_SUMMARY
# when set. Only the floors fail; the total is informational.
set -euo pipefail

declare -A FLOOR=(
	[internal/vfs]=85
	[internal/auth]=90
	[internal/config]=85
	[internal/sftpd]=85
)
MODULE=github.com/o-kolomoiets/go-sftp-server

dirs=$(IFS=,; echo "$*")
percent=$(go tool covdata percent -i="$dirs")
profile=$(mktemp)
trap 'rm -f "$profile"' EXIT
go tool covdata textfmt -i="$dirs" -o "$profile"
total=$(go tool cover -func="$profile" | awk '/^total:/ {print $NF}')

failed=0
summary="| Package | Coverage | Floor |"$'\n'"|---|---|---|"$'\n'
while read -r pkg pct; do
	pkg=${pkg#"$MODULE"/}
	pct=${pct%\%}
	floor=${FLOOR[$pkg]:-}
	mark=""
	if [ -n "$floor" ] && awk -v p="$pct" -v f="$floor" 'BEGIN { exit !(p + 0 < f + 0) }'; then
		mark=" ❌"
		failed=1
		echo "FAIL: $pkg coverage $pct% is below $floor%" >&2
	fi
	summary+="| \`$pkg\` | $pct%$mark | ${floor:+$floor%} |"$'\n'
done < <(echo "$percent" | awk '{print $1, $3}')
summary+="| **total** | $total | |"$'\n'

echo "$summary"
if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
	{ echo "### Coverage (unit + e2e)"; echo; echo "$summary"; } >>"$GITHUB_STEP_SUMMARY"
fi
for pkg in "${!FLOOR[@]}"; do
	if ! echo "$percent" | grep -q "$MODULE/$pkg[[:space:]]"; then
		echo "FAIL: no coverage data for $pkg" >&2
		failed=1
	fi
done
exit "$failed"
