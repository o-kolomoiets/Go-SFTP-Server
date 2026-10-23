#!/usr/bin/env bash
# Checks the files release.yml's generate job uploaded and puts them into a
# new OUT directory, with the empty directories the image copies (ADR 0012).
# GENERATED, where the release job downloaded them, must hold exactly:
# - THIRD_PARTY_LICENSES;
# - completions/_gosftpd, completions/gosftpd.bash and
#   completions/gosftpd.fish;
# - man/gosftpd.1.gz, and man pages named man/gosftpd-*.1.gz;
# as regular files, in the directories man and completions. Code that runs
# in the generate job controls what it uploads, and only this check stands
# between that and the signed archives, packages and image: a planted
# out/docker/home-root/usr/bin/gosftpd would replace the image's binary.
# Missing files fail too: GoReleaser builds without a man page or a
# completion that a pattern does not find.
# OUT/docker/empty and OUT/docker/home-root/home are created here, as make
# generate creates them, never taken from the artifact.
# Usage: .github/scripts/release-out.sh GENERATED OUT
set -euo pipefail

me=${0##*/}
if [ $# -ne 2 ]; then
	echo "usage: $me GENERATED OUT" >&2
	exit 2
fi
generated=$1
out=$2
if ! [ -d "$generated" ] || [ -L "$generated" ]; then
	echo "$me: $generated is not a directory" >&2
	exit 1
fi
if [ -e "$out" ] || [ -L "$out" ]; then
	echo "$me: $out exists: the files go into a new directory" >&2
	exit 1
fi

required="THIRD_PARTY_LICENSES completions/_gosftpd completions/gosftpd.bash completions/gosftpd.fish man/gosftpd.1.gz"
allowed='^(THIRD_PARTY_LICENSES|completions/(_gosftpd|gosftpd\.bash|gosftpd\.fish)|man/gosftpd(-[a-z0-9-]+)?\.1\.gz)$'
status=0
files=()
while IFS= read -r -d '' name; do
	name=${name#./}
	path=$generated/$name
	if [ -L "$path" ]; then
		echo "$me: $name: a symbolic link" >&2
		status=1
	elif [ -d "$path" ]; then
		case $name in
		man | completions) ;;
		*)
			echo "$me: $name: an unexpected directory" >&2
			status=1
			;;
		esac
	elif [ -f "$path" ]; then
		if [[ $name =~ $allowed ]]; then
			files+=("$name")
		else
			echo "$me: $name: an unexpected file" >&2
			status=1
		fi
	else
		echo "$me: $name: neither a regular file nor a directory" >&2
		status=1
	fi
done < <(cd "$generated" && find . -mindepth 1 -print0)
for name in $required; do
	if ! [ -f "$generated/$name" ] || [ -L "$generated/$name" ]; then
		echo "$me: $name is missing" >&2
		status=1
	fi
done
if [ "$status" -ne 0 ]; then
	echo "$me: $generated does not hold exactly the files of make generate that a release takes" >&2
	exit 1
fi

mkdir -p "$out/man" "$out/completions" "$out/docker/empty" "$out/docker/home-root/home"
for name in "${files[@]}"; do
	cp "$generated/$name" "$out/$name"
done
echo "$me: $out holds ${#files[@]} files from $generated, and the image's empty directories"
