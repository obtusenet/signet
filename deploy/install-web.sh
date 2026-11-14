#!/bin/sh
# Copyright (c) 2026 Obtuse Networking LLC
# SPDX-License-Identifier: MIT
#
# Install a version's web files without losing local edits.
#
# usage: install-web.sh <source dir> <destination dir> <manifest> [owner[:group]]
#
# The manifest records the checksum of each file as last installed.  A file is
# replaced only when it still matches that record, so it has not been edited.  An
# edited file, or one with no record, is kept and reported.  New files are added.

set -eu
umask 022

if [ $# -lt 3 ] || [ $# -gt 4 ]; then
	echo "usage: install-web.sh <source dir> <destination dir> <manifest> [owner[:group]]" >&2
	exit 2
fi
src=$1
dest=$2
manifest=$3
owner=${4:-}

if [ ! -d "$src" ]; then
	echo "install-web.sh: $src is not a directory" >&2
	exit 1
fi

checksum() {
	if command -v sha256sum > /dev/null 2>&1; then
		sha256sum < "$1" | cut -d' ' -f1
	else
		sha256 -q "$1"
	fi
}

# The checksum recorded for a path, if any.
recorded() {
	[ -f "$manifest" ] || return 0
	WANT=$1 awk '{ sum = $1; sub(/^[^ ]+  /, ""); if ($0 == ENVIRON["WANT"]) print sum }' "$manifest"
}

take_ownership() {
	[ -z "$owner" ] || chown "$owner" "$1"
}

place() {
	dir=$(dirname "$dest/$1")
	if [ ! -d "$dir" ]; then
		mkdir -p "$dir"
		take_ownership "$dir"
	fi
	tmp="$dest/$1.new.$$"
	cp "$src/$1" "$tmp"
	chmod 644 "$tmp"
	take_ownership "$tmp"
	mv -f "$tmp" "$dest/$1"
}

mkdir -p "$dest"
take_ownership "$dest"

list=$(mktemp "$manifest.list.XXXXXX")
next=$(mktemp "$manifest.next.XXXXXX")
trap 'rm -f "$list" "$next"' EXIT
(cd "$src" && find . -type f | sed 's|^\./||' | sort) > "$list"

while IFS= read -r file; do
	new=$(checksum "$src/$file")
	old=$(recorded "$file")
	if [ ! -e "$dest/$file" ]; then
		place "$file"
		old=$new
	else
		current=$(checksum "$dest/$file")
		if [ "$current" = "$new" ]; then
			old=$new
		elif [ "$current" = "$old" ]; then
			place "$file"
			echo "updated: $dest/$file"
			old=$new
		else
			echo "kept: $dest/$file has local edits; this version's copy is $src/$file"
		fi
	fi
	[ -z "$old" ] || printf '%s  %s\n' "$old" "$file" >> "$next"
done < "$list"

chmod 644 "$next"
mv -f "$next" "$manifest"
