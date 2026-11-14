#!/bin/sh
# Copyright (c) 2026 Obtuse Networking LLC
# SPDX-License-Identifier: MIT
#
# Writes debian/copyright (DEP-5) for an unpacked source tree: signet's own
# licence, then each vendored module's, read from its licence file, so the list
# follows vendor/modules.txt.
#
#   copyright.sh <source tree> > debian/copyright

set -eu
tree=${1:?usage: copyright.sh <source tree>}
cd "$tree"

indent() { # the text as a DEP-5 field continuation: blank lines become " ."
	sed -e 's/[[:space:]]*$//' -e 's/^$/./' -e 's/^/ /'
}

# The licence a file holds, as a DEP-5 short name.
classify() {
	if grep -q 'Apache License' "$1" && grep -q 'MIT' "$1"; then
		echo 'Expat and Apache-2.0'
	elif grep -q 'Apache License' "$1"; then
		echo 'Apache-2.0'
	elif grep -q 'Permission is hereby granted, free of charge' "$1"; then
		echo 'Expat'
	elif grep -q 'Redistribution and use in source and binary forms' "$1"; then
		if grep -qi 'Neither the name' "$1"; then echo 'BSD-3-clause'; else echo 'BSD-2-clause'; fi
	else
		echo "copyright.sh: cannot tell the licence of $1" >&2
		exit 1
	fi
}

holders() { # the Copyright lines of a licence file, or a stand-in
	found=$(grep -iE '^[[:space:]]*(portions )?copyright[[:space:]]*(\(c\)|©|[0-9])' "$1" |
		sed -E 's/^[[:space:]]*(portions )?copyright[[:space:]]*(\(c\)|©)?[[:space:]]*//I' | head -5 || true)
	if [ -n "$found" ]; then printf '%s\n' "$found"; else echo "the authors of $2"; fi
}

cat <<'EOF'
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: signet
Upstream-Contact: Code <code@obtusenet.com>
Source: https://github.com/obtusenet/signet

Files: *
Copyright: 2026 Obtuse Networking LLC
License: Expat
EOF
sed '1,/^Copyright/d' LICENSE | sed '/./,$!d' | indent

for module in $(sed -n 's/^# \([^ ]*\) .*/\1/p' vendor/modules.txt); do
	dir=vendor/$module
	[ -d "$dir" ] || continue
	file=$(ls "$dir" | grep -iE '^(LICEN[CS]E|COPYING)(\.md|\.txt)?$' | head -1)
	if [ -z "$file" ]; then
		echo "copyright.sh: $module has no licence file" >&2
		exit 1
	fi
	license=$(classify "$dir/$file")
	echo
	echo "Files: $dir/*"
	holders "$dir/$file" "$module" | sed '1s/^/Copyright: /; 2,$s/^/ /'
	echo "License: $license"
	if [ "$license" = Apache-2.0 ]; then
		echo " On Debian systems the full text is in /usr/share/common-licenses/Apache-2.0."
	else
		indent < "$dir/$file"
	fi
done

# go-sqlite3 carries the SQLite amalgamation, which is in the public domain.
if [ -f vendor/github.com/mattn/go-sqlite3/sqlite3-binding.c ]; then
	cat <<'EOF'

Files: vendor/github.com/mattn/go-sqlite3/sqlite3-binding.c
 vendor/github.com/mattn/go-sqlite3/sqlite3-binding.h
Copyright: none: the authors of SQLite dedicated it to the public domain
License: public-domain
 The author disclaims copyright to this source code.  In place of a legal
 notice, here is a blessing:
 .
 May you do good and not evil.
 May you find forgiveness for yourself and forgive others.
 May you share freely, never taking more than you give.
EOF
fi
