#!/bin/sh
# Copyright (c) 2026 Obtuse Networking LLC
# SPDX-License-Identifier: MIT
#
# Writes the software bill of materials, SPDX 2.3 in JSON, for a source tree:
# signet itself, the Go toolchain it needs, every module compiled in from
# vendor/ and the SQLite library inside go-sqlite3.  The modules come from
# vendor/modules.txt, their licences from each module's licence file, and
# whether a module is a direct or an indirect dependency from go.mod.
#
#   sbom.sh <source tree> <version> > signet-<version>.spdx.json
#
# distfile.sh runs it, so every source archive carries signet.spdx.json.

set -eu
tree=${1:?usage: sbom.sh <source tree> <version>}
version=${2:?usage: sbom.sh <source tree> <version>}
cd "$tree"

# The SPDX licence expression of a licence file.
classify() {
	if grep -q 'Apache License' "$1" && grep -q 'MIT' "$1"; then
		echo 'MIT AND Apache-2.0'
	elif grep -q 'Apache License' "$1"; then
		echo 'Apache-2.0'
	elif grep -q 'Permission is hereby granted, free of charge' "$1"; then
		echo 'MIT'
	elif grep -q 'Redistribution and use in source and binary forms' "$1"; then
		if grep -qi 'Neither the name' "$1"; then echo 'BSD-3-Clause'; else echo 'BSD-2-Clause'; fi
	else
		echo "sbom.sh: cannot tell the licence of $1" >&2
		exit 1
	fi
}

# The first Copyright line of a licence file, or NOASSERTION.
copyright() {
	found=$(grep -iE '^[[:space:]]*(portions )?copyright[[:space:]]*(\(c\)|©|[0-9])' "$1" | head -1 |
		sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' || true)
	if [ -n "$found" ]; then printf '%s' "$found"; else printf 'NOASSERTION'; fi
}

json() { # a string as a JSON string literal
	printf '"%s"' "$(printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' | tr -d '\000-\037')"
}

# An SPDX identifier from a module path: letters, digits, "." and "-" only.
ref() {
	printf 'SPDXRef-%s' "$(printf '%s' "$1" | sed 's/[^A-Za-z0-9.-]/-/g')"
}

# The module proxy's path for a module or version: capitals become "!" and the
# lower-case letter (go help goproxy).
escape() {
	printf '%s' "$1" | sed 's/[A-Z]/!&/g' | tr 'A-Z' 'a-z'
}

uuid=$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n' |
	sed 's/^\(.\{8\}\)\(.\{4\}\).\(.\{3\}\).\(.\{3\}\)\(.\{12\}\)$/\1-\2-4\3-a\4-\5/')
created=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
go_version=$(sed -n 's/^go \([0-9.]*\).*/\1/p' go.mod)

package() { # spdxid name version purl download licence copyright supplier comment
	printf '    {\n'
	printf '      "SPDXID": %s,\n' "$(json "$1")"
	printf '      "name": %s,\n' "$(json "$2")"
	printf '      "versionInfo": %s,\n' "$(json "$3")"
	printf '      "supplier": %s,\n' "$(json "$8")"
	printf '      "downloadLocation": %s,\n' "$(json "$5")"
	printf '      "filesAnalyzed": false,\n'
	printf '      "licenseConcluded": %s,\n' "$(json "$6")"
	printf '      "licenseDeclared": %s,\n' "$(json "$6")"
	printf '      "copyrightText": %s,\n' "$(json "$7")"
	[ -z "$9" ] || printf '      "comment": %s,\n' "$(json "$9")"
	printf '      "externalRefs": [\n'
	printf '        {"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": %s}\n' "$(json "$4")"
	printf '      ]\n'
	printf '    }'
}

relations=$(mktemp)
trap 'rm -f "$relations"' EXIT
relate() { # from type to [comment]
	if [ -n "${4:-}" ]; then
		printf '    {"spdxElementId": %s, "relationshipType": %s, "relatedSpdxElement": %s, "comment": %s}' \
			"$(json "$1")" "$(json "$2")" "$(json "$3")" "$(json "$4")" >> "$relations"
	else
		printf '    {"spdxElementId": %s, "relationshipType": %s, "relatedSpdxElement": %s}' \
			"$(json "$1")" "$(json "$2")" "$(json "$3")" >> "$relations"
	fi
	printf ',\n' >> "$relations"
}

cat <<EOF
{
  "spdxVersion": "SPDX-2.3",
  "dataLicense": "CC0-1.0",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "signet-$version",
  "documentNamespace": "https://obtusenet.com/spdx/signet-$version-$uuid",
  "creationInfo": {
    "created": "$created",
    "creators": ["Organization: Obtuse Networking LLC", "Tool: signet-sbom.sh-$version"],
    "comment": "Made from vendor/modules.txt and go.mod; every module listed is compiled into the binary."
  },
  "packages": [
EOF

package SPDXRef-signet signet "$version" "pkg:golang/github.com/obtusenet/signet@v$version" NOASSERTION MIT \
	"Copyright (c) 2026 Obtuse Networking LLC" "Organization: Obtuse Networking LLC" \
	"The application. Built with CGO for go-sqlite3."
relate SPDXRef-DOCUMENT DESCRIBES SPDXRef-signet

printf ',\n'
package SPDXRef-go go "$go_version" "pkg:golang/stdlib@v$go_version" https://go.dev/dl/ BSD-3-Clause \
	"Copyright 2009 The Go Authors" "Organization: The Go Authors" \
	"The Go toolchain and standard library; this is the least version go.mod allows, the build may use a later one."
relate SPDXRef-go BUILD_TOOL_OF SPDXRef-signet

sed -n 's/^# \([^ ]*\) \([^ ]*\)$/\1 \2/p' vendor/modules.txt | while read -r module mversion; do
	dir=vendor/$module
	[ -d "$dir" ] || continue
	file=$(ls "$dir" | grep -iE '^(LICEN[CS]E|COPYING)(\.md|\.txt)?$' | head -1)
	if [ -z "$file" ]; then
		echo "sbom.sh: $module has no licence file" >&2
		exit 1
	fi
	license=$(classify "$dir/$file")
	if grep -qE "^[[:space:]]*(require[[:space:]]+)?$module[[:space:]]+$mversion[[:space:]]+// indirect" go.mod; then
		kind=indirect
	else
		kind=direct
	fi
	id=$(ref "$module")
	printf ',\n'
	package "$id" "$module" "$mversion" "pkg:golang/$module@$mversion" \
		"https://proxy.golang.org/$(escape "$module")/@v/$(escape "$mversion").zip" \
		"$license" "$(copyright "$dir/$file")" NOASSERTION "A $kind dependency (go.mod)."
	relate SPDXRef-signet DEPENDS_ON "$id" "$kind"
done

binding=vendor/github.com/mattn/go-sqlite3/sqlite3-binding.h
if [ -f "$binding" ]; then
	sqlite=$(sed -n 's/^#define SQLITE_VERSION[[:space:]]*"\([^"]*\)".*/\1/p' "$binding" | head -1)
	printf ',\n'
	package SPDXRef-sqlite sqlite "$sqlite" "pkg:generic/sqlite@$sqlite" https://sqlite.org/download.html blessing \
		NONE "Organization: SQLite Consortium" \
		"The SQLite amalgamation that go-sqlite3 carries and compiles in; in the public domain."
	relate "$(ref github.com/mattn/go-sqlite3)" CONTAINS SPDXRef-sqlite
fi

printf '\n  ],\n  "relationships": [\n'
sed '$ s/,$//' "$relations"
printf '  ]\n}\n'
