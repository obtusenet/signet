#!/bin/sh
# Copyright (c) 2026 Obtuse Networking LLC
# SPDX-License-Identifier: MIT
# distfile.sh - Create the source archive: by default the zip used by the OpenBSD
# port, or with "tar" the source tarball made by `make build`.
#
# The archive holds the tracked source plus the `vendor` tree, so the port
# builds with no network access (GOPROXY=off, GOFLAGS=-mod=vendor).  It is
# a zip with a single top-level directory (signet-<version>/), which is what
# the ports framework expects: the tree unpacks into ${WRKDIST}.

set -eu

VERSION="${VERSION:-0.14.0}"
DISTNAME="signet-${VERSION}"
case "${1:-zip}" in
zip) DISTFILE="${DISTNAME}.zip" ;;
tar) DISTFILE="${DISTNAME}.tar.gz" ;;
*)
	echo "usage: distfile.sh [zip|tar]" >&2
	exit 1
	;;
esac
DIST_DIR="dist"
STAGE_DIR="build/diststage"

cd "$(dirname "$0")"

if [ ! -d vendor ]; then
	echo "error: vendor/ is missing; run 'go mod vendor' first" >&2
	exit 1
fi

echo "Creating distribution file: ${DIST_DIR}/${DISTFILE}"
mkdir -p "${DIST_DIR}"
rm -f "${DIST_DIR}/${DISTFILE}"
DISTABS=$(cd "${DIST_DIR}" && pwd)
rm -rf "${STAGE_DIR}"
mkdir -p "${STAGE_DIR}/${DISTNAME}"

# Tracked files plus the (untracked) vendored dependencies.  Anything the
# port does not need to build, and anything generated locally, stays out.
FILE_LIST=$(mktemp)
trap 'rm -f "${FILE_LIST}"; rm -rf "${STAGE_DIR}"' EXIT

# Tracked files, untracked files that are not ignored (new sources, the
# vendored tree) and vendor/ explicitly, so a source file that exists only in
# the working tree still reaches the build.
{
	git ls-files
	git ls-files --others --exclude-standard
	find vendor -type f
} | grep -v -e '^dist/' -e '^build/' | sort -u > "${FILE_LIST}"

while IFS= read -r f; do
	mkdir -p "${STAGE_DIR}/${DISTNAME}/$(dirname "$f")"
	cp -p "$f" "${STAGE_DIR}/${DISTNAME}/$f"
done < "${FILE_LIST}"

# The software bill of materials of what the archive holds, also kept beside it.
contrib/packaging/sbom.sh "${STAGE_DIR}/${DISTNAME}" "${VERSION}" > "${STAGE_DIR}/sbom.json"
cp "${STAGE_DIR}/sbom.json" "${STAGE_DIR}/${DISTNAME}/signet.spdx.json"
mv "${STAGE_DIR}/sbom.json" "${DIST_DIR}/${DISTNAME}.spdx.json"

# An archive has no git history to ask, so it carries its own commit.  A build
# with -X main.gitHash still wins.
HASH=$(git rev-parse --short HEAD 2>/dev/null || echo unknown)
if [ -n "$(git status --porcelain 2>/dev/null)" ]; then
	HASH="${HASH}-dirty"
fi
INFO="${STAGE_DIR}/${DISTNAME}/cmd/signet/zz_distinfo.go"
cat > "${INFO}" <<EOF
package main

func init() {
	if gitHash == "unknown" {
		gitHash = "${HASH}"
	}
}
EOF

if [ "${1:-zip}" = tar ]; then
	tar -czf "${DISTABS}/${DISTFILE}" -C "${STAGE_DIR}" "${DISTNAME}"
	echo "Created ${DIST_DIR}/${DISTFILE}"
	exit 0
fi

(cd "${STAGE_DIR}" && zip -q -X -r "${DISTABS}/${DISTFILE}" \
	"${DISTNAME}")

echo "Created ${DIST_DIR}/${DISTFILE}"
echo
echo "distinfo entry:"
if command -v sha256 >/dev/null 2>&1; then
	# OpenBSD
	SUM=$(sha256 -q "${DIST_DIR}/${DISTFILE}")
else
	SUM=$(sha256sum "${DIST_DIR}/${DISTFILE}" | awk '{print $1}')
fi
SIZE=$(wc -c < "${DIST_DIR}/${DISTFILE}" | tr -d ' ')
echo "SHA256 (${DISTFILE}) = ${SUM}"
echo "SIZE (${DISTFILE}) = ${SIZE}"
