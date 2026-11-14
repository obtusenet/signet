#!/bin/sh
# Copyright (c) 2026 Obtuse Networking LLC
# SPDX-License-Identifier: MIT
#
# Builds the Debian package in a debian:13 container, as the calling user, from
# the source tarball of `make build`, and runs lintian on it.  The .deb lands in
# dist/.  Run from the repository root; `make deb` runs it.
#
#   build.sh [debian version]
#
# The version defaults to <version>-1, from the Makefile.  Another one (a test's
# "next version") gets a changelog entry in the build copy only.

set -eu
cd "$(dirname "$0")/../../.."
VERSION=$(sed -n 's/^VERSION=//p' Makefile)
DEBVERSION=${1:-$VERSION-1}
IMAGE=signet-debbuild:13

./distfile.sh tar > /dev/null
docker build -q -t "$IMAGE" contrib/packaging/debian > /dev/null

docker run --rm -u "$(id -u):$(id -g)" -e HOME=/tmp -e VERSION="$VERSION" -e DEBVERSION="$DEBVERSION" \
	-v "$PWD/dist:/out" -v "$PWD/contrib/packaging/debian:/pkg:ro" "$IMAGE" sh -euc '
	cd /tmp
	cp "/out/signet-$VERSION.tar.gz" "signet_$VERSION.orig.tar.gz"
	tar xzf "signet_$VERSION.orig.tar.gz"
	cd "signet-$VERSION"
	cp -r /pkg/debian debian
	/pkg/copyright.sh . > debian/copyright
	if [ "$(dpkg-parsechangelog -S Version)" != "$DEBVERSION" ]; then
		DEBFULLNAME=Code DEBEMAIL=code@obtusenet.com \
			dch -b -v "$DEBVERSION" -D unstable "Build of $DEBVERSION." 2> /dev/null
	fi
	DEB_BUILD_OPTIONS=noddebs dpkg-buildpackage -b -us -uc > /tmp/build.log 2>&1 || { tail -50 /tmp/build.log; exit 1; }
	cd ..
	cp signet_*.deb signet_*.buildinfo signet_*.changes /out/
	lintian --display-info --pedantic signet_*.deb > /out/lintian.txt 2>&1 || true
	echo "--- lintian"
	cat /out/lintian.txt
	ls signet_*.deb
'
