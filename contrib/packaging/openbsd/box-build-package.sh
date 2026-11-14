#!/bin/sh
# Copyright (c) 2026 Obtuse Networking LLC
# SPDX-License-Identifier: MIT
# Build the OpenBSD package on the test box.  Run by `make build-package`, which
# first copies the distfile and its distinfo to /tmp.  Touches no service.
#
# The recorded plist and any earlier package are dropped first: otherwise the
# ports framework treats the package as up to date, or refuses a changed plist.

set -eu

version=$1
arch=$(machine -a)
zip=/tmp/signet-$version.zip
distinfo=/tmp/signet-$version.distinfo

tmp=$(mktemp -d)
trap 'rm -rf "$tmp" "$zip" "$distinfo"' EXIT
unzip -q "$zip" "signet-$version/contrib/packaging/openbsd/www/signet/*" -d "$tmp"

doas rm -rf /usr/ports/www/signet
doas cp -R "$tmp/signet-$version/contrib/packaging/openbsd/www/signet" /usr/ports/www/
doas cp "$distinfo" /usr/ports/www/signet/distinfo

# The framework's own directories: a fresh ports tree has no distfiles yet.
cd /usr/ports/www/signet
distdir=$(make show=FULLDISTDIR)
packages=$(make show=PACKAGE_REPOSITORY)
plists=$(make show=PLIST_REPOSITORY)
pkg=$packages/$arch/all/signet-$version.tgz
doas install -d "$distdir"
doas cp "$zip" "$distdir/"
doas rm -f "$plists/$arch/signet-$version" "$plists/$arch/signet-$version-new" \
	"$pkg" "$packages/$arch/ftp/signet-$version.tgz"

doas make clean
doas make package

ls -l "$pkg"
