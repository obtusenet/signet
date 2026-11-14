#!/bin/sh
# Copyright (c) 2026 Obtuse Networking LLC
# SPDX-License-Identifier: MIT
#
# Builds the FreeBSD package on the FreeBSD box, as the calling user, in an overlay
# at ~/signet-port that never touches /usr/ports.  Run by `make freebsd-package`,
# which first copies the source tarball and its distinfo to /tmp.  Touches no
# service.  DEVELOPER=yes turns on stage-qa; check-plist and portlint run after.
#
#   box-build-package.sh <version>

set -eu
version=$1
P=$HOME/signet-port
tarball=/tmp/signet-$version.tar.gz
distinfo=/tmp/signet-$version.distinfo

mkdir -p "$P/distfiles" "$P/work" "$P/packages" "$P/www" "$P/db"
# signet's ids: 906, OpenBSD's, is opentsdb's here.
printf 'signet:*:784:784::0:0:Signet authentication server:/nonexistent:/usr/sbin/nologin\n' > "$P/UIDs"
printf 'signet:*:784:\n' > "$P/GIDs"
cat > "$P/env.sh" <<EOF
export PORTSDIR=/usr/ports DISTDIR=$P/distfiles WRKDIRPREFIX=$P/work PACKAGES=$P/packages
export PORT_DBDIR=$P/db BATCH=yes
export UID_FILES="/usr/ports/UIDs $P/UIDs" GID_FILES="/usr/ports/GIDs $P/GIDs"
EOF
. "$P/env.sh"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"; rm -f "$tarball" "$distinfo"' EXIT
tar -xzf "$tarball" -C "$tmp" "signet-$version/contrib/packaging/freebsd/www/signet"
rm -rf "$P/www/signet"
cp -R "$tmp/signet-$version/contrib/packaging/freebsd/www/signet" "$P/www/"
cp "$distinfo" "$P/www/signet/distinfo"
cp "$tarball" "$P/distfiles/"

cd "$P/www/signet"
make clean > /dev/null
# portlint on the port as committed: after a build it also reads the work tree's
# pkg-install and pkg-message, whose %%PREFIX%% is already /usr/local.  It asks
# git about the port, and the overlay is not a repository.
echo "--- portlint"
portlint -AC 2>&1 | grep -v 'not a git repository' || true
make DEVELOPER=yes package
make DEVELOPER=yes check-plist
ls -l "$P/packages/All/signet-$version"*.pkg
