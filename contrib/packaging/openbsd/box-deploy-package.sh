#!/bin/sh
# Copyright (c) 2026 Obtuse Networking LLC
# SPDX-License-Identifier: MIT
# Install the package on the test box and restart every instance that runs the
# binary.  Run by `make deploy-package`.  Never touches /etc/signet, and keeps any
# edited web file.
#
# Every instance stops first and comes back even when the install fails, so a
# bad deploy leaves the previous version running rather than nothing.

set -eu

version=$1
pkg=/usr/ports/packages/$(machine -a)/all/signet-$version.tgz
binary=/usr/local/bin/signet
runtime=/var/www/signet
examples=/usr/local/share/examples/signet/web

if [ ! -f "$pkg" ]; then
	echo "$pkg not found; run make build-package first" >&2
	exit 1
fi

# Read the package before anything stops, so a bad one costs no outage.  The sum
# is checked after the install because pkg_add can fail and still exit 0.
tmp=$(mktemp -d)
if ! tar -xzf "$pkg" -C "$tmp" bin/signet; then
	rm -rf "$tmp"
	echo "$pkg is unreadable" >&2
	exit 1
fi
want=$(sha256 -q "$tmp/bin/signet")
rm -rf "$tmp"

# Any rc script that runs this binary, whoever installed it.
instances() {
	grep -l "^daemon=\"$binary\"" /etc/rc.d/* 2>/dev/null | xargs -n1 basename
}

stopped=
start_instances() {
	trap - EXIT
	failed=
	enabled=$(doas rcctl ls on)
	for s in $(instances); do
		case " $stopped " in
		*" $s "*) ;;
		*) echo "$enabled" | grep -qx "$s" || continue ;;
		esac
		doas rcctl start "$s" || failed="$failed $s"
	done
	if [ -n "$failed" ]; then
		echo "failed to start:$failed" >&2
		return 1
	fi
}

trap 'rc=$?; start_instances || true; exit $rc' EXIT
for s in $(instances); do
	if doas rcctl check "$s" >/dev/null 2>&1; then
		doas rcctl stop "$s"
		stopped="$stopped $s"
	fi
done

# -D installed: reinstall when only the contents changed, not the version.
doas pkg_add -I -r -D unsigned -D installed "$pkg"
if [ "$(sha256 -q "$binary")" != "$want" ]; then
	echo "pkg_add did not install $pkg" >&2
	exit 1
fi

# The package leaves the runtime tree alone on upgrade, so bring it up to this
# version, except for files with local edits.
for d in templates static; do
	doas /bin/sh "$examples/../install-web.sh" "$examples/$d" "$runtime/$d" \
		"$runtime/.web-$d.sha256" _signet:_signet
done

start_instances
sleep 1

"$binary" version
for s in $(instances); do
	doas rcctl ls on | grep -qx "$s" && doas rcctl check "$s"
done
curl -fsS --unix-socket "$runtime/signet.sock" http://localhost/health ||
	curl -fsS http://localhost:9090/health
echo
