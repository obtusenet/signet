#!/bin/sh
# Copyright (c) 2026 Obtuse Networking LLC
# SPDX-License-Identifier: MIT
#
# Every source file, script and man page outside vendor/ carries the MIT header, and the
# packages ship LICENSE.  Run from the repository root.

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT" || exit 2
missing=0
for f in $(git ls-files | grep -v '^vendor/'); do
	case "$f" in
	*.go|*.sh|*.py|*.js|*Makefile|*.rc|*Dockerfile|man/man[1-9]/*) ;;
	*) head -c2 "$f" | grep -q '#!' || continue ;;
	esac
	# The header is in the first four lines: after a shebang, if there is one.
	if ! head -4 "$f" | grep -q 'SPDX-License-Identifier: MIT' ||
	   ! head -4 "$f" | grep -q 'Copyright (c) 2026 Obtuse Networking LLC'; then
		echo "FAIL - no MIT header: $f"
		missing=$((missing + 1))
	fi
done
grep -q '^MIT License$' LICENSE || { echo "FAIL - LICENSE is not the MIT text"; missing=$((missing + 1)); }
grep -qx 'share/doc/signet/LICENSE' contrib/packaging/openbsd/www/signet/pkg/PLIST ||
	{ echo "FAIL - the OpenBSD package does not ship LICENSE"; missing=$((missing + 1)); }
grep -q 'LICENSE' deploy/install.sh || { echo "FAIL - the Linux install does not ship LICENSE"; missing=$((missing + 1)); }
grep -q 'LICENSE' contrib/packaging/docker/Dockerfile || { echo "FAIL - the image does not ship LICENSE"; missing=$((missing + 1)); }
echo "license: $missing problems"
[ "$missing" -eq 0 ]
