#!/bin/sh
# Copyright (c) 2026 Obtuse Networking LLC
# SPDX-License-Identifier: MIT
#
# The packages' sample configurations are config/example.yaml with only the
# settings that differ by OS changed (contrib/packaging/config.sh), and the
# committed copies are current.  Run from the repository root; part of make test.

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT" || exit 2
failed=0
fail() { echo "FAIL - $*"; failed=$((failed + 1)); }

for os in openbsd freebsd debian; do
	out=$(contrib/packaging/config.sh "$os") || { fail "$os: config.sh failed"; continue; }
	# Only these settings may differ, one line each.
	extra=$(printf '%s\n' "$out" | diff config/example.yaml - | grep '^[<>]' | grep -cv '^[<>] \(listen\|templates_dir\|static_dir\|database_path\|csv_path\|log_syslog\):')
	[ "$extra" -eq 0 ] || fail "$os: lines other than the OS settings differ"
	[ "$(printf '%s\n' "$out" | wc -l)" -eq "$(wc -l < config/example.yaml)" ] || fail "$os: line count differs"
done

check_copy() { # os file
	if ! contrib/packaging/config.sh "$1" | cmp -s - "$2"; then
		fail "$2 is not current: run make configs"
	fi
}
check_copy openbsd contrib/packaging/openbsd/www/signet/files/config.yaml
check_copy freebsd contrib/packaging/freebsd/www/signet/files/config.yaml.sample
check_copy debian config/example.yaml

echo "config copies: $failed problems"
[ "$failed" -eq 0 ]
