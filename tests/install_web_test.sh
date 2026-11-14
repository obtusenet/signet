#!/bin/bash
# Copyright (c) 2026 Obtuse Networking LLC
# SPDX-License-Identifier: MIT
#
# Tests deploy/install-web.sh, which must never lose an edited web file.  No root,
# network or server is needed.

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOOL="$ROOT/deploy/install-web.sh"
DIR="$(mktemp -d)"
trap 'rm -rf "$DIR"' EXIT

passed=0
failed=0
check() { # name want got
    if [[ "$3" == "$2" ]]; then
        echo "ok   - $1"
        passed=$((passed + 1))
    else
        echo "FAIL - $1: want '$2', got '$3'"
        failed=$((failed + 1))
    fi
}
contains() { # name needle haystack
    if [[ "$3" == *"$2"* ]]; then
        echo "ok   - $1"
        passed=$((passed + 1))
    else
        echo "FAIL - $1: '$2' not in '$3'"
        failed=$((failed + 1))
    fi
}

SRC="$DIR/src"
DEST="$DIR/live/templates"
MANIFEST="$DIR/live/.web.sha256"
mkdir -p "$SRC/email" "$DIR/live"
ship() { printf '%s\n' "$2" > "$SRC/$1"; }
install_web() { "$TOOL" "$SRC" "$DEST" "$MANIFEST" 2>&1; }

echo "=== install-web.sh ==="
echo "--- first install"
ship login.html v1-login
ship recover.html v1-recover
ship email/pin.txt v1-pin
chmod 600 "$SRC/recover.html"
OUTPUT="$(install_web)"
check "exit status" 0 "$?"
check "says nothing when nothing needs saying" "" "$OUTPUT"
check "file installed" v1-login "$(cat "$DEST/login.html")"
check "nested file installed" v1-pin "$(cat "$DEST/email/pin.txt")"
check "a private source file still ends up readable" 644 "$(stat -c %a "$DEST/recover.html")"
check "no leftovers" "" "$(find "$DIR/live" -name '*.new.*' -o -name '*.list.*' -o -name '*.next.*')"

echo "--- same version again"
OUTPUT="$(install_web)"
check "nothing to report" "" "$OUTPUT"
check "no directory nested in itself" "" "$(find "$DEST" -mindepth 1 -type d -name templates)"

echo "--- new version, one file edited"
printf 'my-login\n' > "$DEST/login.html"
ship login.html v2-login
ship recover.html v2-recover
ship email/new.txt v2-new
OUTPUT="$(install_web)"
check "edited file kept" my-login "$(cat "$DEST/login.html")"
contains "edited file reported" "kept: $DEST/login.html has local edits" "$OUTPUT"
contains "report says where the new copy is" "$SRC/login.html" "$OUTPUT"
check "unedited file updated" v2-recover "$(cat "$DEST/recover.html")"
contains "update reported" "updated: $DEST/recover.html" "$OUTPUT"
check "file new in this version added" v2-new "$(cat "$DEST/email/new.txt")"
check "file that did not change left alone" v1-pin "$(cat "$DEST/email/pin.txt")"

echo "--- the edit survives further versions"
ship login.html v3-login
OUTPUT="$(install_web)"
check "still kept" my-login "$(cat "$DEST/login.html")"
contains "still reported" "kept: $DEST/login.html" "$OUTPUT"

echo "--- an edit undone to the version it came from updates again"
printf 'v1-login\n' > "$DEST/login.html"
OUTPUT="$(install_web)"
check "updated" v3-login "$(cat "$DEST/login.html")"
contains "reported" "updated: $DEST/login.html" "$OUTPUT"

echo "--- an edit that matches the new version needs no report"
printf 'v4-login\n' > "$DEST/login.html"
ship login.html v4-login
check "nothing to report" "" "$(install_web)"
ship login.html v5-login
OUTPUT="$(install_web)"
check "and it counts as unedited afterwards" v5-login "$(cat "$DEST/login.html")"

echo "--- a tree with no record, as older installs have"
LEGACY="$DIR/legacy"
mkdir "$LEGACY"
printf 'old-or-edited\n' > "$LEGACY/login.html"
OUTPUT="$("$TOOL" "$SRC" "$LEGACY" "$DIR/legacy.sha256" 2>&1)"
check "unknown file kept" old-or-edited "$(cat "$LEGACY/login.html")"
contains "unknown file reported" "kept: $LEGACY/login.html" "$OUTPUT"
check "missing file added" v2-recover "$(cat "$LEGACY/recover.html")"

echo "--- a file removed by hand comes back"
rm "$DEST/recover.html"
install_web > /dev/null
check "restored" v2-recover "$(cat "$DEST/recover.html")"

echo "--- bad use"
"$TOOL" "$SRC" > /dev/null 2>&1
check "too few arguments" 2 "$?"
"$TOOL" "$DIR/absent" "$DEST" "$MANIFEST" > /dev/null 2>&1
check "no source" 1 "$?"

echo
echo "passed: $passed, failed: $failed"
[[ $failed -eq 0 ]]
