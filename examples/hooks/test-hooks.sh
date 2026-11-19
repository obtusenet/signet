#!/bin/bash
# Copyright (c) 2026 Obtuse Networking LLC
# SPDX-License-Identifier: MIT
#
# Protocol test for the example claims hooks: each hook runs once per request
# (as signet runs it) and must answer a claim_request with a claim_response.
# Exits non-zero if any check fails.
#

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REQUEST='{"type":"claim_request","email":"test@example.com"}'
failures=0

check() {
    local name="$1" output="$2" expected="$3"
    if printf '%s' "$output" | grep -q "$expected"; then
        echo "ok   - $name"
    else
        echo "FAIL - $name (wanted $expected, got: $output)"
        failures=$((failures + 1))
    fi
}

echo "=== Signet Claims Hook Protocol Test ==="

for hook in claims-hook.py claims-hook.sh; do
    path="$SCRIPT_DIR/$hook"

    output=$(printf '%s\n' "$REQUEST" | timeout 5 "$path" 2>/dev/null)
    check "$hook answers a request" "$output" '"type": *"claim_response"'
    check "$hook returns the address" "$output" 'test@example.com'

    # Older signet versions sent no trailing newline; the hooks still cope.
    output=$(printf '%s' "$REQUEST" | timeout 5 "$path" 2>/dev/null)
    check "$hook copes with no trailing newline" "$output" '"type": *"claim_response"'

    # The role comes from the whole domain, not a suffix of the text.
    admin='{"type":"claim_request","email":"boss@Admin.Example.com","session_token":"t"}'
    output=$(printf '%s\n' "$admin" | timeout 5 "$path" 2>/dev/null)
    check "$hook gives the admin domain its role" "$output" '"role": *"admin"'
    list='{"type":"claim_request","email":"a@evil.example,b@admin.example.com","session_token":"t"}'
    output=$(printf '%s\n' "$list" | timeout 5 "$path" 2>/dev/null)
    if printf '%s' "$output" | grep -q '"role": *"admin"'; then
        echo "FAIL - $hook made a list of addresses admin: $output"
        failures=$((failures + 1))
    else
        echo "ok   - $hook gives a list of addresses no role"
    fi

    # Bad input must not produce a claim_response.
    output=$(printf 'not valid json\n' | timeout 5 "$path" 2>/dev/null)
    if printf '%s' "$output" | grep -q '"claim_response"'; then
        echo "FAIL - $hook granted claims for invalid JSON: $output"
        failures=$((failures + 1))
    else
        echo "ok   - $hook grants nothing for invalid JSON"
    fi
done

# radius-claims.py and radius-claims.sh: a role from the RADIUS groups.  The
# shell one runs under each POSIX shell here.
radius_req='{"type":"claim_request","email":"jdoe","source":"radius","radius":{"nas_identifier":"wiki","groups":["staff","wiki-editors","a\",\"wiki-admins","x]y"],"attributes":[{"type":11,"name":"Filter-Id","value":"staff"}]}}'
radius_check() { # name command...
    local name="$1"
    shift
    local output
    output=$(printf '%s\n' "$radius_req" | timeout 5 "$@" 2>/dev/null)
    check "$name answers a request" "$output" '"type": *"claim_response"'
    check "$name takes the role from the groups" "$output" '"role": *"editor"'
    check "$name passes the groups on" "$output" '"groups": *\["staff", *"wiki-editors"'
    check "$name names the application" "$output" '"application": *"wiki"'
    output=$(printf '%s\n' "$REQUEST" | timeout 5 "$@" 2>/dev/null)
    check "$name gives a local account the default role" "$output" '"role": *"user"'
    output=$(printf 'not valid json\n' | timeout 5 "$@" 2>/dev/null)
    if printf '%s' "$output" | grep -q '"claim_response"'; then
        echo "FAIL - $name granted claims for invalid JSON: $output"
        failures=$((failures + 1))
    else
        echo "ok   - $name grants nothing for invalid JSON"
    fi
}
radius_check radius-claims.py "$SCRIPT_DIR/radius-claims.py"
for sh in sh bash ksh mksh ksh93; do
    command -v "$sh" > /dev/null || continue
    radius_check "radius-claims.sh under $sh" "$sh" "$SCRIPT_DIR/radius-claims.sh"
done

if [ "$failures" -ne 0 ]; then
    echo "$failures check(s) failed"
    exit 1
fi
echo "All checks passed"
