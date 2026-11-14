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

if [ "$failures" -ne 0 ]; then
    echo "$failures check(s) failed"
    exit 1
fi
echo "All checks passed"
