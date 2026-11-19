#!/bin/bash
# Copyright (c) 2026 Obtuse Networking LLC
# SPDX-License-Identifier: MIT
#
# Signet against a real FreeRADIUS, in Docker: PAP and MS-CHAPv2, groups,
# different answers by NAS-Identifier, a challenge, and local accounts that never
# reach the server.  FreeRADIUS requires Message-Authenticator in every request,
# and Signet in every reply, so passing at all proves both.  Signet runs here on
# unix sockets; FreeRADIUS listens on a loopback port.  Not part of make test.
#
# Usage: tests/radius_test.sh [path/to/signet]

set -uo pipefail

SIGNET="$(cd "$(dirname "${1:-build/signet}")" && pwd)/$(basename "${1:-build/signet}")"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="freeradius/freeradius-server:3.2.8@sha256:bbb399476d804b710c8289559c5a6ce4ac20cb81113554ea371614f30ee0ad41"
NAME="signet-radius-test-$$"
if [[ ! -x "$SIGNET" ]]; then
    echo "$SIGNET not found; run make first" >&2
    exit 2
fi

DIR="$(mktemp -d)"
PIDS=()
cleanup() {
    for pid in "${PIDS[@]}"; do
        kill "$pid" 2>/dev/null && wait "$pid" 2>/dev/null
    done
    [[ -n "${KEEP_LOGS:-}" ]] && docker logs "$NAME" > "$KEEP_LOGS" 2>&1
    docker rm -f "$NAME" > /dev/null 2>&1
    rm -rf "$DIR"
}
trap cleanup EXIT

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
lacks() { # name needle haystack
    if [[ "$3" != *"$2"* ]]; then
        echo "ok   - $1"
        passed=$((passed + 1))
    else
        echo "FAIL - $1: '$2' is in it"
        failed=$((failed + 1))
    fi
}

echo "=== Signet against FreeRADIUS ==="
docker run -d --name "$NAME" -p 127.0.0.1::1812/udp \
    -v "$ROOT/tests/radius/clients.conf:/etc/freeradius/clients.conf:ro" \
    -v "$ROOT/tests/radius/authorize:/etc/freeradius/mods-config/files/authorize:ro" \
    -v "$ROOT/tests/radius/default:/etc/freeradius/sites-available/default:ro" \
    "$IMAGE" freeradius -X > /dev/null || { echo "docker run failed" >&2; exit 1; }
for _ in $(seq 60); do
    docker logs "$NAME" 2>&1 | grep -q 'Ready to process requests' && break
    sleep 0.5
done
if ! docker logs "$NAME" 2>&1 | grep -q 'Ready to process requests'; then
    docker logs "$NAME" 2>&1 | tail -20
    echo "FreeRADIUS did not start" >&2
    exit 1
fi
PORT="$(docker port "$NAME" 1812/udp | head -1 | sed 's/.*://')"
echo "FreeRADIUS on 127.0.0.1:$PORT"

# start <name> <auth> <nas_identifier> [yaml]: a signet on $DIR/<name>.sock
# asking FreeRADIUS, with one local account, local@example.com.  yaml is more
# top-level settings, and radius ones in its "  " lines go after the block.
start() {
    local dir="$DIR/$1"
    mkdir -p "$dir"
    cat > "$dir/config.yaml" <<YAML
listen: "$dir/signet.sock"
database_path: "$dir/sessions.db"
csv_path: "$dir/users.csv"
templates_dir: "$ROOT/web/templates"
static_dir: "$ROOT/web/static"
cookie_secret: "$(printf 'radius-only-%.0s' 1 2 3 4)"
cookie_secure: false
log_syslog: false
mail:
  program: ""
radius:
  enabled: true
  nas_identifier: "$3"
  servers:
    - address: "127.0.0.1:$PORT"
      secret: "testing123"
      auth: "$2"
  timeout_seconds: 2
  retries: 1
  group_attributes: ["Filter-Id", "Class"]
${4:-}
YAML
    "$SIGNET" user-add -config "$dir/config.yaml" -password-stdin local@example.com \
        <<< "local-long-password" > /dev/null || { echo "user-add failed" >&2; exit 1; }
    "$SIGNET" serve -config "$dir/config.yaml" > "$dir/log" 2>&1 &
    PIDS+=("$!")
    for _ in $(seq 50); do
        [[ -S "$dir/signet.sock" ]] && return
        sleep 0.1
    done
    cat "$dir/log" >&2
    echo "signet $1 did not start" >&2
    exit 1
}

SOCK=""
use() { SOCK="$DIR/$1/signet.sock"; rm -f "$DIR/jar"; }
http() { curl --silent --show-error --max-time 15 --unix-socket "$SOCK" "$@"; }
# login <name> <password>: JSON reply; the cookie goes to $DIR/jar.
login() {
    http -c "$DIR/jar" -H 'Accept: application/json' \
        --data-urlencode "email=$1" --data-urlencode "password=$2" http://localhost/login
}
status() {
    http -o /dev/null -w '%{http_code}' -H 'Accept: application/json' \
        --data-urlencode "email=$1" --data-urlencode "password=$2" http://localhost/login
}
session() { http -b "$DIR/jar" -D "$DIR/headers" http://localhost/session; }
pending() { sed -n 's/.*"pending":"\([^"]*\)".*/\1/p'; }

start pap-wiki pap wiki
start mschap-wiki mschapv2 wiki
start pap-blog pap blog
start pap-2fa pap wiki '  challenge_is_second_factor: true
second_factor: "required"
second_factor_methods: ["totp"]
auth_methods:
  password: "enabled"
  totp: "enabled"'

for inst in pap-wiki mschap-wiki; do
    echo "--- $inst"
    use "$inst"
    contains "jdoe signs in" '"success":true' "$(login jdoe radius-pw)"
    s="$(session)"
    contains "the session is jdoe's" '"user":"jdoe"' "$s"
    contains "by RADIUS" '"method":"radius"' "$s"
    contains "with both groups" '"groups":["wiki-admins","staff"]' "$s"
    contains "no address for a plain name" '"email":""' "$s"
    lacks "no Remote-Email for a plain name" "Remote-Email" "$(cat "$DIR/headers")"
    check "a wrong password is refused" 401 "$(status jdoe wrong-pw)"
    check "an unknown name is refused" 401 "$(status nobody radius-pw)"
    contains "bob signs in to the wiki" '"success":true' "$(login bob bob-pw)"
    contains "as a wiki editor" '"groups":["wiki-editors"]' "$(session)"
    contains "a local account signs in" '"success":true' "$(login local@example.com local-long-password)"
    contains "with no groups" '"claims":{}' "$(session)"
done

echo "--- pap-wiki: names that are addresses, Class, and a challenge"
use pap-wiki
contains "jane@example.com signs in" '"success":true' "$(login jane@example.com jane-pw)"
s="$(session)"
contains "Class is a group" '"groups":["staff"]' "$s"
contains "an address is an address" '"email":"jane@example.com"' "$s"
contains "Remote-Email is set" "Remote-Email: jane@example.com" "$(cat "$DIR/headers")"

reply="$(login otp-user radius-pw)"
contains "otp-user is challenged" '"step":"radius"' "$reply"
contains "with the server's prompt" '"message":"Enter the code from your token"' "$reply"
token="$(pending <<< "$reply")"
check "a wrong answer is refused" 401 "$(http -o /dev/null -w '%{http_code}' \
    --data-urlencode "pending=$token" --data-urlencode "code=000000" http://localhost/login)"
token="$(login otp-user radius-pw | pending)"
check "the right answer signs in" 302 "$(http -c "$DIR/jar" -o /dev/null -w '%{http_code}' \
    --data-urlencode "pending=$token" --data-urlencode "code=123456" http://localhost/login)"
contains "with the group the answer brought" '"groups":["tokens"]' "$(session)"

http -o /dev/null -D "$DIR/headers" -H 'Accept: application/json' \
    --data-urlencode "email=timed" --data-urlencode "password=timed-pw" http://localhost/login
contains "Session-Timeout sets the cookie's Max-Age" "Max-Age=600" "$(cat "$DIR/headers")"

contains "jdoe signs in again" '"success":true' "$(login jdoe radius-pw)"
check "session-revoke matches a RADIUS name exactly" "JDOE has no sessions" \
    "$("$SIGNET" session-revoke -config "$DIR/pap-wiki/config.yaml" JDOE)"
contains "session-revoke ends jdoe's sessions" "sessions of jdoe" \
    "$("$SIGNET" session-revoke -config "$DIR/pap-wiki/config.yaml" jdoe)"
contains "and the session is gone" '"valid":false' "$(session)"

echo "--- pap-blog: another application, other groups"
use pap-blog
contains "bob signs in to the blog" '"success":true' "$(login bob bob-pw)"
contains "as a blog reader" '"groups":["blog-readers"]' "$(session)"

echo "--- pap-2fa: second_factor required, and the challenge counts"
use pap-2fa
token="$(login otp-user radius-pw | pending)"
check "an answered challenge signs in" 302 "$(http -c "$DIR/jar" -o /dev/null -w '%{http_code}' \
    --data-urlencode "pending=$token" --data-urlencode "code=123456" http://localhost/login)"
contains "as the second factor" '"method":"radius+challenge"' "$(session)"
reply="$(login jdoe radius-pw)"
contains "no challenge, so Signet's own factor is added" '"step":"enrol"' "$reply"
lacks "and no session yet" '"success":true' "$reply"

echo "--- what FreeRADIUS saw"
logs="$(docker logs "$NAME" 2>&1)"
lacks "local accounts never reached it" "local@example.com" "$logs"
contains "NAS-Identifier arrived" 'NAS-Identifier = "blog"' "$logs"
lacks "no Calling-Station-Id for a unix-socket client" "Calling-Station-Id" "$logs"
contains "MS-CHAPv2 was checked" 'mschap: Found Cleartext-Password' "$logs"

echo
echo "passed: $passed, failed: $failed"
[[ $failed -eq 0 ]]
