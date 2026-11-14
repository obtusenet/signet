#!/bin/bash
# Copyright (c) 2026 Obtuse Networking LLC
# SPDX-License-Identifier: MIT
#
# Tests the Docker image as its README tells people to run it, with a throwaway
# config, volume and network.  Run by `make test-docker`, which builds the image.
# Mail goes to a fake relay on an internal Docker network, so no message can leave.

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DOCKER_DIR="$ROOT/contrib/packaging/docker"
IMAGE=signet:latest
RELAY_IMAGE=python:3.13-alpine
PROJECT=signettest
CONFIG="$DOCKER_DIR/config.yaml"
ADDR="dockertest@example.com"
PASSWORD="docker-test-long-password"
BASE=http://localhost:8080

if [[ -e "$CONFIG" ]]; then
    echo "$CONFIG exists; this test will not replace it" >&2
    exit 2
fi
if ss -lnt 2>/dev/null | grep -q ':8080\b'; then
    echo ":8080 is in use" >&2
    exit 2
fi

DIR="$(mktemp -d)"
compose() { (cd "$DOCKER_DIR" && docker compose -p "$PROJECT" "$@"); }
cleanup() {
    compose down -v --remove-orphans > /dev/null 2>&1
    docker rm -f "$PROJECT-mail" "$PROJECT-relay" > /dev/null 2>&1
    docker volume rm "$PROJECT-mail-data" > /dev/null 2>&1
    docker network rm "$PROJECT-internal" > /dev/null 2>&1
    rm -f "$CONFIG"
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
code() { curl --silent --max-time 10 --output /dev/null --write-out '%{http_code}' "$@"; }
wait_up() {
    for _ in $(seq 1 30); do
        [[ "$(code "$BASE/health")" == "200" ]] && return 0
        sleep 1
    done
    return 1
}
own_config() { # the README's chown, without needing sudo here
    docker run --rm --network none --user 0 -v "$(dirname "$1"):/d" "$IMAGE" chown 1001:1001 "/d/$(basename "$1")"
}

echo "=== Signet Docker test ==="
echo "--- the build"
contains "version details" "hash $(git -C "$ROOT" rev-parse --short HEAD)" "$(docker run --rm --network none "$IMAGE" signet version)"
docker build -q --target builder -t "$PROJECT-builder" -f "$DOCKER_DIR/Dockerfile" "$ROOT" > /dev/null
BUILD_TREE="$(docker run --rm --network none "$PROJECT-builder" ls -A /app | tr '\n' ' ')"
check "build context is the allow-list" "LICENSE cmd examples go.mod go.sum internal vendor web " "$BUILD_TREE"
docker rmi "$PROJECT-builder" > /dev/null 2>&1

echo "--- refused starts"
OUTPUT="$(docker run --rm --network none -v "$ROOT/config/example.yaml:/etc/signet/config.yaml:ro" "$IMAGE" 2>&1)"
check "no cookie_secret stops it" 1 "$?"
contains "and says why" "cookie_secret must be set" "$OUTPUT"

SECRET="$(openssl rand -hex 32)"
sed "s/^cookie_secret: \"\"/cookie_secret: \"$SECRET\"/" "$ROOT/config/example.yaml" > "$CONFIG"
chmod 600 "$CONFIG"

OUTPUT="$(docker run --rm --network none -v "$CONFIG:/etc/signet/config.yaml:ro" "$IMAGE" 2>&1)"
if [[ "$(id -u)" != 0 && "$(id -u)" != 1001 ]]; then
    contains "a config it cannot read stops it" "permission denied" "$OUTPUT"
fi
own_config "$CONFIG"

mkdir "$DIR/bad-templates"
printf '{{' > "$DIR/bad-templates/login.html"
chmod -R a+rX "$DIR"
OUTPUT="$(docker run --rm --network none -v "$CONFIG:/etc/signet/config.yaml:ro" \
    -v "$DIR/bad-templates:/etc/signet/templates:ro" "$IMAGE" 2>&1)"
check "a broken template stops it" 1 "$?"
contains "and names it" "login.html" "$OUTPUT"

echo "--- Compose, as the README says"
compose up -d --no-build > /dev/null 2>&1
if wait_up; then echo "ok   - it starts"; passed=$((passed + 1)); else echo "FAIL - it did not start"; failed=$((failed + 1)); compose logs --tail 10; fi
check "login page, from the image" 200 "$(code "$BASE/login")"
check "recover page, from the image" 200 "$(code "$BASE/recover")"
check "webauthn.js, from the image" 200 "$(code "$BASE/static/js/webauthn.js")"
contains "email templates, from the image" "pin.txt" "$(compose exec -T signet ls /etc/signet/templates/email)"
check "config warning absent" "" "$(compose logs 2>&1 | grep 'world-readable')"
check "database private" "-rw-------" "$(compose exec -T signet ls -l /var/lib/signet/sessions.db | cut -d' ' -f1)"

compose exec -T signet signet user-add "$ADDR" "$PASSWORD" > /dev/null
JAR="$DIR/jar"
check "login" 302 "$(code -c "$JAR" --data-urlencode "email=$ADDR" --data-urlencode "password=$PASSWORD" "$BASE/login")"
TOKEN="$(awk '/signetid/{print $7}' "$JAR")"
session() { code -H "Cookie: signetid=$TOKEN" "$BASE/session"; }
check "session" 200 "$(session)"
compose restart > /dev/null 2>&1; wait_up
check "session after restart" 200 "$(session)"
compose down > /dev/null 2>&1; compose up -d --no-build > /dev/null 2>&1; wait_up
check "session after recreate" 200 "$(session)"
for _ in $(seq 1 45); do
    HEALTH="$(docker inspect --format '{{.State.Health.Status}}' "$PROJECT-signet-1")"
    [[ "$HEALTH" != starting ]] && break
    sleep 1
done
check "Docker reports healthy" healthy "$HEALTH"
compose down -v > /dev/null 2>&1

echo "--- mail through SMTPHOST, on a network with no way out"
cat > "$DIR/relay.py" <<'PY'
import socketserver, sys
class H(socketserver.StreamRequestHandler):
    def handle(self):
        def say(s): self.wfile.write((s + "\r\n").encode()); self.wfile.flush()
        say("220 fake")
        data = False
        for raw in self.rfile:
            line = raw.decode(errors="replace").rstrip("\r\n")
            print(line, flush=True)
            if data:
                if line == ".": data = False; say("250 ok")
            elif line.upper().startswith("DATA"): data = True; say("354 go")
            elif line.upper().startswith("QUIT"): say("221 bye"); return
            else: say("250 ok")
socketserver.TCPServer.allow_reuse_address = True
socketserver.TCPServer(("0.0.0.0", 25), H).serve_forever()
PY
chmod a+r "$DIR/relay.py"
docker network create --internal "$PROJECT-internal" > /dev/null
docker run -d --name "$PROJECT-relay" --network "$PROJECT-internal" --network-alias relay \
    -v "$DIR/relay.py:/relay.py:ro" "$RELAY_IMAGE" python -u /relay.py > /dev/null
docker volume create "$PROJECT-mail-data" > /dev/null
docker run -d --name "$PROJECT-mail" --network "$PROJECT-internal" -e SMTPHOST=relay \
    -v "$CONFIG:/etc/signet/config.yaml:ro" -v "$PROJECT-mail-data:/var/lib/signet" "$IMAGE" > /dev/null
inside() { docker exec "$PROJECT-mail" "$@"; }
for _ in $(seq 1 30); do
    inside wget -qO- http://localhost:8080/health > /dev/null 2>&1 && break
    sleep 1
done
inside signet user-add -config /etc/signet/config.yaml "$ADDR" "$PASSWORD" > /dev/null
contains "PIN request answered" '"success":true' "$(inside wget -qO- --header 'Content-Type: application/json' \
    --post-data "{\"email\":\"$ADDR\"}" http://localhost:8080/email-pin/send 2>&1)"
sleep 2
MAIL="$(docker logs "$PROJECT-relay" 2>&1)"
contains "relay got the recipient" "RCPT TO:<$ADDR>" "$MAIL"
contains "relay got the sender" "MAIL FROM:<noreply@" "$MAIL"
contains "message uses the text and HTML templates" "multipart/alternative" "$MAIL"
PIN="$(printf '%s\n' "$MAIL" | grep -oE '\b[0-9]{6}\b' | head -1)"
check "PIN in the message" 6 "${#PIN}"
contains "that PIN signs in" '"success":true' "$(inside wget -qO- --header 'Content-Type: application/json' \
    --post-data "{\"email\":\"$ADDR\",\"pin\":\"$PIN\"}" http://localhost:8080/email-pin/verify 2>&1)"
docker rm -f "$PROJECT-mail" > /dev/null
docker volume rm "$PROJECT-mail-data" > /dev/null

echo
echo "passed: $passed, failed: $failed"
[[ $failed -eq 0 ]]
