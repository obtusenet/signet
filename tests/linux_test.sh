#!/bin/bash
# Copyright (c) 2026 Obtuse Networking LLC
# SPDX-License-Identifier: MIT
#
# Tests deploy/install.sh on a throwaway Debian with real systemd, following its own
# next steps, then an upgrade.  Run by `make test-linux`.  systemd needs a privileged
# container on this kind of host; it has no network and the repository is read-only.
# The binary comes from build/signet, so this host needs a compatible libc.

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE=signet-linuxtest
NAME=signet-linuxtest

cleanup() { docker rm -f "$NAME" > /dev/null 2>&1; }
trap cleanup EXIT
cleanup

docker build -q -t "$IMAGE" - > /dev/null <<'DOCKERFILE' || { echo "image build failed" >&2; exit 2; }
FROM debian:13
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends systemd systemd-sysv dbus curl openssl procps > /dev/null && \
    systemctl mask getty@tty1.service console-getty.service systemd-udevd.service systemd-firstboot.service
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
DOCKERFILE

docker run -d -t --name "$NAME" --privileged --network none --cgroupns=private -e container=docker \
    --tmpfs /run --tmpfs /run/lock --tmpfs /tmp -v "$ROOT:/src:ro" "$IMAGE" > /dev/null \
    || { echo "container failed to start" >&2; exit 2; }
for _ in $(seq 1 30); do
    state="$(docker exec "$NAME" systemctl is-system-running 2>/dev/null)"
    [[ "$state" == running || "$state" == degraded ]] && break
    sleep 1
done

docker exec -i "$NAME" bash <<'INSIDE'
set -uo pipefail
ADDR=linuxtest@example.com
PASSWORD=linux-test-long-password
BASE=http://localhost:8080
CONFIG=/etc/signet/config.yaml
LIVE=/etc/signet/templates
passed=0
failed=0
check() {
    if [[ "$3" == "$2" ]]; then echo "ok   - $1"; passed=$((passed + 1))
    else echo "FAIL - $1: want '$2', got '$3'"; failed=$((failed + 1)); fi
}
contains() {
    if [[ "$3" == *"$2"* ]]; then echo "ok   - $1"; passed=$((passed + 1))
    else echo "FAIL - $1: '$2' not in '$3'"; failed=$((failed + 1)); fi
}
code() { curl --silent --max-time 10 --output /dev/null --write-out '%{http_code}' "$@"; }
wait_up() {
    for _ in $(seq 1 40); do
        [[ "$(code "$BASE/health")" == 200 ]] && return 0
        sleep 0.25
    done
    return 1
}
journal() { journalctl -u signet --no-pager -o cat --cursor="$CURSOR"; }
mark() { CURSOR="$(journalctl -n 0 --show-cursor | sed -n 's/^-- cursor: //p')"; }

echo "=== Signet Linux install test ==="
echo "--- first install"
cd /src
OUTPUT="$(./deploy/install.sh 2>&1)"
check "install succeeds" 0 "$?"
contains "prints next steps" "Next steps:" "$OUTPUT"
contains "says PINs need a sendmail" "email PINs cannot be sent" "$OUTPUT"
check "binary installed" 755 "$(stat -c %a /opt/signet/signet)"
check "config private" "640 root signet" "$(stat -c '%a %U %G' "$CONFIG")"
check "template where the config reads it" 644 "$(stat -c %a "$LIVE/login.html")"
check "email template too" 644 "$(stat -c %a "$LIVE/email/pin.txt")"
check "static file where the config reads it" 644 "$(stat -c %a /etc/signet/static/js/webauthn.js)"
check "man page" 644 "$(stat -c %a /usr/share/man/man5/signet-config.yaml.5)"
contains "unit points at the man pages" "man:signet(1)" "$(systemctl show signet -p Documentation)"
check "a stopped service stays stopped" inactive "$(systemctl is-active signet)"

echo "--- no cookie_secret"
mark
systemctl start signet
sleep 2
check "the reason appears once in the journal" 1 "$(journal | grep -c 'cookie_secret must be set')"
systemctl stop signet

echo "--- its next steps, in order"
sed -i "s/^cookie_secret: \"\"/cookie_secret: \"$(openssl rand -hex 32)\"/" "$CONFIG"
systemctl enable signet > /dev/null 2>&1
mark
systemctl start signet
wait_up
check "the service starts" active "$(systemctl is-active signet)"
for path in /login /recover /static/js/webauthn.js; do
    check "GET $path" 200 "$(code "$BASE$path")"
done
contains "logs reach the journal" "Starting signet server" "$(journal)"
check "data private" "600 signet" "$(stat -c '%a %U' /var/lib/signet/sessions.db)"

echo "--- log_syslog is ignored under systemd"
sed -i 's/^log_syslog: .*/log_syslog: true/' "$CONFIG"
mark
systemctl restart signet
wait_up
contains "logs still reach the journal's stdout" "_TRANSPORT=stdout" \
    "$(journalctl -u signet --no-pager -o verbose --cursor="$CURSOR" MESSAGE="INFO: Starting signet server on :8080")"
sed -i 's/^log_syslog: .*/log_syslog: false/' "$CONFIG"
systemctl restart signet
wait_up

echo "--- signing in"
/opt/signet/signet user-add -config "$CONFIG" "$ADDR" "$PASSWORD" > /dev/null
check "user-add as root leaves the file to the service" signet "$(stat -c %U /var/lib/signet/users.csv)"
check "login" 302 "$(code -c /tmp/jar --data-urlencode "email=$ADDR" --data-urlencode "password=$PASSWORD" "$BASE/login")"
TOKEN="$(awk '/signetid/{print $7}' /tmp/jar)"
session() { code -H "Cookie: signetid=$TOKEN" "$BASE/session"; }
check "session" 200 "$(session)"

echo "--- install again, service running"
PID="$(systemctl show signet -p MainPID --value)"
OUTPUT="$(./deploy/install.sh 2>&1)"
check "install succeeds" 0 "$?"
wait_up
check "still running" active "$(systemctl is-active signet)"
[[ "$(systemctl show signet -p MainPID --value)" != "$PID" ]] && RESTARTED=yes || RESTARTED=no
check "restarted on the new binary" yes "$RESTARTED"
check "session survives" 200 "$(session)"
check "next steps not repeated" "" "$(grep 'Next steps' <<< "$OUTPUT")"
check "nothing reported as edited" "" "$(grep '^kept:' <<< "$OUTPUT")"
check "no directories nested in themselves" "" "$(find /etc/signet /opt/signet -mindepth 2 -type d \( -name templates -o -name static \))"
contains "secret kept" 'cookie_secret: "' "$(grep -E '^cookie_secret: "[0-9a-f]{64}"' "$CONFIG")"

echo "--- upgrade to a new version, one template edited"
NEXT=/root/next
mkdir "$NEXT"
cp -r /src/LICENSE /src/build /src/config /src/deploy /src/examples /src/man /src/web "$NEXT/"
printf 'edited-by-admin {{define "login"}}edited-by-admin{{end}}\n' > "$LIVE/login.html"
sed -i '1i <!-- next version -->' "$NEXT/web/templates/login.html" "$NEXT/web/templates/recover.html"
echo new > "$NEXT/web/templates/email/added.txt"
cd "$NEXT"
OUTPUT="$(./deploy/install.sh 2>&1)"
check "install succeeds" 0 "$?"
wait_up
contains "edited template kept" edited-by-admin "$(cat "$LIVE/login.html")"
contains "and reported" "kept: $LIVE/login.html has local edits" "$OUTPUT"
contains "with the new copy's place" /usr/share/doc/signet/examples/web/templates/login.html "$OUTPUT"
contains "new copy is there to read" "next version" "$(cat /usr/share/doc/signet/examples/web/templates/login.html)"
contains "unedited template updated" "next version" "$(cat "$LIVE/recover.html")"
check "new file added" new "$(cat "$LIVE/email/added.txt")"
contains "the edited page is what is served" edited-by-admin "$(curl -s "$BASE/login")"

echo "--- a config with other paths keeps them"
mkdir /srv/pages
sed -i 's#^templates_dir:.*#templates_dir: "/srv/pages"   \# local#' "$CONFIG"
systemctl reset-failed signet   # this test restarts faster than the unit's start limit allows
./deploy/install.sh > /dev/null 2>&1
check "install succeeds" 0 "$?"
wait_up
check "templates go where the config says" 644 "$(stat -c %a /srv/pages/login.html)"
check "and are served" 200 "$(code "$BASE/login")"

echo
echo "passed: $passed, failed: $failed"
[[ $failed -eq 0 ]]
INSIDE
