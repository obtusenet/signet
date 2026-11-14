#!/bin/bash
# Copyright (c) 2026 Obtuse Networking LLC
# SPDX-License-Identifier: MIT
#
# Tests the Debian package on a throwaway Debian 13 with real systemd: install
# (not started), the admin's first steps, an upgrade with an edited template, with
# the service running and stopped, then remove and purge.  The "next version" is
# the same package repacked as <version>-2 with changed templates.  Run by `make
# test-deb`, after `make deb`.  The container is privileged, for systemd, and has
# no network; the repository is read-only.

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION=$(sed -n 's/^VERSION=//p' "$ROOT/Makefile")
DEB="dist/signet_${VERSION}-1_amd64.deb"
IMAGE=signet-debtest
NAME=signet-debtest

[[ -f "$ROOT/$DEB" ]] || { echo "$DEB is missing: run make deb" >&2; exit 2; }

cleanup() { docker rm -f "$NAME" > /dev/null 2>&1; }
trap cleanup EXIT
cleanup

# What a Debian system has before signet: no mail system, as the package only
# recommends one.  The image's policy-rc.d, which refuses every service action, is
# removed: this container boots systemd, and maintainer scripts must act as on a
# real system.
docker build -q -t "$IMAGE" - > /dev/null <<'DOCKERFILE' || { echo "image build failed" >&2; exit 2; }
FROM debian:13
RUN rm -f /usr/sbin/policy-rc.d && apt-get update -qq && apt-get install -y -qq --no-install-recommends systemd systemd-sysv dbus curl openssl procps adduser > /dev/null && \
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

passed=0
failed=0
check() {
    if [[ "$3" == "$2" ]]; then echo "ok   - $1"; passed=$((passed + 1))
    else echo "FAIL - $1: want '$2', got '$3'"; failed=$((failed + 1)); fi
}

echo "=== Signet Debian package test ==="
echo "--- lintian, from the build"
check "lintian has nothing to say" "" "$(cat "$ROOT/dist/lintian.txt" 2>/dev/null || echo 'no dist/lintian.txt')"

docker exec -i -e DEB="/src/$DEB" -e VERSION="$VERSION" "$NAME" bash <<'INSIDE'
set -uo pipefail
ADDR=debtest@example.com
PASSWORD=deb-test-long-password
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
mainpid() { systemctl show signet -p MainPID --value; }

echo "--- install"
OUTPUT="$(dpkg -i "$DEB" 2>&1)"
check "dpkg -i succeeds" 0 "$?"
contains "says to set cookie_secret" "set cookie_secret in $CONFIG" "$OUTPUT"
check "not enabled" disabled "$(systemctl is-enabled signet 2>&1)"
check "not started" inactive "$(systemctl is-active signet 2>&1)"
check "a system user" yes "$( [[ $(id -u _signet) -lt 1000 ]] && echo yes || echo no)"
check "config mode and owner" "640 root:_signet" "$(stat -c '%a %U:%G' "$CONFIG")"
check "config directory" "750 root:_signet" "$(stat -c '%a %U:%G' /etc/signet)"
check "data directory" "750 _signet:_signet" "$(stat -c '%a %U:%G' /var/lib/signet)"
check "templates installed" 644 "$(stat -c %a "$LIVE/login.html")"
check "static files installed" 644 "$(stat -c %a /etc/signet/static/js/webauthn.js)"
check "the config is the example" "" "$(diff /usr/share/signet/config.yaml.example "$CONFIG")"
check "man page" /usr/share/man/man1/signet.1.gz "$(ls /usr/share/man/man1/signet.1.gz)"
check "examples" yes "$( [[ -x /usr/share/doc/signet/examples/hooks/claims-hook.sh ]] && echo yes || echo no)"
contains "commands read the installed config" '(default "/etc/signet/config.yaml")' "$(signet help)"
contains "the unit runs as _signet" "User=_signet" "$(systemctl cat signet)"
contains "the unit runs the packaged binary" "ExecStart=/usr/bin/signet serve" "$(systemctl cat signet)"
systemctl start signet 2> /dev/null
sleep 1
check "a start without a secret fails" yes "$( [[ $(systemctl show signet -p ExecMainStatus --value) != 0 ]] && echo yes || echo no)"
contains "and says why" cookie_secret "$(journalctl -u signet --no-pager -o cat)"
systemctl stop signet
systemctl reset-failed signet 2> /dev/null

echo "--- the admin's first steps"
sed -i "s/^cookie_secret: .*/cookie_secret: \"$(openssl rand -hex 32)\"/" "$CONFIG"
systemctl enable --now signet > /dev/null 2>&1
wait_up
check "running" active "$(systemctl is-active signet)"
check "GET /login" 200 "$(code "$BASE/login")"
signet user-add "$ADDR" "$PASSWORD" > /dev/null
check "user-add with no -config" 0 "$?"
check "and the file is the service's" _signet "$(stat -c %U /var/lib/signet/users.csv)"
check "login" 302 "$(code -c /tmp/jar --data-urlencode "email=$ADDR" --data-urlencode "password=$PASSWORD" "$BASE/login")"
TOKEN="$(awk '/signetid/{print $7}' /tmp/jar)"
session() { code -H "Cookie: signetid=$TOKEN" "$BASE/session"; }
check "session" 200 "$(session)"
check "data private" "600 _signet" "$(stat -c '%a %U' /var/lib/signet/sessions.db)"
PID="$(mainpid)"
systemctl reload signet
sleep 1
check "reload keeps the process" "$PID" "$(mainpid)"
contains "reload reads the config again" "configuration and templates reloaded" "$(journalctl -u signet --no-pager -o cat)"

echo "--- the next version, running, one template edited"
rm -rf /tmp/next && dpkg-deb -R "$DEB" /tmp/next
sed -i "s/^Version: .*/Version: $VERSION-2/" /tmp/next/DEBIAN/control
W=/tmp/next/usr/share/signet/web/templates
sed -i '1i <!-- next version -->' "$W/login.html" "$W/recover.html"
echo new > "$W/email/added.txt"
dpkg-deb -b --root-owner-group /tmp/next /tmp/next.deb > /dev/null
printf 'edited-by-admin {{define "login"}}edited-by-admin{{end}}\n' > "$LIVE/login.html"
OUTPUT="$(dpkg -i /tmp/next.deb 2>&1)"
check "upgrade succeeds" 0 "$?"
wait_up
check "still running" active "$(systemctl is-active signet)"
[[ "$(mainpid)" != "$PID" ]] && RESTARTED=yes || RESTARTED=no
check "restarted on the new version" yes "$RESTARTED"
check "session survives" 200 "$(session)"
contains "edited template kept" edited-by-admin "$(cat "$LIVE/login.html")"
contains "and reported" "kept: $LIVE/login.html has local edits" "$OUTPUT"
contains "unedited template updated" "next version" "$(cat "$LIVE/recover.html")"
check "new file added" new "$(cat "$LIVE/email/added.txt")"
check "secret kept" yes "$(grep -qE '^cookie_secret: "[0-9a-f]{64}"' "$CONFIG" && echo yes || echo no)"
check "cookie_secret hint not repeated" "" "$(grep 'set cookie_secret' <<< "$OUTPUT")"

echo "--- the same version again, stopped"
systemctl stop signet
dpkg -i /tmp/next.deb > /dev/null 2>&1
check "reinstall succeeds" 0 "$?"
sleep 1
check "a stopped service stays stopped" inactive "$(systemctl is-active signet)"
check "and stays enabled" enabled "$(systemctl is-enabled signet)"

echo "--- remove, then purge"
systemctl start signet && wait_up
dpkg -r signet > /dev/null 2>&1
check "remove succeeds" 0 "$?"
check "the service is stopped" inactive "$(systemctl is-active signet 2>&1)"
check "the binary is gone" no "$( [[ -e /usr/bin/signet ]] && echo yes || echo no)"
check "the config stays" yes "$( [[ -e $CONFIG ]] && echo yes || echo no)"
OUTPUT="$(dpkg -P signet 2>&1)"
check "purge succeeds" 0 "$?"
check "/etc/signet is gone" no "$( [[ -e /etc/signet ]] && echo yes || echo no)"
check "the accounts stay" yes "$( [[ -s /var/lib/signet/users.csv ]] && echo yes || echo no)"
contains "and purge says so" "/var/lib/signet is kept" "$OUTPUT"

echo "--- what deploy/install.sh left is reported"
mkdir -p /etc/systemd/system
printf '[Service]\nExecStart=/opt/signet/signet serve\n' > /etc/systemd/system/signet.service
useradd -r signet 2> /dev/null
chown signet /var/lib/signet/users.csv
OUTPUT="$(dpkg -i "$DEB" 2>&1)"
check "install succeeds" 0 "$?"
contains "the old unit is reported" "/etc/systemd/system/signet.service, from deploy/install.sh" "$OUTPUT"
contains "the old owner is reported" "not owned by _signet" "$OUTPUT"
check "and nothing is removed" yes "$( [[ -e /etc/systemd/system/signet.service ]] && echo yes || echo no)"

echo
echo "passed: $passed, failed: $failed"
[[ $failed -eq 0 ]]
INSIDE
inside=$?

echo "host checks: passed $passed, failed $failed"
[[ $inside -eq 0 && $failed -eq 0 ]]
