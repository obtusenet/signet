#!/bin/sh
# Copyright (c) 2026 Obtuse Networking LLC
# SPDX-License-Identifier: MIT
#
# Tests the FreeBSD package on the FreeBSD box: install (not started), the admin's
# first steps, reload, an upgrade with an edited template while running, the same
# version again while stopped, and removal.  pkg cannot restart a service, so the
# upgrade leaves the old one running and says so.  The "next version" is the same port
# packaged again as PORTREVISION=1 with changed templates in its stage.  Run by
# `make test-freebsd` after `make freebsd-package`.  It uses :8080, and removes
# what it installed, the user and the rc.conf entry when it ends.
#
#   box-test-package.sh <version>

set -u
version=$1
P=$HOME/signet-port
. "$P/env.sh"
PKG=$P/packages/All/signet-$version.pkg
NEXT=$P/packages/All/signet-${version}_1.pkg
ETC=/usr/local/etc/signet
CONFIG=$ETC/config.yaml
LIVE=$ETC/templates
BASE=http://localhost:8080
ADDR=fbsdtest@example.com
PASSWORD=fbsd-test-long-password
passed=0
failed=0

check() {
	if [ "$3" = "$2" ]; then echo "ok   - $1"; passed=$((passed + 1))
	else echo "FAIL - $1: want '$2', got '$3'"; failed=$((failed + 1)); fi
}
contains() {
	case "$3" in
	*"$2"*) echo "ok   - $1"; passed=$((passed + 1)) ;;
	*) echo "FAIL - $1: '$2' not in '$3'"; failed=$((failed + 1)) ;;
	esac
}
code() { curl --silent --max-time 10 --output /dev/null --write-out '%{http_code}' "$@"; }
wait_up() {
	i=0
	while [ $i -lt 40 ]; do
		[ "$(code "$BASE/health")" = 200 ] && return 0
		sleep 0.25
		i=$((i + 1))
	done
	return 1
}
child() { doas cat /var/run/signet/signet.pid 2> /dev/null; }
yes_no() { if "$@" > /dev/null 2>&1; then echo yes; else echo no; fi; }
log_since() { doas tail -n +"$1" /var/log/signet.log; }
lines() { n=$(doas wc -l < /var/log/signet.log 2> /dev/null | tr -d ' '); echo $((${n:-0} + 1)); }

cleanup() {
	doas service signet onestop > /dev/null 2>&1
	doas pkg delete -qy signet > /dev/null 2>&1
	doas sysrc -x signet_enable > /dev/null 2>&1
	doas rm -rf "$ETC" /var/db/signet /var/run/signet
	doas rm -f /usr/local/etc/syslog.d/signet.conf /usr/local/etc/newsyslog.conf.d/signet.conf /var/log/signet.log
	doas service syslogd reload > /dev/null 2>&1
	doas pw userdel signet > /dev/null 2>&1
	doas pw groupdel signet > /dev/null 2>&1
}
[ -f "$PKG" ] || { echo "$PKG is missing: run make freebsd-package" >&2; exit 2; }
cleanup

echo "=== Signet FreeBSD package test ==="
echo "--- the next version, for the upgrade"
(
	cd "$P/www/signet" || exit 1
	stage=$(make -V STAGEDIR)$(make -V DATADIR)/web/templates
	sed -i '' '1i\
<!-- next version -->
' "$stage/login.html" "$stage/recover.html"
	rm -f "$(make -V PACKAGE_COOKIE)"
	make PORTREVISION=1 package > /dev/null
	# Back to this version's files, for the next build.
	sed -i '' '1d' "$stage/login.html" "$stage/recover.html"
)
check "a next version is built" yes "$(yes_no test -f "$NEXT")"

echo "--- install"
OUTPUT=$(doas pkg add "$PKG" 2>&1)
check "pkg add succeeds" 0 "$?"
contains "says to set cookie_secret" "Set cookie_secret in" "$OUTPUT"
check "not running" no "$(yes_no doas service signet onestatus)"
check "the user, with the port's id" 784 "$(id -u signet)"
check "config mode and owner" "640 root:signet" "$(doas stat -f '%Lp %Su:%Sg' "$CONFIG")"
check "config directory" "750 root:signet" "$(doas stat -f '%Lp %Su:%Sg' "$ETC")"
check "data directory" "750 signet:signet" "$(doas stat -f '%Lp %Su:%Sg' /var/db/signet)"
check "templates installed" 644 "$(doas stat -f %Lp "$LIVE/login.html")"
check "static files installed" 644 "$(doas stat -f %Lp "$ETC/static/js/webauthn.js")"
check "the config is the sample" "" "$(doas diff "$ETC/config.yaml.sample" "$CONFIG")"
check "the log file" "640" "$(doas stat -f %Lp /var/log/signet.log)"
check "syslog sends signet there" yes "$(yes_no test -f /usr/local/etc/syslog.d/signet.conf)"
check "and newsyslog rotates it" yes "$(yes_no test -f /usr/local/etc/newsyslog.conf.d/signet.conf)"
check "man page" yes "$(yes_no test -f /usr/local/share/man/man1/signet.1.gz)"
check "examples" yes "$(yes_no test -x /usr/local/share/examples/signet/hooks/claims-hook.sh)"
contains "commands read the installed config" "(default \"$CONFIG\")" "$(signet help)"
mark=$(lines)
doas service signet onestart > /dev/null 2>&1
sleep 2
contains "a start without a secret says why" cookie_secret "$(log_since "$mark")"
doas service signet onestop > /dev/null 2>&1

echo "--- the admin's first steps"
secret=$(openssl rand -hex 32)
doas sed -i '' "s/^cookie_secret: .*/cookie_secret: \"$secret\"/" "$CONFIG"
doas sysrc signet_enable=YES > /dev/null
doas service signet start > /dev/null
wait_up
check "running" yes "$(yes_no doas service signet status)"
check "GET /login" 200 "$(code "$BASE/login")"
doas signet user-add "$ADDR" "$PASSWORD" > /dev/null
check "user-add with no -config" 0 "$?"
check "and the file is the service's" signet "$(doas stat -f %Su /var/db/signet/users.csv)"
jar=$(mktemp)
check "login" 302 "$(code -c "$jar" --data-urlencode "email=$ADDR" --data-urlencode "password=$PASSWORD" "$BASE/login")"
TOKEN=$(awk '/signetid/{print $7}' "$jar")
rm -f "$jar"
session() { code -H "Cookie: signetid=$TOKEN" "$BASE/session"; }
check "session" 200 "$(session)"
check "data private" "600 signet" "$(doas stat -f '%Lp %Su' /var/db/signet/sessions.db)"
contains "the log reaches syslog" "Starting signet server" "$(log_since "$mark")"
PID=$(child)
mark=$(lines)
doas service signet reload
sleep 1
check "reload keeps the process" "$PID" "$(child)"
contains "reload reads the config again" "configuration and templates reloaded" "$(log_since "$mark")"

echo "--- the next version, running, one template edited"
printf 'edited-by-admin {{define "login"}}edited-by-admin{{end}}\n' | doas tee "$LIVE/login.html" > /dev/null
OUTPUT=$(doas pkg add "$NEXT" 2>&1)
check "upgrade succeeds" 0 "$?"
check "still running, the old version" "$PID" "$(child)"
contains "says to restart it" "service signet restart" "$OUTPUT"
doas service signet restart > /dev/null
wait_up
[ -n "$(child)" ] && [ "$(child)" != "$PID" ] && RESTARTED=yes || RESTARTED=no
check "restarted on the new version" yes "$RESTARTED"
check "session survives" 200 "$(session)"
contains "edited template kept" edited-by-admin "$(doas cat "$LIVE/login.html")"
contains "and reported" "kept: $LIVE/login.html has local edits" "$OUTPUT"
contains "unedited template updated" "next version" "$(doas cat "$LIVE/recover.html")"
check "secret kept" yes "$(yes_no doas grep -q "$secret" "$CONFIG")"

echo "--- the same version again, stopped"
doas service signet stop > /dev/null
doas pkg add -f "$NEXT" > /dev/null 2>&1
check "reinstall succeeds" 0 "$?"
sleep 1
check "a stopped service stays stopped" no "$(yes_no doas service signet status)"

echo "--- removal"
doas service signet start > /dev/null && wait_up
OUTPUT=$(doas pkg delete -y signet 2>&1)
check "pkg delete succeeds" 0 "$?"
sleep 1
check "the service is stopped" 000 "$(code "$BASE/health")"
check "the binary is gone" no "$(yes_no test -e /usr/local/bin/signet)"
check "the edited config stays" yes "$(yes_no doas test -e "$CONFIG")"
check "the accounts stay" yes "$(yes_no doas test -s /var/db/signet/users.csv)"

cleanup
echo
echo "passed: $passed, failed: $failed"
[ "$failed" -eq 0 ]
