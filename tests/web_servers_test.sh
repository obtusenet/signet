#!/bin/sh
# Copyright (c) 2026 Obtuse Networking LLC
# SPDX-License-Identifier: MIT
#
# Runs examples/web-servers/ as shipped on an OpenBSD box with caddy, nginx and
# httpd installed, and walks each one through a browser's requests.  Only ports,
# the upstream address and the certificate-free address are changed.  Each sample
# gets a throwaway signet with its own database and CSV file on spare ports, and
# a fake app that reports what it was sent.  Running services are left alone, and
# mail goes to the log (mail.program: ""), so no message can leave.
#
# Usage: tests/web_servers_test.sh <examples/web-servers>     (needs doas)

SAMPLES="$(cd "${1:?usage: web_servers_test.sh <examples/web-servers>}" && pwd)"

FRONT=18180      # the sample's web server
FRONT2=18181     # httpd's second server in signet-port.conf
SIGNET_PORT=18090
APP_PORT=18081
SOCKDIR=/var/www/run/signet     # what the FastCGI samples name
CADDY_SOCK=/var/www/signet/signet.sock
SITE_ROOT=/var/www/htdocs/site
EGRESS="$(ifconfig egress | awk '$1 == "inet" { print $2; exit }')"
USER_ADDR=sample@example.com
PASSWORD=sample-long-enough-password
WEB=/usr/local/share/examples/signet/web

for path in "$SOCKDIR" "$SITE_ROOT" "$CADDY_SOCK"; do
    if [ -e "$path" ]; then
        echo "$path already exists; refusing to run over it" >&2
        exit 2
    fi
done
for port in $FRONT $FRONT2 $SIGNET_PORT $APP_PORT; do
    if netstat -an -f inet | awk '$NF == "LISTEN" { print $4 }' | grep -q "\.$port\$"; then
        echo "port $port is in use" >&2
        exit 2
    fi
done

W="$(mktemp -d /tmp/signet-web-servers.XXXXXX)"
chmod 755 "$W"
DATA="$W/signet"
PIDS="$W/pids"
mkdir -p "$PIDS" && chmod 777 "$PIDS"
passed=0
failed=0

stop_all() {
    for pidfile in "$PIDS"/*; do
        [ -f "$pidfile" ] && doas kill "$(cat "$pidfile")" 2>/dev/null
        rm -f "$pidfile" 2>/dev/null || doas rm -f "$pidfile"
    done
    sleep 1
    doas rm -f "$CADDY_SOCK"
}
cleanup() {
    stop_all
    doas rm -rf "$W" "$SOCKDIR" "$SITE_ROOT"
}
trap cleanup EXIT
trap 'exit 1' INT TERM

ok()   { echo "ok   - $1"; passed=$((passed + 1)); }
bad()  { echo "FAIL - $1"; failed=$((failed + 1)); }
check() { # name expected actual
    if [ "$2" = "$3" ]; then ok "$1"; else bad "$1: expected '$2', got '$3'"; fi
}
contains() { # name needle haystack
    case "$3" in
        *"$2"*) ok "$1" ;;
        *) bad "$1: '$2' not in: $(echo "$3" | tr '\n' ' ' | cut -c1-200)" ;;
    esac
}
lacks() { # name needle haystack
    case "$3" in
        *"$2"*) bad "$1: '$2' is in: $(echo "$3" | tr '\n' ' ' | cut -c1-200)" ;;
        *) ok "$1" ;;
    esac
}

# Connects to this host's own address, so signet can tell the client from the
# proxy on loopback, while the Host header stays what a browser would send.
web() { # args: reaches $BASE
    curl --silent --show-error --max-time 10 --connect-to "$HOST:$FRONT:$EGRESS:$FRONT" \
        --connect-to "$HOST:$FRONT2:$EGRESS:$FRONT2" "$@"
}
code() { web --output /dev/null --write-out '%{http_code}' "$@"; }
location() { web --output /dev/null --write-out '%{redirect_url}' "$@"; }

wait_for() { # host:port
    i=0
    while [ $i -lt 50 ]; do
        curl --silent --output /dev/null --max-time 1 "http://$1/" && return 0
        i=$((i + 1))
        sleep 0.2
    done
    return 1
}
wait_for_socket() {
    i=0
    while [ $i -lt 50 ]; do
        doas test -S "$1" && return 0
        i=$((i + 1))
        sleep 0.2
    done
    return 1
}

# --- the throwaway signet ----------------------------------------------------
start_signet() { # listen-yaml, extra yaml lines
    doas rm -rf "$DATA"
    doas install -d -o _signet -g _signet -m 755 "$DATA"
    SECRET="$(openssl rand -hex 32)"
    cat > "$W/config.yaml" <<YAML
$1
database_path: "$DATA/sessions.db"
csv_path: "$DATA/users.csv"
templates_dir: "$WEB/templates"
static_dir: "$WEB/static"
cookie_secret: "$SECRET"
cookie_secure: false
log_syslog: false
self_registration: "enabled"
password_recovery: "enabled"
avatars: "enabled"
avatar_size: 32
public_url: "http://$HOST:$FRONT"
webauthn_rpid: "$HOST"
webauthn_origins:
  - "http://$HOST:$FRONT"
auth_methods:
  password: "enabled"
  webauthn: "enabled"
  email_pin: "enabled"
  totp: "enabled"
mail:
  program: ""
$2
YAML
    chmod 644 "$W/config.yaml"
    as_signet="doas su -s /bin/sh _signet -c"
# A 32-pixel greyscale PNG for the avatar checks.
AVATAR_PNG="iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAAAAABWESUoAAABN0lEQVR42mWSEZOGAABEF8MwDMMwDMMwDMMwDD8MwzAMwzAMwzAMw5u9mb2Z2+8X7L59CwRhFCdplhdlVTdt13+GcZqXdduP87qfFwGiMImztMirsqm79tOPwzyty76dx329D8IIQZrFSVnlRdvVzTD2n2Wd5uPc9ue9bkRhgCxN4qos8q5t6nH49OsyT+exb+9zX2A+ezCfPZjPHsxnDzCfPZjPHsxnD+azB5jPHsxnD+azB/PZ4zefPZjPHsxnD+azB8SvPcSvPSB+7SF+7QHxaw/xaw+IX3uIX3tA/NpD/NoD4tce4tceEL/2EL/2+OPXHuLXHvj2//8fcP/+D7h//wfcv/8D7t//Affv/4D793/A/fs/4P79H3D//g+4f/8H3L//A+7f/wH37/+A+/d/fPn3f/wAQBHwEBpnj3gAAAAASUVORK5CYII="
    $as_signet "/usr/local/bin/signet user-add -config $W/config.yaml $USER_ADDR '$PASSWORD'" > /dev/null 2>&1 \
        || { echo "user-add failed" >&2; exit 2; }
    $as_signet "echo \$\$ > $PIDS/signet; exec /usr/local/bin/signet serve -config $W/config.yaml > $DATA/log 2>&1" &
    sleep 1
}
signet_log() { doas cat "$DATA/log"; }

start_app() {
    cat > "$W/app.py" <<'PY'
import http.server, sys
class H(http.server.BaseHTTPRequestHandler):
    def reply(self):
        n = int(self.headers.get('Content-Length') or 0)
        body = self.rfile.read(n).decode() if n else ''
        lines = ['APP method=%s path=%s body=%s' % (self.command, self.path, body)]
        for name in ('Host', 'X-Forwarded-User', 'X-Forwarded-Email', 'Remote-User', 'Remote-Email', 'Remote-Avatar', 'X-Forwarded-For'):
            lines.append('%s: %s' % (name, self.headers.get(name, '')))
        out = '\n'.join(lines).encode()
        self.send_response(200)
        self.send_header('Content-Length', str(len(out)))
        self.end_headers()
        self.wfile.write(out)
    do_GET = do_POST = reply
    def log_message(self, *a): pass
http.server.HTTPServer(('127.0.0.1', int(sys.argv[1])), H).serve_forever()
PY
    python3 -I "$W/app.py" "$APP_PORT" &
    echo $! > "$PIDS/app"
    wait_for "127.0.0.1:$APP_PORT" || { echo "the fake app did not start" >&2; exit 2; }
}

make_sockdir() { # the command the FastCGI samples give
    doas rm -rf "$SOCKDIR"
    doas install -d -o _signet -g www -m 2770 "$SOCKDIR"
}

# Mechanical changes only: ports, and the upstream the sample names.
adapt() {
    sed -e "s/127\.0\.0\.1:9090/127.0.0.1:$SIGNET_PORT/g" \
        -e "s/127\.0\.0\.1:8080/127.0.0.1:$APP_PORT/g" \
        -e "s/listen 80;/listen $FRONT;/" \
        -e "s/egress port 8080/egress port $FRONT2/" \
        -e "s/egress port 80\$/egress port $FRONT/" \
        -e "s#^http://app.example.com#http://app.example.com:$FRONT#" "$1"
}

start_caddy() { # sample
    doas install -d -o _caddy -g _caddy "$W/caddy"
    { printf '{\n\tadmin off\n}\n'; adapt "$1"; } > "$W/Caddyfile"
    chmod 644 "$W/Caddyfile"
    as_caddy="doas su -s /bin/sh _caddy -c"
    env_caddy="HOME=$W/caddy XDG_DATA_HOME=$W/caddy XDG_CONFIG_HOME=$W/caddy"
    out="$($as_caddy "env $env_caddy /usr/local/bin/caddy validate --adapter caddyfile --config $W/Caddyfile" 2>&1)"
    case "$out" in *"Valid configuration"*) ok "caddy validates it" ;; *) bad "caddy validate: $out"; return 1 ;; esac
    $as_caddy "echo \$\$ > $PIDS/caddy; exec env $env_caddy /usr/local/bin/caddy run --adapter caddyfile --config $W/Caddyfile > $W/caddy/log 2>&1" &
    wait_for "$EGRESS:$FRONT" || { bad "caddy did not start"; return 1; }
}

start_nginx() { # adapted-config-file, flags
    cp /etc/nginx/fastcgi_params "$W/fastcgi_params"
    cat > "$W/nginx.conf" <<CONF
worker_processes 1;
pid $W/nginx.pid;
error_log $W/nginx-error.log;
events { worker_connections 64; }
http {
    include /etc/nginx/mime.types;
    access_log off;
    include $1;
}
CONF
    out="$(doas nginx $2 -t -c "$W/nginx.conf" 2>&1)"
    case "$out" in *"test is successful"*) ok "nginx -t accepts it" ;; *) bad "nginx -t: $out"; return 1 ;; esac
    doas nginx $2 -c "$W/nginx.conf" || { bad "nginx did not start"; return 1; }
    doas cp "$W/nginx.pid" "$PIDS/nginx"
    wait_for "$EGRESS:$FRONT" || { bad "nginx did not answer"; return 1; }
}

start_httpd() { # sample
    make_sockdir_logs
    { printf 'logdir "%s/logs"\nprefork 1\n' "$SOCKDIR"; adapt "$1"; } > "$W/httpd.conf"
    out="$(doas httpd -n -f "$W/httpd.conf" 2>&1)"
    case "$out" in *"configuration OK"*) ok "httpd -n accepts it" ;; *) bad "httpd -n: $out"; return 1 ;; esac
    doas sh -c "echo \$\$ > $PIDS/httpd; exec httpd -d -f $W/httpd.conf > $W/httpd.log 2>&1" &
    wait_for "$EGRESS:$FRONT" || { bad "httpd did not start: $(cat "$W/httpd.log")"; return 1; }
}
make_sockdir_logs() { doas install -d -o www -g www -m 775 "$SOCKDIR/logs"; }

# --- what every sample must do ------------------------------------------------
signet_routes() {
    JAR="$W/jar"; rm -f "$JAR"
    check "/login" 200 "$(code "$BASE/login")"
    contains "the login page is signet's" 'name="password"' "$(web "$BASE/login")"
    check "/recover" 200 "$(code "$BASE/recover")"
    contains "POST /recover reaches signet" "If that address has an account" \
        "$(web --data-urlencode "email=$USER_ADDR" "$BASE/recover")"
    for _ in 1 2 3 4 5 6 7 8 9 10; do
        token="$(signet_log | sed -n 's/.*recover#token=\([A-Za-z0-9_-]*\).*/\1/p' | tail -1)"
        [ -n "$token" ] && break
        sleep 0.2
    done
    contains "a recovery link is checked through the web server" '"success":true' \
        "$(web -H 'Accept: application/json' --data-urlencode "token=$token" "$BASE/recover")"
    check "/register" 200 "$(code "$BASE/register")"
    contains "the register page is signet's" 'Send Link' "$(web "$BASE/register")"
    contains "POST /register reaches signet" "Check your mail" \
        "$(web --data-urlencode 'email=newcomer@example.com' "$BASE/register")"
    for _ in 1 2 3 4 5 6 7 8 9 10; do
        token="$(signet_log | sed -n 's/.*register#token=\([A-Za-z0-9_-]*\).*/\1/p' | tail -1)"
        [ -n "$token" ] && break
        sleep 0.2
    done
    contains "a registration link is checked through the web server" '"success":true' \
        "$(web -H 'Accept: application/json' --data-urlencode "token=$token" "$BASE/register")"
    check "/static/js/webauthn.js" 200 "$(code "$BASE/static/js/webauthn.js")"
    check "/webauthn/keys" 200 "$(code "$BASE/webauthn/keys")"
    check "invite header reaches signet (bad invite is 401, none is 400)" 401 \
        "$(code -H 'X-Signet-Invite: not-a-real-invite' "$BASE/webauthn/invite")"
    contains "POST /email-pin/send" '"success":true' \
        "$(web -H 'Content-Type: application/json' -d "{\"email\":\"$USER_ADDR\"}" "$BASE/email-pin/send")"
    contains "an address with no key gets sign-in options" '"allowCredentials"' \
        "$(web -X POST "$BASE/webauthn/authenticate/start?email=nobody%40example.com")"
    check "no session yet" 401 "$(code "$BASE/session")"
    check "wrong password" 401 "$(code -H 'Accept: application/json' \
        --data-urlencode "email=$USER_ADDR" --data-urlencode 'password=wrong-password-here' "$BASE/login")"
    check "another site's login is refused" 403 "$(code -H 'Origin: https://evil.example' \
        --data-urlencode "email=$USER_ADDR" --data-urlencode "password=$PASSWORD" "$BASE/login")"
    check "form login redirects, with this site's Origin" 302 "$(code -c "$JAR" -H "Origin: $BASE" \
        --data-urlencode "email=$USER_ADDR" --data-urlencode "password=$PASSWORD" "$BASE/login")"
    contains "login set the cookie" signetid "$(cat "$JAR" 2>/dev/null)"
    check "/session with the cookie" 200 "$(code -b "$JAR" "$BASE/session")"
    contains "/session reports the identity header" "remote-user: $USER_ADDR" \
        "$(web -D - -o /dev/null -b "$JAR" "$BASE/session" | tr -d '\r' | tr 'A-Z' 'a-z')"
    check "/account with the cookie" 200 "$(code -b "$JAR" "$BASE/account")"
    contains "the account page is signet's" "$USER_ADDR" "$(web -b "$JAR" "$BASE/account")"
    contains "POST /account reaches signet" 'not right' \
        "$(web -b "$JAR" -H 'Content-Type: application/json' -H "Origin: $BASE" \
            -d '{"action":"password","current":"not-the-password","new":"long-enough-password"}' "$BASE/account")"
    contains "POST /account starts an authenticator" '"qr":"data:image/png' \
        "$(web -b "$JAR" -H 'Content-Type: application/json' -H "Origin: $BASE" \
            -d '{"action":"totp-begin","label":"sample"}' "$BASE/account")"
    avatar="$(web -b "$JAR" -H 'Content-Type: application/json' -H "Origin: $BASE" \
        -d "{\"action\":\"avatar-set\",\"image\":\"$AVATAR_PNG\"}" "$BASE/account" |
        sed -n 's/.*"avatar":"\([^"]*\)".*/\1/p')"
    contains "POST /account sets a picture" "/avatar/" "$avatar"
    check "the picture is served through the web server" "200 image/png" \
        "$(web -o /dev/null -w '%{http_code} %{content_type}' "$BASE$avatar")"
    contains "a key delete reaches signet" 'no such security key' \
        "$(web -X DELETE -b "$JAR" "$BASE/webauthn/credentials/nosuch")"
    code -H 'X-Forwarded-For: 6.6.6.6' "$BASE/login?who=client" > /dev/null
    sleep 0.3
    who="$(signet_log | grep 'who=client' | tail -1)"
    contains "signet logs the real client" "remote=$EGRESS" "$who"
    lacks "a forged X-Forwarded-For is not believed" "6.6.6.6" "$who"
}

logout_checks() {
    check "logout" 303 "$(code -b "$JAR" -c "$JAR" "$BASE/logout")"
    check "session gone after logout" 401 "$(code -b "$JAR" "$BASE/session")"
}

protected_app() { # for samples that gate an application
    anon="$(location "$BASE/page?x=1&y=2")"
    check "anonymous GET is sent to sign in" 302 "$(code "$BASE/page?x=1&y=2")"
    contains "to the login page" "/login?referrer=" "$anon"
    lacks "the anonymous visitor never reaches the app" "APP " "$(web "$BASE/page")"
    # The web server cannot encode it; signet must still read it whole, both
    # for the login page's hidden field and for a POST straight to that URL.
    contains "the login page keeps the whole return address" "y=2" "$(web "$anon")"
    whole="$(location --data-urlencode "email=$USER_ADDR" --data-urlencode "password=$PASSWORD" "$anon")"
    contains "login at that address goes back whole" "/page?x=1&y=2" "$whole"
    back="$(location --data-urlencode "email=$USER_ADDR" --data-urlencode "password=$PASSWORD" \
        --data-urlencode "referrer=$BASE/page?x=1&y=2" "$BASE/login")"
    contains "login goes back to the page, whole" "/page?x=1&y=2" "$back"

    check "anonymous POST is sent to sign in, not refused" 302 "$(code -d 'a=1' "$BASE/page")"
    check "a forged cookie is sent to sign in" 302 \
        "$(code -H 'Cookie: signetid=forged:forged' "$BASE/page")"

    app="$(web -b "$JAR" "$BASE/page?x=1")"
    contains "signed in, GET reaches the app" "APP method=GET path=/page?x=1" "$app"
    contains "the app is told the user" "X-Forwarded-User: $USER_ADDR" "$app"
    contains "the app is told the address" "X-Forwarded-Email: $USER_ADDR" "$app"
    contains "the app sees the browser's Host" "Host: $HOST" "$app"
    contains "the app sees the client" "X-Forwarded-For: $EGRESS" "$app"
    post="$(web -b "$JAR" -d 'a=1' "$BASE/page")"
    contains "signed in, POST reaches the app with its body" "APP method=POST path=/page body=a=1" "$post"
    forged="$(web -b "$JAR" -H 'X-Forwarded-User: admin@example.com' -H 'X-Forwarded-Email: admin@example.com' \
        -H 'Remote-User: admin@example.com' -H 'Remote-Email: admin@example.com' \
        -H 'Remote-Avatar: https://forged.example.com/a.png' "$BASE/page")"
    lacks "the visitor cannot forge an identity header" "admin@example.com" "$forged"
    lacks "nor the avatar, which signet sends only for some accounts" "forged.example.com" "$forged"
}

fail_closed() { # after the session checks: with signet down the app is shut
    doas kill "$(cat "$PIDS/signet")" 2>/dev/null
    rm -f "$PIDS/signet" 2>/dev/null || doas rm -f "$PIDS/signet"
    sleep 1
    lacks "with signet down the app stays shut" "APP " "$(web -b "$JAR" "$BASE/page")"
}

section() { echo; echo "=== $1"; stop_all; doas rm -rf "$SOCKDIR"; }
http_config="listen: \":$SIGNET_PORT\""
fcgi_config="listen: \"$SOCKDIR/fcgi.sock\"
protocol: \"fastcgi\""

start_app_again() { [ -f "$PIDS/app" ] || start_app; }

# ------------------------------------------------------------------------------
HOST=app.example.com
BASE="http://$HOST:$FRONT"

section "caddy/Caddyfile-port"
start_app_again
start_signet "$http_config" 'trusted_proxies: ["127.0.0.1", "::1"]'
if start_caddy "$SAMPLES/caddy/Caddyfile-port"; then
    signet_routes; protected_app; logout_checks
    code -b "$JAR" -c "$JAR" --data-urlencode "email=$USER_ADDR" --data-urlencode "password=$PASSWORD" "$BASE/login" > /dev/null
    fail_closed
fi

section "caddy/Caddyfile-socket"
start_app_again
start_signet "listen: \"$CADDY_SOCK\"
socket_mode: \"0666\"" 'trusted_proxies: ["unix"]'
if wait_for_socket "$CADDY_SOCK" && start_caddy "$SAMPLES/caddy/Caddyfile-socket"; then
    signet_routes; protected_app; logout_checks
else
    bad "signet or caddy did not start on the socket"
fi

section "nginx/signet-port.conf"
start_app_again
start_signet "$http_config" 'trusted_proxies: ["127.0.0.1", "::1"]'
adapt "$SAMPLES/nginx/signet-port.conf" > "$W/sample.conf"
if start_nginx "$W/sample.conf" ""; then
    signet_routes; protected_app
    check "/_session is internal" 404 "$(code "$BASE/_session")"
    logout_checks
    code -b "$JAR" -c "$JAR" --data-urlencode "email=$USER_ADDR" --data-urlencode "password=$PASSWORD" "$BASE/login" > /dev/null
    fail_closed
fi

section "nginx/signet-fcgi.conf, nginx not chrooted (nginx -u), with the real path as its comment says"
start_app_again
make_sockdir
start_signet "$fcgi_config" ""
wait_for_socket "$SOCKDIR/fcgi.sock" || bad "signet made no socket"
adapt "$SAMPLES/nginx/signet-fcgi.conf" | sed 's#unix:/run/signet/fcgi.sock#unix:/var/www/run/signet/fcgi.sock#' > "$W/sample.conf"
if start_nginx "$W/sample.conf" "-u"; then
    signet_routes; protected_app
    check "/_session is internal" 404 "$(code "$BASE/_session")"
    logout_checks
fi

section "nginx/signet-fcgi.conf, OpenBSD's default chroot"
start_app_again
make_sockdir
start_signet "$fcgi_config" ""
wait_for_socket "$SOCKDIR/fcgi.sock" || bad "signet made no socket"
adapt "$SAMPLES/nginx/signet-fcgi.conf" > "$W/sample.conf"
if start_nginx "$W/sample.conf" ""; then
    signet_routes; protected_app
    check "/_session is internal" 404 "$(code "$BASE/_session")"
    logout_checks
    code -b "$JAR" -c "$JAR" --data-urlencode "email=$USER_ADDR" --data-urlencode "password=$PASSWORD" "$BASE/login" > /dev/null
    fail_closed
fi

HOST=site.example.com
BASE="http://$HOST:$FRONT"

section "openbsd-httpd/signet-fcgi.conf"
make_sockdir
start_signet "$fcgi_config" ""
wait_for_socket "$SOCKDIR/fcgi.sock" || bad "signet made no socket"
doas install -d -o root -g daemon -m 755 "$SITE_ROOT" "$SITE_ROOT/sub"
doas sh -c "echo SITE-INDEX > $SITE_ROOT/index.html; echo SITE-PAGE > $SITE_ROOT/page.html; echo SITE-SUB > $SITE_ROOT/sub/page.html"
if start_httpd "$SAMPLES/openbsd-httpd/signet-fcgi.conf"; then
    signet_routes; logout_checks
    contains "the site's index" SITE-INDEX "$(web "$BASE/")"
    contains "a page of the site" SITE-PAGE "$(web "$BASE/page.html")"
    contains "a page further down" SITE-SUB "$(web "$BASE/sub/page.html")"
fi

section "openbsd-httpd/signet-port.conf"
make_sockdir
start_signet "$http_config" "allowed_redirect_hosts:
  - \"$HOST:$FRONT2\""
if start_httpd "$SAMPLES/openbsd-httpd/signet-port.conf"; then
    contains "the static site" SITE-INDEX "$(web "$BASE/")"
    contains "a page of the site" SITE-PAGE "$(web "$BASE/page.html")"
    code_scribe="$(code "http://$HOST:$FRONT2/scribe/")"
    case "$code_scribe" in
        2*|3*|401|403) ok "the editor answers on the second port ($code_scribe)" ;;
        *) bad "the editor on the second port: $code_scribe" ;;
    esac
    SIGNET_BASE="http://$EGRESS:$SIGNET_PORT"
    check "signet on its own port" 200 "$(curl -s -o /dev/null -w '%{http_code}' "$SIGNET_BASE/login")"
    back="$(curl -s -o /dev/null -w '%{redirect_url}' --data-urlencode "email=$USER_ADDR" --data-urlencode "password=$PASSWORD" \
        --data-urlencode "referrer=http://$HOST:$FRONT2/scribe/" "$SIGNET_BASE/login")"
    check "login returns across ports" "http://$HOST:$FRONT2/scribe/" "$back"
fi

stop_all
echo
echo "passed: $passed, failed: $failed"
[ "$failed" -eq 0 ]
