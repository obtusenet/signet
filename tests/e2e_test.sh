#!/bin/bash
# Copyright (c) 2026 Obtuse Networking LLC
# SPDX-License-Identifier: MIT
#
# End-to-end test: starts a throwaway signet on a unix socket, with its own
# database and CSV file, and walks the real flows over HTTP.  It uses no network,
# and mail goes to the log (mail.program: ""), so no message can leave.
#
# Usage: tests/e2e_test.sh [path/to/signet]

set -uo pipefail

SIGNET="$(cd "$(dirname "${1:-build/signet}")" && pwd)/$(basename "${1:-build/signet}")"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ ! -x "$SIGNET" ]]; then
    echo "$SIGNET not found; run make first" >&2
    exit 2
fi

DIR="$(mktemp -d)"
SERVER=""
BASE_SERVER=""
cleanup() {
    [[ -n "$SERVER" ]] && kill "$SERVER" 2>/dev/null && wait "$SERVER" 2>/dev/null
    [[ -n "$BASE_SERVER" ]] && kill "$BASE_SERVER" 2>/dev/null && wait "$BASE_SERVER" 2>/dev/null
    rm -rf "$DIR"
}
trap cleanup EXIT

CONFIG="$DIR/config.yaml"
SOCKET="$DIR/signet.sock"
LOG="$DIR/signet.log"
JAR="$DIR/cookies"
USER_ADDR="e2e@example.com"
PASSWORD="e2e-long-enough-password"

cat > "$CONFIG" <<YAML
listen: "$SOCKET"
database_path: "$DIR/sessions.db"
csv_path: "$DIR/users.csv"
templates_dir: "$ROOT/web/templates"
static_dir: "$ROOT/web/static"
cookie_secret: "$(printf 'e2e-only-%.0s' 1 2 3 4 5)"
cookie_secure: false
log_syslog: false
self_registration: "enabled"
self_registration_approval: "auto_approve"
password_recovery: "enabled"
public_url: "https://signet.example"
auth_methods:
  password: "enabled"
  email_pin: "enabled"
  totp: "enabled"
mail:
  program: ""
YAML

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
http() { curl --silent --show-error --max-time 10 --unix-socket "$SOCKET" "$@"; }
code() { http --output /dev/null --write-out '%{http_code}' "$@"; }

"$SIGNET" user-add -config "$CONFIG" "$USER_ADDR" "$PASSWORD" > /dev/null || { echo "user-add failed" >&2; exit 1; }
API_KEY="$("$SIGNET" client-add -config "$CONFIG" e2e | sed -n 's/^API key.*: //p')"
[[ -n "$API_KEY" ]] || { echo "client-add printed no key" >&2; exit 1; }

"$SIGNET" serve -config "$CONFIG" > "$LOG" 2>&1 &
SERVER=$!
for _ in $(seq 1 100); do
    [[ "$(code http://localhost/health 2>/dev/null)" == "200" ]] && break
    sleep 0.1
done

echo "=== Signet E2E test ==="
echo "--- the package ships every web file"
while IFS= read -r file; do
    contains "PLIST lists $file" "share/examples/signet/$file" \
        "$(cat "$ROOT/contrib/packaging/openbsd/www/signet/pkg/PLIST")"
done < <(cd "$ROOT" && find web -type f | sort)

echo "--- a refused start says why"
BAD_CONFIG="$DIR/bad.yaml"
grep -v '^cookie_secret:' "$CONFIG" > "$BAD_CONFIG"
BAD_OUTPUT="$("$SIGNET" serve -config "$BAD_CONFIG" 2>&1 >/dev/null)"
check "no cookie_secret stops serve" 1 "$?"
contains "stderr names the problem" "cookie_secret must be set" "$BAD_OUTPUT"
mkdir "$DIR/bad-templates"
printf '{{' > "$DIR/bad-templates/login.html"
sed "s#^templates_dir:.*#templates_dir: \"$DIR/bad-templates\"#" "$CONFIG" > "$BAD_CONFIG"
BAD_OUTPUT="$("$SIGNET" serve -config "$BAD_CONFIG" 2>&1 >/dev/null)"
check "a broken template stops serve" 1 "$?"
contains "stderr names the template" "login.html" "$BAD_OUTPUT"

echo "--- running server"
contains "health" '"status":"ok"' "$(http http://localhost/health)"
check "login page" 200 "$(code http://localhost/login)"
check "no WebAuthn routes when it is off" 404 "$(code http://localhost/webauthn/keys)"
"$SIGNET" webauthn-invite -config "$CONFIG" "$USER_ADDR" > /dev/null 2>&1
check "no invite link when WebAuthn is off" 1 "$?"

echo "--- password login"
check "no session yet" 401 "$(code http://localhost/session)"
check "wrong password" 401 "$(code -H 'Accept: application/json' \
    --data-urlencode "email=$USER_ADDR" --data-urlencode 'password=wrong-password-here' http://localhost/login)"
check "form login redirects" 302 "$(code -c "$JAR" \
    --data-urlencode "email=$USER_ADDR" --data-urlencode "password=$PASSWORD" http://localhost/login)"
SESSION="$(http -b "$JAR" http://localhost/session)"
contains "session names the user" "\"email\":\"$USER_ADDR\"" "$SESSION"
contains "session names the method" '"method":"password"' "$SESSION"
contains "JSON login answers JSON" '"success":true' "$(http -H 'Accept: application/json' \
    --data-urlencode "email=$USER_ADDR" --data-urlencode "password=$PASSWORD" http://localhost/login)"

echo "--- validation API"
check "no API key" 401 "$(code -X POST -b "$JAR" http://localhost/api/v1/validate)"
check "bad API key" 401 "$(code -X POST -H 'X-API-Key: sk_wrong' -b "$JAR" http://localhost/api/v1/validate)"
check "no cookie" 401 "$(code -X POST -H "X-API-Key: $API_KEY" http://localhost/api/v1/validate)"
contains "valid session" '"valid":true' "$(http -X POST -H "X-API-Key: $API_KEY" -b "$JAR" http://localhost/api/v1/validate)"

echo "--- logout"
check "logout redirects" 303 "$(code -b "$JAR" -c "$JAR" http://localhost/logout)"
check "session is gone" 401 "$(code -b "$JAR" http://localhost/session)"

echo "--- email PIN, read from the log"
send() { http -H 'Content-Type: application/json' -d "{\"email\":\"$USER_ADDR\"}" http://localhost/email-pin/send; }
contains "PIN sent" '"success":true' "$(send)"
PIN=""
for _ in $(seq 1 50); do
    PIN="$(grep -E '^ +[0-9]{6} *$' "$LOG" | tail -1 | tr -d ' ')"
    [[ -n "$PIN" ]] && break
    sleep 0.1
done
check "PIN in the log" 6 "${#PIN}"
verify() { # pin [args]
    local pin="$1"; shift
    code "$@" -H 'Content-Type: application/json' \
        -d "{\"email\":\"$USER_ADDR\",\"pin\":\"$pin\"}" http://localhost/email-pin/verify
}
WRONG=000000; [[ "$PIN" == "$WRONG" ]] && WRONG=000001
check "wrong PIN" 400 "$(verify "$WRONG")"
check "right PIN" 200 "$(verify "$PIN" -c "$JAR")"
contains "session from a PIN" '"method":"email_pin"' "$(http -b "$JAR" http://localhost/session)"
check "PIN used twice" 400 "$(verify "$PIN")"

echo "--- password recovery, the link read from the log"
RECOVER_ADDR="recover@example.com"
"$SIGNET" user-add -config "$CONFIG" "$RECOVER_ADDR" "first-long-password" > /dev/null
check "the page offers it" 200 "$(code http://localhost/recover)"
contains "same reply with an account" "If that address has an account" \
    "$(http --data-urlencode "email=$RECOVER_ADDR" http://localhost/recover)"
contains "same reply without one" "If that address has an account" \
    "$(http --data-urlencode 'email=nobody@example.com' http://localhost/recover)"
LINK=""
for _ in $(seq 1 50); do
    LINK="$(grep -o 'https://signet.example/recover#token=[A-Za-z0-9_-]*' "$LOG" | head -1)"
    [[ -n "$LINK" ]] && break
    sleep 0.1
done
contains "the link uses public_url" "https://signet.example/recover#token=" "$LINK"
check "one link went out" 1 "$(grep -c 'recovery link sent' "$LOG")"
contains "nothing went to the unknown address" "no recovery link for nobody@example.com" "$(cat "$LOG")"
TOKEN="${LINK##*token=}"
lacks_token="$(grep -c "uri=.*$TOKEN" "$LOG" || true)"
check "checking it" 200 "$(code -H 'Accept: application/json' --data-urlencode "token=$TOKEN" http://localhost/recover)"
check "a short password keeps it" 400 "$(code --data-urlencode "token=$TOKEN" --data-urlencode 'password=short' http://localhost/recover)"
RECOVER_JAR="$DIR/recover.jar"
check "signed in before the reset" 302 "$(code -c "$RECOVER_JAR" --data-urlencode "email=$RECOVER_ADDR" \
    --data-urlencode 'password=first-long-password' http://localhost/login)"
check "using it" 200 "$(code --data-urlencode "token=$TOKEN" --data-urlencode 'password=second-long-password' http://localhost/recover)"
check "that session has ended" 401 "$(code -b "$RECOVER_JAR" http://localhost/session)"
check "the old password is gone" 401 "$(code --data-urlencode "email=$RECOVER_ADDR" \
    --data-urlencode 'password=first-long-password' http://localhost/login)"
check "the new password works" 302 "$(code --data-urlencode "email=$RECOVER_ADDR" \
    --data-urlencode 'password=second-long-password' http://localhost/login)"
check "it works once" 400 "$(code --data-urlencode "token=$TOKEN" --data-urlencode 'password=third-long-password' http://localhost/recover)"
for _ in $(seq 1 50); do
    grep -q 'Your Signet password was changed' "$LOG" && break
    sleep 0.1
done
contains "a notice went out" "Your Signet password was changed" "$(cat "$LOG")"
check "the token reached no request line" 0 "$lacks_token"
check "the token reached no request line afterwards" 0 "$(grep -c "uri=.*$TOKEN" "$LOG" || true)"

GONE_ADDR="gone@example.com"
"$SIGNET" user-add -config "$CONFIG" "$GONE_ADDR" "first-long-password" > /dev/null
http --output /dev/null --data-urlencode "email=$GONE_ADDR" http://localhost/recover
GONE_TOKEN=""
for _ in $(seq 1 50); do
    GONE_TOKEN="$(grep -A20 "To: $GONE_ADDR" "$LOG" | grep -o 'recover#token=[A-Za-z0-9_-]*' | head -1)"
    [[ -n "$GONE_TOKEN" ]] && break
    sleep 0.1
done
GONE_TOKEN="${GONE_TOKEN##*token=}"
check "that account's link is live" 200 "$(code -H 'Accept: application/json' --data-urlencode "token=$GONE_TOKEN" http://localhost/recover)"
"$SIGNET" user-delete -config "$CONFIG" -confirm "$GONE_ADDR" > /dev/null 2>&1
"$SIGNET" user-add -config "$CONFIG" "$GONE_ADDR" "new-owner-password" > /dev/null
check "a deleted account's link does not open its successor" 400 "$(code -H 'Accept: application/json' --data-urlencode "token=$GONE_TOKEN" http://localhost/recover)"

echo "--- registration, the link read from the log"
NEW_ADDR="newcomer@example.com"
NEW_PASSWORD="newcomer-long-password"
contains "the page asks for an address" "Send Link" "$(http http://localhost/register)"
contains "the login page links to it" 'href="/register"' "$(http http://localhost/login)"
contains "an address with no account" "Check your mail" \
    "$(http --data-urlencode "email=$NEW_ADDR" --data-urlencode 'password=an-attackers-password' http://localhost/register)"
contains "an address with an account" "Check your mail" \
    "$(http --data-urlencode "email=$USER_ADDR" http://localhost/register)"
NEW_LINK=""
for _ in $(seq 1 50); do
    NEW_LINK="$(grep -o 'https://signet.example/register#token=[A-Za-z0-9_-]*' "$LOG" | head -1)"
    [[ -n "$NEW_LINK" ]] && grep -q 'told its owner' "$LOG" && break
    sleep 0.1
done
contains "the owner of an account is told" "registration asked for $USER_ADDR, which has an account" "$(cat "$LOG")"
check "no account before the link" 0 "$("$SIGNET" user-list -config "$CONFIG" | grep -c "$NEW_ADDR")"
check "the first request's password opens nothing" 401 "$(code --data-urlencode "email=$NEW_ADDR" \
    --data-urlencode 'password=an-attackers-password' http://localhost/login)"
NEW_TOKEN="${NEW_LINK##*token=}"
check "checking the link" 200 "$(code -H 'Accept: application/json' --data-urlencode "token=$NEW_TOKEN" http://localhost/register)"
check "using the link" 200 "$(code --data-urlencode "token=$NEW_TOKEN" --data-urlencode "password=$NEW_PASSWORD" http://localhost/register)"
check "the account exists" 1 "$("$SIGNET" user-list -config "$CONFIG" | grep -c "$NEW_ADDR")"
check "it signs in with the password from the link" 302 "$(code --data-urlencode "email=$NEW_ADDR" \
    --data-urlencode "password=$NEW_PASSWORD" http://localhost/login)"
check "the link works once" 400 "$(code --data-urlencode "token=$NEW_TOKEN" --data-urlencode 'password=another-long-password' http://localhost/register)"
check "the token reached no request line" 0 "$(grep -c "uri=.*$NEW_TOKEN" "$LOG" || true)"
check "the old stub is gone" 404 "$(code http://localhost/verify-email)"

echo "--- the account page"
ACCOUNT_ADDR="account@example.com"
ACCOUNT_JAR="$DIR/account.jar"
OTHER_JAR="$DIR/other.jar"
"$SIGNET" user-add -config "$CONFIG" "$ACCOUNT_ADDR" "first-long-password" > /dev/null
check "no session goes to sign in" 302 "$(code http://localhost/account)"
for jar in "$ACCOUNT_JAR" "$OTHER_JAR"; do
    code -c "$jar" --data-urlencode "email=$ACCOUNT_ADDR" --data-urlencode 'password=first-long-password' http://localhost/login > /dev/null
done
contains "the page shows the account" "$ACCOUNT_ADDR" "$(http -b "$ACCOUNT_JAR" http://localhost/account)"
change_password() { # current new [args]
    local current="$1" new="$2"; shift 2
    code "$@" -H 'Content-Type: application/json' \
        -d "{\"action\":\"password\",\"current\":\"$current\",\"new\":\"$new\"}" http://localhost/account
}
check "the wrong current password" 400 "$(change_password wrong-password second-long-password -b "$ACCOUNT_JAR")"
check "another site" 403 "$(change_password first-long-password second-long-password -b "$ACCOUNT_JAR" -H 'Origin: https://evil.example')"
check "no session" 401 "$(change_password first-long-password second-long-password)"
check "changing it" 200 "$(change_password first-long-password second-long-password -b "$ACCOUNT_JAR")"
check "this session stays" 200 "$(code -b "$ACCOUNT_JAR" http://localhost/session)"
check "the other session has ended" 401 "$(code -b "$OTHER_JAR" http://localhost/session)"
check "the new password works" 302 "$(code --data-urlencode "email=$ACCOUNT_ADDR" --data-urlencode 'password=second-long-password' http://localhost/login)"
for _ in $(seq 1 50); do
    grep -q 'A change to your Signet account' "$LOG" && break
    sleep 0.1
done
contains "a notice went out" "password of this account was changed" "$(cat "$LOG")"

echo "--- TOTP"
TOTP_ADDR="totp@example.com"
TOTP_PASSWORD="totp-long-password"
TOTP_JAR="$DIR/totp.jar"
"$SIGNET" user-add -config "$CONFIG" "$TOTP_ADDR" "$TOTP_PASSWORD" > /dev/null
check "signing in, no key yet" 302 "$(code -c "$TOTP_JAR" --data-urlencode "email=$TOTP_ADDR" --data-urlencode "password=$TOTP_PASSWORD" http://localhost/login)"
account() { http -b "$TOTP_JAR" -H 'Content-Type: application/json' -d "$1" http://localhost/account; }
json() { node -e 'const d=JSON.parse(require("fs").readFileSync(0));const v=d[process.argv[1]];console.log(Array.isArray(v)?v.join("\n"):v)' "$1"; }
# The code of a base32 secret, some steps from now (RFC 6238).
totp() {
    node -e '
const crypto = require("crypto");
const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
let bits = "";
for (const c of process.argv[1].replace(/=+$/, "")) bits += alphabet.indexOf(c).toString(2).padStart(5, "0");
const key = Buffer.from(bits.match(/.{8}/g).map((b) => parseInt(b, 2)));
const counter = Buffer.alloc(8);
counter.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30000) + Number(process.argv[2])));
const mac = crypto.createHmac("sha1", key).update(counter).digest();
const at = mac[19] & 15;
console.log(String((mac.readUInt32BE(at) & 0x7fffffff) % 1000000).padStart(6, "0"));
' "$1" "$2"
}
BEGUN="$(account '{"action":"totp-begin","label":"e2e phone"}')"
contains "enrolling shows a QR code" '"qr":"data:image/png;base64,' "$BEGUN"
SECRET="$(printf '%s' "$BEGUN" | json secret)"
check "a wrong code saves nothing" 400 "$(code -b "$TOTP_JAR" -H 'Content-Type: application/json' -d '{"action":"totp-finish","code":"000000"}' http://localhost/account)"
FINISHED="$(account "{\"action\":\"totp-finish\",\"code\":\"$(totp "$SECRET" 0)\"}")"
RECOVERY="$(printf '%s' "$FINISHED" | json recovery_codes | head -1)"
check "the first key gets recovery codes" 19 "${#RECOVERY}"
contains "the page lists the key" "e2e phone" "$(http -b "$TOTP_JAR" http://localhost/account)"
step_one() { http --data-urlencode "email=$TOTP_ADDR" --data-urlencode "password=$TOTP_PASSWORD" http://localhost/login; }
pending_of() { sed -n 's/.*name="pending" value="\([^"]*\)".*/\1/p'; }
PENDING="$(step_one | pending_of)"
check "the password now asks for a code" 43 "${#PENDING}"
check "the password alone sets no cookie" 0 "$(http -D - -o /dev/null --data-urlencode "email=$TOTP_ADDR" --data-urlencode "password=$TOTP_PASSWORD" http://localhost/login | grep -c -i '^set-cookie')"
check "a wrong code" 401 "$(code --data-urlencode "pending=$PENDING" --data-urlencode 'code=000000' http://localhost/login)"
NEXT="$(totp "$SECRET" 1)"
CODE_JAR="$DIR/code.jar"
check "the right code" 302 "$(code -c "$CODE_JAR" --data-urlencode "pending=$PENDING" --data-urlencode "code=$NEXT" http://localhost/login)"
contains "the session says how" '"method":"password+totp"' "$(http -b "$CODE_JAR" http://localhost/session)"
check "that code again" 401 "$(code --data-urlencode "pending=$(step_one | pending_of)" --data-urlencode "code=$NEXT" http://localhost/login)"
check "a recovery code" 302 "$(code --data-urlencode "pending=$(step_one | pending_of)" --data-urlencode "code=$RECOVERY" http://localhost/login)"
check "that recovery code again" 401 "$(code --data-urlencode "pending=$(step_one | pending_of)" --data-urlencode "code=$RECOVERY" http://localhost/login)"
"$SIGNET" user-delete-totp -config "$CONFIG" "$TOTP_ADDR" > /dev/null 2>&1
check "the admin command needs confirming" 1 "$?"
contains "the admin command removes the key" "Removed 1 TOTP keys" "$("$SIGNET" user-delete-totp -config "$CONFIG" -confirm "$TOTP_ADDR")"
check "then no code is asked for" 302 "$(code --data-urlencode "email=$TOTP_ADDR" --data-urlencode "password=$TOTP_PASSWORD" http://localhost/login)"

echo "--- limits"
contains "frames refused" "x-frame-options: deny" \
    "$(http -D - -o /dev/null http://localhost/login | tr -d '\r' | tr 'A-Z' 'a-z')"
contains "no type sniffing" "x-content-type-options: nosniff" \
    "$(http -D - -o /dev/null http://localhost/login | tr -d '\r' | tr 'A-Z' 'a-z')"
contains "the login page says it is HTML" "text/html" \
    "$(http -D - -o /dev/null http://localhost/login | tr -d '\r' | tr 'A-Z' 'a-z')"
contains "the browser script says it is script" "javascript" \
    "$(http -D - -o /dev/null http://localhost/static/js/webauthn.js | tr -d '\r' | tr 'A-Z' 'a-z')"
head -c 300000 /dev/zero | tr '\0' a > "$DIR/big"
check "oversized body refused" 413 "$(code -H 'Content-Type: application/json' --data-binary @"$DIR/big" http://localhost/email-pin/send)"
SIZE_BEFORE="$(wc -c < "$LOG")"
{ printf '{"email":"'; cat "$DIR/big"; printf '"}'; } > "$DIR/big.json"
code -H 'Content-Type: application/json' -H 'Transfer-Encoding: chunked' --data-binary @"$DIR/big.json" http://localhost/email-pin/send > /dev/null
{ printf 'email='; cat "$DIR/big"; printf '&password=x'; } > "$DIR/big.form"
code -H 'Transfer-Encoding: chunked' --data-binary @"$DIR/big.form" http://localhost/login > /dev/null
SIZE_AFTER="$(wc -c < "$LOG")"
check "an undeclared big body leaves no big log line" 1 "$(( SIZE_AFTER - SIZE_BEFORE < 2000 ? 1 : 0 ))"
check "a forged log line is refused" 400 "$(code -H 'Content-Type: application/json' \
    -d '{"email":"x@example.com\nINFO: User forged@example.com logged in via password"}' http://localhost/email-pin/send)"
check "the same through the login form" 401 "$(code -H 'Accept: application/json' \
    --data-urlencode $'email=y@example.com\nINFO: forged line' --data-urlencode 'password=whatever-it-is' http://localhost/login)"
check "another site's login is refused" 403 "$(code -H 'Origin: https://evil.example' \
    --data-urlencode "email=$USER_ADDR" --data-urlencode "password=$PASSWORD" http://localhost/login)"
check "this site's login is not" 302 "$(code -H 'Origin: http://localhost' \
    --data-urlencode "email=$USER_ADDR" --data-urlencode "password=$PASSWORD" http://localhost/login)"
contains "the refusal is logged" 'cross-origin request refused: POST "/login" origin="https://evil.example"' "$(cat "$LOG")"

STDIN_ADDR="stdin@example.com"
STDIN_PASSWORD="from standard input, with spaces"
stdin_err="$(printf '%s\n' "$STDIN_PASSWORD" | "$SIGNET" user-add -password-stdin -config "$CONFIG" "$STDIN_ADDR" 2>&1 > /dev/null)"
check "user-add from stdin gives no warning" "" "$stdin_err"
contains "a password as an argument is warned about" "use -password-stdin" \
    "$("$SIGNET" user-add -config "$CONFIG" argwarn@example.com 'an-argument-password' 2>&1 > /dev/null)"
check "user-add reads the password from stdin" 302 "$(code --data-urlencode "email=$STDIN_ADDR" \
    --data-urlencode "password=$STDIN_PASSWORD" http://localhost/login)"
printf '\n' | "$SIGNET" user-add -password-stdin -config "$CONFIG" empty@example.com > /dev/null 2>&1
check "an empty line makes no account" 1 "$?"
printf 'x\n' | "$SIGNET" user-add -password-stdin -config "$CONFIG" both@example.com argument > /dev/null 2>&1
check "stdin and an argument together are refused" 1 "$?"
check "neither of those made an account" 0 "$("$SIGNET" user-list -config "$CONFIG" | grep -c -E 'empty@|both@')"

check "neither reached the log as a line" 0 "$(grep -c -E '^INFO: (User forged|forged line)' "$LOG")"
contains "the refusal is logged" "PIN request refused from" "$(cat "$LOG")"
contains "login refuses it before the limiter" "Login failed from" "$(cat "$LOG")"

echo "--- refusals"

echo "--- an instance under base_path"
BASE_DIR="$DIR/base"
mkdir "$BASE_DIR"
BASE_CONFIG="$BASE_DIR/config.yaml"
BASE_SOCKET="$BASE_DIR/signet.sock"
BASE_LOG="$BASE_DIR/signet.log"
BASE_JAR="$BASE_DIR/cookies"
sed -e "s#^listen:.*#listen: \"$BASE_SOCKET\"#" \
    -e "s#^database_path:.*#database_path: \"$BASE_DIR/sessions.db\"#" \
    -e "s#^csv_path:.*#csv_path: \"$BASE_DIR/users.csv\"#" "$CONFIG" > "$BASE_CONFIG"
cat >> "$BASE_CONFIG" <<YAML
base_path: "/auth"
cookie_name: "authid"
webauthn_rpid: "localhost"
webauthn_origins: ["http://localhost"]
YAML
sed -i 's#^  totp: "enabled"#  totp: "enabled"\n  webauthn: "enabled"#' "$BASE_CONFIG"
sed 's#^base_path:.*#base_path: "/auth/"#' "$BASE_CONFIG" > "$BAD_CONFIG"
BAD_OUTPUT="$("$SIGNET" serve -config "$BAD_CONFIG" 2>&1 >/dev/null)"
check "a trailing slash stops serve" 1 "$?"
contains "stderr names base_path" "base_path" "$BAD_OUTPUT"

BASE_ADDR="base@example.com"
"$SIGNET" user-add -config "$BASE_CONFIG" "$BASE_ADDR" "$PASSWORD" > /dev/null
"$SIGNET" serve -config "$BASE_CONFIG" > "$BASE_LOG" 2>&1 &
BASE_SERVER=$!
bhttp() { curl --silent --show-error --max-time 10 --unix-socket "$BASE_SOCKET" "$@"; }
bcode() { bhttp --output /dev/null --write-out '%{http_code}' "$@"; }
for _ in $(seq 1 100); do
    [[ "$(bcode http://localhost/auth/health 2>/dev/null)" == "200" ]] && break
    sleep 0.1
done
check "health under the base" 200 "$(bcode http://localhost/auth/health)"
check "nothing at the root" 404 "$(bcode http://localhost/health)"
check "nor at the root's login" 404 "$(bcode http://localhost/login)"
check "the script under the base" 200 "$(bcode http://localhost/auth/static/js/webauthn.js)"
BASE_PAGE="$(bhttp http://localhost/auth/login)"
contains "the login page tells the script the base" 'data-base-path="/auth"' "$BASE_PAGE"
contains "the login page posts under the base" 'action="/auth/login"' "$BASE_PAGE"
check "signing in under the base" 302 "$(bcode -c "$BASE_JAR" --data-urlencode "email=$BASE_ADDR" \
    --data-urlencode "password=$PASSWORD" http://localhost/auth/login)"
check "its cookie has its own name" 1 "$(grep -c 'authid' "$BASE_JAR")"
contains "the session under the base" "\"email\":\"$BASE_ADDR\"" "$(bhttp -b "$BASE_JAR" http://localhost/auth/session)"
check "the other instance does not know it" 401 "$(code -b "$BASE_JAR" http://localhost/session)"
check "signing out goes to the base's login" "/auth/login" "$(bhttp -b "$BASE_JAR" -o /dev/null -w '%{redirect_url}' http://localhost/auth/logout | sed 's#^http://localhost##')"
contains "the log has the whole path" 'uri="/auth/login"' "$(cat "$BASE_LOG")"
contains "an invite links under the base" "http://localhost/auth/webauthn/keys#invite=" \
    "$("$SIGNET" webauthn-invite -config "$BASE_CONFIG" "$BASE_ADDR")"

echo "--- SIGHUP reloads the configuration"
# waitfor <status> <url>: poll until the base instance answers with that status.
waitfor() {
    for _ in $(seq 1 50); do
        [[ "$(bcode "$2" 2>/dev/null)" == "$1" ]] && return 0
        sleep 0.1
    done
    return 1
}
sed -i 's#^base_path:.*#base_path: "/moved"#' "$BASE_CONFIG"
printf 'account_lockout_threshold: 3\n' >> "$BASE_CONFIG"
kill -HUP "$BASE_SERVER"
waitfor 200 http://localhost/moved/health
check "the new base answers" 200 "$(bcode http://localhost/moved/health)"
check "the old base does not" 404 "$(bcode http://localhost/auth/health)"
contains "the reload is logged" "configuration and templates reloaded from $BASE_CONFIG" "$(cat "$BASE_LOG")"

for attempt in 1 2 3; do
    bcode --data-urlencode "email=$BASE_ADDR" --data-urlencode "password=wrong-$attempt" \
        http://localhost/moved/login > /dev/null
done
check "the reloaded lockout refuses the right password" 401 "$(bcode --data-urlencode "email=$BASE_ADDR" \
    --data-urlencode "password=$PASSWORD" http://localhost/moved/login)"
contains "the lock is logged" "account locked: $BASE_ADDR after 3 failed sign-ins in a row" "$(cat "$BASE_LOG")"
contains "user-unlock clears it" "Cleared 3 failed sign-ins of $BASE_ADDR" \
    "$("$SIGNET" user-unlock -config "$BASE_CONFIG" "$BASE_ADDR")"
check "then the right password signs in" 302 "$(bcode --data-urlencode "email=$BASE_ADDR" \
    --data-urlencode "password=$PASSWORD" http://localhost/moved/login)"
contains "a second unlock finds nothing" "has no failed sign-ins to clear" \
    "$("$SIGNET" user-unlock -config "$BASE_CONFIG" "$BASE_ADDR")"

echo "--- avatars, switched on by reload"
printf 'avatars: "enabled"\navatar_size: 32\n' >> "$BASE_CONFIG"
kill -HUP "$BASE_SERVER"
for _ in $(seq 1 50); do grep -q 'avatars enabled, 32 pixels' "$BASE_LOG" && break; sleep 0.1; done
check "a fresh sign-in for the page" 302 "$(bcode -c "$BASE_JAR" --data-urlencode "email=$BASE_ADDR" \
    --data-urlencode "password=$PASSWORD" http://localhost/moved/login)"
# A 32-pixel PNG, made here: node has zlib and the CRC.
AVATAR_PNG="$(node -e '
const zlib = require("zlib");
const chunk = (type, data) => {
  const body = Buffer.concat([Buffer.from(type), data]);
  const out = Buffer.alloc(8 + data.length + 4);
  out.writeUInt32BE(data.length, 0); body.copy(out, 4); out.writeUInt32BE(zlib.crc32(body), 8 + data.length);
  return out;
};
const ihdr = Buffer.alloc(13); ihdr.writeUInt32BE(32, 0); ihdr.writeUInt32BE(32, 4); ihdr[8] = 8; ihdr[9] = 2;
const rows = Buffer.alloc(32 * (1 + 32 * 3)); for (let i = 0; i < rows.length; i++) if (i % 97) rows[i] = i & 255;
process.stdout.write(Buffer.concat([Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]), chunk("IHDR", ihdr),
  chunk("IDAT", zlib.deflateSync(rows)), chunk("IEND", Buffer.alloc(0))]).toString("base64"));')"
AVATAR_REPLY="$(bhttp -b "$BASE_JAR" -H 'Content-Type: application/json' \
    -d "{\"action\":\"avatar-set\",\"image\":\"$AVATAR_PNG\"}" http://localhost/moved/account)"
contains "the picture is saved" '"success":true' "$AVATAR_REPLY"
AVATAR_PATH="$(printf '%s' "$AVATAR_REPLY" | json avatar)"
contains "under the base" "/moved/avatar/" "$AVATAR_PATH"
check "it is served" "200 image/png" "$(bhttp -o /dev/null -w '%{http_code} %{content_type}' "http://localhost$AVATAR_PATH")"
contains "the session names it" "\"avatar\":\"https://signet.example$AVATAR_PATH\"" "$(bhttp -b "$BASE_JAR" http://localhost/moved/session)"
contains "the account page shows it" "src=\"$AVATAR_PATH\"" "$(bhttp -b "$BASE_JAR" http://localhost/moved/account)"
check "an SVG is refused" 400 "$(bcode -b "$BASE_JAR" -H 'Content-Type: application/json' \
    -d "{\"action\":\"avatar-set\",\"image\":\"$(printf '<svg/>' | base64)\"}" http://localhost/moved/account)"
contains "avatar-remove takes it down" "Removed the picture of $BASE_ADDR" \
    "$("$SIGNET" avatar-remove -config "$BASE_CONFIG" "$BASE_ADDR")"
check "and it is no longer served" 404 "$(bcode "http://localhost$AVATAR_PATH")"
contains "a second remove finds nothing" "$BASE_ADDR has no picture" \
    "$("$SIGNET" avatar-remove -config "$BASE_CONFIG" "$BASE_ADDR")"
AVATAR_PATH="$(bhttp -b "$BASE_JAR" -H 'Content-Type: application/json' \
    -d "{\"action\":\"avatar-set\",\"image\":\"$AVATAR_PNG\"}" http://localhost/moved/account | json avatar)"
check "a new picture is served" 200 "$(bcode "http://localhost$AVATAR_PATH")"
"$SIGNET" user-delete -config "$BASE_CONFIG" -confirm "$BASE_ADDR" > /dev/null
check "user-delete removes it" 404 "$(bcode "http://localhost$AVATAR_PATH")"

sed -i "s#^listen:.*#listen: \"$BASE_DIR/elsewhere.sock\"#" "$BASE_CONFIG"
kill -HUP "$BASE_SERVER"
for _ in $(seq 1 50); do grep -q 'listen changed' "$BASE_LOG" && break; sleep 0.1; done
contains "a restart-only change is named" "listen changed in $BASE_CONFIG: it takes effect at the next restart" "$(cat "$BASE_LOG")"
check "and the old socket still serves" 200 "$(bcode http://localhost/moved/health)"
check "with no new one" 1 "$([[ -e "$BASE_DIR/elsewhere.sock" ]]; echo $?)"

grep -v '^cookie_secret:' "$BASE_CONFIG" > "$BASE_CONFIG.new" && mv "$BASE_CONFIG.new" "$BASE_CONFIG"
sed -i 's#^base_path:.*#base_path: "/broken"#' "$BASE_CONFIG"
kill -HUP "$BASE_SERVER"
for _ in $(seq 1 50); do grep -q 'reload refused' "$BASE_LOG" && break; sleep 0.1; done
contains "a bad file is refused" "reload refused, keeping the running configuration" "$(cat "$BASE_LOG")"
check "and the running configuration stays" 200 "$(bcode http://localhost/moved/health)"
check "the server is still running" 0 "$(kill -0 "$BASE_SERVER" 2>/dev/null; echo $?)"

echo "--- deleting the account ends its session"
"$SIGNET" user-delete -config "$CONFIG" -confirm "$USER_ADDR" > /dev/null
check "session after delete" 401 "$(code -b "$JAR" http://localhost/session)"

echo
echo "passed: $passed, failed: $failed"
[[ $failed -eq 0 ]]
