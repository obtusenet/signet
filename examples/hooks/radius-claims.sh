#!/bin/sh
# Copyright (c) 2026 Obtuse Networking LLC
# SPDX-License-Identifier: MIT
#
# Claims for RADIUS accounts, in POSIX sh and awk: runs under sh, bash and ksh,
# with any POSIX awk, and needs nothing else.  It does what radius-claims.py
# does: the groups the RADIUS server sent, a role taken from them, and the
# application.  See signet-hooks(5).
#
# Signet sends one line, for an account a RADIUS server accepted:
#
#   {"type":"claim_request","email":"jdoe","source":"radius",
#    "radius":{"nas_identifier":"wiki","groups":["wiki-admins"],"attributes":[...]}}
#
# The groups and the application go back as the JSON text Signet sent, so no
# string is decoded or re-encoded here.  Edit ROLES for your groups.
#
# Usage, in config.yaml:
#
#   claims_hook:
#     enabled: true
#     program: "/usr/local/libexec/signet/radius-claims.sh"

# "group role" per line.  The first group the account has decides its role.
ROLES='wiki-admins admin
wiki-editors editor
staff user'

# A role for accounts in none of those groups, and for users.csv accounts.
DEFAULT_ROLE=user

# member <key>: the raw JSON value of a top-level member of the object on stdin.
member() {
	awk -v target="$1" '
	{
		s = $0; n = length(s); depth = 0; instr = 0; esc = 0
		wantkey = 0; inkey = 0; key = ""; cap = 0; out = ""
		for (i = 1; i <= n; i++) {
			c = substr(s, i, 1)
			if (instr) {
				if (cap) out = out c
				if (esc) { esc = 0; if (inkey) key = key c }
				else if (c == "\\") esc = 1
				else if (c == "\"") inkey = instr = 0
				else if (inkey) key = key c
				continue
			}
			if (c == "\"") {
				instr = 1
				if (depth == 1 && wantkey && !cap) { inkey = 1; wantkey = 0; key = "" }
				if (cap) out = out c
				continue
			}
			if (c == "{" || c == "[") {
				depth++
				if (depth == 1) wantkey = (c == "{")
				if (cap) out = out c
				continue
			}
			if (c == "}" || c == "]") {
				if (cap && depth == 1) break
				depth--
				if (cap) out = out c
				continue
			}
			if (c == ",") {
				if (cap && depth == 1) break
				if (depth == 1) wantkey = 1
				if (cap) out = out c
				continue
			}
			if (c == ":" && depth == 1 && !cap) {
				if (key == target) { cap = 1; out = "" }
				continue
			}
			if (cap) out = out c
		}
		if (cap) {
			gsub(/^[ \t]+|[ \t]+$/, "", out)
			print out
		}
		exit
	}'
}

# elements: the raw elements of the JSON array on stdin, one per line.
elements() {
	awk '
	{
		s = $0; n = length(s); depth = 0; instr = 0; esc = 0; el = ""
		for (i = 1; i <= n; i++) {
			c = substr(s, i, 1)
			if (instr) {
				el = el c
				if (esc) esc = 0
				else if (c == "\\") esc = 1
				else if (c == "\"") instr = 0
				continue
			}
			if (c == "\"") { instr = 1; el = el c; continue }
			if (c == "[" || c == "{") { depth++; if (depth > 1) el = el c; continue }
			if (c == "]" || c == "}") {
				if (depth == 1) break
				depth--; el = el c; continue
			}
			if (c == "," && depth == 1) {
				gsub(/^[ \t]+|[ \t]+$/, "", el); print el; el = ""; continue
			}
			if (depth >= 1) el = el c
		}
		gsub(/^[ \t]+|[ \t]+$/, "", el)
		if (el != "") print el
		exit
	}'
}

error() {
	printf '{"type":"claim_error","error":"%s"}\n' "$1"
	exit 0
}

IFS= read -r request || [ -n "$request" ] || error "no request"
case $request in
'{'*'}') ;;
*) error "the request is not a JSON object" ;;
esac
[ "$(printf '%s\n' "$request" | member type)" = '"claim_request"' ] || error "not a claim_request"

if [ "$(printf '%s\n' "$request" | member source)" != '"radius"' ]; then
	printf '{"type":"claim_response","claims":{"role":"%s","groups":[]}}\n' "$DEFAULT_ROLE"
	exit 0
fi

radius=$(printf '%s\n' "$request" | member radius)
groups=$(printf '%s\n' "$radius" | member groups)
application=$(printf '%s\n' "$radius" | member nas_identifier)
case $groups in '['*']') ;; *) groups='[]' ;; esac
case $application in '"'*'"') ;; *) application='""' ;; esac

# Each group as Signet encoded it, one per line, to compare whole.
have=$(printf '%s\n' "$groups" | elements)
role=$DEFAULT_ROLE
while read -r group name; do
	[ -n "$group" ] || continue
	if printf '%s\n' "$have" | grep -Fqx "\"$group\""; then
		role=$name
		break
	fi
done <<EOF
$ROLES
EOF

printf '{"type":"claim_response","claims":{"role":"%s","groups":%s,"application":%s}}\n' \
	"$role" "$groups" "$application"
