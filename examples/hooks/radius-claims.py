#!/usr/bin/env python3
# Copyright (c) 2026 Obtuse Networking LLC
# SPDX-License-Identifier: MIT
"""
Claims for RADIUS accounts: turns the groups a RADIUS server sent into the
claims an application expects.  See signet-hooks(5).

Signet sends, for an account a RADIUS server accepted:

  {"type":"claim_request","email":"jdoe","source":"radius",
   "radius":{"nas_identifier":"wiki","groups":["wiki-admins"],"attributes":[...]}}

and for a users.csv account "source":"local" and no "radius".  This hook
answers the groups as they came, a role taken from them, and the application
the server answered for.  Edit ROLES for your groups.

Usage, in config.yaml:

  claims_hook:
    enabled: true
    program: "/usr/local/libexec/signet/radius-claims.py"
"""

import json
import sys

# The first group listed here that the account has decides its role.
ROLES = [
    ("wiki-admins", "admin"),
    ("wiki-editors", "editor"),
    ("staff", "user"),
]

# A role for accounts in none of those groups, and for users.csv accounts.
DEFAULT_ROLE = "user"


def claims_for(request):
    if request.get("source") != "radius":
        return {"role": DEFAULT_ROLE, "groups": []}
    radius = request.get("radius") or {}
    groups = [g for g in radius.get("groups") or [] if isinstance(g, str)]
    role = DEFAULT_ROLE
    for group, name in ROLES:
        if group in groups:
            role = name
            break
    return {
        "role": role,
        "groups": groups,
        "application": radius.get("nas_identifier", ""),
    }


def main():
    line = sys.stdin.readline()
    try:
        request = json.loads(line)
    except json.JSONDecodeError:
        print(json.dumps({"type": "claim_error", "error": "the request is not JSON"}))
        return
    if request.get("type") != "claim_request":
        print(json.dumps({"type": "claim_error", "error": "not a claim_request"}))
        return
    print(json.dumps({"type": "claim_response", "claims": claims_for(request)}))
    sys.stdout.flush()


if __name__ == "__main__":
    main()
