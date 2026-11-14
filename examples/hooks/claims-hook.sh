#!/bin/bash
# Copyright (c) 2026 Obtuse Networking LLC
# SPDX-License-Identifier: MIT
#
# Example Signet Claims Hook (Bash version)
#
# This is a simple example hook that returns static claims based on the user's email.
# In production, you would typically query a database, LDAP, or other backend.
#
# Usage:
#     chmod +x examples/hooks/claims-hook.sh
#     # Add to signet.yaml:
#     # claims_hook:
#     #   enabled: true
#     #   program: "/path/to/examples/hooks/claims-hook.sh"
#     #   timeout_seconds: 5
#

set -euo pipefail

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >&2
}

log "Starting claims hook"

# Read JSON lines from stdin and write responses to stdout
while IFS= read -r line || [ -n "$line" ]; do
    # Parse request
    type=$(echo "$line" | python3 -c "import sys, json; print(json.load(sys.stdin).get('type', ''))" 2>/dev/null || echo "")
    
    if [ "$type" != "claim_request" ]; then
        log "Unexpected request type: $type"
        continue
    fi
    
    # Extract email
    email=$(echo "$line" | python3 -c "import sys, json; print(json.load(sys.stdin).get('email', ''))" 2>/dev/null || echo "")
    
    log "Processing claim request for: $email"
    
    # Decide on the domain, taken whole: a suffix test would also match
    # "x@evil.example,y@admin.example.com".  Signet sends one plain address,
    # but a hook that grants roles should not rely on it.
    domain=""
    if [[ "$email" == *@* && "$email" != *@*@* ]]; then
        domain=$(printf '%s' "${email#*@}" | tr '[:upper:]' '[:lower:]')
    fi

    # Get claims based on email domain
    if [[ "$domain" == admin.example.com ]]; then
        claims='{"role":"admin","department":"IT","level":5}'
    elif [[ "$domain" == engineering.example.com ]]; then
        claims='{"role":"engineer","department":"Engineering","level":3}'
    elif [[ "$email" == contractor-* ]]; then
        claims='{"role":"contractor","department":"External","level":1,"contractor":true}'
    else
        claims='{"role":"user","department":"General","level":2}'
    fi
    
    # Add metadata
    # The address travels through the environment, never into the Python source.
    claims=$(echo "$claims" | HOOK_EMAIL="$email" python3 -c "import json, os, sys; d=json.load(sys.stdin); d['source']='claims-hook'; d['email']=os.environ['HOOK_EMAIL']; print(json.dumps(d))")
    
    # Send response
    echo "{\"type\":\"claim_response\",\"claims\":$claims}"
    
done
