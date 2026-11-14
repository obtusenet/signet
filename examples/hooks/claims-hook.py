#!/usr/bin/env python3
# Copyright (c) 2026 Obtuse Networking LLC
# SPDX-License-Identifier: MIT
"""
Example Signet Claims Hook

This is a simple example hook that returns static claims based on the user's email.
In production, you would typically query a database, LDAP, or other backend to
compute dynamic claims.

Usage:
    chmod +x examples/hooks/claims-hook.py
    # Add to signet.yaml:
    # claims_hook:
    #   enabled: true
    #   program: "/path/to/examples/hooks/claims-hook.py"
    #   timeout_seconds: 5

Protocol:
    Reads JSON lines from stdin, writes JSON lines to stdout.
    Logs to stderr for debugging.
"""

import json
import sys

# Example claim mappings (in production, query your backend)
DEFAULT_CLAIMS = {
    "role": "user",
    "authenticated": True,
    "auth_method": "unknown",
}

def get_claims_for_email(email):
    """Get claims for a specific email address."""
    # Decide on the domain, taken whole: a suffix test would also match
    # "x@evil.example,y@admin.example.com".  Signet sends one plain address,
    # but a hook that grants roles should not rely on it.
    if email.count("@") != 1:
        return DEFAULT_CLAIMS
    domain = email.split("@")[1].lower()

    # Example: admin users get admin role
    if domain == "admin.example.com":
        return {
            "role": "admin",
            "department": "IT",
            "level": 5,
        }
    
    # Example: engineering users get engineering department
    if domain == "engineering.example.com":
        return {
            "role": "engineer",
            "department": "Engineering",
            "level": 3,
        }
    
    # Example: users with specific patterns
    if email.startswith("contractor-"):
        return {
            "role": "contractor",
            "department": "External",
            "level": 1,
            "contractor": True,
        }
    
    # Default claims
    return {
        "role": "user",
        "department": "General",
        "level": 2,
    }

def main():
    """Main loop: read requests from stdin, write responses to stdout."""
    sys.stderr.write("[claims-hook] Starting claims hook\n")
    sys.stderr.flush()
    
    for line in sys.stdin:
        try:
            # Parse request
            req = json.loads(line.strip())
            
            if req.get("type") != "claim_request":
                sys.stderr.write(f"[claims-hook] Unexpected request type: {req.get('type')}\n")
                sys.stderr.flush()
                continue
            
            email = req.get("email", "")
            sys.stderr.write(f"[claims-hook] Processing claim request for: {email}\n")
            sys.stderr.flush()
            
            # Get claims for user
            claims = get_claims_for_email(email)
            
            # Add metadata
            claims["source"] = "claims-hook"
            claims["email"] = email
            
            # Send response
            resp = {
                "type": "claim_response",
                "claims": claims,
            }
            
            print(json.dumps(resp), flush=True)
            
        except json.JSONDecodeError as e:
            sys.stderr.write(f"[claims-hook] Invalid JSON: {e}\n")
            sys.stderr.flush()
            print(json.dumps({
                "type": "claim_error",
                "error": f"Invalid JSON: {e}",
            }), flush=True)
            
        except Exception as e:
            sys.stderr.write(f"[claims-hook] Error: {e}\n")
            sys.stderr.flush()
            print(json.dumps({
                "type": "claim_error",
                "error": str(e),
            }), flush=True)

if __name__ == "__main__":
    main()
