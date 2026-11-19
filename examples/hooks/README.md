# Signet External Claims Hooks

This directory contains example implementations of external claims hooks for Signet.
The protocol reference is `signet-hooks(5)`.

## Overview

The claims hook allows you to compute application-specific claims (permissions, roles, etc.) for authenticated users. The hook is an external program that communicates with Signet via stdin/stdout using JSON lines.

## Protocol

### Request (Signet → Hook)

Signet sends a JSON line to the hook's stdin:

```json
{
  "type": "claim_request",
  "email": "user@example.com",
  "source": "local"
}
```

For an account a RADIUS server accepted, `source` is `"radius"`, and a `radius`
member carries the application, the groups and every reply attribute.
`radius-claims.py`, and `radius-claims.sh` in POSIX `sh` and `awk` (bash and ksh
alike), turn those groups into a role; see `signet-hooks(5)` and `examples/radius/`.

### Response (Hook → Signet)

The hook must respond with a JSON line to stdout:

**Success:**
```json
{
  "type": "claim_response",
  "claims": {
    "role": "admin",
    "department": "Engineering",
    "level": 3
  }
}
```

**Error:**
```json
{
  "type": "claim_error",
  "error": "something went wrong"
}
```

### Logging (Hook → Signet)

Signet discards the hook's stderr. To keep debug output, have the hook write it
somewhere itself, such as syslog or its own file.

### Exit without an answer

A hook that exits without answering counts as a failure immediately, without
waiting for `timeout_seconds`, and `on_failure` decides the outcome.

## Configuration

Add the following to your `signet.yaml`:

```yaml
claims_hook:
  enabled: true
  program: "/path/to/your/claims-hook.sh"
  timeout_seconds: 5
  on_failure: "fail-closed"  # or "fail-open"
```

### Fields

- `enabled` (bool): Enable or disable the claims hook
- `program` (string): Path to the hook executable
- `timeout_seconds` (int): Timeout for hook responses (default: 5)
- `on_failure` (string): Behavior on hook failure:
  - `"fail-closed"`: Authentication fails if hook fails (default): no session is
    created and the client gets `403 Sign-in refused`, for every login method. A
    hook can use this to deny a user by answering `claim_error`.
  - `"fail-open"`: Authentication succeeds with empty claims if hook fails

## Example Hooks

### Python Hook (`claims-hook.py`)

A Python implementation that returns static claims based on email domain:

```bash
# Make executable
chmod +x claims-hook.py

# Test the hook
echo '{"type":"claim_request","email":"admin@example.com"}' | ./claims-hook.py

# Configure in signet.yaml
# claims_hook:
#   enabled: true
#   program: "./claims-hook.py"
```

### Bash Hook (`claims-hook.sh`)

A Bash implementation with similar functionality:

```bash
# Make executable
chmod +x claims-hook.sh

# Test the hook
echo '{"type":"claim_request","email":"admin@example.com"}' | ./claims-hook.sh

# Configure in signet.yaml
# claims_hook:
#   enabled: true
#   program: "./claims-hook.sh"
```

## Protocol Testing

Check that the example hooks answer the protocol correctly (needs `python3`):

```bash
./test-hooks.sh
```

## Production Considerations

1. **Performance**: The hook is invoked on every authentication. Ensure it responds quickly.
2. **Fault Tolerance**: Use `on_failure: "fail-open"` if you want authentication to continue if the hook fails.
3. **Security**: The hook runs as the Signet process user. Ensure proper file permissions.
4. **Logging**: Signet discards the hook's stderr; log from the hook itself.
5. **Timeout**: Set `timeout_seconds` appropriately for your hook's response time.

## Example Use Cases

1. **Role-based access control**: Query a database to get user roles
2. **Department-based access**: Return department information for access control
3. **Dynamic permissions**: Compute permissions based on user attributes
4. **Third-party integration**: Query LDAP, Active Directory, etc.

## Troubleshooting

1. **Hook not responding**: Check that the hook is executable and responds within `timeout_seconds`
2. **Invalid JSON**: Ensure the hook sends valid JSON to stdout
3. **Permission errors**: Check file permissions for the hook script
4. **Timeout errors**: Increase `timeout_seconds` or optimize hook performance

## See Also

- `signet-hooks(5)`: the protocol, failure handling and caveats
- `signet-config.yaml(5)`: the `claims_hook` keys
