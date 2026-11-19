# Signet with FreeRADIUS

Signet can check the passwords of names that are not in `users.csv` with RADIUS
servers. This is a working FreeRADIUS 3.2 setup: one client entry for Signet, and
users whose groups differ by application. `tests/radius_test.sh` in the source
tree runs the same thing in Docker. The settings are in `signet-config.yaml(5)`,
and what a claims hook receives is in `signet-hooks(5)`.

## Signet

```yaml
radius:
  enabled: true
  nas_identifier: "wiki"                 # this application
  servers:
    - address: "radius.example.com"      # port 1812
      secret_file: "/etc/signet/radius.secret"
      auth: "pap"                        # or "mschapv2"
  group_attributes: ["Filter-Id"]
```

The secret file holds the shared secret on one line, readable by Signet's user
only:

```sh
umask 077
printf '%s\n' 'a-long-random-secret' > /etc/signet/radius.secret
chown _signet /etc/signet/radius.secret
```

Run one Signet instance per application, each with its own `nas_identifier`
(and `base_path` and `cookie_name`), when the server should answer them
differently.

## FreeRADIUS: the client

In `clients.conf`, with Signet's address and the same secret.
`require_message_authenticator = yes` makes the server drop requests without
one; Signet always sends it, and by default requires it in every reply.

```
client signet {
	ipaddr = 192.0.2.10
	secret = a-long-random-secret
	require_message_authenticator = yes
	limit_proxy_state = yes
}
```

## FreeRADIUS: users and groups

In `mods-config/files/authorize`. Each `Filter-Id` in the reply is one group.
Checking `NAS-Identifier` gives each application its own answer:

```
jdoe	Cleartext-Password := "a-password"
	Filter-Id := "wiki-admins",
	Filter-Id += "staff"

bob	NAS-Identifier == "wiki", Cleartext-Password := "b-password"
	Filter-Id := "wiki-editors"

bob	NAS-Identifier == "blog", Cleartext-Password := "b-password"
	Filter-Id := "blog-readers"
```

`bob` signs in to the wiki as a `wiki-editors` member and to the blog as a
`blog-readers` member, and to any other application not at all.

A reply may also set the session's limits, in seconds:

```
carol	Cleartext-Password := "c-password"
	Session-Timeout := 28800,
	Idle-Timeout := 900
```

Signet uses them up to `radius.max_session_timeout` and
`radius.max_idle_timeout`, which default to its own `cookie_max_age` and
`session_idle_timeout`: raise those to let the server lengthen a session.

A real deployment keeps passwords in LDAP, SQL or Active Directory rather than
in this file; the reply attributes are set the same way.

## MS-CHAPv2

With `auth: "mschapv2"`, the server needs the clear password or its NT hash
(`NT-Password`). In the virtual server, the `authenticate` section needs:

```
Auth-Type mschap {
	mschap
}
```

Signet checks the `MS-CHAP2-Success` in each Access-Accept, so a server that
does not know the password cannot accept.

## The groups in applications

Without a claims hook, a RADIUS account's session has the claims
`{"groups":["wiki-admins","staff"]}`, in `GET /session` and
`/api/v1/validate`. To turn groups into what an application expects, such as a
role, use a claims hook: `examples/hooks/radius-claims.py`, or
`radius-claims.sh` for a host with only `sh` and `awk`, is a starting point.

## Second factors

A RADIUS account's only second factor in Signet is an authenticator app (TOTP).
It can add, use and remove one on `/account`, and never a security key, a mailed
PIN or recovery, whatever `second_factor_methods` lists; local accounts keep every
method that is enabled. With `second_factor: "required"`, enable and list `totp`,
or RADIUS accounts are refused.

The server may have its own second factor, such as a token code asked with an
Access-Challenge. Signet passes the prompt and the answer, but cannot see or manage
that factor, and it does not count toward `second_factor`: under `"required"` such a
user also adds an app, and answers two prompts.

## Names

`users.csv` is asked first, so a local account with a RADIUS user's name signs in
on its own password and never reaches the server. When RADIUS names are mail
addresses, that includes an account self-registered by whoever reads the
mailbox. Keep the names apart, or leave `self_registration` off.

`signet session-revoke jdoe` ends a RADIUS account's sessions in Signet. The
server is not told; disable the account there to stop new sign-ins.

## Security

PAP over UDP hides the password with MD5 and the shared secret, and an MS-CHAPv2
exchange can be attacked offline. Keep the path between Signet and the server on
a trusted network, or under IPsec, and use a long random secret.
