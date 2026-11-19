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
role, use a claims hook: `examples/hooks/radius-claims.py` is a starting point.

## Security

PAP over UDP hides the password with MD5 and the shared secret, and an MS-CHAPv2
exchange can be attacked offline. Keep the path between Signet and the server on
a trusted network, or under IPsec, and use a long random secret.
