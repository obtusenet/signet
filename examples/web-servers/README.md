# Web-server example configurations

Sample setups for putting a web server in front of signet. Each server has
two variants, matching signet's `listen` field:

- **port** — signet on TCP: `listen: ":9090"`
- **socket** — signet on a unix socket: `listen: "/path/signet.sock"`
  (HTTP over the socket) or `protocol: "fastcgi"` with
  `listen: "/path/fcgi.sock"` (FastCGI, signet as the responder)

| Variant | Server | Transport to signet | Why you would pick it |
|---|---|---|---|
| `caddy/Caddyfile-port` | Caddy v2 | TCP proxy | simplest Caddy setup |
| `caddy/Caddyfile-socket` | Caddy v2 | HTTP over unix socket (`unix//path`) | no TCP port; Caddy cannot speak FastCGI as a client |
| `nginx/signet-port.conf` | nginx | TCP proxy | classic `auth_request` gate |
| `nginx/signet-fcgi.conf` | nginx | FastCGI over unix socket | no port for signet; `REMOTE_ADDR` comes from the protocol |
| `openbsd-httpd/signet-port.conf` | httpd(8) | signet on its own TCP port | httpd-only box without FastCGI mount |
| `openbsd-httpd/signet-fcgi.conf` | httpd(8) | **FastCGI over unix socket** | httpd has NO reverse proxy — FastCGI is how signet gets the SAME ORIGIN on an httpd-only box |

Every example mounts signet's auth URIs (`/login /logout /session /recover /register /account`,
`/webauthn/*`, `/email-pin/*`, `/avatar/*`, `/static/js/webauthn.js`) on the same origin
as the protected application, which is what makes the `signetid` cookie
first-party and the login → return → logout loop work.

Set `trusted_proxies` in signet's config to match the variant, or every client
shares one rate-limit budget and the log shows only the proxy:

| Variant | `trusted_proxies` |
|---|---|
| TCP proxy on the same host | `["127.0.0.1", "::1"]` |
| HTTP over a unix socket | `["unix"]` |
| FastCGI | none: the web server reports the client directly |

A visitor can send `Remote-User`, `Remote-Email` and `Remote-Avatar` too, so the web server
must not pass the visitor's copies to the application. The nginx examples clear all three, since
signet sends `Remote-Avatar` only for an account with a picture. Caddy's `forward_auth`
`copy_headers` removes a visitor's copy of each header it names (tested with Caddy 2.11.4).
`make test-web-servers` sends forged ones through every example.

The web server must pass `Host` on unchanged, as every example does. Over plain HTTP a browser
sends no `Sec-Fetch-Site`, so signet compares `Origin` with `Host` and refuses a login whose
`Host` was rewritten.

Every example listens on plain HTTP so that it runs as it stands. `cookie_secure` defaults to
`true`, and a browser will not send that cookie over plain HTTP, so either terminate TLS in the
web server, which is what a real deployment does, or set `cookie_secure: false` to try one out.

The return address a web server sends to `/login?referrer=` cannot be URL-encoded by nginx or
Caddy. Signet takes such a value whole, so `/page?x=1&y=2` comes back intact.

`make test-web-servers` runs all of these on the OpenBSD test box.

Caddy syntax reminder: the unix upstream is `unix//absolute/path` (two
slashes, no colon); `unix:/path` fails with "unknown network".

For FastCGI sockets: signet binds them (it is the responder), so the web
server's user must have write access to connect — a setgid directory or an
opened `socket_mode` (signet-config.yaml(5)).

Installed locations:

- OpenBSD (port): `/usr/local/share/examples/signet/web-servers/`
- Linux (`deploy/install.sh`): `/usr/share/doc/signet/examples/web-servers/`
- Docker image: `/usr/share/doc/signet/examples/web-servers/`

The example claims hooks live in `../hooks/` and are installed beside these
files (`share/examples/signet/hooks/` on OpenBSD).

## A second instance on the same host

`base_path` puts every route of an instance under one path, so another application can have
its own signet, with its own users, database, hook and approval setting, on the same host and
port. One prefix is then the only route the web server needs. It must pass the path whole:
signet removes the base itself, and answers 404 outside it.

The instances need different `cookie_name` values, because both cookies are set for the
same host with path `/`. Links in mail are `public_url`, then `base_path`, so `public_url`
stays the site's address with no path.

```yaml
listen: "127.0.0.1:9091"          # or a socket of its own
base_path: "/comments-auth"
cookie_name: "commentsid"
public_url: "https://www.example.com"
database_path: "/var/www/signet-comments/sessions.db"
csv_path: "/var/www/signet-comments/users.csv"
```

Caddy (`handle`, not `handle_path`, which would remove the prefix; the matcher takes the base
with and without what follows):

```
@comments_auth path /comments-auth /comments-auth/*
handle @comments_auth {
	reverse_proxy 127.0.0.1:9091
}
```

nginx (no URI after the address in `proxy_pass`, so the path goes whole; over FastCGI,
`fastcgi_params` passes it in `REQUEST_URI`):

```
location /comments-auth/ {
    proxy_pass http://127.0.0.1:9091;
    proxy_set_header Host $host;
}
```

httpd(8), with the instance on its own FastCGI socket:

```
location "/comments-auth/*" {
	fastcgi { socket "/run/signet-comments/fcgi.sock" }
}
```

The application behind the site checks a visitor with `POST /comments-auth/api/v1/validate`
and a key from `signet client-add` run against that instance's config, or with
`/comments-auth/session`.
