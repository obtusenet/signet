# Signet

Signet is a small sign-in service for web applications you run yourself. It shows
the login page, checks who someone is, and gives the browser one session cookie.
Your web server and applications then ask Signet whose cookie it is. One sign-in
covers every application behind the same web server, and none of them has to store
passwords or implement security keys.

It is one Go binary with its accounts in a CSV file and its sessions in SQLite, and
it runs on OpenBSD, FreeBSD and Linux, behind Caddy, nginx or OpenBSD's httpd.

## What it does

- **Sign-in methods:** passwords (argon2id or bcrypt), security keys and passkeys
  (WebAuthn), a PIN sent by mail, and TOTP codes from an authenticator app as a
  second step.
- **Accounts:** self-registration with mail verification and optional approval,
  password recovery by mail, an `/account` page for passwords, keys, TOTP and a
  picture, lockout after repeated failures, and a `signet` command for
  administrators.
- **For applications:**
  - `GET /session` answers whose cookie it is, and sets `Remote-User` and
    `Remote-Email` headers, so a web server can use it for forward-auth.
  - `POST /api/v1/validate` checks a cookie for a backend, with an API key per
    application.
  - A claims hook, an external program you write, adds roles, groups or anything
    else to each session at sign-in.
- **Deployment:** HTTP on a port or a unix socket, or FastCGI. Several instances
  can share one database, or serve separate applications under different paths on
  one host. `SIGHUP` reloads the configuration and templates. Logging goes to
  syslog or the systemd journal. The pages are templates you can edit.
- **Packaging:** OpenBSD and FreeBSD ports, a Debian 13 package, a Docker image
  and an install script for systemd Linux.

## Signet is not an OIDC or OAuth 2.0 provider

Signet does part of what an OpenID Connect provider does, in a simpler way:

| | Signet | OIDC / OAuth 2.0 provider |
|---|---|---|
| Central login page, one sign-in for many applications | Yes | Yes |
| Passwords, security keys, mailed PINs, TOTP | Yes | Usually |
| Identity and claims for an application | `/session` JSON and headers, `/api/v1/validate`, claims hook | ID token (JWT), userinfo endpoint |
| How an application trusts it | It asks Signet over HTTP, or the web server does (forward-auth) | It verifies signed tokens |
| Where applications must be | Same host or parent domain as the cookie, behind your web server | Anywhere |
| Third-party clients, consent screens, delegated API access | No | Yes |
| Tokens (access, refresh, ID, JWT), discovery, JWKS | No | Yes |

Use Signet when your applications run behind your own web server and you want them
to share one sign-in. You don't need a token protocol for that. Use an OIDC
provider when applications on other domains, or third-party software that only
speaks OIDC or SAML, must sign in through you, or when you need delegated API
access.

## Install from source

You need:

- Go 1.26 or later, and a C compiler: the SQLite driver uses cgo and carries
  SQLite itself.
- `make`.
- For `make test`: `node`, `python3` and `curl`.

The source tree carries its dependencies in `vendor/`, so building needs no network.

```sh
git clone https://github.com/obtusenet/signet.git
cd signet
make          # build/signet
make test     # Go, browser-script, hook, packaging and end-to-end tests
```

Make a configuration. The sample's paths are the packages' paths, so for a trial
from the source tree, point them at a working directory:

```sh
mkdir -p run
cp -R web/templates web/static run/
cp config/example.yaml run/config.yaml
openssl rand -hex 32          # the cookie_secret
vi run/config.yaml
```

In `run/config.yaml`, set:

```yaml
listen: "127.0.0.1:8080"
cookie_secret: "<the 64 hex digits>"
cookie_secure: false          # only while you test over plain HTTP
templates_dir: "run/templates"
static_dir: "run/static"
database_path: "run/sessions.db"
csv_path: "run/users.csv"
mail:
  program: ""                 # writes mail to the log instead of sending it
```

Keep the file unreadable by other users (`chmod 600 run/config.yaml`). Add an account,
typing its password, and start the server:

```sh
./build/signet user-add -config run/config.yaml -password-stdin you@example.com
./build/signet serve -config run/config.yaml
```

Open `http://127.0.0.1:8080/login` and sign in. `/account` is your account page;
`/session` shows the session as an application sees it.

For real use:

1. Put Signet behind your web server over HTTPS, and route its paths to it.
   `examples/web-servers/` has Caddy, nginx and OpenBSD httpd configurations,
   with forward-auth for the applications you protect.
2. Set `cookie_secure: true` (the default), `public_url`, and the mail settings,
   so PINs, recovery and registration links can be sent.
3. Install it as a service:
   - **OpenBSD:** the port in `contrib/packaging/openbsd/`.
   - **FreeBSD:** the port in `contrib/packaging/freebsd/`.
   - **Debian 13:** `make deb`; see `contrib/packaging/debian/README.md`.
   - **Other systemd Linux:** `sudo ./deploy/install.sh`, which also upgrades.
   - **Docker:** `make docker-image`; see `contrib/packaging/docker/README.md`.

   The packages read `/etc/signet/config.yaml` (`/usr/local/etc/signet/` on
   FreeBSD) without `-config`, and are installed but not started until you set
   `cookie_secret`.

## Administration

```sh
signet user-add [-hash bcrypt|argon2id] [-password-stdin] <email> [password]
signet user-list
signet user-approve <email>...              # self-registered accounts
signet user-unlock <email>                  # after a lockout
signet user-delete-totp <email>             # for a lost authenticator
signet user-delete -confirm <email>         # also ends sessions, removes keys
signet webauthn-invite [-ttl 24h] <email>   # one-time link to enroll a key
signet client-add [--origins …] <name>      # an API key for /api/v1/validate
signet avatar-remove <email>
signet help
```

Each command takes `-config <path>` before its arguments. `signet(1)` lists them all.

## Configuration

One YAML file configures Signet. `config/example.yaml` contains every setting with
a comment. `signet-config.yaml(5)` (`man/man5/signet-config.yaml.5`) is the full
reference. A setting you leave out takes the default shown here. Times are in
seconds unless the table says otherwise. Switches take `"enabled"` or `"disabled"`.

`serve` checks the file when it starts, and refuses to start on a mistake,
including a key it does not know, so a misspelt setting cannot go unnoticed.
`SIGHUP` reads the file again. Settings marked † need a restart instead.

### Server

| Setting | Default | Meaning |
|---|---|---|
| `listen` † | `":8080"` | `host:port`, `[::]:port` or `:port` for TCP, or an absolute path for a unix socket |
| `protocol` † | `"http"` | `"http"`, or `"fastcgi"` for a web server that speaks FastCGI (OpenBSD httpd, nginx) |
| `socket_mode` † | `"0660"` | Octal mode of the socket file when `listen` is a path |
| `templates_dir` | `/etc/signet/templates` | The HTML and mail templates (`signet-template(5)`) |
| `static_dir` | `/etc/signet/static` | `js/webauthn.js` |
| `public_url` | none | This instance's URL as a browser reaches it, for links in mail. Recovery and mail-verified registration stay off without it |
| `base_path` | none | Serve every route under this path (e.g. `/app-auth`), so instances can share a host |
| `trusted_proxies` | `[]` | Addresses, CIDR ranges or `unix` whose `X-Forwarded-For` is believed. List your reverse proxy, or every client shares its rate limits |
| `allowed_redirect_hosts` | `[]` | Other hosts a sign-in may return to. A name without a port allows the default port only |

### Cookie and session

| Setting | Default | Meaning |
|---|---|---|
| `cookie_secret` | none, required | Signs cookies and derives other keys. At least 32 characters (`openssl rand -hex 32`). Instances sharing a database must share it. Changing it signs everyone out and makes stored TOTP keys unreadable |
| `cookie_name` | `signetid` | Instances on one host need different names |
| `cookie_domain` | empty | Empty for the host only, or a parent domain to share the cookie with subdomains |
| `cookie_max_age` | `86400` | Session lifetime |
| `cookie_secure` | `true` | Set `false` only for plain-HTTP testing |

### Storage

| Setting | Default | Meaning |
|---|---|---|
| `database_path` † | `/var/lib/signet/sessions.db` | SQLite: sessions, security keys, TOTP keys, API clients, pictures |
| `csv_path` † | `/var/lib/signet/users.csv` | Accounts: address, password hash, flags. You may edit it by hand while the server runs; it is reloaded |

### Passwords

| Setting | Default | Meaning |
|---|---|---|
| `password_hash_algorithm` | `argon2id` | Or `bcrypt`. Each account keeps the algorithm it was hashed with |
| `bcrypt_cost` | `12` | |
| `argon2id_time`, `argon2id_memory`, `argon2id_parallelism` | `1`, `65536` (KiB), `4` | |
| `argon2id_salt_length`, `argon2id_key_length` | `16`, `32` | Bytes |

### Sign-in methods

| Setting | Default | Meaning |
|---|---|---|
| `auth_methods.password` | `enabled` | |
| `auth_methods.email_pin` | `enabled` | A PIN by mail; needs a working `mail.program` |
| `auth_methods.webauthn` | `disabled` | Security keys and passkeys; needs the two settings below and HTTPS |
| `webauthn_rpid` | none | The domain name keys are bound to, e.g. `signet.example.com` |
| `webauthn_origins` | none | The page origins, e.g. `https://signet.example.com` |
| `webauthn_rp_name` | `Signet` | The name a browser shows |
| `auth_methods.totp` | `disabled` | Accounts with an authenticator key need a code after a password or a PIN |
| `totp_issuer` | `Signet` | The name an authenticator app shows |
| `second_factor` | `optional` | `required`: every sign-in proves two factors. Keys must check a PIN or fingerprint, a password or PIN is followed by a code, and an account with neither adds one at sign-in |
| `second_factor_methods` | `[totp, webauthn]` | What may follow a password or PIN, and be added. `email_pin` is allowed but weak, and `serve` warns |

### Accounts

| Setting | Default | Meaning |
|---|---|---|
| `self_registration` | `disabled` | `enabled` lets people create accounts at `/register` |
| `self_registration_approval` | `required` | New accounts wait for `signet user-approve`; `auto_approve` skips that |
| `email_verification` | `required` | The account is created from a mailed link. `disabled` creates it at once, unproved |
| `registration_link_ttl` | `86400` | |
| `password_recovery` | `disabled` | `enabled` mails a reset link from `/recover` |
| `recovery_link_ttl` | `3600` | |
| `account_reauth_window` | `600` | How recent a sign-in must be to change the account |
| `avatars` | `disabled` | A picture per account; the web server must route `/avatar/` |
| `avatar_size` | `256` | Pixels square, 32 to 512 |
| `multi_device` | `enabled` | Not implemented; ignored |

### Limits and lockout

Each pair is the most allowed (`*_limit`) per window in seconds (`*_window`).

| Settings | Default | Counts |
|---|---|---|
| `login_address_limit`, `login_rate_limit`, `login_rate_window` | `enabled`, `5`, `300` | Failed passwords per account address. Reset by a sign-in |
| `login_source_limit`, `login_source_rate_limit`, `login_source_rate_window` | `enabled`, `20`, `300` | Failed passwords per client address |
| `account_lockout_threshold`, `account_lockout_duration` | `100`, `30` (minutes) | Failed passwords, PINs and codes in a row before those are refused; `0` is off. A passkey, recovery or `signet user-unlock` still gets in |
| `email_rate_limit`, `email_rate_window` | `3`, `60` | PINs sent per address |
| `mail_link_rate_limit`, `mail_link_rate_window` | `3`, `3600` | Recovery and registration mails per address |
| `mail_link_source_rate_limit`, `mail_link_source_rate_window` | `10`, `3600` | The same per client address |
| `webauthn_rate_limit`, `webauthn_rate_window` | `30`, `60` | Security-key ceremony steps per client |
| `register_rate_limit`, `register_rate_window` | `5`, `3600` | Registrations per client |
| `avatar_rate_limit`, `avatar_rate_window` | `10`, `3600` | New pictures per account |
| `api_rate_limit`, `api_rate_window` | `60`, `60` | `/api/v1/validate` calls per API client |

The counts are kept in memory, by each process: instances that share one `users.csv` and
database each count on their own, so _n_ of them allow _n_ times each limit. The counts start
over on a restart or reload. Lockout counts are kept in the database, so they are shared and
survive both.

### Mail

Signet runs a `sendmail`-compatible program, as `mail(1)` does. Where mail may go
is your mail system's decision.

| Setting | Default | Meaning |
|---|---|---|
| `mail.program` | `/usr/sbin/sendmail` | Empty writes every message, PINs included, to the log: for development only |
| `mail.from_address` | empty | The sender, which receives bounces. Empty leaves it to the mail system |
| `mail.from_name` | `Signet` | |

### Claims hook

| Setting | Default | Meaning |
|---|---|---|
| `claims_hook.enabled` | `false` | Run a program at each sign-in, whose JSON answer becomes the session's `claims` (`signet-hooks(5)`) |
| `claims_hook.program` | none | Its path; `examples/hooks/` has samples |
| `claims_hook.timeout_seconds` | `5` | |
| `claims_hook.on_failure` | `fail-closed` | `fail-closed` refuses the sign-in when the hook fails; `fail-open` signs in with no claims |

### Logging

| Setting | Default | Meaning |
|---|---|---|
| `log_syslog` † | `false` | Log to syslog instead of stdout. Under systemd the journal is used either way |
| `log_level` | `info` | Not implemented: every level is logged |

## Documentation

- `signet(1)`: the command.
- `signet-config.yaml(5)`: the configuration.
- `signet-template(5)`: the templates and their variables.
- `signet-hooks(5)`: the claims hook protocol.
- `signet-api(7)` and `docs/API.md`: the HTTP API, for people writing clients
  or web-server configuration. `docs/API.md` is written to be read whole by a
  tool or a language model.
- `docs/DESIGN.md`: how it fits together, and why.
- `examples/web-servers/` and `examples/hooks/`: working samples.
- `contrib/packaging/*/README.md`: each package.

`man -l man/man5/signet-config.yaml.5` reads a page from the source tree.

## Software bill of materials

Each source archive carries `signet.spdx.json`, an SPDX 2.3 list of everything
compiled into Signet: each Go module at its vendored version and licence, the Go
toolchain, and the SQLite library in the SQLite driver. Each release attaches the
same file. `make sbom` writes one for the working tree to `dist/`.

## Written by AI

Signet's code, tests, packaging and documentation were written by an AI model:
Anthropic's Claude, working through Claude Code. A person directed the work. They
decided what Signet should do and how it should behave, reviewed the changes,
and tested it on real OpenBSD, FreeBSD and Linux systems with real browsers and
security keys.

The tests (`make test`, and the package and web-server tests described in
`AGENTS.md`) are how the behaviour is checked. Like any software, Signet may contain
mistakes. It is authentication software, so read `docs/SECURITY.md`, review it
before you rely on it, and report problems.

## To do

- Allow authentication with YubiKeys.

## Contributing and security

Pull requests are welcome; see `docs/CONTRIBUTING.md`. Report security problems
privately, as `docs/SECURITY.md` describes, not in a public issue.

## License

MIT; see `LICENSE`. Copyright (c) 2026 Obtuse Networking LLC.
