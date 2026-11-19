# AGENTS.md: Signet

Instructions for AI agents (and people) working on Signet. This file gives the same
rules as `docs/CONTRIBUTING.md`, plus what an agent needs to find its way.

Signet is a sign-in service for web applications: one Go binary that does
passwords, security keys (WebAuthn), mailed PINs and TOTP, and issues one session
cookie that applications check through `/session` or `/api/v1/validate`. It is not
an OIDC or OAuth provider. `README.md` explains the difference.

**Version:** 0.14.2

## Where things are

| What | Where |
|---|---|
| What Signet is, install from source, every setting | `README.md` |
| How it works and why: storage, sessions, methods, limits | `docs/DESIGN.md` |
| The HTTP contract, complete, meant to be read whole | `docs/API.md` (and `man/man7/signet-api.7`) |
| Commands | `man/man1/signet.1` |
| Settings, in full | `man/man5/signet-config.yaml.5`, `config/example.yaml` |
| Templates and their variables | `man/man5/signet-template.5` |
| Claims hook protocol | `man/man5/signet-hooks.5` |
| Pull requests, design rules, style | `docs/CONTRIBUTING.md` |
| Reporting vulnerabilities | `docs/SECURITY.md` |
| Packages | `contrib/packaging/{openbsd,freebsd,debian,docker}/README.md`, `deploy/` |

Read `docs/DESIGN.md` and the relevant part of `docs/API.md` before changing
behaviour.

## Layout

```
cmd/signet/            CLI entry point and admin commands
internal/
  server/              HTTP server, routing, transports, pages, reload
  auth/                password and PIN sign-in, account policy, rate limits, lockout
  webauthn/            security-key ceremonies, credentials, invites
  otp/                 TOTP
  radius/              RADIUS client: PAP, MS-CHAPv2, Message-Authenticator, groups
  session/ cookie/     sessions (SQLite, tokens hashed) and signed cookies
  backend/csv/         accounts in users.csv, reloaded on change
  db/                  SQLite connection and migrations
  email/ maillink/     sendmail, PINs, one-time links in mail
  claims/              the external claims hook
  apiclient/           API keys for /api/v1/validate
  avatar/ clientaddr/ config/ logging/ password/
web/templates/ web/static/   the pages, mail templates and webauthn.js
man/                   manual pages (mdoc)
config/example.yaml    every setting, commented; the packages' samples are made from it
deploy/                systemd unit, Linux installer, install-web.sh
contrib/packaging/     OpenBSD and FreeBSD ports, Debian, Docker, config.sh, sbom.sh
examples/              claims hooks and web-server configurations
tests/                 end-to-end and shell tests
vendor/                dependencies; Signet builds with no network
```

## Build and test

```sh
make               # build/signet
make lint          # go fmt and go vet
make test          # all of the below that need no network; must pass
make test-go       # go test ./...
make test-js       # the browser script and pages, against mocks (needs node)
make test-hooks    # the example claims hooks (needs python3)
make test-e2e      # real flows against a throwaway server on a unix socket (needs curl)
make test-configs  # the packages' sample configs match config/example.yaml
make test-sbom     # the SPDX SBOM covers every vendored module
make sbom          # dist/signet-<version>.spdx.json
make build         # source tarball with vendor/ and the SBOM
```

These need Docker, and are not part of `make test`:
- `make test-go-current` and `make vuln-current`: the Go tests, and a
  vulnerability scan, with the newest Go release (`GO_IMAGE`, pinned by digest).
  `make test` uses this host's Go, which proves the minimum in `go.mod`.
- `make test-docker`
- `make test-radius`: Signet against FreeRADIUS in Docker
- `make test-linux`
- `make deb` and `make test-deb`

The box targets build and test on real OpenBSD and FreeBSD machines over ssh. They
need `TESTBOX` or `FBSDBOX` as `user@host`, given on the command line or in
`local.mk`, which is not tracked:
- `build-package`, `deploy-package`, `test-web-servers`, `vuln-box` (`TESTBOX`);
- `vuln-host HOST=user@host`, for any machine's installed binary;
- `freebsd-package`, `test-freebsd` (`FBSDBOX`).

## Rules for changes

- **Tests and mail:** tests must never send real mail or reach the network.
  - Use `mail.program: ""`, which logs messages, or a fake program.
  - Use `example.com` addresses and documentation IP ranges.
- **Documentation goes with the change:**
  - a man page for any change in behaviour;
  - `docs/API.md` and `signet-api(7)` for any HTTP change;
  - `config/example.yaml` and `signet-config.yaml(5)` for a setting, then
    `make configs`.
- **Generated files:** don't hand-edit them.
  - `contrib/packaging/openbsd/www/signet/files/config.yaml` and
    `contrib/packaging/freebsd/www/signet/files/config.yaml.sample` come from
    `make configs`.
  - `debian/copyright` and the SBOM are generated at build time.
- **Dependencies:** standard library first. Each new module is vendored
  (`go mod vendor`), preferably MIT, BSD or Apache licensed, and the SBOM test
  must still pass.
- **Licence header:** each new source file and script starts with
  `Copyright (c) 2026 Obtuse Networking LLC` and `SPDX-License-Identifier: MIT`.
  `make test` checks it.
- **Documents:** new ones go in `docs/`, not the repository root.
- **Pull requests:** one topic each, with what changed, why, and how it was tested.
  Releases and version bumps are the maintainer's.

## Behaviour that must not regress

- **RADIUS:** a name `users.csv` has never goes to a RADIUS server. Every request
  carries `Message-Authenticator`, and a reply without a valid one is dropped
  unless `require_message_authenticator: false`. An MS-CHAPv2 Accept must prove
  the server knew the password. No answer fails closed (`503`). A RADIUS account
  never signs in by a key, a mailed PIN or recovery.
- **Failures:** each JSON endpoint answers with a status code that describes the
  failure and a JSON body. `POST /login` gives a plain form a 302, and
  `Accept: application/json` gets JSON. Never mix the two.
- **Session cookie:** `HttpOnly`, `SameSite=Strict`, and `Secure` unless
  `cookie_secure: false`. Its token is random, and stored only as a hash.
- **Account policy:** every sign-in method asks `auth.AccountPolicy`, and honours
  `claims_hook.on_failure`.
- **TOTP** is a second step after a password or a PIN, and a security key signs in
  alone.
- **Security keys:** enrollment needs a session or an invite, and never takes the
  address from the request. Unknown addresses get decoy options.
- **Links in mail** come from `public_url`, never the request. Their tokens are
  hashed, single use, and travel in the URL fragment.
- **Return after sign-in:** local paths and same-host URLs only, unless the host is
  in `allowed_redirect_hosts`. Signet's own `/login`, `/register`, `/recover` and
  `/logout` are never a return address.
- **Cross-origin requests:** a state-changing one from a browser is refused with
  403 (`http.CrossOriginProtection`). `/api/v1/validate` is exempt.
- **`X-Forwarded-For`** counts only from `trusted_proxies`, read from the right.
- **Logs:**
  - Passwords, tokens and PINs are never logged, except with `mail.program: ""`,
    which warns.
  - Every rate-limit refusal is logged at warning level.
  - Each request is logged as one line.
- **Web files:** `deploy/install-web.sh` never overwrites a template or static file
  the administrator has edited.
- **`base_path`:** everything Signet names (redirects, pages, mail links,
  `webauthn.js`) carries it.
- **`SIGHUP`:** a bad file keeps the running server.

## Style

- **Go:** `gofmt`. Comments say why. Wrap errors with `%w`.
- **Shell:** POSIX `sh` unless the script already uses bash.
- **Man pages:** mdoc, clean under `mandoc -Tlint`. Lines under 80 bytes, a new
  line per sentence.
- **Prose:** short and plain, in present tense, naming settings, paths and
  commands exactly.
- **Commits:** a short summary line, a blank line, then what changed and why. An AI
  agent adds a `Co-Authored-By:` line naming itself.
