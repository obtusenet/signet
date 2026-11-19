# Signet design

How Signet fits together, and why it is built the way it is. The HTTP contract is in
`docs/API.md`, and the settings are in `signet-config.yaml(5)`.

## The idea

Signing in to a web application ends the same way whatever the method: the browser
holds a cookie that the application trusts. Signet does every sign-in method and
issues that one cookie. Applications, or the web server in front of them, ask Signet
what the cookie means. An application never sees a password, a key or a PIN.

```
browser ── web server ──┬── Signet ── users.csv (accounts)
                        │      ├───── RADIUS servers (other accounts' passwords, groups)
                        │      ├───── SQLite (sessions, keys, clients, pictures)
                        │      ├───── sendmail (PINs, links, notices)
                        │      └───── claims hook (roles, groups)
                        └── application (asks Signet: GET /session or POST /api/v1/validate)
```

The web server terminates TLS and routes Signet's paths to it. It reaches Signet by
HTTP on a port, by HTTP over a unix socket, or by FastCGI. FastCGI is there because
OpenBSD's httpd(8) speaks it and has no reverse proxy. `listen` says where Signet
listens, and `protocol` says how.

## Storage

- **Accounts in a CSV file:** address, password hash, algorithm, and the
  `locked`, `self_registered` and approval flags. An administrator can read and
  edit it with any tool, while the server runs.
  - An address is one plain `local@domain` and nothing else. Commas, quotes,
    angle brackets, parentheses, spaces, a second `@`, `|` and `/` are refused,
    because mailers split a recipient at commas (OpenSMTPD, sendmail and Postfix
    all do), and an application or hook could read any one address of a list.
  - Addresses match without regard to case. The form in the file is the
    account's, and every address that comes in is replaced by it before
    sessions, keys, codes or limits see it. A new account that differs from one
    in the file only in case is refused, and a file with two such rows does not
    load.
  - The server reloads the file when it changes, through `fsnotify` with polling
    as a fallback. It never holds a lock on the file.
  - A write takes a lock on the directory and replaces the file by rename, so
    `signet user-add` works while `serve` runs. Comment lines are kept.
- **Everything else in SQLite,** in WAL mode, so several instances can share one
  database: sessions, security keys, ceremony state and invites, TOTP keys, mail-link
  tokens, failed sign-in counts, API clients and pictures.
  - New databases are created `0600`. `secure_delete` is on.
- **Secrets at rest:**
  - Session tokens and mail-link tokens are stored as hashes. Only the cookie or
    the link carries the token.
  - TOTP secrets are encrypted with a key derived from `cookie_secret`. A leaked
    database or backup is useless alone, and changing the secret makes every TOTP
    key unreadable.
  - API keys are stored as SHA-256 hashes and shown once.

A RADIUS backend for accounts is planned and not built.

## Sessions and the cookie

- A session is a random 32-byte token, in a cookie that carries it with a signature,
  the SHA-256 of `cookie_secret` and the token (not an HMAC: the token must also
  be in the session store, so the signature is a first filter). The cookie is `HttpOnly`, `SameSite=Strict` and `Secure` by default.
- `GET /session` answers with the account, the sign-in method, the times and the
  claims, and sets `Remote-User`, `Remote-Email` and `Remote-Avatar`. That makes it
  a forward-auth endpoint for Caddy, nginx and httpd.
- `POST /api/v1/validate` does the same for a backend that holds the cookie, with
  an API key per application and CORS limited to that application's origins.
- `?claims=refresh` runs the claims hook again for a session.
- A session lasts `cookie_max_age` from sign-in, and with `session_idle_timeout`
  ends sooner when nothing reads it. A use is written at most once a minute, so a
  busy session costs few writes, and the limit is kept to within that.
- Removing a security key, using a recovery link and deleting an account end every
  session of the account. Changing a password ends the account's other sessions.
  Editing `users.csv` by hand, or setting `locked`, stops new sign-ins but leaves
  existing sessions to expire. That is a deliberate choice.

## Sign-in methods and accounts

- Every method asks one policy, `auth.AccountPolicy`, whether the account may sign
  in: it exists, it is not `locked`, and it is not awaiting approval.
- **TOTP is a second step**, after a password or a mailed PIN, for an account that
  has a key.
  - A security key signs in alone. The mailbox alone must not be enough, so
    recovery by mail does not skip the code either.
  - Each code works once (RFC 6238 §5.2). Ten recovery codes, shown once, cover a
    lost authenticator.
- **`second_factor: required`** makes every sign-in prove two factors; `optional`,
  the default, leaves it to each account.
  - A key must verify its user (PIN or fingerprint) when added and at each
    sign-in, and is then two factors alone.
  - A password or PIN is followed by a TOTP code, or after a password, a mailed
    PIN when `second_factor_methods` lists `email_pin`. The mailbox is weak as a
    second factor, since recovery is by mail too, so `serve` warns.
  - An account with no app and no key adds one before its sign-in finishes. The
    step token, like the code step's, allows nothing else. Whoever has only the
    password can do this, so `webauthn-invite` before the first sign-in is the
    stronger way to provision.
  - The account page keeps an account's last app or key.
- **Security keys** need a signed-in session or a one-time invite to enroll. The
  address is never taken from the request.
  - An unknown, locked or keyless address still gets sign-in options, with decoy
    keys derived from `cookie_secret`, so the answer does not show which addresses
    have accounts.
- **Links in mail** (recovery, registration) always come from `public_url`, never
  from the request: a forged `Host` header would otherwise put an attacker's site in
  a real message.
  - The token travels in the URL fragment, so it reaches no access log.
  - Opening the link spends nothing, because mail scanners fetch links. Submitting
    the page does.
  - Tokens are single use, and a newer one replaces the older.
- **Registration** takes only an address and mails a link. The account is created
  when the link is used, with the password chosen there, so an unproved address
  never becomes an account. Recovery and registration answer every address alike.
- **Changing the account** (password, keys, TOTP, picture) needs a sign-in within
  `account_reauth_window`. Every change except a picture mails the owner a notice.

## RADIUS accounts

- **Signet is a RADIUS client** (RFC 2865, UDP; no RadSec yet), for passwords of names
  `users.csv` does not have. A name the file has, in any state, never goes to RADIUS,
  so local accounts work while the servers are down and their passwords stay here.
- **A local account shadows a RADIUS one of the same name.** When RADIUS names are
  mail addresses, an account added to `users.csv` for one, by `user-add` or by
  self-registration from whoever reads that mailbox, signs in on its own password and
  never reaches the server. This follows from asking `users.csv` first, and is left
  to the administrator: keep the names apart, or keep self-registration off.
- **`signet session-revoke`** ends a RADIUS account's sessions here. The server is not
  told: RADIUS has no request by which a client ends a session on the server.
- **The client is Signet's own**, on the standard library and `x/crypto/md4`: PAP
  (§5.2) and MS-CHAPv2 (RFC 2759), several servers in order, retries that keep the
  identifier and authenticator.
- **Replies are proved:** the Response Authenticator always, `Message-Authenticator`
  (RFC 3579 §3.2) in every request and, by default, required in every reply against
  forged replies (CVE-2024-3596). An MS-CHAPv2 Accept must carry the server's proof
  that it knew the password (`MS-CHAP2-Success`, RFC 2759 §8.7).
- **One application per instance**, named to the servers as `NAS-Identifier`. One
  session serves every application behind an instance, so per-application answers
  need per-application instances, as `base_path` already allows.
- **Groups are claims.** `radius.group_attributes` (`Filter-Id` by default; there is
  no standard group attribute) become `{"groups":[...]}`, or the claims hook gets the
  whole reply and answers the claims. The reply is kept with the session, so a claims
  refresh sees what the sign-in saw: Signet cannot ask again without the password.
- **The server's decision is final.** A RADIUS account has no password, mailed PIN,
  recovery or key here, since each would sign it in without the server and without
  groups.
- **TOTP is a RADIUS account's only second factor.** It may add, use and remove an
  authenticator app on `/account`, and nothing else, whatever
  `second_factor_methods` lists; local accounts keep every enabled method. A key
  as a step after a RADIUS password was considered and not taken. Under
  `second_factor: required` a RADIUS account without an app adds one at sign-in, so
  `totp` must be enabled and listed, or the account is refused. A server's
  Access-Challenge is the server's own factor, which Signet can neither see nor
  manage, and does not satisfy `second_factor`.
- **Access-Challenge** becomes a step, like the code step: the server's prompt, one
  answer per challenge, sent with `State` to the server that asked.
- **No answer fails closed** with `503`, and is not counted against the account.
- **The server may set the session's limits.** `Session-Timeout` and `Idle-Timeout`
  in an Accept replace `cookie_max_age` and `session_idle_timeout` for that session,
  up to ceilings that default to those same values: a server can shorten a session,
  and lengthen one only as far as the administrator allows. Signet does not send its
  own limits, since RFC 2865 §5.44 forbids both attributes in a request.
- PAP over UDP and MS-CHAPv2 are weak against someone on the network path. Keep
  RADIUS on a trusted network, or under IPsec.

## Limits and lockout

- **Rate limits** are sliding windows kept in memory, per process: failed passwords
  per address and per client address, PIN mails, link mails, security-key ceremonies,
  registrations, pictures, API calls and claims refreshes. Every refusal is logged
  at warning level.
  - Instances that share one `users.csv` and database count on their own, so _n_ of
    them allow _n_ times each limit, and a restart or reload starts the counts over.
    This is a decision (2026-11-13): the lockout below is the shared, lasting limit.
  - A password, PIN or code attempt counts before it is checked, and attempts
    on one account are checked one at a time, within one process. Guesses sent together therefore get
    no more tries than guesses sent one after another, and the lockout sees each
    failure before the next check.
  - At most as many password hashes run at once as there are CPUs, and never
    more than 8. The rest wait. An argon2id hash holds its memory (64 MiB by
    default) while it runs, so this bounds what a burst of sign-ins can use.
  - Instances that share a database each allow the full count, and a restart
    clears them. One instance is the normal deployment.
- **Lockout** is a persistent count in SQLite of consecutive failed passwords, PINs
  and codes on an existing account. At 100 by default (NIST SP 800-63B §5.2.2),
  those methods are refused for a while and the owner is mailed.
  - A security key still signs in, so knowing someone's address is not enough to
    lock them out.
  - A locked attempt is answered like a wrong password.
- **Client addresses** come from `X-Forwarded-For` only when the peer is in
  `trusted_proxies`, read from the right. FastCGI needs nothing, because the web
  server reports the client itself.

## Requests

- Each JSON endpoint answers a failure with a status code that describes it and a
  JSON body. Clients branch on the status.
- A browser's state-changing request from another origin answers 403, decided by
  `Sec-Fetch-Site` and `Origin` (Go's `http.CrossOriginProtection`), not by tokens.
  `/api/v1/validate` is exempt, because its key and allowed origins govern it.
- Bodies stop at 128 KiB, headers at 32 KiB, and log messages at one line of 8 KiB.
  Every response carries `X-Frame-Options: DENY` and `X-Content-Type-Options: nosniff`.
- `POST /login` serves plain forms with a redirect, and `fetch()` with JSON, by
  `Accept`. The pages work without JavaScript, apart from security keys.
- After a sign-in, Signet returns to the posted `referrer`, then `?referrer=`, then
  the `Referer` header, then `/account`. Another host is allowed only when listed in
  `allowed_redirect_hosts`.

## Several instances

- Instances may share a database and accounts. They must then share
  `cookie_secret`, and the cookie works on all of them.
- Separate applications with separate users get an instance each, with its own
  files, hook and approval setting, served under a `base_path` on the same host.
  - Everything Signet names carries the base: redirects, pages, mail links and
    `webauthn.js`.
  - The cookie's path stays `/`, so `cookie_name` must differ between instances.

## Running

- `SIGHUP` reads the configuration and templates again. If they are good, a new
  server takes over on the same listener; if not, the running one stays and the log
  says why. Settings that cannot change that way are named in the log.
- Logging:
  - Under systemd, to stdout and stderr for the journal.
  - Elsewhere, to syslog or stdout, as `log_syslog` says.
  - Fatal errors go to both.
- Mail is handed to the system's `sendmail`, as `mail(1)` does. Signet speaks no
  mail protocol, and where mail may go is the mail system's policy.
- The web files (templates and `webauthn.js`) are installed by
  `deploy/install-web.sh`, which every package and the Linux installer use. It
  replaces a file only if it still matches what was last installed, so an
  administrator's edits survive upgrades, and it reports what it kept.
- The binary's default configuration path is set at build time
  (`-X main.defaultConfig`). The packages use their system path, and a plain `make`
  uses `config.yaml`.

## Not built

- `log_level`: every level is logged.
- One session per account (`multi_device: disabled`).
- RadSec (RADIUS over TLS, RFC 6614).
- Rate limits shared between instances.
