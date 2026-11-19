# Signet HTTP API

Version: 0.14.2  
Audience: a developer or an automated agent writing a client, a backend
integration, or a reverse-proxy configuration against signet.

This file is the complete, self-contained contract. The same material in
man-page form is `signet-api(7)`.

---

## 0. TL;DR

- Signet is an HTTP authentication service. It issues a signed cookie named
  `signetid` and can describe the session behind it.
- Sign in: `POST /login` (form-encoded) with `email`, `password` and an optional
  `referrer`. Send `Accept: application/json` to receive JSON instead of a 302.
  With RADIUS on, `email` may be a plain name, which RADIUS servers check
  (section 4.7e); such an account's `email` in `/session` is empty.
- Ask about a session: `GET /session` → `200 {"valid":true,...}` or
  `401 {"valid":false,...}`.
- Sign out: `GET` or `POST /logout` → deletes the session, expires the cookie.
- A backend validates a cookie it received from a browser with
  `POST /api/v1/validate` plus an `X-API-Key` header.
- Everything else (`/health`, `/static/js/webauthn.js`, `/recover`,
  `/email-pin/*`, `/webauthn/*`) is listed below.

---

## 1. Conventions

| Item | Value |
|---|---|
| Default base URL | `http://127.0.0.1:8080` (config `listen`) |
| Transports | TCP, HTTP over a unix socket, or FastCGI (`protocol: fastcgi`) — the `listen` address always says where, `protocol` says how; same HTTP contract over either |
| Production shape | behind Caddy/nginx on `https://app.example.com` |
| Paths | every path here is from the root. With `base_path` (e.g. `/comments-auth`) each is under it, `/comments-auth/login` and so on, and everything outside answers `404`. Redirects and links name the base, the default return after a sign-in (`/comments-auth/account`) included |
| Addresses | one plain `local@domain`, matched without regard to case. Lists, names, quotes, comments, `|` and `/` are refused as not an address, before anything else looks at them. Replies, sessions and `Remote-Email` give the account's own form |
| Request bodies | `application/json`, except the HTML forms (`/login`, `/recover`, `/register`) |
| Response bodies | JSON on API endpoints; HTML on pages; `text/plain` for un-negotiated errors |
| Session cookie | `signetid` (config `cookie_name`; instances on one host need different names), `HttpOnly`, `SameSite=Strict`, `Path=/`, `Secure` unless `cookie_secure: false` |
| JSON success | `{"success": true, ...}` (login/PIN) or a documented object (`/session`) |
| JSON failure | `{"success": false, "error": "..."}` or `{"valid": false, "error": "..."}`, with the HTTP status that describes the failure |
| Auth | the `signetid` cookie; no bearer tokens |
| API auth | `X-API-Key` (registered client) for `/api/v1/validate` only |
| Cross-origin | a browser's request other than `GET`, `HEAD` or `OPTIONS` from another origin answers `403 {"success":false,"error":"Cross-origin request refused"}`, unless its host is in `allowed_redirect_hosts`. `Sec-Fetch-Site` decides; without it, `Origin` must match `Host`, so a web server in front must pass `Host` on unchanged. Clients that send neither are not affected. `/api/v1/validate` is exempt: its key and `allowed_origins` govern it |
| Tracing | every request logs `http request method=... uri=... status=... bytes=... duration=... remote=...` |

Every JSON endpoint signals failure with the HTTP status code, so a client can
branch on the status alone: `400` bad request, `401` not authenticated or bad
session/API key, `403` forbidden, `404` unknown path, `405` wrong method,
`413` a body over 128 KiB, `429` rate limited, `500` internal, `503` method
disabled. Only the HTML form paths (`GET /login`, a non-JSON `POST /login`,
`GET /recover`) answer with HTML or plain text.

Every response carries `X-Frame-Options: DENY` and `X-Content-Type-Options: nosniff`. What is not
a valid address is refused before anything else looks at it: `401` on `POST /login` and WebAuthn
sign-in, `400` on the email PIN calls.

`Content negotiation`: `POST /login` returns JSON when the request has
`Accept: application/json` **or** `X-Requested-With: XMLHttpRequest`;
otherwise it returns a `302`. Do not send JSON headers if you want a redirect.

`Client address`: the connection's address, used by the rate limits and the request log.
From a peer listed in `trusted_proxies` it is the rightmost `X-Forwarded-For` entry that
is not a trusted proxy; from any other peer the header is ignored. Over FastCGI the web
server reports the client directly.

`Rate limiting`: every refusal is logged as a warning, e.g.
`WARN: rate limited: validation API for client "scribe" from 192.0.2.9`.
The endpoints and their answers are unchanged by the log line.

---

## 2. Session model

A sign-in creates a row in the session store and sets:

```
Set-Cookie: signetid=<token>:<signature>; Path=/; Max-Age=86400; HttpOnly; SameSite=Strict
```

- `token` is 32 random bytes as 64 hex characters. `signature` is the SHA-256
  of `cookie_secret` followed by the token, in hex. It is not an HMAC, and needs
  none: the token is also looked up in the session store, so a signature alone
  admits nobody. Sessions survive a restart, and instances sharing a
  database accept each other's cookies when they use the same secret.
- The cookie is opaque to clients: store it, send it back, never parse it.
- `Max-Age` comes from `cookie_max_age` (seconds), or for a RADIUS account from
  the reply's `Session-Timeout` (section 4.7e).
- With `session_idle_timeout` set, a session that no request has read for that
  long ends: `/session` answers `{"valid":false,"error":"session expired"}`.
  `GET /session`, `POST /api/v1/validate` and the account page each count as a
  use, written down at most once a minute.
- Logout deletes the row, so replaying an old cookie value fails with
  `{"valid":false,"error":"session not found"}`.
- `claims` is a JSON object produced by the optional external claims hook at
  sign-in; `{}` when no hook is configured.

---

## 3. Endpoint index

| Method | Path | Auth | Success | Purpose |
|---|---|---|---|---|
| GET | `/login` | no | 200 HTML | login page |
| POST | `/login` | no | 200 JSON or 302 | password sign-in |
| GET | `/` | cookie | 200 HTML / 302 | who am I page |
| GET | `/session` | cookie | 200 JSON | inspect session |
| GET, POST | `/logout` | cookie (optional) | 200 JSON or 303 | sign out |
| GET | `/register` | no | 200 HTML | registration page |
| POST | `/register` | no | 200 / 302 / 400 / 403 / 409 / 429 | ask for a registration link, check one, use one, or register at once |
| GET | `/account` | cookie | 200 HTML / 302 | account page |
| POST | `/account` | cookie | 200 / 400 / 401 / 403 / 429 | change the account |
| GET | `/avatar/{id}` | no | 200 image | an account's picture, with `avatars` on |
| GET | `/recover` | no | 200 HTML | recovery page |
| POST | `/recover` | no | 200 / 400 / 403 | ask for a recovery link, check one, or use one |
| POST | `/email-pin/send` | no | 200 JSON | send a PIN |
| POST | `/email-pin/verify` | no | 200 JSON + cookie | verify a PIN |
| GET | `/webauthn/invite` | invite | 200 JSON | can this invite still be used |
| POST | `/webauthn/register/start` | cookie or invite | 200 JSON | begin registration |
| POST | `/webauthn/register/finish?ceremony=&label=` | cookie or invite | 200 JSON | finish registration |
| POST | `/webauthn/authenticate/start?email=` | no | 200 JSON | begin assertion |
| POST | `/webauthn/authenticate/finish?email=&ceremony=` | no | 200 JSON + cookie | finish assertion |
| GET | `/webauthn/credentials` | cookie | 200 JSON | list your credentials |
| DELETE | `/webauthn/credentials/{id}` | cookie | 200 JSON + cookie expired | delete your credential, ending all your sessions |
| GET | `/webauthn/keys` | no | 200 HTML | security-key page |
| POST | `/api/v1/validate` | `X-API-Key` + cookie | 200 JSON | server-side validation by a registered app |
| GET | `/health` | no | 200 JSON | liveness |
| GET | `/static/js/webauthn.js` | no | 200 JS | browser WebAuthn client |

`/register` is described in section 4.7a.

---

## 4. Endpoints

### 4.1 `GET /login`

Renders `login.html`. Query parameter `referrer` is copied into a hidden form
field (and into `.Referrer`) so the POST can return the user to that location.
Encode it. Web servers cannot, so an unencoded value with a `?` of its own, such as
`?referrer=/page?x=1&y=2`, is taken whole and verbatim, to the end of the query.

- `200` `text/html`
- `500` if the template cannot be rendered

### 4.2 `POST /login`

Request (form-encoded):

```
email=a@example.com&password=secret&referrer=%2Fdashboard
```

`referrer` is optional. The password method is selected implicitly. With
`radius.enabled`, `email` may also be a plain name: a name the CSV file lacks is
checked by the RADIUS servers, exactly as typed (section 4.7e).

Response with `Accept: application/json`:

```json
{"success": true, "redirect": "/dashboard"}
```

plus `Set-Cookie`. Without JSON negotiation: `302` with `Location` set to the
same target and the same cookie.

Errors:

| Status | Body (JSON mode) | Cause |
|---|---|---|
| 400 | `{"success":false,"error":"email and password are required"}` | missing field |
| 401 | `{"success":false,"error":"Invalid email or password"}` | anything that is not a valid address (or, with RADIUS on, a valid name); bad credentials; unknown, locked or unapproved account; an Access-Reject; rate limited; or locked by `account_lockout_threshold` failures in a row, even with the right password |
| 403 | `{"success":false,"error":"Password sign-in is disabled"}` | `auth_methods.password` is disabled |
| 403 | `{"success":false,"error":"Sign-in refused"}` | claims hook failed or denied under `on_failure: fail-closed` |
| 500 | `text/plain` | template failure |
| 503 | `{"success":false,"error":"Sign-in is unavailable. Try again later."}` | no RADIUS server gave a valid reply, for a name the CSV file lacks |

Redirect target precedence: posted `referrer` → `?referrer=` → HTTP `Referer`
→ `/account`. This instance's `/login`, `/register`, `/recover` and `/logout` are never a
target, so a sign-in after registering does not land back on the registration page. Paths beginning with `/` (but not `//`) and absolute URLs whose host
equals the request host are accepted. A path with a `.` or `..` segment, encoded
or not, is refused: a browser resolves `/.//evil.example/` to `//evil.example/`,
another host. An absolute URL on a different host is
honoured only when its hostname is listed in `allowed_redirect_hosts`
(see signet-config.yaml(5)); it is then returned as a full URL, in both the
302 `Location` and the JSON `redirect` field. Hostnames, IPv4 addresses and
IPv6 addresses (full or minified, bracketed to carry a port) are all valid
entries; IP literals are compared canonically. Anything else falls back to `/account`.

### 4.3 `GET /`

- valid cookie → `200` HTML containing the signed-in address
- otherwise → `302` to `/login`
- any other path under `/` → `404`

### 4.4 `GET /session`

Requires the cookie. `200`:

```json
{
  "valid": true,
  "user": "a@example.com",
  "email": "a@example.com",
  "method": "password",
  "created_at": "2026-10-23T00:45:42Z",
  "expires_at": "2026-10-24T00:45:42Z",
  "claims": {},
  "claims_refreshed": false,
  "avatar": null
}
```

`method` is one of `password`, `email_pin`, `webauthn`, `radius`, or one of
them with the second step after a `+` (`password+totp`). Also sets the response
header `Remote-User` to the account, and `Remote-Email` to it when it is a mail
address. A RADIUS account named `jdoe` has `"user":"jdoe"`, `"email":""` and no
`Remote-Email`.

`avatar` is the account's picture (section 4.7d): `public_url`, then `base_path`, then
`/avatar/{id}`, or only the path when `public_url` is not set. It is `null` when the account has
none or `avatars` is off, and choosing what to show then is the application's. When it is set,
the response also has a `Remote-Avatar` header with the same value.

`401`:

```json
{"valid": false, "error": "session not found"}
```

Other `error` values: `cookie not found: http: named cookie not present`,
`invalid cookie signature`, `invalid cookie format`, `session expired`.

`?claims=refresh` re-runs the claims hook and returns the new claims with
`"claims_refreshed": true`; without a hook it is a no-op. For a RADIUS account
the hook is given the reply stored at sign-in. Each run starts a
program, so an account gets `claims_hook.refresh_rate_limit` runs in
`claims_hook.refresh_rate_window` seconds (6 in 60 by default). Past that the
stored claims are answered with `"claims_refreshed": false`, as when the hook
fails, and the refusal is logged.

`405` for any method other than GET or HEAD.

### 4.5 `GET|POST /logout`

Deletes the session row and sends `Set-Cookie: signetid=; Path=/; Max-Age=0`.

- JSON negotiation → `200 {"success": true}`
- otherwise → `303` to `/login`
- `405` for other methods
- no session present → same success response (idempotent)

### 4.6 `GET /recover`

Renders `recover.html` with `.RecoveryEnabled`, `.Error`, `.Message`, `.Email`, `.Token`, `.Done`.
`200`. Recovery is on when `password_recovery` is enabled, `public_url` is set and
`auth_methods.password` is not disabled.

A mailed link is `<public_url><base_path>/recover#token=<token>`, where `base_path` is empty at the
root. The token stays in the fragment, so it does not reach access logs. The page's script removes it
from the address bar, checks it, and only then asks for a password; a link pasted into a tab already on
the page, where only the fragment changes, is checked the same way. Opening a link spends nothing.

### 4.7 `POST /recover`

Form-encoded, and it does one of three things. With `Accept: application/json` the reply is
`{"success":true,"message":"..."}` or `{"success":false,"error":"..."}`, otherwise the page.
Any of them answers `403` while recovery is off.

| Fields | Status | Meaning |
|---|---|---|
| `email` | 200 | the same text for every address. A link is mailed if the account may sign in. A limit reached changes nothing in the reply |
| `email` empty | 400 | address missing |
| `token` | 200 / 400 | the link is live / it is not. Nothing is spent |
| `token`, `password` | 200 | password changed, every session of the account ended, cookie expired, notice mailed |
| `token`, `password` | 400 | dead link, or a password under 8 characters, which leaves the link usable |

A token works once, a newer one ends the older, and it is refused if the account has since been
locked or removed. An account with no password can set one this way.

### 4.7a `GET` and `POST /register`

`GET` renders `register.html` with `.RegistrationEnabled`, `.VerificationRequired`, `.Error`,
`.Message`, `.Email`, `.Token`, `.Done`. `POST` answers `403` while registration is off: when
`self_registration` is not enabled, or `email_verification` is `required` and `public_url` is not set.

With `email_verification: required`, the default, the account is created only from a link in mail,
`<public_url><base_path>/register#token=<token>`, with the password chosen there. An address that has not proved
itself is never in the CSV file. JSON replies as for `/recover`.

| Fields | Status | Meaning |
|---|---|---|
| `email` | 200 | the same text for every address. It mails a link, or tells the owner of an account that it exists. A `password` here is ignored |
| `email` empty | 400 | address missing |
| `token` | 200 / 400 | the link is live / it is not. Nothing is spent |
| `token`, `password` | 200 | account created, with `self_registered`, and `approved` unless `self_registration_approval` is `required` |
| `token`, `password` | 400 | dead link, an address that now has an account, or a password under 8 characters, which leaves the link usable |

With `email_verification: disabled`, `email` and `password` create the account at once and answer
`302` to `/login`; `400` for bad input, `409` when the address has an account, which shows who has
one, and `429` over `register_rate_limit` per requester.

### 4.7b `GET` and `POST /account`

`GET` renders `account.html` for a signed-in user (`.Email`, `.Fresh`, `.PasswordEnabled`,
`.HasPassword`, `.WebAuthnEnabled`, and with avatars `.AvatarsEnabled`, `.Avatar`, `.AvatarSize`), or answers `302` to `/login?referrer=/account`.

`POST` is JSON. `{"action":"password","current":"...","new":"..."}` changes the password, ends the
account's other sessions and mails a notice. `current` is empty for an account with no password.

| Status | Cause |
|---|---|
| 200 | `{"success":true,"message":"..."}` |
| 400 | wrong current password, which counts against the login limits, a short new one, or an unknown action |
| 401 | no session |
| 403 | the sign-in is older than `account_reauth_window`; sign in again. Or the account may not sign in |

Adding or removing a security key also answers `403` when the sign-in is not recent, unless an invite
is used. Each change mails a notice.

With `auth_methods.totp` enabled, these actions manage authenticator apps, under the same rules:

| Action | Fields | Reply |
|---|---|---|
| `totp-begin` | `label` | `{"success":true,"secret":"...","url":"otpauth://...","qr":"data:image/png;base64,..."}`. Nothing is saved yet |
| `totp-finish` | `code` | `{"success":true}`, with `recovery_codes` for the account's first key, shown only this once. `400` for a wrong code or an expired setup |
| `totp-remove` | `id` | `{"success":true}`, and the account's other sessions end. `404` for a key it does not have |
| `totp-codes` | | `{"success":true,"recovery_codes":[...]}`, replacing the old ones |

With `avatars` enabled, under the same rule of a recent sign-in, and with no notice by mail:

| Action | Fields | Reply |
|---|---|---|
| `avatar-set` | `image`: a PNG or JPEG, base64, exactly `avatar_size` pixels square | `{"success":true,"message":"...","avatar":"<base_path>/avatar/<id>"}`. `400` for another size or format, `413` past the 128 KiB body limit, `429` past `avatar_rate_limit` |
| `avatar-remove` | | `{"success":true,"message":"..."}`, whether or not there was one |

With `avatars` off, both answer `403`.

### 4.7d `GET /avatar/{id}`

An account's picture, to anyone: `{id}` is 32 lowercase hex digits, random and new with every
upload, so it says nothing about the account. `200` with `Content-Type: image/png` or `image/jpeg`,
`Cache-Control: public, max-age=31536000, immutable`, `Content-Security-Policy: default-src 'none'`
and `Cross-Origin-Resource-Policy: cross-origin`. An id that is replaced, removed or never existed
answers `404`. The route exists only while `avatars` is enabled.

The image is never served as uploaded: signet checks its size from the header, decodes it and
encodes it again, which drops metadata such as a photo's position. The account page crops and
scales a chosen file in the browser, so any image the browser can read will do there.
### 4.7c The code step of a sign-in

For an account with a TOTP key, a right password or PIN starts no session. A security key signs in
alone. `POST /login` answers the page showing its code form, or with `Accept: application/json`
`{"success":false,"totp_required":true,"step":"code","pending":"..."}`, as `POST /email-pin/verify`
does.

`POST /login` with form fields `pending` and `code`, which may be a recovery code, answers `302` to
the `referrer` field with the session cookie, or `401` with the page, which says whether a recovery
code or an app code was refused. A code works once (RFC 6238 §5.2). Five wrong ones per address in five minutes stop further tries, and `pending` lasts five
minutes. The session's `method` says what was used: `password+totp`, `email_pin+totp`,
`password+recovery-code`.

Recovery by mail does not skip this: a new password still needs a code at the next sign-in. Someone
who has lost their authenticator and recovery codes needs `signet user-delete-totp`.

### 4.7d Other second steps, with `second_factor: required`

With `second_factor: required` every sign-in by password or PIN takes a second step, and the JSON
reply names it in `step`: `"code"` (above; `totp_required` is true only for it), `"mail"` or
`"enrol"`. A security key must verify its user (`userVerification: "required"`) and signs in alone.

- **`"mail"`**, after a password when `second_factor_methods` lists `email_pin`: a PIN is mailed,
  and `POST /login` with `pending` and `code` set to the PIN answers `302` with the session
  (`method` `password+email_pin`) or `401` with the page. A wrong PIN counts toward the lockout;
  after three the step ends. It lasts ten minutes.
- **`"enrol"`**, for an account with no authenticator app and no key: `POST /login` with `pending`
  and `action`:
  - no `action`: the page with the choices (`.EnrolTOTP`, `.EnrolKey`);
  - `totp-begin`: the page with a new app key, its secret and QR code;
  - `totp-finish` and `code`: `200`, the session cookie, and the page showing the recovery codes
    once (`method` `password+totp` or `email_pin+totp`); `401` for a wrong code;
  - `key`: `303` to `/webauthn/keys#invite=<token>`, a one-time invite for the account. The step
    ends; once added, the key signs in.

  The step lasts fifteen minutes.
- An account whose only second factor is a key gets `403`
  `{"success":false,"error":"This account signs in with its security key."}` for a right password
  or PIN, and one with none it may add gets `403` with another message.

The account page refuses with `409` to remove an account's last app or key, unless
`second_factor_methods` lists `email_pin`.

A RADIUS account (section 4.7e) takes only `"code"` or `"enrol"`, and at `"enrol"` only an app:
`.EnrolKey` is false and `action=key` answers `403`.

### 4.7e RADIUS accounts

With `radius.enabled`, a password for a name the CSV file does not have is checked by RADIUS servers
(signet-config.yaml(5)). A name the file has never goes to them, so a local account shadows a
RADIUS one of the same name, including one self-registered for an address that is also a RADIUS
name. `signet session-revoke <name>` ends a RADIUS account's sessions.

- **Access-Accept**: as a password. The session's `method` is `radius`, and its `claims` are
  `{"groups":[...]}` from `radius.group_attributes`, or the claims hook's answer (signet-hooks(5)).
  An app's code may follow (`radius+totp`). A `Session-Timeout` sets the session's lifetime and
  the cookie's `Max-Age`, and an `Idle-Timeout` its idle limit, each up to
  `radius.max_session_timeout` and `radius.max_idle_timeout` (by default `cookie_max_age` and
  `session_idle_timeout`, so a server can shorten but not lengthen a session until they are
  raised). Signet sends neither: RFC 2865 §5.44 forbids them in an Access-Request.
- **Access-Challenge**: no session. JSON gets
  `{"success":false,"step":"radius","pending":"...","message":"<the server's Reply-Message>"}`;
  a form gets the page asking for it. `POST /login` with `pending` and `code` set to the answer
  sends it to the server that asked, with its `State`. The step is spent by that one answer, lasts
  five minutes, and a sign-in answers at most three challenges.
- **Access-Reject**: `401`, counted as a failed sign-in.
- **No valid reply** from any server: `503`. Not counted against the account.

A RADIUS account has no password, PIN, recovery, registration or security key here: those answer as
for an unknown address. `/account` shows its apps and picture, and refuses a password change with
`403`.

### 4.8 `POST /email-pin/send`

`503` when `auth_methods.email_pin` is not enabled.

Request:

```json
{"email": "a@example.com"}
```

| Status | Body |
|---|---|
| 200 | `{"success":true,"message":"PIN sent to your email"}` |
| 400 | `{"success":false,"error":"Invalid request body"}` or `Email is required` |
| 429 | `{"success":false,"error":"Rate limit exceeded"}`, per requester or per address |
| 500 | `{"success":false,"error":"Internal server error"}` |

The 200 is the same for every address. No mail goes to an unknown account, one
that may not sign in, or one locked out after wrong guesses, and a message the mail
system refuses also answers 200, with the refusal in the log. The 500 is an internal
error, such as the database being unavailable. Only the newest PIN
for an address is valid.

### 4.9 `POST /email-pin/verify`

`503` when the method is disabled.

Request:

```json
{"email": "a@example.com", "pin": "123456"}
```

| Status | Body |
|---|---|
| 200 | `{"success":true,"message":"PIN verified successfully"}` + session cookie |
| 400 | `{"success":false,"error":"Email and PIN are required"}` or `Invalid or expired PIN` |
| 403 | `{"success":false,"error":"Sign-in refused"}`: claims hook, `fail-closed` |
| 429 | `{"success":false,"error":"Rate limit exceeded"}` |
| 500 | `{"success":false,"error":"Internal server error"}` |

Three wrong guesses against an address lock PIN sign-in for it for 30 minutes,
answered as `Invalid or expired PIN`, whichever client address made them. The
account's other sign-in methods are unaffected.

The PIN is single use. On success the browser is signed in (session `method`
is `email_pin`) and the login page redirects to the referrer.

### 4.10 WebAuthn

Bodies follow the WebAuthn Level 2 JSON encoding (`PublicKeyCredential`,
`AttestationResponse`, `AssertionResponse`), with binary fields base64url
encoded. Each `start` returns a `ceremony` ID that the matching `finish` presents
once; it expires after five minutes.

Enrollment acts on the account of the signed-in session, or of the invite in the
`X-Signet-Invite` header (`signet webauthn-invite`). An address in the request is
ignored, so nobody can add a key to another account.

| Call | Identity | Success |
|---|---|---|
| `GET /webauthn/invite` | invite in `X-Signet-Invite`; spends nothing | `{"success":true}`; `400` without one, `401` used or expired |
| `POST /webauthn/register/start` | session or invite | `{"success":true,"options":{...},"ceremony":"..."}` |
| `POST /webauthn/register/finish?ceremony=&label=` | session or invite; body is the registration response | `{"success":true,"credential":{...}}`, spends an invite |
| `POST /webauthn/authenticate/start?email=` | none | `{"success":true,"options":{...},"ceremony":"..."}` |
| `POST /webauthn/authenticate/finish?email=&ceremony=` | none; body is the assertion response | `{"success":true}` + session cookie |
| `GET /webauthn/credentials` | session | `{"success":true,"user":"...","credentials":[...]}` |
| `DELETE /webauthn/credentials/{id}` | session, own credential | `{"success":true,"signed_out":true}`; every session of the account ends and the cookie is expired |
| `GET /webauthn/keys` | none | 200 HTML: the security-key page |

Failures are `{"success":false,"error":"..."}`:

| Status | When |
|---|---|
| 400 | missing `email`; label over 64 bytes; registration failed verification |
| 401 | enrollment or credential call without a session or valid invite; login cannot proceed |
| 403 | enrollment on an account that may not sign in; login refused by a `fail-closed` claims hook |
| 404 | `DELETE` of a credential that is not the caller's |
| 405 | wrong method |
| 500 | internal error |

`POST /webauthn/authenticate/start` answers `200` with options for any valid address, so the reply
does not show which accounts have a key. An address that cannot sign in with one, because it is
unknown, locked or has no key, is offered invented keys that stay the same for that address, and
`finish` fails. Every login failure has the same body. A signature counter that fails to increase refuses the
login as a possible cloned authenticator (WebAuthn L2 §6.1.1).

An invite link is `<origin>/webauthn/keys#invite=<token>`. The token stays in the
fragment and a request header, so it does not reach access logs.

WebAuthn requires `webauthn_origins` to contain the exact browser origin
(scheme, host and port) the page is served from, a secure context (HTTPS or
`localhost`), and an `webauthn_rpid` that is a domain name, not an IP address.

The start and finish calls count against `webauthn_rate_limit` per requester, never per
address. Over budget they answer `429 {"success":false,"error":"Rate limit exceeded"}`.

### 4.11 `POST /api/v1/validate`

Server-to-server cookie validation for a **registered application**.

Register the application once and keep the key it prints:

```sh
doas -u _signet signet client-add --config /etc/signet/config.yaml \
  --origins https://app.example.com scribe
# Client "scribe" registered.
# API key (shown once, store it now): sk_...
```

```
curl -X POST http://127.0.0.1:8080/api/v1/validate \
  -H 'X-API-Key: sk_...' \
  -H 'Cookie: signetid=<value>'
```

The session cookie may travel in the `Cookie` header or in the JSON body;
**the body wins when both are present**:

```json
{"cookie": "signetid=<value>"}
```

| Status | Body | Cause |
|---|---|---|
| 200 | `{"valid":true,"user":"a@example.com","method":"password","claims":{},"avatar":null}` | valid session; `avatar` as for `/session` |
| 400 | `{"valid":false,"error":"invalid request body"}` | malformed JSON |
| 401 | `{"valid":false,"error":"X-API-Key header required"}` | no key |
| 401 | `{"valid":false,"error":"invalid API key"}` | unknown or revoked key |
| 401 | `{"valid":false,"error":"no session cookie"}` | neither body nor header carried one |
| 401 | `{"valid":false,"error":"invalid cookie signature"}` | forged cookie |
| 401 | `{"valid":false,"error":"session not found"}` | expired or logged-out session |
| 403 | `{"valid":false,"error":"origin is not allowed"}` | CORS preflight from an unlisted origin |
| 405 | `{"valid":false,"error":"Method not allowed"}` | not POST or OPTIONS |
| 429 | `{"valid":false,"error":"rate limit exceeded"}` | over `api_rate_limit` per `api_rate_window`, counted per client |

CORS: when the request's `Origin` is listed in a client's `allowed_origins`,
responses carry the matching `Access-Control-Allow-Origin`, `-Credentials`,
`-Headers` (`X-API-Key, Content-Type`) and `-Methods` (`POST, OPTIONS`);
`OPTIONS` preflight answers `204`.

### 4.12 `GET /health`

`200 {"status":"ok"}`. No authentication; safe for a load balancer probe.

### 4.13 `GET /static/js/webauthn.js`

The browser helper used by the login page. `200` JavaScript when `static_dir`
is configured; `404` otherwise.

---

## 5. Status code catalog

| Code | Meaning in signet |
|---|---|
| 200 | success |
| 302 | login succeeded (form mode), or `/` without a session |
| 303 | logout without JSON negotiation |
| 400 | malformed request, missing field, bad/expired PIN, malformed validate body |
| 401 | bad credentials, rate-limited login, invalid/absent session, bad or unknown API key |
| 403 | recovery disabled, or a CORS preflight from an unlisted origin |
| 404 | unknown path |
| 405 | method not allowed on a known path |
| 429 | too many PIN requests, or validation calls over the client budget |
| 500 | internal error, template failure |
| 503 | auth method disabled (`/email-pin/*`), or no RADIUS server answered (`POST /login`) |

---

## 6. Recommended flows

### 6.1 Password sign-in from a browser page

```js
const res = await fetch('/login', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/x-www-form-urlencoded',
    'Accept': 'application/json',
  },
  body: new URLSearchParams({ email, password, referrer: location.pathname }),
});
const data = await res.json();      // {success:true, redirect:"/dashboard"}
if (data.success) location.href = data.redirect;
```

### 6.2 Backend validates the browser's cookie

```go
req, _ := http.NewRequest("POST", signetURL+"/api/v1/validate", nil)
req.Header.Set("X-API-Key", apiKey)   // from `signet client-add`
req.AddCookie(browserCookie)          // signetid
resp, _ := http.DefaultClient.Do(req)
// 200 {"valid":true,...}   or   401 {"valid":false,"error":...}
```

If the application holds the cookie value itself rather than a request, send it
in the body instead (it takes precedence over the header):

```go
body := strings.NewReader(`{"cookie": "` + cookieValue + `"}`)
req, _ := http.NewRequest("POST", signetURL+"/api/v1/validate", body)
req.Header.Set("Content-Type", "application/json")
req.Header.Set("X-API-Key", apiKey)
```

### 6.3 Reverse proxy forward-auth (Caddy)

```caddyfile
forward_auth 127.0.0.1:9090 {
	uri /session
	copy_headers Remote-User Remote-Email Remote-Avatar
	@unauthenticated status 401
	handle_response @unauthenticated {
		redir * /login 302
	}
}
```

`copy_headers` also removes a visitor's own copy of each header it names. Signet sends
`Remote-Avatar` only for an account with a picture, so a proxy that copies headers some other
way must clear the visitor's `Remote-User`, `Remote-Email` and `Remote-Avatar` itself (the nginx
examples do).

Then pass the identity upstream:

```caddyfile
reverse_proxy 127.0.0.1:8088 {
	header_up X-Forwarded-User {http.request.header.Remote-User}
}
```

`/login`, `/logout`, `/session`, `/recover`, `/register`, `/account`, `/webauthn/*`, `/email-pin/*` and
`/static/js/webauthn.js` must be routed to signet and **not** through
forward-auth, or the login page cannot be reached. With `base_path` they are all under it, so the one
prefix, passed on whole, is the only route needed (see `examples/web-servers/README.md`).

### 6.4 Sign-out

```js
await fetch('/logout', { method: 'POST', headers: { 'Accept': 'application/json' } });
```

---

## 7. Configuration that changes the API

| Key | Effect |
|---|---|
| `listen` | base URL |
| `cookie_name`, `cookie_domain`, `cookie_max_age` | cookie identity and lifetime |
| `session_idle_timeout` | seconds without a use before a session ends; 0, the default, never |
| `cookie_secure` | `Secure` attribute; keep `true` behind TLS |
| `auth_methods.{password,webauthn,email_pin}` | whether a method's endpoints exist (`email_pin` answers 503 when off; `webauthn` also needs `webauthn_rpid` and `webauthn_origins`) |
| `webauthn_origins` | exact origins allowed for WebAuthn |
| `login_address_limit`, `login_rate_limit`, `login_rate_window` | whether failed passwords are counted per address, and how many per window |
| `login_source_limit`, `login_source_rate_limit`, `login_source_rate_window` | whether failed passwords are counted per client address, and how many per window; a client over it is refused even with the right password |
| `email_rate_limit`, `email_rate_window` | PIN sends/verifies per window |
| `claims_hook.*` | whether `claims` is populated, and `?claims=refresh` does anything |
| `base_path` | the path every route is under; empty serves from the root |
| `password_recovery`, `public_url` | whether `/recover` offers the form; links in mail are `public_url`, then `base_path`, then the page, so `public_url` has no path when a base is set |
| `self_registration`, `email_verification` | whether `/register` works, and whether it needs a link in mail |
| `auth_methods.totp`, `totp_issuer` | whether an account with a key needs a code, and the name an app shows |
| `account_reauth_window` | seconds a sign-in counts as recent, for account changes |
| `recovery_link_ttl`, `registration_link_ttl` | seconds a link works |
| `mail_link_rate_limit`, `mail_link_rate_window`, `mail_link_source_rate_limit`, `mail_link_source_rate_window` | messages with a link, per address and per client address |
| `api_rate_limit`, `api_rate_window` | per-client budget for `/api/v1/validate` (0 disables) |
| `avatars`, `avatar_size`, `avatar_rate_limit`, `avatar_rate_window` | whether `/avatar/` and the picture actions exist, the side in pixels an upload must have, and uploads per account per window |
| `radius.*` | whether names the CSV file lacks are checked by RADIUS, and the `radius` step, `503` and `groups` claims that brings |

API clients live in the `api_clients` table and are managed with
`signet client-add`, `client-list` and `client-revoke`; only a hash of each key
is stored, so a key is shown exactly once.

---

## 8. Known limitations

1. A recovery link trusts the mailbox alone, with no second factor.
2. `email_verification` applies to self-registration only: `user-add` trusts its administrator.
3. The login rate limit answers with the same 401 as bad credentials, so a
   client cannot distinguish "wrong password" from "slow down". `/api/v1/validate`
   is different: over budget it answers `429`.
4. `POST /email-pin/send` answers 200 whether or not the message reached the mail
   system, so that it shows nothing about which accounts exist. A refusal is logged.
5. Removing an account from the CSV file by hand, or setting `locked`, stops new
   logins but leaves existing sessions valid until they expire.
   `signet user-delete` ends them.
6. `SIGHUP` reads the configuration and templates again, but settings such as
   the listen address need a restart; the log names them.

---

## 9. Verification recipe

```sh
BASE=http://127.0.0.1:9090

curl -s $BASE/health                                   # {"status":"ok"}
curl -s -o /dev/null -w '%{http_code}\n' $BASE/session # 401

rm -f jar
curl -s -c jar -H 'Accept: application/json' \
  -d 'email=test@localhost&password=letmeinnow&referrer=/dashboard' \
  $BASE/login                                          # {"redirect":"/dashboard","success":true}

curl -s -b jar $BASE/session                           # {"valid":true,...}
curl -s -b jar -X POST -H 'Accept: application/json' \
  $BASE/logout                                         # {"success":true}
curl -s -b jar $BASE/session                           # 401 {"valid":false,...}

# validation API: register a client, then check the cookie
KEY=$(signet client-add --config config.yaml probe | sed -n 's/.*: //p')
curl -s $BASE/api/v1/validate -H "X-API-Key: $KEY" \
  -H "Cookie: signetid=invalid:deadbeef"               # 401 {"valid":false,...}
signet client-revoke --config config.yaml probe
```
