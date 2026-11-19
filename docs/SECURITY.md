# Security policy

Signet is authentication software, so a flaw in it can expose every application
behind it. Please report a suspected vulnerability privately.

## Reporting

Use either:

- GitHub's private vulnerability reporting: **Report a vulnerability** on the
  [Security tab](https://github.com/obtusenet/signet/security);
- mail to **code@obtusenet.com** with "signet security" in the subject.

Include:

- the version (`signet version`) and how it is deployed: web server, transport
  (HTTP, socket or FastCGI), and which sign-in methods are on;
- what an attacker can do, and the steps or a test that shows it;
- whether you want to be credited, and how.

Don't open a public issue or pull request for a vulnerability until a fix is
released.

## What to expect

- An acknowledgement within 7 days.
- An assessment within 30 days: whether it is a vulnerability, how severe it is,
  and the plan for it.
- A fix in a new release. The release notes describe the problem, with credit if
  you want it, once the fix is out.

A coordinated disclosure date can be agreed. Without one, details are published
when the fix is released, or 90 days after the report, whichever is first.

## Supported versions

Only the latest release gets security fixes. Signet is pre-1.0 and has no long-term
branches.

## Go and its standard library

The Go that compiles Signet decides which standard-library fixes a binary has, and
a binary keeps the library it was built with.

- **Signet itself** is tested on two Go versions: the oldest it supports (the
  `go` line in `go.mod`) and the newest release, pinned in the `Makefile` as
  `GO_IMAGE`. `make test-go-current` and `make vuln-current` use the newest.
- **The Docker image** is built with that newest release, pinned by digest.
- **The OpenBSD, FreeBSD and Debian packages** are built with their operating
  system's Go, and get its fixes when the system updates its Go and the package is
  rebuilt. Until then, building Signet from source with a current Go is the way
  around it.
- `make vuln` checks a binary built here, and `make vuln-host HOST=user@host`
  checks the one a machine runs. `govulncheck` lists only the vulnerable functions
  the binary contains.

## In scope

- Signet's code, the shipped templates and `webauthn.js`, and the packaging in
  `contrib/` and `deploy/`.
- The sample web-server configurations in `examples/web-servers/`, where they
  would expose a deployment that follows them.
- The RADIUS client, including what it accepts as a reply, and the examples in
  `examples/radius/` and `examples/hooks/`.

## Out of scope

- A deployment that ignores the documentation. For example:
  - `cookie_secure: false` over HTTPS;
  - a readable config file;
  - a `trusted_proxies` entry that lets clients forge their address;
  - `mail.program: ""` in production.
- Vulnerabilities in Go, its standard library or a dependency, unless Signet uses
  it in a way that makes it exploitable. Report those upstream. `make vuln` runs
  `govulncheck` on the built binary.
- Limits that are documented, such as rate limits counted per process
  (`docs/DESIGN.md`), or what PAP over UDP and MS-CHAPv2 expose on the network
  path to a RADIUS server.
- A RADIUS server's own decisions: Signet trusts a valid Access-Accept.

## The code was written by AI

Signet was written by an AI model under a person's direction (see `README.md`).
Review it accordingly. Reports are welcome even when they're uncertain.
