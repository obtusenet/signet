# Contributing to Signet

Pull requests and issues are welcome. Contributions are accepted under the MIT
licence (`LICENSE`), as the rest of Signet is. No sign-off or agreement is needed.

Report a security problem privately, as `docs/SECURITY.md` describes, not in an
issue or pull request.

## Before a pull request

1. **Open an issue first for anything large:** a new feature, setting, dependency
   or change of behaviour. Signet prefers small, explicit choices (see "Design
   rules" below), and agreeing the design first saves rewriting.
2. **Build and test:**

   ```sh
   make          # build/signet
   make lint     # go fmt (rewrites files) and go vet
   make test     # every suite that needs no network: Go, browser script, hooks,
                 # web-file installer, licence headers, sample configs, SBOM, end to end
   ```

   `make test` must pass. Add a test for what you change. If you touch the
   package or Docker paths and have the tools, run the matching target:
   `make test-docker`, `make test-linux` or `make test-deb`.
3. **Update the documentation in the same change.** Each change that alters
   behaviour updates the matching places:
   - the manual page (`man/`);
   - `docs/API.md` for HTTP changes, and `signet-api(7)` with it;
   - `config/example.yaml` and `signet-config.yaml(5)` for settings. Run
     `make configs` after changing the example: the packages' sample configs
     are made from it.
4. **One topic per pull request,** with a description of what changes, why, and
   how you tested it.

## Design rules

- **Expose facts, and let configuration decide policy.** Prefer a setting with a
  documented default over automatic behaviour. Be consistent rather than clever.
- **Small dependency set.** The standard library first. A new dependency needs a
  reason, an MIT, BSD or Apache licence by preference, and is vendored
  (`go mod vendor`): Signet builds with no network.
- **Real status codes.** Each JSON endpoint answers a failure with a status that
  describes it and a JSON body. Pages work without JavaScript where they can.
- **Never trust the request for what it must not decide:** the address to enroll
  a key for, the host in a mailed link, or a client address from an untrusted
  proxy.
- **Secrets stay out of logs.** Passwords, tokens and PINs are never logged. The
  only exception is `mail.program: ""`, which is for development and warns.
- **Rate-limit refusals are logged** at warning level, naming the limit.

## Style

- Go: `gofmt`. Comments say why rather than what. Errors are wrapped with `%w` and
  name what failed.
- Shell: POSIX `sh` unless a script already uses bash.
- Every source file and script outside `vendor/` starts with:

  ```
  Copyright (c) 2026 Obtuse Networking LLC
  SPDX-License-Identifier: MIT
  ```

  in the file's comment syntax. `make test` checks it.
- Man pages: mdoc, clean under `mandoc -Tlint man/*/*` apart from references to
  pages that are not installed. Text lines stay under 80 bytes, with each sentence
  on a new line.
- Documentation: plain, short sentences in present tense. Name the setting, path
  or command exactly. New documents go in `docs/`, not the repository root.
- Commit messages: a short summary line, a blank line, then what changed and why.

## AI-assisted contributions

Signet itself was written with an AI model (see `README.md`), and contributions made
with AI tools are welcome on the same terms as any other. You are responsible for
what you submit: understand it, test it and describe it accurately. `AGENTS.md`
gives an AI agent the same rules as this file.
