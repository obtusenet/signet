# OpenBSD port for signet

The port lives in `www/signet/`. It builds entirely from the vendored
dependencies in the distfile, so the build sandbox never touches the network.

On the test box, `make build-package` does steps 1 to 4 from the working tree and
`make deploy-package` does the install; `make box` runs both. The steps
below are the same thing by hand, for any other machine.

## 1. Build the distfile

```sh
./distfile.sh
```

It writes `dist/signet-0.15.0.zip` — the tracked source plus `vendor/`, under a
single `signet-0.15.0/` top-level directory — and prints the `distinfo` entry.
Copy that entry into `www/signet/distinfo`.

The zip layout matters twice over:

* no top-level directory makes the `lang/go` module try to move the tree into
  its own Go workspace (`mv ... Invalid argument`);
* `vendor/` missing makes `go test ./...` fail with
  `directory prefix . does not contain main module`.

## 2. Install the port into the tree

The port's `Makefile` deliberately does **not** set `MODGO_MODNAME`: that would
point `GOPROXY` at `${WRKDIR}/go_modules` and ignore `vendor/`. It sets
`MODGO_GO111MODULE=on`, builds with `GOFLAGS=-mod=vendor GOPROXY=off`, and
overrides `do-build` *and* `do-install` (the module's install target looks in
`${MODGO_WORKSPACE}/bin`, which this port never populates).

```sh
doas cp -R contrib/packaging/openbsd/www/signet /usr/ports/www/
doas cp dist/signet-0.15.0.zip /usr/ports/distfiles/
```

The port's `SITES` is the GitHub release, where the zip is attached when the
version is published. Copying the zip in, as above, builds a version that is not
published yet.

## 3. Register the package user

`pkg_create` only accepts `@newuser`/`@newgroup` names that start with `_` and
are listed in the tree's user database. Signet uses uid 906:

```sh
grep -w 906 /usr/ports/infrastructure/db/user.list   # must be empty
printf '906\t_signet\t\t_signet\t\twww/signet\n' | doas tee -a \
	/usr/ports/infrastructure/db/user.list
```

## 4. Package

```sh
cd /usr/ports/www/signet
doas make package
```

The result is `/usr/ports/packages/amd64/all/signet-0.15.0.tgz`. `make package`
runs `go test ./...` first, in `do-build`.

If the framework answers `Error: change in plist ... forgot to bump a
REVISION`, the recorded plist of an earlier package disagrees with the new one.
Either bump `REVISION` in the Makefile, or drop the stale records before
rebuilding:

```sh
doas rm -f /usr/ports/plist/amd64/signet-0.15.0{,-new} \
	/usr/ports/packages/amd64/{all,ftp}/signet-0.15.0.tgz
```

## 5. Install and enable

```sh
doas pkg_add -Dunsigned /usr/ports/packages/amd64/all/signet-0.15.0.tgz
```

The package config sample is `/etc/signet/config.yaml` (from
`share/examples/signet/config.yaml`), mode 0640 and group `_signet` because it
holds the cookie signing secret. **`signet serve` refuses to start until
`cookie_secret` is set** to at least 32 characters, so set it first. Generate one
with `openssl rand -hex 32`. Instances sharing a database must use the same value.

`cookie_secure` defaults to `true`, which is right behind a TLS-terminating
proxy. A plain-HTTP test deployment, including the checks under "Verification",
must set it to `false`, otherwise browsers silently drop the session cookie:

```yaml
cookie_secure: false
```

Then start the service:

```sh
doas rcctl enable signet
doas rcctl start signet
```

If `rcctl` answers `signet(failed)`, the reason is in `/var/log/messages`: any error
that stops `serve`, a bad config included, goes to syslog whatever `log_syslog` says.

`rc_pre` creates `/var/www/signet`, takes ownership of the runtime tree, and
seeds `templates/` (with the `email/` PIN message) and `static/` from
`/usr/local/share/examples/signet/web/` on first start.

The rc script does **not** redirect stdout: rc.subr's stop bookkeeping waits
for the full `daemon_timeout` and reports `failed` when it does, even though
the daemon stopped. Logs therefore go to syslog (`log_syslog: true` in the
sample config); read them with `tail -f /var/log/messages`.

**Upgrades do not touch the runtime `templates/` or `static/` trees** — those directories
are the local customization point. To bring them up to a new package, run this for each:

```sh
doas /bin/sh /usr/local/share/examples/signet/install-web.sh \
	/usr/local/share/examples/signet/web/templates /var/www/signet/templates \
	/var/www/signet/.web-templates.sha256 _signet:_signet
doas /bin/sh /usr/local/share/examples/signet/install-web.sh \
	/usr/local/share/examples/signet/web/static /var/www/signet/static \
	/var/www/signet/.web-static.sha256 _signet:_signet
doas rcctl restart signet
```

It replaces a file only if it matches what the last version installed. A file with local
edits is kept, and it tells you where this version's copy is, so you can compare them. A
tree seeded before 0.13.27 has no such record: until the first run, any file that differs
is treated as edited and kept.

**Upgrading from the 0.5 series:** set `cookie_secret` and restrict the config
file's mode first, since an existing config is left as it is. After installing,
run `signet user-approve` for accounts made by the old `user-add`, which wrote only
`self_registered`; while approval is required they cannot sign in until then.

**Behind a proxy**, list it in `trusted_proxies`, such as `["unix"]` for a web server on
the socket, or every client shares one rate-limit budget. `serve` warns about the socket
case. FastCGI needs nothing.

## Verification

```sh
curl -s http://localhost:9090/health      # {"status":"ok"}
curl -s -o /dev/null -w '%{http_code}\n' http://localhost:9090/login
curl -s -o /dev/null -w '%{http_code}\n' \
	http://localhost:9090/static/js/webauthn.js
```

Create a user with the packaged binary (it must run as `_signet` so the CSV
stays writable):

```sh
doas su -fl -c daemon -s /bin/sh _signet -c \
	"/usr/local/bin/signet user-add -config /etc/signet/config.yaml \
	-password-stdin user@example.com" < password-file
```
