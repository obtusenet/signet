# FreeBSD port

`www/signet`, built on a FreeBSD 15.1 box (`FBSDBOX=user@host`, on the command line or
in `local.mk`) from the source tarball of `make build`, with the dependencies from
`vendor/`, as the OpenBSD port does.

```sh
make freebsd-package   # build there; stage-qa, check-plist and portlint
make test-freebsd      # install and exercise it there, on :8080, then remove it
```

`box-build-package.sh` builds as the calling user in an overlay, `~/signet-port`, with
its own `DISTDIR`, `WRKDIRPREFIX`, `PACKAGES`, `PORT_DBDIR` and `UIDs`/`GIDs`, so
`/usr/ports` is never touched; `~/signet-port/env.sh` sets them for a shell. The box
needs `go127` (or whichever Go `USES=go:1.26+` picks) and `portlint` as packages: the
overlay cannot install build dependencies, which needs root.

The tests run during the build (`do-build`), with `TMPDIR` and `GOTMPDIR` at `/tmp`:
a unix socket's path must fit in 104 bytes, and the work directory's may not.

portlint leaves two warnings: no `WWW` (signet has no public page) and
`DEVELOPER=yes` not in `/etc/make.conf` (the build passes it).

## What it installs

| Path | What |
|------|------|
| `/usr/local/bin/signet` | the binary; its commands read `/usr/local/etc/signet/config.yaml` without `-config` |
| `/usr/local/etc/rc.d/signet` | runs it under `daemon(8)` as `signet`, restarting it if it stops; `reload` sends SIGHUP |
| `/usr/local/etc/signet/config.yaml` | from `config.yaml.sample` (`@sample`), `0640 root:signet` |
| `/usr/local/etc/signet/templates`, `static` | working copies of the web files |
| `/usr/local/share/signet/web` | the web files as shipped |
| `/var/db/signet` | database and `users.csv`, `0750 signet` |
| `/var/log/signet.log` | the log, through `syslog.d/signet.conf`; `newsyslog.conf.d/signet.conf` rotates it |
| `/usr/local/share/examples/signet` | claims hooks, web-server samples, and a FreeRADIUS guide |

The user and group are `signet`, id 784: 906, OpenBSD's, is `opentsdb` here.

## Behaviour

- **Not started.** `signet_enable` defaults to NO. Set `cookie_secret`, then
  `sysrc signet_enable=YES` and `service signet start`.
- **Upgrades** keep the config, keep an edited template or static file and say so
  (`deploy/install-web.sh`). **A running service keeps the old version** until
  `service signet restart`, which the upgrade says to run: pkg ends every process an
  install script starts, so a package cannot restart a service. This differs from
  the Debian package, which restarts it.
- **Removal** stops the service (not during an upgrade, `PKG_UPGRADE`), and keeps an
  edited config, the web files' working copies and `/var/db/signet`.
- The Python example hooks are installed not executable, so Python is not a dependency:
  run them as `python3 claims-hook.py`. `radius-claims.sh` needs only `sh` and `awk`.

## Releases

`make release` bumps `DISTVERSION` and commits a `distinfo` for the release's tarball.
`freebsd-package` writes its own for the working tree's tarball each time, so a
build between releases needs no commit.
