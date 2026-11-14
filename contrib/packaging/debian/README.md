# Debian package

A package for Debian 13 (trixie), amd64, built with debhelper from the source
tarball of `make build`, with the dependencies from `vendor/`, as the OpenBSD port
does. Go 1.26 comes from trixie-backports; trixie's own is 1.24.

```sh
make deb        # dist/signet_<version>-1_amd64.deb and dist/lintian.txt
make test-deb   # the package on a throwaway Debian with real systemd
```

`build.sh` builds the image in `Dockerfile` (`signet-debbuild:13`) and runs the build
in it as the calling user. `debian/` is copied into the unpacked source there, and
`copyright.sh` writes `debian/copyright` from `vendor/modules.txt`, so it follows the
vendored modules. The tests run during the build: a failing test means no package.
lintian runs with `--pedantic`; its two overrides are for a package that never goes
to the Debian archive.

## What it installs

| Path | What |
|------|------|
| `/usr/bin/signet` | the binary; its commands read `/etc/signet/config.yaml` without `-config` |
| `/usr/lib/systemd/system/signet.service` | `deploy/signet.service` with `_signet` and these paths |
| `/etc/signet/config.yaml` | copied from `/usr/share/signet/config.yaml.example` on first install, `0640 root:_signet` |
| `/etc/signet/templates`, `/etc/signet/static` | working copies of the web files |
| `/usr/share/signet/web` | the web files as shipped |
| `/var/lib/signet` | database and `users.csv`, `0750 _signet` |
| `/usr/share/doc/signet/examples` | claims hooks and web-server samples |

## Behaviour

- **Not started.** The unit is installed, not enabled or started: `serve` needs
  `cookie_secret`. Set it, then `systemctl enable --now signet`.
- **The config is not a conffile.** It holds `cookie_secret`, so `postinst` writes it
  only when there is none, and dpkg never asks about it or rewrites it.
- **Upgrades** keep the config, keep an edited template or static file and say so
  (`deploy/install-web.sh`), and restart the service only if it is running.
- **Remove** stops the service. **Purge** removes `/etc/signet` and keeps
  `/var/lib/signet`, which holds the accounts and keys; the `_signet` user stays.
- **The user** is `_signet`, a system user created by `adduser`.
- **From `deploy/install.sh`:** a machine set up by the script has
  `/etc/systemd/system/signet.service`, which hides the packaged unit, and data owned
  by `signet`. `postinst` reports both and changes nothing.

## Releases

`make release` adds a `debian/changelog` entry, `<version>-1`. `build.sh [version]`
builds another Debian version with a changelog entry in the build copy only.
