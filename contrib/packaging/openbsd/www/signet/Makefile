# Copyright (c) 2026 Obtuse Networking LLC
# SPDX-License-Identifier: MIT

COMMENT =	multi-factor authentication server

DISTNAME =	signet-0.14.2
DISTFILES =	${DISTNAME}.zip
EXTRACT_SUFX =	.zip
# The zip is attached to the GitHub release.  Before the release is published,
# copy dist/${DISTNAME}.zip into the distfiles directory, as the README says.
SITES =		https://github.com/obtusenet/signet/releases/download/v${DISTNAME:S/signet-//}/

CATEGORIES =	www

HOMEPAGE =	https://github.com/obtusenet/signet

MAINTAINER =	Code <code@obtusenet.com>

# MIT
PERMIT_PACKAGE =	Yes

# The dependencies are vendored in the distfile: the build sandbox has no
# network access, so the proxy must not be consulted.  MODGO_MODNAME is
# deliberately unset -- it would point GOPROXY at ${WRKDIR}/go_modules.
MODULES =	lang/go
MODGO_GO111MODULE =	on

# The Go toolchain installed by lang/go needs GOROOT in the environment;
# the ports framework builds with a cleared one.  Resolve it here, where
# the environment is still intact.
GOROOT_LOCAL !=	go env GOROOT

# The archive unpacks into ${WRKDIR}/${DISTNAME}; the lang/go module moves
# that tree into its Go workspace and sets WRKSRC accordingly.
# Build against the vendored dependencies only.
GOENV =	${SETENV} ${MAKE_ENV} PATH=${PATH} GOROOT=${GOROOT_LOCAL} \
	GO111MODULE=on GOFLAGS=-mod=vendor GOPROXY=off

# Expand the port's paths in the rc script at package-build time.
SUBST_VARS =	LOCALBASE LOCALSTATEDIR SYSCONFDIR

# The tests run in do-build; the framework's own test step would use its
# GOPROXY=invalid environment.
NO_TEST =	Yes

do-build:
	cd ${WRKSRC} && ${GOENV} go test ./...
	cd ${WRKSRC} && ${GOENV} go build \
		-ldflags "-X main.buildTime=$$(date -u +%Y-%m-%dT%H:%M:%SZ) -X main.defaultConfig=${SYSCONFDIR}/signet/config.yaml" \
		-o ${WRKBUILD}/signet ./cmd/signet

# do-build writes the binary to ${WRKBUILD}; the module's own install target
# would look for ${MODGO_WORKSPACE}/bin, which this port never populates.
do-install:
	${INSTALL_PROGRAM} ${WRKBUILD}/signet ${PREFIX}/bin/signet

post-install:
	${INSTALL_DATA_DIR} ${PREFIX}/share/doc/signet
	${INSTALL_DATA} ${WRKSRC}/LICENSE ${PREFIX}/share/doc/signet/
	${INSTALL_DATA_DIR} ${PREFIX}/share/examples/signet
	${INSTALL_DATA} ${FILESDIR}/config.yaml \
		${PREFIX}/share/examples/signet/config.yaml
	${INSTALL_SCRIPT} ${WRKSRC}/deploy/install-web.sh ${PREFIX}/share/examples/signet/
	${INSTALL_DATA_DIR} ${PREFIX}/share/examples/signet/web/templates
	${INSTALL_DATA} ${WRKSRC}/web/templates/login.html \
		${PREFIX}/share/examples/signet/web/templates/
	${INSTALL_DATA} ${WRKSRC}/web/templates/recover.html \
		${PREFIX}/share/examples/signet/web/templates/
	${INSTALL_DATA} ${WRKSRC}/web/templates/register.html \
		${PREFIX}/share/examples/signet/web/templates/
	${INSTALL_DATA} ${WRKSRC}/web/templates/account.html \
		${PREFIX}/share/examples/signet/web/templates/
	${INSTALL_DATA} ${WRKSRC}/web/templates/webauthn.html \
		${PREFIX}/share/examples/signet/web/templates/
	${INSTALL_DATA_DIR} ${PREFIX}/share/examples/signet/web/templates/email
	${INSTALL_DATA} ${WRKSRC}/web/templates/email/pin.html \
		${WRKSRC}/web/templates/email/pin.txt \
		${WRKSRC}/web/templates/email/recover.html \
		${WRKSRC}/web/templates/email/recover.txt \
		${WRKSRC}/web/templates/email/password-changed.html \
		${WRKSRC}/web/templates/email/password-changed.txt \
		${WRKSRC}/web/templates/email/register.html \
		${WRKSRC}/web/templates/email/register.txt \
		${WRKSRC}/web/templates/email/account-exists.html \
		${WRKSRC}/web/templates/email/account-exists.txt \
		${WRKSRC}/web/templates/email/account-change.html \
		${WRKSRC}/web/templates/email/account-change.txt \
		${PREFIX}/share/examples/signet/web/templates/email/
	${INSTALL_DATA_DIR} ${PREFIX}/share/examples/signet/web/static/js
	${INSTALL_DATA} ${WRKSRC}/web/static/js/webauthn.js \
		${PREFIX}/share/examples/signet/web/static/js/
	${INSTALL_DATA_DIR} ${PREFIX}/share/examples/signet/hooks
	${INSTALL_SCRIPT} ${WRKSRC}/examples/hooks/claims-hook.sh \
		${WRKSRC}/examples/hooks/claims-hook.py \
		${WRKSRC}/examples/hooks/radius-claims.py \
		${WRKSRC}/examples/hooks/radius-claims.sh \
		${WRKSRC}/examples/hooks/test-hooks.sh \
		${PREFIX}/share/examples/signet/hooks/
	${INSTALL_DATA} ${WRKSRC}/examples/hooks/README.md \
		${PREFIX}/share/examples/signet/hooks/
	${INSTALL_DATA_DIR} ${PREFIX}/share/examples/signet/radius
	${INSTALL_DATA} ${WRKSRC}/examples/radius/README.md \
		${PREFIX}/share/examples/signet/radius/
	${INSTALL_DATA_DIR} ${PREFIX}/share/examples/signet/web-servers/caddy
	${INSTALL_DATA_DIR} ${PREFIX}/share/examples/signet/web-servers/nginx
	${INSTALL_DATA_DIR} ${PREFIX}/share/examples/signet/web-servers/openbsd-httpd
	${INSTALL_DATA} ${WRKSRC}/examples/web-servers/README.md \
		${PREFIX}/share/examples/signet/web-servers/
	${INSTALL_DATA} ${WRKSRC}/examples/web-servers/caddy/Caddyfile-port \
		${WRKSRC}/examples/web-servers/caddy/Caddyfile-socket \
		${PREFIX}/share/examples/signet/web-servers/caddy/
	${INSTALL_DATA} ${WRKSRC}/examples/web-servers/nginx/signet-port.conf \
		${WRKSRC}/examples/web-servers/nginx/signet-fcgi.conf \
		${PREFIX}/share/examples/signet/web-servers/nginx/
	${INSTALL_DATA} ${WRKSRC}/examples/web-servers/openbsd-httpd/signet-port.conf \
		${WRKSRC}/examples/web-servers/openbsd-httpd/signet-fcgi.conf \
		${PREFIX}/share/examples/signet/web-servers/openbsd-httpd/
	${INSTALL_DATA_DIR} ${PREFIX}/man/man1
	${INSTALL_MAN} ${WRKSRC}/man/man1/signet.1 \
		${PREFIX}/man/man1/signet.1
	${INSTALL_DATA_DIR} ${PREFIX}/man/man5
	${INSTALL_MAN} ${WRKSRC}/man/man5/signet-config.yaml.5 \
		${PREFIX}/man/man5/signet-config.yaml.5
	${INSTALL_MAN} ${WRKSRC}/man/man5/signet-hooks.5 \
		${PREFIX}/man/man5/signet-hooks.5
	${INSTALL_MAN} ${WRKSRC}/man/man5/signet-template.5 \
		${PREFIX}/man/man5/signet-template.5
	${INSTALL_DATA_DIR} ${PREFIX}/man/man7
	${INSTALL_MAN} ${WRKSRC}/man/man7/signet-api.7 \
		${PREFIX}/man/man7/signet-api.7

.include "modules.inc"
.include <bsd.port.mk>