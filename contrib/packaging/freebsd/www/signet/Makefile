# Copyright (c) 2026 Obtuse Networking LLC
# SPDX-License-Identifier: MIT

PORTNAME=	signet
DISTVERSION=	0.14.0
CATEGORIES=	www
# The distfile is `make build`'s tarball, with vendor/, attached to the GitHub
# release.  The box targets copy it into DISTDIR, so a build before the release
# is published does not fetch it.
MASTER_SITES=	https://github.com/obtusenet/signet/releases/download/v${DISTVERSION}/

MAINTAINER=	code@obtusenet.com
COMMENT=	Web sign-in server with passwords, security keys and TOTP
WWW=		https://github.com/obtusenet/signet

LICENSE=	MIT
LICENSE_FILE=	${WRKSRC}/LICENSE

USES=		go:1.26+,no_targets shebangfix
# The example shell hooks' interpreter, at FreeBSD's path; bash does not become a
# dependency.  The Python hook is installed not executable, so Python does not
# either: run it as python3 claims-hook.py.
SHEBANG_FILES=	examples/hooks/*.sh
USE_RC_SUBR=	signet

SUB_FILES=	pkg-deinstall pkg-install pkg-message
SUB_LIST=	SIGNET_USER=${USERS}

USERS=		signet
GROUPS=		signet

OPTIONS_DEFINE=	EXAMPLES

PORTDATA=	*
PORTEXAMPLES=	*

# Modules mode, with only the vendored dependencies: nothing is fetched.
SIGNET_GOENV=	${SETENV} ${MAKE_ENV} ${GO_ENV} GO111MODULE=on GOFLAGS=-mod=vendor GOPROXY=off

# The tests run first, as in the OpenBSD port: a failing test means no package.
# Under /tmp, because a unix socket's path must fit in 104 bytes and WRKDIR's
# may not.
do-build:
	cd ${WRKSRC} && ${SIGNET_GOENV} TMPDIR=/tmp GOTMPDIR=/tmp ${GO_CMD} test ./...
	cd ${WRKSRC} && ${SIGNET_GOENV} ${GO_CMD} build \
		-ldflags "-X main.buildTime=$$(date -u +%Y-%m-%dT%H:%M:%SZ) -X main.defaultConfig=${ETCDIR}/config.yaml" \
		-o ${WRKDIR}/bin/signet ./cmd/signet

do-install:
	${INSTALL_PROGRAM} ${WRKDIR}/bin/signet ${STAGEDIR}${PREFIX}/bin/
	${MKDIR} ${STAGEDIR}${ETCDIR} ${STAGEDIR}/var/db/signet
	${INSTALL_DATA} ${FILESDIR}/config.yaml.sample ${STAGEDIR}${ETCDIR}/
	${MKDIR} ${STAGEDIR}${PREFIX}/etc/syslog.d ${STAGEDIR}${PREFIX}/etc/newsyslog.conf.d
	${INSTALL_DATA} ${FILESDIR}/signet-syslog.conf.sample ${STAGEDIR}${PREFIX}/etc/syslog.d/signet.conf.sample
	${INSTALL_DATA} ${FILESDIR}/signet-newsyslog.conf.sample \
		${STAGEDIR}${PREFIX}/etc/newsyslog.conf.d/signet.conf.sample
	${MKDIR} ${STAGEDIR}${DATADIR}/web
	cd ${WRKSRC}/web && ${COPYTREE_SHARE} "templates static" ${STAGEDIR}${DATADIR}/web
	${INSTALL_SCRIPT} ${WRKSRC}/deploy/install-web.sh ${STAGEDIR}${DATADIR}/
.for s in 1 5 7
	${INSTALL_MAN} ${WRKSRC}/man/man${s}/*.${s} ${STAGEDIR}${PREFIX}/share/man/man${s}/
.endfor

do-install-EXAMPLES-on:
	${MKDIR} ${STAGEDIR}${EXAMPLESDIR}
	cd ${WRKSRC}/examples && ${COPYTREE_SHARE} "hooks web-servers" ${STAGEDIR}${EXAMPLESDIR}
	${INSTALL_SCRIPT} ${WRKSRC}/examples/hooks/*.sh ${STAGEDIR}${EXAMPLESDIR}/hooks/

.include <bsd.port.mk>
