# Copyright (c) 2026 Obtuse Networking LLC
# SPDX-License-Identifier: MIT

.PHONY: vuln vuln-box vuln-host vuln-current build-current test-go-current all build test regress test-go test-js test-hooks test-license test-configs test-sbom sbom configs test-unit test-e2e test-web-servers clean run \
	fmt vet lint install distfile man install-man \
	build-package deploy-package box check-dist release docker-image test-docker test-radius test-web test-linux deb test-deb freebsd-package test-freebsd

BINARY_NAME=signet
BUILD_DIR=build
VERSION=0.15.0
DIST_DIR=dist
TARBALL=$(BINARY_NAME)-$(VERSION).tar.gz

# Get the latest commit hash for versioning
GIT_HASH=$(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME=$(shell date -u '+%Y-%m-%dT%H:%M:%SZ')

LDFLAGS=-ldflags "-X main.gitHash=$(GIT_HASH) -X main.buildTime=$(BUILD_TIME)"

# The boxes the box targets build and test on, as user@host: TESTBOX (OpenBSD:
# build-package, deploy-package, box, vuln-box, test-web-servers and the release)
# and FBSDBOX (FreeBSD: freebsd-package, test-freebsd).  Give them on the command
# line or in local.mk, which is not tracked.
-include local.mk
TESTBOX ?=
FBSDBOX ?=
# The first line of a box target's recipe: stop when its box is not set.
need = @test -n "$($(1))" || { echo "$(1) is not set: give $(1)=user@host or set it in local.mk" >&2; exit 1; }

# Compile the binary to build/signet.
all:
	go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/signet

# The source tarball, dist/signet-<version>.tar.gz: the working tree's tracked
# and untracked non-ignored files plus vendor/, so it builds with no network.
build:
	./distfile.sh tar

# The regression suite: Go tests, the browser script against a mocked browser
# API (needs node), the example claims hooks (need bash and python3), and the real
# flows against a throwaway server on a unix socket (needs curl; no network or mail).
test: test-go test-js test-hooks test-web test-license test-configs test-sbom test-e2e

regress: test

test-go:
	go test ./...

test-js:
	node --test tests/webauthn_js_test.js tests/recover_js_test.js tests/account_js_test.js tests/login_js_test.js tests/login_steps_js_test.js

test-hooks:
	./examples/hooks/test-hooks.sh

test-unit:
	go test ./internal/...

test-license:
	tests/license_test.sh

# deploy/install-web.sh, which must never lose an edited web file.
test-web:
	tests/install_web_test.sh

# The packages' sample configurations: config/example.yaml with only the OS's
# settings changed, and current.  `make configs` writes them.
test-configs:
	tests/config_copies_test.sh

# The software bill of materials, SPDX 2.3: dist/signet-<version>.spdx.json.
# distfile.sh also puts it in every source archive, as signet.spdx.json.
sbom:
	@mkdir -p $(DIST_DIR)
	contrib/packaging/sbom.sh . $(VERSION) > $(DIST_DIR)/signet-$(VERSION).spdx.json
	@echo "Created $(DIST_DIR)/signet-$(VERSION).spdx.json"

test-sbom:
	tests/sbom_test.sh

configs:
	contrib/packaging/config.sh openbsd > contrib/packaging/openbsd/www/signet/files/config.yaml
	contrib/packaging/config.sh freebsd > contrib/packaging/freebsd/www/signet/files/config.yaml.sample

# deploy/install.sh on a throwaway Debian with real systemd: pulls a base image and
# runs a privileged container with no network.  Not part of `make test`.
test-linux: all
	tests/linux_test.sh

# The Debian 13 package, built with debhelper in a container as this user, and
# checked by lintian: dist/signet_<version>-1_amd64.deb.  Pulls the build image's
# packages; not part of `make test`.
deb:
	contrib/packaging/debian/build.sh

# The package on a throwaway Debian with real systemd: install, first steps,
# upgrades, remove and purge.  Privileged container, no network.
test-deb: deb
	tests/deb_test.sh

# The Docker image with its version details, and its own test.  Not part of `make
# test`: they pull base images.  test-docker publishes :8080 while it runs.
docker-image:
	docker build --build-arg GIT_HASH=$(GIT_HASH) --build-arg BUILD_TIME=$(BUILD_TIME) \
		-t $(BINARY_NAME):$(VERSION) -t $(BINARY_NAME):latest \
		-f contrib/packaging/docker/Dockerfile .

test-docker: docker-image
	tests/docker_test.sh

# Signet against FreeRADIUS (pinned by digest) in Docker: PAP, MS-CHAPv2, groups,
# NAS-Identifier, a challenge.  Pulls the image; not part of `make test`.
test-radius: all
	tests/radius_test.sh $(BUILD_DIR)/$(BINARY_NAME)

# examples/web-servers/ as shipped, on the test box, with throwaway instances on
# spare ports; running services are left alone.  Not part of `make test`.
# Known vulnerabilities in what the compiled binary actually reaches, standard
# library included.  It contacts vuln.go.dev, so it is not part of make test.  It
# scans the binary because govulncheck 1.0.4's source mode stops with an internal
# error on this tree.  make release runs it and warns, without stopping.
vuln: all
	govulncheck -mode=binary $(BUILD_DIR)/signet

# The same for what a machine runs: a package is built with its operating
# system's Go, which decides its standard-library fixes.  HOST is user@host; BIN
# is where the binary is.  vuln-box does it for TESTBOX.
BIN ?= /usr/local/bin/signet
vuln-host:
	$(call need,HOST)
	mkdir -p $(BUILD_DIR)
	scp -q $(HOST):$(BIN) $(BUILD_DIR)/signet.host
	go version $(BUILD_DIR)/signet.host
	govulncheck -mode=binary $(BUILD_DIR)/signet.host

vuln-box:
	$(call need,TESTBOX)
	$(MAKE) vuln-host HOST=$(TESTBOX)

# "Current Go": the newest Go release, pinned by digest, so a test or a scan with
# it gives the same answer every time.  go.mod's go line stays the oldest Go a
# supported platform has, and make test runs on whatever Go this host has; these
# run the same code on the newest.  Moving the pin is a commit of its own, made
# when Go publishes a security release.  They need Docker, and run offline.
GO_IMAGE = golang:1.27.4-trixie@sha256:b54b2639de8c1bfe538ec5ffc45f29b1932235ac5f6d63c059853646677112d9
GO_RUN = docker run --rm --network none -u $$(id -u):$$(id -g) -e HOME=/tmp \
	-e GOFLAGS=-mod=vendor -e GOPROXY=off -e GOTOOLCHAIN=local -e GOCACHE=/src/$(BUILD_DIR)/gocache-current \
	-v "$(CURDIR)":/src -w /src $(GO_IMAGE)

test-go-current:
	mkdir -p $(BUILD_DIR)
	$(GO_RUN) sh -c 'go version && go vet ./... && go test -race ./...'

build-current:
	mkdir -p $(BUILD_DIR)
	$(GO_RUN) go build $(LDFLAGS) -o $(BUILD_DIR)/signet.current ./cmd/signet

# govulncheck runs here, as vuln does: it needs vuln.go.dev, and reads the binary.
vuln-current: build-current
	go version $(BUILD_DIR)/signet.current
	govulncheck -mode=binary $(BUILD_DIR)/signet.current

test-web-servers:
	$(call need,TESTBOX)
	tar -czf - examples/web-servers tests/web_servers_test.sh | ssh $(TESTBOX) \
		'd=$$(mktemp -d) && tar -xzf - -C $$d && sh $$d/tests/web_servers_test.sh $$d/examples/web-servers; rc=$$?; rm -rf $$d; exit $$rc'

test-e2e: all
	./tests/e2e_test.sh $(BUILD_DIR)/$(BINARY_NAME)

clean:
	rm -rf $(BUILD_DIR)
	rm -f $(DIST_DIR)/$(TARBALL)

run: all
	./$(BUILD_DIR)/$(BINARY_NAME) serve -config config/example.yaml

fmt:
	go fmt ./...

vet:
	go vet ./...

lint: fmt vet

install: all
	./deploy/install.sh

# Create distribution file for OpenBSD port
distfile:
	./distfile.sh

# Build man pages (requires mandoc)
man:
	mandoc -Tascii man/man1/signet.1 | head -1
	mandoc -Tascii man/man5/signet-config.yaml.5 | head -1
	mandoc -Tascii man/man5/signet-hooks.5 | head -1
	mandoc -Tascii man/man5/signet-template.5 | head -1
	mandoc -Tascii man/man7/signet-api.7 | head -1

# Install man pages
install-man:
	install -d -o root -g wheel -m 755 /usr/local/man/man1
	install -d -o root -g wheel -m 755 /usr/local/man/man5
	install -d -o root -g wheel -m 755 /usr/local/man/man7
	install -o root -g wheel -m 444 man/man1/signet.1 /usr/local/man/man1/
	install -o root -g wheel -m 444 man/man5/signet-config.yaml.5 /usr/local/man/man5/
	install -o root -g wheel -m 444 man/man5/signet-hooks.5 /usr/local/man/man5/
	install -o root -g wheel -m 444 man/man5/signet-template.5 /usr/local/man/man5/
	install -o root -g wheel -m 444 man/man7/signet-api.7 /usr/local/man/man7/

# Run one of the box scripts on the test box, with the version as its argument.
# It is copied over rather than fed to `sh -s`, because a command inside the
# script could otherwise read the rest of the script as its own stdin.
define run_on_box
ssh $(TESTBOX) 'cat > /tmp/signet-$(1)' < contrib/packaging/openbsd/$(1)
ssh $(TESTBOX) 'sh /tmp/signet-$(1) $(VERSION); rc=$$?; rm -f /tmp/signet-$(1); exit $$rc'
endef

# Build the OpenBSD package on the test box from the working tree: distfile.sh
# here, then `make package` in /usr/ports there, which runs the Go tests in the
# ports sandbox.  Services are not touched.
# DIST_READY=1 (as release gives it) sends the zip already in dist/ with the
# committed distinfo instead, so the archive the release publishes is the one
# the box builds, and it is not overwritten.
build-package:
	$(call need,TESTBOX)
	@mkdir -p $(BUILD_DIR)
	@if test -n "$(DIST_READY)"; then \
		$(MAKE) --no-print-directory check-dist && \
		cp contrib/packaging/openbsd/www/signet/distinfo $(BUILD_DIR)/distfile.out; \
	else \
		./distfile.sh > $(BUILD_DIR)/distfile.out; \
	fi
	ssh $(TESTBOX) 'cat > /tmp/signet-$(VERSION).zip' < $(DIST_DIR)/signet-$(VERSION).zip
	grep -E '^(SHA256|SIZE) ' $(BUILD_DIR)/distfile.out | ssh $(TESTBOX) 'cat > /tmp/signet-$(VERSION).distinfo'
	$(call run_on_box,box-build-package.sh)

# Install the package built by build-package and restart every instance that
# runs the binary.  Never touches /etc/signet.
deploy-package:
	$(call need,TESTBOX)
	$(call run_on_box,box-deploy-package.sh)

box: build-package deploy-package

# The archives in dist/ are the ones the committed distinfo files describe.
check-dist:
	@set -e; z=signet-$(VERSION).zip; t=signet-$(VERSION).tar.gz; \
	for f in $$z $$t; do test -f $(DIST_DIR)/$$f || { echo "$(DIST_DIR)/$$f is missing" >&2; exit 1; }; done; \
	ok=0; \
	check() { \
		want=`sed -n "s/^SHA256 ($$2) = //p" $$1`; size=`sed -n "s/^SIZE ($$2) = //p" $$1`; \
		have=`sha256sum $(DIST_DIR)/$$2 | cut -d' ' -f1`; hsize=`stat -c %s $(DIST_DIR)/$$2`; \
		if test "$$want" = "$$have" && test "$$size" = "$$hsize"; then echo "ok   - $$2 matches $$1"; \
		else echo "FAIL - $$2 does not match $$1" >&2; ok=1; fi; }; \
	check contrib/packaging/openbsd/www/signet/distinfo $$z; \
	check contrib/packaging/freebsd/www/signet/distinfo $$t; \
	exit $$ok

# The FreeBSD port's distinfo for this version's tarball, written by freebsd-package.
FBSD_DISTINFO=$(BUILD_DIR)/signet-$(VERSION).fbsd-distinfo

# The FreeBSD package, built on the FreeBSD box in an overlay (~/signet-port) from
# the working tree's tarball; /usr/ports is not touched.  Runs stage-qa,
# check-plist and portlint there.
freebsd-package:
	$(call need,FBSDBOX)
	@mkdir -p $(BUILD_DIR)
	./distfile.sh tar > /dev/null
	@f=signet-$(VERSION).tar.gz; \
	{ echo "TIMESTAMP = `date +%s`"; \
	  echo "SHA256 ($$f) = `sha256sum $(DIST_DIR)/$$f | cut -d' ' -f1`"; \
	  echo "SIZE ($$f) = `stat -c %s $(DIST_DIR)/$$f`"; } > $(FBSD_DISTINFO)
	ssh $(FBSDBOX) 'cat > /tmp/signet-$(VERSION).tar.gz' < $(DIST_DIR)/signet-$(VERSION).tar.gz
	ssh $(FBSDBOX) 'cat > /tmp/signet-$(VERSION).distinfo' < $(FBSD_DISTINFO)
	ssh $(FBSDBOX) 'cat > /tmp/signet-box-build-package.sh' < contrib/packaging/freebsd/box-build-package.sh
	ssh $(FBSDBOX) 'sh /tmp/signet-box-build-package.sh $(VERSION); rc=$$?; rm -f /tmp/signet-box-build-package.sh; exit $$rc'

# The package on the FreeBSD box: install, first steps, reload, upgrades and removal,
# on :8080.  It removes what it installed when it ends.
test-freebsd:
	$(call need,FBSDBOX)
	ssh $(FBSDBOX) 'cat > /tmp/signet-box-test-package.sh' < contrib/packaging/freebsd/box-test-package.sh
	ssh $(FBSDBOX) 'sh /tmp/signet-box-test-package.sh $(VERSION); rc=$$?; rm -f /tmp/signet-box-test-package.sh; exit $$rc'

# Full release flow, run from a clean tree with the feature commits already in:
#
#   make release VERSION=x.y.z [SKIP_PUSH=1] [SKIP_BOX=1] [TESTBOX=user@host]
#
# Order mirrors the release rules: lint+test+compile must pass BEFORE the
# version is bumped; then bump commit, distfile + distinfo commit, tag,
# push branch and tag, and finally `make box`.
# The archives are made once, from the bump commit while the tree is clean, and
# before their checksums enter it: the distinfo commit cannot describe an
# archive that holds itself.  `make box` then builds that same zip
# (DIST_READY=1), and check-dist proves dist/ still matches the tag.
release:
ifeq ($(origin VERSION),command line)
	@echo "releasing signet $(VERSION)"
	@test -n "$(SKIP_BOX)" || test -n "$(TESTBOX)" \
		|| { echo "TESTBOX is not set: set it in local.mk, or give SKIP_BOX=1" >&2; exit 1; }
	@set -e; \
	git diff --quiet && git diff --cached --quiet \
		|| { echo "working tree is not clean - commit the features first"; exit 1; }; \
	echo "$(VERSION)" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+$$' \
		|| { echo "VERSION must look like x.y.z"; exit 1; }; \
	old=`sed -n 's/^VERSION=//p' Makefile`; \
	echo "old version: $$old -> $(VERSION); running lint test build vuln"; \
	$(MAKE) --no-print-directory lint test all; \
	$(MAKE) --no-print-directory vuln \
		|| echo "WARNING: make vuln failed, see above; the release continues"; \
	sed -i 's/version   = "[^"]*"/version   = "$(VERSION)"/' cmd/signet/main.go; \
	sed -i 's/^VERSION=.*/VERSION=$(VERSION)/' Makefile; \
	sed -i 's/:-[0-9][0-9.]*/:-$(VERSION)/' distfile.sh; \
	sed -i 's/^Version: .*/Version: $(VERSION)  /' docs/API.md; \
	old_esc=`printf '%s' "$$old" | sed 's/\./\\\\./g'`; \
	sed -i 's/^\*\*Version:\*\* .*/**Version:** $(VERSION)/' AGENTS.md; \
	sed -i "s/signet-$$old_esc/signet-$(VERSION)/g" contrib/packaging/openbsd/README.md; \
	sed -i "s/signet-[0-9][0-9.]*/signet-$(VERSION)/" contrib/packaging/openbsd/www/signet/Makefile; \
	sed -i 's/^DISTVERSION=.*/DISTVERSION=	$(VERSION)/' contrib/packaging/freebsd/www/signet/Makefile; \
	cl=contrib/packaging/debian/debian/changelog; \
	{ printf 'signet (%s-1) unstable; urgency=medium\n\n  * Release %s.\n\n -- Code <code@obtusenet.com>  %s\n\n' \
		"$(VERSION)" "$(VERSION)" "`LC_ALL=C date -R`"; cat $$cl; } > $$cl.new && mv $$cl.new $$cl; \
	git add -u; \
	git commit -m "$(VERSION): version bump"; \
	echo "creating the archives from the committed tree"; \
	./distfile.sh both > $(BUILD_DIR)/distfile.out; \
	grep -E '^(SHA256|SIZE) ' $(BUILD_DIR)/distfile.out \
		> contrib/packaging/openbsd/www/signet/distinfo; \
	f=signet-$(VERSION).tar.gz; \
	{ echo "TIMESTAMP = `date +%s`"; \
	  echo "SHA256 ($$f) = `sha256sum $(DIST_DIR)/$$f | cut -d' ' -f1`"; \
	  echo "SIZE ($$f) = `stat -c %s $(DIST_DIR)/$$f`"; } > contrib/packaging/freebsd/www/signet/distinfo; \
	git add contrib/packaging/openbsd/www/signet/distinfo contrib/packaging/freebsd/www/signet/distinfo; \
	git commit -m "port: new distfile checksum"; \
	$(MAKE) --no-print-directory check-dist; \
	git tag -a "v$(VERSION)" -m "signet $(VERSION)"; \
	echo "tagged v$(VERSION)"
	@if test -n "$(SKIP_PUSH)"; then echo "SKIP_PUSH set - not pushing"; else git push origin HEAD "refs/tags/v$(VERSION)"; fi
	@if test -n "$(SKIP_BOX)"; then echo "SKIP_BOX set - not building on the box"; else $(MAKE) --no-print-directory box DIST_READY=1; fi
	@$(MAKE) --no-print-directory check-dist
	@echo "publish $(DIST_DIR)/signet-$(VERSION).{tar.gz,zip,spdx.json} with v$(VERSION)"
else
	@echo "usage: make release VERSION=x.y.z [SKIP_PUSH=1] [SKIP_BOX=1] [TESTBOX=user@host]"; exit 1
endif
