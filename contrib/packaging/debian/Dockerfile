# Copyright (c) 2026 Obtuse Networking LLC
# SPDX-License-Identifier: MIT
#
# The Debian 13 build environment for the package: debhelper, lintian, and Go 1.26
# from trixie-backports (trixie's own Go is 1.24).  build.sh builds this image and
# runs the build in it as the calling user, not root.
FROM debian:13
RUN echo 'deb http://deb.debian.org/debian trixie-backports main' > /etc/apt/sources.list.d/backports.list \
 && apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      build-essential debhelper devscripts lintian fakeroot ca-certificates \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends -t trixie-backports golang-1.26-go \
 && rm -rf /var/lib/apt/lists/*
