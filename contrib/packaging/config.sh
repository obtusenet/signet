#!/bin/sh
# Copyright (c) 2026 Obtuse Networking LLC
# SPDX-License-Identifier: MIT
#
# Writes an OS's sample configuration to standard output: config/example.yaml
# with only the settings that differ by OS changed.  Run from the repository
# root; `make configs` writes every copy, and tests/config_copies_test.sh checks
# that the committed copies are current.
#
#   contrib/packaging/config.sh openbsd|freebsd|debian

set -eu
os=${1:?usage: config.sh openbsd|freebsd|debian}

case "$os" in
openbsd)
	listen=':9090'
	web=/var/www/signet
	data=/var/www/signet
	syslog='log_syslog: true      # the rc script does not redirect stdout, so syslog is where the log goes'
	;;
freebsd)
	listen=':8080'
	web=/usr/local/etc/signet
	data=/var/db/signet
	syslog='log_syslog: true      # through syslog to /var/log/signet.log'
	;;
debian)
	listen=':8080'
	web=/etc/signet
	data=/var/lib/signet
	syslog='log_syslog: false     # systemd: the journal collects stdout and stderr'
	;;
*)
	echo "config.sh: unknown OS: $os" >&2
	exit 2
	;;
esac

# Each pattern must match exactly one line; config_copies_test.sh checks that only
# these lines differ from the example.
sed \
	-e "s|^listen: \"[^\"]*\"|listen: \"$listen\"|" \
	-e "s|^templates_dir: \"[^\"]*\"|templates_dir: \"$web/templates\"|" \
	-e "s|^static_dir: \"[^\"]*\"|static_dir: \"$web/static\"|" \
	-e "s|^database_path: \"[^\"]*\"|database_path: \"$data/sessions.db\"|" \
	-e "s|^csv_path: \"[^\"]*\"|csv_path: \"$data/users.csv\"|" \
	-e "s|^log_syslog: .*|$syslog|" \
	config/example.yaml
