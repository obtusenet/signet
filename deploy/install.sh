#!/bin/bash
# Copyright (c) 2026 Obtuse Networking LLC
# SPDX-License-Identifier: MIT
set -euo pipefail

# Signet Installation Script
# This script installs Signet for direct deployment on Linux systems.

SIGNET_USER="signet"
SIGNET_GROUP="signet"
SIGNET_HOME="/opt/signet"
SIGNET_DATA="/var/lib/signet"
SIGNET_LOGS="/var/log/signet"
SIGNET_CONFIG="/etc/signet"
SIGNET_SERVICE="/etc/systemd/system/signet.service"
SIGNET_DOCS="/usr/share/doc/signet"

echo "=== Signet Installation ==="
echo ""

# Check for root privileges
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" 
   exit 1
fi

# Create group and user
echo "Creating signet group and user..."
groupadd -r ${SIGNET_GROUP} 2>/dev/null || true
useradd -r -g ${SIGNET_GROUP} -d ${SIGNET_HOME} -s /usr/sbin/nologin ${SIGNET_USER} 2>/dev/null || true

# Create directories
echo "Creating directories..."
mkdir -p ${SIGNET_HOME}
mkdir -p ${SIGNET_DATA}
mkdir -p ${SIGNET_LOGS}
mkdir -p ${SIGNET_CONFIG}

# Copy binary
# To a new name and then over the old one, so a running service does not block it.
echo "Installing binary..."
if [[ -f "build/signet" ]]; then
    cp build/signet ${SIGNET_HOME}/signet.new
    chmod 755 ${SIGNET_HOME}/signet.new
    mv -f ${SIGNET_HOME}/signet.new ${SIGNET_HOME}/signet
else
    echo "Error: build/signet not found. Run 'make' first."
    exit 1
fi

chown ${SIGNET_USER}:${SIGNET_GROUP} ${SIGNET_HOME}

# Copy example config
# Never over an existing file: it holds the site's settings and cookie_secret.
if [[ -e ${SIGNET_CONFIG}/config.yaml ]]; then
    echo "Keeping existing ${SIGNET_CONFIG}/config.yaml"
else
    echo "Installing example configuration..."
    cp config/example.yaml ${SIGNET_CONFIG}/config.yaml
    chown root:${SIGNET_GROUP} ${SIGNET_CONFIG}/config.yaml
    chmod 640 ${SIGNET_CONFIG}/config.yaml
fi

# Copy examples: claims hooks and web-server sample configs
echo "Installing examples..."
mkdir -p ${SIGNET_DOCS}/examples
cp -r examples/hooks ${SIGNET_DOCS}/examples/
cp -r examples/radius ${SIGNET_DOCS}/examples/
cp -r examples/web-servers ${SIGNET_DOCS}/examples/
chmod 755 ${SIGNET_DOCS}/examples/hooks/claims-hook.sh ${SIGNET_DOCS}/examples/hooks/claims-hook.py ${SIGNET_DOCS}/examples/hooks/radius-claims.py ${SIGNET_DOCS}/examples/hooks/radius-claims.sh ${SIGNET_DOCS}/examples/hooks/test-hooks.sh 2>/dev/null || true
chmod 644 ${SIGNET_DOCS}/examples/hooks/README.md ${SIGNET_DOCS}/examples/web-servers/README.md 2>/dev/null || true
install -m 644 LICENSE ${SIGNET_DOCS}/LICENSE

# This version's web files, then the working copies the config reads.
# install-web.sh replaces only files that have not been edited.
echo "Installing templates and static files..."
config_path() { # key default
    local value
    value=$(sed -n "s/^$1:[[:space:]]*\"\{0,1\}\([^\"#]*\).*/\1/p" ${SIGNET_CONFIG}/config.yaml | head -1)
    value=${value%"${value##*[![:space:]]}"}
    if [[ $value == /* ]]; then echo "$value"; else echo "$2"; fi
}
rm -rf ${SIGNET_DOCS}/examples/web
mkdir -p ${SIGNET_DOCS}/examples/web
cp -r web/templates web/static ${SIGNET_DOCS}/examples/web/
chmod -R a+rX ${SIGNET_DOCS}/examples/web
TEMPLATES_DIR=$(config_path templates_dir ${SIGNET_CONFIG}/templates)
STATIC_DIR=$(config_path static_dir ${SIGNET_CONFIG}/static)
deploy/install-web.sh ${SIGNET_DOCS}/examples/web/templates "$TEMPLATES_DIR" ${SIGNET_CONFIG}/.web-templates.sha256
deploy/install-web.sh ${SIGNET_DOCS}/examples/web/static "$STATIC_DIR" ${SIGNET_CONFIG}/.web-static.sha256

# Copy man pages
echo "Installing man pages..."
for section in 1 5 7; do
    mkdir -p /usr/share/man/man${section}
    install -m 644 man/man${section}/*.${section} /usr/share/man/man${section}/
done

# Copy systemd service file
echo "Installing systemd service..."
cp deploy/signet.service ${SIGNET_SERVICE}

# Reload systemd
echo "Reloading systemd..."
systemctl daemon-reload

# Set data directory permissions
chown ${SIGNET_USER}:${SIGNET_GROUP} ${SIGNET_DATA}
chmod 750 ${SIGNET_DATA}

chown ${SIGNET_USER}:${SIGNET_GROUP} ${SIGNET_LOGS}
chmod 750 ${SIGNET_LOGS}

# A running service moves to this version; a stopped one stays stopped.
if systemctl is-active --quiet signet; then
    echo "Restarting signet..."
    systemctl restart signet || { echo "signet failed to restart; see: journalctl -u signet" >&2; exit 1; }
fi

echo ""
echo "=== Installation Complete ==="
echo ""
if [[ ! -e ${SIGNET_CONFIG}/.installed ]]; then
    echo "Next steps:"
    echo "1. Edit configuration: vi ${SIGNET_CONFIG}/config.yaml"
    echo "   Set cookie_secret (required): openssl rand -hex 32"
    echo "2. Enable and start the service:"
    echo "   systemctl enable signet"
    echo "   systemctl start signet"
    echo "3. Check service status: systemctl status signet"
    echo "4. View logs: journalctl -u signet -f"
    echo ""
    touch ${SIGNET_CONFIG}/.installed
fi
PROGRAM=$(config_path "  program" /usr/sbin/sendmail)
if [[ ! -x $PROGRAM ]]; then
    echo "Mail: $PROGRAM is not installed, so email PINs cannot be sent. Install a mail"
    echo "system that provides it, or set mail.program in ${SIGNET_CONFIG}/config.yaml."
    echo ""
fi
