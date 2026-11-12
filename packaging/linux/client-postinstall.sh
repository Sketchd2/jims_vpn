#!/bin/sh
# Runs after install and after upgrade.
systemd-sysusers /usr/lib/sysusers.d/jimsvpn.conf 2>/dev/null || groupadd -rf jimsvpn 2>/dev/null || true
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload
    systemctl enable jvpn.service >/dev/null 2>&1 || true
    systemctl restart jvpn.service || true
fi
echo "JimsVPN installed. Join a network with: sudo jvpn join <token>"
echo "To use jvpn without sudo: sudo usermod -aG jimsvpn \$USER (then log in again)"
