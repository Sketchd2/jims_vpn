#!/bin/sh
# Runs after install and after upgrade.
systemd-sysusers /usr/lib/sysusers.d/jimsvpn-hub.conf 2>/dev/null || useradd -r -d /var/lib/jimsvpn-hub -s /usr/sbin/nologin jimsvpn-hub 2>/dev/null || true
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload
    systemctl enable jvpn-hub.service >/dev/null 2>&1 || true
    if [ -f /var/lib/jimsvpn-hub/hub.json ]; then
        systemctl restart jvpn-hub.service || true
    else
        echo "JimsVPN hub installed. Finish setup with:"
        echo "  sudo jvpn-hub init --public-host <this server's DNS name or IP>"
        echo "  sudo systemctl start jvpn-hub"
    fi
fi
exit 0
