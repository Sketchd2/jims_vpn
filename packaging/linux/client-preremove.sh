#!/bin/sh
[ "$1" = "upgrade" ] && exit 0
if [ -d /run/systemd/system ]; then
    systemctl disable --now jvpn.service >/dev/null 2>&1 || true
fi
exit 0
