#!/bin/bash
if [ -f /tmp/cloudflared.pid ]; then
    kill "$(cat /tmp/cloudflared.pid)" 2>/dev/null
    rm /tmp/cloudflared.pid
    echo "Tunnel stopped"
else
    pkill cloudflared 2>/dev/null
    echo "Tunnel stopped (by name)"
fi
