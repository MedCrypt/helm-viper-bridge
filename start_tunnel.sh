#!/bin/bash
nohup cloudflared tunnel run helm-api > tunnel.log 2>&1 &
echo $! > /tmp/cloudflared.pid
echo "Tunnel started (PID: $(cat /tmp/cloudflared.pid))"
echo "  Public: https://helm-api.com"
echo "  Docs:   https://helm-api.com/docs"
