#!/bin/bash
echo "================================"
echo "Server & Tunnel Status"
echo "================================"
echo ""

if [ -f /tmp/fastapi_server.pid ] && kill -0 "$(cat /tmp/fastapi_server.pid)" 2>/dev/null; then
    echo "FastAPI Server: Running (PID: $(cat /tmp/fastapi_server.pid))"
    echo "  http://localhost:8000"
else
    echo "FastAPI Server: Not running"
fi

echo ""

if [ -f /tmp/cloudflared.pid ] && kill -0 "$(cat /tmp/cloudflared.pid)" 2>/dev/null; then
    echo "Cloudflare Tunnel: Running (PID: $(cat /tmp/cloudflared.pid))"
    echo "  https://helm-api.com"
else
    echo "Cloudflare Tunnel: Not running"
fi

echo ""
echo "================================"
