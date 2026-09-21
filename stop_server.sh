#!/bin/bash
# Kill the op run wrapper and the Python child process
if [ -f /tmp/fastapi_server.pid ]; then
    kill "$(cat /tmp/fastapi_server.pid)" 2>/dev/null
    rm /tmp/fastapi_server.pid
fi
# Always kill by port to catch the Python child process
lsof -ti:8000 | xargs kill -9 2>/dev/null
echo "Server stopped"
