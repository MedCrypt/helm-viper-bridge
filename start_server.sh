#!/bin/bash
cd "$(dirname "$0")"
source venv/bin/activate
nohup op run --env-file .env -- python fastapi_server.py >> server.log 2>&1 &
echo $! > /tmp/fastapi_server.pid
echo "Server started (PID: $(cat /tmp/fastapi_server.pid))"
echo "  Local: http://localhost:8000"
echo "  Docs:  http://localhost:8000/docs"
