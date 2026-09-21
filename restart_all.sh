#!/bin/bash
cd "$(dirname "$0")"
echo "Restarting server and tunnel..."
./stop_server.sh
./stop_tunnel.sh
sleep 2
./start_server.sh
sleep 2
./start_tunnel.sh
echo "Restart complete"
