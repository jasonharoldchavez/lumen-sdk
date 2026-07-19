#!/bin/bash

echo "====================================================="
echo "       LUMEN ENTERPRISE NETWORK ORCHESTRATOR         "
echo "====================================================="

# 1. Automated Process Cleanup
echo "[*] Scanning for zombie node processes..."
pkill -f "python3 lumen_node_network.py" 2>/dev/null
pkill -f "python3 dashboard.py" 2>/dev/null
sleep 1

# 2. Automated State Reset
echo "[*] Clearing data states to prevent constraint collisions..."
rm -f network_node_*.db
sleep 0.5

# 3. Background Daemon Deployment
echo "[*] Deploying Node Alpha (Port 8001) as background daemon..."
python3 lumen_node_network.py 8001 > node_8001.log 2>&1 &

echo "[*] Deploying Node Beta (Port 8002) as background daemon..."
python3 lumen_node_network.py 8002 > node_8002.log 2>&1 &

# Wait briefly for ports to bind open
sleep 2

echo "[✔] Cluster successfully deployed!"
echo "====================================================="
echo "[*] Launching Real-Time Network Ledger Monitor..."
echo "====================================================="
sleep 1

# 4. Attach Live Monitor to foreground
python3 dashboard.py
