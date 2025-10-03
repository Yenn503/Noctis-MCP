#!/bin/bash
# Noctis-MCP Server Startup Script
# Run this before using Noctis in Cursor

echo "🌙 Starting Noctis-MCP Server..."
echo "================================"

cd "$(dirname "$0")"

# Activate virtual environment
echo "[*] Activating virtual environment..."
source venv/bin/activate

# Check if server module exists
if [ ! -f "server/noctis_server.py" ]; then
    echo "[!] Error: server/noctis_server.py not found!"
    exit 1
fi

# Start the server
echo "[*] Starting API server on http://localhost:8888"
echo "[*] Press Ctrl+C to stop"
echo ""

python server/noctis_server.py

echo ""
echo "[*] Server stopped"

