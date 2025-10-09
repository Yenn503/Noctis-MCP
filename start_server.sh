#!/bin/bash
# Start Noctis MCP Server v3.0

echo "========================================"
echo "  Noctis MCP Server v3.0"
echo "  Stageless Loader Automation"
echo "========================================"
echo ""

# Check dependencies
echo "[*] Checking dependencies..."

# Check Python
if ! command -v python3 &> /dev/null; then
    echo "[!] Python3 not found. Install it first."
    exit 1
fi

# Check Flask
if ! python3 -c "import flask" 2>/dev/null; then
    echo "[!] Flask not installed. Installing..."
    pip install flask
fi

# Check MinGW
if ! command -v x86_64-w64-mingw32-gcc &> /dev/null; then
    echo "[!] WARNING: mingw-w64 not found. Install with:"
    echo "    sudo apt install mingw-w64"
fi

# Check MSFVenom
if ! command -v msfvenom &> /dev/null; then
    echo "[!] WARNING: msfvenom not found. Install metasploit-framework"
fi

echo "[+] Dependencies OK"
echo ""

# Start server
echo "[*] Starting server on http://localhost:8888..."
echo ""

cd "$(dirname "$0")"
python3 server/noctis_server.py
