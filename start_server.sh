#!/bin/bash
# Noctis-MCP Server Startup Script
#
# This ensures the server runs with venv python where RAG deps are installed

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "======================================================================"
echo "                   NOCTIS-MCP SERVER STARTUP"
echo "======================================================================"
echo ""

# Check if venv exists
if [ ! -d "venv" ]; then
    echo -e "${RED}❌ Virtual environment not found${NC}"
    echo ""
    echo "Run setup first:"
    echo "  ./scripts/setup/setup.sh"
    exit 1
fi

# Activate venv
source venv/bin/activate

# Check RAG dependencies
echo "Checking dependencies..."
python3 -c "import chromadb; import sentence_transformers" 2>/dev/null
if [ $? -ne 0 ]; then
    echo -e "${RED}❌ RAG dependencies missing${NC}"
    echo ""
    echo "Installing..."
    pip install chromadb sentence-transformers
fi

echo -e "${GREEN}✅ All dependencies installed${NC}"
echo ""

# Start server
echo "Starting Noctis-MCP server..."
echo ""
python3 server/noctis_server.py "$@"
