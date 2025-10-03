#!/bin/bash
#
# Noctis-MCP Automated Setup Script
# ==================================
# Automatically sets up Noctis-MCP environment
#

set -e  # Exit on error

# Get the repository root (2 levels up from this script)
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
REPO_ROOT="$( cd "$SCRIPT_DIR/../.." && pwd )"

# Change to repository root
cd "$REPO_ROOT"

echo "🚀 Noctis-MCP Automated Setup"
echo "=============================="
echo ""
echo "📂 Repository: $REPO_ROOT"
echo ""

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Detect OS
OS=$(uname -s)
echo "📋 Detected OS: $OS"
echo ""

# Step 1: Check Python version
echo "🐍 Checking Python version..."
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
    echo -e "${GREEN}✓${NC} Python $PYTHON_VERSION found"
else
    echo -e "${RED}✗${NC} Python 3 not found!"
    echo "Please install Python 3.11+ first"
    exit 1
fi

# Verify Python 3.11+
REQUIRED_VERSION="3.11"
if python3 -c "import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)"; then
    echo -e "${GREEN}✓${NC} Python version is 3.11 or higher"
else
    echo -e "${YELLOW}⚠${NC} Warning: Python 3.11+ recommended (current: $PYTHON_VERSION)"
fi
echo ""

# Step 2: Create virtual environment
echo "📦 Creating virtual environment..."
if [ -d "venv" ]; then
    echo -e "${YELLOW}⚠${NC} Virtual environment already exists"
    read -p "Recreate it? (y/N) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        rm -rf venv
        python3 -m venv venv
        echo -e "${GREEN}✓${NC} Virtual environment recreated"
    fi
else
    python3 -m venv venv
    echo -e "${GREEN}✓${NC} Virtual environment created"
fi
echo ""

# Step 3: Activate virtual environment and install dependencies
echo "📥 Installing Python dependencies..."
source venv/bin/activate

# Upgrade pip
pip install --upgrade pip > /dev/null 2>&1
echo -e "${GREEN}✓${NC} pip upgraded"

# Install dependencies
if [ -f "requirements.txt" ]; then
    pip install -r requirements.txt > /dev/null 2>&1
    echo -e "${GREEN}✓${NC} Dependencies installed"
else
    echo -e "${RED}✗${NC} requirements.txt not found!"
    exit 1
fi
echo ""

# Step 4: Check compiler (OS-specific)
echo "🔨 Checking MinGW compiler..."

if [[ "$OS" == "Linux" ]]; then
    # Linux: Auto-install via apt
    if command -v x86_64-w64-mingw32-gcc &> /dev/null; then
        MINGW_VERSION=$(x86_64-w64-mingw32-gcc --version | head -n1)
        echo -e "${GREEN}✓${NC} MinGW x64 found: $MINGW_VERSION"
    else
        echo -e "${YELLOW}⚠${NC} MinGW x64 not found"
        read -p "Install MinGW-w64? (Y/n) " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Nn]$ ]]; then
            sudo apt update && sudo apt install mingw-w64 -y
            echo -e "${GREEN}✓${NC} MinGW installed"
        fi
    fi
    
    if command -v i686-w64-mingw32-gcc &> /dev/null; then
        echo -e "${GREEN}✓${NC} MinGW x86 found"
    fi

elif [[ "$OS" == "Darwin" ]]; then
    # macOS: Check if installed, guide to Homebrew if not
    if command -v x86_64-w64-mingw32-gcc &> /dev/null; then
        MINGW_VERSION=$(x86_64-w64-mingw32-gcc --version | head -n1)
        echo -e "${GREEN}✓${NC} MinGW x64 found: $MINGW_VERSION"
    else
        echo -e "${YELLOW}⚠${NC} MinGW not found!"
        echo ""
        echo "On macOS, install MinGW via Homebrew:"
        echo ""
        echo "  brew install mingw-w64"
        echo ""
        echo "If you don't have Homebrew, install it first:"
        echo "  /bin/bash -c \"\$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\""
        echo ""
        read -p "Press Enter to continue without MinGW (you can install it later)..." -r
    fi
    
    if command -v i686-w64-mingw32-gcc &> /dev/null; then
        echo -e "${GREEN}✓${NC} MinGW x86 found"
    fi

else
    echo -e "${YELLOW}⚠${NC} Unknown OS: $OS"
    echo "MinGW installation may require manual setup"
fi

echo ""

# Step 5: Run tests
echo "🧪 Running test suite..."
if python -m pytest tests/ -v --tb=short > /dev/null 2>&1; then
    TEST_COUNT=$(python -m pytest tests/ --co -q 2>/dev/null | grep -c "test_" || echo "0")
    echo -e "${GREEN}✓${NC} All tests passed ($TEST_COUNT tests)"
else
    echo -e "${YELLOW}⚠${NC} Some tests failed (this might be OK if C2 servers aren't running)"
fi
echo ""

# Step 6: Verify imports
echo "🔍 Verifying installation..."

# Test MCP client
if python -c "from noctis_mcp_client.noctis_mcp import mcp" 2>/dev/null; then
    echo -e "${GREEN}✓${NC} MCP client working"
else
    echo -e "${RED}✗${NC} MCP client import failed"
fi

# Test C2 adapters
if python -c "from c2_adapters import SliverAdapter, HavocAdapter, MythicAdapter" 2>/dev/null; then
    echo -e "${GREEN}✓${NC} C2 adapters working"
else
    echo -e "${RED}✗${NC} C2 adapters import failed"
fi

# Test compiler
if python -c "from compilation import get_compiler" 2>/dev/null; then
    echo -e "${GREEN}✓${NC} Compilation module working"
else
    echo -e "${RED}✗${NC} Compilation module import failed"
fi

# Test server
if python -c "from server.noctis_server import app" 2>/dev/null; then
    echo -e "${GREEN}✓${NC} Flask server working"
else
    echo -e "${RED}✗${NC} Flask server import failed"
fi

# Verify technique database
TECHNIQUE_COUNT=$(python -c "import json; print(json.load(open('techniques/metadata/index.json'))['total_techniques'])" 2>/dev/null)
if [ ! -z "$TECHNIQUE_COUNT" ]; then
    echo -e "${GREEN}✓${NC} Technique database loaded: ${TECHNIQUE_COUNT} unique techniques"
else
    echo -e "${YELLOW}⚠${NC} Technique database not found (run: python utils/technique_indexer.py)"
fi
echo ""

# Step 7: Final summary
echo "========================================="
echo -e "${GREEN}✅ Noctis-MCP Setup Complete!${NC}"
echo "========================================="
echo ""
echo "📚 Next steps:"
echo "  1. Activate venv:     source venv/bin/activate"
echo "  2. Start server:      python server/noctis_server.py"
echo "  3. Run verification:  python verify_setup.py"
echo "  4. Read quickstart:   cat QUICKSTART.md"
echo ""
echo "🎯 Optional C2 setup:"
echo "  - Sliver:  curl https://sliver.sh/install | sudo bash"
echo "  - Havoc:   See C2 docs/HAVOC_INTEGRATION.md"
echo "  - Mythic:  See C2 docs/MYTHIC_INTEGRATION.md"
echo ""
echo "📖 Documentation:"
echo "  - Setup guide:        SETUP.md"
echo "  - Quick reference:    QUICK_REFERENCE.md"
echo "  - Documentation map:  DOCUMENTATION_MAP.md"
echo ""
echo "🚀 Happy hacking with Noctis-MCP!"

