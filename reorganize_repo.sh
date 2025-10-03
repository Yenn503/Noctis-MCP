#!/bin/bash
# Noctis-MCP Repository Reorganization Script
# This script reorganizes the repository structure for better organization

set -e

echo "╔════════════════════════════════════════════════════════════════╗"
echo "║      NOCTIS-MCP REPOSITORY REORGANIZATION                      ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""

# Create backup first
echo "[1/8] Creating backup..."
BACKUP_DIR="../Noctis-MCP-backup-$(date +%Y%m%d-%H%M%S)"
cp -r . "$BACKUP_DIR"
echo "✓ Backup created at: $BACKUP_DIR"
echo ""

# Create new directory structure
echo "[2/8] Creating new directory structure..."
mkdir -p src
mkdir -p data/techniques/examples data/config
mkdir -p build/{compiled,test_output,logs}
mkdir -p scripts/setup
mkdir -p tests/unit tests/integration tests/fixtures
echo "✓ New directories created"
echo ""

# Move source code to src/
echo "[3/8] Moving source code..."
mv c2_adapters src/ 2>/dev/null || true
mv compilation src/ 2>/dev/null || true
mv server src/ 2>/dev/null || true
mv noctis_mcp_client src/ 2>/dev/null || true
mv utils src/ 2>/dev/null || true
echo "✓ Source code moved to src/"
echo ""

# Move data files
echo "[4/8] Moving data files..."
mv techniques data/ 2>/dev/null || true
mv Examples data/techniques/examples 2>/dev/null || true
mv config.yaml data/config/ 2>/dev/null || true
echo "✓ Data files moved to data/"
echo ""

# Move build outputs
echo "[5/8] Moving build outputs..."
mv compiled/* build/compiled/ 2>/dev/null || true
rmdir compiled 2>/dev/null || true
mv test_output/* build/test_output/ 2>/dev/null || true
rmdir test_output 2>/dev/null || true
mv logs/* build/logs/ 2>/dev/null || true
rmdir logs 2>/dev/null || true
mv *.log build/logs/ 2>/dev/null || true
echo "✓ Build outputs moved to build/"
echo ""

# Move scripts
echo "[6/8] Moving scripts..."
mv setup.sh scripts/setup/ 2>/dev/null || true
mv setup.ps1 scripts/setup/ 2>/dev/null || true
mv setup.bat scripts/setup/ 2>/dev/null || true
mv start_noctis.sh scripts/ 2>/dev/null || true
mv verify_setup.py scripts/ 2>/dev/null || true
echo "✓ Scripts moved to scripts/"
echo ""

# Move test files (keep test_all.py in root)
echo "[7/8] Organizing test files..."
if [ -d "tests" ]; then
    # Move existing test files to appropriate subdirectories
    find tests -name "test_c2*.py" -exec mv {} tests/integration/ 2>/dev/null \; || true
    find tests -name "test_*_integration.py" -exec mv {} tests/integration/ 2>/dev/null \; || true
    find tests -name "test_*.py" ! -name "test_*_integration.py" ! -name "test_c2*.py" -exec mv {} tests/unit/ 2>/dev/null \; || true
fi
echo "✓ Test files organized"
echo ""

# Update .gitignore
echo "[8/8] Updating .gitignore..."
cat > .gitignore << 'GITIGNORE'
# Python
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
venv/
env/
ENV/

# Build outputs
build/
*.exe
*.dll
*.bin
*.o

# Logs
*.log
logs/

# IDE
.vscode/
.idea/
*.swp
*.swo

# OS
.DS_Store
Thumbs.db

# Project specific
compiled/
test_output/
noctis_server.log

# Temporary files
*.tmp
*.temp
GITIGNORE

echo "✓ .gitignore updated"
echo ""

echo "╔════════════════════════════════════════════════════════════════╗"
echo "║                  REORGANIZATION COMPLETE!                      ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""
echo "Next steps:"
echo "1. Update import paths in Python files:"
echo "   - Change 'from server' to 'from src.server'"
echo "   - Change 'from c2_adapters' to 'from src.c2_adapters'"
echo "   - etc."
echo ""
echo "2. Update config paths in code:"
echo "   - config.yaml → data/config/config.yaml"
echo "   - techniques/ → data/techniques/"
echo ""
echo "3. Test the changes:"
echo "   python test_all.py"
echo ""
echo "4. Commit if everything works:"
echo "   git add -A"
echo "   git commit -m 'Reorganize repository structure'"
echo ""
echo "Backup location: $BACKUP_DIR"

