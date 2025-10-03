#!/bin/bash
# Safe Repository Cleanup - Phase 1
# This script only moves non-code files, no breaking changes!

echo "╔════════════════════════════════════════════════════════════════╗"
echo "║          SAFE REPOSITORY CLEANUP (Phase 1)                     ║"
echo "║          No code changes - just organizing files               ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""

# Create new directories
echo "[1/4] Creating directory structure..."
mkdir -p build/compiled
mkdir -p build/test_output
mkdir -p build/logs
mkdir -p scripts/setup
echo "✓ Directories created"
echo ""

# Move build outputs
echo "[2/4] Moving build outputs..."
if [ -d "compiled" ] && [ "$(ls -A compiled 2>/dev/null)" ]; then
    mv compiled/* build/compiled/ 2>/dev/null && echo "  ✓ Moved compiled binaries"
    rmdir compiled 2>/dev/null && echo "  ✓ Removed old compiled/ directory"
fi

if [ -d "test_output" ] && [ "$(ls -A test_output 2>/dev/null)" ]; then
    mv test_output/* build/test_output/ 2>/dev/null && echo "  ✓ Moved test outputs"
    rmdir test_output 2>/dev/null && echo "  ✓ Removed old test_output/ directory"
fi

if [ -d "logs" ] && [ "$(ls -A logs 2>/dev/null)" ]; then
    mv logs/* build/logs/ 2>/dev/null && echo "  ✓ Moved log directory"
    rmdir logs 2>/dev/null && echo "  ✓ Removed old logs/ directory"
fi

# Move loose log files
find . -maxdepth 1 -name "*.log" -exec mv {} build/logs/ \; 2>/dev/null && echo "  ✓ Moved root log files" || true
echo ""

# Move scripts
echo "[3/4] Organizing scripts..."
[ -f "setup.sh" ] && mv setup.sh scripts/setup/ && echo "  ✓ Moved setup.sh"
[ -f "setup.ps1" ] && mv setup.ps1 scripts/setup/ && echo "  ✓ Moved setup.ps1"
[ -f "setup.bat" ] && mv setup.bat scripts/setup/ && echo "  ✓ Moved setup.bat"
[ -f "start_noctis.sh" ] && mv start_noctis.sh scripts/ && echo "  ✓ Moved start_noctis.sh"
[ -f "verify_setup.py" ] && mv verify_setup.py scripts/ && echo "  ✓ Moved verify_setup.py"
echo ""

# Update .gitignore
echo "[4/4] Updating .gitignore..."
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
*.egg-info/
dist/
build/

# Logs
*.log

# IDE
.vscode/
.idea/
*.swp
*.swo

# OS
.DS_Store
Thumbs.db
*.bak

# Project specific - Old locations (for migration)
compiled/
test_output/
logs/

# Build directory
build/*
!build/.gitkeep

# Temporary
*.tmp
*.temp
GITIGNORE

# Create .gitkeep files
touch build/compiled/.gitkeep
touch build/test_output/.gitkeep
touch build/logs/.gitkeep

echo "✓ .gitignore updated"
echo ""

echo "╔════════════════════════════════════════════════════════════════╗"
echo "║                   CLEANUP COMPLETE!                            ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""
echo "Summary of changes:"
echo "  ✓ Build outputs moved to build/"
echo "  ✓ Scripts organized in scripts/"
echo "  ✓ Logs consolidated in build/logs/"
echo "  ✓ .gitignore updated"
echo ""
echo "Files moved (no code changes!):"
echo "  • compiled/* → build/compiled/"
echo "  • test_output/* → build/test_output/"
echo "  • logs/* → build/logs/"
echo "  • *.log → build/logs/"
echo "  • setup scripts → scripts/setup/"
echo ""
echo "Next steps:"
echo "  1. Test that everything works: python test_all.py"
echo "  2. Check the repo looks good: ls -la"
echo "  3. If OK, commit: git add -A && git commit -m 'Organize repo: move build outputs and scripts'"
echo ""
echo "Note: Update installation docs to reference scripts/setup/"

