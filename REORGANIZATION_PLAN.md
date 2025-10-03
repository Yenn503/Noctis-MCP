# Repository Reorganization Plan

## Quick Assessment

**Current Issues:**
- ❌ 21 files in root directory (should be ~5-6)
- ❌ Logs scattered in multiple places
- ❌ Build outputs mixed with source
- ❌ No clear separation of concerns

## Recommended Approach: **Incremental (Safer)**

Don't reorganize everything at once. Do it step-by-step to avoid breaking things.

---

## Phase 1: Immediate Wins (No Breaking Changes)

### Step 1.1: Move Build Outputs
```bash
# Create build directory structure
mkdir -p build/{compiled,test_output,logs}

# Move build outputs (won't break anything)
mv compiled/* build/compiled/ 2>/dev/null || true
mv test_output/* build/test_output/ 2>/dev/null || true
mv *.log build/logs/ 2>/dev/null || true
mv logs/* build/logs/ 2>/dev/null || true
```

**Update `.gitignore`:**
```
build/
*.exe
*.dll
*.log
test_output/
compiled/
```

**Result:** Root directory cleaner, no code changes needed

---

### Step 1.2: Organize Scripts
```bash
# Create scripts directory
mkdir -p scripts/setup

# Move setup scripts
mv setup.sh setup.ps1 setup.bat scripts/setup/
mv start_noctis.sh verify_setup.py scripts/
```

**Update README.md installation section:**
```bash
# Old: ./setup.sh
# New: ./scripts/setup/setup.sh
```

**Result:** Setup scripts organized, minimal impact

---

### Step 1.3: Better .gitignore
Create comprehensive `.gitignore`:
```
# Python
__pycache__/
*.py[cod]
venv/

# Build outputs
build/
*.exe
*.dll
*.bin

# Logs
*.log
logs/

# IDE
.vscode/
.idea/

# Temp
*.tmp
noctis_server.log
```

---

## Phase 2: Data Organization (Medium Risk)

### Step 2.1: Create Data Directory
```bash
mkdir -p data/techniques data/config

# Move data files
mv techniques data/
mv Examples data/techniques/examples
mv config.yaml data/config/
```

### Step 2.2: Update Code References
Update these files to use new paths:

**Files to update:**
- `server/noctis_server.py` - Update config.yaml path
- `server/code_assembler.py` - Update techniques path  
- `utils/technique_indexer.py` - Update Examples path

**Example changes:**
```python
# Before
TECHNIQUE_DIR = "techniques/metadata"

# After  
TECHNIQUE_DIR = "data/techniques/metadata"
```

---

## Phase 3: Source Organization (Higher Risk)

### Step 3.1: Create src/ Directory
```bash
mkdir src
mv c2_adapters compilation server noctis_mcp_client utils src/
```

### Step 3.2: Update All Imports
This is the time-consuming part. Update imports in all files:

```python
# Before
from server.noctis_server import app
from c2_adapters import SliverAdapter

# After
from src.server.noctis_server import app
from src.c2_adapters import SliverAdapter
```

### Step 3.3: Add `__init__.py` to src/
```bash
touch src/__init__.py
```

---

## Alternative: Minimal Cleanup (Safest)

If you don't want to break anything, just do these simple moves:

```bash
# 1. Create directories
mkdir -p build scripts/setup

# 2. Move non-code files only
mv *.exe build/ 2>/dev/null || true
mv test_output build/
mv compiled build/
mv *.log build/logs/ 2>/dev/null || true

# 3. Move scripts
mv setup.* scripts/setup/
mv start_noctis.sh scripts/

# 4. Update .gitignore
echo "build/" >> .gitignore
echo "*.log" >> .gitignore

# Done! No code changes needed.
```

---

## My Recommendation: **Minimal Cleanup First**

**For your project, I recommend:**

1. ✅ **DO NOW** (Phase 1): Move build outputs & scripts
   - Zero risk
   - Immediate improvement
   - 10 minutes

2. ⚠️ **DO LATER** (Phase 2): Move data files
   - Low risk
   - Need to update ~5 file paths
   - 30 minutes

3. ❌ **DON'T DO YET** (Phase 3): Reorganize source to src/
   - High risk
   - Need to update 50+ imports
   - 2-3 hours + testing
   - **Only do this if planning major refactor**

---

## Quick Start: Run This Now

```bash
# Safe cleanup that won't break anything
mkdir -p build/{compiled,test_output,logs}
mkdir -p scripts/setup

# Move build outputs
mv compiled/* build/compiled/ 2>/dev/null || true
mv test_output/* build/test_output/ 2>/dev/null || true  
mv *.log build/logs/ 2>/dev/null || true

# Move scripts
mv setup.sh setup.ps1 setup.bat scripts/setup/
mv start_noctis.sh verify_setup.py scripts/

# Update .gitignore
cat >> .gitignore << EOF
build/
*.log
*.exe
test_output/
compiled/
EOF

# Test that nothing broke
python test_all.py

# If tests pass, commit
git add -A
git commit -m "Organize build outputs and scripts into subdirectories"
```

---

## Final Directory Structure Goal

```
Noctis-MCP/
├── 📁 src/              # Source code (Phase 3)
├── 📁 data/             # Data files (Phase 2)
├── 📁 build/            # Build outputs ✓ (Phase 1)
├── 📁 scripts/          # Setup scripts ✓ (Phase 1)
├── 📁 tests/            # Keep as is
├── 📁 docs/             # Keep as is
├── 📄 README.md
├── 📄 LICENSE
├── 📄 requirements.txt
├── 📄 .gitignore
└── 📄 test_all.py
```

**Current Status:**
- ✅ Phase 1 ready to do (safe)
- ⏳ Phase 2 optional (low risk)
- ❌ Phase 3 not recommended yet (high effort)

---

## Automation Script

I've created `reorganize_repo.sh` that does everything automatically, but **USE WITH CAUTION**. It will:
- Create backup
- Move everything
- But you'll need to update 50+ import statements

**Better approach:** Do Phase 1 manually, test, commit. Then decide if you need Phase 2/3.

