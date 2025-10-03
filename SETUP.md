# Noctis-MCP Setup Guide

Complete setup guide to get Noctis-MCP running on your system from scratch.

## System Requirements

### Supported Operating Systems
- ✅ **Linux** (Kali, Ubuntu, Debian) - Full support
- ✅ **Windows 10/11** - Full support
- ⚠️ **macOS** - Partial support (Python API works, no compilation yet)

### Hardware Requirements
- **CPU:** x64 architecture (required)
- **RAM:** 4GB minimum, 8GB recommended
- **Disk:** 2GB free space
- **Network:** Internet connection for C2 servers

---

## Quick Start (5 minutes)

```bash
# 1. Clone repository
git clone https://github.com/yourusername/Noctis-MCP.git
cd Noctis-MCP

# 2. Run automated setup
chmod +x setup.sh
./setup.sh

# 3. Verify installation
python verify_setup.py

# 4. Start using Noctis!
python noctis_mcp_client/noctis_mcp.py
```

---

## Detailed Setup Instructions

### Step 1: Python Environment

**Install Python 3.11+**

Linux:
```bash
sudo apt update
sudo apt install python3.11 python3.11-venv python3-pip
```

Windows:
```powershell
# Download from python.org or use winget
winget install Python.Python.3.11
```

**Create Virtual Environment**

```bash
# Create venv
python3 -m venv venv

# Activate (Linux/macOS)
source venv/bin/activate

# Activate (Windows)
venv\Scripts\activate

# Verify
python --version  # Should show 3.11+
```

### Step 2: Install Dependencies

```bash
# Upgrade pip
pip install --upgrade pip

# Install all dependencies
pip install -r requirements.txt

# Verify installation
pip list | grep -E "flask|fastmcp|requests"
```

**Expected packages:**
- Flask 3.0+
- FastMCP (latest)
- requests
- cryptography
- pycryptodome
- pytest

### Step 3: Compiler Setup

#### **Linux (MinGW Cross-Compilation)**

```bash
# Install MinGW-w64
sudo apt update
sudo apt install mingw-w64 -y

# Verify installation
x86_64-w64-mingw32-gcc --version
i686-w64-mingw32-gcc --version

# Both should show GCC version info
```

#### **Windows (MSBuild)**

```powershell
# Install Visual Studio Build Tools
# Download from: https://visualstudio.microsoft.com/downloads/

# Or use winget
winget install Microsoft.VisualStudio.2022.BuildTools

# Verify
where msbuild
# Should show: C:\Program Files\Microsoft Visual Studio\...\MSBuild.exe
```

### Step 4: Run Tests

```bash
# Activate venv
source venv/bin/activate  # Linux
# venv\Scripts\activate  # Windows

# Run all tests
python -m pytest tests/ -v

# Expected: 49 tests passing
```

**Test breakdown:**
- Linux compiler tests: 12 tests
- Sliver integration: 4 tests  
- Havoc integration: 15 tests
- Mythic integration: 13 tests
- C2 base tests: 5 tests

### Step 5: Start Noctis Server

```bash
# Start Flask API server
cd /path/to/Noctis-MCP
source venv/bin/activate
python server/noctis_server.py

# Server starts on http://localhost:5000
```

**Verify server:**
```bash
curl http://localhost:5000/api/stats
# Should return JSON with statistics
```

---

## C2 Framework Setup (Optional)

### Sliver C2

```bash
# Quick install
curl https://sliver.sh/install | sudo bash

# Verify
sliver-server version

# Start server
sliver-server

# Usage with Noctis
# See: C2 docs/INSTALL_SLIVER.md
```

### Havoc C2

```bash
# Clone Havoc
git clone https://github.com/HavocFramework/Havoc.git
cd Havoc

# Build
make

# Start teamserver
./havoc server --profile ./profiles/havoc.yaotl

# Usage with Noctis
# See: C2 docs/HAVOC_INTEGRATION.md
```

### Mythic C2

```bash
# Clone Mythic
git clone https://github.com/its-a-feature/Mythic.git
cd Mythic

# Install Docker dependencies
sudo ./install_docker_ubuntu.sh

# Start Mythic
sudo ./mythic-cli start

# Access UI: https://127.0.0.1:7443
# See: C2 docs/MYTHIC_INTEGRATION.md
```

---

## Verification Checklist

Run this checklist to ensure everything is working:

### ✅ Python Environment
```bash
python --version                    # 3.11+
pip list | grep flask              # Flask installed
pip list | grep fastmcp            # FastMCP installed
```

### ✅ Compilers
```bash
# Linux
x86_64-w64-mingw32-gcc --version   # MinGW x64
i686-w64-mingw32-gcc --version     # MinGW x86

# Windows
msbuild -version                    # MSBuild
```

### ✅ Tests
```bash
python -m pytest tests/ -v --tb=short
# Expected: 49/49 passing
```

### ✅ Server
```bash
python server/noctis_server.py &
sleep 2
curl http://localhost:5000/api/stats | jq .
# Should return JSON statistics
```

### ✅ MCP Client
```bash
python -c "from noctis_mcp_client.noctis_mcp import mcp; print('✅ MCP client works!')"
```

### ✅ C2 Adapters
```bash
python -c "from c2_adapters import SliverAdapter, HavocAdapter, MythicAdapter; print('✅ C2 adapters imported!')"
```

### ✅ Compilation Test
```bash
python test_mingw_simple.py
# Should compile Windows PE successfully
```

---

## Common Issues & Solutions

### Issue: `ImportError: No module named 'flask'`

**Solution:**
```bash
# Make sure venv is activated
source venv/bin/activate

# Reinstall dependencies
pip install -r requirements.txt
```

### Issue: `MinGW not found`

**Solution:**
```bash
# Linux
sudo apt update
sudo apt install mingw-w64

# Verify
which x86_64-w64-mingw32-gcc
```

### Issue: `Tests failing`

**Solution:**
```bash
# Check Python version
python --version  # Must be 3.11+

# Reinstall dependencies
pip install --upgrade -r requirements.txt

# Run specific test
python -m pytest tests/test_linux_compiler.py -v
```

### Issue: `MSBuild not found` (Windows)

**Solution:**
```powershell
# Install Visual Studio Build Tools
winget install Microsoft.VisualStudio.2022.BuildTools

# Add to PATH
$env:PATH += ";C:\Program Files\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin"
```

### Issue: `Sliver server not starting`

**Solution:**
```bash
# Check if already running
ps aux | grep sliver

# Kill old process
pkill sliver-server

# Restart
sliver-server
```

---

## Directory Structure

```
Noctis-MCP/
├── c2_adapters/           # C2 framework integrations
│   ├── base_adapter.py    # Abstract base class
│   ├── sliver_adapter.py  # Sliver C2
│   ├── havoc_adapter.py   # Havoc C2
│   ├── mythic_adapter.py  # Mythic C2
│   └── config.py          # C2 configurations
├── compilation/           # Cross-platform compilation
│   ├── windows_compiler.py  # MSBuild (Windows)
│   └── linux_compiler.py    # MinGW (Linux)
├── server/                # Flask REST API
│   ├── noctis_server.py   # Main API server
│   ├── obfuscation/       # Obfuscation modules
│   └── polymorphic/       # Polymorphic engine
├── noctis_mcp_client/     # MCP client (AI interface)
│   └── noctis_mcp.py      # 14 MCP tools
├── techniques/            # Malware techniques database
│   └── metadata/          # 126+ techniques indexed
├── tests/                 # Test suite (49 tests)
├── C2 docs/               # C2 documentation
└── venv/                  # Virtual environment
```

---

## Next Steps

1. ✅ **Verify Setup** - Run `python verify_setup.py`
2. 📚 **Read Quickstart** - See `QUICKSTART.md`
3. 🔧 **Try Examples** - Check `Examples/` directory
4. 🎯 **Generate Malware** - Use MCP tools or API
5. 🚀 **Deploy C2** - Set up Sliver/Havoc/Mythic

---

## Getting Help

- **Documentation**: See `DOCUMENTATION_MAP.md`
- **Quick Reference**: See `QUICK_REFERENCE.md`
- **Issues**: Open GitHub issue
- **Examples**: Check `Examples/` directory

---

## System Info

**Developed on:**
- OS: Kali Linux 2024
- Python: 3.13.7
- Compiler: MinGW-w64 (GCC 10.3+)
- Tests: 49/49 passing

**Should work on:**
- Any Linux distro (Ubuntu, Debian, Kali, etc.)
- Windows 10/11 (with Visual Studio Build Tools)
- Python 3.11+ required

---

## Success Indicators

You're ready to use Noctis when:

✅ All 49 tests pass  
✅ Server starts on port 5000  
✅ MCP client imports successfully  
✅ Compiler found and working  
✅ C2 adapters import without errors  

**Run verification script:**
```bash
python verify_setup.py
```

This should output: **"🎉 Noctis-MCP is ready to use!"**

