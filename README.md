<div align="center">

![Noctis-MCP Logo](NoctisAI.png)

**RAG-Powered Malware Development Platform**

[![Python](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows-lightgrey)](https://github.com/Yenn503/Noctis-MCP)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

</div>

**Legal Disclaimer**: For authorized security research, penetration testing, and red team operations only. Unauthorized use is illegal.

## What is Noctis-MCP?

Noctis-MCP is a malware development platform that uses RAG (Retrieval Augmented Generation) to provide intelligence-driven code generation. The AI in your IDE acts as the agent, while these tools provide real-time intelligence from GitHub repos, security blogs, and research papers.

## Features

- **RAG Intelligence**: 55+ knowledge chunks, 24+ GitHub repos, security blogs
- **Live Intelligence**: Real-time data from GitHub API, security blog RSS feeds  
- **11 MCP Tools**: Intelligence search, code generation, technique analysis
- **Dynamic Code Generation**: RAG-informed code assembly with real GitHub patterns
- **Technique Library**: 10 active techniques with MITRE ATT&CK mappings
- **C2 Integration**: Sliver, Havoc, Mythic framework support
- **Learning System**: Records detection results to improve recommendations

## Quick Start

### Prerequisites

- Python 3.11+
- Compiler (MinGW-w64 on Linux, Visual Studio Build Tools on Windows)
- MCP-compatible IDE (Cursor, VSCode with Claude extension)

### Installation

```bash
git clone https://github.com/Yenn503/Noctis-MCP.git
cd Noctis-MCP

# Linux/macOS
chmod +x scripts/setup/setup.sh
./scripts/setup/setup.sh

# Windows
.\scripts\setup\setup.ps1

# Initialize RAG system
python scripts/rag_setup.py

# Verify installation
python scripts/verify_setup.py
```

### Start Server

```bash
python -m server.noctis_server
```

### Configure MCP

**Cursor:**
The `mcp_config_cursor.json` is pre-configured.

**VSCode with Claude Desktop:**
Add to your Claude Desktop config:

```json
{
  "mcpServers": {
    "noctis": {
      "command": "python",
      "args": ["-m", "noctis_mcp_client.noctis_mcp"],
      "cwd": "C:\\Users\\YourUsername\\Desktop\\Noctis-MCP"
    }
  }
}
```

**Verify Tools:**
Ask your AI: "What MCP tools do you have access to?" - you should see 11 Noctis tools.

## Usage Examples

### Basic Workflow

```
User: "Generate a CrowdStrike bypass using syscalls"

AI: [Searches RAG intelligence] → [Selects techniques] → [Generates code with headers] → [Optimizes OPSEC] → [Validates] → [Delivers result]
```

### Available Tools

| Tool | Purpose |
|------|---------|
| `search_intelligence()` | Search RAG for techniques and research |
| `analyze_technique()` | Deep analysis of specific techniques |
| `fetch_latest()` | Get latest intelligence from GitHub/blogs |
| `generate_code()` | RAG-informed code generation |
| `optimize_opsec()` | Improve code stealth |
| `validate_code()` | Compilation and quality checks |
| `select_techniques()` | AI technique recommendations |
| `compare_techniques()` | Side-by-side technique analysis |
| `compile_code()` | Compile to binary |
| `record_feedback()` | Report detection results |
| `rag_stats()` | RAG system statistics |

## Techniques

| ID | Technique | Category | MITRE |
|----|-----------|----------|-------|
| NOCTIS-T001 | Steganography | Evasion | T1027.003 |
| NOCTIS-T002 | Encryption | Defense Evasion | T1027 |
| NOCTIS-T003 | API Hashing | Defense Evasion | T1027.007 |
| NOCTIS-T004 | Syscalls | Defense Evasion | T1106 |
| NOCTIS-T005 | Unhooking | Defense Evasion | T1562.001 |
| NOCTIS-T006 | Stack Spoof | Defense Evasion | T1014 |
| NOCTIS-T007 | VEH | Defense Evasion | T1055.012 |
| NOCTIS-T008 | Injection | Execution | T1055 |
| NOCTIS-T009 | GPU Evasion | Defense Evasion | T1027 |
| NOCTIS-T010 | Persistence | Persistence | T1547.001 |

## C2 Integration

Supports Sliver, Havoc, and Mythic frameworks:

```python
import requests

response = requests.post("http://localhost:8888/api/c2/sliver/generate", json={
    "listener_name": "https-443",
    "protocol": "https",
    "arch": "x64",
    "format": "shellcode"
})
```

## Malware Generation & File Management

**Automatic Code Generation & Saving**: The `generate_code` tool creates complete malware implementations with automatic file saving.

### Generated Files
- **Source files**: `generated_T004_T008_YYYYMMDD_HHMMSS.c` (3,000+ lines of real implementations)
- **Header files**: `generated_T004_T008_YYYYMMDD_HHMMSS.h` (100+ function declarations)
- **File paths**: Returned in `files_saved` field of MCP responses
- **Compiled binaries**: Created in `compiled/` directory when using `compile_code()`

### What Gets Generated
- **Real function implementations** extracted from GitHub repos (not templates)
- **Complete malware payloads** with evasion techniques
- **MITRE ATT&CK mapped** techniques (T1055, T1106, etc.)
- **RAG-informed code** using patterns from 24+ GitHub repositories
- **OPSEC optimized** code with string encryption and API hashing

### File Naming Convention
- `generated_{technique_ids}_{timestamp}.{extension}`
- Example: `generated_T004_T008_20251005_040526.c` (Syscalls + Injection)
- Timestamps ensure unique filenames for each generation

## Update Intelligence

```bash
# Fetch latest from GitHub, arXiv, blogs
python scripts/update_intelligence.py
```

## Troubleshooting

**RAG not working:**
```bash
python scripts/rag_setup.py
curl http://localhost:8888/api/v2/rag/stats
```

**Tools not visible:**
- Restart your IDE completely
- Check MCP config path is absolute
- Verify server is running on port 8888

**Code validation fails:**
- Compilation module error: Check compiler installation
- Linux: `sudo apt-get install mingw-w64`
- Windows: Install Visual Studio Build Tools

**Server won't start:**
```bash
# Check port 8888 is free
netstat -ano | findstr :8888   # Windows
lsof -i :8888                  # Linux/macOS
```

## OPSEC

**High Risk:**
- Running compiled malware on dev machine
- Testing against production EDR without authorization

**Best Practices:**
- Use isolated VMs for testing
- Delete compiled binaries after testing
- Always validate code before delivery
- Report detection results for learning

## License

MIT License - See [LICENSE](LICENSE)

## Support

- [GitHub Issues](https://github.com/Yenn503/Noctis-MCP/issues)
- [MITRE Mappings](docs/MITRE_MAPPING_SUMMARY.md)
- [C2 Integration](docs/C2_INTEGRATION.md)