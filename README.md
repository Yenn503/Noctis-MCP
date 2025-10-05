<div align="center">

![Noctis-MCP Logo](NoctisAI.png)

**🤖 AI-Powered Malware Development Platform**

*Intelligence-Driven Red Team Operations*

[![Python](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey)](https://github.com/Yenn503/Noctis-MCP)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![MCP Tools](https://img.shields.io/badge/MCP%20Tools-11-brightgreen)](https://github.com/Yenn503/Noctis-MCP)

</div>

**Legal Disclaimer**: For authorised security research, penetration testing, and red team operations only. Unauthorised use is illegal and prohibited.

## What is Noctis-AI?

**Noctis-MCP** malware development platform that transforms your AI assistant into a sophisticated red team operator. Think of it as having a malware development expert with access to the latest evasion techniques, real-world implementations, and cutting-edge research - all integrated directly into your IDE.

Next Update is educational classes and modules coming for the techniques used

### How It Works

**The AI in your IDE becomes the agent** - it reasons, plans, and makes decisions. **Noctis-MCP provides the intelligence** - real-time access to:

- **55+ Knowledge Chunks** from security research for the AI
- **GitHub Repositories** with real malware implementations  
- **Research Papers** from arXiv and security conferences
- **Live Intelligence** from security blogs and threat feeds
- **Detection Patterns** from EDR/AV testing results

### The Prompt:

Instead of writing malware from scratch or copying outdated techniques, you simply ask:

> *"Generate a CrowdStrike bypass using the latest syscall techniques"*

**Noctis-MCP responds by:**
1. 🔍 **Searching** its intelligence database for current evasion methods
2. 🧠 **Analysing** which techniques work best against your target
3. 💻 **Generating** production-ready code using real GitHub implementations
4. 🛡️ **Optimising** for OPSEC with string encryption and API hashing
5. ✅ **Validating** the code compiles and passes quality checks
6. 📁 **Saving** complete source files with headers and documentation

**Result:** You get 3,000+ lines of battle-tested malware code in seconds, not hours.

## Key Features

### 🧠 **Intelligence Engine**
- **RAG-Powered Search**: 55+ knowledge chunks, 24+ GitHub repos, 30+ research papers
- **Live Intelligence**: Real-time data from GitHub API, security blog RSS feeds, arXiv
- **Detection Intelligence**: EDR/AV bypass patterns and effectiveness scores
- **Learning System**: Records detection results to improve future recommendations

### 🛠️ **11 Agentic MCP Tools**
- **Intelligence**: `search_intelligence()`, `analyze_technique()`, `fetch_latest()`
- **Code Generation**: `generate_code()`, `optimize_opsec()`, `validate_code()`
- **Technique Selection**: `select_techniques()`, `compare_techniques()`
- **Compilation**: `compile_code()`, `record_feedback()`, `rag_stats()`

### 🎯 **Advanced Capabilities**
- **Dynamic Code Generation**: RAG-informed assembly using real GitHub patterns
- **10 MITRE ATT&CK Techniques**: Syscalls, injection, encryption, steganography, etc.
- **C2 Framework Integration**: Sliver, Havoc, Mythic support
- **Cross-Platform Compilation**: Windows binaries from Linux/macOS
- **OPSEC Optimisation**: String encryption, API hashing, control flow obfuscation

## 🚀 Quick Start

### ⚠️ **Critical Requirements**

**Noctis-MCP requires TWO components running simultaneously:**
1. **Noctis Server** (Flask API on port 8888)
2. **MCP Client** (via Cursor/VSCode)

**Both must be running for the MCP tools to work!**

### 📋 Prerequisites

- **Python 3.11+** (3.13.2 recommended)
- **Compiler**: MinGW-w64 (Linux/macOS) or Visual Studio Build Tools (Windows)
- **MCP-Compatible IDE**: Cursor, VSCode etc (co-pilot,claude)
- **Package Manager**: Homebrew (macOS), apt/dnf (Linux)

### 🛠️ Installation

**For detailed platform-specific instructions, see [SETUP.md](SETUP.md)**

```bash
# 1. Clone the repository
git clone https://github.com/Yenn503/Noctis-MCP.git
cd Noctis-MCP

# 2. Run automated setup
# Linux/macOS
chmod +x scripts/setup/setup.sh
./scripts/setup/setup.sh

# Windows
.\scripts\setup\setup.ps1

# 3. Initialise RAG intelligence system
source venv/bin/activate  # Linux/macOS
# venv\Scripts\activate   # Windows
python scripts/rag_setup.py

# 4. Verify installation
python scripts/verify_setup.py
```

### 🖥️ Start the Server

```bash
# Activate virtual environment
source venv/bin/activate  # Linux/macOS
# venv\Scripts\activate   # Windows

# Start Noctis server
python server/noctis_server.py --port 8888
```

**Keep this terminal running!** The server must stay active for MCP tools to work.

### 🔧 Configure MCP for Cursor

**Edit `~/.cursor/mcp.json` (macOS/Linux) or `%APPDATA%\Cursor\User\mcp.json` (Windows):**

```json
{
  "mcpServers": {
    "noctis-mcp": {
      "command": "/path/to/Noctis-MCP/venv/bin/python",
      "args": ["-m", "noctis_mcp_client.noctis_mcp"],
      "cwd": "/path/to/Noctis-MCP",
      "description": "Noctis-MCP v3.0-agentic - RAG-Powered Malware Development (11 agentic tools)",
      "timeout": 300,
      "env": {
        "PYTHONPATH": "/path/to/Noctis-MCP"
      }
    }
  }
}
```

**⚠️ Replace `/path/to/Noctis-MCP` with your actual installation path!**

### ✅ Verify Setup

1. **Restart Cursor completely** (Cmd+Q then reopen)
2. **Test the connection**: Ask "What MCP tools do you have access to?"
3. **You should see 11 Noctis tools** listed

**If you see "no tools" or a red circle, see [Troubleshooting](#troubleshooting) below.**

## 💡 Usage Examples

### 🎯 **Basic Workflow**

```
User: "Generate a CrowdStrike bypass using the latest syscall techniques"

AI: [Searches RAG intelligence] → [Selects techniques] → [Generates code with headers] → [Optimizes OPSEC] → [Validates] → [Delivers result]

Result: 3,000+ lines of production-ready malware code in seconds
```

### 🛠️ **Available MCP Tools**

| Category | Tool | Purpose |
|----------|------|---------|
| **Intelligence** | `search_intelligence()` | Search RAG for techniques and research |
| | `analyze_technique()` | Deep analysis of specific techniques |
| | `fetch_latest()` | Get latest intelligence from GitHub/blogs |
| **Code Generation** | `generate_code()` | RAG-informed code generation |
| | `optimize_opsec()` | Improve code stealth |
| | `validate_code()` | Compilation and quality checks |
| **Technique Selection** | `select_techniques()` | AI technique recommendations |
| | `compare_techniques()` | Side-by-side technique analysis |
| **Compilation** | `compile_code()` | Compile to binary |
| | `record_feedback()` | Report detection results |
| **Utilities** | `rag_stats()` | RAG system statistics |

### 🚀 **Real-World Examples**

**Example 1: EDR Bypass**
```
User: "Create a Crowdstrike bypass using process injection"

AI Response:
- Searches for the latest Windows Defender evasion techniques
- Finds 15+ GitHub repos with injection methods
- Generates code using Hell's Gate + API unhooking
- Optimises with string encryption and API hashing
- Validates compilation and OPSEC score
- Saves: generated_T008_T005_20251005_174523.c (2,847 lines)
```

**Example 2: C2 Integration**
```
User: "Generate a Sliver beacon with syscall evasion"

AI Response:
- Analyses Sliver C2 framework requirements
- Selects syscall technique (NOCTIS-T004)
- Generates beacon code with direct NTDLL calls
- Optimises for stealth and stability
- Compiles to Windows PE binary
- Saves: sliver_beacon_syscalls.exe
```

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

Supports Sliver and Mythic frameworks:

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
- **OPSEC optimised** code with string encryption and API hashing

### File Naming Convention
- `generated_{technique_ids}_{timestamp}.{extension}`
- Example: `generated_T004_T008_20251005_040526.c` (Syscalls + Injection)
- Timestamps ensure unique filenames for each generation

## Update Intelligence

```bash
# Fetch latest from GitHub, arXiv, blogs
python scripts/update_intelligence.py
```

## 🚨 Troubleshooting

### **"No Tools" or Red Circle in Cursor**

**Most Common Issue:** MCP tools not visible in Cursor

**Solutions:**
1. **Server not running** - Start with `python server/noctis_server.py --port 8888`
2. **Wrong Python path** - Use full path to venv Python in MCP config
3. **Missing PYTHONPATH** - Add PYTHONPATH to MCP env variables
4. **Cursor not restarted** - Completely quit and restart Cursor

**Debug Steps:**
```bash
# 1. Check if the server is running
curl http://localhost:8888/health

# 2. Test MCP client directly
source venv/bin/activate
python -m noctis_mcp_client.noctis_mcp

# 3. Check MCP config syntax
cat ~/.cursor/mcp.json | python -m json.tool
```

### **Server Issues**

**Port 8888 in use:**
```bash
# Find what's using port 8888
lsof -i :8888  # macOS/Linux
netstat -ano | findstr :8888  # Windows

# Kill the process or use a different port
python server/noctis_server.py --port 8889
```

**Server won't start:**
```bash
# Check Python environment
source venv/bin/activate
python --version

# Check dependencies
pip list | grep -E "(flask|fastmcp|requests)"
```

### **RAG System Issues**

**RAG not working:**
```bash
# Reinitialise RAG system
source venv/bin/activate
python scripts/rag_setup.py

# Check RAG status
curl http://localhost:8888/api/v2/rag/stats
```

**Missing intelligence:**
```bash
# Update intelligence from live sources
python scripts/update_intelligence.py
```

### **Compilation Issues**

**Code validation fails:**
- **Linux**: `sudo apt-get install mingw-w64`
- **macOS**: `brew install mingw-w64`
- **Windows**: Install Visual Studio Build Tools

**Import errors:**
```bash
# Activate virtual environment
source venv/bin/activate  # Linux/macOS
venv\Scripts\activate     # Windows

# Reinstall dependencies
pip install -r requirements.txt
```

### **Still Having Issues?**

1. **Check the logs** in your terminal where the server is running
2. **Verify all steps** in [SETUP.md](SETUP.md)
3. **Open a GitHub issue** with your error messages
4. **Join the community** for support

## 🛡️ OPSEC & Security

### **⚠️ High Risk Activities**
- Running compiled malware on the development machine
- Testing against production EDR without authorisation
- Using generated code in unauthorised environments
- Sharing detection results without proper sanitisation

### **✅ Best Practices**
- **Use isolated VMs** for all testing and development
- **Delete compiled binaries** immediately after testing
- **Always validate code** before delivery to clients
- **Report detection results** using `record_feedback()` for learning
- **Use proper C2 infrastructure** with encrypted communications
- **Follow responsible disclosure** for any vulnerabilities found

### **🔒 Legal Compliance**
- **Authorized testing only** - Ensure you have proper authorization
- **Scope limitations** - Stay within defined testing boundaries
- **Documentation** - Maintain proper records of all activities
- **Incident response** - Have procedures for handling detections

---

## 📚 Documentation

- **[SETUP.md](SETUP.md)** - Complete installation guide for all platforms
- **[MITRE Mappings](docs/MITRE_MAPPING_SUMMARY.md)** - Technique mappings and coverage
- **[C2 Integration](docs/C2_INTEGRATION.md)** - Framework integration details
- **[Examples/](Examples/)** - Sample implementations and tutorials

---

## 🤝 Support & Community

### **Getting Help**
- **[GitHub Issues](https://github.com/Yenn503/Noctis-MCP/issues)** - Bug reports and feature requests
- **[Discussions](https://github.com/Yenn503/Noctis-MCP/discussions)** - Community support and questions
- **[Wiki](https://github.com/Yenn503/Noctis-MCP/wiki)** - Additional documentation and guides

### **Contributing**
- **Pull Requests** welcome for bug fixes and improvements
- **Documentation** contributions appreciated
- **Technique submissions** for new evasion methods
- **Intelligence sharing** for RAG system improvements

### **License**
MIT License - See [LICENSE](LICENSE) for details

---

## 🎯 What's Next?

1. **Try the Examples** - Start with the MaldevAcademy loaders
2. **Explore Techniques** - Experiment with different evasion methods
3. **Integrate C2** - Connect with your preferred C2 framework
4. **Contribute** - Help improve the platform and intelligence

**Happy Hacking with Noctis-AI! 🔥**

---

<div align="center">

**Author: Yenn503**
**Community project 🧠**

*Transforming AI assistants into sophisticated red team operators*

</div>
