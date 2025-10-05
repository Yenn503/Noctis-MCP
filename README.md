<div align="center">

![Noctis-MCP Logo](NoctisAI.png)

**RAG-Powered Agentic Malware Development Platform**

[![Python](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows-lightgrey)](https://github.com/Yenn503/Noctis-MCP)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Version](https://img.shields.io/badge/version-3.0.0--agentic-orange)](https://github.com/Yenn503/Noctis-MCP)

</div>

**Legal Disclaimer**: This tool is designed exclusively for authorized security research, penetration testing, and red team operations. Unauthorized use of malware development tools is illegal. Users assume full responsibility for compliance with applicable laws.

---

## What's New in v3.0 - RAG-Powered Agentic System

### Truly Agentic Intelligence

**Noctis-MCP v3.0** is a complete rebuild featuring **RAG (Retrieval Augmented Generation)** for dynamic, intelligence-driven malware development. The AI in your IDE (Claude, GPT-4, etc.) acts as the **agent** - these tools provide **intelligence**.

### Revolutionary Features

✅ **RAG-Powered Intelligence**: 55+ knowledge chunks from techniques, research papers, GitHub repos, security blogs
✅ **Live Intelligence Gathering**: Real-time data from GitHub API, arXiv, RSS feeds
✅ **11 Agentic Tools**: Designed for AI decision-making, not fixed workflows
✅ **Dynamic Code Generation**: No static templates - RAG-informed code assembly
✅ **Validation Pipeline**: AI can verify code quality and iterate until perfect
✅ **IDE-Agnostic**: Works with Cursor, VSCode, any MCP-compatible IDE
✅ **4 Collaborative Agents**: TechniqueSelection, MalwareDevelopment, OpsecOptimization, Learning

### Agentic Workflow Example

```python
# AI-driven workflow (not fixed scripts!)

# 1. AI searches for intelligence
search_intelligence("CrowdStrike evasion techniques", target_av="CrowdStrike")

# 2. AI analyzes specific techniques
analyze_technique("syscalls", target_av="CrowdStrike", include_code_examples=True)

# 3. AI fetches latest research
fetch_latest("NTDLL unhooking", sources="github,arxiv,blogs")

# 4. AI generates code using RAG intelligence
generate_code(["syscalls", "unhooking"], target_av="CrowdStrike", use_rag=True)

# 5. AI validates before delivery
validate_code(source_code, output_name="payload")

# 6. If validation fails, AI fixes and retries
# The AI iterates until validate_code returns "ready_for_use"
```

---

## Overview

Noctis-MCP v3.0 is a **RAG-powered agentic framework** where:

- **The AI in your IDE is the agent** (Claude, GPT-4, Copilot, etc.)
- **MCP tools provide intelligence** (not fixed workflows)
- **RAG system delivers dynamic knowledge** (not static templates)
- **AI makes decisions** based on real-time intelligence

### Core Components

🧠 **RAG Engine**
- ChromaDB vector database (55+ knowledge chunks indexed)
- Sentence-transformers embeddings (all-MiniLM-L6-v2)
- 5 intelligence collections: knowledge_base, github_repos, research_papers, blog_posts, detection_intel

🔍 **Live Intelligence**
- GitHub API (malware techniques, evasion research)
- arXiv API (academic security papers)
- Security blogs (MDSec, Outflank, XPN, TrustedSec, SpecterOps)

🤖 **4 Collaborative Agents**
- **TechniqueSelectionAgent**: RAG-powered technique recommendations
- **MalwareDevelopmentAgent**: Dynamic code assembly from intelligence
- **OpsecOptimizationAgent**: Stealth optimization using detection patterns
- **LearningEngine**: Feedback loop for continuous improvement

📚 **Knowledge Base**
- 10 active techniques (syscalls, injection, encryption, unhooking, etc.)
- MITRE ATT&CK mappings (12 unique TTPs)
- 38 production C/C++ examples (MaldevAcademy Loader1, Loader2, TheSilencer)
- Conceptual understanding (not just code templates)

### The 11 Agentic MCP Tools

| Category | Tool | Purpose |
|----------|------|---------|
| **Intelligence** | `search_intelligence()` | Search RAG system for techniques, research, intelligence |
| | `analyze_technique()` | Deep analysis using ALL intelligence sources |
| | `fetch_latest()` | Get cutting-edge intelligence from GitHub/arXiv/blogs |
| **Code Generation** | `generate_code()` | RAG-informed dynamic code generation |
| | `optimize_opsec()` | Improve code stealth using RAG intelligence |
| | `validate_code()` | Compilation + quality checks with error feedback |
| **Technique Selection** | `select_techniques()` | AI-powered technique recommendations |
| | `compare_techniques()` | Side-by-side technique analysis |
| **Execution** | `compile_code()` | Compile code to binary |
| **Learning** | `record_feedback()` | Report detection results for learning |
| **Utilities** | `rag_stats()` | RAG system statistics |

---

## Quick Start

### Prerequisites

- **Python 3.11+**
- **Compiler** (for Windows malware):
  - **Linux**: MinGW-w64 (installed by setup script)
  - **Windows**: Visual Studio Build Tools 2019+
- **MCP-Compatible IDE**: Cursor, VSCode with Claude extension, etc.

### Installation

**Linux/macOS:**
```bash
git clone https://github.com/Yenn503/Noctis-MCP.git
cd Noctis-MCP

# Automated setup
chmod +x scripts/setup/setup.sh
./scripts/setup/setup.sh

# Initialize RAG system (IMPORTANT!)
python scripts/rag_setup.py

# Verify installation
python scripts/verify_setup.py
```

**Windows:**
```powershell
git clone https://github.com/Yenn503/Noctis-MCP.git
cd Noctis-MCP

# Automated setup
.\scripts\setup\setup.ps1

# Initialize RAG system (IMPORTANT!)
python scripts\rag_setup.py

# Verify installation
python scripts\verify_setup.py
```

### Start Server

```bash
# Start Noctis server (port 8888)
python -m server.noctis_server

# Server will show:
# [+] RAG System: ENABLED (55 knowledge chunks indexed)
# [*] Server starting on http://127.0.0.1:8888
```

### Configure MCP in Cursor/VSCode

**Cursor:**
The `mcp_config_cursor.json` is already configured. Cursor will auto-detect it.

**VSCode with Claude Desktop:**
Add to `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "noctis": {
      "command": "python",
      "args": ["-m", "noctis_mcp_client.noctis_mcp"],
      "cwd": "/path/to/Noctis-MCP"
    }
  }
}
```

**Verify Tools are Available:**
In your IDE, ask the AI: "What MCP tools do you have access to?"

You should see 11 Noctis tools available.

---

## Usage Examples

### Example 1: AI-Driven CrowdStrike Bypass

```
User: "I need a CrowdStrike bypass using syscalls"

AI: Let me search for CrowdStrike evasion intelligence...
[Calls: search_intelligence("CrowdStrike syscall evasion")]

AI: Found 5 relevant techniques. Let me analyze syscalls specifically...
[Calls: analyze_technique("syscalls", target_av="CrowdStrike")]

AI: I'll also check for the latest research...
[Calls: fetch_latest("CrowdStrike evasion", sources="github,arxiv")]

AI: Based on intelligence gathered, I'll generate code using syscalls + unhooking...
[Calls: generate_code(["syscalls", "unhooking"], target_av="CrowdStrike")]

AI: Let me validate the code before delivering it...
[Calls: validate_code(code)]

AI: Validation passed! Here's your CrowdStrike bypass:
[Delivers code with detailed explanation]
```

### Example 2: OPSEC Optimization Loop

```
User: "Generate a process injector with max OPSEC"

AI: I'll generate an initial injector...
[Calls: generate_code(["injection"], target_av="Windows Defender")]

AI: Let me validate it...
[Calls: validate_code(code)]
Result: OPSEC score 6.5/10 - needs improvement

AI: I'll optimize for better stealth...
[Calls: optimize_opsec(code, target_av="Windows Defender", target_score=9.0)]

AI: Validating optimized version...
[Calls: validate_code(optimized_code)]
Result: OPSEC score 9.2/10 - ready for use!

AI: Here's your high-OPSEC injector with explanation of improvements made.
```

### Example 3: Technique Research

```
User: "What's the best technique for evading Elastic EDR?"

AI: Let me search our intelligence for Elastic EDR evasion...
[Calls: search_intelligence("Elastic EDR evasion")]

AI: I found several techniques. Let me compare the top candidates...
[Calls: compare_techniques(["syscalls", "unhooking", "stack_spoof"], target_av="Elastic")]

AI: Based on effectiveness scores and recent intelligence:
1. Direct Syscalls (9.2/10) - bypasses userland hooks
2. NTDLL Unhooking (8.5/10) - removes EDR hooks
3. Stack Spoofing (7.8/10) - evades stack analysis

I recommend syscalls + unhooking combination.
```

---

## RAG System

### Knowledge Sources

**1. Local Knowledge Base (55 chunks)**
- `techniques/knowledge/syscalls.md` - Direct system calls
- `techniques/knowledge/injection.md` - Process injection techniques
- `techniques/knowledge/encryption.md` - Payload encryption

**2. Live Intelligence**
- **GitHub**: Latest malware techniques, evasion research
- **arXiv**: Academic security papers
- **Security Blogs**: MDSec, Outflank, XPN, TrustedSec, SpecterOps

**3. Detection Intelligence**
- Historical detection data from user feedback
- AV/EDR effectiveness scores
- Technique success rates by target

### Update Intelligence

```bash
# Fetch latest intelligence from GitHub, arXiv, blogs
python scripts/update_intelligence.py

# This adds new intelligence to RAG database
# AI can now use cutting-edge research in code generation
```

### RAG Statistics

```python
# From your IDE AI
rag_stats()

# Returns:
{
  "enabled": true,
  "knowledge_base": 55,
  "github_repos": 12,
  "research_papers": 8,
  "blog_posts": 15,
  "detection_intel": 23,
  "embedding_model": "all-MiniLM-L6-v2",
  "vector_db": "ChromaDB"
}
```

---

## API Reference

**Base URL:** `http://localhost:8888`

### Agentic Intelligence Endpoints

```
POST /api/v2/intelligence/search       - Search RAG for intelligence
POST /api/v2/intelligence/analyze      - Deep technique analysis
POST /api/v2/intelligence/fetch-latest - Fetch live intelligence

POST /api/v2/code/generate              - RAG-informed code generation
POST /api/v2/code/validate              - Validate code quality
POST /api/v2/code/optimize-opsec        - OPSEC optimization

POST /api/v2/techniques/select          - Technique selection
POST /api/v2/techniques/compare         - Compare techniques

GET  /api/v2/rag/stats                  - RAG system stats
```

### Legacy Endpoints (Still Supported)

```
GET  /api/techniques                    - List techniques
POST /api/generate                      - Generate code
POST /api/compile                       - Compile code
POST /api/analyze/opsec                 - OPSEC analysis
```

Full API documentation: Use the AI in your IDE to explore endpoints dynamically!

---

## Technique Library

### Active Techniques (10)

| ID | Technique | Category | MITRE ATT&CK | Description |
|----|-----------|----------|--------------|-------------|
| NOCTIS-T001 | Steganography | Evasion | T1027.003 | Hide payloads in images |
| NOCTIS-T002 | Encryption | Defense Evasion | T1027 | AES/RC4 payload encryption |
| NOCTIS-T003 | API Hashing | Defense Evasion | T1027.007 | Hash-based API resolution |
| NOCTIS-T004 | Syscalls | Defense Evasion | T1106 | Direct system calls (Hell's Gate) |
| NOCTIS-T005 | Unhooking | Defense Evasion | T1562.001 | Remove EDR hooks from NTDLL |
| NOCTIS-T006 | Stack Spoof | Defense Evasion | T1014 | Spoof call stack frames |
| NOCTIS-T007 | VEH | Defense Evasion | T1055.012 | Vectored exception handling |
| NOCTIS-T008 | Injection | Execution | T1055 | Process injection (multiple methods) |
| NOCTIS-T009 | GPU Evasion | Defense Evasion | T1027 | GPU-based payload execution |
| NOCTIS-T010 | Persistence | Persistence | T1547.001 | Registry/scheduled task persistence |

**MITRE Coverage:** 12 unique TTPs across 4 tactics

---

## C2 Integration

Noctis-MCP supports C2 framework integration:

- **Sliver**: HTTPS, mTLS, DNS beacons
- **Havoc**: Sleep obfuscation (Ekko, Foliage, Zilean), custom profiles
- **Mythic**: Apollo, Athena agents with custom protocols

Generate C2 beacons via Python API:
```python
import requests

response = requests.post("http://localhost:8888/api/c2/sliver/generate", json={
    "listener_name": "https-443",
    "protocol": "https",
    "arch": "x64",
    "format": "shellcode"
})
```

See `docs/C2_INTEGRATION.md` for details.

---

## Architecture

### Agentic Design Philosophy

**Traditional Approach:**
```
User → Static Tool → Fixed Workflow → Predefined Output
```

**Noctis v3.0 Agentic Approach:**
```
User → AI Agent (in IDE) → Dynamic Tool Selection → RAG Intelligence → AI Reasoning → Custom Solution
```

**Key Principle:** The AI in your IDE (Claude, GPT-4) makes decisions. Tools provide intelligence.

### System Components

```
┌─────────────────────────────────────────────────────────────┐
│                    YOUR IDE (Cursor/VSCode)                 │
│                                                             │
│  ┌───────────────────────────────────────────────────┐    │
│  │   AI Agent (Claude/GPT-4)                         │    │
│  │   - Makes decisions                                │    │
│  │   - Calls MCP tools                                │    │
│  │   - Iterates until satisfied                       │    │
│  └──────────────────┬──────────────────────────────────┘    │
└────────────────────┼────────────────────────────────────────┘
                     │ MCP Protocol
                     ▼
┌─────────────────────────────────────────────────────────────┐
│              Noctis-MCP Server (localhost:8888)             │
│                                                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │  RAG Engine  │  │   4 Agents   │  │ Code Assembly│     │
│  │  ChromaDB    │  │  Selection   │  │  Dynamic     │     │
│  │  55 chunks   │  │  Development │  │  Generation  │     │
│  │              │  │  OPSEC       │  │              │     │
│  └──────────────┘  │  Learning    │  └──────────────┘     │
│                     └──────────────┘                        │
│  ┌──────────────────────────────────────────────────┐      │
│  │  Live Intelligence Gathering                     │      │
│  │  - GitHub API (malware techniques)               │      │
│  │  - arXiv API (research papers)                   │      │
│  │  - RSS Feeds (security blogs)                    │      │
│  └──────────────────────────────────────────────────┘      │
└─────────────────────────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│              Knowledge Base & Examples                      │
│  - 10 technique metadata files                              │
│  - 3 knowledge markdown files (syscalls, injection, encrypt)│
│  - 38 production C/C++ examples (MaldevAcademy)            │
└─────────────────────────────────────────────────────────────┘
```

---

## Development

### Project Structure

```
Noctis-MCP/
├── server/                    # Core server
│   ├── noctis_server.py      # Main Flask API
│   ├── agentic_api.py        # RAG-powered endpoints
│   ├── code_assembler.py     # Dynamic code assembly
│   ├── rag/                  # RAG engine
│   │   └── rag_engine.py     # ChromaDB + embeddings
│   ├── intelligence/          # Live intelligence
│   │   └── live_intel.py     # GitHub/arXiv/RSS
│   └── agents/               # 4 collaborative agents
│       ├── technique_selection_agent.py
│       ├── malware_development_agent.py
│       ├── opsec_optimization_agent.py
│       └── learning_engine.py
├── noctis_mcp_client/        # MCP client
│   └── noctis_mcp.py         # 11 agentic tools
├── techniques/               # Technique library
│   ├── metadata/            # 10 technique JSON files
│   └── knowledge/           # RAG knowledge base
│       ├── syscalls.md
│       ├── injection.md
│       └── encryption.md
├── Examples/                 # Production code examples
│   ├── MaldevAcademy/       # Loader1, Loader2
│   └── MyOwn/               # TheSilencer
├── compilation/              # Cross-platform compilation
├── c2_adapters/             # C2 framework integration
├── scripts/                 # Utilities
│   ├── rag_setup.py         # Initialize RAG
│   └── update_intelligence.py # Fetch latest intel
└── data/                    # Databases
    ├── rag_db/              # ChromaDB vector store
    └── knowledge_base.db    # Technique database
```

### Contributing

Contributions welcome! See `docs/CONTRIBUTING.md` (if it exists).

**Key Areas:**
- Add new techniques to `techniques/knowledge/`
- Improve RAG intelligence sources
- Enhance agent decision-making
- Add AV/EDR detection patterns

---

## OPSEC Considerations

### Detection Risks

**High Risk:**
- Running compiled malware on your development machine
- Testing against production EDR without authorization
- Leaving malware samples in accessible directories

**Medium Risk:**
- Uploading to VirusTotal (samples become public)
- Using default technique combinations
- Excessive debug output in code

**Low Risk:**
- Using RAG system (local embeddings, no API calls)
- Generating code (not executing)
- Testing in isolated VMs

### Best Practices

1. **Isolated Testing**: Use air-gapped VMs for malware testing
2. **Clean Compilation**: Delete compiled binaries after testing
3. **Custom Techniques**: Combine techniques in unique ways (avoid patterns)
4. **OPSEC Validation**: Always use `validate_code()` before delivery
5. **Learning Feedback**: Report detection results via `record_feedback()` to improve

---

## Troubleshooting

### RAG System Not Working

```bash
# Verify RAG is initialized
python scripts/rag_setup.py

# Check RAG stats
curl http://localhost:8888/api/v2/rag/stats

# Should show: "enabled": true, "knowledge_base": 55
```

### Tools Not Visible in IDE

**Cursor:**
1. Check `mcp_config_cursor.json` exists
2. Restart Cursor completely
3. Ask AI: "What MCP tools do you have?"

**VSCode + Claude Desktop:**
1. Check `claude_desktop_config.json` configuration
2. Restart Claude Desktop app
3. Verify `cwd` path is correct absolute path

### Compilation Fails

**Linux:**
```bash
# Install MinGW
sudo apt-get install mingw-w64
```

**Windows:**
```powershell
# Install Visual Studio Build Tools
# Download from: https://visualstudio.microsoft.com/downloads/
```

### Server Won't Start

```bash
# Check port 8888 is not in use
netstat -ano | findstr :8888   # Windows
lsof -i :8888                  # Linux/macOS

# Start on different port
python -m server.noctis_server --port 9999
```

---

## Security & Ethics

### Responsible Use

This tool is designed for **authorized security research ONLY**:

✅ **Authorized Use:**
- Penetration testing with written authorization
- Red team operations for your organization
- Security research in isolated environments
- Education in controlled lab settings

❌ **Prohibited Use:**
- Unauthorized access to systems
- Malicious attacks
- Distribution of malware
- Any illegal activities

### Privacy

- **RAG system is local**: All embeddings run on your machine (sentence-transformers)
- **No data sent to cloud**: ChromaDB is local vector database
- **Live intelligence**: GitHub/arXiv APIs used with public data only

---

## License

MIT License - See [LICENSE](LICENSE) file for details.

---

## Acknowledgments

- **MaldevAcademy**: Code examples (Loader1, Loader2)
- **MDSec, Outflank, XPN, TrustedSec, SpecterOps**: Intelligence sources
- **MITRE ATT&CK**: Technique taxonomy
- **Anthropic**: MCP protocol for agentic tool use

---

## Support

- **Issues**: [GitHub Issues](https://github.com/Yenn503/Noctis-MCP/issues)
- **MITRE Mappings**: See `docs/MITRE_MAPPING_SUMMARY.md`
- **C2 Integration**: See `docs/C2_INTEGRATION.md`

---

<div align="center">

**Noctis-MCP v3.0-agentic**
*RAG-Powered Intelligence for Agentic Malware Development*

Built for the AI agent in your IDE.

</div>
