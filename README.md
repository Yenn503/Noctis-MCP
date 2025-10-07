<div align="center">

![Noctis-MCP Logo](NoctisAI.png)

**AI-Powered Malware Development Platform**

*Intelligence-Driven Red Team Operations with MCP Integration*

[![Python](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey)](https://github.com/Yenn503/Noctis-MCP)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

[![Join Noctis AI on Discord](https://img.shields.io/badge/Join_Noctis_AI-5865F2?style=for-the-badge&logo=discord&logoColor=white)](https://discord.gg/bBtyAWSkW)

</div>

---

**Legal Notice**: For authorized security research, penetration testing, and red team operations only. Unauthorized use is illegal and prohibited.

---

## Overview

Noctis-MCP is a malware development platform that integrates directly into your IDE through the Model Context Protocol (MCP). It provides RAG-powered intelligence, dynamic code generation, and interactive learning for offensive security operations.

**Core Capabilities:**
- RAG-powered intelligence aggregation from 25+ security sources
- Dynamic malware generation with OPSEC optimization
- C2 framework integration (Sliver, Adaptix, Mythic)
- BOF compilation for beacon operations
- Interactive learning system with 10 curated techniques
- Linux cross-compilation for Windows targets

## How It Works

Noctis-MCP operates as a client-server architecture:

**Server Component** (Flask API on port 8888)
- RAG engine with ChromaDB for intelligence retrieval
- Parallel search architecture with cross-encoder re-ranking
- In-memory caching system for performance optimization
- Code generation API with template system
- Education system with SQLite-backed progress tracking
- Live intelligence feeds from security blogs and GitHub

**MCP Client** (IDE Integration)
- 20 agentic tools exposed to Claude/GPT-4
- Direct access to RAG database and code generation
- Real-time intelligence updates with smart caching
- Interactive learning modules and quizzes

**Workflow:**
1. AI assistant calls MCP tools from your IDE
2. MCP client communicates with Noctis server
3. Server processes requests using RAG and generation engines
4. Results returned to AI for contextualized responses
5. Generated code can be compiled and deployed immediately

## Key Features

### Intelligence Engine
- **RAG Database**: 300+ indexed documents from research papers, GitHub repos, and security blogs
- **VX-API Integration**: 250 production malware functions from VX-Underground indexed for code generation
- **Performance**: Parallel collection searching (3x faster), cross-encoder re-ranking (15-30% better relevance)
- **Smart Caching**: In-memory caching with 24-hour TTL for repeat queries (40-100x faster)
- **Auto-Update**: Fetches latest intelligence when data exceeds 7 days
- **Detection Learning**: Records detection results to improve future recommendations

### Code Generation
- **RAG-Informed**: Uses real-world patterns from knowledge base
- **OPSEC Optimization**: String encryption, API hashing, control flow obfuscation
- **Multi-File Support**: C/C++ + Assembly + Resources
- **Validation**: Automated compilation and error feedback

### C2 Integration
- **Sliver**: Extension-based BOF system with extension.json manifests
- **Adaptix**: AxScript BOF execution with crash-safe operations
- **Mythic Forge**: Command augmentation for Apollo/Athena agents
- **BOF Compilation**: COFF object files with position-independent code

### Linux Cross-Compilation
- **MinGW-w64**: x64 and x86 Windows binary generation
- **NASM**: Assembly compilation to COFF objects
- **windres**: Resource compilation for PE files
- **Multi-Architecture**: Supports x64, x86, ARM64

### Learning System
- **10 Techniques**: Process injection, syscalls, obfuscation, C2 protocols, etc.
- **13 Modules**: Theory, code examples, and hands-on labs
- **70+ Quizzes**: Interactive questions with detailed explanations
- **Progress Tracking**: SQLite database records completion and scores

## Installation

### Prerequisites
- Python 3.11+ (3.13.2 recommended)
- MinGW-w64 (Linux/macOS) or Visual Studio Build Tools (Windows)
- MCP-compatible IDE (Cursor or VSCode)
- 4GB RAM minimum (8GB+ for RAG operations)

### Linux/macOS Setup

```bash
# Clone repository
git clone https://github.com/Yenn503/Noctis-MCP.git
cd Noctis-MCP

# Install system dependencies (Ubuntu/Debian)
sudo apt update
sudo apt install -y python3 python3-pip python3-venv mingw-w64 nasm git

# macOS: brew install python@3.13 mingw-w64 nasm

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install Python dependencies
pip install --upgrade pip
pip install -r requirements.txt

# Index VX-API source code into RAG (250 production malware functions)
python scripts/index_vx_sources.py
```

### Windows Setup

```powershell
# Install Python 3.11+ from python.org
# Install Visual Studio Build Tools

# Create virtual environment
python -m venv venv
.\venv\Scripts\activate

# Install dependencies
pip install --upgrade pip
pip install -r requirements.txt

# Index VX-API source code into RAG
python scripts/index_vx_sources.py
```

### Start Server

```bash
# Activate virtual environment
source venv/bin/activate  # Linux/macOS
.\venv\Scripts\activate   # Windows

# Start Noctis server
python server/noctis_server.py --port 8888
```

Expected output:
```
[+] Connected to server: http://127.0.0.1:8888
[+] RAG System: ENABLED (300+ documents indexed)
[+] Education System: 10 techniques, 13 modules, 70+ quizzes
[*] 20 Agentic Tools Available
```

### Configure IDE

**Cursor IDE:**

Add to MCP settings (Cursor Settings → Features → Model Context Protocol):

```json
{
  "mcpServers": {
    "noctis": {
      "command": "/path/to/Noctis-MCP/venv/bin/python",
      "args": ["-m", "noctis_mcp_client.noctis_mcp"],
      "cwd": "/path/to/Noctis-MCP"
    }
  }
}
```

**VSCode:**

Install MCP extension and add to settings:

```json
{
  "mcp.servers": {
    "noctis": {
      "command": "/path/to/Noctis-MCP/venv/bin/python",
      "args": ["-m", "noctis_mcp_client.noctis_mcp"],
      "cwd": "/path/to/Noctis-MCP"
    }
  }
}
```

Replace `/path/to/Noctis-MCP` with your actual installation path. Restart IDE after configuration.

## Usage

### Intelligence Research

Ask your AI assistant:
- "Find the latest process injection techniques"
- "Analyze direct syscalls for EDR bypass"
- "Search for AES encryption implementations"

The AI will use MCP tools to search the RAG database and return intelligence from security blogs, GitHub repos, and research papers.

### Code Generation

Request malware generation:
- "Generate process injection code using syscalls"
- "Create a BOF for remote process enumeration"
- "Build a Sliver beacon with Hell's Gate syscalls"

The AI will generate complete, compilable code with OPSEC optimizations and build instructions.

### Learning Mode

Start interactive learning:
- "List learning topics" - Browse 10 curated techniques
- "Teach me process injection" - Get 4 interactive modules
- "Give me a quiz" - Test understanding with graded questions
- "Show my progress" - View completed modules and scores

### C2 Operations

Generate C2 payloads:
- "Generate a Sliver beacon for 192.168.1.100:443"
- "Create an Adaptix BOF with Hell's Gate syscalls"
- "Build a Mythic Forge command for process injection"

The system will compile BOF files, generate extension manifests, and provide deployment instructions.

## MCP Tools (20 Available)

**Intelligence (3)**
- `search_intelligence` - RAG search with auto-update
- `analyze_technique` - Deep technique analysis
- `fetch_latest` - Get cutting-edge intelligence

**Code Generation (3)**
- `generate_code` - RAG-informed code generation
- `optimize_opsec` - Stealth enhancement
- `validate_code` - Compilation and quality checks

**Technique Selection (2)**
- `select_techniques` - AI-powered recommendations
- `compare_techniques` - Side-by-side analysis

**Compilation (2)**
- `compile_code` - Binary generation
- `record_feedback` - Detection result learning

**Learning (9)**
- `list_learning_topics` - Browse curriculum
- `start_lesson` - Begin technique learning
- `get_lesson_module` - Retrieve module content
- `complete_module` - Mark module done
- `check_understanding` - Take quiz
- `submit_quiz` - Submit answers with grading
- `get_learning_progress` - View progress
- `get_recommended_lesson` - Get next suggestion
- `search_lessons` - Search topics

**Utilities (1)**
- `rag_stats` - RAG system status

## Configuration

Edit `config.yaml`:

```yaml
server:
  host: 127.0.0.1
  port: 8888

paths:
  techniques: techniques
  lessons: data/lessons.json
  rag_db: data/rag_db
  education_db: data/education_progress.db

rag:
  enabled: true
  auto_update_days: 7
  cache_hours: 24
```

## Project Structure

```
Noctis-MCP/
├── noctis_mcp_client/          # MCP client with 20 tools
├── server/                      # Flask API server
│   ├── noctis_server.py        # Server entry point
│   ├── rag/                    # RAG engine (ChromaDB)
│   ├── education/              # Learning system
│   └── agents/                 # Specialized AI agents
├── c2_adapters/                # C2 framework integrations
│   ├── sliver_adapter.py       # Sliver integration
│   ├── adaptix_adapter.py      # Adaptix integration
│   └── mythic_adapter.py       # Mythic Forge integration
├── compilation/                # Compilation engines
│   ├── bof_compiler.py         # BOF COFF compilation
│   └── linux_compiler.py       # Cross-compilation
├── techniques/                 # Knowledge base
│   ├── knowledge/              # Markdown documentation
│   └── metadata/               # Technique metadata
├── external/                   # External code repositories
│   └── VX-API/                 # VX-Underground API (250 functions)
├── data/                       # Data files
│   ├── lessons.json            # 10 curated techniques
│   ├── quizzes.json            # 70+ quiz questions
│   └── rag_db/                 # ChromaDB (auto-created)
├── templates/                  # Code templates
│   └── bof/                    # BOF templates
├── scripts/                    # Utility scripts
│   ├── index_vx_sources.py     # VX-API RAG indexer
│   └── intelligence_updater.py # Intelligence updater
└── docs/                       # Documentation
```

## Documentation

- **[SETUP.md](docs/SETUP.md)** - Detailed installation guide
- **[ARCHITECTURE.md](docs/ARCHITECTURE.md)** - System architecture
- **[EDUCATION_SYSTEM.md](docs/EDUCATION_SYSTEM.md)** - Learning system documentation
- **[C2_INTEGRATION.md](docs/C2_INTEGRATION.md)** - C2 framework integration guide

## Security & Ethics

This platform is designed for authorized security research and red team operations. By using Noctis-MCP, you agree to:

- Use only in authorized penetration testing engagements
- Follow responsible disclosure practices
- Comply with applicable laws and regulations
- Not use for malicious purposes or unauthorized access

Misuse of this tool is illegal and against the project's intended purpose.

## Contributing

Contributions are welcome. Please:

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Open a pull request

Priority areas: new techniques, quiz questions, intelligence sources, documentation.

## License

MIT License - See [LICENSE](LICENSE) for details

---

<div align="center">

**Built for the Security Research Community**

[![Join Noctis AI on Discord](https://img.shields.io/badge/Join_Noctis_AI-5865F2?style=for-the-badge&logo=discord&logoColor=white)](https://discord.gg/bBtyAWSkW)

</div>
