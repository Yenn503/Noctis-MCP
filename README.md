<div align="center">

![Noctis-MCP Logo](NoctisAI.png)

**AI-Powered Malware Development & Learning Platform**

*Intelligence-Driven Red Team Operations with Interactive Education*

[![Python](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey)](https://github.com/Yenn503/Noctis-MCP)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![MCP Tools](https://img.shields.io/badge/MCP%20Tools-20-brightgreen)](https://github.com/Yenn503/Noctis-MCP)

</div>

## Join the community

[![Join Noctis AI on Discord](https://img.shields.io/badge/Join_Noctis_AI-5865F2?style=for-the-badge&logo=discord&logoColor=white)](https://discord.gg/bBtyAWSkW)

**Legal Disclaimer**: For authorised security research, penetration testing, and red team operations only. Unauthorised use is illegal and prohibited.

---

##  What is Noctis-MCP?

**Noctis-MCP** is an AI-powered malware development and learning platform that transforms your IDE into a sophisticated red team education and operations center. It combines:

-  **RAG-Powered Intelligence** - Access research and real-world implementations
-  **Dynamic Code Generation** - Generate ready malware with AI assistance
-  **Interactive Learning System** - Learn 10 malware techniques from beginner to advanced
-  **Progress Tracking** - Track your learning journey with quizzes and achievements

Think of it as having both a **malware development expert** and a **personal tutor** integrated directly into your IDE.

---

##  Key Features

### **Interactive Education System** 

**Learn malware development interactively with AI as your tutor:**

- **10 Curated Techniques** - From Process Injection to Advanced Syscalls
- **13 Learning Modules** - Theory, code examples, and hands-on labs
- **70+ Quiz Questions** - Test your understanding with detailed explanations
- **Progress Tracking** - SQLite database tracks completed modules and quiz scores
- **Achievements System** - Earn badges as you progress through the curriculum
- **AI Tutor** - Interactive Q&A with Claude/GPT-4 using your IDE chat

**Just ask: "I want to learn malware development"** and start your journey!

### **Intelligence Engine**

- **RAG-Powered Search** - 55+ knowledge chunks, GitHub repos, research papers
- **Auto-Update System** - Fetches latest intelligence from 25+ security blogs
- **Smart Caching** - 24hr cache prevents redundant fetches
- **Detection Intelligence** - EDR/AV bypass patterns and effectiveness scores
- **Learning System** - Records detection results to improve recommendations

### **20 Agentic MCP Tools**

**Intelligence Gathering (3 tools):**
- `search_intelligence()` - Search RAG with auto-update if data >7 days old
- `analyze_technique()` - Deep dive into specific techniques
- `fetch_latest()` - Get cutting-edge intelligence (24hr smart cache)

**Code Generation (3 tools):**
- `generate_code()` - RAG-informed dynamic code generation
- `optimize_opsec()` - Improve code stealth using intelligence
- `validate_code()` - Compile & quality check with error feedback

**Technique Selection (2 tools):**
- `select_techniques()` - AI-powered technique recommendations
- `compare_techniques()` - Side-by-side analysis

**Compilation & Feedback (2 tools):**
- `compile_code()` - Build binaries
- `record_feedback()` - Learning from testing results

**Interactive Learning (9 tools):**
- `list_learning_topics()` - Browse curriculum
- `start_lesson()` - Begin learning a technique
- `get_lesson_module()` - Get module content
- `complete_module()` - Mark module as done
- `check_understanding()` - Take quiz
- `submit_quiz()` - Submit quiz answers
- `get_learning_progress()` - View progress
- `get_recommended_lesson()` - Get next suggestion
- `search_lessons()` - Search for topics

**Utilities (1 tool):**
- `rag_stats()` - RAG system status

### 💻 **Advanced Capabilities**

- **Dynamic Code Generation** - RAG-informed assembly using real GitHub patterns
- **10 MITRE ATT&CK Techniques** - Syscalls, injection, encryption, steganography, etc.
- **C2 Framework Integration** - Sliver, Adaptix, Mythic with BOF support
- **BOF Compilation** - Beacon Object Files for Sliver/Adaptix/Mythic Forge
- **Linux Cross-Compilation** - MinGW + NASM + windres for Windows payloads
- **Multi-File Projects** - C/C++ + Assembly + Resources compilation
- **OPSEC Optimisation** - String encryption, API hashing, control flow obfuscation

---

##  Quick Start

### ⚠️ **System Requirements**

**Noctis-MCP requires TWO components running simultaneously:**

1. **Noctis Server** (Flask API on port 8888)
2. **MCP Client** (via Cursor/VSCode)

**Both must be running for the MCP tools to work!**

### Prerequisites

- **Python 3.11+** (3.13.2 recommended)
- **Compiler**: MinGW-w64 (Linux/macOS) or Visual Studio Build Tools (Windows)
- **MCP-Compatible IDE**: Cursor, VSCode with Claude/Copilot
- **4GB RAM minimum** (8GB+ recommended for RAG)

---

## Installation

### **Step 1: Clone Repository**

```bash
git clone https://github.com/Yenn503/Noctis-MCP.git
cd Noctis-MCP
```

### **Step 2: Install Dependencies**

<details>
<summary><b>🐧 Linux (Ubuntu/Debian)</b></summary>

```bash
# Install system dependencies
sudo apt update
sudo apt install -y python3 python3-pip python3-venv mingw-w64 git

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install Python packages
pip install --upgrade pip
pip install -r requirements.txt
```

</details>

<details>
<summary><b>🍎 macOS</b></summary>

```bash
# Install Homebrew if not already installed
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install dependencies
brew install python@3.13 mingw-w64

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install Python packages
pip install --upgrade pip
pip install -r requirements.txt
```

</details>

<details>
<summary><b>🪟 Windows</b></summary>

```powershell
# Install Python 3.11+ from python.org
# Install Visual Studio Build Tools from Microsoft

# Create virtual environment
python -m venv venv
.\venv\Scripts\activate

# Install Python packages
pip install --upgrade pip
pip install -r requirements.txt
```

</details>

### **Step 3: Start Noctis Server**

```bash
# Activate virtual environment first
source venv/bin/activate  # Linux/macOS
# OR
.\venv\Scripts\activate   # Windows

# Start server
python server/noctis_server.py --port 8888
```

**Expected output:**
```
[+] Connected to server: http://127.0.0.1:8888
[+] RAG System: ENABLED (55 knowledge chunks indexed)
[+] Education System: 10 techniques, 13 modules, 70+ quizzes
[*] 20 Agentic Tools Available
```

### **Step 4: Configure IDE (Cursor/VSCode)**

<details>
<summary><b>Cursor IDE Setup</b></summary>

1. Open Cursor Settings (Cmd/Ctrl + ,)
2. Navigate to "Features" → "Model Context Protocol"
3. Add MCP server configuration:

**Add to Cursor's MCP settings:**
```json
{
  "mcpServers": {
    "noctis": {
      "command": "/path/to/Noctis-MCP/venv/bin/python",
      "args": [
        "-m",
        "noctis_mcp_client.noctis_mcp"
      ],
      "cwd": "/path/to/Noctis-MCP"
    }
  }
}
```

4. Replace `/path/to/Noctis-MCP` with your actual venv installation path
5. Restart Cursor

</details>

<details>
<summary><b>VSCode Setup</b></summary>

1. Install MCP extension for VSCode
2. Open VSCode settings (Cmd/Ctrl + ,)
3. Search for "MCP" settings
4. Add server configuration:

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

5. Reload VSCode window

</details>

### **Step 5: Verify Installation**

In your IDE, ask the AI:

```
"List learning topics"
```

**Expected response:**
```
📚 MALWARE DEVELOPMENT CURRICULUM
✅ 10 techniques available:

🟢 BEGINNER LEVEL:
  • Process Injection Fundamentals (45 min)
  • Persistence Mechanisms (50 min)

🟡 INTERMEDIATE LEVEL:
  • Shellcode Injection (60 min)
  • PE File Manipulation (70 min)
  ...
```

---

##  Usage Examples

### 🎓 **Learning Mode**

**Start Learning:**
```
You: "I want to learn malware development"
AI: Shows 10 techniques organized by difficulty

You: "Teach me process injection"
AI: Delivers 4 interactive modules with theory, code, and labs

You: "Give me a quiz"
AI: Presents 10 questions, grades answers, and shows explanations
```

### **Intelligence Research**

**Search for Techniques:**
```
You: "Find the latest process injection techniques"
AI: Searches RAG, returns 10 intelligence sources from:
    - Knowledge base
    - GitHub repos
    - Research papers
    - Security blogs
```

**Analyse Specific Technique:**
```
You: "Analyse direct syscalls for EDR bypass"
AI: Returns detailed analysis with:
    - How it works
    - Evasion effectiveness
    - Code examples
    - Detection methods
```

### 💻 **Code Generation**

**Generate Malware:**
```
You: "Generate process injection code using syscalls"
AI: Generates complete, compilable C code with:
    - Direct syscall implementation
    - String obfuscation
    - Error handling
    - Build instructions
```

**Optimise for OPSEC:**
```
You: "Optimise this code for stealth"
AI: Enhances with:
    - API hashing
    - String encryption
    - Control flow obfuscation
    - Anti-debugging checks
```

### **Progress Tracking**

**Check Progress:**
```
You: "Show my learning progress"
AI: Displays:
    - Completed techniques: 3
    - In progress: 2
    - Quiz scores: 90%, 85%, 100%
    - Achievements earned: 5
```

---

## 📂 Project Structure

```
Noctis-MCP/
│
├── noctis_mcp_client/          # MCP client (20 tools)
│   └── noctis_mcp.py           # Tool definitions + formatters
│
├── server/                      # Flask API server
│   ├── noctis_server.py        # Main server entry point
│   ├── agentic_api.py          # RAG-powered intelligence API
│   ├── education_api.py        # Learning system API (15 endpoints)
│   │
│   ├── rag/                    # RAG engine
│   │   ├── rag_engine.py       # ChromaDB wrapper
│   │   └── embedder.py         # Sentence transformers
│   │
│   ├── education/              # Education system
│   │   ├── lesson_manager.py  # Curated lesson delivery
│   │   └── learning_engine.py # Progress tracking, quizzes
│   │
│   ├── agents/                 # Specialized AI agents
│   └── intelligence/           # Live intelligence feeds
│
├── data/                       # Data files
│   ├── lessons.json            # 10 curated techniques (28K lines)
│   ├── quizzes.json            # 70+ quiz questions
│   ├── rag_db/                 # ChromaDB (auto-created)
│   └── education_progress.db   # SQLite (auto-created)
│
├── techniques/                 # Knowledge base
│   ├── knowledge/              # Markdown files
│   └── metadata/               # Technique metadata
│
├── docs/                       # Documentation
│   ├── ARCHITECTURE.md         # System architecture
│   ├── EDUCATION_SYSTEM.md     # Learning system docs
│   └── SETUP.md                # Detailed setup guide
│
├── scripts/                    # Utility scripts
│   ├── intelligence_updater.py # Background intelligence gathering
│   └── setup_auto_update.sh    # Cron automation
│
├── config.yaml                 # System configuration
├── requirements.txt            # Python dependencies
└── README.md                   # This file
```

---

## 🎓 Learning Curriculum

### **Beginner Level**
1. **Process Injection Fundamentals** (45 min)
   - Classic DLL injection
   - Remote thread creation
   - Memory manipulation basics

2. **Persistence Mechanisms** (50 min)
   - Registry Run keys
   - Scheduled tasks
   - Service installation

### **Intermediate Level**
3. **Shellcode Injection** (60 min)
   - Position-independent code
   - RWX memory allocation
   - Staged payloads

4. **PE File Manipulation** (70 min)
   - PE structure understanding
   - Section manipulation
   - Code cave injection

5. **Code Obfuscation** (55 min)
   - String encryption
   - Control flow flattening
   - API obfuscation

6. **C2 Protocols** (65 min)
   - HTTP/HTTPS C2
   - DNS tunnelling
   - Beaconing strategies

### **Advanced Level**
7. **Process Hollowing** (75 min)
   - Process creation in suspended state
   - Memory unmapping
   - Entry point modification

8. **API Hooking** (90 min)
   - IAT hooking
   - Inline hooking
   - Trampoline functions

9. **Direct Syscalls** (80 min)
   - Bypassing userland hooks
   - Hell's Gate / Halo's Gate
   - SysWhispers implementation

10. **Crypters & Packers** (85 min)
    - Encryption techniques
    - Polymorphic code
    - Reflective PE loading

---

## 🔧 Configuration

### config.yaml

```yaml
server:
  host: 127.0.0.1
  port: 8888
  debug: false

paths:
  techniques: techniques
  knowledge: techniques/knowledge
  lessons: data/lessons.json
  quizzes: data/quizzes.json
  rag_db: data/rag_db
  education_db: data/education_progress.db

rag:
  enabled: true
  auto_update_days: 7
  cache_hours: 24
```

---

## 📊 Intelligence Sources

Noctis-MCP aggregates intelligence from 25+ sources:

**Security Blogs:**
- MDSec, Outflank, VX-Underground
- Malware-Traffic-Analysis, MalwareTech
- SANS, Krebs on Security, Bleeping Computer
- *...and 18 more*

**GitHub:**
- 20+ malware-specific queries
- Trending repositories
- Real-world implementations

**Research:**
- arXiv security papers
- Conference proceedings
- Academic research

---

##  Documentation

- **[SETUP.md](docs/SETUP.md)** - Detailed installation for all platforms
- **[ARCHITECTURE.md](docs/ARCHITECTURE.md)** - System architecture and data flows
- **[EDUCATION_SYSTEM.md](docs/EDUCATION_SYSTEM.md)** - Learning system deep dive
- **[C2_INTEGRATION.md](docs/C2_INTEGRATION.md)** - C2 framework integration guide

---

## Contributing

We welcome contributions! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

**Priority areas:**
- New malware techniques
- Additional quiz questions
- Intelligence source integrations
- Documentation improvements

---

## Security & Ethics

**Noctis-MCP is designed for:**
- ✅ Security research and education
- ✅ Authorised penetration testing
- ✅ Red team operations with permission
- ✅ Detection rule development

**NOT for:**
- ❌ Unauthorised access to systems
- ❌ Malicious activities
- ❌ Distribution of harmful software

**By using this tool, you agree to use it responsibly and legally.**

---

## 📜 License

MIT License - See [LICENSE](LICENSE) for details

---

<div align="center">

**Made with ❤️ by Yenn for the Community**

[![Join Noctis AI on Discord](https://img.shields.io/badge/Join_Noctis_AI-5865F2?style=for-the-badge&logo=discord&logoColor=white)](https://discord.gg/bBtyAWSkW)

</div>
