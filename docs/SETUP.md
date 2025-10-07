# Noctis-MCP Setup Guide

**Complete setup instructions for Windows, Linux, and macOS**

## Critical Requirements

**The MCP tools require TWO components running:**
1. **Noctis Server** (Flask API on port 8888)
2. **MCP Client** (via Cursor/VSCode)

**Both must be running simultaneously for MCP tools to work!**

---

## macOS Setup

### Prerequisites
- **Python 3.11+** (3.13.2 recommended)
- **Homebrew** (package manager)
- **Git** (version control)

### Step 1: Install Homebrew (if not installed)
```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

### Step 2: Install Cross-Compiler
```bash
brew install mingw-w64
```

### Step 3: Clone and Setup
```bash
git clone https://github.com/Yenn503/Noctis-MCP.git
cd Noctis-MCP
chmod +x scripts/setup/setup.sh
./scripts/setup/setup.sh
```

### Step 4: Initialize RAG System
```bash
source venv/bin/activate
python scripts/rag_setup.py
```

### Step 5: Configure MCP for Cursor
Edit `~/.cursor/mcp.json`:
```json
{
  "mcpServers": {
    "noctis-mcp": {
      "command": "/path/to/Noctis-MCP/venv/bin/python",
      "args": ["-m", "noctis_mcp_client.noctis_mcp"],
      "cwd": "/path/to/Noctis-MCP",
      "description": "Noctis-MCP v2.0 - Hybrid Intelligence System for Malware Development (17 tools)",
      "timeout": 300,
      "env": {
        "PYTHONPATH": "/path/to/Noctis-MCP"
      }
    }
  }
}
```

**Replace `/path/to/Noctis-MCP` with your actual path!**

### Step 6: Start the Server
```bash
source venv/bin/activate
python server/noctis_server.py --port 8888
```

### Step 7: Restart Cursor
**Completely quit and restart Cursor** for MCP changes to take effect.

---

## Linux Setup

### Prerequisites
- **Python 3.11+**
- **Git**
- **MinGW-w64** (cross-compiler)

### Step 1: Install Dependencies
```bash
# Ubuntu/Debian
sudo apt update
sudo apt install python3.11 python3.11-venv python3-pip git mingw-w64

# CentOS/RHEL/Fedora
sudo dnf install python3.11 python3.11-venv python3-pip git mingw-w64-gcc
```

### Step 2: Clone and Setup
```bash
git clone https://github.com/Yenn503/Noctis-MCP.git
cd Noctis-MCP
chmod +x scripts/setup/setup.sh
./scripts/setup/setup.sh
```

### Step 3: Initialize RAG System
```bash
source venv/bin/activate
python scripts/rag_setup.py
```

### Step 4: Configure MCP for Cursor
Edit `~/.cursor/mcp.json`:
```json
{
  "mcpServers": {
    "noctis-mcp": {
      "command": "/path/to/Noctis-MCP/venv/bin/python",
      "args": ["-m", "noctis_mcp_client.noctis_mcp"],
      "cwd": "/path/to/Noctis-MCP",
      "description": "Noctis-MCP v2.0 - Hybrid Intelligence System for Malware Development (17 tools)",
      "timeout": 300,
      "env": {
        "PYTHONPATH": "/path/to/Noctis-MCP"
      }
    }
  }
}
```

### Step 5: Start the Server
```bash
source venv/bin/activate
python server/noctis_server.py --port 8888
```

### Step 6: Restart Cursor
**Completely quit and restart Cursor** for MCP changes to take effect.

---

## Windows Setup

### Prerequisites
- **Python 3.11+**
- **Git**
- **Visual Studio Build Tools** (for compilation)

### Step 1: Install Visual Studio Build Tools
Download and install from: https://visualstudio.microsoft.com/visual-cpp-build-tools/
- Select "C++ build tools" workload
- Include "Windows 10/11 SDK"

### Step 2: Clone and Setup
```cmd
git clone https://github.com/Yenn503/Noctis-MCP.git
cd Noctis-MCP
scripts\setup\setup.ps1
```

### Step 3: Initialize RAG System
```cmd
venv\Scripts\activate
python scripts\rag_setup.py
```

### Step 4: Configure MCP for Cursor
Edit `%APPDATA%\Cursor\User\mcp.json`:
```json
{
  "mcpServers": {
    "noctis-mcp": {
      "command": "C:\\path\\to\\Noctis-MCP\\venv\\Scripts\\python.exe",
      "args": ["-m", "noctis_mcp_client.noctis_mcp"],
      "cwd": "C:\\path\\to\\Noctis-MCP",
      "description": "Noctis-MCP v2.0 - Hybrid Intelligence System for Malware Development (17 tools)",
      "timeout": 300,
      "env": {
        "PYTHONPATH": "C:\\path\\to\\Noctis-MCP"
      }
    }
  }
}
```

### Step 5: Start the Server
```cmd
venv\Scripts\activate
python server\noctis_server.py --port 8888
```

### Step 6: Restart Cursor
**Completely quit and restart Cursor** for MCP changes to take effect.

---

## Verification Steps

### 1. Check Server Status
```bash
curl http://localhost:8888/health
# Should return: {"status": "healthy", "version": "2.0.0"}
```

### 2. Check Education System
```bash
curl http://localhost:8888/api/v2/education/stats
# Should return: {"total_techniques": 10, "total_modules": 13, "total_quizzes": 70+}
```

### 3. Check RAG System
```bash
curl http://localhost:8888/api/v2/rag/stats
# Should return RAG statistics
```

### 4. Test MCP Tools in Cursor
Ask: **"What MCP tools do you have access to?"**

You should see 17 Noctis tools organized by category:

**Core Malware Tools (7):**
- `search_intelligence` - Search malware techniques via RAG with MITRE TTPs and OPSEC scores
- `generate_code` - Get structured guidance for AI to write malware code
- `optimize_opsec` - Get OPSEC improvement recommendations for existing code
- `validate_code` - Check code quality and get security warnings
- `compile_code` - Cross-compile for Windows from any OS
- `test_detection` - Test binary in live sandbox (Hybrid Analysis) against real AV/EDR
- `record_feedback` - Record detection results to improve system learning

**Education System (9 tools):**
- `list_learning_topics` - Browse 10 curated malware development techniques
- `start_lesson` - Begin interactive lesson on a specific technique
- `get_lesson_module` - Retrieve specific lesson module content
- `take_quiz` - Test knowledge with interactive quizzes
- `get_learning_progress` - View learning progress and achievements
- `check_understanding` - Validate comprehension of current lesson
- `list_quizzes` - Browse available quizzes by technique
- `get_quiz_results` - Review quiz performance history
- `reset_progress` - Reset learning progress for fresh start

**Utility (1):**
- `rag_stats` - View RAG system health and indexed source statistics

---

## Troubleshooting

### "No tools" or Red Circle in Cursor

**Common Causes:**
1. **Server not running** - Start with `python server/noctis_server.py --port 8888`
2. **Wrong Python path** - Use full path to venv Python in MCP config
3. **Missing PYTHONPATH** - Add PYTHONPATH to MCP env variables
4. **Cursor not restarted** - Completely quit and restart Cursor

**Debug Steps:**
```bash
# 1. Check if server is running
curl http://localhost:8888/health

# 2. Test MCP client directly
source venv/bin/activate
python -m noctis_mcp_client.noctis_mcp

# 3. Check MCP config syntax
cat ~/.cursor/mcp.json | python -m json.tool
```

### Server Won't Start

**Port 8888 in use:**
```bash
# Find what's using port 8888
lsof -i :8888  # macOS/Linux
netstat -ano | findstr :8888  # Windows

# Kill the process or use different port
python server/noctis_server.py --port 8889
```

### Import Errors

**Virtual environment not activated:**
```bash
source venv/bin/activate  # macOS/Linux
venv\Scripts\activate     # Windows
```

**Missing dependencies:**
```bash
pip install -r requirements.txt
```

### RAG System Issues

**Reinitialize RAG:**
```bash
source venv/bin/activate
python scripts/rag_setup.py
```

**Check RAG status:**
```bash
curl http://localhost:8888/api/v2/rag/stats
```

---

## Daily Usage

### Starting Noctis-MCP
1. **Start the server:**
   ```bash
   cd /path/to/Noctis-MCP
   source venv/bin/activate
   python server/noctis_server.py --port 8888
   ```

2. **Open Cursor** (MCP tools will be available)

### Stopping Noctis-MCP
1. **Stop server:** `Ctrl+C` in server terminal
2. **Close Cursor**

### Updating Intelligence
```bash
source venv/bin/activate
python scripts/update_intelligence.py
```

---

## Next Steps

1. **Read the README.md** for usage examples
2. **Try the Examples/** directory for sample code
3. **Check docs/** for detailed documentation
4. **Join the community** for support

---

## Legal Notice

**For authorized security research, penetration testing, and red team operations only.**
**Unauthorized use is illegal and prohibited.**

---

## Support

- **GitHub Issues:** https://github.com/Yenn503/Noctis-MCP/issues
- **Documentation:** See `docs/` directory
- **Community:** Check project discussions
