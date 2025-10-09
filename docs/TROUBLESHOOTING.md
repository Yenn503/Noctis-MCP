# Noctis-MCP Troubleshooting Guide

Common issues and solutions for Noctis-MCP setup and usage.

---

## Table of Contents

1. [Setup Issues](#setup-issues)
2. [Server Won't Start](#server-wont-start)
3. [MCP Tools Not Working](#mcp-tools-not-working)
4. [Compilation Failures](#compilation-failures)
5. [C2 Beacon Generation](#c2-beacon-generation)
6. [RAG/Search Issues](#ragsearch-issues)
7. [Performance Problems](#performance-problems)

---

## Setup Issues

### Virtual Environment Won't Create

**Symptom:**
```bash
python3 -m venv venv
Error: No module named venv
```

**Solution:**
```bash
# Ubuntu/Debian
sudo apt install python3-venv python3-pip

# CentOS/RHEL/Fedora
sudo dnf install python3-venv python3-pip

# macOS
brew install python@3.11
```

---

### pip install fails with "permission denied"

**Symptom:**
```
ERROR: Could not install packages due to an OSError: [Errno 13] Permission denied
```

**Solution:**
```bash
# DON'T use sudo pip! Instead, activate venv first:
source venv/bin/activate  # Linux/macOS
venv\Scripts\activate     # Windows

# Then install:
pip install -r requirements.txt
```

---

### MinGW not found on Linux

**Symptom:**
```
✗ MinGW x64 - Install: sudo apt install mingw-w64
```

**Solution:**
```bash
# Ubuntu/Debian
sudo apt update
sudo apt install mingw-w64

# Verify installation
x86_64-w64-mingw32-gcc --version
```

---

## Server Won't Start

### Port 8888 already in use

**Symptom:**
```
OSError: [Errno 98] Address already in use
```

**Solution:**

**Option 1: Kill existing process**
```bash
# Find process using port 8888
lsof -i :8888

# Kill it
kill -9 <PID>
```

**Option 2: Use different port**
```bash
python server/noctis_server.py --port 8889
```

**Option 3: Check if old server running**
```bash
# Find all noctis_server processes
ps aux | grep noctis_server

# Kill all
pkill -f noctis_server
```

---

### ImportError: No module named 'chromadb'

**Symptom:**
```
ImportError: No module named 'chromadb'
ModuleNotFoundError: No module named 'sentence_transformers'
```

**Solution:**
```bash
# Ensure venv activated
source venv/bin/activate

# Install RAG dependencies
pip install chromadb sentence-transformers

# Verify
python -c "import chromadb; print('✓ ChromaDB installed')"
```

---

### RAG engine initialization failed

**Symptom:**
```
[WARNING] RAG engine initialization failed: ...
[WARNING] Agentic features will be disabled
```

**Solution:**

**1. Check dependencies:**
```bash
source venv/bin/activate
pip install chromadb sentence-transformers torch
```

**2. Check disk space:**
```bash
df -h  # Ensure >1GB free in data/rag_db
```

**3. Re-initialize RAG:**
```bash
rm -rf data/rag_db
python scripts/rag_setup.py
```

---

## MCP Tools Not Working

### Red circle in Cursor / "No tools found"

**Symptom:**
- Cursor shows red circle next to Noctis-MCP
- Asking "What MCP tools do you have?" shows nothing

**Root Causes & Solutions:**

#### 1. Server not running
```bash
# Check if server running
curl http://localhost:8888/health

# If not running, start it:
./start_server.sh
```

#### 2. Wrong Python path in MCP config
```bash
# Generate correct config
python scripts/generate_mcp_config.py

# Copy output to Cursor Settings → MCP
```

#### 3. Cursor not restarted
```
1. Completely quit Cursor (Cmd+Q / Alt+F4)
2. Restart Cursor
3. Wait 10 seconds
4. Ask: "What MCP tools do you have?"
```

#### 4. PYTHONPATH not set
Check your MCP config includes:
```json
{
  "env": {
    "PYTHONPATH": "/absolute/path/to/Noctis-MCP"
  }
}
```

---

### "Connection refused" error

**Symptom:**
```
ERROR: Noctis server not running. Start with: python3 server/noctis_server.py
```

**Solution:**

1. **Check server status:**
```bash
curl http://localhost:8888/health
```

2. **If server not running, check why:**
```bash
# Check if venv activated
which python  # Should show venv/bin/python

# Try starting manually to see errors
python server/noctis_server.py --port 8888
```

3. **Check firewall:**
```bash
# Linux: Allow port 8888
sudo ufw allow 8888

# macOS: Check System Preferences → Security → Firewall
```

---

### Tools connect but return errors

**Symptom:**
```
Tool: noctis_search_techniques
Error: 500 Internal Server Error
```

**Solution:**

1. **Check server logs:**
```bash
# Server will print errors to console
# Look for tracebacks
```

2. **Verify server health:**
```bash
curl http://localhost:8888/health
# Should return:
# {"status":"healthy","version":"2.0.0",...}
```

3. **Test RAG directly:**
```bash
curl -X POST http://localhost:8888/api/v2/search \
  -H "Content-Type: application/json" \
  -d '{"query":"test","target_av":"Defender","n_results":5}'
```

---

## Compilation Failures

### MSBuild not found (on Linux)

**Symptom:**
```
ERROR: MSBuild not found. Please install Visual Studio Build Tools.
```

**Root Cause:** Server trying to use Windows compiler on Linux

**Solution:** Already fixed in server/agentic_api.py. Update to latest version:
```bash
git pull origin main
```

---

### MinGW compilation fails with "undefined reference"

**Symptom:**
```
undefined reference to `__imp_CreateFileA`
undefined reference to `__imp_VirtualAllocEx`
```

**Solution:**

**Add missing libraries:**
```c
// At top of your .c file:
#pragma comment(lib, "kernel32")
#pragma comment(lib, "user32")
#pragma comment(lib, "advapi32")
```

**Or specify in compilation:**
```bash
x86_64-w64-mingw32-gcc malware.c -o malware.exe \
  -lkernel32 -luser32 -ladvapi32 -lws2_32
```

---

### "Permission denied" when writing compiled binary

**Symptom:**
```
OSError: [Errno 13] Permission denied: 'compiled/malware.exe'
```

**Solution:**
```bash
# Check permissions on compiled/ directory
ls -ld compiled/

# Fix permissions
chmod 755 compiled/

# If directory doesn't exist
mkdir -p compiled
```

---

## C2 Beacon Generation

### "Sliver C2 server not detected"

**Symptom:**
```json
{
  "success": false,
  "error": "Sliver C2 server not detected",
  "status": "not_installed"
}
```

**Solution:**

**1. Install Sliver:**
```bash
curl https://sliver.sh/install | sudo bash
```

**2. Start Sliver server:**
```bash
sliver-server daemon
```

**3. Create listener:**
```bash
sliver-client
> https --lhost 0.0.0.0 --lport 443
> jobs  # Verify listener running
```

**4. Retry beacon generation:**
```
AI: "Generate Sliver beacon for 10.0.0.1:443"
```

---

### "Failed to connect to Sliver server"

**Symptom:**
```
Error: Failed to connect to Sliver server
```

**Solutions:**

**1. Check Sliver server running:**
```bash
pgrep -f sliver-server
# Should return process ID
```

**2. Check Sliver configs:**
```bash
ls ~/.sliver/configs/
# Should have sliver-client.cfg
```

**3. Test Sliver client connection:**
```bash
sliver-client
# Should connect without errors
```

**4. If all else fails, reinstall:**
```bash
curl https://sliver.sh/install | sudo bash
```

---

### Alternative: Standalone beacon without C2

If C2 setup is too complex, use standalone template:

```
AI: "I want to bypass CrowdStrike EDR"
# Will recommend integrated_loader.c template
# No C2 server required!
```

---

## RAG/Search Issues

### "No results found" for valid queries

**Symptom:**
```
Query: "process injection"
Results Found: 0
```

**Solutions:**

**1. Check RAG database initialized:**
```bash
ls -lh data/rag_db/chroma.sqlite3
# Should be > 1MB
```

**2. Re-index knowledge base:**
```bash
source venv/bin/activate
python scripts/rag_setup.py
```

**3. Check knowledge files exist:**
```bash
ls techniques/knowledge/
# Should have: injection.md, syscalls.md, etc.
```

**4. Test RAG directly:**
```python
from server.rag.rag_engine import RAGEngine
rag = RAGEngine(persist_dir='data/rag_db')
results = rag.search_knowledge("test", n_results=5)
print(f"Found {len(results)} results")
```

---

### Negative relevance scores (-104%)

**Symptom:**
```
Relevance: -104.2%
Relevance: -123.5%
```

**Solution:** Already fixed in server/agentic_api.py. Update to latest:
```bash
git pull origin main
```

Scores now normalized to 0-100%.

---

### RAG search is slow (>10 seconds)

**Solutions:**

**1. Reduce result count:**
```
noctis_search_techniques("query", "AV", n_results=5)  # Instead of 10
```

**2. Check system resources:**
```bash
htop  # Look for high CPU/memory usage
```

**3. Clear embedding cache:**
```bash
rm -rf /tmp/noctis_embedding_cache
```

**4. Upgrade hardware:**
- RAG requires: 4GB RAM, 2 CPU cores minimum
- Recommended: 8GB RAM, 4 CPU cores

---

## Performance Problems

### Server uses 100% CPU

**Cause:** RAG indexing or heavy search queries

**Solutions:**

**1. Wait for indexing to complete:**
```
First startup: 30-60 seconds to index
Check logs: "RAG engine initialized: ..."
```

**2. Limit concurrent searches:**
- Don't spam search queries
- Wait for previous search to complete

**3. Reduce embedding model size:**
Edit `server/rag/rag_engine.py`:
```python
# Change from:
model_name = 'all-MiniLM-L6-v2'  # 384 dimensions

# To lighter model:
model_name = 'all-MiniLM-L12-v2'  # Faster but less accurate
```

---

### "Database is locked" error

**Symptom:**
```
sqlite3.OperationalError: database is locked
```

**Solution:** Already fixed in server/utils/learning.py. Update to latest:
```bash
git pull origin main
```

Now uses WAL mode with 30s timeout.

---

### High memory usage (>4GB)

**Cause:** RAG embedding model loaded in memory

**Solutions:**

**1. Restart server periodically:**
```bash
# Every 24 hours
pkill -f noctis_server
./start_server.sh
```

**2. Disable RAG if not needed:**
```python
# Edit config.yaml:
rag:
  enabled: false
```

**3. Use swap space:**
```bash
# Add 4GB swap (Linux)
sudo fallocate -l 4G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
```

---

## Still Having Issues?

### Run Verification Script

```bash
python verify_setup.py
```

This checks:
- Python version
- Dependencies
- Compilers
- Server health
- RAG database
- File structure

### Get Debug Logs

```bash
# Start server with debug mode
python server/noctis_server.py --debug --port 8888 > debug.log 2>&1
```

### Check GitHub Issues

https://github.com/Yenn503/Noctis-MCP/issues

Search for your error message. If not found, create a new issue with:
1. OS and Python version
2. Output of `python verify_setup.py`
3. Server logs (last 50 lines)
4. Steps to reproduce

---

## Quick Reference

| Problem | Quick Fix |
|---------|-----------|
| Server won't start | `pkill -f noctis_server && ./start_server.sh` |
| Tools not showing | Generate new MCP config, restart Cursor completely |
| Compilation fails | Check MinGW installed: `x86_64-w64-mingw32-gcc --version` |
| C2 beacon fails | Check framework installed and running |
| No search results | Re-index: `python scripts/rag_setup.py` |
| Database locked | Update code: `git pull origin main` |

---

**For more help:**
- Documentation: `docs/SETUP.md`
- GitHub: https://github.com/Yenn503/Noctis-MCP/issues
- Discord: [Noctis AI Community](https://discord.gg/bBtyAWSkW)
