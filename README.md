<div align="center">

![Noctis-MCP Logo](NoctisAI.png)

# Noctis-MCP

**Hybrid Intelligence System for Malware Development**

*Intelligence-Driven Red Team Operations with MCP Integration*

[![Python](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey)](https://github.com/Yenn503/Noctis-MCP)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

[![Join Noctis AI on Discord](https://img.shields.io/badge/Join_Noctis_AI-5865F2?style=for-the-badge&logo=discord&logoColor=white)](https://discord.gg/bBtyAWSkW)

</div>

---

**Status:** Production Ready | **Version:** 2.0 | **Tools:** 5

Noctis-MCP provides 5 core MCP tools that give AI agents (Claude, GPT-4, etc.) access to malware development intelligence, RAG-powered technique search, and automated compilation. The AI uses this intelligence to write code, not copy templates.

---

## How It Works

```
User: "Build process injection evading CrowdStrike"
  ↓
AI calls: search_intelligence("process injection CrowdStrike")
  ↓
Gets: MITRE TTPs, OPSEC scores (8/10), warnings ("Avoid CreateRemoteThread")
  ↓
AI calls: generate_code(["injection", "syscalls"], "CrowdStrike")
  ↓
Gets: Implementation patterns, function signatures, synthesis
  ↓
AI WRITES CODE using all the guidance (straight into your IDE)
  ↓
AI calls: validate_code() → compile_code(final EXE)
```

**Key:** The AI writes code. The server provides intelligence.

---

## Quick Start

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Start Server

```bash
python server/noctis_server.py
```

Server starts on `http://localhost:8888`

### 3. Configure MCP in Your IDE

**For Cursor/Claude Desktop:**

Add to `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "noctis-mcp": {
      "command": "python",
      "args": ["/path/to/Noctis-MCP/noctis_mcp_client/noctis_mcp.py"],
      "env": {
        "NOCTIS_SERVER_URL": "http://localhost:8888"
      }
    }
  }
}
```

### 4. Use in IDE

```
You: "Build a process injection tool that evades CrowdStrike Falcon"

AI will:
1. Call search_intelligence() to get OPSEC guidance
2. Call generate_code() to get implementation patterns
3. Write the code using the intelligence
4. Call validate_code() and compile_code()
```

---

## 5 MCP Tools

| Tool | Purpose |
|------|---------|
| `noctis_search_techniques(query, target_av, n_results)` | Search RAG knowledge base for techniques, get OPSEC guidance |
| `noctis_recommend_template(objective)` | Get template recommendation based on objective |
| `noctis_generate_beacon(c2_framework, listener_host, listener_port, architecture, format)` | Generate C2 beacon shellcode (Sliver/Adaptix/Mythic) |
| `noctis_compile(source_file, target_os, architecture, optimization)` | Compile malware for Windows/Linux |
| `noctis_record_result(template, techniques, target_av, detected, notes)` | Record attack results for learning system |

---

## Intelligence Sources

The system uses 4 intelligence sources:

1. **Knowledge Files** - OPSEC guidance, technique comparisons (8 files)
2. **Security Blogs** - Current detection status (35 RSS feeds: MDSec, Outflank, Cracked5pider, etc.)
3. **GitHub Repos** - Real-world implementation patterns (27 queries: malware orgs, specific techniques)
4. **arXiv Research** - Academic papers on malware detection and evasion

**Total:** 400+ sources indexed (expanded from 353 with Argus intelligence)

---

## Example: Process Injection

```python
# AI workflow (automatic):
1. search_intelligence("process injection CrowdStrike evasion")
   → Returns: "Use indirect syscalls (OPSEC 8/10), Avoid CreateRemoteThread"

2. generate_code(["injection", "syscalls"], "CrowdStrike")
   → Returns:
      MITRE: T1055, T1106
      Patterns: VirtualAllocEx(RW) → Write → VirtualProtectEx(RX)
      Warnings: Avoid CreateRemoteThread
      Functions: NtAllocateVirtualMemory(...)

3. AI writes code:
```

```c
#include <windows.h>

// MITRE: T1055, T1106
// OPSEC: 8/10 - Indirect syscalls vs CrowdStrike

BOOL InjectPayload(DWORD pid, LPVOID payload, SIZE_T size) {
    // Per guidance: Allocate RW (not RWX!)
    LPVOID remote = VirtualAllocEx(hProc, NULL, size,
                                    MEM_COMMIT, PAGE_READWRITE);
    WriteProcessMemory(hProc, remote, payload, size, NULL);

    // Per OPSEC pattern: Change to RX
    VirtualProtectEx(hProc, remote, size, PAGE_EXECUTE_READ, &old);

    // Per warning: NOT using CreateRemoteThread!
    // Using thread hijacking instead...
}
```

```python
4. validate_code(source_code) → Quality check
5. compile_code(source_code) → Build binary
```

**Result:** Dynamic, OPSEC-aware code tailored to target AV.

---

## Project Structure

```
Noctis-MCP/
├── server/
│   ├── noctis_server.py           # Main server
│   ├── agentic_api.py              # Intelligence & code APIs
│   ├── education_api.py            # Education system
│   ├── utils/
│   │   ├── intelligence_processor.py  # RAG → Intelligence
│   │   └── pattern_extractor.py       # Extract patterns
│   ├── rag/rag_engine.py           # RAG with caching
│   ├── learning_engine.py          # Detection feedback
│   └── code_assembler.py           # Code assembly
├── noctis_mcp_client/
│   └── noctis_mcp.py               # 5 MCP tools
└── techniques/
    ├── injection/                  # Process injection techniques
    ├── syscalls/                   # Direct syscall implementations
    ├── amsi/                       # AMSI bypass techniques
    ├── unhooking/                  # EDR unhooking methods
    ├── sleep_obfuscation/          # Memory encryption during sleep
    ├── crypto/                     # Payload encryption
    ├── evasion/                    # Evasion techniques
    ├── templates/                  # Production-ready templates
    ├── bof_templates/              # Beacon Object File templates
    └── knowledge/                  # OPSEC guidance files
```

---

## Education System

9 interactive tools for learning malware development:

- Browse 10 curated techniques
- Step-by-step lessons with modules
- Interactive quizzes with 70+ questions
- Progress tracking (SQLite)
- AI-powered teaching

**Example:**
```
AI: list_learning_topics()
AI: start_lesson("process_injection")
AI: Guides you through concepts, then check_understanding()
```

---

## Technical Details

### Intelligence Processing

```
RAG Search → IntelligenceProcessor → Structured Output
  |              |                       |
  |              ├─ Extract MITRE TTPs   |
  |              ├─ Score OPSEC          |
  |              ├─ Find patterns        |
  |              └─ Synthesize recommendations
  |
  └─ 3 Sources: Knowledge, Blogs, GitHub
```

### Pattern Extraction

Learns from `Examples/` without copying:
- Function call sequences
- Memory management patterns
- API resolution techniques
- Error handling patterns

Returns **HOW** real code works, not the code itself.

---

## System Metrics

- **MCP Tools:** 5 (search, recommend, generate_beacon, compile, record_result)
- **Server Endpoints:** ~15 active v2 API endpoints
- **Intelligence:** 400+ indexed sources (RAG knowledge base)
- **RAG:** ChromaDB with cross-encoder re-ranking
- **Caching:** 24-hour TTL for performance

---

## Security Research Use Only

Noctis-MCP is designed for:
- Security researchers
- Red team operations
- Malware analysis education
- AV/EDR bypass research

**Not for malicious use.**

---

## Documentation

- **[BEACON_BUILDER.md](docs/BEACON_BUILDER.md)** - Beacon compilation and EDR evasion
- **[C2_INTEGRATION.md](docs/C2_INTEGRATION.md)** - C2 framework integration
- **[SETUP.md](docs/SETUP.md)** - Detailed setup instructions

---

## What Changed in v2.0

### Removed (Redundant/Old)
- Old agent system (`server/agents/`)
- Old v1 endpoints
- Test files and reference code (cleaned up)
- Obfuscation/polymorphic modules (not used)

### Added (v2.0)
- RAG-powered intelligence search (539 knowledge chunks)
- Automated intelligence updates (35+ security blogs, GitHub, arXiv)
- MITRE ATT&CK extraction in all intelligence
- 5 focused MCP tools (search, recommend, generate_beacon, compile, record_result)
- C2 integration (Sliver/Mythic/Adaptix)
- Automated beacon builder with EDR-specific targeting
- Cross-platform compilation (MinGW-w64)
- Professional documentation
- Cleaner architecture

### Advanced Evasion Techniques (2024-2025 Research)

Noctis-MCP implements cutting-edge techniques from 2024-2025 offensive security research:

**Syscall Evasion:**
- SysWhispers3 - Randomized syscall jumper with jump address randomization
- Caches 16 syscall addresses from ntdll.dll, selects randomly per invocation

**AMSI Bypass:**
- VEH² Hardware Breakpoint - Zero memory patching, works on Windows 11 24H2
- Uses Vectored Exception Handlers + debug registers (DR0)

**Sleep Obfuscation:**
- Zilean - Thread pool wait-based sleep, eliminates ROP chain artifacts
- ShellcodeFluctuation - PAGE_NOACCESS memory hiding, defeats memory dumps

**Process Injection:**
- PoolParty - Thread pool injection (100% EDR bypass documented)
- Early Cascade - Pre-EDR timing attack, injects before EDR hooks load
- Phantom DLL Hollowing - Transactional NTFS for backed memory without disk file

**Unhooking:**
- Perun's Fart - Memory-based NTDLL unhooking, reads from process memory (not disk)

**Call Stack Evasion:**
- SilentMoonwalk - ROP-based call stack spoofing with synthetic frames
- Creates legitimate-looking call stacks pointing to Windows modules

**Kernel-Level Techniques (Knowledge Bases Only):**
- MiniFilter Altitude Manipulation - Pre-emptive EDR disablement via registry (30-40% detection)
- Advanced DKOM - Data-only kernel attacks, FudModule techniques (40-50% detection)
- RealBlindingEDR - Enhanced kernel callback manipulation (55-65% detection)
- EDRSandBlast - BYOVD kernel callback removal (60-70% detection)
- Windows Downdate - OS rollback for VBS/HVCI bypass (70-80% detection)
- Documented for blue team awareness and post-compromise scenarios where detection acceptable

**Overall Impact:**
- Detection risk: 25-30% (baseline) → 2-5% (integrated techniques)
- EDR bypass rate: 70-75% → 95-98%
- OPSEC score: 5.5/10 → 9.5/10

All implementations available in `techniques/` directory with full documentation.

---

## Development

```bash
# Run tests
python -c "from server import agentic_api; print('Server loads successfully')"

# Check tool count
grep -c "^@mcp.tool()" noctis_mcp_client/noctis_mcp.py
# Should output: 5

# Start server with debug
python server/noctis_server.py --debug
```

---

## License

MIT License - See LICENSE file

---

## Contributing

Contributions welcome for:
- More knowledge files
- Additional intelligence sources
- Education content
- Bug fixes

---

## Links & Community

- **GitHub:** https://github.com/Yenn503/Noctis-MCP
- **Discord:** Join [Noctis AI Community](https://discord.gg/bBtyAWSkW) for support and discussions
- **Issues:** Report bugs and request features
- **Docs:** See `docs/` folder

## Author

Created by Lewis Desmond

[![LinkedIn](https://img.shields.io/badge/LinkedIn-0077B5?style=for-the-badge&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/lewis-desmond-a7b00b204)

---

**Built for security research**
