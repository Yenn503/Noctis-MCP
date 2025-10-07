# Noctis-MCP

**Hybrid Intelligence System for Malware Development**

Noctis-MCP provides 16 MCP tools that give AI agents (Claude, GPT-4, etc.) access to malware development intelligence. The AI uses this intelligence to write code, not copy templates.

**Status:** Production Ready | **Version:** 2.0 | **Tools:** 16

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
AI WRITES CODE using all the guidance (like you're doing right now)
  ↓
AI calls: validate_code() → compile_code()
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

## 16 MCP Tools

### Core Malware Tools (6)

| Tool | Purpose |
|------|---------|
| `search_intelligence(query, target_av)` | Get RAG intelligence with MITRE TTPs, OPSEC scores |
| `generate_code(techniques, target_av)` | Get guidance for AI to write code |
| `optimize_opsec(code, target_av)` | Get OPSEC improvement recommendations |
| `validate_code(code)` | Check code quality, get warnings |
| `compile_code(code, arch)` | Build binary (Windows/Linux) |
| `record_feedback(techniques, av, detected)` | Record detection results for learning |

### Education System (9)

Interactive learning system with lessons, quizzes, and progress tracking.

### Utility (1)

- `rag_stats()` - RAG system health check

---

## Intelligence Sources

The system uses 4 intelligence sources:

1. **Knowledge Files** - OPSEC guidance, technique comparisons
2. **Security Blogs** - Current detection status (what's detected NOW)
3. **GitHub Repos** - Real-world implementation patterns
4. **VX-API** - Function signatures and prototypes

**Total:** 353+ sources indexed

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
│   │   └── pattern_extractor.py       # Extract patterns from Examples/
│   ├── rag/rag_engine.py           # RAG with caching
│   ├── learning_engine.py          # Detection feedback
│   └── code_assembler.py           # Code assembly
├── noctis_mcp_client/
│   └── noctis_mcp.py               # 16 MCP tools
├── techniques/
│   ├── knowledge/                  # OPSEC guidance files
│   └── security_blogs/             # Detection intelligence
├── external/
│   ├── github_repos/               # Implementation patterns
│   └── VX-API/                     # Function signatures
└── Examples/                       # Reference implementations
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
  └─ 4 Sources: Knowledge, Blogs, GitHub, VX-API
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

- **Tools:** 16 (Core: 6, Education: 9, Utility: 1)
- **Endpoints:** ~25 active v2 endpoints
- **Intelligence:** 353+ indexed sources
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

- **[SYSTEM_OVERVIEW.md](SYSTEM_OVERVIEW.md)** - Complete system explanation
- **[SETUP.md](docs/SETUP.md)** - Detailed setup instructions
- **[INTELLIGENCE_SYSTEM.md](docs/INTELLIGENCE_SYSTEM.md)** - How intelligence works
- **[EDUCATION_SYSTEM.md](docs/EDUCATION_SYSTEM.md)** - Learning system details
- **[C2_INTEGRATION.md](docs/C2_INTEGRATION.md)** - C2 framework integration

---

## What Changed in v2.0

### Removed (Redundant/Old)
- 4 redundant tools (20 → 16 tools)
- Old agent system (`server/agents/`)
- Old v1 endpoints
- Obfuscation/polymorphic modules (not used)

### Added/Improved
- MITRE ATT&CK extraction in all intelligence
- Updated tool descriptions (AI knows to write code)
- Cleaner architecture
- Better documentation

---

## Development

```bash
# Run tests
python -c "from server import agentic_api; print('Server loads successfully')"

# Check tool count
grep -c "^@mcp.tool()" noctis_mcp_client/noctis_mcp.py
# Should output: 16

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

## Links

- **GitHub:** https://github.com/yourusername/Noctis-MCP
- **Issues:** Report bugs and request features
- **Docs:** See `docs/` folder

---

**Built for security research**
