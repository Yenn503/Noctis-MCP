# Noctis-MCP System Overview

**Version:** 2.0 (Hybrid Intelligence System)
**Tools:** 17 MCP tools
**Status:** Production Ready

---

## How It Works

```
USER: "Build process injection evading CrowdStrike"
    ↓
AI (Cursor/Claude): Calls search_intelligence("process injection CrowdStrike")
    ↓
SERVER: Returns structured intelligence
  {
    "mitre_ttps": ["T1055", "T1106"],
    "recommendations": [{"technique": "Indirect Syscalls", "opsec_score": 8}],
    "warnings": ["Avoid CreateRemoteThread"],
    ...
  }
    ↓
AI: Understands OPSEC guidance
    ↓
AI: Calls generate_code(["syscalls"], "CrowdStrike")
    ↓
SERVER: Returns patterns + guidance
  {
    "intelligence": {...OPSEC scores, warnings...},
    "patterns": {...function sequences, memory patterns...},
    "vx_api_functions": [...signatures...],
    "synthesis": {...recommended approach...}
  }
    ↓
AI: WRITES CODE NORMALLY in editor (like you're doing now)
    ↓
AI: Calls validate_code(source_code="...") to self-check
    ↓
AI: Calls compile_code(source_code="...") to build binary
    ↓
AI: Calls record_feedback(...) after testing
```

**KEY POINT:** The AI writes code normally in the IDE. The server provides intelligence/guidance, not code files.

---

## 17 MCP Tools

### Core Malware Tools (7)

1. **search_intelligence(query, target_av)** → Get RAG intelligence
   Returns: MITRE TTPs, OPSEC scores, recommendations, warnings

2. **generate_code(technique_ids, target_av)** → Get guidance for writing code
   Returns: Intelligence, patterns, function signatures, synthesis

3. **optimize_opsec(source_code, target_av)** → Get OPSEC improvement tips
   Returns: Suggested improvements, better techniques

4. **validate_code(source_code)** → Check code quality
   Returns: Compilation check, quality metrics, warnings

5. **compile_code(source_code, architecture)** → Build binary
   Returns: Binary path or compilation errors

6. **test_detection(binary_path, target_av, environment)** → Test in live sandbox
   Returns: Detection verdict, OPSEC score, signatures, recommendations

7. **record_feedback(techniques, av, detected)** → Record detection results
   Returns: Updated effectiveness scores

### Education Tools (9)

8-16. Full interactive learning system
   - List topics, start lessons, get modules, take quizzes, track progress

### Utility (1)

17. **rag_stats()** → System health check
   Returns: RAG status, indexed sources count

---

## What Changed

### Removed (Redundant Tools)
- ❌ `analyze_technique()` - AI can use `search_intelligence()` with specific query
- ❌ `fetch_latest()` - Should be automatic server background job
- ❌ `select_techniques()` - AI is smart enough to decide
- ❌ `compare_techniques()` - AI can compare using search results

### Removed (Old Code)
- ❌ `server/agents/` - Old agent system
- ❌ `server/obfuscation/` - Only used by old system
- ❌ `server/polymorphic/` - Only used by old system
- ❌ `server/opsec_analyzer.py` - Superseded by IntelligenceProcessor
- ❌ 13 old v1 endpoints from noctis_server.py

### Added/Improved (Initial v2.0)
- ✅ IntelligenceProcessor extracts MITRE TTPs automatically
- ✅ Updated MCP formatter to show intelligence (not code files)
- ✅ Cleaned MCP client (20 tools → 16 tools → 17 tools)
- ✅ Added live detection testing with Hybrid Analysis
- ✅ Automated intelligence updates from 35+ sources
- ✅ OPSEC-aware workflow to prevent technique burning

### Phase 1 Upgrades (Latest)
- ✅ **SysWhispers3** - Randomized syscall jumper (15-20% detection vs 20-25%)
- ✅ **VEH² AMSI Bypass** - Hardware breakpoint method, Windows 11 24H2 compatible
- ✅ **Zilean Sleep Obfuscation** - Thread pool wait-based (5-10% vs 30-35% ROP chains)
- ✅ **PoolParty Injection** - Thread pool injection (0-5% detection, 100% EDR bypass documented)
- ✅ Expanded intelligence sources (35 RSS feeds, 27 GitHub queries, arXiv papers)
- ✅ Updated knowledge base (4 new technique documentation files)

---

## Intelligence Sources

The system uses 4 intelligence sources (expanded in Phase 1):

1. **Knowledge Files** (`techniques/knowledge/*.md`) - **7 files**
   - Strategic OPSEC guidance
   - WHY techniques work, detection risks
   - **New:** SysWhispers3, VEH² AMSI, Zilean, PoolParty documentation

2. **Security Blogs** (RSS feeds) - **35 sources**
   - Current detection status (WHAT'S detected NOW)
   - **New:** Cracked5pider, RedOps, Alice Climent-Pommeret, Elastic Security Labs
   - Sources: MDSec, Outflank, VX-Underground, Binary Defense, Cyberark Labs, etc.

3. **GitHub Repos** (live search) - **27 queries**
   - Real-world implementations, HOW code works
   - **New:** Org-specific (Cracked5pider, SafeBreach-Labs, Maldev-Academy, outflanknl)
   - Technique-specific (PoolParty, Zilean, SysWhispers3, VEH AMSI, RecycledGate)

4. **arXiv Research Papers** - **Academic security research**
   - Latest malware detection/evasion papers
   - Adversarial ML, EDR bypass techniques
   - Polymorphic malware, syscall hooking research

**Total:** 400+ sources indexed (expanded from 353)

---

## Example Workflow

```bash
# 1. Start Noctis server
python server/noctis_server.py

# 2. In Cursor/Claude IDE with MCP configured:
User: "Build a process injection tool evading CrowdStrike"

# AI automatically:
# - Calls search_intelligence("process injection CrowdStrike")
# - Learns: Use indirect syscalls (OPSEC 8/10), avoid CreateRemoteThread
# - Calls generate_code(["syscalls", "injection"], "CrowdStrike")
# - Gets: Patterns, function signatures, implementation order
# - WRITES CODE in editor using guidance
# - Calls validate_code() to check quality
# - Calls compile_code() to build
# - User tests, AI calls record_feedback() with results
```

---

## Files Structure

```
Noctis-MCP/
├── server/
│   ├── noctis_server.py          # Main server (6 active endpoints)
│   ├── agentic_api.py             # v2 API (intelligence & code)
│   ├── education_api.py           # v2 API (education system)
│   ├── utils/
│   │   ├── intelligence_processor.py  # Structures RAG → Intelligence
│   │   └── pattern_extractor.py       # Extracts patterns from Examples/
│   ├── rag/
│   │   └── rag_engine.py          # RAG with caching
│   ├── learning_engine.py         # Detection feedback
│   └── code_assembler.py          # Code assembly
├── noctis_mcp_client/
│   └── noctis_mcp.py              # 17 MCP tools
├── techniques/
│   ├── knowledge/                 # OPSEC guidance files
│   └── security_blogs/            # Detection intelligence
└── external/
    ├── github_repos/              # Implementation patterns
    └── VX-API/                    # Function signatures
```

---

## Testing

```bash
# Test core system
python test_complete_flow.py

# Test tools
python -c "
from noctis_mcp_client.noctis_mcp import *
# All 17 tools importable
"
```

---

## System Metrics

- **Tools:** 17 (Core: 7, Education: 9, Utility: 1)
- **Endpoints:** ~26 active v2 endpoints
- **Intelligence Sources:** 353+ indexed (auto-updating)
- **Detection Testing:** Hybrid Analysis API v2
- **Status:** Production ready

---

## Key Principle

**The AI writes code. The server provides intelligence.**

This hybrid approach leverages:
- ✅ AI's coding ability (Claude, GPT, etc.)
- ✅ Server's domain intelligence (RAG, patterns, OPSEC)
- ✅ Dynamic, unique code every time
- ✅ Informed by latest security research
