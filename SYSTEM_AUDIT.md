# Noctis-MCP System Audit

**Date:** 2025-10-08
**Status:** MAJOR ISSUES FOUND

---

## Executive Summary

**CRITICAL FINDING:** Most technique implementations in the repo are NOT indexed by RAG and NOT accessible to the AI. The system has a broken intelligence flow.

---

## 1. MCP Tools Audit (21 tools)

### Core Malware Tools (7 tools)
1. ✅ **search_intelligence** - Searches RAG for intelligence (BUT: incomplete data)
2. ✅ **generate_code** - Returns intelligence for AI to write code (NOW FIXED: shows templates)
3. ✅ **optimize_opsec** - OPSEC optimization suggestions
4. ✅ **validate_code** - Validates code quality
5. ✅ **compile_code** - Compiles to binary
6. ⚠️  **test_detection** - VirusTotal testing (requires VT_API_KEY)
7. ✅ **record_feedback** - Records detection results

### C2 Integration Tools (4 tools)
8. ⚠️  **generate_c2_beacon** - Generates C2 shellcode (Linux only)
9. ⚠️  **compile_malware** - Compiles with C2 (Linux only)
10. ⚠️ **setup_c2_listener** - C2 listener instructions (Linux only)
11. ⚠️ **install_c2_framework** - Auto-installs C2 (Linux only)

**Assessment:** C2 tools are OS-specific (Linux only). Windows users cannot use them.

### Education Tools (9 tools)
12-20. ✅ Full learning system (lessons, quizzes, progress tracking)

### Utility (1 tool)
21. ✅ **rag_stats** - RAG health check

---

## 2. RAG Intelligence Flow - BROKEN

### What RAG Currently Indexes

```
✅ INDEXED:
- techniques/knowledge/        → 11 .md files (OPSEC guidance)
- techniques/templates/         → 4 .c files (code templates)
- docs/                         → AI guides

❌ NOT INDEXED:
- techniques/injection/         → poolparty.c, phantom_dll_hollowing.c, early_cascade.c
- techniques/syscalls/          → syswhispers3.c
- techniques/amsi/              → veh2_bypass.c
- techniques/unhooking/         → peruns_fart.c
- techniques/sleep_obfuscation/ → zilean.c, shellcode_fluctuation.c
- techniques/crypto/            → encryption implementations
- techniques/evasion/           → evasion techniques
- techniques/vx-api/            → VX-Underground function signatures
- techniques/reference_implementations/ → MaldevAcademy, MyOwn (only via metadata)
```

### Critical Gap

**The AI CANNOT find these implementations:**
- PoolParty injection (100% EDR bypass documented)
- SysWhispers3 randomized syscalls (15-20% detection)
- VEH² AMSI bypass (Windows 11 24H2 compatible)
- Zilean sleep obfuscation (5-10% detection)
- Phantom DLL Hollowing
- Early Cascade timing attack
- Perun's Fart unhooking

These are **YOUR BEST TECHNIQUES** but they're invisible to the AI!

---

## 3. Intelligence Sources Audit

### Source 1: Knowledge Files ✅ WORKING
**Location:** `techniques/knowledge/*.md`
**Indexed:** YES (11 files)
**Purpose:** OPSEC guidance, technique comparisons

**Provides:**
- OPSEC scores (1-10)
- Detection risks
- Technique comparisons
- When to use what

**Example:**
```
SysWhispers3 Randomized Syscalls: OPSEC 8.5/10
PoolParty Thread Pool Injection: OPSEC 9.5/10
Zilean Sleep Obfuscation: 5-10% detection vs 30-35% ROP chains
```

### Source 2: Security Blogs ⚠️ NOT INDEXED
**Purpose:** Current detection status (what's detected NOW)
**Expected:** 35 RSS feeds from MDSec, Outflank, Cracked5pider, etc.
**Reality:** NOT in RAG database - fetched live via LiveIntelligence class

**Problem:** RAG doesn't have blog intelligence unless you manually run update scripts.

### Source 3: GitHub Repos ⚠️ NOT INDEXED
**Purpose:** Real-world implementations
**Expected:** 27 queries (Cracked5pider, SafeBreach-Labs, Maldev-Academy, etc.)
**Reality:** NOT in RAG database - fetched live via LiveIntelligence class

**Problem:** Same as blogs - requires manual update.

### Source 4: arXiv Research Papers ⚠️ NOT INDEXED
**Purpose:** Academic security research
**Reality:** NOT in RAG database - requires manual update

### Source 5: VX-API ❌ NOT INDEXED
**Location:** `techniques/vx-api/VX-API/`
**Indexed:** NO (script exists but not run)
**Script:** `scripts/index_vx_sources.py`

**Problem:** 400+ production-grade malware function signatures are NOT indexed.

---

## 4. How Intelligence Flows (Current State)

### User Request: "Build CrowdStrike bypass"

```
1. User asks: "Build CrowdStrike bypass"
   ↓
2. AI calls: search_intelligence("CrowdStrike evasion", "CrowdStrike")
   ↓
3. RAG searches ONLY:
   ✅ techniques/knowledge/*.md files
   ⚠️  techniques/templates/*.c files (not implementations)
   ❌ Does NOT find actual implementations (poolparty.c, syswhispers3.c, etc.)
   ↓
4. Returns intelligence:
   - OPSEC scores from knowledge files
   - Generic recommendations
   - ❌ NO ACTUAL CODE REFERENCES (because not indexed!)
   ↓
5. AI calls: generate_code(["syscalls", "injection"], "CrowdStrike")
   ↓
6. Server:
   - Searches RAG (same limited data)
   - PatternExtractor looks at reference_implementations/ (MaldevAcademy, MyOwn)
   - ❌ Does NOT find poolparty.c, syswhispers3.c!
   - Recommends template: integrated_loader.c
   ↓
7. AI:
   - Sees: "READ techniques/templates/integrated_loader.c" ✅ NOW WORKS
   - Reads template
   - Modifies based on intelligence
   - ❌ Never knows about poolparty.c, syswhispers3.c, veh2_bypass.c
```

### What's Missing

**The AI never learns about:**
- PoolParty injection (techniques/injection/poolparty.c)
- SysWhispers3 (techniques/syscalls/syswhispers3.c)
- VEH² AMSI (techniques/amsi/veh2_bypass.c)
- Zilean sleep (techniques/sleep_obfuscation/zilean.c)
- Perun's Fart (techniques/unhooking/peruns_fart.c)
- VX-API signatures (techniques/vx-api/)

---

## 5. Metadata System - Partial Coverage

### What Metadata Does

**Location:** `techniques/metadata/*.json`
**Purpose:** Maps technique IDs to source files

**Current metadata files:**
```
✅ api_hashing.json
✅ encryption.json
⚠️  gpu_evasion.json
⚠️  index.json
✅ injection.json → points to MaldevAcademy/MyOwn, NOT poolparty.c
✅ persistence.json
⚠️  stack_spoof.json
⚠️  steganography.json
✅ syscalls.json → points to HellsHall.c, NOT syswhispers3.c
✅ unhooking.json → points to MaldevAcademy, NOT peruns_fart.c
✅ veh.json
```

### Problem

Metadata **only** points to reference_implementations (MaldevAcademy, MyOwn).
It does NOT point to standalone implementations:
- techniques/injection/poolparty.c ❌
- techniques/syscalls/syswhispers3.c ❌
- techniques/amsi/veh2_bypass.c ❌
- etc.

---

## 6. How ANY AV/EDR Should Work (But Doesn't)

### User asks: "Build ESET bypass"

**Expected flow:**
1. search_intelligence("ESET evasion", "ESET")
2. RAG finds knowledge about ESET from:
   - Knowledge files mentioning ESET
   - Blog posts about ESET detections
   - GitHub repos with ESET bypasses
3. Returns OPSEC guidance specific to ESET
4. AI writes code using that guidance

**Actual flow:**
1. search_intelligence("ESET evasion", "ESET")
2. RAG searches only knowledge/*.md files
3. If "ESET" not mentioned in those 11 files → NO RESULTS
4. AI gets generic fallback recommendations
5. ❌ No ESET-specific intelligence

### Why This Fails

**Intelligence is NOT target-specific:**
- Knowledge files have tables like "CrowdStrike, SentinelOne, Defender"
- If your AV isn't in that table → no results
- Blog/GitHub/arXiv NOT indexed → no fresh intelligence
- System cannot learn about NEW AVs

---

## 7. What's Actually Working

✅ **Templates Display** (JUST FIXED)
- AI now sees: "READ techniques/templates/integrated_loader.c"
- Knows to read template files
- Can modify them

✅ **Knowledge Files**
- 11 OPSEC guidance files indexed
- Provide strategic recommendations
- Technique comparisons

✅ **Reference Implementations Pattern Extraction**
- MaldevAcademy and MyOwn code analyzed
- Patterns extracted (not raw code)
- Function sequences identified

✅ **Education System**
- 9 tools for interactive learning
- Lessons, quizzes, progress tracking
- Works independently

✅ **Compilation & Validation**
- Code validation works
- Compilation works
- Detection testing works (with VT_API_KEY)

---

## 8. Critical Issues Summary

### Issue #1: Missing Implementations ❌ CRITICAL
**Problem:** Best techniques not indexed by RAG
**Impact:** AI cannot use PoolParty, SysWhispers3, VEH², Zilean, etc.
**Files missing:** 20+ implementation files

### Issue #2: Blog/GitHub Intelligence ❌ CRITICAL
**Problem:** Blog and GitHub intelligence not in RAG
**Impact:** No current detection status, no real-world examples
**Missing:** 35 RSS feeds, 27 GitHub queries, arXiv papers

### Issue #3: VX-API Not Indexed ❌ HIGH
**Problem:** 400+ function signatures not in RAG
**Impact:** AI doesn't have function prototypes
**Script exists but not run:** scripts/index_vx_sources.py

### Issue #4: Target-Specific Intelligence ❌ HIGH
**Problem:** Intelligence not tailored to specific AVs
**Impact:** Generic recommendations for all AVs
**Example:** ESET query returns CrowdStrike guidance

### Issue #5: Metadata Gaps ⚠️ MEDIUM
**Problem:** Metadata only covers reference_implementations
**Impact:** New standalone implementations not tracked
**Missing:** poolparty, syswhispers3, veh2_bypass, etc.

### Issue #6: C2 Integration OS-Limited ⚠️ LOW
**Problem:** C2 tools only work on Linux
**Impact:** Windows users cannot use C2 features
**4 tools affected:** generate_c2_beacon, compile_malware, setup_c2_listener, install_c2_framework

---

## 9. Recommended Fixes

### Priority 1: Index All Techniques (CRITICAL)

**Action:** Create comprehensive indexing script

```python
# NEW: scripts/index_all_techniques.py

# Index these folders:
1. techniques/injection/*.c
2. techniques/syscalls/*.c
3. techniques/amsi/*.c
4. techniques/unhooking/*.c
5. techniques/sleep_obfuscation/*.c
6. techniques/crypto/*.c
7. techniques/evasion/*.c

# For each file:
- Extract function signatures
- Extract comments/documentation
- Add to RAG with metadata:
  - source: "technique_implementation"
  - category: "injection", "syscalls", etc.
  - filename: "poolparty.c"
  - technique_name: "PoolParty Thread Pool Injection"
```

### Priority 2: Index VX-API (HIGH)

**Action:** Run existing script

```bash
python scripts/index_vx_sources.py
```

This indexes 400+ VX-Underground function signatures.

### Priority 3: Index Blog/GitHub Intelligence (HIGH)

**Action:** Run intelligence updater

```bash
# Run weekly intelligence update
python scripts/update_intelligence.py --mode weekly

# Or daily (lighter update)
python scripts/update_intelligence.py --mode daily
```

### Priority 4: Create Metadata for Standalone Techniques (MEDIUM)

**Action:** Create JSON metadata for:
- poolparty.json
- syswhispers3.json
- veh2_bypass.json
- zilean.json
- peruns_fart.json
- etc.

### Priority 5: Target-Specific Intelligence (MEDIUM)

**Action:** Improve IntelligenceProcessor to:
- Search for target_av in all sources
- Fallback to generic guidance
- Learn from user queries (add to knowledge base)

---

## 10. Testing After Fixes

```bash
# 1. Index everything
python scripts/index_all_techniques.py
python scripts/index_vx_sources.py
python scripts/update_intelligence.py

# 2. Test search
python -c "
from server.rag import RAGEngine
rag = RAGEngine()
results = rag.search_knowledge('PoolParty injection')
print(len(results), 'results found')
print(results[0]['content'][:200])
"

# 3. Test generate_code
# In Cursor: generate_code(['injection'], 'CrowdStrike')
# Should now find poolparty.c!
```

---

## Conclusion

**Current State:** System is partially broken. AI can generate code but is missing access to the best techniques.

**After Fixes:** AI will have access to:
- ✅ All 20+ technique implementations
- ✅ 400+ VX-API function signatures
- ✅ 35 security blog feeds
- ✅ 27 GitHub implementation queries
- ✅ Academic research papers
- ✅ Target-specific intelligence

**Result:** AI can build CrowdStrike/ESET/ANY AV bypasses using your best techniques (PoolParty, SysWhispers3, VEH², Zilean, etc.)
