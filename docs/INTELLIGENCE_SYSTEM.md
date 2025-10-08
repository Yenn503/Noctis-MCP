# Intelligence-Driven Code Generation System

## Overview

Noctis-MCP uses a **hybrid intelligence system** where AI agents (Claude, GPT, etc.) write malware code using structured guidance from multiple intelligence sources.

**Key Principle**: The AI writes the code, the system provides intelligence.

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│ AI AGENT (Claude/GPT in IDE)                            │
│ - Calls MCP tools                                        │
│ - Receives structured intelligence                       │
│ - WRITES code using guidance                             │
└────────────────┬────────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────────────┐
│ NOCTIS MCP TOOLS                                         │
│ - search_intelligence() → Returns strategic guidance     │
│ - generate_code() → Returns patterns + intelligence      │
│ - validate_code() → Compiles and checks OPSEC            │
└────────────────┬────────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────────────┐
│ INTELLIGENCE PROCESSING LAYER                            │
│ ┌──────────────────────┐  ┌─────────────────────────┐   │
│ │ Intelligence         │  │ Pattern Extractor       │   │
│ │ Processor            │  │                         │   │
│ │ - Structures RAG     │  │ - Extracts patterns     │   │
│ │ - Scores OPSEC       │  │   from Examples/        │   │
│ │ - Synthesizes        │  │ - Not raw code          │   │
│ └──────────────────────┘  └─────────────────────────┘   │
└────────────────┬────────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────────────┐
│ DATA SOURCES (400+ indexed)                              │
│ ├─ Knowledge Files: 7 files (Phase 1 upgraded)           │
│ ├─ Security Blogs: 35 RSS feeds (expanded)               │
│ ├─ GitHub Repos: 27 queries (malware orgs)               │
│ ├─ arXiv Research: Academic papers (NEW)                 │
│ └─ VX-API: Function signatures                           │
└─────────────────────────────────────────────────────────┘
```

## How Each Source Contributes

### 1. Knowledge Files (techniques/knowledge/*.md)
**Purpose**: Strategic OPSEC guidance

**Current Files** (7 total):
- `syscalls.md` - Direct syscalls, SysWhispers3 randomization ⭐
- `amsi_bypass.md` - VEH² hardware breakpoint bypass ⭐
- `sleep_obfuscation.md` - Zilean thread pool sleep ⭐
- `injection.md` - PoolParty thread pool injection ⭐
- `encryption.md` - Payload encryption techniques

⭐ = Phase 1 upgrades (2024-2025 research)

**Provides**:
- OPSEC scores (1-10) for different techniques
- Method comparisons (SysWhispers3 vs Hell's Hall, Zilean vs Ekko)
- Detection risk analysis (current: 8-12% with Phase 1)
- When to use which technique

**Example Output**:
```json
{
  "recommendations": [
    {
      "technique": "SysWhispers3 Randomized Syscalls",
      "opsec_score": 8.5,
      "reason": "Eliminates static call patterns, 15-20% detection vs 20-25% Hell's Hall"
    },
    {
      "technique": "PoolParty Thread Pool Injection",
      "opsec_score": 9.5,
      "reason": "100% EDR bypass documented (CrowdStrike, SentinelOne, Palo Alto)"
    }
  ],
  "warnings": ["⚠ CreateRemoteThread heavily monitored", "⚠ Memory patching fails on Win11 24H2"]
}
```

### 2. Security Blogs (RSS feeds)
**Purpose**: Current detection status

**Sources** (35 RSS feeds):
- **Elite Researchers**: Cracked5pider (Havoc C2), Alice Climent-Pommeret, am0nsec
- **Security Firms**: MDSec, Outflank, SafeBreach Labs, RedOps, Binary Defense
- **Research Labs**: Elastic Security Labs, Cyberark Labs, IBM X-Force
- **Communities**: VX-Underground, Red Canary, PPN (snovvcrash)
- **Full list**: 35 feeds (expanded from 23 in Phase 1)

**Provides**:
- Recent security updates (what's detected NOW)
- Bypass techniques that currently work
- AV/EDR version-specific information
- Latest malware research (Zilean, PoolParty, etc.)

**Example Output**:
```json
{
  "detection_patterns": [
    "CrowdStrike Falcon v7.2 (March 2024) now detects Hell's Gate",
    "Windows 11 24H2 blocks traditional AMSI memory patching"
  ],
  "bypasses": [
    {
      "title": "SysWhispers3 randomization evades Falcon behavioral detection",
      "source": "Cracked5pider",
      "recent": true
    },
    {
      "title": "VEH² hardware breakpoint AMSI bypass works on Win11 24H2",
      "source": "CrowdStrike disclosure (Black Hat MEA 2023)",
      "recent": true
    }
  ]
}
```

### 3. GitHub Repos (indexed repositories)
**Purpose**: Real-world implementation patterns

**Search Queries** (27 total):
- **Technique-specific**: PoolParty, Zilean, SysWhispers3, VEH AMSI, Phantom DLL Hollowing, RecycledGate
- **Organization-specific**: org:Cracked5pider, org:SafeBreach-Labs, org:Maldev-Academy, org:outflanknl, org:WKL-Sec, org:vxunderground
- **User-specific**: user:gmh5225 syscall, user:am0nsec
- **General**: Process injection, syscalls evasion, AMSI bypass, Cobalt Strike

**Provides**:
- HOW real malware implements techniques
- Function call sequences (order matters)
- Code structure patterns (NOT raw code)

**Example Output**:
```json
{
  "patterns": {
    "implementation_approach": [
      "SysWhispers3: Cache 16 syscall addresses, randomize on each invocation",
      "PoolParty: Thread pool TP_TIMER + module stomping (100% EDR bypass)"
    ],
    "function_sequences": [{
      "sequence": "FindStompModule → StompModule → CreateTPTimer → QueueTPTimer",
      "description": "PoolParty injection pattern"
    }],
    "memory_patterns": [
      "Allocate RW, write payload, change to RX - OPSEC safe",
      "Shellcode in legitimate DLL .text section (PoolParty method)"
    ]
  }
}
```

### 4. arXiv Research Papers (NEW in Phase 1)
**Purpose**: Academic security research

**Search Queries**:
- Malware detection evasion
- Adversarial machine learning security
- EDR bypass techniques
- Polymorphic malware
- Syscall hooking research

**Provides**:
- Latest academic research on evasion
- Novel detection bypass methods
- Theoretical foundations for techniques
- Emerging threat intelligence

**Example Output**:
```json
{
  "research_papers": [
    {
      "title": "Evading Machine Learning Malware Detection via Adversarial Examples",
      "authors": "Chen et al.",
      "year": 2024,
      "findings": "Gradient-based perturbations can evade ML-based EDR classifiers"
    }
  ]
}
```

### 5. VX-API (external/VX-API/)
**Purpose**: Function signatures

**Provides**:
- Exact function prototypes
- Parameter types
- Return values

**Example Output**:
```json
{
  "vx_api_functions": [
    {
      "function": "NtAllocateVirtualMemory",
      "context": "NTSTATUS NtAllocateVirtualMemory(...)"
    }
  ]
}
```

## Complete Workflow Example

### User Request:
```
"Build a C2 beacon that bypasses CrowdStrike Falcon"
```

### AI Agent Execution:

**Step 1**: Search for intelligence
```python
search_intelligence("C2 beacon CrowdStrike evasion")
```

**Returns**:
```json
{
  "summary": "Top: HTTPS beacon with indirect syscalls (OPSEC 8/10)",
  "recommendations": [
    {"technique": "Indirect Syscalls", "opsec_score": 8},
    {"technique": "API Hashing", "opsec_score": 7}
  ],
  "warnings": ["⚠ Avoid WinINet, use WinHTTP instead"],
  "detection_patterns": ["Falcon monitors: CreateRemoteThread, RWX memory"]
}
```

**Step 2**: Get code generation guidance
```python
generate_code(["syscalls", "http_beacon"], "CrowdStrike", "high")
```

**Returns**:
```json
{
  "intelligence": {
    "syscalls": {
      "recommendations": [...],
      "warnings": [...]
    },
    "http_beacon": {...}
  },
  "patterns": {
    "syscalls": {
      "function_sequences": [{
        "sequence": "NtAllocateVirtualMemory → NtWriteVirtualMemory",
        "description": "Memory management pattern"
      }],
      "memory_patterns": ["Use RW→RX, not RWX directly"]
    }
  },
  "vx_api_functions": [
    {"function": "NtAllocateVirtualMemory", ...},
    {"function": "WinHttpOpen", ...}
  ],
  "synthesis": {
    "recommended_approach": ["High OPSEC - proceed with indirect syscalls"],
    "opsec_warnings": ["Avoid CreateRemoteThread"],
    "implementation_order": [...]
  }
}
```

**Step 3**: AI writes code
```c
// AI synthesizes the guidance into working code
#include <windows.h>
#include <winhttp.h>

// Based on VX-API signatures
typedef NTSTATUS (NTAPI *pNtAllocateVirtualMemory)(...);

// Following pattern: Dynamic SSN resolution
DWORD GetSyscallNumber(LPCSTR functionName) {
    // Implementation based on GitHub pattern
    ...
}

// Following pattern: RW → RX memory
BOOL SafeMemoryAlloc(...) {
    // Allocate RW (not RWX - per OPSEC guidance)
    ...
    // Write payload
    ...
    // Change to RX
    VirtualProtect(..., PAGE_EXECUTE_READ, ...);
}

// HTTP beacon using WinHTTP (per warning: avoid WinINet)
BOOL SendBeacon(...) {
    // Use WinHttp APIs from VX-API signatures
    ...
}
```

## Components

### Intelligence Processor
**File**: `server/utils/intelligence_processor.py`

**Responsibilities**:
- Process raw RAG results
- Extract OPSEC scores
- Identify detection patterns
- Synthesize recommendations
- Return structured intelligence

**Key Methods**:
- `process_intelligence()` - Main entry point
- `_process_knowledge()` - Extract from knowledge files
- `_process_blogs()` - Extract current detections
- `_process_github()` - Extract patterns
- `_synthesize_recommendations()` - Combine all sources

### Pattern Extractor
**File**: `server/utils/pattern_extractor.py`

**Responsibilities**:
- Extract patterns from Examples/ code
- Identify function call sequences
- Extract memory management patterns
- Find API usage patterns
- Return structured patterns (NOT raw code)

**Key Methods**:
- `extract_patterns_for_technique()` - Main entry point
- `_extract_function_sequences()` - API call order
- `_extract_memory_patterns()` - Memory allocation patterns
- `_extract_api_patterns()` - API resolution techniques

### Updated Endpoints

**`/api/v2/rag/search`**
- Now returns structured intelligence
- Uses IntelligenceProcessor
- Returns recommendations, warnings, patterns

**`/api/v2/code/generate`**
- Now returns guidance, not code
- Combines intelligence + patterns + VX-API
- AI uses this to write code

## MCP Tools

### search_intelligence()
Returns strategic intelligence from RAG

### generate_code()
Returns structured guidance for code writing:
- Intelligence (OPSEC, warnings)
- Patterns (how real code does it)
- VX-API signatures (functions to use)

AI uses this guidance to write custom code.

## Benefits

### For AI Agents
1. **Clear guidance**: Knows what to avoid (detected methods)
2. **Proven patterns**: Learns from real implementations
3. **Current info**: Gets latest detection status
4. **Building blocks**: Has exact function signatures

### For Users
1. **Dynamic**: Every generation is unique
2. **Current**: Based on latest blog intelligence
3. **Smart**: AI makes decisions based on target_av
4. **Flexible**: Works with any AI model

### For Researchers
1. **Educational**: See HOW and WHY techniques work
2. **Practical**: Get working, compilable code
3. **Up-to-date**: Intelligence auto-updates
4. **Professional**: Production-quality implementations

## Future Enhancements

1. **Code validation**: Compile and check for OPSEC issues
2. **Iterative improvement**: AI refines based on validation
3. **More knowledge files**: Expand coverage to all techniques
4. **Real-time detection**: Monitor AV updates daily
