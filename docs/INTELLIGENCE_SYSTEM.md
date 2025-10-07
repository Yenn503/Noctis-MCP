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
│ DATA SOURCES                                             │
│ ├─ Knowledge Files (OPSEC guidance, WHY)                 │
│ ├─ Security Blogs (Current detections, WHAT NOW)         │
│ ├─ GitHub Repos (Implementation HOW)                     │
│ └─ VX-API (Function signatures, BUILDING BLOCKS)         │
└─────────────────────────────────────────────────────────┘
```

## How Each Source Contributes

### 1. Knowledge Files (techniques/knowledge/*.md)
**Purpose**: Strategic OPSEC guidance

**Provides**:
- OPSEC scores (1-10) for different techniques
- Method comparisons (Hell's Gate vs Heaven's Gate)
- Detection risk analysis
- When to use which technique

**Example Output**:
```json
{
  "recommendations": [
    {
      "technique": "Indirect Syscalls",
      "opsec_score": 8,
      "reason": "Bypasses CrowdStrike Falcon v7 hooks effectively"
    }
  ],
  "warnings": ["⚠ CreateRemoteThread heavily monitored"]
}
```

### 2. Security Blogs (RSS feeds)
**Purpose**: Current detection status

**Provides**:
- Recent security updates (what's detected NOW)
- Bypass techniques that currently work
- AV/EDR version-specific information

**Example Output**:
```json
{
  "detection_patterns": [
    "CrowdStrike Falcon v7.2 (March 2024) now detects Hell's Gate"
  ],
  "bypasses": [
    {
      "title": "Halo's Gate still effective against Falcon",
      "recent": true
    }
  ]
}
```

### 3. GitHub Repos (indexed repositories)
**Purpose**: Real-world implementation patterns

**Provides**:
- HOW real malware implements techniques
- Function call sequences (order matters)
- Code structure patterns (NOT raw code)

**Example Output**:
```json
{
  "patterns": {
    "implementation_approach": ["Dynamic SSN resolution from clean NTDLL copy"],
    "function_sequences": [{
      "sequence": "NtAllocateVirtualMemory → NtWriteVirtualMemory → NtCreateThreadEx",
      "description": "Safe injection pattern"
    }],
    "memory_patterns": ["Allocate RW, write payload, change to RX - OPSEC safe"]
  }
}
```

### 4. VX-API (external/VX-API/)
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
