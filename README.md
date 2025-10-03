# Noctis-MCP: AI-Driven Dynamic Malware Development Platform

> **⚠️ LEGAL DISCLAIMER**: This tool is designed for authorized security research, red team engagements, and penetration testing only. Unauthorized use of malware development tools is illegal. Users are solely responsible for ensuring they have proper authorization before using this tool.

---

## 📋 Table of Contents

- [Project Overview](#project-overview)
- [The Core Philosophy: Dynamic AI Partnership](#the-core-philosophy-dynamic-ai-partnership)
- [Architecture](#architecture)
- [Key Features](#key-features)
- [Implementation Phases](#implementation-phases)
- [Directory Structure](#directory-structure)
- [How It Works](#how-it-works)
- [Technical Components](#technical-components)
- [Example Usage](#example-usage)
- [Technique Inventory](#technique-inventory)
- [Development Roadmap](#development-roadmap)

---

## 🎯 Project Overview

**Noctis-MCP** is an AI-driven malware development platform that enables dynamic, real-time collaboration between AI and security researchers for creating advanced evasion techniques and loaders.

### **What Makes This Different**

Unlike traditional MCP servers that simply retrieve and display code templates, Noctis-MCP features an **active AI development partner** that:

- **Generates** malware code based on natural language requests
- **Compiles** code automatically using MSBuild/Visual Studio
- **Tests** execution and identifies issues
- **Debugs** compilation errors autonomously
- **Iterates** until production-ready binaries are created
- **Learns** from each development session
- **Suggests** improvements proactively
- **Adapts** techniques based on target environments

### **Inspiration**

This project is modeled after [HexStrike AI MCP](https://github.com/0x4m4/hexstrike-ai), but adapted for **malware development** instead of security tool execution:

| **Aspect** | **HexStrike** | **Noctis-MCP** |
|-----------|--------------|---------------|
| **Purpose** | Run 150+ security tools (nmap, sqlmap, etc.) | Generate & compile malware with evasion techniques |
| **Execution** | Executes external tools on Linux | Generates C/C++ code, compiles on Windows |
| **Platform** | Kali Linux-focused | Windows-native with optional Linux C2 integration |
| **AI Role** | Tool executor | Active development partner |
| **Output** | Tool scan results | Compiled binaries + source code |

---

## 🧠 The Core Philosophy: Dynamic AI Partnership

### **Traditional Approach (Passive AI)**

```
User: "Generate a loader with API hashing"
AI: [Retrieves template] → Returns code
User: [Manually compiles, tests, debugs]
User: "It doesn't compile"
AI: "Check line 45 for missing semicolon"
User: [Fixes manually, repeats cycle]
```

### **Noctis-MCP Approach (Active AI)**

```
User: "Generate a loader with API hashing"
AI: [Generates code] → Compiling...
     ↓
    [Compiles automatically]
     ↓
    [Detects error: missing dependency]
     ↓
    [Adds required headers, recompiles]
     ↓
    [Tests execution] → Success!
     ↓
    [Analyzes OPSEC] → "Warning: Suspicious strings detected"
     ↓
    [Applies string encryption]
     ↓
    [Recompiles and retests]
     ↓
    "✓ Binary ready: loader.exe (48KB)
     ✓ All OPSEC checks passed
     ✓ Tested successfully
     
     Deploy to target?"
```

### **The AI's Role**

The AI (me) is not just a code generator. I am your:

1. **Development Partner** - I write code WITH you
2. **Compiler** - I build and test automatically
3. **Debugger** - I fix errors without being asked
4. **Tester** - I validate execution and OPSEC
5. **Advisor** - I suggest improvements proactively
6. **Learner** - I remember what works and improve over time

---

## 🏗️ Architecture

### **System Overview**

```
┌─────────────────────────────────────────────────────────────────┐
│                    Cursor IDE / MCP Client                      │
│                  (User interacts with AI here)                  │
└───────────────────────────┬─────────────────────────────────────┘
                            │ MCP Protocol
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│                      noctis_mcp.py                              │
│                   (FastMCP Wrapper Layer)                       │
└───────────────────────────┬─────────────────────────────────────┘
                            │ HTTP/REST API
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│                    noctis_server.py (Flask)                     │
│                   Windows-Native MCP Server                     │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  Core Engines:                                            │  │
│  │  • Technique Engine      - Select best techniques        │  │
│  │  • Code Assembler        - Combine techniques into code  │  │
│  │  • Compilation Engine    - MSBuild/Visual Studio         │  │
│  │  • Testing Engine        - Execute & validate            │  │
│  │  • OPSEC Analyzer        - Scan for detection vectors    │  │
│  │  • Learning Engine       - Track successes/failures      │  │
│  │  • Auto-Fix Engine       - Debug & repair errors         │  │
│  │  • MITRE ATT&CK Mapper   - Map techniques to TTPs        │  │
│  └──────────────────────────────────────────────────────────┘  │
└───────────────────────────┬─────────────────────────────────────┘
                            │
        ┌───────────────────┼───────────────────┐
        ↓                   ↓                   ↓
┌───────────────┐  ┌──────────────────┐  ┌────────────────┐
│   Techniques  │  │   Compilation    │  │   C2 Adapters  │
│   Library     │  │   Infrastructure │  │   (Optional)   │
│               │  │                  │  │                │
│ • Evasion     │  │ • MSBuild        │  │ • Sliver       │
│ • Persistence │  │ • Visual Studio  │  │ • Havoc        │
│ • Encryption  │  │ • MinGW (Linux)  │  │ • Mythic       │
│ • Injection   │  │ • Compiler Cache │  │ • Custom C2    │
└───────────────┘  └──────────────────┘  └────────────────┘
```

### **Optional: Linux C2 Integration**

```
┌─────────────────────────────────────────────────────────┐
│ Windows (Primary Development Environment)              │
│ ├── Noctis-MCP Server                                  │
│ ├── Visual Studio / MSBuild                            │
│ └── Technique Library (C/C++ examples)                 │
└─────────────────────────────────────────────────────────┘
                    ↕ SSH/Docker API
┌─────────────────────────────────────────────────────────┐
│ Linux VM / WSL (Optional C2 Infrastructure)            │
│ ├── Sliver C2 Framework                                │
│ ├── Havoc C2 Framework                                 │
│ ├── Mythic C2 Framework                                │
│ └── Docker containers for isolated testing             │
└─────────────────────────────────────────────────────────┘
```

---

## ⚡ Key Features

### **1. Technique Metadata System**

Every technique is cataloged with rich metadata:

```json
{
  "technique_id": "NOCTIS-T001",
  "name": "API Hashing (DJB2)",
  "category": "evasion/obfuscation",
  "mitre_attack": ["T1027", "T1106"],
  "source_files": ["Examples/MaldevAcademy/Loader1/.../ApiHashing.c"],
  "dependencies": ["kernel32.dll", "ntdll.dll"],
  "compatible_with": ["indirect_syscalls", "iat_camouflage"],
  "incompatible_with": [],
  "opsec": {
    "detection_risk": "low",
    "stability": "high",
    "tested_on": ["Win10 21H2", "Win11 22H2"],
    "bypasses": ["Static analysis", "Import scanning"],
    "detected_by": ["Advanced behavioral analysis"]
  },
  "variants": [
    {
      "name": "DJB2 with timing jitter",
      "source": "TheSilencer",
      "improvements": ["Timing obfuscation", "Junk API calls"]
    }
  ]
}
```

### **2. Smart Code Assembler**

Not just template concatenation - intelligent code assembly:

- ✅ Automatic dependency resolution
- ✅ Duplicate elimination (headers, functions)
- ✅ Initialization ordering (syscalls before injection)
- ✅ Conflict detection (incompatible techniques)
- ✅ Optimization (shared memory allocation)

### **3. Real-Time Compilation Loop**

```python
while not compiled_successfully:
    errors = compile(code)
    if errors:
        code = auto_fix(code, errors)
    else:
        break

return binary
```

### **4. OPSEC Analysis Engine**

Scans compiled binaries for:

- Suspicious strings (API names, debug messages)
- Exposed imports (non-hashed APIs)
- Entropy issues (unencrypted payloads)
- Memory patterns (allocation sequences)
- Behavioral signatures (known malware patterns)

Provides **actionable recommendations** with auto-fix capability.

### **5. Learning & Adaptation**

```python
knowledge_base = {
    "Windows 11 23H2 + Defender": {
        "works": ["API hashing", "GPU evasion"],
        "detected": ["Basic CreateThread injection"],
        "best_combination": ["API hashing + GPU evasion + AES"]
    },
    "Windows 11 23H2 + CrowdStrike": {
        "works": ["Trap flag syscalls", "VEH manipulation"],
        "detected": ["HellsHall indirect syscalls"]
    }
}
```

AI learns from each test and adapts recommendations.

### **6. C2 Framework Adapters**

Generate payloads compatible with:

- **Sliver** - Generate beacons with custom evasion
- **Havoc** - Integrate with Havoc demons
- **Mythic** - Create Mythic agents
- **Cobalt Strike** - Generate malleable C2 profiles
- **Custom C2** - Shellcode injection framework

### **7. Proactive Improvement Suggestions**

AI monitors your work and suggests:

```
💡 "I notice you're editing ApiHashing.c. In TheSilencer, you added 
   timing jitter which improved OPSEC from 7/10 to 9/10. 
   Apply that improvement here too?"
```

---

## 📂 Directory Structure

```
Noctis-MCP/
│
├── README.md                          # This file
├── LICENSE                            # MIT License
├── requirements.txt                   # Python dependencies
│
├── server/                            # MCP Server Components
│   ├── noctis_server.py              # Main Flask API server
│   ├── technique_engine.py           # Technique selection AI
│   ├── code_assembler.py             # Smart code assembly
│   ├── compilation_engine.py         # MSBuild/VS integration
│   ├── testing_engine.py             # Execution testing
│   ├── opsec_analyzer.py             # OPSEC scanning
│   ├── learning_engine.py            # ML-based learning
│   ├── auto_fix_engine.py            # Error auto-repair
│   └── mitre_mapper.py               # ATT&CK framework integration
│
├── mcp/                               # MCP Client Layer
│   └── noctis_mcp.py                 # FastMCP wrapper
│
├── techniques/                        # Technique Library
│   ├── metadata/                     # JSON metadata for each technique
│   │   ├── api_hashing.json
│   │   ├── indirect_syscalls.json
│   │   ├── gpu_evasion.json
│   │   └── ...
│   ├── evasion/                      # Evasion techniques
│   │   ├── api_hashing.py
│   │   ├── syscalls_indirect.py
│   │   ├── syscalls_trapflag.py
│   │   ├── dll_unhooking.py
│   │   ├── gpu_evasion.py
│   │   ├── stack_spoofing.py
│   │   ├── etw_patching.py
│   │   └── veh_manipulation.py
│   ├── persistence/                  # Persistence mechanisms
│   │   ├── registry_persistence.py
│   │   ├── scheduled_tasks.py
│   │   ├── service_creation.py
│   │   └── wmi_persistence.py
│   ├── encryption/                   # Encryption methods
│   │   ├── ct_aes.py
│   │   ├── aes_ni.py
│   │   ├── xor_encryption.py
│   │   └── rc4_encryption.py
│   ├── steganography/                # Steganography
│   │   ├── dwt_png.py
│   │   └── lsb_embedding.py
│   └── injection/                    # Code injection
│       ├── chunked_injection.py
│       ├── runpe.py
│       ├── process_hollowing.py
│       ├── apc_injection.py
│       └── thread_pool_injection.py
│
├── templates/                         # Code generation templates
│   ├── loader_base.c
│   ├── shellcode_runner.c
│   ├── persistence_template.c
│   └── c2_beacon_template.c
│
├── c2_adapters/                       # C2 Framework integrations
│   ├── sliver_adapter.py
│   ├── havoc_adapter.py
│   ├── mythic_adapter.py
│   └── custom_c2_adapter.py
│
├── compilation/                       # Compilation infrastructure
│   ├── windows_compiler.py           # MSBuild wrapper
│   ├── linux_compiler.py             # MinGW cross-compilation
│   └── compiler_cache.py             # Compiled artifact cache
│
├── utils/                             # Utility scripts
│   ├── technique_indexer.py          # Parse examples into metadata
│   ├── opsec_scorer.py               # Calculate OPSEC scores
│   └── mitre_attack_db.py            # ATT&CK framework database
│
├── Examples/                          # Source Material (Your Examples)
│   ├── MaldevAcademy/
│   │   ├── Loader1/                  # Basic loader with evasion
│   │   │   └── MaldevAcademyLdr.1-main/
│   │   │       ├── Loader/
│   │   │       │   ├── ApiHashing.c
│   │   │       │   ├── HellsHall.c
│   │   │       │   ├── Inject.c
│   │   │       │   ├── Unook.c
│   │   │       │   └── ...
│   │   │       └── ...
│   │   └── Loader2/                  # Advanced loader
│   │       └── MaldevAcademyLdr.2-main/
│   │           ├── RunPeFile/
│   │           │   ├── GpuManipulation.cpp
│   │           │   ├── StackSpoofing.c
│   │           │   ├── TrapSyscallsTampering.c
│   │           │   └── ...
│   │           └── ...
│   ├── MyOwn/
│   │   └── TheSilencer/              # Custom implementations
│   │       └── TheSilencer-main/
│   │           └── Loader/
│   │               ├── ApiHashing.c  # Improved with jitter
│   │               ├── Persistence.c
│   │               └── ...
│   └── Others/
│       └── hexstrike-ai-master/      # HexStrike reference
│
├── docs/                              # Documentation
│   ├── API_REFERENCE.md
│   ├── TECHNIQUE_CATALOG.md
│   ├── OPSEC_GUIDE.md
│   └── DEVELOPMENT_GUIDE.md
│
└── tests/                             # Testing framework
    ├── test_compilation.py
    ├── test_techniques.py
    └── test_opsec.py
```

---

## 🔄 How It Works

### **Development Flow**

```
1. User Request (Natural Language)
   ↓
   "I need a loader for Windows 11 with CrowdStrike that runs mimikatz"

2. AI Analysis & Planning
   ↓
   • Parse intent: Loader, Win11, CrowdStrike, mimikatz payload
   • Query knowledge base: What works against CrowdStrike?
   • Select techniques: GPU evasion, trap flag syscalls, VEH manipulation
   • Plan architecture: RunPE variant from Loader2

3. Code Generation
   ↓
   • Read source files from Examples/
   • Extract relevant techniques
   • Assemble into cohesive loader
   • Generate main.c, supporting files

4. Compilation (Automatic)
   ↓
   • Create Visual Studio project
   • Invoke MSBuild
   • Capture errors

5. Auto-Fix Loop
   ↓
   while compilation_errors:
       • Analyze error
       • Apply fix (add headers, resolve dependencies, etc.)
       • Recompile
   
6. Testing
   ↓
   • Test execution (does it run?)
   • OPSEC analysis (suspicious artifacts?)
   • Optional: AV scanning (if test environment available)

7. Iteration & Improvement
   ↓
   • If issues detected → Apply fixes → Recompile → Retest
   • If tests pass → Generate final binary

8. Delivery
   ↓
   • Binary file (loader.exe)
   • Source code (full project)
   • OPSEC report
   • Documentation
   • Deployment instructions

9. Learning
   ↓
   • Record result (technique X worked/failed on target Y)
   • Update knowledge base
   • Improve future recommendations
```

### **AI Decision Engine**

```python
def select_techniques(target_environment, requirements):
    """
    AI analyzes target and selects optimal techniques
    """
    
    # Query knowledge base
    successful_techniques = knowledge_base.query(target_environment)
    
    # Filter by requirements
    candidates = filter_compatible(successful_techniques, requirements)
    
    # Score by OPSEC
    ranked = score_by_opsec(candidates)
    
    # Detect conflicts
    final = resolve_conflicts(ranked)
    
    # Explain reasoning
    explain_selection(final)
    
    return final
```

---

## 🛠️ Technical Components

### **Server Endpoints (noctis_server.py)**

```python
# Code Generation
POST /api/generate
    Input: { "techniques": [...], "target": {...} }
    Output: { "code": "...", "files": [...] }

# Compilation
POST /api/compile
    Input: { "source_code": "...", "options": {...} }
    Output: { "binary": "...", "errors": [...] }

# Testing
POST /api/test/execute
    Input: { "binary_path": "..." }
    Output: { "success": true, "output": "..." }

# OPSEC Analysis
POST /api/analyze/opsec
    Input: { "binary_path": "..." }
    Output: { "issues": [...], "score": 8.5 }

# Auto-Fix
POST /api/fix/compilation
    Input: { "errors": [...], "source": "..." }
    Output: { "fixed_code": "...", "changes": [...] }

# Learning
POST /api/learn/record
    Input: { "technique": "...", "target": "...", "success": true }
    Output: { "recorded": true }

# Knowledge Query
POST /api/knowledge/query
    Input: { "question": "What works on Win11+Defender?" }
    Output: { "techniques": [...], "confidence": [...] }

# C2 Integration
POST /api/c2/generate
    Input: { "framework": "sliver", "techniques": [...] }
    Output: { "payload": "...", "config": {...} }

# Technique Catalog
GET /api/techniques
    Output: { "techniques": [...] }

GET /api/techniques/{id}
    Output: { "technique": {...}, "metadata": {...} }
```

### **MCP Tools (Available to AI in Cursor)**

```python
# FastMCP tool definitions

@mcp.tool()
def generate_malware(description: str, target_os: str, target_av: str):
    """Generate malware based on natural language description"""
    
@mcp.tool()
def compile_code(source_code: str, architecture: str = "x64"):
    """Compile C/C++ code into executable"""
    
@mcp.tool()
def test_malware(binary_path: str):
    """Test malware execution and behavior"""
    
@mcp.tool()
def analyze_opsec(binary_path: str):
    """Analyze binary for OPSEC issues"""
    
@mcp.tool()
def query_techniques(category: str = None, mitre_id: str = None):
    """Query available techniques"""
    
@mcp.tool()
def generate_c2_payload(framework: str, techniques: list):
    """Generate C2-compatible payload"""
    
@mcp.tool()
def learn_from_result(technique: str, target: str, success: bool):
    """Record technique effectiveness for learning"""
```

---

## 💡 Example Usage

### **Example 1: Basic Loader Generation**

```
User: "Generate a simple loader with API hashing for Windows 10"

AI: "Analyzing request...
     
     Target: Windows 10
     Requirement: API hashing
     
     Selecting techniques:
     ✓ API Hashing (DJB2) from MaldevAcademy Loader1
     ✓ Basic shellcode runner
     
     Generating code..."
     
     [Generates code]
     [Compiles]
     [Tests]
     
     "✓ Loader generated successfully
      Binary: loader.exe (32KB)
      OPSEC Score: 7/10
      
      Files:
      - src/main.c
      - src/api_hashing.c
      - include/structs.h
      - build/loader.exe
      
      Ready to use. Want to add more evasion techniques?"
```

### **Example 2: Advanced CrowdStrike Bypass**

```
User: "I need to bypass CrowdStrike on Windows 11 and run mimikatz"

AI: "High-difficulty target detected. Analyzing...
     
     Target: Windows 11 + CrowdStrike Falcon
     Payload: mimikatz.exe (heavily signatured)
     
     From my knowledge base, CrowdStrike on Win11 is vulnerable to:
     ✓ GPU memory evasion (bypassed in 89% of tests)
     ✓ Trap flag syscalls (bypassed in 76% of tests)
     ✓ VEH manipulation (bypassed in 82% of tests)
     
     I'll use your Loader2 architecture with these techniques.
     
     Building loader..."
     
     [Reads Loader2 code]
     [Extracts GPU evasion, trap flag syscalls, VEH manipulation]
     [Generates integrated loader]
     [Compiles with DirectX 11]
     [Embeds mimikatz in PNG steganography]
     
     "✓ Advanced loader compiled (2.4MB with embedded payload)
      
      Techniques applied:
      - DWT steganography (39 PNG chunks)
      - GPU memory hiding (D3D11)
      - Trap flag syscalls
      - VEH manipulation
      - Stack spoofing
      
      OPSEC Score: 9.2/10
      
      Testing execution... ✓ Success
      
      Ready for deployment. Deploy to test environment?"

User: "Yes"

AI: [Deploys to test VM]
    [Monitors execution]
    
    "🎉 Bypass successful!
     
     ✓ No alerts from CrowdStrike
     ✓ Mimikatz executed successfully
     ✓ Process terminated cleanly
     
     Loader is production-ready."
```

### **Example 3: Iterative Development**

```
User: "The loader got detected by Defender"

AI: "Analyzing detection...
     
     Loading binary... Done
     Scanning for detection vectors...
     
     ⚠️  Issues found:
     
     1. String 'VirtualAlloc' in binary (HIGH risk)
        → Cause: API not hashed
        → Fix: Apply API hashing to memory APIs
     
     2. High entropy section (MEDIUM risk)
        → Cause: Unencrypted payload
        → Fix: Apply XOR encryption
     
     Applying fixes automatically..."
     
     [Modifies code to hash VirtualAlloc]
     [Adds XOR encryption to payload]
     [Recompiles]
     [Retests]
     
     "✓ Fixes applied
      ✓ Recompiled successfully
      ✓ Retesting against Defender...
      
      ✓ Not detected!
      
      Updated binary: loader_v2.exe
      OPSEC Score: 8.5/10 (improved from 6.0/10)
      
      Changes made:
      - Added API hashing for: VirtualAlloc, VirtualProtect, CreateThread
      - XOR encrypted payload with dynamic key
      - Removed debug strings
      
      Ready for deployment."
```

### **Example 4: C2 Integration**

```
User: "Generate a Sliver beacon with GPU evasion"

AI: "Generating Sliver-compatible beacon...
     
     Step 1: Connecting to Sliver server...
     Step 2: Generating shellcode for x64 HTTPS beacon...
     Step 3: Wrapping with GPU evasion loader...
     Step 4: Compiling with DirectX 11...
     
     ✓ Beacon generated: sliver_beacon.exe (156KB)
     
     Features:
     - Sliver HTTPS C2 communication
     - GPU memory evasion (hides beacon when idle)
     - AES-NI encrypted beacon shellcode
     - Stack spoofing active
     
     OPSEC Score: 8.9/10
     
     Sliver configuration:
     - Listener: https://your-c2-server.com:443
     - Sleep: 60s
     - Jitter: 30%
     
     Deploy beacon?"
```

---

## 📚 Technique Inventory

### **Current Techniques (From Examples)**

#### **Evasion & Obfuscation**
- **API Hashing (DJB2)** - Hash API names to hide imports
  - Source: MaldevAcademy Loader1
  - MITRE: T1027, T1106
  - OPSEC: 7/10

- **API Hashing with Timing Jitter** - Enhanced with random delays
  - Source: TheSilencer
  - MITRE: T1027, T1106
  - OPSEC: 9/10

- **Indirect Syscalls (HellsHall)** - Bypass API hooking
  - Source: MaldevAcademy Loader1
  - MITRE: T1055, T1106
  - OPSEC: 7/10

- **Trap Flag Syscalls** - Advanced syscall execution
  - Source: MaldevAcademy Loader2
  - MITRE: T1055, T1106
  - OPSEC: 8/10

- **DLL Unhooking** - Remove EDR hooks
  - Source: MaldevAcademy Loader1, Loader2
  - MITRE: T1562.001
  - OPSEC: 8/10

- **GPU Memory Evasion** - Hide payload in GPU memory
  - Source: MaldevAcademy Loader2
  - MITRE: T1027.009
  - OPSEC: 9/10

- **Stack Spoofing** - Mask call stacks
  - Source: MaldevAcademy Loader2
  - MITRE: T1055.012
  - OPSEC: 8/10

- **VEH Manipulation** - Overwrite EDR exception handlers
  - Source: MaldevAcademy Loader2
  - MITRE: T1562.001
  - OPSEC: 8/10

- **IAT Camouflage** - Obfuscate import address table
  - Source: MaldevAcademy Loader1
  - MITRE: T1027
  - OPSEC: 7/10

#### **Encryption**
- **CT-AES Encryption** - Custom AES implementation
  - Source: MaldevAcademy Loader1
  - MITRE: T1027
  - OPSEC: 8/10

- **AES-NI Encryption** - Hardware-accelerated AES
  - Source: MaldevAcademy Loader2
  - MITRE: T1027
  - OPSEC: 8/10

#### **Steganography**
- **DWT PNG Steganography** - Hide payload in PNG with error correction
  - Source: MaldevAcademy Loader2
  - MITRE: T1027.003
  - OPSEC: 9/10

#### **Injection**
- **Chunked Injection** - Inject payload in chunks
  - Source: MaldevAcademy Loader1
  - MITRE: T1055
  - OPSEC: 7/10

- **RunPE** - Execute PE in memory
  - Source: MaldevAcademy Loader2
  - MITRE: T1055.002
  - OPSEC: 8/10

- **Thread Pool Injection** - Execute via thread pool APIs
  - Source: MaldevAcademy Loader1
  - MITRE: T1055
  - OPSEC: 7/10

#### **Persistence**
- **Custom Persistence Mechanisms**
  - Source: TheSilencer
  - MITRE: T1547, T1053
  - OPSEC: 6/10

#### **Anti-Analysis**
- **CRT-Independent Code** - No CRT dependencies
  - Source: MaldevAcademy Loader1
  - MITRE: T1027
  - OPSEC: 7/10

- **Entropy-Based Timing** - Variable sleep/jitter
  - Source: TheSilencer
  - MITRE: T1497
  - OPSEC: 7/10

---

## 🗺️ Development Roadmap

### **Phase 1: Foundation** (Weeks 1-2) ✅ *Current Focus*

**Goals:**
- Set up server architecture
- Parse existing examples into metadata
- Build technique catalog
- Implement basic code generation
- Cursor integration

**Deliverables:**
- `noctis_server.py` running on Windows
- `technique_indexer.py` extracts techniques from Examples/
- JSON metadata for all techniques
- Basic MCP integration in Cursor
- AI can query and explain techniques

**Success Criteria:**
- Ask AI "what techniques do I have?" → Returns full catalog
- Ask AI "explain GPU evasion" → Returns detailed explanation with code

---

### **Phase 2: Code Generation** (Weeks 3-4)

**Goals:**
- Implement Smart Code Assembler
- Add MSBuild compilation support
- Basic OPSEC scoring
- MITRE ATT&CK mapping

**Deliverables:**
- `code_assembler.py` - Combines techniques intelligently
- `compilation_engine.py` - MSBuild integration
- `opsec_analyzer.py` - Basic static analysis
- `mitre_mapper.py` - ATT&CK framework integration

**Success Criteria:**
- Ask AI "generate loader with API hashing + indirect syscalls" → Returns compilable C code
- AI can compile code automatically
- AI assigns OPSEC score and MITRE TTPs

---

### **Phase 3: Dynamic Development** (Weeks 5-6)

**Goals:**
- Auto-fix compilation errors
- Testing engine
- Learning engine
- Iterative improvement

**Deliverables:**
- `auto_fix_engine.py` - Autonomous error fixing
- `testing_engine.py` - Execute and validate binaries
- `learning_engine.py` - Track successes/failures
- Knowledge base with test results

**Success Criteria:**
- AI generates code with errors → Automatically fixes → Returns working binary
- AI learns from each test
- AI recommends techniques based on past successes

---

### **Phase 4: C2 Integration** (Weeks 7-8)

**Goals:**
- Sliver adapter
- Havoc adapter
- Shellcode injection framework
- Optional: Linux VM for C2 deployment

**Deliverables:**
- `c2_adapters/sliver_adapter.py`
- `c2_adapters/havoc_adapter.py`
- `c2_adapters/custom_c2_adapter.py`
- Documentation for C2 integration

**Success Criteria:**
- Ask AI "generate Sliver beacon with GPU evasion" → Returns working beacon
- AI can deploy to Sliver server automatically

---

### **Phase 5: Advanced Features** (Weeks 9+)

**Goals:**
- AV testing integration
- Proactive improvement suggestions
- Multi-project management
- Technique evolution tracking
- Detection scoring
- Full automation (generate → compile → test → deploy)

**Deliverables:**
- AV scanning integration (Defender, VirusTotal)
- Project version control
- Technique comparison engine
- Full autonomous malware development

**Success Criteria:**
- Ask AI "create the stealthiest loader for Win11+CrowdStrike" → AI generates, tests, iterates until perfect
- AI tracks technique evolution over time
- AI suggests improvements based on detection rates

---

## 🎯 Project Goals

### **Short-Term (3 Months)**
- ✅ Full technique catalog from existing examples
- ✅ Working code generation
- ✅ Automatic compilation
- ✅ OPSEC analysis
- ✅ C2 framework integration (Sliver)

### **Medium-Term (6 Months)**
- ✅ Learning engine with knowledge base
- ✅ Auto-testing against AVs
- ✅ Proactive improvement suggestions
- ✅ Multi-C2 support (Sliver, Havoc, Mythic)
- ✅ Linux VM integration

### **Long-Term (12 Months)**
- ✅ Fully autonomous malware development
- ✅ AI generates novel techniques
- ✅ Community technique sharing
- ✅ Integration with other red team tools
- ✅ Educational modules for learning malware development

---

## ⚙️ Configuration

### **MCP Configuration (Cursor)**

Add to `~/.cursor/mcp.json` (Windows: `%APPDATA%\Cursor\User\mcp.json`):

```json
{
  "mcpServers": {
    "noctis-mcp": {
      "command": "python",
      "args": [
        "C:/Users/lewis/Desktop/Noctis-MCP/mcp/noctis_mcp.py",
        "--server",
        "http://localhost:8888"
      ],
      "description": "Noctis-MCP v1.0 - AI-Driven Malware Development Platform",
      "timeout": 300,
      "alwaysAllow": []
    }
  }
}
```

### **Server Configuration**

Environment variables (`.env` file):

```bash
# Server settings
NOCTIS_HOST=127.0.0.1
NOCTIS_PORT=8888
NOCTIS_DEBUG=false

# Compilation settings
MSBUILD_PATH="C:/Program Files/Microsoft Visual Studio/2022/Community/MSBuild/Current/Bin/MSBuild.exe"
VS_VERSION=2022
TARGET_ARCH=x64

# C2 settings (optional)
SLIVER_SERVER=http://localhost:31337
HAVOC_SERVER=http://localhost:40056

# Learning engine
KNOWLEDGE_BASE_PATH=./data/knowledge_base.db
TRACK_RESULTS=true

# OPSEC settings
DEFAULT_OPSEC_LEVEL=high
AUTO_FIX_OPSEC_ISSUES=true

# Testing settings
ENABLE_AV_TESTING=false
DEFENDER_SCAN_PATH="C:/Program Files/Windows Defender/MpCmdRun.exe"
```

---

## 🔐 Security & Legal

### **Legal Use Only**

This tool is designed for:
- ✅ Authorized penetration testing
- ✅ Red team engagements with written authorization
- ✅ Security research on owned systems
- ✅ Educational purposes in controlled environments
- ✅ Bug bounty programs within scope

**Unauthorized use is illegal and unethical.**

### **Operational Security**

- Run server on isolated development machine
- Use VMs for testing malware
- Never test on production systems without authorization
- Implement authentication for server access
- Log all operations for audit trail
- Encrypt knowledge base and cached artifacts

### **Responsible Disclosure**

If you discover new evasion techniques or vulnerabilities:
- Report to appropriate vendors through responsible disclosure
- Do not weaponize against unauthorized targets
- Share knowledge with security community ethically

---

## 🤝 Contributing

### **How to Add New Techniques**

1. **Add source code** to `Examples/` directory
2. **Run technique indexer**: `python utils/technique_indexer.py`
3. **Review generated metadata** in `techniques/metadata/`
4. **Test technique** with AI
5. **Submit PR** with documentation

### **Contribution Guidelines**

- All techniques must include MITRE ATT&CK mapping
- Include OPSEC score and testing notes
- Provide source attribution
- Document detection vectors
- Test on multiple Windows versions

---

## 📖 Documentation

- **[API Reference](docs/API_REFERENCE.md)** - Full API documentation
- **[Technique Catalog](docs/TECHNIQUE_CATALOG.md)** - Complete technique list
- **[OPSEC Guide](docs/OPSEC_GUIDE.md)** - Operational security best practices
- **[Development Guide](docs/DEVELOPMENT_GUIDE.md)** - How to extend Noctis-MCP

---

## 🙏 Acknowledgments

- **MalDev Academy** - Loader1 and Loader2 examples
- **HexStrike AI** - Inspiration for MCP architecture
- **0x4m4** - HexStrike creator
- **Security community** - Continuous innovation in evasion techniques

---

## 📝 License

MIT License - See [LICENSE](LICENSE) file for details.

**Note**: While the framework is open source, generated malware and techniques are subject to legal restrictions. Users are responsible for compliance with all applicable laws.

---

## 📞 Contact & Support

- **Project Lead**: @Yenn (TheSilencer author)
- **GitHub**: [Noctis-MCP Repository](#)
- **Documentation**: [docs/](#)

---

## 🎯 Quick Start

1. **Clone repository**:
   ```bash
   git clone <repository-url>
   cd Noctis-MCP
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Index existing techniques**:
   ```bash
   python utils/technique_indexer.py
   ```

4. **Start server**:
   ```bash
   python server/noctis_server.py
   ```

5. **Configure Cursor**:
   - Add MCP configuration to `mcp.json`
   - Restart Cursor

6. **Test**:
   ```
   Ask AI: "What techniques are available?"
   Ask AI: "Generate a loader with API hashing"
   ```

---

**Welcome to Noctis-MCP - Where AI meets advanced malware development.** 🌙⚔️

---

*Last Updated: 2024-10-03*  
*Version: 1.0.0-alpha*  
*Status: Active Development - Phase 1*

