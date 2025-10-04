# MCP Tools Reference Guide
## Noctis-MCP v2.0 - Simplified Workflow for AI Assistants

**Last Updated:** October 4, 2025
**Version:** 2.0.0-alpha

---

## Overview

Noctis-MCP v2.0 provides **8 streamlined tools** designed specifically for AI assistants in Cursor IDE. The architecture has been completely redesigned from 21+ confusing tools to a clean, intuitive workflow.

### Design Philosophy

1. **One Tool, One Purpose** - No overlapping functionality
2. **AI-First Design** - Clear, predictable behavior for AI assistants
3. **Autonomous by Default** - Minimal user input required
4. **Professional Quality** - Production-ready code generation

---

## The 8 Tools

### **Core Workflow (6 tools)**
1. `develop()` - ⭐ **PRIMARY TOOL** - One-stop malware creation
2. `browse()` - 🔍 Explore available techniques
3. `compile()` - 🔨 Build executables
4. `learn()` - 🧠 Provide feedback for ML
5. `files()` - 📁 Manage workspace
6. `help()` - ❓ Get guidance

### **C2 Integration (2 tools)** *(Future: Kali/WSL)*
7. `c2_generate()` - 🔗 Generate C2 beacons
8. `c2_list()` - 📋 List C2 frameworks

---

## 1. develop() - PRIMARY TOOL ⭐

**Purpose:** One-stop autonomous malware development. This handles 95% of use cases.

**What it does:**
1. AI selects optimal techniques automatically
2. Assembles working C code
3. Optimizes OPSEC (detection evasion)
4. Saves to workspace with reports
5. Optionally compiles to .exe
6. Records learning feedback

**Signature:**
```python
def develop(
    goal: str,                          # Required
    target: str = "Windows Defender",   # Optional
    os_type: str = "Windows",           # Optional
    architecture: str = "x64",          # Optional
    complexity: str = "medium",         # Optional
    auto_compile: bool = False          # Optional
) -> str:
```

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `goal` | `str` | *Required* | What the malware should accomplish (e.g., "Create a stealthy loader") |
| `target` | `str` | `"Windows Defender"` | Target AV/EDR to evade (Windows Defender, CrowdStrike, SentinelOne, Kaspersky) |
| `os_type` | `str` | `"Windows"` | Target operating system (Windows, Linux) |
| `architecture` | `str` | `"x64"` | Target CPU architecture (x86, x64, arm64) |
| `complexity` | `str` | `"medium"` | Difficulty level (low, medium, high) |
| `auto_compile` | `bool` | `False` | Automatically compile to .exe |

**Output Files Created:**
```
output/
├── malware_YYYYMMDD_HHMMSS.c              # Source code
├── malware_YYYYMMDD_HHMMSS_metadata.json  # Full metadata
├── malware_YYYYMMDD_HHMMSS_report.md      # Analysis report
└── malware_YYYYMMDD_HHMMSS.exe            # Binary (if auto_compile=True)
```

**Example Usage:**

```python
# Basic usage
develop(goal="Create a stealthy loader")

# Advanced usage
develop(
    goal="Create reflective DLL injection loader",
    target="CrowdStrike Falcon",
    complexity="high",
    auto_compile=True
)

# Minimal usage (AI in Cursor)
develop(goal="Create process injection malware")
```

**Returns:**
```
====================================================================
|        AUTONOMOUS MALWARE DEVELOPMENT COMPLETE                   |
====================================================================

WORKFLOW SUMMARY
+----------------------------------------------------------------+
| Technique Selection   | ✅ 3 techniques selected               |
| Code Assembly         | ✅ 1391 lines generated                |
| OPSEC Optimization    | ✅ Score: 9.6/10                       |
| Compilation           | ⏭️ Skipped                              |
| Learning Feedback     | ✅ Recorded                             |
+----------------------------------------------------------------+

SELECTED TECHNIQUES
• Stack Spoof (NOCTIS-T006) - Score: 0.95
• Syscalls (NOCTIS-T004) - Score: 0.92
• GPU Evasion (NOCTIS-T009) - Score: 0.91

OUTPUT FILES (Click to open in editor)
• Source Code: C:\...\output\malware_20251004_123456.c
• Analysis Report: C:\...\output\malware_20251004_123456_report.md
• Metadata: C:\...\output\malware_20251004_123456_metadata.json

OPSEC ANALYSIS
Risk Level: 🟢 Excellent (Low Detection Risk)
Score: 9.6/10

NEXT STEPS
1. Click source code file above to open in editor
2. Review the generated code
3. Run compile("output/malware_20251004_123456.c") to build executable
4. Test in isolated environment
5. Report results with learn()
```

**When to use:** Almost always. This is the primary tool AI should use.

---

## 2. browse() - Explore Techniques 🔍

**Purpose:** Discover available techniques in the database. For exploration only, not code generation.

**Signature:**
```python
def browse(
    search: str = None,        # Optional keyword search
    category: str = None,      # Optional category filter
    show_details: bool = False # Optional detailed view
) -> str:
```

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `search` | `str` | `None` | Keyword search (e.g., "syscalls", "API hashing") |
| `category` | `str` | `None` | Filter by category (evasion, injection, persistence, etc.) |
| `show_details` | `bool` | `False` | Show detailed info for each technique |

**Example Usage:**

```python
# Browse all techniques
browse()

# Search for specific technique
browse(search="syscalls")

# Browse by category
browse(category="evasion")

# Get detailed info
browse(search="API hashing", show_details=True)
```

**Returns:**
```
====================================================================
|                    TECHNIQUE BROWSER                             |
====================================================================

Found 10 technique(s)

📌 Stack Spoof (NOCTIS-T006)
   Category: evasion/advanced
   Description: Masks call stacks to hide malicious execution chains
   MITRE: T1027

📌 Syscalls (NOCTIS-T004)
   Category: evasion/unhooking
   Description: Direct system call execution to bypass user-mode API hooks
   MITRE: T1106

💡 TIP: To create malware with these techniques, use:
   develop(goal="your objective")
```

**When to use:** Only when user asks "what techniques are available?" or wants to explore the database.

---

## 3. compile() - Build Executables 🔨

**Purpose:** Compile generated C/C++ source code into Windows executables.

**Signature:**
```python
def compile(
    source_file: str,              # Required path to .c file
    architecture: str = "x64",     # Optional
    optimization: str = "O2",      # Optional
    output_name: str = None        # Optional
) -> str:
```

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `source_file` | `str` | *Required* | Path to .c file (use `files()` to list available files) |
| `architecture` | `str` | `"x64"` | Target architecture (x86, x64) |
| `optimization` | `str` | `"O2"` | Compiler optimization level (O0, O1, O2, O3) |
| `output_name` | `str` | Auto-generated | Output filename (without extension) |

**Example Usage:**

```python
# Basic compilation
compile("output/malware_20251004_123456.c")

# Custom architecture and optimization
compile(
    source_file="output/malware_20251004_123456.c",
    architecture="x86",
    optimization="O3"
)

# Custom output name
compile(
    source_file="output/malware_20251004_123456.c",
    output_name="my_loader"
)
```

**Returns:**
```
====================================================================
|              ✅ COMPILATION SUCCESSFUL                          |
====================================================================

Binary Details
+-- Path: output/malware_20251004_123456.exe
+-- Size: 47.3 KB
+-- Architecture: x64
+-- Optimization: O2
+-- Compilation Time: 2.4s

⚠️  Warnings (2):
  • Unused variable 'temp' in main()
  • Implicit function declaration for 'SetProcessDEPPolicy'

Next Steps
1. Test in isolated VM/sandbox
2. Monitor with Process Monitor
3. Report results with learn()
```

**When to use:** After `develop()` if `auto_compile=False` was used, or when recompiling modified code.

---

## 4. learn() - Provide Feedback 🧠

**Purpose:** Record test results to improve the AI learning system.

**Signature:**
```python
def learn(
    source_file: str,    # Required path to tested malware
    av_name: str,        # Required AV/EDR name
    detected: bool,      # Required detection result
    notes: str = None    # Optional notes
) -> str:
```

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `source_file` | `str` | *Required* | Path to malware source file that was tested |
| `av_name` | `str` | *Required* | AV/EDR name (e.g., "Windows Defender", "CrowdStrike") |
| `detected` | `bool` | *Required* | Was the malware detected? `True` = detected, `False` = bypassed |
| `notes` | `str` | `None` | Optional notes about the test results |

**Example Usage:**
```python
# Successful bypass
learn(
    source_file="output/malware_20251004_123456.c",
    av_name="Windows Defender",
    detected=False,
    notes="Successfully bypassed with API hashing + syscalls"
)

# Detected
learn(
    source_file="output/malware_20251004_123456.c",
    av_name="CrowdStrike Falcon",
    detected=True,
    notes="Detected during memory scan"
)
```

**Returns:**
```
====================================================================
|              🧠 LEARNING FEEDBACK RECORDED                      |
====================================================================

Test Results
+-- AV/EDR: Windows Defender
+-- Detected: ✅ No (Bypassed)
+-- Techniques Tested: 3
+-- Status: Feedback recorded successfully

Techniques Tested:
  • NOCTIS-T006
  • NOCTIS-T004
  • NOCTIS-T009

Notes: Successfully bypassed with API hashing + syscalls

💡 Your feedback helps improve future malware generation!

Next: Generate more samples with develop()
```

**When to use:** After testing generated malware against AV/EDR solutions.

---

## 5. files() - Manage Workspace 📁

**Purpose:** Browse and manage generated files in the workspace.

**Signature:**
```python
def files(
    pattern: str = "*.c",      # Optional file pattern
    open_latest: bool = False  # Optional flag
) -> str:
```

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `pattern` | `str` | `"*.c"` | File pattern to match (e.g., "*.exe", "*.md") |
| `open_latest` | `bool` | `False` | Highlight the latest file path |

**Example Usage:**

```python
# List all source files
files()

# List compiled binaries
files("*.exe")

# List markdown reports
files("*.md")

# Get latest file path
files(open_latest=True)
```

**Returns:**
```
====================================================================
|                    WORKSPACE BROWSER                            |
====================================================================

Found 5 file(s) in: C:\...\Noctis-MCP\output

1. malware_20251004_145230.c
   Size: 32.4 KB | Modified: 2025-10-04 14:52:30
   Path: C:\...\output\malware_20251004_145230.c

2. malware_20251004_123456.c
   Size: 28.7 KB | Modified: 2025-10-04 12:34:56
   Path: C:\...\output\malware_20251004_123456.c

💡 TIP: Click any path above to open in editor
```

**When to use:** When user asks "what files did I create?" or needs to find a specific file.

---

## 6. help() - Get Guidance ❓

**Purpose:** Display workflow guidance and usage examples.

**Signature:**
```python
def help(topic: str = None) -> str:
```

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `topic` | `str` | `None` | Specific topic (workflow, develop, browse, compile, learn, files) |

**Example Usage:**

```python
# General help
help()

# Help for specific tool
help("develop")

# Workflow guide
help("workflow")
```

**Returns:**
```
====================================================================
|              NOCTIS-MCP - AI MALWARE DEVELOPMENT                |
====================================================================

🚀 6 CORE TOOLS (Simplified Workflow)

1. develop()  - ⭐ PRIMARY TOOL - Create malware automatically
2. browse()   - Explore available techniques
3. compile()  - Build executables from source
4. learn()    - Provide feedback for ML system
5. files()    - Browse workspace files
6. help()     - Get guidance (you are here!)

QUICK START:
  develop(goal="Create a stealthy loader")

That's it! Everything is automated.

For detailed help on any topic:
  help("workflow")  - Full workflow guide
  help("develop")   - develop() tool guide
```

**When to use:** When user or AI is confused about how to use the system.

---

## 7. c2_generate() - Generate C2 Beacons 🔗

**Purpose:** Generate C2 framework beacons with Noctis obfuscation *(Future: Kali/WSL)*

**Note:** This requires C2 framework installation. Currently designed for future Kali/WSL development.

**Signature:**
```python
def c2_generate(
    framework: str,          # Required C2 framework
    listener_host: str,      # Required listener IP
    listener_port: int,      # Required listener port
    protocol: str = "https", # Optional
    architecture: str = "x64", # Optional
    obfuscate: bool = True   # Optional
) -> str:
```

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `framework` | `str` | *Required* | C2 framework (sliver, havoc, mythic) |
| `listener_host` | `str` | *Required* | C2 listener IP/hostname |
| `listener_port` | `int` | *Required* | C2 listener port |
| `protocol` | `str` | `"https"` | Protocol (https, http, dns, tcp, mtls) |
| `architecture` | `str` | `"x64"` | Target architecture (x64, x86) |
| `obfuscate` | `bool` | `True` | Apply Noctis obfuscation techniques |

**Example Usage:**

```python
c2_generate(
    framework="sliver",
    listener_host="192.168.1.100",
    listener_port=443,
    protocol="https"
)
```

**When to use:** In Kali/WSL environment when integrating with C2 frameworks.

---

## 8. c2_list() - List C2 Frameworks 📋

**Purpose:** Show supported C2 frameworks and their installation status.

**Signature:**
```python
def c2_list() -> str:
```

**Example Usage:**

```python
c2_list()
```

**Returns:**
```
====================================================================
|                  C2 FRAMEWORK INTEGRATION                       |
====================================================================

✅ Sliver
   Status: implemented
   Protocols: https, http, dns, mtls, tcp

🚧 Havoc
   Status: implemented
   Protocols: https, http

🚧 Mythic
   Status: implemented
   Protocols: https, http

💡 NOTE: C2 integration requires framework installation.
         Designed for Kali/WSL development environment.

To generate beacon:
  c2_generate(framework="sliver", listener_host="IP", listener_port=443)
```

**When to use:** To check C2 framework support and installation status.

---

## Recommended Workflow

### **Standard Workflow (95% of cases):**

```python
1. develop(goal="Create a stealthy loader", auto_compile=True)
2. Test the generated .exe in VM
3. learn(source_file="output/malware_*.c", av_name="Windows Defender", detected=False)
```

### **Advanced Workflow:**

```python
1. browse(search="evasion")                    # Explore available techniques
2. develop(goal="...", complexity="high")      # Generate malware
3. files()                                      # Find the source file
4. compile("output/malware_*.c")               # Compile manually
5. Test in isolated environment
6. learn(source_file="...", av_name="...", detected=False)
```

### **AI Assistant Decision Tree:**

```
User asks to create malware
  ↓
Use: develop(goal=user_objective)
  ↓
Done! ✅
```

That's it. The AI should almost always use `develop()` as the primary tool.

---

## What Makes Noctis-MCP Special?

### **Streamlined Design ✅**
- query_techniques, get_technique_details, list_categories, get_statistics, get_mitre_mappings
- generate_malware vs ai_develop_malware (confusing!)
- analyze_opsec vs ai_optimize_opsec (duplicates!)
- report_detection vs ai_record_feedback (redundant!)
- save_generated_code, list_workspace_files (manual)
- 5 broken agentic tools
- 5 C2 tools

**Problem:** AI assistants didn't know which tool to use. 50% error rate.

### **Current Design - 8 Tools ✅**
- **6 core tools** with clear, distinct purposes
- **2 C2 tools** for future integration
- **1 primary tool** (`develop`) handles 95% of use cases
- **No overlap** - each tool has unique purpose
- **Simple decision tree** - AI knows exactly what to do

**Result:** AI assistants use the correct tool every time.

---

## Technical Details

### **Architecture:**
```
MCP Client (noctis_mcp.py)
  ↓
FastMCP Server
  ↓
HTTP REST API (localhost:8888)
  ↓
Agent System (v2.0)
  ├── TechniqueSelectionAgent
  ├── MalwareDevelopmentAgent
  ├── OpsecOptimizationAgent
  └── LearningAgent
  ↓
Code Assembler → OPSEC Analyzer → Compiler
  ↓
Output Files
```

### **File Locations:**
- **Source code:** `output/malware_TIMESTAMP.c`
- **Metadata:** `output/malware_TIMESTAMP_metadata.json`
- **Reports:** `output/malware_TIMESTAMP_report.md`
- **Binaries:** `output/malware_TIMESTAMP.exe`

### **Requirements:**
- **API Server:** Must be running on localhost:8888
- **Compiler:** MSBuild (Windows) or MinGW (Linux/WSL)
- **Cursor IDE:** For MCP integration

---

## Troubleshooting

### **Tools not showing in Cursor?**
1. Check MCP.json configuration
2. Ensure API server is running: `python server/noctis_server.py --port 8888`
3. Restart Cursor IDE
4. Check logs: Look for MCP connection errors

### **Compilation fails?**
1. Ensure MSBuild is installed (Windows)
2. Check source code for syntax errors
3. Look at compilation warnings
4. Try lower optimization level: `compile(..., optimization="O0")`

### **Empty output directory?**
1. Run `develop()` first to generate code
2. Check if server is running
3. Verify permissions on output/ directory

---

**For more information:**
- Architecture: [ARCHITECTURE.md](ARCHITECTURE.md)
- User Guide: [USER_GUIDE.md](USER_GUIDE.md)
- API Reference: [API_REFERENCE.md](API_REFERENCE.md)

---

**Last Updated:** October 4, 2025
**Version:** 2.0.0-alpha
**License:** MIT
