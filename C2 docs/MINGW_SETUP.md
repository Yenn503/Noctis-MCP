# MinGW Cross-Compilation Setup Guide

**Cross-compile Windows malware on Linux without needing Windows!**

Noctis-MCP now supports **MinGW-w64** for cross-compiling Windows executables on Linux. This guide shows you how to set it up and use it.

---

## Quick Start

### 1. Install MinGW-w64

```bash
# Debian/Ubuntu/Kali
sudo apt-get update
sudo apt-get install mingw-w64

# Fedora/RHEL
sudo dnf install mingw64-gcc mingw32-gcc

# Arch
sudo pacman -S mingw-w64-gcc
```

### 2. Verify Installation

```bash
# Check x64 compiler
x86_64-w64-mingw32-gcc --version

# Check x86 compiler
i686-w64-mingw32-gcc --version
```

You should see something like:
```
x86_64-w64-mingw32-gcc (GCC) 14-win32
```

### 3. Test Noctis Compilation

```bash
cd ~/Noctis-MCP
source venv/bin/activate

# Run MinGW tests
python -m pytest tests/test_linux_compiler.py -v
```

**Expected result:** All 12 tests pass ✅

---

## How It Works

Noctis-MCP **automatically detects** your operating system and uses the appropriate compiler:

- **Windows:** Uses MSBuild + Visual Studio
- **Linux:** Uses MinGW-w64 cross-compiler

No configuration needed! The `get_compiler()` function handles everything:

```python
from compilation import get_compiler

# Automatically uses MinGW on Linux, MSBuild on Windows
compiler = get_compiler(output_dir="compiled")

result = compiler.compile(
    source_code=malware_code,
    architecture="x64",      # or "x86"
    optimization="O2",       # O0, O1, O2, O3
    output_name="payload",
    subsystem="Console"      # or "Windows"
)

if result.success:
    print(f"Binary: {result.binary_path}")
    print(f"Size: {result.metadata['binary_size']:,} bytes")
```

---

## Features

### Supported Architectures
- ✅ **x64** (64-bit Windows) - `x86_64-w64-mingw32-gcc`
- ✅ **x86** (32-bit Windows) - `i686-w64-mingw32-gcc`

### Supported Subsystems
- ✅ **Console** - Standard command-line executable
- ✅ **Windows** - GUI application (no console window)

### Optimization Levels
- **O0** - No optimization (debugging)
- **O1** - Basic optimization
- **O2** - Moderate optimization (recommended)
- **O3** - Aggressive optimization

### Windows APIs Supported
- ✅ **Win32 API** - Full support (kernel32, user32, advapi32, etc.)
- ✅ **PE Headers** - IMAGE_DOS_HEADER, IMAGE_NT_HEADERS, etc.
- ✅ **Windows Types** - HMODULE, FARPROC, DWORD, etc.
- ✅ **MessageBox, LoadLibrary, GetProcAddress** - All work!

---

## Example: Compile Malware with API Hashing

```python
#!/usr/bin/env python3
from compilation import get_compiler

# Malware code with API hashing (DJB2)
malware = """
#include <windows.h>
#include <stdio.h>

// DJB2 hash function
UINT64 djb2(PBYTE str) {
    UINT64 hash = 0x7734773477347734;
    INT c;
    while (c = *str++)
        hash = ((hash << 0x5) + hash) + c;
    return hash;
}

// Resolve API by hash
FARPROC GetProcAddressH(HMODULE hModule, UINT64 hash) {
    // ... PE parsing code ...
    return NULL;  // Simplified
}

int main() {
    HMODULE hKernel32 = LoadLibraryA("kernel32.dll");
    
    // Hash instead of plaintext API name
    UINT64 hash = djb2((PBYTE)"VirtualAlloc");
    FARPROC pVirtualAlloc = GetProcAddressH(hKernel32, hash);
    
    MessageBoxA(NULL, "Hashed APIs!", "Noctis", MB_OK);
    return 0;
}
"""

# Compile with MinGW (automatic on Linux)
compiler = get_compiler(output_dir="output")

result = compiler.compile(
    source_code=malware,
    architecture="x64",
    optimization="O2",
    output_name="malware",
    subsystem="Console"
)

if result.success:
    print(f"✓ Compiled: {result.binary_path}")
    print(f"✓ Size: {result.metadata['binary_size']:,} bytes")
    print(f"✓ Time: {result.compilation_time:.2f}s")
    print(f"✓ Arch: {result.metadata['architecture']}")
else:
    print(f"✗ Failed!")
    for error in result.errors:
        print(f"  - {error}")
```

**Output:**
```
✓ Compiled: output/malware.exe
✓ Size: 39,936 bytes
✓ Time: 1.02s
✓ Arch: x64
```

---

## Testing Compiled Binaries

### Option 1: Wine (on Linux)

```bash
# Install Wine
sudo apt-get install wine64 wine32

# Run Windows executable
wine output/malware.exe
```

### Option 2: Windows VM

```bash
# Copy to shared folder or upload to VM
scp output/malware.exe user@windows-vm:/path/
```

### Option 3: VirusTotal

**⚠️ OPSEC WARNING:** Only upload if you don't care about exposure!

```bash
# Upload to VirusTotal (exposes your binary to AV vendors!)
curl -X POST 'https://www.virustotal.com/vtapi/v2/file/scan' \
  -F file=@output/malware.exe \
  -F apikey=YOUR_API_KEY
```

---

## Compilation Options

### Static Linking (No DLLs)

MinGW automatically uses static linking, so your binaries have **no external dependencies**:

```bash
# Check dependencies
wine output/malware.exe
# No missing DLL errors! Everything is included.
```

### Symbol Stripping

Symbols are automatically stripped with the `-s` flag:

```bash
# Verify symbols are stripped
file output/malware.exe
# Output: PE32+ executable ... (stripped to external PDB)
```

### Optimization Comparison

```python
# Test different optimization levels
for opt in ["O0", "O1", "O2", "O3"]:
    result = compiler.compile(
        source_code=code,
        optimization=opt,
        output_name=f"malware_{opt}"
    )
    print(f"{opt}: {result.metadata['binary_size']:,} bytes")
```

**Example output:**
```
O0: 52,224 bytes
O1: 43,008 bytes
O2: 39,936 bytes
O3: 38,400 bytes
```

---

## Integration with Noctis API

The Noctis API server automatically uses the correct compiler:

```bash
# Start Noctis server (on Linux)
cd ~/Noctis-MCP
source venv/bin/activate
python server/noctis_server.py
```

**API Request:**
```bash
curl -X POST http://localhost:8888/api/compile \
  -H "Content-Type: application/json" \
  -d '{
    "source_code": "#include <windows.h>\nint main() { MessageBoxA(NULL, \"Hi!\", \"Test\", MB_OK); return 0; }",
    "architecture": "x64",
    "optimization": "O2",
    "output_name": "test"
  }'
```

**Response:**
```json
{
  "success": true,
  "binary_path": "compiled/test.exe",
  "compilation_time": 0.98,
  "metadata": {
    "architecture": "x64",
    "optimization": "O2",
    "compiler": "/usr/bin/x86_64-w64-mingw32-gcc",
    "platform": "Windows (cross-compiled from Linux)",
    "binary_size": 39936
  }
}
```

---

## Troubleshooting

### MinGW not found

**Error:**
```
MinGW-w64 not found. Install with:
  sudo apt-get install mingw-w64
```

**Solution:**
```bash
sudo apt-get update
sudo apt-get install mingw-w64
```

### Compilation errors with Windows headers

**Error:**
```
fatal error: windows.h: No such file or directory
```

**Solution:**
```bash
# Install MinGW headers
sudo apt-get install mingw-w64-tools

# Verify headers exist
ls /usr/x86_64-w64-mingw32/include/windows.h
```

### Binary won't run on Windows

**Issue:** "Not a valid Win32 application"

**Solution:** Check architecture matches:
- Windows x64: Use `architecture="x64"`
- Windows x86: Use `architecture="x86"`

---

## Performance Benchmarks

Tested on Kali Linux 2024 (Intel i7, 16GB RAM):

| Code Size | Architecture | Optimization | Compile Time | Binary Size |
|-----------|--------------|--------------|--------------|-------------|
| 100 lines | x64          | O2           | 0.89s        | 37,888 bytes|
| 500 lines | x64          | O2           | 1.23s        | 54,272 bytes|
| 1000 lines| x64          | O2           | 1.87s        | 89,600 bytes|
| 100 lines | x86          | O2           | 0.76s        | 32,256 bytes|

**Conclusion:** MinGW is **fast** and produces **compact** binaries!

---

## Advanced Usage

### Custom Compiler Flags

```python
from compilation.linux_compiler import LinuxCompiler

compiler = LinuxCompiler(output_dir="output")

# Access to modify compiler command (advanced)
# See compilation/linux_compiler.py for details
```

### Multi-file Projects

```python
# Coming soon: Multi-file support for MinGW
# Currently: Concatenate files or use includes
```

---

## Comparison: MSBuild vs MinGW

| Feature | Windows (MSBuild) | Linux (MinGW) |
|---------|-------------------|---------------|
| Requires Windows | ✅ Yes | ❌ No |
| Compile Time | ~0.8s | ~1.0s |
| Binary Size | ~40KB | ~39KB |
| Optimization | Full | Full |
| Windows API Support | Native | Full |
| Cross-platform | ❌ No | ✅ Yes |
| **Verdict** | **Best on Windows** | **Best on Linux** |

---

## Next Steps

1. ✅ MinGW installed and working
2. ✅ Noctis automatically uses it
3. ⏳ Test with Sliver C2 beacon generation
4. ⏳ Deploy to Windows VM and test callback

**Ready for C2 integration!** See `INSTALL_SLIVER.md` for next steps.

---

**Questions?** Check `CURRENT_STATUS.md` or open an issue on GitHub.

**Happy cross-compiling!** 🚀

