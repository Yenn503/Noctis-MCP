# Direct System Calls (Syscalls)

## Technique ID: NOCTIS-T001

## Conceptual Understanding

### What Are Direct Syscalls?

Direct system calls bypass the standard Windows API (kernel32.dll, kernelbase.dll) and NTDLL user-mode wrappers to invoke kernel functions directly. This is achieved by:

1. **Retrieving syscall numbers** (SSNs) from NTDLL or hardcoding them
2. **Setting up registers** according to x64 calling convention
3. **Executing the syscall instruction** to transition to kernel mode

### Why Use Direct Syscalls?

**EDR/AV Evasion Benefits:**
- Bypasses userland hooks placed by security products in NTDLL and kernel32
- Reduces API call visibility in monitored functions
- Avoids behavioral detection of suspicious API sequences

**Limitations:**
- Syscall numbers change between Windows versions
- Kernel-mode callbacks can still detect syscalls
- ETW (Event Tracing for Windows) may log kernel activity
- Requires precise register setup and stack alignment

### Common Use Cases

1. **Process Injection**: `NtAllocateVirtualMemory`, `NtWriteVirtualMemory`, `NtCreateThreadEx`
2. **Process Enumeration**: `NtQuerySystemInformation`
3. **File Operations**: `NtCreateFile`, `NtReadFile`, `NtWriteFile`
4. **Token Manipulation**: `NtAdjustPrivilegesToken`, `NtDuplicateToken`

## Implementation Patterns

### Pattern 1: Hell's Gate (Dynamic SSN Retrieval)

**Concept**: Parse NTDLL at runtime to extract syscall numbers from clean function stubs.

**Advantages**:
- Works across Windows versions
- Resilient to inline hooks (can search for clean syscall stubs)

**Code Pattern**:
```c
DWORD GetSSN(LPCSTR functionName) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    BYTE* funcAddress = (BYTE*)GetProcAddress(ntdll, functionName);

    // Check for syscall stub: mov r10, rcx; mov eax, <SSN>; syscall; ret
    if (funcAddress[0] == 0x4C && funcAddress[1] == 0x8B &&
        funcAddress[2] == 0xD1 && funcAddress[3] == 0xB8) {
        return *(DWORD*)(funcAddress + 4); // Extract SSN
    }
    return 0;
}
```

### Pattern 2: Halo's Gate (Hooked Function Detection)

**Concept**: If target function is hooked, search nearby functions for clean syscall stubs.

**Advantages**:
- Detects and bypasses inline hooks
- More resilient than Hell's Gate

**Detection Logic**:
```c
BOOL IsHooked(BYTE* funcAddress) {
    // Check for jmp or push/ret (common hook patterns)
    if (funcAddress[0] == 0xE9 || funcAddress[0] == 0xFF) {
        return TRUE; // Hooked
    }
    return FALSE; // Clean
}
```

### Pattern 3: Tartarus' Gate (Full NTDLL Remapping)

**Concept**: Load a fresh copy of NTDLL from disk into memory to bypass all hooks.

**Advantages**:
- Complete hook evasion
- Works even with heavily monitored systems

**Disadvantages**:
- More complex implementation
- Higher OPSEC risk (memory artifacts)

## OPSEC Considerations

### Detection Vectors

1. **Memory Scanning**: Custom NTDLL copies in memory
2. **Behavioral Analysis**: Unusual syscall patterns
3. **Kernel Callbacks**: `PsSetCreateProcessNotifyRoutineEx` can detect process creation
4. **ETW Tracing**: Kernel ETW providers log syscall activity

### Evasion Improvements

1. **Combine with ETW patching** to disable kernel event tracing
2. **Use indirect syscalls** via `Wow64Transition` on 32-bit processes
3. **Randomize syscall order** to avoid behavioral signatures
4. **Implement sleep obfuscation** between syscalls

## Integration with Other Techniques

### Complementary Techniques

- **API Hashing** (NOCTIS-T002): Hide function resolution
- **Unhooking** (NOCTIS-T005): Restore clean NTDLL before syscalls
- **ETW Patching**: Disable kernel event logging
- **Stack Spoofing**: Hide call stack during syscall execution

### Example Workflow

```
1. Unhook NTDLL (restore clean .text section)
2. Resolve syscall numbers via Hell's Gate
3. Patch ETW to disable tracing
4. Execute direct syscalls for injection
5. Use stack spoofing during syscall execution
```

## Target AV/EDR Effectiveness

| Security Product | Effectiveness | Notes |
|-----------------|---------------|-------|
| Windows Defender | High | Often doesn't hook NTDLL deeply |
| CrowdStrike Falcon | Medium | Kernel callbacks detect syscalls |
| Palo Alto Cortex XDR | Medium | Behavioral analysis may flag |
| Carbon Black | High | Limited userland hooking |
| SentinelOne | Low | Advanced kernel monitoring |

## Real-World Examples

### GitHub Projects
- **SysWhispers2**: Generates direct syscall stubs
- **Hell's Gate**: Dynamic SSN retrieval
- **Halo's Gate**: Hooked function bypass
- **Tartarus' Gate**: Full NTDLL remapping

### Research Papers
- "Bypass EDR's memory protection, introduction to hooking" (MDSec)
- "Bypassing User-Mode Hooks and Direct Invocation of System Calls" (Outflank)

## Learning Resources

- **Blog Posts**: MDSec, Outflank, RedTeam Tactics
- **Code Examples**: GitHub (SysWhispers, InlineWhispers)
- **Research**: "Windows Internals" by Russinovich

## Version-Specific Notes

- **Windows 10**: Syscall numbers stable within major builds
- **Windows 11**: New kernel protections (VBS, HVCI)
- **Server 2019/2022**: Similar to Windows 10 21H2

## Metadata

- **MITRE ATT&CK**: T1055 (Process Injection), T1106 (Native API)
- **Complexity**: Medium
- **Stability**: High (when SSNs resolved dynamically)
- **OPSEC Score**: 7.5/10
