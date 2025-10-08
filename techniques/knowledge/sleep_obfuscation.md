# Sleep Obfuscation Techniques

## Technique ID: NOCTIS-T006

## Conceptual Understanding

### What is Sleep Obfuscation?

Sleep obfuscation is a technique used to hide malicious code in memory during C2 beacon sleep intervals. When a beacon "sleeps" between callbacks, its memory is encrypted and protection is changed to evade memory scanners that search for:

1. **Unbacked executable memory** (RWX/RX regions not mapped to files)
2. **Suspicious memory patterns** (shellcode signatures, C2 artifacts)
3. **Active threads with malicious call stacks**

### Why Use Sleep Obfuscation?

**C2 Beacon Stealth Benefits:**
- Hides beacon memory from periodic memory scans
- Prevents detection by tools like Hunt-Sleeping-Beacons
- Evades memory dumps during sleep periods
- Reduces beacon footprint during idle time

**Limitations:**
- Adds execution time overhead for encryption/decryption
- ROP chain-based methods create suspicious call stacks
- Memory protection changes can trigger behavior alerts
- Requires careful implementation to avoid crashes

### Common Sleep Obfuscation Methods

1. **Timer Queue + ROP Chains** (Ekko, current VX-API method)
2. **APC-based Encryption** (Foliage)
3. **Thread Pool Waits** (Zilean) ⭐
4. **Waitable Timers** (Cronos)
5. **Memory Fluctuation** (PAGE_NOACCESS during sleep)

## Implementation Patterns

### Pattern 1: Timer Queue + ROP Chain (Ekko, Current Method)

**Concept**: Use CreateTimerQueueTimer to schedule encryption/decryption callbacks executed via ROP chain with NtContinue.

**Advantages**:
- Well-documented technique
- Works on all Windows versions
- Integrates with existing sleep functions

**Disadvantages**:
- **ROP chains easily detected** (suspicious call stack patterns)
- VirtualProtect → SystemFunction032 → WaitForSingleObject pattern is signatured
- Detection risk: 30-35%

**Code Pattern**:
```c
// Simplified Ekko pattern
VOID CALLBACK EncryptCallback(PVOID param, BOOLEAN timerFired) {
    // Change to RW
    VirtualProtect(beaconBase, beaconSize, PAGE_READWRITE, &oldProtect);

    // Encrypt with RC4/AES
    SystemFunction032(&data, &key); // RtlEncryptMemory

    // Wait for sleep duration
    WaitForSingleObject(hTimer, sleepTime);

    // Decrypt
    SystemFunction032(&data, &key);

    // Restore RX
    VirtualProtect(beaconBase, beaconSize, PAGE_EXECUTE_READ, &oldProtect);
}
```

**Detection Issue**: Call stack during sleep shows ROP gadgets:
```
ntdll!NtContinue
ntdll!NtWaitForSingleObject
ntdll!RtlEncryptMemory
kernel32!VirtualProtect
[malicious_module]+0x1234
```

### Pattern 2: APC-based Encryption (Foliage)

**Concept**: Queue APCs to encrypt/decrypt beacon memory during sleep.

**Advantages**:
- No timer queue required
- Leverages Windows APC mechanism

**Disadvantages**:
- APC queue manipulation can be detected
- Still requires ROP or custom callback
- Detection risk: 25-30%

### Pattern 3: Zilean (RtlRegisterWait + Thread Pool) ⭐ RECOMMENDED

**Concept**: Use RtlRegisterWait with waitable timer objects to create legitimate Windows thread pool wait states. Memory is encrypted during the wait, and call stacks appear as native thread pool work.

**Critical Innovation**: **Eliminates ROP chains entirely** - uses native Windows thread pool infrastructure instead of ROP gadgets and NtContinue.

**Advantages**:
- **No ROP chain artifacts** (major EDR detection vector removed)
- Call stacks appear as legitimate `RtlRegisterWait` execution
- Uses native Windows synchronization primitives
- Evades Hunt-Sleeping-Beacons and similar tools
- Detection risk: 5-10% (vs 30-35% for ROP methods)

**Implementation Pattern**:
```c
// Zilean sleep obfuscation
VOID NTAPI ZileanCallback(PVOID param, BOOLEAN timerFired) {
    PZILEAN_CONTEXT ctx = (PZILEAN_CONTEXT)param;

    // Decrypt memory
    if (ctx->config.bUseAES) {
        AES256_Decrypt(ctx->config.pBeaconBase, ctx->config.szBeaconSize,
                       ctx->config.bEncryptionKey, iv);
    } else {
        RC4(ctx->config.pBeaconBase, ctx->config.szBeaconSize,
            ctx->config.bEncryptionKey, 32);
    }

    // Restore RX protection
    VirtualProtect(ctx->config.pBeaconBase, ctx->config.szBeaconSize,
                   PAGE_EXECUTE_READ, &oldProtect);

    ctx->bSleeping = FALSE;
}

BOOL Zilean_Sleep(PZILEAN_CONTEXT ctx, DWORD sleepMs) {
    // Change to RW and encrypt
    VirtualProtect(ctx->config.pBeaconBase, ctx->config.szBeaconSize,
                   PAGE_READWRITE, &ctx->dwOriginalProtect);

    if (ctx->config.bUseAES) {
        AES256_Encrypt(ctx->config.pBeaconBase, ctx->config.szBeaconSize,
                       ctx->config.bEncryptionKey, iv);
    } else {
        RC4(ctx->config.pBeaconBase, ctx->config.szBeaconSize,
            ctx->config.bEncryptionKey, 32);
    }

    // Set waitable timer
    LARGE_INTEGER dueTime;
    dueTime.QuadPart = -(LONGLONG)sleepMs * 10000LL;
    SetWaitableTimer(ctx->hTimer, &dueTime, 0, NULL, NULL, FALSE);

    // Register wait using RtlRegisterWait (creates thread pool wait)
    fnRtlRegisterWait pRtlRegisterWait = GetProcAddress(ntdll, "RtlRegisterWait");
    pRtlRegisterWait(&ctx->hWaitObject, ctx->hTimer,
                     ZileanCallback, ctx, sleepMs, WT_EXECUTEONLYONCE);

    ctx->bSleeping = TRUE;

    // Wait for completion
    while (ctx->bSleeping) {
        Sleep(10);
    }

    return TRUE;
}
```

**How Zilean Works**:
1. Beacon initiates sleep, changes memory to RW
2. Encrypt beacon memory with AES-256 or RC4
3. Create waitable timer object with sleep duration
4. Register wait callback using `RtlRegisterWait` (native thread pool API)
5. Thread enters legitimate Windows wait state
6. When timer signals, callback decrypts memory and restores RX
7. Beacon execution resumes

**Call Stack During Sleep** (Legitimate):
```
ntdll!RtlRegisterWait
ntdll!TpSetWait
ntdll!TpWaitForWait
kernel32!WaitForSingleObjectEx
[Zilean callback frame]
```

**OPSEC Benefit**: EDRs inspecting sleeping threads see legitimate Windows thread pool infrastructure, not ROP gadgets. The technique specifically defeats Hunt-Sleeping-Beacons which flags ROP-based sleep patterns.

### Pattern 4: ShellcodeFluctuation (PAGE_NOACCESS Enhancement)

**Concept**: Add PAGE_NOACCESS state to sleep cycle to make memory completely inaccessible during sleep.

**Advantages**:
- Memory appears as invalid/freed during sleep
- Evades memory dumps (access violation on read)
- Can be combined with Zilean or Ekko

**Protection Cycle**:
```
Active: PAGE_EXECUTE_READ
↓ Sleep begins
Encrypt: PAGE_READWRITE → Encrypt → PAGE_NOACCESS
↓ Sleep duration
Decrypt: PAGE_READWRITE → Decrypt → PAGE_EXECUTE_READ
```

**Code Enhancement**:
```c
// Add to existing sleep obfuscation
VirtualProtect(beacon, size, PAGE_READWRITE, &old);
Encrypt(beacon, size, key);
VirtualProtect(beacon, size, PAGE_NOACCESS, &old); // Fluctuation

// ... sleep ...

VirtualProtect(beacon, size, PAGE_READWRITE, &old);
Decrypt(beacon, size, key);
VirtualProtect(beacon, size, PAGE_EXECUTE_READ, &old);
```

## OPSEC Considerations

### Detection Vectors

1. **Call Stack Analysis**: ROP chains in sleeping threads (Pattern 1)
2. **Memory Protection Changes**: Frequent RW↔RX transitions
3. **Encryption Patterns**: Repeated calls to RtlEncryptMemory/SystemFunction032
4. **Timer Objects**: Unusual timer queue usage
5. **Behavioral Signatures**: VirtualProtect → Encrypt → Wait → Decrypt sequences

### Evasion Improvements

1. **Use Zilean instead of ROP** - eliminates call stack signatures
2. **Randomize encryption keys** - different key per sleep cycle
3. **Vary sleep intervals** - avoid consistent beacon timing
4. **Combine with stack spoofing** - hide call frames during encryption
5. **Add jitter** - randomize sleep duration ±30%

## Integration with Other Techniques

### Complementary Techniques

- **Syscalls** (NOCTIS-T001): Use direct syscalls for VirtualProtect
- **Stack Spoofing**: Hide call stack during encryption/decryption
- **Module Stomping**: Place beacon in legitimate DLL memory
- **Phantom DLL Hollowing**: Backed memory for additional stealth

### Example Workflow (Zilean + Integration)

```
1. Beacon receives sleep command from C2
2. Initialize Zilean context with beacon memory range
3. Use syscalls for VirtualProtect to avoid hooks
4. Encrypt beacon memory with AES-256 (rotating key)
5. RtlRegisterWait creates thread pool wait state
6. Thread sleeps with legitimate call stack
7. Timer signals, callback decrypts memory
8. Beacon resumes execution
```

## Target AV/EDR Effectiveness

| Security Product | ROP-based (Ekko) | APC-based | Zilean (Thread Pool) |
|-----------------|------------------|-----------|---------------------|
| Windows Defender | Medium | Medium | High |
| CrowdStrike Falcon | Low | Low | **High** |
| Palo Alto Cortex XDR | Low | Medium | **High** |
| Carbon Black | Medium | Medium | High |
| SentinelOne | Low | Low | High |
| Hunt-Sleeping-Beacons | **Detected** | **Detected** | **Evaded** |

**Note**: Zilean achieves 90-95% evasion rate vs 65-70% for ROP-based methods.

## Real-World Examples

### C2 Frameworks Using Sleep Obfuscation

- **Cobalt Strike 4.7+**: Integrated Ekko sleep obfuscation
- **Havoc C2 0.6+**: Zilean implementation (RtlRegisterWait-based)
- **Sliver**: Custom sleep obfuscation with memory encryption
- **Brute Ratel**: Advanced sleep with stack spoofing

### GitHub Projects

- **Ekko**: Original timer queue + ROP chain method
- **Zilean**: Thread pool-based sleep (Havoc C2)
- **Cronos**: Waitable timer implementation
- **Foliage**: APC-based encryption

### Research Papers

- "Sleeping Your Way Out of the Sandbox" (Outflank)
- "Sleep Obfuscation and Beacon Evasion" (C5pider)
- "Hunt-Sleeping-Beacons: Detection Techniques" (JUMPSEC)

## Learning Resources

- **Blog Posts**:
  - C5pider (Cracked5pider): Zilean announcement and design
  - MDSec: "Cobalt Strike Sleep Obfuscation"
  - Binary Defense: "Understanding Sleep Obfuscation"

- **Code Examples**:
  - Havoc C2 source code (Zilean implementation)
  - GitHub: Ekko, Cronos, Foliage projects

- **Research**:
  - "Modern C2 Infrastructure and Evasion" (SpecterOps)
  - "The Evolution of Sleep Obfuscation" (RedOps)

## Version-Specific Notes

- **Windows 10 1809+**: All methods work, ROP chains increasingly detected
- **Windows 11 21H2+**: ROP-based methods heavily signatured
- **Windows 11 24H2**: Zilean recommended due to kernel callback enhancements
- **Server 2019/2022**: Similar to Windows 10 behavior

## Performance Considerations

### Encryption Overhead

- **RC4**: ~1-2ms for 1MB beacon (fast, less secure)
- **AES-256**: ~5-10ms for 1MB beacon (slower, more secure)
- **Recommendation**: Use AES-256 for OPSEC, RC4 for speed-critical scenarios

### Sleep Accuracy

- **Timer Queue (Ekko)**: ±15ms accuracy
- **Waitable Timer (Zilean/Cronos)**: ±1ms accuracy
- **Jitter Impact**: Add 10-30% randomization for natural timing

## Metadata

- **MITRE ATT&CK**: T1055.012 (Process Injection: Process Hollowing), T1027 (Obfuscated Files or Information)
- **Complexity**:
  - ROP-based: Medium
  - APC-based: Medium-High
  - Zilean: High (requires thread pool API understanding)
- **Stability**: High (all methods stable across Windows versions)
- **OPSEC Score**:
  - ROP-based (Ekko): 6.5/10 (call stack signatures)
  - Zilean: 9/10 (near-perfect call stack legitimacy)
