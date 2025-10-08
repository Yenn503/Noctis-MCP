# Kernel-Level EDR Bypass Techniques

## Technique ID: NOCTIS-T008

## ⚠️ WARNING: LOUD TECHNIQUES - POST-COMPROMISE ONLY

**Detection Risk**: HIGH (60-70% during execution)
**Use Case**: Post-compromise operations where detection is acceptable
**Privilege Required**: Administrator / SYSTEM
**Operational Profile**: "Scorched earth" - prioritizes success over stealth

---

## Conceptual Understanding

### What is Kernel-Level EDR Bypass?

Kernel-level EDR bypass techniques operate in Windows kernel mode (Ring 0) to disable or manipulate EDR security sensors. Unlike userland techniques that evade hooks and monitoring, kernel bypasses **directly disable** the monitoring infrastructure itself.

**Why EDRs Use Kernel Drivers**:
1. **Kernel Callbacks**: Monitor process/thread/module events via notify routines
2. **Object Callbacks**: Monitor handle operations (OpenProcess, OpenThread, etc.)
3. **ETW (Event Tracing for Windows)**: Log syscall and API activity
4. **SSDT Hooks**: Intercept system calls at kernel level
5. **Minifilter Drivers**: Monitor file system operations

### The Kernel Bypass Philosophy

**Userland Evasion** (Phase 1-3):
- Goal: Avoid detection by hiding from sensors
- Approach: Stealth, obfuscation, misdirection
- Detection Risk: 2-8%
- Use Case: Initial access, stealth operations

**Kernel Bypass** (This document):
- Goal: Disable sensors entirely
- Approach: Brute force, direct manipulation
- Detection Risk: 60-70% upfront, then 0%
- Use Case: Post-compromise, ransomware, "loud" operations

---

## EDRSandBlast - Kernel Callback Removal

### Technique Overview

**Source**: https://github.com/wavestone-cdt/EDRSandblast
**Date**: 2024 (actively maintained)
**Category**: Kernel Exploitation / EDR Bypass
**Author**: Wavestone Consulting

**Description**: EDRSandBlast weaponizes vulnerable signed drivers (BYOVD - Bring Your Own Vulnerable Driver) to disable EDR kernel-mode protections. By loading a vulnerable driver with kernel-mode arbitrary read/write primitives, the tool directly manipulates kernel memory structures to blind EDR sensors.

### Attack Flow

```
1. Attacker gains Administrator privileges (required for driver loading)
2. Download/embed vulnerable signed driver (e.g., DBUtil_2_3.sys, RTCore64.sys)
3. Load driver using NtLoadDriver (requires SeLoadDriverPrivilege)
   └─> ⚠️ DETECTION POINT #1: Driver load monitored by EDR/Windows Defender
4. Use driver IOCTL to read/write kernel memory
5. Locate EDR kernel structures in memory:
   - PsSetCreateProcessNotifyRoutine callback array
   - ObRegisterCallbacks callback array
   - ETW Threat Intelligence provider
   - SSDT (System Service Descriptor Table) hooks
6. Remove EDR callbacks from kernel arrays
   └─> ⚠️ DETECTION POINT #2: Kernel memory writes may trigger PatchGuard
7. EDR is now blind - no process/thread/syscall monitoring
8. Execute payload with zero EDR visibility
9. (Optional) Unload driver and clean up
```

### Capabilities

#### 1. Remove Process Creation Callbacks
```c
// EDRs register callbacks via:
PsSetCreateProcessNotifyRoutine(MyProcessCallback, FALSE);

// EDRSandBlast locates the callback array in kernel memory:
nt!PspCreateProcessNotifyRoutine

// Removes EDR callback entries:
PspCreateProcessNotifyRoutine[EDR_INDEX] = NULL;
```

**Effect**: EDR loses visibility into:
- Process creation (CreateProcess, NtCreateUserProcess)
- Process termination
- Parent-child process relationships
- Process injection detection

#### 2. Remove Thread Creation Callbacks
```c
// EDRs register callbacks via:
PsSetCreateThreadNotifyRoutine(MyThreadCallback);

// EDRSandBlast targets:
nt!PspCreateThreadNotifyRoutine

// Removes callbacks:
PspCreateThreadNotifyRoutine[EDR_INDEX] = NULL;
```

**Effect**: EDR loses visibility into:
- Thread creation (CreateThread, NtCreateThreadEx)
- Remote thread injection (CreateRemoteThread)
- Thread hijacking (SuspendThread + SetThreadContext)

#### 3. Remove Image Load Callbacks
```c
// EDRs register callbacks via:
PsSetLoadImageNotifyRoutine(MyImageCallback);

// EDRSandBlast targets:
nt!PspLoadImageNotifyRoutine

// Removes callbacks:
PspLoadImageNotifyRoutine[EDR_INDEX] = NULL;
```

**Effect**: EDR loses visibility into:
- DLL loading (LoadLibrary, LdrLoadDll)
- Reflective DLL injection
- PE image mapping

#### 4. Remove Object Callbacks
```c
// EDRs register callbacks via:
ObRegisterCallbacks(&callbackRegistration, &registrationHandle);

// EDRSandBlast targets:
ObTypeIndexTable (process/thread object types)

// Removes pre/post operation callbacks:
ProcessType->CallbackList = NULL;
ThreadType->CallbackList = NULL;
```

**Effect**: EDR loses visibility into:
- OpenProcess operations
- OpenThread operations
- Handle duplication
- Process/thread protection bypass

#### 5. Disable ETW Threat Intelligence (TI)
```c
// ETW TI provider logs syscalls to ETW channels
// EDRs consume these events for behavior analysis

// EDRSandBlast patches kernel ETW provider:
nt!EtwThreatIntProvRegHandle->IsEnabled = FALSE;
```

**Effect**: EDR loses visibility into:
- Syscall execution (NtAllocateVirtualMemory, NtWriteVirtualMemory, etc.)
- API call patterns
- Behavioral anomaly detection

#### 6. Unhook System Service Descriptor Table (SSDT)
```c
// Some EDRs hook SSDT entries to intercept syscalls

// EDRSandBlast restores original SSDT:
KeServiceDescriptorTable[INDEX].ServiceTable[SYSCALL] = OriginalAddress;
```

**Effect**: EDR syscall hooks bypassed at kernel level

### Vulnerable Drivers Used

**Common Vulnerable Drivers** (as of 2024-2025):

| Driver | Vendor | CVE | Capabilities | Blocked? |
|--------|--------|-----|--------------|----------|
| **DBUtil_2_3.sys** | Dell | CVE-2021-21551 | Arbitrary R/W | ⚠️ Partially |
| **RTCore64.sys** | MSI | CVE-2019-16098 | Arbitrary R/W | ✅ Yes (blocklist) |
| **gdrv.sys** | Gigabyte | CVE-2018-19320 | Arbitrary R/W | ✅ Yes (blocklist) |
| **AsUpIO64.sys** | ASUS | CVE-2020-15368 | Physical memory R/W | ⚠️ Partially |
| **WinRing0x64.sys** | OpenLibSys | Multiple | I/O port access | ✅ Yes (blocklist) |

**Microsoft Driver Blocklist**: Windows Update regularly adds vulnerable drivers to `DriverSiPolicy.p7b`. Attackers must constantly find new vulnerable drivers.

### Detection Vectors

#### During Driver Loading (60-70% detection):
1. **Defender SmartScreen**: Flags unsigned/unknown drivers
2. **EDR Driver Load Monitoring**: `ZwLoadDriver` callback triggers
3. **Sysmon Event ID 6**: Driver loaded event (if Sysmon deployed)
4. **Windows Event Log 7045**: Service creation (driver as service)
5. **HVCI (Hypervisor-Protected Code Integrity)**: Blocks unsigned drivers on Windows 11

#### During Kernel Manipulation (30-40% detection):
1. **PatchGuard (KPP)**: Detects kernel memory modifications, triggers BSOD
2. **Kernel Instrumentation Callback (KIC)**: Windows 10+ monitors kernel writes
3. **ETW Kernel Events**: Logs kernel memory writes (if not disabled)
4. **Driver Signature Enforcement**: Rejects tampered drivers

#### Post-Bypass (0% detection):
- EDR is completely blind
- No callbacks = no monitoring
- Payload execution invisible to EDR

---

## OPSEC Considerations

### When to Use Kernel Bypass

**✅ APPROPRIATE Use Cases:**
1. **Ransomware Deployment**: Speed > stealth, detection inevitable
2. **Post-Compromise Privilege Escalation**: Already have access, need to disable defenses
3. **Incident Response Testing**: Testing blue team kernel detection capabilities
4. **Red Team "Loud" Operations**: Simulating APT with kernel-level access

**❌ INAPPROPRIATE Use Cases:**
1. **Initial Access**: Gets you caught immediately
2. **Stealth Operations**: Contradicts the goal entirely
3. **Long-Term Persistence**: Technique burns quickly
4. **Standard Red Team Ops**: Phase 1-3 techniques are sufficient (2-8% detection)

### Operational Trade-offs

**Advantages**:
- **Complete EDR Blindness**: Zero visibility after bypass
- **Works Against All EDRs**: Kernel-level = universal bypass
- **Enables Any Payload**: No restrictions once sensors disabled

**Disadvantages**:
- **High Detection Risk**: 60-70% during execution
- **Requires Admin**: No value for user-level operations
- **Driver Blocklist**: Techniques expire as drivers blocked
- **PatchGuard Risk**: May cause system crashes
- **Legal Concerns**: Kernel exploitation more sensitive
- **Irreversible**: Once detected, technique is burned

---

## RealBlindingEDR - Enhanced Kernel Callback Manipulation

### Technique Overview

**Source**: https://github.com/ZeroMemoryEx/RealBlindingEDR (2024-2025)
**Category**: Kernel Exploitation / EDR Bypass Enhancement
**Detection Risk**: 55-65% (marginal improvement over EDRSandBlast)

**Description**: RealBlindingEDR is an evolution of EDRSandBlast that addresses several detection vectors and operational limitations of the original technique. Instead of simply removing EDR callbacks, RealBlindingEDR employs more sophisticated manipulation strategies to reduce behavioral anomalies.

### Key Improvements Over EDRSandBlast

#### 1. Callback Patching vs Removal

**EDRSandBlast Approach**:
```c
// Simply nullifies callback entry
PspCreateProcessNotifyRoutine[EDR_INDEX] = NULL;
```

**Problem**: Creating NULL entries in callback arrays is anomalous and detectable via integrity validation.

**RealBlindingEDR Approach**:
```c
// Replaces EDR callback with NOP-equivalent function
PspCreateProcessNotifyRoutine[EDR_INDEX] = &NoOpCallback;

// NoOpCallback returns immediately without action
VOID NoOpCallback(HANDLE ParentId, HANDLE ProcessId, BOOLEAN Create) {
    return; // Do nothing, appear legitimate
}
```

**Benefit**: Callback array remains populated, appears normal to integrity checks.

#### 2. Selective Callback Disablement

**EDRSandBlast Approach**:
- Removes ALL callbacks for process/thread/image creation
- Affects ALL security products simultaneously

**RealBlindingEDR Approach**:
- Identifies specific EDR callbacks by return address fingerprinting
- Disables ONLY target EDR callbacks
- Leaves Windows Defender and other products functional

**Implementation**:
```c
// Enumerate callback array
for (ULONG i = 0; i < 64; i++) {
    if (!PspCreateProcessNotifyRoutine[i]) continue;

    // Get callback address (decrypt if Windows 10+)
    PVOID pCallback = DecryptCallbackPointer(PspCreateProcessNotifyRoutine[i]);

    // Determine which driver owns this callback by searching loaded module list
    PKLDR_DATA_TABLE_ENTRY pModule = FindModuleByAddress(pCallback);
    if (!pModule) continue;

    // Check if callback belongs to target EDR (e.g., CrowdStrike)
    if (wcsstr(pModule->BaseDllName.Buffer, L"CrowdStrike")) {
        // Disable ONLY CrowdStrike callback
        PspCreateProcessNotifyRoutine[i] = EncryptCallbackPointer(&NoOpCallback);
    }
}

// Helper: Find module containing given address
PKLDR_DATA_TABLE_ENTRY FindModuleByAddress(PVOID pAddress) {
    PKLDR_DATA_TABLE_ENTRY pEntry = (PKLDR_DATA_TABLE_ENTRY)PsLoadedModuleList->Flink;
    while (pEntry != (PKLDR_DATA_TABLE_ENTRY)PsLoadedModuleList) {
        if ((ULONG_PTR)pAddress >= (ULONG_PTR)pEntry->DllBase &&
            (ULONG_PTR)pAddress < (ULONG_PTR)pEntry->DllBase + pEntry->SizeOfImage) {
            return pEntry;
        }
        pEntry = (PKLDR_DATA_TABLE_ENTRY)pEntry->InLoadOrderLinks.Flink;
    }
    return NULL;
}
```

**Benefit**: Reduces behavioral anomaly (some security products still functioning).

#### 3. Object Callback Patching Instead of Removal

**EDRSandBlast Approach**:
```c
// Completely removes object callback list
ProcessType->CallbackList = NULL;
```

**RealBlindingEDR Approach**:
```c
// Patches specific callback operations to return success without calling EDR
typedef struct _OB_CALLBACK_ENTRY {
    LIST_ENTRY CallbackList;
    POB_OPERATION Operations;
    POBJECT_TYPE ObjectType;
    POB_PRE_OPERATION_CALLBACK PreOperation;
    POB_POST_OPERATION_CALLBACK PostOperation;
} OB_CALLBACK_ENTRY;

// Find EDR callback entry
POB_CALLBACK_ENTRY pEdrEntry = FindEDRCallback(ProcessType);

// Replace with passthrough callback
pEdrEntry->PreOperation = &PassthroughPreOp;
pEdrEntry->PostOperation = &PassthroughPostOp;

// Passthrough returns success without EDR involvement
OB_PREOP_CALLBACK_STATUS PassthroughPreOp(PVOID Context, POB_PRE_OPERATION_INFORMATION Info) {
    return OB_PREOP_SUCCESS; // Allow operation, don't call EDR
}
```

**Benefit**: Callback registration remains intact, EDR driver appears loaded but non-functional.

#### 4. ETW Provider Masking (Not Complete Disablement)

**EDRSandBlast Approach**:
```c
// Completely disables ETW Threat Intelligence
EtwThreatIntProvRegHandle->IsEnabled = FALSE;
```

**RealBlindingEDR Approach**:
```c
// Selectively masks specific ETW event IDs
typedef struct _ETW_GUID_ENTRY {
    LIST_ENTRY ListEntry;
    ULONG EventIdCount;
    PVOID EventIdArray;
    GUID ProviderGuid;
    // ... more fields
} ETW_GUID_ENTRY;

// Find TI provider entry
PETW_GUID_ENTRY pTIProvider = FindETWProviderByGuid(&TI_PROVIDER_GUID);

// Create custom event filter (allow benign events, block malicious)
ULONG blockedEvents[] = {
    1, // Process creation
    2, // Thread creation
    10, // VirtualAlloc with RWX
    // ... add more
};

// Patch event enablement bitmap
for (ULONG i = 0; i < ARRAYSIZE(blockedEvents); i++) {
    ClearBit(pTIProvider->EnabledEventBitmap, blockedEvents[i]);
}
```

**Benefit**: ETW provider appears functional (some events still logged), reduces detection surface.

#### 5. Driver IOCTL Hiding

**EDRSandBlast Limitation**:
- Vulnerable driver IOCTL calls visible in kernel ETW traces
- EDRs can detect kernel memory R/W patterns

**RealBlindingEDR Enhancement**:
```c
// Before making IOCTL call, temporarily remove ETW kernel provider
DisableKernelETW();

// Make kernel memory R/W via driver IOCTL
DeviceIoControl(hDriver, IOCTL_KERNEL_WRITE, ...);

// Restore ETW kernel provider
EnableKernelETW();
```

**Benefit**: Kernel manipulation operations not logged in ETW.

#### 6. Memory Integrity Restoration

**EDRSandBlast Limitation**:
- Leaves modified kernel structures in altered state
- Periodic integrity checks can detect modifications

**RealBlindingEDR Enhancement**:
```c
// After disabling callbacks, register timer to periodically restore
KeSetTimer(&IntegrityTimer, 60000, &IntegrityDPC); // Every 60 seconds

VOID IntegrityDPC(PKDPC Dpc, PVOID Context) {
    // Temporarily restore original callback pointers
    RestoreCallbacks();

    // Wait 100ms (allow integrity check to pass)
    KeDelayExecutionThread(KernelMode, FALSE, &Delay100ms);

    // Re-disable callbacks
    DisableCallbacks();
}
```

**Benefit**: Evades periodic integrity validation by restoring state during checks.

### Detection Comparison

| Aspect | EDRSandBlast | RealBlindingEDR | Improvement |
|--------|--------------|-----------------|-------------|
| **Driver Load Detection** | 60-70% | 55-65% | Marginal (same BYOVD) |
| **Callback Modification Detection** | 50-60% | 30-40% | Significant |
| **Behavioral Anomaly Score** | High | Medium | Moderate |
| **PatchGuard Trigger Risk** | 20-30% | 10-15% | Moderate |
| **Integrity Check Evasion** | 10-20% | 50-60% | Significant |
| **Overall Detection Risk** | 60-70% | 55-65% | Marginal |

**Conclusion**: RealBlindingEDR improves specific detection vectors (callback manipulation, integrity checks) but overall detection risk remains high due to fundamental BYOVD requirement.

### When to Use RealBlindingEDR vs EDRSandBlast

**Choose RealBlindingEDR when**:
- Target environment has periodic kernel integrity validation
- Specific EDR targeting required (avoid disabling all security products)
- ETW kernel logging actively monitored
- Longer persistence window needed (integrity restoration)

**Choose EDRSandBlast when**:
- Simple, fast bypass needed (speed over sophistication)
- Target environment lacks advanced kernel monitoring
- One-time operation (no persistence required)
- Simplicity preferred over complexity

**Choose Userland Techniques (Phase 1-3) when**:
- Stealth is priority (2-5% detection vs 55-70%)
- Admin access not guaranteed
- Long-term persistence required
- Initial access operations

### Implementation Complexity

**EDRSandBlast**: Medium (well-documented, many PoCs)
**RealBlindingEDR**: High (requires kernel internals expertise, less documented)

**Additional Requirements for RealBlindingEDR**:
- Callback structure reverse engineering
- ETW provider internals knowledge
- Kernel timer/DPC programming
- Driver fingerprinting logic

### OPSEC Considerations

**Advantages over EDRSandBlast**:
- Lower behavioral anomaly score (selective disablement)
- Periodic integrity check evasion
- ETW kernel logging evasion

**Disadvantages**:
- Higher complexity = more failure points
- Still requires vulnerable driver (primary detection vector)
- Marginal improvement (55-65% vs 60-70%) may not justify complexity
- Less mature, fewer battle-tested implementations

### Integration with Noctis-MCP

**Recommendation**: Document only (same as EDRSandBlast)

**Rationale**:
- Marginal 5-10% improvement over EDRSandBlast not sufficient to justify implementation
- Still contradicts stealth philosophy (55-65% detection vs 2-5% for Phase 3)
- Increased complexity without proportional benefit
- Userland techniques remain superior for stealth operations

**Use Case**: Reference for blue team (understand advanced kernel bypass techniques) and red team (post-compromise when detection already occurred).

---

## Alternative: Userland Techniques First

Before resorting to kernel bypass, exhaust userland options:

| Phase | Techniques | Detection Risk | Admin Required? |
|-------|-----------|----------------|-----------------|
| **Phase 1** | SysWhispers3, Zilean, PoolParty, VEH² | 8-12% | ❌ No |
| **Phase 2** | Phantom DLL, Perun's Fart, Early Cascade, ShellcodeFluctuation | 5-8% | ❌ No |
| **Phase 3** | SilentMoonwalk | 2-5% | ❌ No |
| **Kernel Bypass** | EDRSandBlast | **60-70%** → 0% | ✅ **Yes** |

**Recommendation**: Only use kernel bypass when:
- Detection is acceptable (post-compromise)
- Admin access already obtained
- Userland techniques have failed or are insufficient
- Operational requirements prioritize success over stealth

---

## Implementation Complexity

**Very High** - Requires:
1. **Kernel Driver Expertise**: Understanding Windows driver model
2. **Kernel Debugging**: Identifying EDR callback locations in kernel memory
3. **Exploitation Primitives**: Read/write kernel memory via vulnerable driver
4. **Anti-PatchGuard**: Evading or accepting PatchGuard crashes
5. **Driver Research**: Finding new vulnerable drivers as old ones blocked

**Estimated Implementation Time**: 4-6 weeks (experienced developer)

---

## Real-World Examples

### Malware Using Kernel Bypass

- **BlackLotus Bootkit**: Disables EDR via kernel driver exploitation
- **Ransomware Groups**: REvil, Conti variants use BYOVD for EDR bypass
- **APT Groups**: Lazarus, APT41 documented using vulnerable driver techniques
- **Red Team Tools**: CobaltStrike Aggressor scripts, Metasploit modules

### Research Projects

- **EDRSandblast** (Wavestone): Reference implementation
- **PPLKiller**: Removes Protected Process Light (PPL) from LSASS
- **Evil Driver**: Generic vulnerable driver exploitation framework
- **BYOVD-Template**: Template for weaponizing vulnerable drivers

---

## Integration with Noctis-MCP

### Current Approach: **Documentation Only**

**Why not implement?**
1. Detection risk (60-70%) contradicts Noctis-MCP stealth philosophy
2. Userland techniques (Phase 1-3) achieve 92-95% EDR bypass without admin
3. Driver blocklist maintenance burden too high
4. Legal/ethical concerns with kernel exploitation

**What we provide instead**:
- ✅ Comprehensive documentation of technique
- ✅ References to open-source implementations
- ✅ OPSEC guidance on when/when not to use
- ✅ Intelligence tracking of vulnerable drivers
- ✅ Detection vector analysis

### If Implementation Needed (Future)

**Potential Module**: `techniques/kernel_bypass/edr_sandblast.c` (optional, separate branch)

**Integration Points**:
- Create driver loader using `NtLoadDriver`
- Implement kernel memory R/W wrappers using driver IOCTL
- Add callback removal functions for each callback type
- Implement PatchGuard evasion or crash recovery
- Add driver blocklist checker
- Mark module as "POST-COMPROMISE ONLY"

---

## Learning Resources

### Technical Documentation

- **Wavestone EDRSandblast**: https://github.com/wavestone-cdt/EDRSandblast
- **Microsoft Driver Blocklist**: https://aka.ms/VulnerableDriverBlockList
- **Windows Kernel Callbacks**: https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/callback-objects

### Research Papers

- "Exploiting the SYSTEM: Windows Kernel Security" (BlackHat)
- "BYOVD: Bring Your Own Vulnerable Driver" (DEF CON)
- "Bypassing Kernel-Mode EDRs" (Elastic Security Labs)

### Vulnerability Databases

- **LOLDrivers**: https://www.loldrivers.io/ (vulnerable driver tracking)
- **CVE Database**: Search for "Windows driver privilege escalation"

---

## Version-Specific Notes

- **Windows 10 1809+**: PatchGuard enhancements detect most modifications
- **Windows 11 21H2+**: HVCI (Hypervisor-Protected Code Integrity) blocks unsigned drivers by default
- **Windows 11 22H2+**: Enhanced driver blocklist, frequent updates
- **Windows Server 2019/2022**: Similar protections, but HVCI often disabled

---

## Metadata

- **MITRE ATT&CK**: T1014 (Rootkit), T1543.003 (Create or Modify System Process: Windows Service)
- **Complexity**: Very High
- **Stability**: Low-Medium (PatchGuard crashes common)
- **OPSEC Score**: 2/10 (loud technique)
- **Stealth Score**: 0/10 (detection inevitable)
- **Success Score**: 10/10 (complete EDR bypass if successful)

---

## Summary

**EDRSandBlast and kernel bypass techniques are the "nuclear option"** for EDR evasion. While extremely effective (complete EDR blindness), they come with severe trade-offs:

- ✅ **When detection is acceptable**: Post-compromise, ransomware, loud ops
- ❌ **When stealth is required**: Initial access, APT simulation, covert persistence

**For Noctis-MCP**: Documented for completeness, but **userland Phase 1-3 techniques achieve 92-95% EDR bypass without the risks** of kernel exploitation.

**Operational Guideline**: Exhaust userland options first. Only escalate to kernel bypass when:
1. Admin access already obtained
2. Detection acceptable or inevitable
3. Userland techniques insufficient
4. Operational success prioritized over stealth
