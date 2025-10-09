// Reference code for Noctis-MCP AI intelligence system
// SysWhispers3 - Randomized Syscall Jumper Implementation
// Source: https://github.com/gmh5225/syscall-SysWhispers3
// Research: Argus Red Team Intelligence Report 2024-2025

#ifndef SYSWHISPERS3_H
#define SYSWHISPERS3_H

#include <Windows.h>

// Maximum number of syscall instruction addresses to cache
#define MAX_SYSCALL_CACHE 16

// Syscall stub structure
typedef struct _SYSCALL_STUB {
    DWORD dwSSN;                    // System Service Number
    PVOID pSyscallAddr;             // Address of syscall instruction
    BOOL bCached;                   // Whether this entry is valid
} SYSCALL_STUB, *PSYSCALL_STUB;

// Syscall cache for randomization
typedef struct _SYSCALL_CACHE {
    SYSCALL_STUB stubs[MAX_SYSCALL_CACHE];
    DWORD dwCacheSize;
    HMODULE hNtdll;
} SYSCALL_CACHE, *PSYSCALL_CACHE;

// Initialize SysWhispers3 system
BOOL SW3_Initialize(PSYSCALL_CACHE pCache);

// Resolve SSN and populate cache with random syscall addresses
BOOL SW3_ResolveFunction(
    PSYSCALL_CACHE pCache,
    LPCSTR pszFunctionName,
    DWORD* pdwSSN
);

// Get randomized syscall address from cache
PVOID SW3_GetRandomSyscallAddr(PSYSCALL_CACHE pCache);

// Execute syscall with randomized jump
NTSTATUS SW3_ExecuteSyscall(
    PSYSCALL_CACHE pCache,
    DWORD dwSSN,
    PVOID pArgs
);

// Cleanup cache
VOID SW3_Cleanup(PSYSCALL_CACHE pCache);

// Common NT API wrappers using SysWhispers3
NTSTATUS SW3_NtAllocateVirtualMemory(
    PSYSCALL_CACHE pCache,
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);

NTSTATUS SW3_NtProtectVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T NumberOfBytesToProtect,
    ULONG NewAccessProtection,
    PULONG OldAccessProtection
);

NTSTATUS SW3_NtCreateThreadEx(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID StartRoutine,
    PVOID Argument,
    ULONG CreateFlags,
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PVOID AttributeList
);

NTSTATUS SW3_NtWaitForSingleObject(
    HANDLE Handle,
    BOOLEAN Alertable,
    PLARGE_INTEGER Timeout
);

#endif // SYSWHISPERS3_H
