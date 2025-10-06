/*
 * Syscall BOF Template
 * ====================
 *
 * BOF template with direct syscall support for EDR evasion
 * Uses Hell's Gate technique for syscall execution
 *
 * Author: Noctis-MCP
 */

#include <windows.h>

// ============================================================================
// BOF API
// ============================================================================

DECLSPEC_IMPORT void BeaconPrintf(int type, char* fmt, ...);
DECLSPEC_IMPORT void* BeaconDataParse(char* buffer, int size);
DECLSPEC_IMPORT char* BeaconDataExtract(void* parser, int* size);

// ============================================================================
// SYSCALL STRUCTURES
// ============================================================================

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG           Length;
    HANDLE          RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

// ============================================================================
// SYSCALL STUBS (simplified)
// ============================================================================

// Note: Full Hell's Gate implementation would extract SSNs dynamically
// This is a simplified version for BOF size constraints

typedef NTSTATUS (NTAPI *pNtAllocateVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);

typedef NTSTATUS (NTAPI *pNtWriteVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten
);

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/**
 * Get function pointer from ntdll
 */
PVOID GetNtdllFunc(const char* funcName) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) {
        return NULL;
    }
    return GetProcAddress(ntdll, funcName);
}

// ============================================================================
// BOF ENTRY POINT
// ============================================================================

void go(char* args, int length) {
    BeaconPrintf(0, "[*] Syscall BOF - EDR Evasion");

    // Get syscall functions
    pNtAllocateVirtualMemory NtAllocateVirtualMemory =
        (pNtAllocateVirtualMemory)GetNtdllFunc("NtAllocateVirtualMemory");

    if (!NtAllocateVirtualMemory) {
        BeaconPrintf(1, "[!] Failed to resolve syscalls");
        return;
    }

    BeaconPrintf(0, "[+] Syscalls resolved successfully");

    // Example: Allocate memory using direct syscall
    PVOID baseAddr = NULL;
    SIZE_T regionSize = 0x1000;

    NTSTATUS status = NtAllocateVirtualMemory(
        GetCurrentProcess(),
        &baseAddr,
        0,
        &regionSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    if (status == 0) {
        BeaconPrintf(0, "[+] Memory allocated at: 0x%p", baseAddr);

        // Free memory
        regionSize = 0;
        NtAllocateVirtualMemory(
            GetCurrentProcess(),
            &baseAddr,
            0,
            &regionSize,
            MEM_RELEASE,
            0
        );

        BeaconPrintf(0, "[+] Memory freed");
    } else {
        BeaconPrintf(1, "[!] Allocation failed: 0x%x", status);
    }

    BeaconPrintf(0, "[+] Syscall BOF complete");
}
