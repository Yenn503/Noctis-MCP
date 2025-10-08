#include <Windows.h>

#include "Structures.h"
#include "TrapSyscallsTampering.h"
#include "Utilities.h"
#include "DebugMacros.h"

#ifdef TRAP_SYSCALLS_TAMPERING



// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
//
// Global Variables

__declspec(thread) static WORD t_wSyscallNumber     = 0x00;
static PVOID g_pVectoredHandle                      = NULL;

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

static LONG WINAPI TrapSyscallsExceptionHandler(IN PEXCEPTION_POINTERS pExceptionInfo)
{
    if (pExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP)
    {
        if (*(WORD*)pExceptionInfo->ExceptionRecord->ExceptionAddress != (g_wSyscallOpcode ^ 0x1234))
        {
            pExceptionInfo->ContextRecord->EFlags |= EFLAGS_TF;
        }
        else
        {
            if (!t_wSyscallNumber)
            {
				// DBG_PRINT_A("[v] Caught Syscall: 0x%p [SSN:%d]", pExceptionInfo->ExceptionRecord->ExceptionAddress, (WORD)pExceptionInfo->ContextRecord->Rax);
                t_wSyscallNumber = (WORD)pExceptionInfo->ContextRecord->Rax;
                pExceptionInfo->ContextRecord->EFlags |= EFLAGS_TF;
            }
            else
            {
				// DBG_PRINT_A("[v] Restoring Original Syscall Number: 0x%p [SSN:%d] (Was:%d)", pExceptionInfo->ExceptionRecord->ExceptionAddress, t_wSyscallNumber, pExceptionInfo->ContextRecord->Rax);
                pExceptionInfo->ContextRecord->Rax = t_wSyscallNumber;
                pExceptionInfo->ContextRecord->EFlags &= ~EFLAGS_TF;
                t_wSyscallNumber = 0x00;
            }
        }
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

BOOL InitializeTrapSyscallsVectoredHandler()
{
    if (g_pVectoredHandle)
        return TRUE;

    if (!(g_pVectoredHandle = AddVectoredExceptionHandler(0x00, TrapSyscallsExceptionHandler)))
    {
        DBG_PRINT_A("[!] AddVectoredExceptionHandler Failed With Error: %lu", GetLastError());
        return FALSE;
    }

    return TRUE;
}


BOOL DestroyTrapSyscallsVectoredHandler()
{
    if (!g_pVectoredHandle)
        return FALSE;

    if (!RemoveVectoredExceptionHandler(g_pVectoredHandle))
    {
        DBG_PRINT_A("[!] RemoveVectoredExceptionHandler Failed With Error: %lu", GetLastError());
        return FALSE;
    }

    g_pVectoredHandle = NULL;
    return TRUE;
}


// ==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

#endif // TRAP_SYSCALLS_TAMPERING
