// Reference code for Noctis-MCP AI intelligence system
// SilentMoonwalk Implementation

#include "silentmoonwalk.h"
#include <stdio.h>
#include <time.h>

// ROP gadget byte patterns (x64)
static BYTE PATTERN_POP_RBP_RET[] = {0x5D, 0xC3};                    // pop rbp; ret
static BYTE PATTERN_POP_RCX_RET[] = {0x59, 0xC3};                    // pop rcx; ret
static BYTE PATTERN_ADD_RSP_20_RET[] = {0x48, 0x83, 0xC4, 0x20, 0xC3}; // add rsp, 0x20; ret
static BYTE PATTERN_ADD_RSP_28_RET[] = {0x48, 0x83, 0xC4, 0x28, 0xC3}; // add rsp, 0x28; ret

// Initialize SilentMoonwalk spoofing engine
BOOL SilentMoonwalk_Initialize(
    PSPOOF_CONTEXT pContext,
    SPOOF_MODE mode
) {
    if (!pContext) return FALSE;

    ZeroMemory(pContext, sizeof(SPOOF_CONTEXT));
    pContext->mode = mode;

    // Scan ntdll.dll for ROP gadgets
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) return FALSE;

    if (!_SilentMoonwalk_ScanGadgets(hNtdll, &pContext->gadgets)) {
        // Fallback: scan kernel32.dll
        HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
        if (!hKernel32 || !_SilentMoonwalk_ScanGadgets(hKernel32, &pContext->gadgets)) {
            return FALSE;
        }
    }

    pContext->gadgets.bInitialized = TRUE;

    // Initialize random seed for synthetic frame generation
    srand((unsigned int)time(NULL));

    return TRUE;
}

// Internal: Scan module for ROP gadgets
BOOL _SilentMoonwalk_ScanGadgets(
    HMODULE hModule,
    PGADGET_CACHE pCache
) {
    if (!hModule || !pCache) return FALSE;

    // Get module base and size
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;

    // Validate e_lfanew to prevent access violation
    SIZE_T moduleSize = 0;
    {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery(hModule, &mbi, sizeof(mbi)) == 0) return FALSE;
        moduleSize = mbi.RegionSize;
    }

    if (pDosHeader->e_lfanew > moduleSize - sizeof(IMAGE_NT_HEADERS)) {
        return FALSE; // e_lfanew points outside module
    }

    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + pDosHeader->e_lfanew);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) return FALSE;

    SIZE_T szModuleSize = pNtHeaders->OptionalHeader.SizeOfImage;

    // Find .text section
    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNtHeaders);
    PVOID pTextBase = NULL;
    SIZE_T szTextSize = 0;

    for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
        PIMAGE_SECTION_HEADER pCurrentSection = &pSection[i];

        // Check for .text section (compare full 8 bytes to handle padding correctly)
        if (memcmp(pCurrentSection->Name, ".text\0\0\0", 8) == 0) {
            // Validate section is within module bounds
            if (pCurrentSection->VirtualAddress + pCurrentSection->Misc.VirtualSize > szModuleSize) {
                continue; // Skip invalid section
            }

            pTextBase = (BYTE*)hModule + pCurrentSection->VirtualAddress;
            szTextSize = pCurrentSection->Misc.VirtualSize;
            break;
        }
    }

    if (!pTextBase) return FALSE;

    // Scan for gadgets in .text section
    pCache->popRbpRet.pAddress = _SilentMoonwalk_FindGadget(
        pTextBase, szTextSize, PATTERN_POP_RBP_RET, sizeof(PATTERN_POP_RBP_RET)
    );
    pCache->popRbpRet.type = GADGET_POP_RBP_RET;

    pCache->popRcxRet.pAddress = _SilentMoonwalk_FindGadget(
        pTextBase, szTextSize, PATTERN_POP_RCX_RET, sizeof(PATTERN_POP_RCX_RET)
    );
    pCache->popRcxRet.type = GADGET_POP_RCX_RET;

    pCache->addRsp20Ret.pAddress = _SilentMoonwalk_FindGadget(
        pTextBase, szTextSize, PATTERN_ADD_RSP_20_RET, sizeof(PATTERN_ADD_RSP_20_RET)
    );
    pCache->addRsp20Ret.type = GADGET_ADD_RSP_RET;
    pCache->addRsp20Ret.offset = 0x20;

    pCache->addRsp28Ret.pAddress = _SilentMoonwalk_FindGadget(
        pTextBase, szTextSize, PATTERN_ADD_RSP_28_RET, sizeof(PATTERN_ADD_RSP_28_RET)
    );
    pCache->addRsp28Ret.type = GADGET_ADD_RSP_RET;
    pCache->addRsp28Ret.offset = 0x28;

    // Verify essential gadgets found
    return (pCache->popRbpRet.pAddress != NULL &&
            pCache->addRsp20Ret.pAddress != NULL);
}

// Internal: Find specific gadget pattern
PVOID _SilentMoonwalk_FindGadget(
    PVOID pModuleBase,
    SIZE_T szModuleSize,
    BYTE* pattern,
    SIZE_T patternSize
) {
    if (!pModuleBase || !pattern || patternSize == 0) return NULL;

    // Guard against integer underflow
    if (szModuleSize < patternSize) return NULL;

    BYTE* pScanBase = (BYTE*)pModuleBase;

    // Fix off-by-one: i <= szModuleSize - patternSize (not <)
    for (SIZE_T i = 0; i <= szModuleSize - patternSize; i++) {
        if (memcmp(pScanBase + i, pattern, patternSize) == 0) {
            return (PVOID)(pScanBase + i);
        }
    }

    return NULL;
}

// Build synthetic call stack frames
BOOL SilentMoonwalk_BuildSyntheticStack(
    PSPOOF_CONTEXT pContext,
    DWORD dwFrameCount
) {
    if (!pContext || dwFrameCount == 0) return FALSE;

    // Validate frame count against mode-specific limits
    DWORD maxFrames = (pContext->mode == SPOOF_MODE_SYNTHETIC) ? 8 : 4;
    if (dwFrameCount > maxFrames) return FALSE;

    // Verify gadgets were successfully initialized
    if (!pContext->gadgets.bInitialized ||
        !pContext->gadgets.popRbpRet.pAddress ||
        !pContext->gadgets.addRsp20Ret.pAddress) {
        return FALSE;
    }

    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");

    if (!hNtdll || !hKernel32) return FALSE;

    // Create synthetic frames pointing to legitimate modules
    for (DWORD i = 0; i < dwFrameCount; i++) {
        // Alternate between ntdll and kernel32 for realistic call stack
        HMODULE hModule = (i % 2 == 0) ? hNtdll : hKernel32;

        if (!_SilentMoonwalk_CreateFrame(&pContext->frames[i], hModule)) {
            return FALSE;
        }
    }

    pContext->dwFrameCount = dwFrameCount;
    return TRUE;
}

// Internal: Create synthetic frame pointing to legitimate code
BOOL _SilentMoonwalk_CreateFrame(
    PSYNTHETIC_FRAME pFrame,
    HMODULE hModule
) {
    if (!pFrame || !hModule) return FALSE;

    // Get random legitimate return address from module
    pFrame->returnAddress = SilentMoonwalk_GetLegitimateReturnAddress(hModule);
    if (!pFrame->returnAddress) return FALSE;

    // Set rbp to point within module (simulate frame pointer)
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + pDosHeader->e_lfanew);
    SIZE_T szModuleSize = pNtHeaders->OptionalHeader.SizeOfImage;

    // Random offset within module for rbp (simulate local variable area)
    pFrame->rbpValue = (BYTE*)hModule + (rand() % (szModuleSize / 2));

    return TRUE;
}

// Utility: Get random legitimate return address from module
PVOID SilentMoonwalk_GetLegitimateReturnAddress(HMODULE hModule) {
    if (!hModule) return NULL;

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) return NULL;

    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + pDosHeader->e_lfanew);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) return NULL;

    // Find .text section
    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNtHeaders);
    for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
        PIMAGE_SECTION_HEADER pCurrentSection = &pSection[i];

        if (memcmp(pCurrentSection->Name, ".text\0\0\0", 8) == 0) {
            // Validate section is within module bounds
            SIZE_T szModuleSize = pNtHeaders->OptionalHeader.SizeOfImage;
            if (pCurrentSection->VirtualAddress + pCurrentSection->Misc.VirtualSize > szModuleSize) {
                continue;
            }

            PVOID pTextBase = (BYTE*)hModule + pCurrentSection->VirtualAddress;
            SIZE_T szTextSize = pCurrentSection->Misc.VirtualSize;

            // Ensure .text section is large enough for safe random selection
            if (szTextSize < 256) return NULL;

            // Return random address within .text (must be valid instruction)
            // For reference implementation, use offset that's likely a valid instruction
            SIZE_T offset = (rand() % (szTextSize / 16)) * 16; // Align to 16 bytes

            // Paranoid bounds check
            if (offset >= szTextSize) return NULL;

            return (BYTE*)pTextBase + offset;
        }
    }

    return NULL;
}

// Execute function with spoofed call stack (up to 4 arguments)
PVOID SilentMoonwalk_CallWithSpoofedStack(
    PSPOOF_CONTEXT pContext,
    PVOID pFunction,
    PVOID arg1,
    PVOID arg2,
    PVOID arg3,
    PVOID arg4
) {
    if (!pContext || !pFunction) return NULL;
    if (!pContext->gadgets.bInitialized) return NULL;

    PVOID args[4] = {arg1, arg2, arg3, arg4};
    return _SilentMoonwalk_ExecuteSpoofedCall(pContext, pFunction, args, 4);
}

// Execute function with spoofed stack (8 arguments - SYNTHETIC mode only)
PVOID SilentMoonwalk_CallWithSpoofedStack8(
    PSPOOF_CONTEXT pContext,
    PVOID pFunction,
    PVOID arg1, PVOID arg2, PVOID arg3, PVOID arg4,
    PVOID arg5, PVOID arg6, PVOID arg7, PVOID arg8
) {
    if (!pContext || !pFunction) return NULL;
    if (pContext->mode != SPOOF_MODE_SYNTHETIC) return NULL;
    if (!pContext->gadgets.bInitialized) return NULL;

    PVOID args[8] = {arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8};
    return _SilentMoonwalk_ExecuteSpoofedCall(pContext, pFunction, args, 8);
}

// Internal: Execute spoofed call (simplified reference implementation)
// NOTE: Production implementation requires assembly trampoline with ROP chain
PVOID _SilentMoonwalk_ExecuteSpoofedCall(
    PSPOOF_CONTEXT pContext,
    PVOID pFunction,
    PVOID* args,
    DWORD dwArgCount
) {
    if (!pContext || !pFunction || !args) return NULL;

    // WARNING: This is a REFERENCE implementation showing the concept
    // A real implementation requires inline assembly or external .asm file
    // to manipulate stack frames and execute ROP gadgets properly

    // The actual implementation would:
    // 1. Save original RSP/RBP
    // 2. Build synthetic stack frames using ROP gadgets
    // 3. Set RSP to point to synthetic stack
    // 4. Call target function with x64 calling convention (RCX, RDX, R8, R9, stack)
    // 5. Use ROP gadget to restore original stack on return
    // 6. Return function result

    // For reference purposes, here's the conceptual flow:
    /*
    Assembly pseudocode:

    ; Save original state
    mov [pContext->pOriginalRsp], rsp
    mov [pContext->pOriginalRbp], rbp

    ; Build synthetic stack
    ; Frame 3 (deepest)
    push [pContext->frames[2].returnAddress]
    mov rbp, [pContext->frames[2].rbpValue]

    ; Frame 2
    push [pContext->frames[1].returnAddress]
    mov rbp, [pContext->frames[1].rbpValue]

    ; Frame 1 (closest to target)
    push [pContext->frames[0].returnAddress]
    mov rbp, [pContext->frames[0].rbpValue]

    ; Push ROP gadget address (for stack restoration on return)
    push [pContext->gadgets.addRsp28Ret.pAddress]

    ; Setup arguments (x64 fastcall convention)
    mov rcx, [args[0]]  ; arg1
    mov rdx, [args[1]]  ; arg2
    mov r8,  [args[2]]  ; arg3
    mov r9,  [args[3]]  ; arg4

    ; Stack args for args 5-8 (if SYNTHETIC mode)
    if (dwArgCount > 4) {
        push [args[7]]
        push [args[6]]
        push [args[5]]
        push [args[4]]
    }

    ; Call target function
    call pFunction

    ; ROP gadget executes here (add rsp, 0x28; ret)
    ; This skips over synthetic frames and returns to real caller

    ; Restore original RBP
    mov rbp, [pContext->pOriginalRbp]

    ; Return value is in RAX
    ret
    */

    // Since inline assembly is not portable in C, production code would use:
    // 1. External .asm file with the above assembly
    // 2. Function pointer casting and careful stack manipulation
    // 3. Compiler-specific intrinsics (__asm blocks in MSVC)

    // For this reference implementation, we mark it as unimplemented
    // The technique is documented for educational purposes

    return NULL; // Placeholder - requires assembly implementation
}

// Cleanup spoofing context
VOID SilentMoonwalk_Cleanup(PSPOOF_CONTEXT pContext) {
    if (!pContext) return;

    // Clear sensitive data
    SecureZeroMemory(&pContext->gadgets, sizeof(GADGET_CACHE));
    SecureZeroMemory(pContext->frames, sizeof(pContext->frames));

    ZeroMemory(pContext, sizeof(SPOOF_CONTEXT));
}

// Utility: Validate call stack is spoofed (debug/testing)
BOOL SilentMoonwalk_ValidateSpoofedStack(PVOID pExpectedModule) {
    // This would walk the current call stack using RtlCaptureStackBackTrace
    // or similar and verify frames point to expected module

    // Reference implementation placeholder
    return TRUE;
}
