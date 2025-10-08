// Payload Encryption Module Implementation
// Provides standalone encryption functions for AI-generated code

#include "payload_crypto.h"
#include <stdio.h>

// RC4 Internal: Key Scheduling Algorithm
static VOID RC4_KSA(BYTE* pS, BYTE* pKey, SIZE_T szKeyLen) {
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

// RC4 Internal: Pseudo-Random Generation Algorithm
static VOID RC4_PRGA(BYTE* pS, BYTE* pData, SIZE_T szDataLen) {
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

// RC4 Encryption/Decryption (symmetric)
VOID Crypto_RC4(BYTE* pData, SIZE_T szDataLen, BYTE* pKey, SIZE_T szKeyLen) {
    if (!pData || !pKey || szDataLen == 0 || szKeyLen == 0) return;

    BYTE S[256];
    RC4_KSA(S, pKey, szKeyLen);
    RC4_PRGA(S, pData, szDataLen);
    SecureZeroMemory(S, sizeof(S));
}

// AES-256 Encryption (CBC mode)
BOOL Crypto_AES256_Encrypt(BYTE* pData, SIZE_T szDataLen, BYTE* pKey, BYTE* pIV) {
    if (!pData || !pKey || !pIV || szDataLen == 0) return FALSE;

    // Validate data length is multiple of 16 (AES block size)
    if (szDataLen % 16 != 0) {
        fprintf(stderr, "[-] AES data length must be multiple of 16 bytes\n");
        return FALSE;
    }

    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status;
    BOOL bResult = FALSE;

    // Open AES algorithm provider
    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) {
        fprintf(stderr, "[-] BCryptOpenAlgorithmProvider failed: 0x%x\n", status);
        goto cleanup;
    }

    // Set chaining mode to CBC
    status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
        (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (!BCRYPT_SUCCESS(status)) {
        fprintf(stderr, "[-] BCryptSetProperty failed: 0x%x\n", status);
        goto cleanup;
    }

    // Generate key object (256-bit key expected)
    status = BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, pKey, 32, 0);
    if (!BCRYPT_SUCCESS(status)) {
        fprintf(stderr, "[-] BCryptGenerateSymmetricKey failed: 0x%x\n", status);
        goto cleanup;
    }

    // CRITICAL: BCrypt modifies IV in-place during CBC mode
    // Must copy IV to preserve original for decryption
    BYTE ivCopy[16];
    memcpy(ivCopy, pIV, 16);

    // Encrypt in-place
    ULONG cbResult;
    status = BCryptEncrypt(hKey, pData, (ULONG)szDataLen, NULL,
        ivCopy, 16, pData, (ULONG)szDataLen, &cbResult, 0);
    if (!BCRYPT_SUCCESS(status)) {
        fprintf(stderr, "[-] BCryptEncrypt failed: 0x%x\n", status);
        goto cleanup;
    }

    bResult = TRUE;

cleanup:
    if (hKey) BCryptDestroyKey(hKey);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    return bResult;
}

// AES-256 Decryption (CBC mode)
BOOL Crypto_AES256_Decrypt(BYTE* pData, SIZE_T szDataLen, BYTE* pKey, BYTE* pIV) {
    if (!pData || !pKey || !pIV || szDataLen == 0) return FALSE;

    // Validate data length is multiple of 16 (AES block size)
    if (szDataLen % 16 != 0) {
        fprintf(stderr, "[-] AES data length must be multiple of 16 bytes\n");
        return FALSE;
    }

    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status;
    BOOL bResult = FALSE;

    // Open AES algorithm provider
    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) {
        fprintf(stderr, "[-] BCryptOpenAlgorithmProvider failed: 0x%x\n", status);
        goto cleanup;
    }

    // Set chaining mode to CBC
    status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
        (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (!BCRYPT_SUCCESS(status)) {
        fprintf(stderr, "[-] BCryptSetProperty failed: 0x%x\n", status);
        goto cleanup;
    }

    // Generate key object
    status = BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, pKey, 32, 0);
    if (!BCRYPT_SUCCESS(status)) {
        fprintf(stderr, "[-] BCryptGenerateSymmetricKey failed: 0x%x\n", status);
        goto cleanup;
    }

    // CRITICAL: BCrypt modifies IV in-place
    // Must copy IV to preserve original
    BYTE ivCopy[16];
    memcpy(ivCopy, pIV, 16);

    // Decrypt in-place
    ULONG cbResult;
    status = BCryptDecrypt(hKey, pData, (ULONG)szDataLen, NULL,
        ivCopy, 16, pData, (ULONG)szDataLen, &cbResult, 0);
    if (!BCRYPT_SUCCESS(status)) {
        fprintf(stderr, "[-] BCryptDecrypt failed: 0x%x\n", status);
        goto cleanup;
    }

    bResult = TRUE;

cleanup:
    if (hKey) BCryptDestroyKey(hKey);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    return bResult;
}

// XOR Cipher (simple obfuscation)
VOID Crypto_XOR(BYTE* pData, SIZE_T szDataLen, BYTE* pKey, SIZE_T szKeyLen) {
    if (!pData || !pKey || szDataLen == 0 || szKeyLen == 0) return;

    for (SIZE_T i = 0; i < szDataLen; i++) {
        pData[i] ^= pKey[i % szKeyLen];
    }
}

// Generate random encryption key
BOOL Crypto_GenerateKey(BYTE* pKey, SIZE_T szKeyLen) {
    if (!pKey || szKeyLen == 0) return FALSE;

    BCRYPT_ALG_HANDLE hAlgRng = NULL;
    NTSTATUS status;

    status = BCryptOpenAlgorithmProvider(&hAlgRng, BCRYPT_RNG_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) {
        fprintf(stderr, "[-] BCryptOpenAlgorithmProvider (RNG) failed: 0x%x\n", status);
        return FALSE;
    }

    status = BCryptGenRandom(hAlgRng, pKey, (ULONG)szKeyLen, 0);

    BCryptCloseAlgorithmProvider(hAlgRng, 0);

    return BCRYPT_SUCCESS(status);
}

// Generate random IV for AES
BOOL Crypto_GenerateIV(BYTE* pIV, SIZE_T szIVLen) {
    // IV generation is same as key generation
    return Crypto_GenerateKey(pIV, szIVLen);
}

// Key derivation from password (PBKDF2)
BOOL Crypto_DeriveKeyFromPassword(
    LPCSTR pszPassword,
    SIZE_T szPasswordLen,
    BYTE* pSalt,
    SIZE_T szSaltLen,
    DWORD dwIterations,
    BYTE* pDerivedKey,
    SIZE_T szDerivedKeyLen
) {
    if (!pszPassword || !pSalt || !pDerivedKey) return FALSE;
    if (szPasswordLen == 0 || szSaltLen == 0 || szDerivedKeyLen == 0) return FALSE;

    BCRYPT_ALG_HANDLE hAlg = NULL;
    NTSTATUS status;
    BOOL bResult = FALSE;

    // Open PBKDF2 algorithm
    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_PBKDF2_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) {
        fprintf(stderr, "[-] BCryptOpenAlgorithmProvider (PBKDF2) failed: 0x%x\n", status);
        return FALSE;
    }

    // Derive key
    status = BCryptDeriveKeyPBKDF2(
        hAlg,
        (PUCHAR)pszPassword,
        (ULONG)szPasswordLen,
        pSalt,
        (ULONG)szSaltLen,
        dwIterations,
        pDerivedKey,
        (ULONG)szDerivedKeyLen,
        0
    );

    if (!BCRYPT_SUCCESS(status)) {
        fprintf(stderr, "[-] BCryptDeriveKeyPBKDF2 failed: 0x%x\n", status);
        goto cleanup;
    }

    bResult = TRUE;

cleanup:
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return bResult;
}

// Example usage and testing
#ifdef CRYPTO_TEST_MAIN
int main() {
    printf("=== Payload Crypto Test ===\n\n");

    // Test 1: XOR encryption
    printf("[*] Test 1: XOR Encryption\n");
    BYTE xorData[] = "Hello, World! This is a secret message.";
    BYTE xorKey[] = "SecretKey";
    SIZE_T xorDataLen = sizeof(xorData) - 1;  // Exclude null terminator

    printf("    Original: %s\n", xorData);
    Crypto_XOR(xorData, xorDataLen, xorKey, sizeof(xorKey) - 1);
    printf("    Encrypted: ");
    for (SIZE_T i = 0; i < xorDataLen; i++) printf("%02X ", xorData[i]);
    printf("\n");

    Crypto_XOR(xorData, xorDataLen, xorKey, sizeof(xorKey) - 1);
    printf("    Decrypted: %s\n\n", xorData);

    // Test 2: RC4 encryption
    printf("[*] Test 2: RC4 Encryption\n");
    BYTE rc4Data[] = "Sensitive payload data for malware";
    BYTE rc4Key[] = "MyRC4Key12345";
    SIZE_T rc4DataLen = sizeof(rc4Data) - 1;

    printf("    Original: %s\n", rc4Data);
    Crypto_RC4(rc4Data, rc4DataLen, rc4Key, sizeof(rc4Key) - 1);
    printf("    Encrypted: ");
    for (SIZE_T i = 0; i < rc4DataLen; i++) printf("%02X ", rc4Data[i]);
    printf("\n");

    Crypto_RC4(rc4Data, rc4DataLen, rc4Key, sizeof(rc4Key) - 1);
    printf("    Decrypted: %s\n\n", rc4Data);

    // Test 3: AES-256 encryption
    printf("[*] Test 3: AES-256 Encryption\n");
    BYTE aesData[64] = "This is highly sensitive shellcode data, 64 bytes total.";  // Must be 16-byte aligned
    BYTE aesKey[32];
    BYTE aesIV[16];

    // Generate random key and IV
    if (!Crypto_GenerateKey(aesKey, 32)) {
        printf("[-] Failed to generate AES key\n");
        return 1;
    }
    if (!Crypto_GenerateIV(aesIV, 16)) {
        printf("[-] Failed to generate IV\n");
        return 1;
    }

    printf("    Original: %s\n", aesData);

    if (!Crypto_AES256_Encrypt(aesData, sizeof(aesData), aesKey, aesIV)) {
        printf("[-] AES encryption failed\n");
        return 1;
    }

    printf("    Encrypted: ");
    for (SIZE_T i = 0; i < 32; i++) printf("%02X ", aesData[i]);  // Show first 32 bytes
    printf("...\n");

    if (!Crypto_AES256_Decrypt(aesData, sizeof(aesData), aesKey, aesIV)) {
        printf("[-] AES decryption failed\n");
        return 1;
    }

    printf("    Decrypted: %s\n\n", aesData);

    // Test 4: Key derivation from password
    printf("[*] Test 4: PBKDF2 Key Derivation\n");
    const char* password = "MyWeakPassword123";
    BYTE salt[16];
    BYTE derivedKey[32];

    // Generate random salt
    if (!Crypto_GenerateKey(salt, 16)) {
        printf("[-] Failed to generate salt\n");
        return 1;
    }

    printf("    Password: %s\n", password);
    printf("    Salt: ");
    for (int i = 0; i < 16; i++) printf("%02X ", salt[i]);
    printf("\n");

    if (!Crypto_DeriveKeyFromPassword(password, strlen(password), salt, 16, 10000, derivedKey, 32)) {
        printf("[-] Key derivation failed\n");
        return 1;
    }

    printf("    Derived Key (256-bit): ");
    for (int i = 0; i < 32; i++) printf("%02X ", derivedKey[i]);
    printf("\n");

    printf("\n[+] All crypto tests passed!\n");
    return 0;
}
#endif
