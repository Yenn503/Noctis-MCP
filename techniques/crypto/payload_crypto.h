// Payload Encryption Module
// Extracted from zilean.c for standalone use
//
// Provides RC4 and AES-256 encryption for AI to use in any context
// Use this for: Shellcode encryption, string obfuscation, config encryption

#ifndef PAYLOAD_CRYPTO_H
#define PAYLOAD_CRYPTO_H

#include <windows.h>
#include <bcrypt.h>

#pragma comment(lib, "bcrypt.lib")

// RC4 Stream Cipher
// Fast, simple, good for runtime encryption
// OPSEC: Moderate (7/10) - well-known but effective
VOID Crypto_RC4(BYTE* pData, SIZE_T szDataLen, BYTE* pKey, SIZE_T szKeyLen);

// AES-256 Encryption (CBC mode)
// Stronger than RC4, industry standard
// OPSEC: High (9/10) - harder to break, hardware accelerated
BOOL Crypto_AES256_Encrypt(BYTE* pData, SIZE_T szDataLen, BYTE* pKey, BYTE* pIV);

// AES-256 Decryption (CBC mode)
BOOL Crypto_AES256_Decrypt(BYTE* pData, SIZE_T szDataLen, BYTE* pKey, BYTE* pIV);

// XOR Cipher (simple obfuscation)
// Use for quick string hiding, not strong encryption
// OPSEC: Low (5/10) - easily reversed, but fast
VOID Crypto_XOR(BYTE* pData, SIZE_T szDataLen, BYTE* pKey, SIZE_T szKeyLen);

// Generate random encryption key
// Uses BCryptGenRandom for cryptographically secure randomness
BOOL Crypto_GenerateKey(BYTE* pKey, SIZE_T szKeyLen);

// Generate random IV for AES
BOOL Crypto_GenerateIV(BYTE* pIV, SIZE_T szIVLen);

// Key derivation from password (PBKDF2)
// Converts weak passwords into strong 256-bit keys
BOOL Crypto_DeriveKeyFromPassword(
    LPCSTR pszPassword,
    SIZE_T szPasswordLen,
    BYTE* pSalt,
    SIZE_T szSaltLen,
    DWORD dwIterations,
    BYTE* pDerivedKey,
    SIZE_T szDerivedKeyLen
);

#endif // PAYLOAD_CRYPTO_H
