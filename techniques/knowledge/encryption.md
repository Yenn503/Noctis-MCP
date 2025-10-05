# Payload Encryption and Obfuscation

## Technique ID: NOCTIS-T004

## Conceptual Understanding

### What Is Payload Encryption?

Payload encryption is the process of encoding shellcode, executables, or configuration data to evade static analysis and signature-based detection. Encryption serves multiple purposes:

1. **Signature Evasion**: Encrypted payloads don't match known malware signatures
2. **String Obfuscation**: Hide C2 URLs, API names, and other IOCs
3. **Memory Protection**: Encrypt shellcode when dormant, decrypt only during execution
4. **Anti-Analysis**: Prevent automated analysis tools from extracting IOCs

### Encryption vs Encoding

- **Encoding**: Reversible transformation (Base64, XOR) - easily detected
- **Encryption**: Cryptographic transformation requiring key - more secure
- **Obfuscation**: Code transformation to hide logic - complements encryption

## Encryption Algorithms

### 1. AES (Advanced Encryption Standard)

**Use Case**: Strong encryption for payloads, configuration data

**Advantages**:
- Industry standard, well-tested
- Hardware acceleration (AES-NI)
- Multiple modes (CBC, GCM, CTR)

**Disadvantages**:
- Requires crypto library (Windows CryptoAPI, mbedTLS)
- Imports may be flagged

**OPSEC Score**: 8/10

**Code Pattern**:
```c
#include <wincrypt.h>

BOOL AES_Decrypt(BYTE* ciphertext, DWORD ciphertextLen, BYTE* key, BYTE* iv, BYTE* plaintext) {
    HCRYPTPROV hProv;
    HCRYPTKEY hKey;
    HCRYPTHASH hHash;

    CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);
    CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash);
    CryptHashData(hHash, key, 32, 0);
    CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey);

    memcpy(plaintext, ciphertext, ciphertextLen);
    CryptDecrypt(hKey, 0, TRUE, 0, plaintext, &ciphertextLen);

    CryptDestroyKey(hKey);
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    return TRUE;
}
```

### 2. RC4 (Rivest Cipher 4)

**Use Case**: Lightweight encryption, minimal imports

**Advantages**:
- Simple implementation (can implement custom, no imports)
- Fast, low overhead
- Stream cipher (no padding required)

**Disadvantages**:
- Cryptographically weak (still sufficient for obfuscation)
- Well-known algorithm (may be flagged)

**OPSEC Score**: 6/10

**Custom Implementation**:
```c
void RC4_Init(unsigned char* S, unsigned char* key, int keylen) {
    for (int i = 0; i < 256; i++) S[i] = i;
    int j = 0;
    for (int i = 0; i < 256; i++) {
        j = (j + S[i] + key[i % keylen]) % 256;
        unsigned char temp = S[i];
        S[i] = S[j];
        S[j] = temp;
    }
}

void RC4_Crypt(unsigned char* S, unsigned char* data, int datalen) {
    int i = 0, j = 0;
    for (int k = 0; k < datalen; k++) {
        i = (i + 1) % 256;
        j = (j + S[i]) % 256;
        unsigned char temp = S[i];
        S[i] = S[j];
        S[j] = temp;
        data[k] ^= S[(S[i] + S[j]) % 256];
    }
}
```

### 3. ChaCha20

**Use Case**: Modern alternative to AES, no hardware dependency

**Advantages**:
- Faster than AES in software
- No imports needed (can implement custom)
- Resistant to timing attacks

**Disadvantages**:
- Less common (may stand out)
- Larger code footprint

**OPSEC Score**: 7/10

### 4. XOR with Rotating Key

**Use Case**: Quick obfuscation, not true encryption

**Advantages**:
- Extremely simple
- No imports, inline assembly possible
- Fast

**Disadvantages**:
- Easily reversed with analysis
- Not cryptographically secure

**OPSEC Score**: 4/10 (use only for basic obfuscation)

**Code Pattern**:
```c
void XOR_Decrypt(BYTE* data, DWORD dataLen, BYTE* key, DWORD keyLen) {
    for (DWORD i = 0; i < dataLen; i++) {
        data[i] ^= key[i % keyLen];
    }
}
```

## Key Management

### Key Storage Strategies

1. **Hardcoded Key**:
   - Simplest, embedded in binary
   - Risk: Key extracted via static analysis
   - Mitigation: Obfuscate key with separate XOR

2. **Environment-Based Key**:
   - Derive key from hostname, username, MAC address
   - Advantage: Payload only decrypts on target system
   - OPSEC: Strong anti-analysis

3. **Time-Based Key**:
   - Derive key from current date/time
   - Advantage: Payload "expires" after certain date
   - Use case: Time-limited engagements

4. **Remote Key Retrieval**:
   - Fetch key from C2 server
   - Advantage: Payload useless without C2 access
   - Risk: Network activity before payload execution

5. **Key Derivation Function (KDF)**:
   - Use PBKDF2, Argon2 to derive key from passphrase
   - Advantage: Slow brute-force attempts
   - Example: `CryptDeriveKey()` with SHA256

### Key Obfuscation

**Stack String Key**:
```c
char key[17];
key[0] = 'S'; key[1] = 'e'; key[2] = 'c';
key[3] = 'r'; key[4] = 'e'; key[5] = 't';
key[6] = 'K'; key[7] = 'e'; key[8] = 'y';
key[9] = '1'; key[10] = '2'; key[11] = '3';
key[12] = '4'; key[13] = '5'; key[14] = '6';
key[15] = '7'; key[16] = '\0';
```

**XOR-Encoded Key**:
```c
BYTE encKey[] = { 0x12, 0x34, 0x56, 0x78 };
BYTE xorVal = 0xAA;
for (int i = 0; i < sizeof(encKey); i++) {
    encKey[i] ^= xorVal;
}
```

## Memory Encryption Patterns

### 1. Decrypt-Execute-Encrypt (Sleep Obfuscation)

**Pattern**: Decrypt shellcode before execution, re-encrypt when sleeping.

**Use Case**: Long-running implants (C2 beacons)

**Advantage**: Shellcode encrypted in memory during sleep (evades memory scanning)

**Code Pattern**:
```c
// Before sleep
RC4_Crypt(S, shellcode, shellcodeLen);
Sleep(60000); // Encrypted during sleep

// After sleep
RC4_Crypt(S, shellcode, shellcodeLen); // Decrypt again
ExecuteShellcode();
```

### 2. Layered Encryption

**Pattern**: Multiple encryption layers with different keys.

**Example**:
```
Payload → AES Encrypt (Key1) → XOR (Key2) → RC4 Encrypt (Key3)
```

**Advantage**: Even if one layer is broken, payload remains protected

**OPSEC Score**: 9/10

### 3. Memory Fluctuation

**Pattern**: Change memory protection between RW and RX, encrypt when RW.

**Code Pattern**:
```c
// Execute
VirtualProtect(shellcode, shellcodeLen, PAGE_EXECUTE_READ, &oldProtect);
ExecuteShellcode();

// Encrypt
VirtualProtect(shellcode, shellcodeLen, PAGE_READWRITE, &oldProtect);
RC4_Crypt(S, shellcode, shellcodeLen);

// Sleep
Sleep(60000);
```

## Staged Decryption

### Multi-Stage Loader

**Stage 1**: Tiny stub (decrypts Stage 2)
**Stage 2**: Intermediate loader (decrypts Stage 3)
**Stage 3**: Full payload

**Advantage**:
- Only small stub on disk (lower detection)
- Each stage uses different encryption

**Example Flow**:
```
Stage1.exe (XOR-encrypted Stage2)
  → Stage2 (RC4-encrypted Stage3)
    → Stage3 (AES-encrypted final payload)
      → Final Payload (decrypted in memory)
```

## String Encryption

### Configuration Encryption

**IOCs to Encrypt**:
- C2 URLs: `hxxp://malicious-c2.com`
- User-Agent strings
- API function names (used with API hashing)
- Registry keys, file paths

**Example**:
```c
// Encrypted C2 URL
BYTE encURL[] = { 0x4A, 0x8F, 0x23, 0xE1, ... };

// Decrypt at runtime
XOR_Decrypt(encURL, sizeof(encURL), key, keyLen);
char* c2URL = (char*)encURL; // "http://malicious-c2.com"
```

### API String Obfuscation

Combined with **API Hashing** (NOCTIS-T002):
```c
// Instead of GetProcAddress("VirtualAlloc")
DWORD hash = 0x91AFCA54; // Hash of "VirtualAlloc"
FARPROC pFunc = GetProcAddressByHash(hKernel32, hash);
```

## Target AV/EDR Effectiveness

| Security Product | Best Algorithm | OPSEC Score | Notes |
|-----------------|----------------|-------------|-------|
| Windows Defender | AES + Custom Key | 8/10 | Strong against signatures |
| CrowdStrike Falcon | ChaCha20 + Memory Encryption | 7/10 | Memory scanning focus |
| Palo Alto Cortex XDR | Layered (AES+RC4) | 8/10 | Behavioral analysis may flag decryption |
| Carbon Black | RC4 + Environment Key | 7/10 | Good signature evasion |
| SentinelOne | AES + Sleep Obfuscation | 6/10 | Advanced memory analysis |

## Integration with Other Techniques

### Recommended Combinations

1. **Encryption + Syscalls**:
   - Encrypt payload, use syscalls to allocate/write memory
   - Bypasses API hooks during injection

2. **Encryption + Process Injection**:
   - Encrypt shellcode before `WriteProcessMemory`
   - Include decryption stub in injected code

3. **Encryption + Unhooking**:
   - Encrypt payload, unhook NTDLL, decrypt and execute
   - Maximum evasion

4. **Encryption + Steganography**:
   - Hide encrypted payload in image files
   - Extract and decrypt at runtime

5. **Encryption + API Hashing**:
   - Encrypt payload + hash all API calls
   - No plaintext IOCs in binary

## OPSEC Considerations

### Detection Vectors

1. **Entropy Analysis**:
   - Encrypted data has high entropy
   - **Bypass**: Pad with low-entropy data, use steganography

2. **Decryption Routine Detection**:
   - EDRs flag decryption loops
   - **Bypass**: Use legitimate crypto APIs, obfuscate loop

3. **CryptoAPI Imports**:
   - `CryptDecrypt`, `CryptDeriveKey` may be flagged
   - **Bypass**: Custom implementation, dynamic loading

4. **Memory Scanning**:
   - Decrypted payload visible in memory
   - **Bypass**: Sleep obfuscation, memory fluctuation

### Evasion Improvements

1. **Randomize Encryption Key** per build
2. **Use uncommon algorithms** (ChaCha20, Salsa20)
3. **Combine with polymorphism** (code mutation)
4. **Implement decryption in assembly** (harder to analyze)

## Real-World Examples

### GitHub Projects
- **Ekko**: Sleep obfuscation with encryption
- **ScareCrow**: Payload encryption framework
- **Donut**: In-memory PE loader with encryption
- **SGN**: Shikata Ga Nai polymorphic encoder

### C2 Frameworks
- **Cobalt Strike**: AES-encrypted beacons
- **Sliver**: ChaCha20-Poly1305 for C2 comms
- **Mythic**: Customizable encryption per agent

## Metadata

- **MITRE ATT&CK**: T1027 (Obfuscated Files or Information), T1027.002 (Software Packing)
- **Complexity**: Medium
- **Stability**: High
- **Average OPSEC Score**: 7/10
