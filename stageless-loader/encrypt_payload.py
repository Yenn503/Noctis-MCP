#!/usr/bin/env python3
"""
Simple RC4 Payload Encryption
Usage: python3 encrypt_payload.py <input.bin> <output.enc>
"""

import sys
import os

def rc4_crypt(data, key):
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]

    i = j = 0
    result = bytearray()
    for byte in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        result.append(byte ^ S[(S[i] + S[j]) % 256])
    return bytes(result)

if len(sys.argv) != 3:
    print("Usage: python3 encrypt_payload.py <input.bin> <output.enc>")
    sys.exit(1)

input_file = sys.argv[1]
output_file = sys.argv[2]

# Read plaintext payload
with open(input_file, 'rb') as f:
    plaintext = f.read()

print(f"[*] Input: {input_file} ({len(plaintext)} bytes)")

# Generate random RC4 key
rc4_key = os.urandom(32)

# Encrypt with RC4
print("[*] Encrypting with RC4...")
encrypted = rc4_crypt(plaintext, rc4_key)

# Save encrypted payload
with open(output_file, 'wb') as f:
    f.write(encrypted)

# Save key to C header file
keys_file = output_file.replace('.enc', '_keys.h')
with open(keys_file, 'w') as f:
    f.write("// Auto-generated RC4 key\n\n")
    f.write(f"static BYTE g_Rc4Key[32] = {{ {', '.join(f'0x{b:02x}' for b in rc4_key)} }};\n")

print(f"\n[+] Encrypted: {output_file} ({len(encrypted)} bytes)")
print(f"[+] Key saved: {keys_file}")
print(f"\n[!] Copy the key into your loader's source code!")
