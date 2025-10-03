#!/usr/bin/env python3
"""
String Encryption Obfuscation
==============================

Encrypts string literals in C/C++ code to evade signature detection.

Features:
- XOR encryption with random keys
- AES encryption (compile-time)
- RC4 stream cipher
- Automatic decryption stub generation

Author: Noctis-MCP Community
License: MIT
"""

import re
import os
import logging
from typing import List, Tuple, Dict
from dataclasses import dataclass


logger = logging.getLogger(__name__)


@dataclass
class EncryptedString:
    """Represents an encrypted string"""
    original: str
    encrypted: bytes
    key: bytes
    method: str  # 'xor', 'aes', 'rc4'
    variable_name: str


class StringEncryptor:
    """
    Encrypts string literals in C code
    
    Automatically:
    - Finds all string literals
    - Encrypts them with chosen method
    - Generates decryption functions
    - Replaces literals with decryption calls
    """
    
    def __init__(self, method: str = 'xor'):
        """
        Initialize string encryptor
        
        Args:
            method: Encryption method ('xor', 'aes', 'rc4')
        """
        self.method = method
        self.encrypted_strings: List[EncryptedString] = []
        self.string_counter = 0
    
    def encrypt_code(self, code: str, exclude_patterns: List[str] = None) -> Tuple[str, str]:
        """
        Encrypt all strings in code
        
        Args:
            code: C source code
            exclude_patterns: Patterns to exclude from encryption (e.g., format strings with %)
        
        Returns:
            (modified_code, decryption_functions)
        """
        logger.info(f"Encrypting strings with method: {self.method}")
        
        if exclude_patterns is None:
            exclude_patterns = [
                r'%[sd]',  # Format specifiers
                r'\\x',     # Hex escapes
            ]
        
        # Find all string literals
        string_pattern = r'"([^"\\]*(\\.[^"\\]*)*)"'
        strings = list(re.finditer(string_pattern, code))
        
        logger.info(f"Found {len(strings)} string literals")
        
        modified_code = code
        replacements = []
        
        # Encrypt each string
        for match in reversed(strings):  # Reverse to maintain positions
            string_content = match.group(1)
            
            # Check exclusions
            should_exclude = False
            for pattern in exclude_patterns:
                if re.search(pattern, string_content):
                    should_exclude = True
                    logger.debug(f"Excluding string: {string_content[:30]}")
                    break
            
            if should_exclude:
                continue
            
            # Skip very short strings (< 3 chars)
            if len(string_content) < 3:
                continue
            
            # Encrypt the string
            encrypted = self._encrypt_string(string_content)
            self.encrypted_strings.append(encrypted)
            
            # Create replacement code
            replacement = f"decrypt_{self.method}_{encrypted.variable_name}()"
            
            # Store replacement (position, old, new)
            replacements.append((match.start(), match.end(), replacement))
        
        # Apply replacements
        for start, end, replacement in replacements:
            modified_code = modified_code[:start] + replacement + modified_code[end:]
        
        # Generate decryption functions
        decryption_code = self._generate_decryption_functions()
        
        logger.info(f"Encrypted {len(self.encrypted_strings)} strings")
        
        return modified_code, decryption_code
    
    def _encrypt_string(self, plaintext: str) -> EncryptedString:
        """Encrypt a single string"""
        self.string_counter += 1
        var_name = f"str_{self.string_counter}"
        
        if self.method == 'xor':
            encrypted, key = self._xor_encrypt(plaintext)
        elif self.method == 'aes':
            encrypted, key = self._aes_encrypt(plaintext)
        elif self.method == 'rc4':
            encrypted, key = self._rc4_encrypt(plaintext)
        else:
            raise ValueError(f"Unknown encryption method: {self.method}")
        
        return EncryptedString(
            original=plaintext,
            encrypted=encrypted,
            key=key,
            method=self.method,
            variable_name=var_name
        )
    
    def _xor_encrypt(self, plaintext: str) -> Tuple[bytes, bytes]:
        """XOR encryption with random key"""
        key = os.urandom(16)  # 16-byte key
        plaintext_bytes = plaintext.encode('utf-8')
        
        encrypted = bytearray()
        for i, byte in enumerate(plaintext_bytes):
            encrypted.append(byte ^ key[i % len(key)])
        
        return bytes(encrypted), key
    
    def _aes_encrypt(self, plaintext: str) -> Tuple[bytes, bytes]:
        """AES encryption (requires pycryptodome)"""
        try:
            from Crypto.Cipher import AES
            from Crypto.Util.Padding import pad
            
            key = os.urandom(32)  # AES-256
            cipher = AES.new(key, AES.MODE_ECB)
            plaintext_bytes = plaintext.encode('utf-8')
            padded = pad(plaintext_bytes, AES.block_size)
            encrypted = cipher.encrypt(padded)
            
            return encrypted, key
        except ImportError:
            logger.warning("pycryptodome not installed, falling back to XOR")
            return self._xor_encrypt(plaintext)
    
    def _rc4_encrypt(self, plaintext: str) -> Tuple[bytes, bytes]:
        """RC4 stream cipher"""
        try:
            from Crypto.Cipher import ARC4
            
            key = os.urandom(16)
            cipher = ARC4.new(key)
            plaintext_bytes = plaintext.encode('utf-8')
            encrypted = cipher.encrypt(plaintext_bytes)
            
            return encrypted, key
        except ImportError:
            logger.warning("pycryptodome not installed, falling back to XOR")
            return self._xor_encrypt(plaintext)
    
    def _generate_decryption_functions(self) -> str:
        """Generate C decryption functions"""
        if self.method == 'xor':
            return self._generate_xor_decryption()
        elif self.method == 'aes':
            return self._generate_aes_decryption()
        elif self.method == 'rc4':
            return self._generate_rc4_decryption()
    
    def _generate_xor_decryption(self) -> str:
        """Generate XOR decryption code"""
        code = """// XOR String Decryption - Auto-generated by Noctis-MCP
#include <stdlib.h>
#include <string.h>

"""
        
        # Generate encrypted string data
        for enc_str in self.encrypted_strings:
            # Convert to C byte array
            enc_bytes = ', '.join(f'0x{b:02x}' for b in enc_str.encrypted)
            key_bytes = ', '.join(f'0x{b:02x}' for b in enc_str.key)
            
            code += f"""// Original: "{enc_str.original[:30]}{'...' if len(enc_str.original) > 30 else ''}"
static unsigned char {enc_str.variable_name}_enc[] = {{ {enc_bytes} }};
static unsigned char {enc_str.variable_name}_key[] = {{ {key_bytes} }};
static char* {enc_str.variable_name}_decrypted = NULL;

char* decrypt_xor_{enc_str.variable_name}() {{
    if ({enc_str.variable_name}_decrypted == NULL) {{
        int len = {len(enc_str.encrypted)};
        int key_len = {len(enc_str.key)};
        {enc_str.variable_name}_decrypted = (char*)malloc(len + 1);
        
        for (int i = 0; i < len; i++) {{
            {enc_str.variable_name}_decrypted[i] = {enc_str.variable_name}_enc[i] ^ {enc_str.variable_name}_key[i % key_len];
        }}
        {enc_str.variable_name}_decrypted[len] = '\\0';
    }}
    return {enc_str.variable_name}_decrypted;
}}

"""
        
        # Add cleanup function
        code += """// Cleanup function (call at exit)
void cleanup_encrypted_strings() {
"""
        for enc_str in self.encrypted_strings:
            code += f"    if ({enc_str.variable_name}_decrypted) free({enc_str.variable_name}_decrypted);\n"
        
        code += "}\n\n"
        
        return code
    
    def _generate_aes_decryption(self) -> str:
        """Generate AES decryption code (would need crypto library)"""
        # For now, fall back to XOR
        logger.warning("AES decryption in C requires external library, using XOR")
        return self._generate_xor_decryption()
    
    def _generate_rc4_decryption(self) -> str:
        """Generate RC4 decryption code"""
        # Implement RC4 in C
        code = """// RC4 String Decryption - Auto-generated by Noctis-MCP
#include <stdlib.h>
#include <string.h>

// RC4 Implementation
void rc4_crypt(unsigned char* data, int data_len, unsigned char* key, int key_len) {
    unsigned char S[256];
    int i, j = 0, t;
    
    // KSA (Key Scheduling Algorithm)
    for (i = 0; i < 256; i++) S[i] = i;
    
    for (i = 0; i < 256; i++) {
        j = (j + S[i] + key[i % key_len]) % 256;
        t = S[i]; S[i] = S[j]; S[j] = t;
    }
    
    // PRGA (Pseudo-Random Generation Algorithm)
    i = j = 0;
    for (int k = 0; k < data_len; k++) {
        i = (i + 1) % 256;
        j = (j + S[i]) % 256;
        t = S[i]; S[i] = S[j]; S[j] = t;
        data[k] ^= S[(S[i] + S[j]) % 256];
    }
}

"""
        
        # Generate encrypted string data
        for enc_str in self.encrypted_strings:
            enc_bytes = ', '.join(f'0x{b:02x}' for b in enc_str.encrypted)
            key_bytes = ', '.join(f'0x{b:02x}' for b in enc_str.key)
            
            code += f"""// Original: "{enc_str.original[:30]}{'...' if len(enc_str.original) > 30 else ''}"
static unsigned char {enc_str.variable_name}_enc[] = {{ {enc_bytes} }};
static unsigned char {enc_str.variable_name}_key[] = {{ {key_bytes} }};
static char* {enc_str.variable_name}_decrypted = NULL;

char* decrypt_rc4_{enc_str.variable_name}() {{
    if ({enc_str.variable_name}_decrypted == NULL) {{
        int len = {len(enc_str.encrypted)};
        {enc_str.variable_name}_decrypted = (char*)malloc(len + 1);
        memcpy({enc_str.variable_name}_decrypted, {enc_str.variable_name}_enc, len);
        rc4_crypt((unsigned char*){enc_str.variable_name}_decrypted, len, 
                  {enc_str.variable_name}_key, {len(enc_str.key)});
        {enc_str.variable_name}_decrypted[len] = '\\0';
    }}
    return {enc_str.variable_name}_decrypted;
}}

"""
        
        return code


# =============================================================================
# TESTING
# =============================================================================

def test_string_encryption():
    """Test string encryption"""
    
    test_code = '''
#include <stdio.h>

int main() {
    printf("Hello, World!\\n");
    printf("This is a test string\\n");
    printf("Malware signature here\\n");
    
    char* message = "Secret payload";
    printf("Status: %s\\n", message);  // Should not encrypt format string
    
    return 0;
}
'''
    
    print("[*] Testing String Encryption...")
    print(f"\n[*] Original code:")
    print("=" * 60)
    print(test_code)
    print("=" * 60)
    
    # Test XOR encryption
    encryptor = StringEncryptor(method='xor')
    modified_code, decryption_funcs = encryptor.encrypt_code(test_code)
    
    print(f"\n[+] Encrypted {len(encryptor.encrypted_strings)} strings")
    print(f"\n[*] Modified code:")
    print("=" * 60)
    print(modified_code)
    print("=" * 60)
    
    print(f"\n[*] Decryption functions:")
    print("=" * 60)
    print(decryption_funcs[:500] + "..." if len(decryption_funcs) > 500 else decryption_funcs)
    print("=" * 60)
    
    # Test RC4 encryption
    print(f"\n[*] Testing RC4 encryption...")
    encryptor_rc4 = StringEncryptor(method='rc4')
    modified_code_rc4, decryption_funcs_rc4 = encryptor_rc4.encrypt_code(test_code)
    
    print(f"[+] Encrypted {len(encryptor_rc4.encrypted_strings)} strings with RC4")
    
    return encryptor


if __name__ == "__main__":
    test_string_encryption()

