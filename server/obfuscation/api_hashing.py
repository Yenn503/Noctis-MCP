#!/usr/bin/env python3
"""
API Hashing Obfuscation
========================

Hides Windows API calls by resolving them at runtime using hashes.

Techniques:
- DJB2 hashing
- ROT13 + XOR
- CRC32 hashing
- Custom hash algorithms

Author: Noctis-MCP Community
License: MIT
"""

import re
import logging
from typing import List, Dict, Tuple, Set
from dataclasses import dataclass


logger = logging.getLogger(__name__)


@dataclass
class HashedAPI:
    """Represents a hashed API call"""
    original_name: str
    hash_value: int
    library: str  # DLL name (e.g., 'kernel32.dll')
    replacement_name: str


class APIHasher:
    """
    Hashes Windows API calls to hide imports
    
    Automatically:
    - Detects direct API calls
    - Generates hashes
    - Creates resolver functions
    - Replaces calls with hashed lookups
    """
    
    # Common Windows DLLs and their APIs
    COMMON_APIS = {
        'kernel32.dll': [
            'VirtualAlloc', 'VirtualAllocEx', 'VirtualProtect', 'VirtualProtectEx',
            'CreateRemoteThread', 'CreateRemoteThreadEx', 'OpenProcess', 'GetProcAddress',
            'LoadLibraryA', 'LoadLibraryW', 'GetModuleHandleA', 'GetModuleHandleW',
            'WriteProcessMemory', 'ReadProcessMemory', 'CreateProcessA', 'CreateProcessW',
            'Sleep', 'WaitForSingleObject', 'CloseHandle'
        ],
        'ntdll.dll': [
            'NtAllocateVirtualMemory', 'NtProtectVirtualMemory', 'NtWriteVirtualMemory',
            'NtCreateThreadEx', 'NtOpenProcess', 'NtQuerySystemInformation',
            'RtlInitUnicodeString'
        ],
        'advapi32.dll': [
            'RegOpenKeyExA', 'RegSetValueExA', 'RegCloseKey',
            'OpenProcessToken', 'AdjustTokenPrivileges'
        ],
        'user32.dll': [
            'MessageBoxA', 'MessageBoxW', 'FindWindowA', 'GetForegroundWindow'
        ]
    }
    
    def __init__(self, hash_method: str = 'djb2'):
        """
        Initialize API hasher
        
        Args:
            hash_method: Hashing method ('djb2', 'rot13xor', 'crc32')
        """
        self.hash_method = hash_method
        self.hashed_apis: List[HashedAPI] = []
        self.api_counter = 0
    
    def obfuscate_code(self, code: str) -> Tuple[str, str]:
        """
        Obfuscate API calls in code
        
        Args:
            code: C source code
        
        Returns:
            (modified_code, resolver_functions)
        """
        logger.info(f"Obfuscating APIs with method: {self.hash_method}")
        
        # Build API list from all DLLs
        api_list = []
        dll_map = {}
        for dll, apis in self.COMMON_APIS.items():
            for api in apis:
                api_list.append(api)
                dll_map[api] = dll
        
        # Find API calls in code
        modified_code = code
        replacements = []
        
        for api_name in api_list:
            # Match function calls: ApiName(
            pattern = rf'\b{re.escape(api_name)}\s*\('
            matches = list(re.finditer(pattern, code))
            
            if matches:
                logger.debug(f"Found {len(matches)} calls to {api_name}")
                
                # Hash the API
                hash_value = self._hash_string(api_name)
                dll_name = dll_map.get(api_name, 'kernel32.dll')
                
                # Create hashed API entry
                self.api_counter += 1
                replacement_name = f"api_{self.api_counter}"
                
                hashed_api = HashedAPI(
                    original_name=api_name,
                    hash_value=hash_value,
                    library=dll_name,
                    replacement_name=replacement_name
                )
                self.hashed_apis.append(hashed_api)
                
                # Replace all occurrences
                modified_code = re.sub(pattern, f'{replacement_name}(', modified_code)
        
        # Generate resolver code
        resolver_code = self._generate_resolver()
        
        logger.info(f"Obfuscated {len(self.hashed_apis)} API calls")
        
        return modified_code, resolver_code
    
    def _hash_string(self, s: str) -> int:
        """Hash a string with chosen method"""
        if self.hash_method == 'djb2':
            return self._djb2_hash(s)
        elif self.hash_method == 'rot13xor':
            return self._rot13xor_hash(s)
        elif self.hash_method == 'crc32':
            return self._crc32_hash(s)
        else:
            return self._djb2_hash(s)
    
    def _djb2_hash(self, s: str) -> int:
        """DJB2 hash algorithm"""
        hash_val = 5381
        for char in s:
            hash_val = ((hash_val << 5) + hash_val) + ord(char)
            hash_val &= 0xFFFFFFFF  # Keep 32-bit
        return hash_val
    
    def _rot13xor_hash(self, s: str) -> int:
        """ROT13 + XOR hash"""
        hash_val = 0
        for i, char in enumerate(s):
            rotated = ((ord(char) + 13) % 256)
            hash_val ^= (rotated << (i % 24))
            hash_val &= 0xFFFFFFFF
        return hash_val
    
    def _crc32_hash(self, s: str) -> int:
        """CRC32 hash"""
        import zlib
        return zlib.crc32(s.encode()) & 0xFFFFFFFF
    
    def _generate_resolver(self) -> str:
        """Generate API resolver code"""
        if self.hash_method == 'djb2':
            hash_func = self._generate_djb2_c()
        elif self.hash_method == 'rot13xor':
            hash_func = self._generate_rot13xor_c()
        else:
            hash_func = self._generate_djb2_c()
        
        code = """// API Hashing - Auto-generated by Noctis-MCP
#include <windows.h>
#include <stdio.h>

"""
        
        # Add hash function
        code += hash_func + "\n"
        
        # Add API resolver
        code += """// API Resolver
FARPROC resolve_api(HMODULE hModule, DWORD hash) {
    if (!hModule) return NULL;
    
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + pDosHeader->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hModule + 
        pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    
    DWORD* pAddressOfFunctions = (DWORD*)((BYTE*)hModule + pExportDir->AddressOfFunctions);
    DWORD* pAddressOfNames = (DWORD*)((BYTE*)hModule + pExportDir->AddressOfNames);
    WORD* pAddressOfNameOrdinals = (WORD*)((BYTE*)hModule + pExportDir->AddressOfNameOrdinals);
    
    for (DWORD i = 0; i < pExportDir->NumberOfNames; i++) {
        char* szFunctionName = (char*)((BYTE*)hModule + pAddressOfNames[i]);
        DWORD dwHash = hash_string(szFunctionName);
        
        if (dwHash == hash) {
            WORD wOrdinal = pAddressOfNameOrdinals[i];
            DWORD dwFunctionRVA = pAddressOfFunctions[wOrdinal];
            return (FARPROC)((BYTE*)hModule + dwFunctionRVA);
        }
    }
    
    return NULL;
}

"""
        
        # Generate function pointers and initializers
        for api in self.hashed_apis:
            code += f"// {api.original_name} from {api.library}\n"
            code += f"typedef decltype(&{api.original_name}) {api.replacement_name}_t;\n"
            code += f"{api.replacement_name}_t {api.replacement_name} = NULL;\n\n"
        
        # Generate initialization function
        code += """// Initialize all hashed APIs
BOOL initialize_hashed_apis() {
"""
        
        # Group by DLL
        dlls_used = {}
        for api in self.hashed_apis:
            if api.library not in dlls_used:
                dlls_used[api.library] = []
            dlls_used[api.library].append(api)
        
        # Load each DLL and resolve APIs
        for dll, apis in dlls_used.items():
            code += f'    HMODULE h{dll.replace(".", "_")} = LoadLibraryA("{dll}");\n'
            code += f'    if (!h{dll.replace(".", "_")}) return FALSE;\n\n'
            
            for api in apis:
                code += f'    {api.replacement_name} = ({api.replacement_name}_t)resolve_api('
                code += f'h{dll.replace(".", "_")}, 0x{api.hash_value:08X}); // {api.original_name}\n'
                code += f'    if (!{api.replacement_name}) return FALSE;\n\n'
        
        code += '    return TRUE;\n}\n\n'
        
        return code
    
    def _generate_djb2_c(self) -> str:
        """Generate DJB2 hash function in C"""
        return """// DJB2 Hash Function
DWORD hash_string(const char* str) {
    DWORD hash = 5381;
    int c;
    while ((c = *str++))
        hash = ((hash << 5) + hash) + c;
    return hash;
}
"""
    
    def _generate_rot13xor_c(self) -> str:
        """Generate ROT13+XOR hash function in C"""
        return """// ROT13+XOR Hash Function
DWORD hash_string(const char* str) {
    DWORD hash = 0;
    int i = 0;
    while (str[i]) {
        BYTE rotated = ((str[i] + 13) % 256);
        hash ^= (rotated << (i % 24));
        i++;
    }
    return hash;
}
"""


# =============================================================================
# TESTING
# =============================================================================

def test_api_hashing():
    """Test API hashing"""
    
    test_code = '''
#include <windows.h>
#include <stdio.h>

int main() {
    // Allocate memory
    void* mem = VirtualAlloc(NULL, 4096, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!mem) {
        printf("VirtualAlloc failed\\n");
        return 1;
    }
    
    // Get module handle
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    
    // Get proc address
    FARPROC pGetProcAddress = GetProcAddress(hKernel32, "GetProcAddress");
    
    printf("APIs resolved successfully\\n");
    
    return 0;
}
'''
    
    print("[*] Testing API Hashing...")
    print(f"\n[*] Original code:")
    print("=" * 60)
    print(test_code)
    print("=" * 60)
    
    # Hash APIs
    hasher = APIHasher(hash_method='djb2')
    modified_code, resolver_code = hasher.obfuscate_code(test_code)
    
    print(f"\n[+] Hashed {len(hasher.hashed_apis)} API calls")
    for api in hasher.hashed_apis:
        print(f"    {api.original_name} -> 0x{api.hash_value:08X}")
    
    print(f"\n[*] Modified code:")
    print("=" * 60)
    print(modified_code)
    print("=" * 60)
    
    print(f"\n[*] Resolver code (first 500 chars):")
    print("=" * 60)
    print(resolver_code[:500] + "...")
    print("=" * 60)


if __name__ == "__main__":
    test_api_hashing()

