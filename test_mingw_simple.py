#!/usr/bin/env python3
"""
Simple MinGW Cross-Compilation Test
=====================================

Tests MinGW can compile Windows malware code with Windows APIs.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from compilation import get_compiler

# Realistic malware code with Windows APIs
test_code = """
#include <windows.h>
#include <stdio.h>

// API Hashing function (from Noctis techniques)
UINT64 djb2(PBYTE str) {
    UINT64 hash = 0x7734773477347734;
    INT c;
    while (c = *str++)
        hash = ((hash << 0x5) + hash) + c;
    return hash;
}

// Get function by hash
FARPROC GetProcAddressH(HMODULE hModule, UINT64 functionHash) {
    if (hModule == NULL)
        return NULL;
    
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
        return NULL;
    
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((PBYTE)hModule + dosHeader->e_lfanew);
    
    IMAGE_DATA_DIRECTORY exportDirectory = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    PIMAGE_EXPORT_DIRECTORY exportTable = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)hModule + exportDirectory.VirtualAddress);
    
    PDWORD functionNameArray = (PDWORD)((PBYTE)hModule + exportTable->AddressOfNames);
    PDWORD functionAddressArray = (PDWORD)((PBYTE)hModule + exportTable->AddressOfFunctions);
    PWORD functionOrdinalArray = (PWORD)((PBYTE)hModule + exportTable->AddressOfNameOrdinals);
    
    for (DWORD i = 0; i < exportTable->NumberOfNames; i++) {
        char* functionName = (char*)((PBYTE)hModule + functionNameArray[i]);
        
        if (djb2((PBYTE)functionName) == functionHash) {
            return (FARPROC)((PBYTE)hModule + functionAddressArray[functionOrdinalArray[i]]);
        }
    }
    
    return NULL;
}

int main() {
    printf("\\n=======================================================\\n");
    printf("  Noctis-MCP - MinGW Cross-Compilation Test\\n");
    printf("=======================================================\\n\\n");
    
    // Test 1: Load Library
    printf("[*] Test 1: Loading kernel32.dll...\\n");
    HMODULE hKernel32 = LoadLibraryA("kernel32.dll");
    if (!hKernel32) {
        printf("[!] Failed to load kernel32.dll\\n");
        return 1;
    }
    printf("[+] kernel32.dll loaded at: 0x%p\\n\\n", hKernel32);
    
    // Test 2: API Hashing
    printf("[*] Test 2: Testing API hashing...\\n");
    UINT64 hash = djb2((PBYTE)"VirtualAlloc");
    printf("[+] Hash of 'VirtualAlloc': 0x%llX\\n", hash);
    
    FARPROC pVirtualAlloc = GetProcAddressH(hKernel32, hash);
    if (pVirtualAlloc) {
        printf("[+] Resolved VirtualAlloc via hash: 0x%p\\n\\n", pVirtualAlloc);
    } else {
        printf("[-] Failed to resolve VirtualAlloc\\n\\n");
    }
    
    // Test 3: MessageBox
    printf("[*] Test 3: Displaying MessageBox...\\n");
    MessageBoxA(
        NULL,
        "This malware was cross-compiled on Linux using MinGW!\\n\\n"
        "Features demonstrated:\\n"
        "- Windows API calls\\n"
        "- API hashing (DJB2)\\n"
        "- Dynamic function resolution\\n\\n"
        "Compiled by: Noctis-MCP",
        "Noctis-MCP | MinGW Test",
        MB_OK | MB_ICONINFORMATION
    );
    printf("[+] MessageBox displayed!\\n\\n");
    
    printf("=======================================================\\n");
    printf("  All tests passed! MinGW cross-compilation works!\\n");
    printf("=======================================================\\n");
    
    return 0;
}
"""

def main():
    print("=" * 70)
    print("MINGW CROSS-COMPILATION TEST")
    print("=" * 70)
    print()
    print("[*] Testing MinGW can compile Windows malware with:")
    print("    - Windows API calls (LoadLibrary, MessageBox)")
    print("    - PE parsing (DOS/NT headers)")
    print("    - API hashing (DJB2 algorithm)")
    print("    - Dynamic function resolution")
    print()
    
    print("[*] Getting compiler...")
    compiler = get_compiler(output_dir="test_output")
    print(f"[+] Using: {type(compiler).__name__}")
    print()
    
    print("[*] Compiling Windows malware on Linux...")
    result = compiler.compile(
        source_code=test_code,
        architecture="x64",
        optimization="O2",
        output_name="noctis_test",
        subsystem="Console"
    )
    
    print()
    print("=" * 70)
    print("RESULTS")
    print("=" * 70)
    
    if result.success:
        print(f"✓ SUCCESS! Malware compiled successfully!")
        print()
        print(f"Binary:       {result.binary_path}")
        print(f"Size:         {result.metadata.get('binary_size', 0):,} bytes")
        print(f"Architecture: {result.metadata.get('architecture')}")
        print(f"Optimization: {result.metadata.get('optimization')}")
        print(f"Time:         {result.compilation_time:.2f}s")
        print(f"Warnings:     {len(result.warnings)}")
        print()
        print("=" * 70)
        print("NEXT STEPS")
        print("=" * 70)
        print(f"1. Test on Windows: Copy {result.binary_path} to Windows VM")
        print(f"2. Test with Wine:  wine {result.binary_path}")
        print()
        return 0
    else:
        print(f"✗ FAILED!")
        print()
        for i, error in enumerate(result.errors[:10], 1):
            print(f"{i}. {error}")
        return 1

if __name__ == "__main__":
    sys.exit(main())

