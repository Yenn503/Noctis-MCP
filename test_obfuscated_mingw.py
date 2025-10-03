#!/usr/bin/env python3
"""
Test Obfuscated Malware Compilation with MinGW
================================================

Tests that MinGW can compile code with all Noctis obfuscation techniques.
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

from compilation import get_compiler
from server.obfuscation.string_encryption import StringEncryptor
from server.obfuscation.api_hashing import APIHasher
from server.obfuscation.control_flow import ControlFlowFlattener
from server.polymorphic.engine import PolymorphicEngine

def test_obfuscated_compilation():
    """Test compilation with all obfuscation techniques"""
    
    # Base malware code with Windows API
    base_code = """
#include <windows.h>
#include <stdio.h>

// Test function with string that will be encrypted
void ShowMessage() {
    const char* message = "This is a secret message from Noctis-MCP!";
    MessageBoxA(NULL, message, "Noctis Malware", MB_OK | MB_ICONINFORMATION);
}

// Test function that will use API hashing
BOOL TestAPICall() {
    // Get kernel32 base address
    HMODULE hKernel32 = LoadLibraryA("kernel32.dll");
    if (!hKernel32) return FALSE;
    
    // This will be hashed with API hashing
    FARPROC pGetProcAddress = GetProcAddress(hKernel32, "GetProcAddress");
    if (!pGetProcAddress) return FALSE;
    
    return TRUE;
}

int main() {
    printf("[+] Noctis-MCP Obfuscated Malware Test\\n");
    printf("[+] Compiled with MinGW cross-compiler\\n");
    printf("[+] All obfuscation techniques applied\\n\\n");
    
    ShowMessage();
    
    if (TestAPICall()) {
        printf("[+] API calls successful\\n");
    }
    
    printf("[+] Test complete!\\n");
    return 0;
}
"""
    
    print("=" * 70)
    print("TESTING OBFUSCATED MALWARE COMPILATION WITH MINGW")
    print("=" * 70)
    print()
    
    # Step 1: Apply obfuscations
    print("[1/5] Applying string encryption (XOR)...")
    string_encryptor = StringEncryptor(method="xor")
    code_with_strings, _ = string_encryptor.encrypt_code(base_code)
    strings_encrypted = code_with_strings.count("XOR_DECRYPT")  # Count XOR decrypt functions
    print(f"      ✓ String encryption applied")
    print()
    
    print("[2/5] Applying API hashing (DJB2)...")
    api_hasher = APIHasher(hash_method="djb2")
    code_with_apis, _ = api_hasher.obfuscate_code(code_with_strings)
    apis_hashed = code_with_apis.count("GetProcAddressH")  # Count hashing function uses
    print(f"      ✓ API hashing applied")
    print()
    
    print("[3/5] Applying control flow flattening...")
    cf_flattener = ControlFlowFlattener()
    code_with_cf = cf_flattener.flatten(code_with_apis)
    print(f"      ✓ Control flow flattened")
    print()
    
    print("[4/5] Applying polymorphic mutations...")
    poly_engine = PolymorphicEngine()
    final_code, poly_stats = poly_engine.generate_variant(code_with_cf, mutation_level="medium")
    uniqueness = poly_stats.get('uniqueness_score', 0.0) * 100  # Convert to percentage
    print(f"      ✓ Polymorphic variant generated ({uniqueness:.1f}% unique)")
    print()
    
    # Step 2: Compile with MinGW
    print("[5/5] Compiling with MinGW cross-compiler...")
    compiler = get_compiler(output_dir="test_output")
    
    compilation_result = compiler.compile(
        source_code=final_code,
        architecture="x64",
        optimization="O2",
        output_name="obfuscated_malware",
        subsystem="Console"
    )
    
    print()
    print("=" * 70)
    print("COMPILATION RESULTS")
    print("=" * 70)
    
    if compilation_result.success:
        print(f"✓ SUCCESS! Obfuscated malware compiled successfully!")
        print()
        print(f"Binary Path:       {compilation_result.binary_path}")
        print(f"Binary Size:       {compilation_result.metadata.get('binary_size', 0):,} bytes")
        print(f"Architecture:      {compilation_result.metadata.get('architecture')}")
        print(f"Optimization:      {compilation_result.metadata.get('optimization')}")
        print(f"Compilation Time:  {compilation_result.compilation_time:.2f}s")
        print(f"Compiler:          {compilation_result.metadata.get('compiler')}")
        print()
        
        if compilation_result.warnings:
            print(f"Warnings:          {len(compilation_result.warnings)}")
        else:
            print(f"Warnings:          None")
        
        print()
        print("=" * 70)
        print("OBFUSCATION SUMMARY")
        print("=" * 70)
        print(f"String Encryption: XOR method applied")
        print(f"API Hashing:       DJB2 method applied")
        print(f"Control Flow:      Flattened (state machine)")
        print(f"Polymorphic:       {uniqueness:.1f}% uniqueness")
        print()
        print(f"Original Size:     {len(base_code):,} bytes")
        print(f"Obfuscated Size:   {len(final_code):,} bytes")
        print(f"Size Increase:     {len(final_code)/len(base_code):.1f}x")
        print()
        
        print("=" * 70)
        print("NEXT STEPS")
        print("=" * 70)
        print(f"1. Test on Windows VM: {compilation_result.binary_path}")
        print(f"2. Run with Wine:      wine {compilation_result.binary_path}")
        print(f"3. Analyze with AV:    Submit to VirusTotal (OPSEC warning!)")
        print()
        
        return True
    else:
        print(f"✗ FAILED! Compilation errors:")
        print()
        for i, error in enumerate(compilation_result.errors, 1):
            print(f"{i}. {error}")
        print()
        
        if compilation_result.warnings:
            print(f"Warnings:")
            for i, warning in enumerate(compilation_result.warnings, 1):
                print(f"{i}. {warning}")
        
        return False


if __name__ == "__main__":
    try:
        success = test_obfuscated_compilation()
        sys.exit(0 if success else 1)
    except Exception as e:
        print(f"\n[!] Test failed with exception: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

