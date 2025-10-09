#!/bin/bash
# Quick build script for API hashing test

echo "========================================"
echo "Building Noctis API Hashing Test"
echo "========================================"
echo ""

# Check if we're on macOS or Windows
if [[ "$OSTYPE" == "darwin"* ]]; then
    echo "[!] Detected macOS - This is Windows-specific code"
    echo "[!] Cross-compilation not supported in quick test"
    echo "[!] Please run on Windows with MSVC or MinGW"
    echo ""
    echo "Windows build command:"
    echo "  cl /Fe:test_api_hashing.exe test_api_hashing.c api_hashing.c"
    echo ""
    echo "Or with MinGW on Windows:"
    echo "  gcc -o test_api_hashing.exe test_api_hashing.c api_hashing.c"
    exit 1
fi

# Attempt compilation
echo "[*] Compiling with GCC..."
gcc -o test_api_hashing.exe test_api_hashing.c api_hashing.c -lkernel32 -lntdll

if [ $? -eq 0 ]; then
    echo "[+] Compilation successful!"
    echo "[*] Running test..."
    ./test_api_hashing.exe
else
    echo "[-] Compilation failed"
    exit 1
fi
