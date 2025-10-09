#!/usr/bin/env python3
"""
Noctis-MCP Hash Generator
Generates DJB2 hashes for API function names and module names

Usage:
    python generate_hashes.py                      # Interactive mode
    python generate_hashing.py NtAllocateVirtualMemory  # Hash single function
    python generate_hashes.py --file apis.txt      # Hash from file (one per line)
    python generate_hashes.py --generate-all       # Generate all common hashes
"""

import sys

def djb2_hash(string):
    """
    Calculate DJB2 hash of a string
    Algorithm: hash = hash * 33 + c
    Initial value: 5381
    """
    hash_value = 5381
    for char in string:
        hash_value = ((hash_value << 5) + hash_value) + ord(char)
        hash_value &= 0xFFFFFFFF  # Keep as 32-bit unsigned
    return hash_value

def generate_hash_define(api_name, hash_value, prefix="HASH"):
    """Generate C preprocessor define statement"""
    return f"#define {prefix}_{api_name:<35} 0x{hash_value:08X}"

def generate_common_hashes():
    """Generate hashes for commonly used APIs"""

    print("// ================================================================")
    print("// NTDLL Functions")
    print("// ================================================================\n")

    ntdll_apis = [
        # Memory Management
        "NtAllocateVirtualMemory",
        "NtWriteVirtualMemory",
        "NtReadVirtualMemory",
        "NtProtectVirtualMemory",
        "NtFreeVirtualMemory",
        "NtQueryVirtualMemory",

        # Section Operations
        "NtCreateSection",
        "NtMapViewOfSection",
        "NtUnmapViewOfSection",
        "NtOpenSection",

        # Thread/Process
        "NtCreateThread",
        "NtCreateThreadEx",
        "NtOpenThread",
        "NtResumeThread",
        "NtSuspendThread",
        "NtTerminateThread",
        "NtQueueApcThread",

        "NtOpenProcess",
        "NtTerminateProcess",
        "NtQuerySystemInformation",

        # Synchronization
        "NtDelayExecution",
        "NtWaitForSingleObject",
        "NtWaitForMultipleObjects",
        "NtSignalAndWaitForSingleObject",

        # Registry
        "NtCreateKey",
        "NtOpenKey",
        "NtSetValueKey",
        "NtQueryValueKey",
        "NtDeleteKey",
        "NtDeleteValueKey",
        "NtEnumerateKey",

        # File Operations
        "NtCreateFile",
        "NtOpenFile",
        "NtReadFile",
        "NtWriteFile",
        "NtClose",

        # Timer Operations
        "NtSetTimer",
        "NtCancelTimer",
        "NtCreateTimer",

        # ETW/Tracing
        "NtTraceEvent",
        "NtTraceControl",

        # Rtl Functions
        "RtlRegisterWait",
        "RtlDeregisterWait",
        "RtlCreateTimer",
        "RtlDeleteTimer",
        "RtlCreateTimerQueue",
        "RtlDeleteTimerQueue",
    ]

    for api in ntdll_apis:
        hash_val = djb2_hash(api)
        print(generate_hash_define(api, hash_val))

    print("\n// ================================================================")
    print("// KERNEL32 Functions")
    print("// ================================================================\n")

    kernel32_apis = [
        # Module Loading
        "LoadLibraryA",
        "LoadLibraryW",
        "LoadLibraryExA",
        "LoadLibraryExW",
        "GetProcAddress",
        "GetModuleHandleA",
        "GetModuleHandleW",
        "GetModuleHandleExA",
        "GetModuleHandleExW",
        "FreeLibrary",

        # Memory
        "VirtualAlloc",
        "VirtualAllocEx",
        "VirtualProtect",
        "VirtualProtectEx",
        "VirtualFree",
        "VirtualFreeEx",
        "VirtualQuery",
        "VirtualQueryEx",

        # Heap
        "HeapAlloc",
        "HeapFree",
        "HeapReAlloc",
        "GetProcessHeap",
        "HeapCreate",
        "HeapDestroy",

        # Thread
        "CreateThread",
        "CreateRemoteThread",
        "CreateRemoteThreadEx",
        "ResumeThread",
        "SuspendThread",
        "TerminateThread",
        "GetCurrentThread",
        "GetCurrentThreadId",
        "GetThreadContext",
        "SetThreadContext",

        # Process
        "CreateProcessA",
        "CreateProcessW",
        "OpenProcess",
        "GetCurrentProcess",
        "GetCurrentProcessId",
        "TerminateProcess",

        # Sync
        "Sleep",
        "SleepEx",
        "WaitForSingleObject",
        "WaitForSingleObjectEx",
        "WaitForMultipleObjects",

        # Threadpool
        "CreateThreadpool",
        "CreateThreadpoolTimer",
        "SetThreadpoolTimer",
        "CloseThreadpoolTimer",
        "CreateThreadpoolWork",
        "SubmitThreadpoolWork",
        "CloseThreadpoolWork",

        # File
        "CreateFileA",
        "CreateFileW",
        "ReadFile",
        "WriteFile",
        "CloseHandle",
        "GetFileSize",
        "SetFilePointer",

        # Console
        "GetStdHandle",
        "WriteConsoleA",
        "WriteConsoleW",
        "ReadConsoleA",
        "ReadConsoleW",
    ]

    for api in kernel32_apis:
        hash_val = djb2_hash(api)
        print(generate_hash_define(api, hash_val))

    print("\n// ================================================================")
    print("// ADVAPI32 Functions")
    print("// ================================================================\n")

    advapi32_apis = [
        # Registry
        "RegCreateKeyA",
        "RegCreateKeyW",
        "RegCreateKeyExA",
        "RegCreateKeyExW",
        "RegOpenKeyA",
        "RegOpenKeyW",
        "RegOpenKeyExA",
        "RegOpenKeyExW",
        "RegSetValueA",
        "RegSetValueW",
        "RegSetValueExA",
        "RegSetValueExW",
        "RegQueryValueA",
        "RegQueryValueW",
        "RegQueryValueExA",
        "RegQueryValueExW",
        "RegDeleteKeyA",
        "RegDeleteKeyW",
        "RegDeleteValueA",
        "RegDeleteValueW",
        "RegCloseKey",

        # Token/Security
        "OpenProcessToken",
        "OpenThreadToken",
        "AdjustTokenPrivileges",
        "LookupPrivilegeValueA",
        "LookupPrivilegeValueW",
        "DuplicateToken",
        "DuplicateTokenEx",
        "SetThreadToken",
    ]

    for api in advapi32_apis:
        hash_val = djb2_hash(api)
        print(generate_hash_define(api, hash_val))

    print("\n// ================================================================")
    print("// AMSI/Security Functions")
    print("// ================================================================\n")

    security_apis = [
        "AmsiScanBuffer",
        "AmsiScanString",
        "AmsiInitialize",
        "AmsiUninitialize",
        "AddVectoredExceptionHandler",
        "RemoveVectoredExceptionHandler",
        "SetUnhandledExceptionFilter",
    ]

    for api in security_apis:
        hash_val = djb2_hash(api)
        print(generate_hash_define(api, hash_val))

    print("\n// ================================================================")
    print("// Module Names")
    print("// ================================================================\n")

    modules = [
        "ntdll.dll",
        "kernel32.dll",
        "kernelbase.dll",
        "advapi32.dll",
        "user32.dll",
        "gdi32.dll",
        "win32u.dll",
        "amsi.dll",
        "bcrypt.dll",
        "crypt32.dll",
        "ws2_32.dll",
        "wininet.dll",
        "winhttp.dll",
    ]

    for module in modules:
        module_name = module.replace(".", "_")
        hash_val = djb2_hash(module)
        print(generate_hash_define(module_name, hash_val))

    print("\n// ================================================================")
    print("// Special Hashes")
    print("// ================================================================\n")

    specials = [
        (".text", "text_section"),
        (".data", "data_section"),
        (".rdata", "rdata_section"),
    ]

    for text, name in specials:
        hash_val = djb2_hash(text)
        print(generate_hash_define(name, hash_val))

def interactive_mode():
    """Interactive hash generation"""
    print("=" * 70)
    print("Noctis-MCP API Hash Generator (DJB2)")
    print("=" * 70)
    print("\nEnter API names to hash (one per line)")
    print("Press Ctrl+C to exit\n")

    try:
        while True:
            api_name = input("API Name: ").strip()
            if not api_name:
                continue

            hash_val = djb2_hash(api_name)
            print(f"  Hash: 0x{hash_val:08X}")
            print(f"  Define: {generate_hash_define(api_name, hash_val)}\n")
    except KeyboardInterrupt:
        print("\n\nExiting...")
        sys.exit(0)

def hash_from_file(filename):
    """Hash APIs from file (one per line)"""
    try:
        with open(filename, 'r') as f:
            for line in f:
                api_name = line.strip()
                if api_name and not api_name.startswith('#'):
                    hash_val = djb2_hash(api_name)
                    print(generate_hash_define(api_name, hash_val))
    except FileNotFoundError:
        print(f"Error: File '{filename}' not found")
        sys.exit(1)

def main():
    if len(sys.argv) == 1:
        # No arguments - interactive mode
        interactive_mode()
    elif sys.argv[1] == '--generate-all':
        # Generate all common hashes
        generate_common_hashes()
    elif sys.argv[1] == '--file':
        # Hash from file
        if len(sys.argv) < 3:
            print("Error: Please specify filename")
            print("Usage: python generate_hashes.py --file <filename>")
            sys.exit(1)
        hash_from_file(sys.argv[2])
    elif sys.argv[1] in ['-h', '--help']:
        print(__doc__)
    else:
        # Hash single API
        api_name = sys.argv[1]
        hash_val = djb2_hash(api_name)
        print(f"API:    {api_name}")
        print(f"Hash:   0x{hash_val:08X}")
        print(f"Define: {generate_hash_define(api_name, hash_val)}")

if __name__ == "__main__":
    main()
