#!/usr/bin/env python3
"""
Noctis-MCP Setup Verification Script
=====================================

Comprehensive verification of Noctis-MCP installation.
Checks all components and reports status.
"""

import sys
import platform
import subprocess
from pathlib import Path

# Get repository root (parent of scripts directory)
SCRIPT_DIR = Path(__file__).parent.resolve()
REPO_ROOT = SCRIPT_DIR.parent

# Add repository root to Python path for imports
sys.path.insert(0, str(REPO_ROOT))

# ANSI colors
GREEN = '\033[0;32m'
YELLOW = '\033[1;33m'
RED = '\033[0;31m'
BLUE = '\033[0;34m'
NC = '\033[0m'  # No Color


def print_header(text):
    """Print section header"""
    print(f"\n{BLUE}{'='*50}{NC}")
    print(f"{BLUE}{text:^50}{NC}")
    print(f"{BLUE}{'='*50}{NC}\n")


def check_item(name, condition, message=""):
    """Print check result"""
    if condition:
        print(f"{GREEN}✓{NC} {name}")
        if message:
            print(f"  → {message}")
        return True
    else:
        print(f"{RED}✗{NC} {name}")
        if message:
            print(f"  → {message}")
        return False


def check_warning(name, message):
    """Print warning"""
    print(f"{YELLOW}⚠{NC} {name}")
    print(f"  → {message}")


# Track results
checks_passed = 0
checks_failed = 0
warnings = 0


# ============================================================================
# SYSTEM CHECKS
# ============================================================================

print_header("SYSTEM INFORMATION")

os_name = platform.system()
print(f"Operating System: {os_name}")
print(f"Python Version: {sys.version.split()[0]}")
print(f"Platform: {platform.platform()}")

# Check Python version
py_version = sys.version_info
if py_version >= (3, 11):
    checks_passed += check_item(
        "Python 3.11+",
        True,
        f"Version {py_version.major}.{py_version.minor}.{py_version.micro}"
    )
else:
    checks_failed += check_item(
        "Python 3.11+",
        False,
        f"Version {py_version.major}.{py_version.minor} (upgrade recommended)"
    )


# ============================================================================
# PYTHON DEPENDENCIES
# ============================================================================

print_header("PYTHON DEPENDENCIES")

required_packages = {
    'flask': 'Flask',
    'fastmcp': 'FastMCP',
    'requests': 'Requests',
    'cryptography': 'Cryptography',
    'Crypto': 'PyCryptodome',
    'pytest': 'Pytest'
}

for module, name in required_packages.items():
    try:
        __import__(module)
        checks_passed += check_item(f"{name}", True)
    except ImportError:
        checks_failed += check_item(f"{name}", False, "Not installed")


# ============================================================================
# COMPILER CHECKS
# ============================================================================

print_header("COMPILER AVAILABILITY")

if os_name == "Linux":
    # Check MinGW
    try:
        result = subprocess.run(
            ['x86_64-w64-mingw32-gcc', '--version'],
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            version = result.stdout.split('\n')[0]
            checks_passed += check_item("MinGW x64", True, version)
        else:
            checks_failed += check_item("MinGW x64", False)
    except FileNotFoundError:
        checks_failed += check_item(
            "MinGW x64",
            False,
            "Install: sudo apt install mingw-w64"
        )
    
    try:
        result = subprocess.run(
            ['i686-w64-mingw32-gcc', '--version'],
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            checks_passed += check_item("MinGW x86", True)
        else:
            checks_failed += check_item("MinGW x86", False)
    except FileNotFoundError:
        checks_failed += check_item("MinGW x86", False)

elif os_name == "Windows":
    # Check MSBuild
    try:
        result = subprocess.run(
            ['msbuild', '-version'],
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            checks_passed += check_item("MSBuild", True)
        else:
            checks_failed += check_item("MSBuild", False)
    except FileNotFoundError:
        checks_failed += check_item(
            "MSBuild",
            False,
            "Install Visual Studio Build Tools"
        )


# ============================================================================
# NOCTIS MODULES
# ============================================================================

print_header("NOCTIS MODULES")

noctis_modules = {
    'noctis_mcp_client.noctis_mcp': 'MCP Client',
    'server.noctis_server': 'Flask Server',
    'c2_adapters': 'C2 Adapters',
    'c2_adapters.sliver_adapter': 'Sliver Adapter',
    'c2_adapters.havoc_adapter': 'Havoc Adapter',
    'c2_adapters.mythic_adapter': 'Mythic Adapter',
    'compilation': 'Compilation Module',
    'server.obfuscation.string_encryption': 'String Encryption',
    'server.obfuscation.api_hashing': 'API Hashing',
    'server.polymorphic.engine': 'Polymorphic Engine'
}

for module, name in noctis_modules.items():
    try:
        __import__(module)
        checks_passed += check_item(f"{name}", True)
    except ImportError as e:
        checks_failed += check_item(f"{name}", False, str(e))


# ============================================================================
# FILE STRUCTURE
# ============================================================================

print_header("FILE STRUCTURE")

required_files = [
    'requirements.txt',
    'README.md',
    'SETUP.md',
    'QUICKSTART.md',
    'server/noctis_server.py',
    'noctis_mcp_client/noctis_mcp.py',
    'c2_adapters/__init__.py',
    'compilation/__init__.py',
    'techniques/metadata/index.json'
]

for file_path in required_files:
    exists = (REPO_ROOT / file_path).exists()
    if exists:
        checks_passed += check_item(f"{file_path}", True)
    else:
        checks_failed += check_item(f"{file_path}", False, "Missing")


# ============================================================================
# TEST SUITE
# ============================================================================

print_header("TEST SUITE")

try:
    result = subprocess.run(
        [sys.executable, '-m', 'pytest', 'tests/', '--co', '-q'],
        capture_output=True,
        text=True,
        timeout=10
    )
    
    if result.returncode == 0:
        # Count tests
        test_count = result.stdout.count('test_')
        checks_passed += check_item(
            "Test Discovery",
            True,
            f"{test_count} tests found"
        )
        
        # Try running tests
        print("\nRunning tests (this may take a minute)...")
        test_result = subprocess.run(
            [sys.executable, '-m', 'pytest', 'tests/', '-v', '--tb=short'],
            capture_output=True,
            text=True,
            timeout=60
        )
        
        if test_result.returncode == 0:
            checks_passed += check_item("Test Execution", True, "All tests passed")
        else:
            warnings += 1
            check_warning(
                "Test Execution",
                "Some tests failed (may be due to missing C2 servers)"
            )
    else:
        checks_failed += check_item("Test Discovery", False)
        
except subprocess.TimeoutExpired:
    warnings += 1
    check_warning("Test Execution", "Tests timed out")
except Exception as e:
    checks_failed += check_item("Test Suite", False, str(e))


# ============================================================================
# C2 FRAMEWORKS (OPTIONAL)
# ============================================================================

print_header("C2 FRAMEWORKS (Optional)")

c2_checks = {
    'sliver-server': 'Sliver',
    'havoc': 'Havoc',
    'mythic-cli': 'Mythic'
}

for cmd, name in c2_checks.items():
    try:
        subprocess.run(
            [cmd, '--version'],
            capture_output=True,
            timeout=2
        )
        print(f"{GREEN}✓{NC} {name} installed")
    except (FileNotFoundError, subprocess.TimeoutExpired):
        print(f"{YELLOW}○{NC} {name} not installed (optional)")


# ============================================================================
# FINAL SUMMARY
# ============================================================================

print_header("VERIFICATION SUMMARY")

total_checks = checks_passed + checks_failed
success_rate = (checks_passed / total_checks * 100) if total_checks > 0 else 0

print(f"Total Checks: {total_checks}")
print(f"{GREEN}Passed: {checks_passed}{NC}")
print(f"{RED}Failed: {checks_failed}{NC}")
print(f"{YELLOW}Warnings: {warnings}{NC}")
print(f"\nSuccess Rate: {success_rate:.1f}%")

# Final verdict
print()
if checks_failed == 0:
    print(f"{GREEN}{'='*50}{NC}")
    print(f"{GREEN}🎉 Noctis-MCP is ready to use!{NC}")
    print(f"{GREEN}{'='*50}{NC}")
    print("\n📚 Next steps:")
    print("  1. Start server: python server/noctis_server.py")
    print("  2. Read quickstart: cat QUICKSTART.md")
    print("  3. Try examples: cd Examples/")
    sys.exit(0)
elif checks_failed <= 3:
    print(f"{YELLOW}{'='*50}{NC}")
    print(f"{YELLOW}⚠️  Noctis-MCP is mostly working{NC}")
    print(f"{YELLOW}{'='*50}{NC}")
    print("\n⚠️  Some components need attention:")
    print("  - Review failed checks above")
    print("  - See SETUP.md for installation help")
    print("  - Most features should still work")
    sys.exit(0)
else:
    print(f"{RED}{'='*50}{NC}")
    print(f"{RED}❌ Setup incomplete{NC}")
    print(f"{RED}{'='*50}{NC}")
    print("\n❌ Please fix the failed checks:")
    print("  1. Read SETUP.md for detailed instructions")
    print("  2. Install missing dependencies")
    print("  3. Run this script again")
    sys.exit(1)

