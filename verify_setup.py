#!/usr/bin/env python3
"""
Noctis-MCP Setup Verification
==============================

Comprehensive validation of Noctis-MCP installation.
Run this after setup to ensure everything works correctly.
"""

import sys
import os
import platform
import subprocess
import shutil
from pathlib import Path

# Add repo to path
sys.path.insert(0, str(Path(__file__).parent))

# Colors
GREEN = '\033[0;32m'
YELLOW = '\033[1;33m'
RED = '\033[0;31m'
BLUE = '\033[0;34m'
NC = '\033[0m'

# Track results
passed = 0
failed = 0
warnings = 0

def check(name, condition, message="", error_msg=""):
    """Print check result"""
    global passed, failed
    if condition:
        print(f"{GREEN}✓{NC} {name}")
        if message:
            print(f"  → {message}")
        passed += 1
        return True
    else:
        print(f"{RED}✗{NC} {name}")
        if error_msg:
            print(f"  → {error_msg}")
        failed += 1
        return False

def warn(name, message):
    """Print warning"""
    global warnings
    print(f"{YELLOW}⚠{NC} {name}")
    print(f"  → {message}")
    warnings += 1

def header(text):
    """Print section header"""
    print(f"\n{BLUE}{'='*70}{NC}")
    print(f"{BLUE}{text:^70}{NC}")
    print(f"{BLUE}{'='*70}{NC}\n")

def main():
    print(f"\n{BLUE}{'='*70}{NC}")
    print(f"{BLUE}{'NOCTIS-MCP SETUP VERIFICATION':^70}{NC}")
    print(f"{BLUE}{'='*70}{NC}\n")

    # System Info
    header("SYSTEM INFORMATION")
    os_name = platform.system()
    py_version = sys.version_info
    print(f"OS: {os_name}")
    print(f"Python: {py_version.major}.{py_version.minor}.{py_version.micro}")
    print(f"Architecture: {platform.machine()}")

    # Python Version
    if py_version >= (3, 11):
        check("Python 3.11+", True, f"{py_version.major}.{py_version.minor}.{py_version.micro}")
    else:
        check("Python 3.11+", False, error_msg=f"Found {py_version.major}.{py_version.minor}, upgrade recommended")

    # Virtual Environment
    header("VIRTUAL ENVIRONMENT")
    venv_path = Path("venv")
    if os_name == "Windows":
        venv_python = venv_path / "Scripts" / "python.exe"
    else:
        venv_python = venv_path / "bin" / "python"

    check("Virtual environment", venv_path.exists(), str(venv_path))
    check("Python executable", venv_python.exists(), str(venv_python))

    # Core Dependencies
    header("PYTHON DEPENDENCIES")

    deps_to_check = {
        'flask': 'Flask',
        'fastmcp': 'FastMCP',
        'requests': 'Requests',
        'chromadb': 'ChromaDB (RAG)',
        'sentence_transformers': 'SentenceTransformers (RAG)',
        'yaml': 'PyYAML',
        'cryptography': 'Cryptography'
    }

    for module, name in deps_to_check.items():
        try:
            __import__(module)
            check(name, True)
        except ImportError:
            check(name, False, error_msg="Not installed - run: pip install -r requirements.txt")

    # Noctis Modules
    header("NOCTIS MODULES")

    noctis_modules = {
        'noctis_mcp_client.noctis_mcp': 'MCP Client',
        'server.noctis_server': 'Server',
        'server.agentic_api': 'Agentic API',
        'server.rag.rag_engine': 'RAG Engine',
        'compilation.linux_compiler': 'Linux Compiler',
        'c2_adapters.sliver_adapter': 'Sliver Adapter',
        'c2_adapters.mythic_adapter': 'Mythic Adapter'
    }

    for module, name in noctis_modules.items():
        try:
            __import__(module)
            check(name, True)
        except ImportError as e:
            check(name, False, error_msg=str(e))

    # MCP Tools
    header("MCP TOOLS")

    try:
        from noctis_mcp_client.noctis_mcp import (
            noctis_search_techniques,
            noctis_recommend_template,
            noctis_generate_beacon,
            noctis_compile,
            noctis_record_result
        )
        check("Tool: noctis_search_techniques", True)
        check("Tool: noctis_recommend_template", True)
        check("Tool: noctis_generate_beacon", True)
        check("Tool: noctis_compile", True)
        check("Tool: noctis_record_result", True)
    except ImportError as e:
        check("MCP Tools", False, error_msg=str(e))

    # Compilers
    header("COMPILERS")

    if os_name == "Linux":
        mingw_x64 = shutil.which('x86_64-w64-mingw32-gcc')
        mingw_x86 = shutil.which('i686-w64-mingw32-gcc')
        nasm = shutil.which('nasm')

        if mingw_x64:
            check("MinGW x64", True, mingw_x64)
        else:
            check("MinGW x64", False, error_msg="Install: sudo apt install mingw-w64")

        if mingw_x86:
            check("MinGW x86", True, mingw_x86)
        else:
            check("MinGW x86", False, error_msg="Install: sudo apt install mingw-w64")

        if nasm:
            check("NASM Assembler", True, nasm)
        else:
            warn("NASM Assembler", "Optional - for assembly compilation")

    elif os_name == "Windows":
        try:
            result = subprocess.run(['cl.exe', '/?'], capture_output=True, timeout=5)
            if result.returncode == 0:
                check("MSVC Compiler", True)
            else:
                check("MSVC Compiler", False, error_msg="Install Visual Studio Build Tools")
        except (FileNotFoundError, subprocess.TimeoutExpired):
            check("MSVC Compiler", False, error_msg="Install Visual Studio Build Tools")

    elif os_name == "Darwin":  # macOS
        mingw = shutil.which('x86_64-w64-mingw32-gcc')
        if mingw:
            check("MinGW", True, mingw)
        else:
            check("MinGW", False, error_msg="Install: brew install mingw-w64")

    # Server Health
    header("SERVER STATUS")

    try:
        import requests
        response = requests.get('http://localhost:8888/health', timeout=5)
        if response.status_code == 200:
            data = response.json()
            check("Server Running", True, "http://localhost:8888")

            # Check RAG
            if 'rag_enabled' in data or data.get('technique_implementations', 0) > 0:
                check("RAG System", True, f"{data.get('technique_implementations', 0)} implementations")

            check("Server Version", True, data.get('version', 'unknown'))
        else:
            check("Server Running", False, error_msg=f"HTTP {response.status_code}")
    except requests.exceptions.ConnectionError:
        warn("Server Not Running", "Start with: ./start_server.sh")
    except Exception as e:
        warn("Server Check Failed", str(e))

    # File Structure
    header("FILE STRUCTURE")

    required_files = [
        'README.md',
        'requirements.txt',
        'start_server.sh',
        'server/noctis_server.py',
        'noctis_mcp_client/noctis_mcp.py',
        'scripts/generate_mcp_config.py'
    ]

    for file in required_files:
        check(file, Path(file).exists())

    # RAG Database
    header("RAG DATABASE")

    rag_db = Path('data/rag_db')
    if rag_db.exists():
        chroma_db = rag_db / 'chroma.sqlite3'
        if chroma_db.exists():
            size_mb = chroma_db.stat().st_size / (1024 * 1024)
            check("ChromaDB", True, f"{size_mb:.1f} MB")
        else:
            warn("ChromaDB", "Database file missing - will be created on first run")
    else:
        warn("RAG Database", "Not initialized - will be created on server startup")

    # C2 Frameworks (Optional)
    header("C2 FRAMEWORKS (Optional)")

    c2_frameworks = {
        'sliver-server': 'Sliver',
        'sliver-client': 'Sliver Client',
        'mythic-cli': 'Mythic'
    }

    for cmd, name in c2_frameworks.items():
        if shutil.which(cmd):
            print(f"{GREEN}✓{NC} {name} installed")
        else:
            print(f"{YELLOW}○{NC} {name} not installed (optional)")

    # Summary
    header("VERIFICATION SUMMARY")

    total = passed + failed
    success_rate = (passed / total * 100) if total > 0 else 0

    print(f"Total Checks: {total}")
    print(f"{GREEN}Passed: {passed}{NC}")
    print(f"{RED}Failed: {failed}{NC}")
    print(f"{YELLOW}Warnings: {warnings}{NC}")
    print(f"\nSuccess Rate: {success_rate:.1f}%\n")

    # Final verdict
    if failed == 0:
        print(f"{GREEN}{'='*70}{NC}")
        print(f"{GREEN}🎉 Noctis-MCP is ready to use!{NC}")
        print(f"{GREEN}{'='*70}{NC}\n")
        print("📚 Next steps:")
        print("  1. Generate MCP config: python scripts/generate_mcp_config.py")
        print("  2. Configure your IDE with the generated config")
        print("  3. Start server: ./start_server.sh")
        print("  4. Restart your IDE")
        print("  5. Ask: 'What MCP tools do you have?'\n")
        return 0
    elif failed <= 3:
        print(f"{YELLOW}{'='*70}{NC}")
        print(f"{YELLOW}⚠️  Noctis-MCP mostly working (minor issues){NC}")
        print(f"{YELLOW}{'='*70}{NC}\n")
        print("⚠️  Some components need attention:")
        print("  - Review failed checks above")
        print("  - See docs/SETUP.md for help")
        print("  - Most features should still work\n")
        return 0
    else:
        print(f"{RED}{'='*70}{NC}")
        print(f"{RED}❌ Setup incomplete{NC}")
        print(f"{RED}{'='*70}{NC}\n")
        print("❌ Please fix the failed checks:")
        print("  1. Review error messages above")
        print("  2. See docs/SETUP.md for detailed instructions")
        print("  3. Run this script again after fixes\n")
        return 1

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print(f"\n\n{YELLOW}Cancelled by user{NC}")
        sys.exit(130)
    except Exception as e:
        print(f"\n{RED}Error: {e}{NC}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
