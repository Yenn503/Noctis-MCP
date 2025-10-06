#!/usr/bin/env python3
"""
BOF (Beacon Object Files) Compiler
====================================

Compiles C code to COFF object files for C2 frameworks.

Supports:
- Sliver BOF (requires x86 + x64 + extension.json)
- Cobalt Strike BOF (COFF .o files)
- Adaptix BOF (position-independent, single-threaded)

Author: Noctis-MCP Team
License: MIT
"""

import os
import sys
import json
import subprocess
import tempfile
import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime

logger = logging.getLogger(__name__)


@dataclass
class BOFResult:
    """Result of BOF compilation"""
    success: bool
    x86_path: Optional[str] = None
    x64_path: Optional[str] = None
    extension_json: Optional[str] = None
    errors: List[str] = None
    metadata: Dict = None

    def __post_init__(self):
        if self.errors is None:
            self.errors = []
        if self.metadata is None:
            self.metadata = {}


class BOFCompiler:
    """
    Beacon Object File (BOF) compiler

    Compiles C code to COFF object files compatible with:
    - Sliver C2
    - Cobalt Strike
    - Adaptix C2
    - Brute Ratel
    """

    # BOF-specific compilation flags
    BOF_FLAGS_X64 = [
        '-c',                              # Compile only (no linking)
        '-masm=intel',                     # Intel assembly syntax
        '-fno-asynchronous-unwind-tables', # No unwind tables
        '-fno-ident',                      # No compiler identification
        '-fpack-struct=8',                 # 8-byte struct packing
        '-falign-functions=16',            # 16-byte function alignment
        '-Os',                             # Optimize for size
        '-nostdlib',                       # No standard library
        '-fPIC',                           # Position-independent code
        '-fno-stack-protector',            # No stack canaries
        '-fomit-frame-pointer',            # No frame pointer
        '-Wno-unused-function',            # Suppress warnings
        '-Wno-unused-variable'
    ]

    BOF_FLAGS_X86 = [
        '-c',
        '-m32',                            # 32-bit mode
        '-masm=intel',
        '-fno-asynchronous-unwind-tables',
        '-fno-ident',
        '-fpack-struct=8',
        '-falign-functions=16',
        '-Os',
        '-nostdlib',
        '-fPIC',
        '-fno-stack-protector',
        '-fomit-frame-pointer',
        '-Wno-unused-function',
        '-Wno-unused-variable'
    ]

    def __init__(self, output_dir: str = "bof_output"):
        """
        Initialize BOF compiler

        Args:
            output_dir: Directory for compiled BOF files
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Check MinGW availability
        self.mingw_x64 = self._check_mingw('x86_64-w64-mingw32-gcc')
        self.mingw_x86 = self._check_mingw('i686-w64-mingw32-gcc')

        if not self.mingw_x64 and not self.mingw_x86:
            raise RuntimeError("MinGW not found. Install: sudo apt-get install mingw-w64")

        logger.info(f"BOFCompiler initialized")
        logger.info(f"MinGW x64: {self.mingw_x64 is not None}")
        logger.info(f"MinGW x86: {self.mingw_x86 is not None}")

    def _check_mingw(self, compiler: str) -> Optional[str]:
        """Check if MinGW compiler exists"""
        import shutil
        return shutil.which(compiler)

    def compile_bof(
        self,
        source_code: str,
        bof_name: str = "beacon_object",
        c2_framework: str = "sliver"
    ) -> BOFResult:
        """
        Compile C source to BOF object files

        Args:
            source_code: C source code with go() entry point
            bof_name: Name for BOF output
            c2_framework: Target framework (sliver, cobalt_strike, adaptix)

        Returns:
            BOFResult with paths to compiled object files
        """
        start_time = datetime.now()

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)

            # Write source file
            source_file = temp_path / f"{bof_name}.c"
            source_file.write_text(source_code, encoding='utf-8')

            # Compile x64
            x64_obj = None
            if self.mingw_x64:
                x64_obj = self._compile_arch(
                    source_file,
                    bof_name,
                    "x64",
                    self.mingw_x64,
                    self.BOF_FLAGS_X64
                )

            # Compile x86
            x86_obj = None
            if self.mingw_x86:
                x86_obj = self._compile_arch(
                    source_file,
                    bof_name,
                    "x86",
                    self.mingw_x86,
                    self.BOF_FLAGS_X86
                )

            if not x64_obj and not x86_obj:
                return BOFResult(
                    success=False,
                    errors=["Failed to compile both x86 and x64"]
                )

            # Generate extension.json for Sliver
            extension_json = None
            if c2_framework == "sliver":
                extension_json = self._generate_sliver_extension(
                    bof_name,
                    x86_obj,
                    x64_obj
                )

            compilation_time = (datetime.now() - start_time).total_seconds()

            return BOFResult(
                success=True,
                x86_path=x86_obj,
                x64_path=x64_obj,
                extension_json=extension_json,
                metadata={
                    'bof_name': bof_name,
                    'c2_framework': c2_framework,
                    'compilation_time': compilation_time
                }
            )

    def _compile_arch(
        self,
        source_file: Path,
        bof_name: str,
        arch: str,
        compiler: str,
        flags: List[str]
    ) -> Optional[str]:
        """Compile for specific architecture"""
        output_file = self.output_dir / f"{bof_name}_{arch}.o"

        cmd = [compiler] + flags + [str(source_file), '-o', str(output_file)]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )

            if result.returncode == 0 and output_file.exists():
                # Validate COFF format
                if self._validate_coff(output_file):
                    logger.info(f"Compiled BOF {arch}: {output_file}")
                    return str(output_file)
                else:
                    logger.error(f"Invalid COFF format: {output_file}")
                    return None
            else:
                logger.error(f"BOF compilation failed ({arch}): {result.stderr}")
                return None

        except subprocess.TimeoutExpired:
            logger.error(f"BOF compilation timeout ({arch})")
            return None
        except Exception as e:
            logger.error(f"BOF compilation error ({arch}): {e}")
            return None

    def _validate_coff(self, obj_file: Path) -> bool:
        """Validate COFF object file format"""
        try:
            # Check COFF magic number
            with open(obj_file, 'rb') as f:
                magic = f.read(2)
                # COFF magic: 0x8664 (x64) or 0x014c (x86)
                return magic in [b'\x64\x86', b'\x4c\x01']
        except:
            return False

    def _generate_sliver_extension(
        self,
        bof_name: str,
        x86_path: Optional[str],
        x64_path: Optional[str]
    ) -> Optional[str]:
        """
        Generate extension.json for Sliver BOF

        Sliver REQUIRES (per official spec):
        - extension.json with specific fields
        - x86.o and x64.o object files
        - entrypoint: "go"
        - depends_on: "coff-loader" (not array)
        """
        if not x86_path and not x64_path:
            return None

        extension_data = {
            "name": bof_name,
            "version": "1.0.0",
            "command_name": bof_name.lower(),
            "extension_author": "Noctis-MCP",
            "entrypoint": "go",
            "depends_on": "coff-loader",  # String, not array per Sliver spec
            "files": []
        }

        # Add x86 file
        if x86_path:
            extension_data["files"].append({
                "os": "windows",
                "arch": "x86",
                "path": Path(x86_path).name
            })

        # Add x64 file
        if x64_path:
            extension_data["files"].append({
                "os": "windows",
                "arch": "x64",
                "path": Path(x64_path).name
            })

        # Write extension.json
        json_path = self.output_dir / "extension.json"
        with open(json_path, 'w') as f:
            json.dump(extension_data, f, indent=2)

        logger.info(f"Generated Sliver extension.json: {json_path}")
        return str(json_path)

    def compile_technique_to_bof(
        self,
        technique_id: str,
        c2_framework: str = "sliver"
    ) -> BOFResult:
        """
        Compile a Noctis technique to BOF

        Args:
            technique_id: Noctis technique ID (e.g., NOCTIS-T004)
            c2_framework: Target framework

        Returns:
            BOFResult
        """
        # Load technique using TechniqueManager
        from server.noctis_server import TechniqueManager

        metadata_path = Path(__file__).parent.parent / 'techniques' / 'metadata'
        tech_mgr = TechniqueManager(str(metadata_path))

        technique = tech_mgr.get_by_id(technique_id)
        if not technique:
            return BOFResult(
                success=False,
                errors=[f"Technique {technique_id} not found"]
            )

        # Load source code
        examples_root = Path(__file__).parent.parent / 'Examples'
        source_code = ""

        source_files = technique.get('source_files', [])[:2]  # First 2 files
        for source_file in source_files:
            file_path = examples_root / source_file.replace('\\', '/')
            if file_path.exists() and file_path.suffix == '.c':
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    source_code += f.read() + "\n\n"

        if not source_code:
            return BOFResult(
                success=False,
                errors=[f"No source code found for {technique_id}"]
            )

        # Wrap in BOF template
        bof_code = self._wrap_in_bof_template(source_code, technique)

        # Compile
        bof_name = technique.get('name', 'technique').replace(' ', '_').lower()
        return self.compile_bof(bof_code, bof_name, c2_framework)

    def _wrap_in_bof_template(self, technique_code: str, technique_metadata: Dict) -> str:
        """Wrap technique code in BOF template"""
        template = f'''/*
 * BOF: {technique_metadata.get("name", "Unknown")}
 * Technique: {technique_metadata.get("technique_id", "Unknown")}
 * Generated by Noctis-MCP
 */

#include <windows.h>

// BOF API declarations (Beacon)
DECLSPEC_IMPORT void BeaconPrintf(int type, char* fmt, ...);
DECLSPEC_IMPORT void* BeaconDataParse(char* buffer, int size);
DECLSPEC_IMPORT char* BeaconDataExtract(void* parser, int* size);

// ===== Technique Implementation =====
{technique_code}

// ===== BOF Entry Point =====
void go(char* args, int length) {{
    BeaconPrintf(0, "[*] Executing {technique_metadata.get("name", "technique")}");

    // Parse arguments
    void* parser = BeaconDataParse(args, length);

    // TODO: Call technique functions here

    BeaconPrintf(0, "[+] Execution complete");
}}
'''
        return template


# ============================================================================
# TESTING
# ============================================================================

def test_bof_compilation():
    """Test BOF compilation"""
    test_code = '''
#include <windows.h>

DECLSPEC_IMPORT void BeaconPrintf(int type, char* fmt, ...);

void go(char* args, int length) {
    BeaconPrintf(0, "Hello from Noctis BOF!");

    // Get computer name
    char computerName[256];
    DWORD size = sizeof(computerName);
    if (GetComputerNameA(computerName, &size)) {
        BeaconPrintf(0, "Computer: %s", computerName);
    }
}
'''

    print("[*] Testing BOF Compiler...")

    try:
        compiler = BOFCompiler(output_dir="test_bof")
        result = compiler.compile_bof(test_code, "test_bof", "sliver")

        if result.success:
            print(f"[+] BOF compilation successful!")
            print(f"[+] x86: {result.x86_path}")
            print(f"[+] x64: {result.x64_path}")
            print(f"[+] extension.json: {result.extension_json}")
        else:
            print(f"[!] BOF compilation failed: {result.errors}")

        return result.success

    except Exception as e:
        print(f"[!] Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = test_bof_compilation()
    sys.exit(0 if success else 1)
