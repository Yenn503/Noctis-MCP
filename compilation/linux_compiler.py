#!/usr/bin/env python3
"""
Linux Cross-Compilation Engine (MinGW)
=======================================

Compiles Windows executables from Linux using MinGW-w64 cross-compiler.

This module enables Linux users to generate Windows malware without
needing a Windows machine or virtual machine.

Features:
- MinGW-w64 detection (x64 and x86)
- GCC-style compilation
- Same API as WindowsCompiler
- Cross-platform compatibility

Author: Noctis-MCP Community
License: MIT
"""

import os
import sys
import subprocess
import tempfile
import logging
from pathlib import Path
from typing import Optional, Dict, List, Tuple
from dataclasses import dataclass
from datetime import datetime
import shutil


# Setup logging
logger = logging.getLogger(__name__)


@dataclass
class CompilationResult:
    """Result of a compilation operation"""
    success: bool
    binary_path: Optional[str] = None
    output: str = ""
    errors: List[str] = None
    warnings: List[str] = None
    compilation_time: float = 0.0
    metadata: Dict = None
    
    def __post_init__(self):
        if self.errors is None:
            self.errors = []
        if self.warnings is None:
            self.warnings = []
        if self.metadata is None:
            self.metadata = {}


class MinGWDetector:
    """
    Detects MinGW-w64 cross-compiler installation on Linux
    
    Searches for:
    - x86_64-w64-mingw32-gcc (64-bit Windows)
    - i686-w64-mingw32-gcc (32-bit Windows)
    """
    
    COMPILERS = {
        "x64": "x86_64-w64-mingw32-gcc",
        "x86": "i686-w64-mingw32-gcc"
    }
    
    @classmethod
    def find_mingw(cls, architecture: str = "x64") -> Optional[str]:
        """
        Find MinGW cross-compiler for specified architecture
        
        Args:
            architecture: x64 or x86
        
        Returns:
            Path to compiler or None if not found
        """
        compiler_name = cls.COMPILERS.get(architecture)
        if not compiler_name:
            logger.error(f"Unknown architecture: {architecture}")
            return None
        
        logger.info(f"Searching for MinGW compiler: {compiler_name}")
        
        # Check if in PATH
        compiler_path = shutil.which(compiler_name)
        if compiler_path:
            logger.info(f"Found MinGW at: {compiler_path}")
            return compiler_path
        
        logger.error(f"MinGW compiler not found: {compiler_name}")
        return None
    
    @classmethod
    def check_installation(cls) -> Dict[str, bool]:
        """
        Check which MinGW compilers are installed
        
        Returns:
            Dict with x64/x86 availability
        """
        return {
            "x64": cls.find_mingw("x64") is not None,
            "x86": cls.find_mingw("x86") is not None
        }


class ErrorParser:
    """
    Parses GCC/MinGW compilation errors
    """
    
    @staticmethod
    def parse_output(output: str) -> Tuple[List[str], List[str]]:
        """
        Parse GCC output for errors and warnings
        
        Args:
            output: GCC stdout/stderr output
        
        Returns:
            Tuple of (errors, warnings)
        """
        errors = []
        warnings = []
        
        for line in output.split('\n'):
            line = line.strip()
            if not line:
                continue
            
            # GCC error pattern: filename:line:col: error: message
            if ": error:" in line:
                errors.append(line)
            # GCC warning pattern: filename:line:col: warning: message
            elif ": warning:" in line:
                warnings.append(line)
            # Linker errors: undefined reference, etc.
            elif "undefined reference" in line.lower():
                errors.append(line)
        
        return errors, warnings


class LinuxCompiler:
    """
    Linux-based Windows cross-compilation engine

    Compiles C/C++ code for Windows targets using MinGW-w64.
    Provides identical API to WindowsCompiler for seamless cross-platform use.
    Supports: .c, .cpp, .asm (NASM), .rc (windres)
    """

    def __init__(self, output_dir: str = "compiled"):
        """
        Initialize Linux compiler

        Args:
            output_dir: Directory for compiled binaries
        """
        # Check MinGW installation
        self.available_archs = MinGWDetector.check_installation()

        if not any(self.available_archs.values()):
            raise RuntimeError(
                "MinGW-w64 not found. Install with:\n"
                "  sudo apt-get install mingw-w64\n"
                "  or\n"
                "  sudo dnf install mingw64-gcc mingw32-gcc"
            )

        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.error_parser = ErrorParser()

        # Check for NASM (assembly compiler)
        self.nasm_available = shutil.which('nasm') is not None

        # Check for windres (resource compiler)
        self.windres_available = {
            'x64': shutil.which('x86_64-w64-mingw32-windres') is not None,
            'x86': shutil.which('i686-w64-mingw32-windres') is not None
        }

        logger.info(f"LinuxCompiler initialized")
        logger.info(f"Available architectures: {self.available_archs}")
        logger.info(f"NASM available: {self.nasm_available}")
        logger.info(f"windres available: {self.windres_available}")
    
    def compile(
        self,
        source_code: str,
        architecture: str = "x64",
        optimization: str = "O2",
        output_name: str = "payload",
        subsystem: str = "Console",
        auto_fix: bool = False
    ) -> CompilationResult:
        """
        Compile C/C++ source code to Windows executable
        
        Args:
            source_code: C/C++ source code string
            architecture: x86 or x64
            optimization: O0, O1, O2, O3
            output_name: Name for output executable (without .exe)
            subsystem: Console or Windows
            auto_fix: Attempt to auto-fix compilation errors (not used in MinGW)
        
        Returns:
            CompilationResult with success status and binary path or errors
        """
        start_time = datetime.now()
        
        logger.info(f"Cross-compiling {output_name} for Windows {architecture} with {optimization}")
        
        # Check if architecture is supported
        if not self.available_archs.get(architecture):
            return CompilationResult(
                success=False,
                errors=[f"MinGW compiler for {architecture} not installed"]
            )
        
        # Find compiler
        compiler = MinGWDetector.find_mingw(architecture)
        if not compiler:
            return CompilationResult(
                success=False,
                errors=[f"MinGW compiler not found for {architecture}"]
            )
        
        # Create temporary directory for compilation
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            
            # Write source file
            source_file = temp_path / "main.c"
            source_file.write_text(source_code, encoding='utf-8')
            
            # Output file path
            binary_name = f"{output_name}.exe"
            temp_binary = temp_path / binary_name
            
            # Build GCC command
            cmd = [
                compiler,
                str(source_file),
                f"-{optimization}",  # Optimization level
                "-o", str(temp_binary),
                "-s",  # Strip symbols
            ]
            
            # Subsystem flag
            if subsystem.lower() == "windows":
                cmd.append("-mwindows")  # GUI subsystem (no console)
            else:
                cmd.append("-mconsole")  # Console subsystem
            
            # Additional flags for malware dev
            cmd.extend([
                "-Wall",  # All warnings
                "-Wno-unused-variable",  # Suppress unused variable warnings
                "-Wno-unused-function",  # Suppress unused function warnings
                "-static",  # Static linking (no DLL dependencies)
                "-ffunction-sections",  # Separate functions for better optimization
                "-fdata-sections",  # Separate data for better optimization
                "-Wl,--gc-sections",  # Remove unused sections
            ])
            
            logger.debug(f"MinGW command: {' '.join(cmd)}")
            
            # Run MinGW
            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=300  # 5 minute timeout
                )
                
                output = result.stdout + "\n" + result.stderr
                errors, warnings = self.error_parser.parse_output(output)
                
                # Check if compilation succeeded
                if temp_binary.exists():
                    # Copy binary to output directory
                    final_path = self.output_dir / binary_name
                    shutil.copy2(temp_binary, final_path)
                    
                    # Make it executable (for Wine testing)
                    os.chmod(final_path, 0o755)
                    
                    compilation_time = (datetime.now() - start_time).total_seconds()
                    
                    # Get binary size
                    binary_size = final_path.stat().st_size
                    
                    logger.info(f"Cross-compilation successful: {final_path}")
                    logger.info(f"Binary size: {binary_size:,} bytes")
                    
                    return CompilationResult(
                        success=True,
                        binary_path=str(final_path),
                        output=output,
                        errors=errors,
                        warnings=warnings,
                        compilation_time=compilation_time,
                        metadata={
                            "architecture": architecture,
                            "optimization": optimization,
                            "subsystem": subsystem,
                            "compiler": compiler,
                            "platform": "Windows (cross-compiled from Linux)",
                            "binary_size": binary_size,
                            "compiled_at": datetime.now().isoformat()
                        }
                    )
                else:
                    # Compilation failed
                    logger.error(f"Cross-compilation failed with {len(errors)} errors")
                    compilation_time = (datetime.now() - start_time).total_seconds()
                    
                    return CompilationResult(
                        success=False,
                        output=output,
                        errors=errors if errors else ["Compilation failed (no binary produced)"],
                        warnings=warnings,
                        compilation_time=compilation_time
                    )
                    
            except subprocess.TimeoutExpired:
                logger.error("Compilation timeout")
                return CompilationResult(
                    success=False,
                    errors=["Compilation timeout (exceeded 5 minutes)"],
                    compilation_time=300.0
                )
            except Exception as e:
                logger.error(f"Compilation error: {e}")
                return CompilationResult(
                    success=False,
                    errors=[f"Compilation error: {str(e)}"]
                )

    def compile_asm(self, asm_file: str, architecture: str = "x64") -> Optional[str]:
        """
        Compile assembly file to object file using NASM

        Args:
            asm_file: Path to .asm file
            architecture: x64 or x86

        Returns:
            Path to .o file or None if failed
        """
        if not self.nasm_available:
            logger.error("NASM not installed. Install: sudo apt-get install nasm")
            return None

        nasm_format = "win64" if architecture == "x64" else "win32"
        output_file = asm_file.replace('.asm', '.o')

        cmd = ['nasm', '-f', nasm_format, asm_file, '-o', output_file]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                logger.info(f"Compiled assembly: {asm_file} -> {output_file}")
                return output_file
            else:
                logger.error(f"NASM error: {result.stderr}")
                return None
        except Exception as e:
            logger.error(f"Assembly compilation error: {e}")
            return None

    def compile_resource(self, rc_file: str, architecture: str = "x64") -> Optional[str]:
        """
        Compile resource file to object file using windres

        Args:
            rc_file: Path to .rc file
            architecture: x64 or x86

        Returns:
            Path to .o file or None if failed
        """
        if not self.windres_available.get(architecture):
            logger.error(f"windres not available for {architecture}")
            return None

        windres_cmd = 'x86_64-w64-mingw32-windres' if architecture == 'x64' else 'i686-w64-mingw32-windres'
        output_file = rc_file.replace('.rc', '.o')

        cmd = [windres_cmd, rc_file, '-o', output_file]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                logger.info(f"Compiled resource: {rc_file} -> {output_file}")
                return output_file
            else:
                logger.error(f"windres error: {result.stderr}")
                return None
        except Exception as e:
            logger.error(f"Resource compilation error: {e}")
            return None

    def compile_project(
        self,
        c_files: List[str],
        asm_files: List[str] = None,
        rc_files: List[str] = None,
        architecture: str = "x64",
        optimization: str = "O2",
        output_name: str = "payload",
        subsystem: str = "Console"
    ) -> CompilationResult:
        """
        Compile multi-file project with C, assembly, and resources

        Args:
            c_files: List of .c/.cpp files
            asm_files: List of .asm files
            rc_files: List of .rc files
            architecture: x64 or x86
            optimization: O0, O1, O2, O3
            output_name: Name for output executable
            subsystem: Console or Windows

        Returns:
            CompilationResult
        """
        start_time = datetime.now()
        logger.info(f"Compiling multi-file project: {len(c_files)} C files, {len(asm_files or [])} ASM, {len(rc_files or [])} RC")

        object_files = []

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)

            # Compile C files to object files
            compiler = MinGWDetector.find_mingw(architecture)
            for c_file in c_files:
                obj_file = temp_path / (Path(c_file).stem + '.o')
                cmd = [compiler, '-c', c_file, f'-{optimization}', '-o', str(obj_file)]
                result = subprocess.run(cmd, capture_output=True, text=True)
                if result.returncode == 0:
                    object_files.append(str(obj_file))
                else:
                    return CompilationResult(
                        success=False,
                        errors=[f"C compilation failed: {result.stderr}"]
                    )

            # Compile assembly files
            if asm_files:
                for asm_file in asm_files:
                    obj_file = self.compile_asm(asm_file, architecture)
                    if obj_file:
                        object_files.append(obj_file)
                    else:
                        logger.warning(f"Skipping assembly file: {asm_file}")

            # Compile resource files
            if rc_files:
                for rc_file in rc_files:
                    obj_file = self.compile_resource(rc_file, architecture)
                    if obj_file:
                        object_files.append(obj_file)
                    else:
                        logger.warning(f"Skipping resource file: {rc_file}")

            # Link all object files
            binary_name = f"{output_name}.exe"
            final_binary = self.output_dir / binary_name

            link_cmd = [compiler] + object_files + [
                '-o', str(final_binary),
                f'-{optimization}',
                '-s',  # Strip symbols
                '-static'
            ]

            if subsystem.lower() == "windows":
                link_cmd.append('-mwindows')
            else:
                link_cmd.append('-mconsole')

            result = subprocess.run(link_cmd, capture_output=True, text=True)

            if result.returncode == 0 and final_binary.exists():
                compilation_time = (datetime.now() - start_time).total_seconds()
                binary_size = final_binary.stat().st_size

                logger.info(f"Multi-file compilation successful: {final_binary}")

                return CompilationResult(
                    success=True,
                    binary_path=str(final_binary),
                    output=result.stdout,
                    compilation_time=compilation_time,
                    metadata={
                        'c_files': len(c_files),
                        'asm_files': len(asm_files or []),
                        'rc_files': len(rc_files or []),
                        'architecture': architecture,
                        'binary_size': binary_size
                    }
                )
            else:
                return CompilationResult(
                    success=False,
                    errors=[f"Linking failed: {result.stderr}"]
                )


# ============================================================================
# TESTING
# ============================================================================

def test_compilation():
    """Test basic cross-compilation"""
    
    # Simple Hello World C code
    test_code = """
#include <stdio.h>
#include <windows.h>

int main() {
    printf("Hello from Noctis-MCP (Linux -> Windows)!\\n");
    MessageBoxA(NULL, "Compiled with MinGW on Linux!", "Noctis-MCP", MB_OK);
    return 0;
}
"""
    
    print("[*] Testing Linux Cross-Compiler (MinGW)...")
    
    try:
        # Check installation
        availability = MinGWDetector.check_installation()
        print(f"[*] MinGW availability: {availability}")
        
        compiler = LinuxCompiler(output_dir="test_output")
        print(f"[+] LinuxCompiler initialized")
        
        print("[*] Cross-compiling test code for Windows x64...")
        result = compiler.compile(
            source_code=test_code,
            architecture="x64",
            optimization="O2",
            output_name="test_hello",
            subsystem="Console"
        )
        
        if result.success:
            print(f"[+] Cross-compilation successful!")
            print(f"[+] Binary: {result.binary_path}")
            print(f"[+] Size: {result.metadata.get('binary_size', 0):,} bytes")
            print(f"[+] Time: {result.compilation_time:.2f}s")
            if result.warnings:
                print(f"[!] Warnings: {len(result.warnings)}")
            print(f"[*] Test with Wine: wine {result.binary_path}")
        else:
            print(f"[!] Cross-compilation failed!")
            print(f"[!] Errors:")
            for error in result.errors:
                print(f"    - {error}")
        
        return result.success
        
    except Exception as e:
        print(f"[!] Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = test_compilation()
    sys.exit(0 if success else 1)

