#!/usr/bin/env python3
"""
Tests for Linux Cross-Compiler (MinGW)
=======================================

Tests MinGW-w64 cross-compilation functionality.
"""

import unittest
import os
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from compilation.linux_compiler import LinuxCompiler, MinGWDetector


class TestMinGWDetector(unittest.TestCase):
    """Test MinGW detection"""
    
    def test_check_installation(self):
        """Test MinGW installation check"""
        availability = MinGWDetector.check_installation()
        
        self.assertIsInstance(availability, dict)
        self.assertIn("x64", availability)
        self.assertIn("x86", availability)
        
        # At least one should be available on Kali
        self.assertTrue(
            availability["x64"] or availability["x86"],
            "MinGW not installed - install with: sudo apt-get install mingw-w64"
        )
    
    def test_find_mingw_x64(self):
        """Test finding x64 compiler"""
        compiler = MinGWDetector.find_mingw("x64")
        
        if compiler:
            self.assertTrue(os.path.exists(compiler))
            self.assertIn("x86_64", compiler)
    
    def test_find_mingw_x86(self):
        """Test finding x86 compiler"""
        compiler = MinGWDetector.find_mingw("x86")
        
        if compiler:
            self.assertTrue(os.path.exists(compiler))
            self.assertIn("i686", compiler)


class TestLinuxCompiler(unittest.TestCase):
    """Test Linux cross-compiler"""
    
    def setUp(self):
        """Set up test environment"""
        # Check if MinGW is available
        availability = MinGWDetector.check_installation()
        if not any(availability.values()):
            self.skipTest("MinGW not installed")
        
        self.compiler = LinuxCompiler(output_dir="test_output")
    
    def test_compiler_initialization(self):
        """Test compiler initializes correctly"""
        self.assertIsNotNone(self.compiler)
        self.assertTrue(self.compiler.output_dir.exists())
    
    def test_simple_compilation_x64(self):
        """Test simple C compilation for x64"""
        source_code = """
#include <stdio.h>

int main() {
    printf("Hello from MinGW x64!\\n");
    return 0;
}
"""
        
        result = self.compiler.compile(
            source_code=source_code,
            architecture="x64",
            optimization="O2",
            output_name="test_simple_x64"
        )
        
        if not self.compiler.available_archs.get("x64"):
            self.skipTest("x64 MinGW not available")
        
        self.assertTrue(result.success, f"Compilation failed: {result.errors}")
        self.assertIsNotNone(result.binary_path)
        self.assertTrue(os.path.exists(result.binary_path))
        self.assertTrue(result.binary_path.endswith(".exe"))
        self.assertGreater(result.compilation_time, 0)
    
    def test_simple_compilation_x86(self):
        """Test simple C compilation for x86"""
        source_code = """
#include <stdio.h>

int main() {
    printf("Hello from MinGW x86!\\n");
    return 0;
}
"""
        
        if not self.compiler.available_archs.get("x86"):
            self.skipTest("x86 MinGW not available")
        
        result = self.compiler.compile(
            source_code=source_code,
            architecture="x86",
            optimization="O2",
            output_name="test_simple_x86"
        )
        
        self.assertTrue(result.success, f"Compilation failed: {result.errors}")
        self.assertIsNotNone(result.binary_path)
        self.assertTrue(os.path.exists(result.binary_path))
    
    def test_windows_api_compilation(self):
        """Test compilation with Windows API calls"""
        source_code = """
#include <windows.h>
#include <stdio.h>

int main() {
    MessageBoxA(NULL, "Hello from MinGW!", "Noctis-MCP", MB_OK);
    printf("MessageBox displayed!\\n");
    return 0;
}
"""
        
        result = self.compiler.compile(
            source_code=source_code,
            architecture="x64",
            optimization="O2",
            output_name="test_winapi"
        )
        
        if not self.compiler.available_archs.get("x64"):
            self.skipTest("x64 MinGW not available")
        
        self.assertTrue(result.success, f"Compilation failed: {result.errors}")
    
    def test_optimization_levels(self):
        """Test different optimization levels"""
        source_code = """
#include <stdio.h>
int main() { return 0; }
"""
        
        for opt_level in ["O0", "O1", "O2", "O3"]:
            result = self.compiler.compile(
                source_code=source_code,
                architecture="x64",
                optimization=opt_level,
                output_name=f"test_opt_{opt_level}"
            )
            
            if not self.compiler.available_archs.get("x64"):
                self.skipTest("x64 MinGW not available")
            
            self.assertTrue(result.success, f"{opt_level} failed: {result.errors}")
    
    def test_console_subsystem(self):
        """Test console subsystem"""
        source_code = """
#include <stdio.h>
int main() {
    printf("Console app\\n");
    return 0;
}
"""
        
        result = self.compiler.compile(
            source_code=source_code,
            architecture="x64",
            subsystem="Console",
            output_name="test_console"
        )
        
        if not self.compiler.available_archs.get("x64"):
            self.skipTest("x64 MinGW not available")
        
        self.assertTrue(result.success)
    
    def test_windows_subsystem(self):
        """Test Windows (GUI) subsystem"""
        source_code = """
#include <windows.h>

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
                   LPSTR lpCmdLine, int nCmdShow) {
    MessageBoxA(NULL, "GUI App", "Noctis-MCP", MB_OK);
    return 0;
}
"""
        
        result = self.compiler.compile(
            source_code=source_code,
            architecture="x64",
            subsystem="Windows",
            output_name="test_gui"
        )
        
        if not self.compiler.available_archs.get("x64"):
            self.skipTest("x64 MinGW not available")
        
        self.assertTrue(result.success)
    
    def test_compilation_metadata(self):
        """Test compilation metadata"""
        source_code = "int main() { return 0; }"
        
        result = self.compiler.compile(
            source_code=source_code,
            architecture="x64",
            optimization="O2",
            output_name="test_metadata"
        )
        
        if not self.compiler.available_archs.get("x64"):
            self.skipTest("x64 MinGW not available")
        
        self.assertTrue(result.success)
        self.assertIn("architecture", result.metadata)
        self.assertIn("optimization", result.metadata)
        self.assertIn("binary_size", result.metadata)
        self.assertIn("compiler", result.metadata)
        self.assertEqual(result.metadata["architecture"], "x64")
        self.assertEqual(result.metadata["optimization"], "O2")
    
    def test_error_handling(self):
        """Test compilation error handling"""
        # Invalid C code
        source_code = """
#include <stdio.h>

int main() {
    invalid_function_call();  // Undefined function
    return 0;
}
"""
        
        result = self.compiler.compile(
            source_code=source_code,
            architecture="x64",
            output_name="test_error"
        )
        
        if not self.compiler.available_archs.get("x64"):
            self.skipTest("x64 MinGW not available")
        
        # Should fail
        self.assertFalse(result.success)
        self.assertTrue(len(result.errors) > 0)


if __name__ == "__main__":
    # Run tests
    unittest.main(verbosity=2)

