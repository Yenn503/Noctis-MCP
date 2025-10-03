#!/usr/bin/env python3
"""
Windows Compilation Engine
==========================

Compiles generated C/C++ malware code using MSBuild and Visual Studio.

This module provides automatic compilation with:
- MSBuild detection
- Project file generation
- Error parsing and reporting
- Binary management

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
import json


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


class MSBuildDetector:
    """
    Detects MSBuild installation on Windows
    
    Searches common locations:
    - Visual Studio 2022
    - Visual Studio 2019
    - .NET Framework
    - PATH environment variable
    """
    
    COMMON_PATHS = [
        r"C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe",
        r"C:\Program Files\Microsoft Visual Studio\2022\Professional\MSBuild\Current\Bin\MSBuild.exe",
        r"C:\Program Files\Microsoft Visual Studio\2022\Enterprise\MSBuild\Current\Bin\MSBuild.exe",
        r"C:\Program Files\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\MSBuild.exe",
        r"C:\Program Files\Microsoft Visual Studio\2019\Community\MSBuild\Current\Bin\MSBuild.exe",
        r"C:\Program Files\Microsoft Visual Studio\2019\Professional\MSBuild\Current\Bin\MSBuild.exe",
        r"C:\Program Files\Microsoft Visual Studio\2019\Enterprise\MSBuild\Current\Bin\MSBuild.exe",
        r"C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\MSBuild\Current\Bin\MSBuild.exe",
        r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe",
        r"C:\Windows\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe",
    ]
    
    @classmethod
    def find_msbuild(cls) -> Optional[str]:
        """
        Find MSBuild.exe on the system
        
        Returns:
            Path to MSBuild.exe or None if not found
        """
        logger.info("Searching for MSBuild...")
        
        # Check common installation paths
        for path in cls.COMMON_PATHS:
            if os.path.exists(path):
                logger.info(f"Found MSBuild at: {path}")
                return path
        
        # Check PATH environment variable
        try:
            result = subprocess.run(
                ["where", "msbuild"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0 and result.stdout.strip():
                path = result.stdout.strip().split('\n')[0]
                logger.info(f"Found MSBuild in PATH: {path}")
                return path
        except Exception as e:
            logger.debug(f"Failed to search PATH: {e}")
        
        logger.error("MSBuild not found on system")
        return None


class ProjectGenerator:
    """
    Generates Visual Studio project files (.vcxproj)
    """
    
    VCXPROJ_TEMPLATE = r"""<?xml version="1.0" encoding="utf-8"?>
<Project DefaultTargets="Build" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <ItemGroup Label="ProjectConfigurations">
    <ProjectConfiguration Include="Release|{platform}">
      <Configuration>Release</Configuration>
      <Platform>{platform}</Platform>
    </ProjectConfiguration>
  </ItemGroup>
  <PropertyGroup Label="Globals">
    <ProjectGuid>{{8BC9CEB8-8B4A-11D0-8D11-00A0C91BC942}}</ProjectGuid>
    <Keyword>Win32Proj</Keyword>
    <RootNamespace>{project_name}</RootNamespace>
    <WindowsTargetPlatformVersion>10.0</WindowsTargetPlatformVersion>
  </PropertyGroup>
  <Import Project="$(VCTargetsPath)\Microsoft.Cpp.Default.props" />
  <PropertyGroup Label="Configuration">
    <ConfigurationType>Application</ConfigurationType>
    <UseDebugLibraries>false</UseDebugLibraries>
    <PlatformToolset>v142</PlatformToolset>
    <CharacterSet>Unicode</CharacterSet>
    <WholeProgramOptimization>{optimization}</WholeProgramOptimization>
  </PropertyGroup>
  <Import Project="$(VCTargetsPath)\Microsoft.Cpp.props" />
  <PropertyGroup>
    <OutDir>$(SolutionDir)bin\$(Platform)\$(Configuration)\</OutDir>
    <IntDir>$(SolutionDir)obj\$(Platform)\$(Configuration)\</IntDir>
    <TargetName>{output_name}</TargetName>
    <LinkIncremental>false</LinkIncremental>
  </PropertyGroup>
  <ItemDefinitionGroup>
    <ClCompile>
      <WarningLevel>Level3</WarningLevel>
      <PrecompiledHeader>NotUsing</PrecompiledHeader>
      <Optimization>{optimization_level}</Optimization>
      <FunctionLevelLinking>true</FunctionLevelLinking>
      <IntrinsicFunctions>true</IntrinsicFunctions>
      <SDLCheck>false</SDLCheck>
      <PreprocessorDefinitions>NDEBUG;_CONSOLE;%(PreprocessorDefinitions)</PreprocessorDefinitions>
      <ConformanceMode>true</ConformanceMode>
    </ClCompile>
    <Link>
      <SubSystem>{subsystem}</SubSystem>
      <GenerateDebugInformation>false</GenerateDebugInformation>
      <EnableCOMDATFolding>true</EnableCOMDATFolding>
      <OptimizeReferences>true</OptimizeReferences>
    </Link>
  </ItemDefinitionGroup>
  <ItemGroup>
{source_files}
  </ItemGroup>
  <Import Project="$(VCTargetsPath)\Microsoft.Cpp.targets" />
</Project>
"""
    
    def generate_vcxproj(
        self,
        source_file: str,
        architecture: str = "x64",
        optimization: str = "O2",
        output_name: str = "payload",
        subsystem: str = "Console"
    ) -> str:
        """
        Generate .vcxproj file content
        
        Args:
            source_file: Path to source .c or .cpp file
            architecture: x86 or x64
            optimization: O0, O1, O2, O3
            output_name: Name of output executable (without .exe)
            subsystem: Console or Windows
        
        Returns:
            XML string for .vcxproj file
        """
        # Map optimization levels
        opt_map = {
            "O0": ("Disabled", "false"),
            "O1": ("MinSpace", "false"),
            "O2": ("MaxSpeed", "true"),
            "O3": ("Full", "true")
        }
        
        opt_level, whole_program_opt = opt_map.get(optimization, ("MaxSpeed", "true"))
        
        # Platform mapping
        platform = "x64" if architecture == "x64" else "Win32"
        
        # Source files XML
        source_files_xml = f'    <ClCompile Include="{os.path.basename(source_file)}" />'
        
        # Generate project file
        project_content = self.VCXPROJ_TEMPLATE.format(
            platform=platform,
            project_name=output_name,
            optimization=whole_program_opt,
            optimization_level=opt_level,
            output_name=output_name,
            subsystem=subsystem,
            source_files=source_files_xml
        )
        
        return project_content


class ErrorParser:
    """
    Parses MSBuild compilation errors
    """
    
    @staticmethod
    def parse_output(output: str) -> Tuple[List[str], List[str]]:
        """
        Parse MSBuild output for errors and warnings
        
        Args:
            output: MSBuild stdout/stderr output
        
        Returns:
            Tuple of (errors, warnings)
        """
        errors = []
        warnings = []
        
        for line in output.split('\n'):
            line = line.strip()
            if not line:
                continue
            
            # Match error pattern: filename(line,col): error C####: message
            if ": error " in line.lower():
                errors.append(line)
            elif ": warning " in line.lower():
                warnings.append(line)
        
        return errors, warnings


class WindowsCompiler:
    """
    Main Windows compilation engine
    
    Compiles C/C++ code using MSBuild and Visual Studio.
    """
    
    def __init__(self, msbuild_path: Optional[str] = None, output_dir: str = "compiled"):
        """
        Initialize compiler
        
        Args:
            msbuild_path: Path to MSBuild.exe (auto-detected if None)
            output_dir: Directory for compiled binaries
        """
        self.msbuild_path = msbuild_path or MSBuildDetector.find_msbuild()
        if not self.msbuild_path:
            raise RuntimeError("MSBuild not found. Please install Visual Studio Build Tools.")
        
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        self.project_generator = ProjectGenerator()
        self.error_parser = ErrorParser()
        
        logger.info(f"WindowsCompiler initialized with MSBuild: {self.msbuild_path}")
    
    def compile(
        self,
        source_code: str,
        architecture: str = "x64",
        optimization: str = "O2",
        output_name: str = "payload",
        subsystem: str = "Console"
    ) -> CompilationResult:
        """
        Compile C/C++ source code to executable
        
        Args:
            source_code: C/C++ source code string
            architecture: x86 or x64
            optimization: O0, O1, O2, O3
            output_name: Name for output executable (without .exe)
            subsystem: Console or Windows
        
        Returns:
            CompilationResult with success status and binary path or errors
        """
        start_time = datetime.now()
        
        logger.info(f"Compiling {output_name} for {architecture} with {optimization}")
        
        # Create temporary directory for compilation
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            
            # Write source file
            source_file = temp_path / "main.c"
            source_file.write_text(source_code, encoding='utf-8')
            
            # Generate project file
            project_content = self.project_generator.generate_vcxproj(
                source_file=str(source_file),
                architecture=architecture,
                optimization=optimization,
                output_name=output_name,
                subsystem=subsystem
            )
            
            project_file = temp_path / f"{output_name}.vcxproj"
            project_file.write_text(project_content, encoding='utf-8')
            
            # Build MSBuild command
            platform = "x64" if architecture == "x64" else "Win32"
            cmd = [
                self.msbuild_path,
                str(project_file),
                f"/p:Configuration=Release",
                f"/p:Platform={platform}",
                "/t:Build",
                "/v:minimal"
            ]
            
            logger.debug(f"MSBuild command: {' '.join(cmd)}")
            
            # Run MSBuild
            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    cwd=temp_dir,
                    timeout=300  # 5 minute timeout
                )
                
                output = result.stdout + "\n" + result.stderr
                errors, warnings = self.error_parser.parse_output(output)
                
                # Check if compilation succeeded
                binary_name = f"{output_name}.exe"
                binary_path = temp_path / "bin" / platform / "Release" / binary_name
                
                if binary_path.exists():
                    # Copy binary to output directory
                    final_path = self.output_dir / binary_name
                    import shutil
                    shutil.copy2(binary_path, final_path)
                    
                    compilation_time = (datetime.now() - start_time).total_seconds()
                    
                    logger.info(f"Compilation successful: {final_path}")
                    
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
                            "compiled_at": datetime.now().isoformat()
                        }
                    )
                else:
                    # Compilation failed
                    logger.error(f"Compilation failed with {len(errors)} errors")
                    compilation_time = (datetime.now() - start_time).total_seconds()
                    
                    return CompilationResult(
                        success=False,
                        output=output,
                        errors=errors,
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


# ============================================================================
# TESTING
# ============================================================================

def test_compilation():
    """Test basic compilation"""
    
    # Simple Hello World C code
    test_code = """
#include <stdio.h>

int main() {
    printf("Hello from Noctis-MCP!\\n");
    return 0;
}
"""
    
    print("[*] Testing Windows Compiler...")
    
    try:
        compiler = WindowsCompiler(output_dir="test_output")
        print(f"[+] MSBuild found: {compiler.msbuild_path}")
        
        print("[*] Compiling test code...")
        result = compiler.compile(
            source_code=test_code,
            architecture="x64",
            optimization="O2",
            output_name="test_hello"
        )
        
        if result.success:
            print(f"[+] Compilation successful!")
            print(f"[+] Binary: {result.binary_path}")
            print(f"[+] Time: {result.compilation_time:.2f}s")
            if result.warnings:
                print(f"[!] Warnings: {len(result.warnings)}")
        else:
            print(f"[!] Compilation failed!")
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

