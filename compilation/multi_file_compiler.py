#!/usr/bin/env python3
"""
Multi-file Project Compiler
============================

Extends Windows compilation to support complex multi-file projects.

Features:
- Multiple source files (.c/.cpp)
- Header files (.h)
- Modular project structure
- Automatic dependency resolution
- Proper include paths

Author: Noctis-MCP Community
License: MIT
"""

import os
import shutil
import logging
from pathlib import Path
from typing import Dict, List, Optional
from dataclasses import dataclass, field

from compilation.windows_compiler import WindowsCompiler, CompilationResult


logger = logging.getLogger(__name__)


@dataclass
class ProjectFile:
    """Represents a single file in the project"""
    filename: str
    content: str
    file_type: str  # 'source', 'header', 'main'


@dataclass
class ProjectStructure:
    """Represents a complete multi-file project"""
    name: str
    files: List[ProjectFile] = field(default_factory=list)
    include_directories: List[str] = field(default_factory=list)
    libraries: List[str] = field(default_factory=list)
    defines: List[str] = field(default_factory=list)
    
    def add_file(self, filename: str, content: str, file_type: str):
        """Add a file to the project"""
        self.files.append(ProjectFile(filename, content, file_type))
    
    def get_source_files(self) -> List[ProjectFile]:
        """Get all source files"""
        return [f for f in self.files if f.file_type in ['source', 'main']]
    
    def get_header_files(self) -> List[ProjectFile]:
        """Get all header files"""
        return [f for f in self.files if f.file_type == 'header']


class MultiFileProjectGenerator:
    """
    Generates Visual Studio projects for multi-file malware projects
    """
    
    # Enhanced .vcxproj template for multiple files
    VCXPROJ_MULTI_TEMPLATE = r"""<?xml version="1.0" encoding="utf-8"?>
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
      <Optimization>{optimization_level}</Optimization>
      <FunctionLevelLinking>true</FunctionLevelLinking>
      <IntrinsicFunctions>true</IntrinsicFunctions>
      <SDLCheck>false</SDLCheck>
      <PreprocessorDefinitions>WIN32;NDEBUG;_CONSOLE;{defines};%(PreprocessorDefinitions)</PreprocessorDefinitions>
      <ConformanceMode>true</ConformanceMode>
      <AdditionalIncludeDirectories>{include_dirs}</AdditionalIncludeDirectories>
      <RuntimeLibrary>MultiThreaded</RuntimeLibrary>
      <BufferSecurityCheck>false</BufferSecurityCheck>
    </ClCompile>
    <Link>
      <SubSystem>{subsystem}</SubSystem>
      <GenerateDebugInformation>false</GenerateDebugInformation>
      <EnableCOMDATFolding>true</EnableCOMDATFolding>
      <OptimizeReferences>true</OptimizeReferences>
      <AdditionalDependencies>{libraries};%(AdditionalDependencies)</AdditionalDependencies>
    </Link>
  </ItemDefinitionGroup>
  <ItemGroup>
{source_files}
  </ItemGroup>
  <ItemGroup>
{header_files}
  </ItemGroup>
  <Import Project="$(VCTargetsPath)\Microsoft.Cpp.targets" />
</Project>
"""
    
    def generate_vcxproj(self, project: ProjectStructure, 
                         architecture: str, optimization: str,
                         output_name: str, subsystem: str = "Console") -> str:
        """
        Generate .vcxproj file for multi-file project
        
        Args:
            project: ProjectStructure with all files
            architecture: x86 or x64
            optimization: O0, O1, O2, O3
            output_name: Output executable name
            subsystem: Console or Windows
        
        Returns:
            .vcxproj file content
        """
        logger.info(f"Generating multi-file project: {project.name}")
        
        # Map architecture
        platform = "x64" if architecture == "x64" else "Win32"
        
        # Map optimization
        optimization_map = {
            'O0': 'Disabled',
            'O1': 'MinSpace',
            'O2': 'MaxSpeed',
            'O3': 'Full'
        }
        opt_level = optimization_map.get(optimization, 'MaxSpeed')
        opt_flag = "true" if optimization in ['O2', 'O3'] else "false"
        
        # Generate source file entries
        source_entries = []
        for source_file in project.get_source_files():
            source_entries.append(f'    <ClCompile Include="src\\{source_file.filename}" />')
        
        # Generate header file entries
        header_entries = []
        for header_file in project.get_header_files():
            header_entries.append(f'    <ClInclude Include="include\\{header_file.filename}" />')
        
        # Format include directories
        include_dirs = ";".join(["include"] + project.include_directories) if project.include_directories else "include"
        
        # Format libraries
        libraries = ";".join(project.libraries) if project.libraries else "kernel32.lib;user32.lib"
        
        # Format defines
        defines = ";".join(project.defines) if project.defines else ""
        
        # Generate project file
        vcxproj = self.VCXPROJ_MULTI_TEMPLATE.format(
            project_name=project.name,
            platform=platform,
            optimization=opt_flag,
            optimization_level=opt_level,
            output_name=output_name,
            subsystem=subsystem,
            source_files="\n".join(source_entries),
            header_files="\n".join(header_entries),
            include_dirs=include_dirs,
            libraries=libraries,
            defines=defines
        )
        
        return vcxproj


class MultiFileCompiler:
    """
    Compiles multi-file malware projects
    
    Handles complex projects with:
    - Multiple source files
    - Header files
    - Custom include paths
    - Library dependencies
    """
    
    def __init__(self, output_dir: str = "compiled_projects"):
        self.output_dir = output_dir
        self.base_compiler = WindowsCompiler(output_dir=output_dir)
        self.project_generator = MultiFileProjectGenerator()
        
        # Ensure output directory exists
        os.makedirs(output_dir, exist_ok=True)
    
    def compile_project(self, project: ProjectStructure,
                       architecture: str = "x64",
                       optimization: str = "O2",
                       output_name: str = "malware",
                       subsystem: str = "Console") -> CompilationResult:
        """
        Compile a multi-file project
        
        Args:
            project: ProjectStructure with all files
            architecture: x86 or x64
            optimization: O0, O1, O2, O3
            output_name: Name for executable (without .exe)
            subsystem: Console or Windows
        
        Returns:
            CompilationResult with binary path or errors
        """
        import time
        start_time = time.time()
        
        logger.info(f"Compiling multi-file project: {project.name}")
        logger.info(f"  Source files: {len(project.get_source_files())}")
        logger.info(f"  Header files: {len(project.get_header_files())}")
        
        # Create project directory (use absolute path)
        project_dir = Path(self.output_dir).absolute() / project.name
        if project_dir.exists():
            shutil.rmtree(project_dir)
        
        project_dir.mkdir(parents=True, exist_ok=True)
        
        # Create subdirectories
        src_dir = project_dir / "src"
        include_dir = project_dir / "include"
        bin_dir = project_dir / "bin" / "x64" / "Release"
        
        src_dir.mkdir(exist_ok=True)
        include_dir.mkdir(parents=True, exist_ok=True)
        bin_dir.mkdir(parents=True, exist_ok=True)
        
        # Write source files
        for source_file in project.get_source_files():
            source_path = src_dir / source_file.filename
            with open(source_path, 'w', encoding='utf-8') as f:
                f.write(source_file.content)
            logger.info(f"  Created: src/{source_file.filename}")
        
        # Write header files
        for header_file in project.get_header_files():
            header_path = include_dir / header_file.filename
            with open(header_path, 'w', encoding='utf-8') as f:
                f.write(header_file.content)
            logger.info(f"  Created: include/{header_file.filename}")
        
        # Generate .vcxproj file
        vcxproj_content = self.project_generator.generate_vcxproj(
            project, architecture, optimization, output_name, subsystem
        )
        
        vcxproj_path = project_dir / f"{project.name}.vcxproj"
        with open(vcxproj_path, 'w', encoding='utf-8') as f:
            f.write(vcxproj_content)
        logger.info(f"  Created: {project.name}.vcxproj")
        
        # Compile using MSBuild
        try:
            msbuild_path = self.base_compiler.msbuild_path
            if not msbuild_path:
                return CompilationResult(
                    success=False,
                    errors=["MSBuild not found on system"],
                    output="MSBuild detection failed"
                )
            
            # Build the project
            platform = "x64" if architecture == "x64" else "Win32"
            cmd = [
                msbuild_path,
                str(vcxproj_path),
                "/p:Configuration=Release",
                f"/p:Platform={platform}",
                "/t:Rebuild",
                "/m",  # Multi-processor build
                "/nologo"
            ]
            
            logger.info(f"Running MSBuild: {' '.join(cmd)}")
            
            import subprocess
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60,
                cwd=str(project_dir)
            )
            
            compilation_time = time.time() - start_time
            
            # Check result
            if result.returncode == 0:
                # Find the executable
                exe_path = bin_dir / f"{output_name}.exe"
                if exe_path.exists():
                    # Copy to output directory root
                    final_path = Path(self.output_dir) / f"{output_name}.exe"
                    shutil.copy(str(exe_path), str(final_path))
                    
                    logger.info(f"Compilation successful: {final_path}")
                    
                    return CompilationResult(
                        success=True,
                        binary_path=str(final_path),
                        output=result.stdout,
                        warnings=self._extract_warnings(result.stdout),
                        compilation_time=compilation_time,
                        metadata={
                            'project_name': project.name,
                            'source_files': len(project.get_source_files()),
                            'header_files': len(project.get_header_files()),
                            'architecture': architecture,
                            'optimization': optimization,
                            'project_dir': str(project_dir)
                        }
                    )
                else:
                    return CompilationResult(
                        success=False,
                        errors=[f"Executable not found at: {exe_path}"],
                        output=result.stdout,
                        compilation_time=compilation_time
                    )
            else:
                # Compilation failed
                errors = self._extract_errors(result.stdout + result.stderr)
                warnings = self._extract_warnings(result.stdout + result.stderr)
                
                logger.error(f"Compilation failed with {len(errors)} errors")
                
                return CompilationResult(
                    success=False,
                    errors=errors,
                    warnings=warnings,
                    output=result.stdout + result.stderr,
                    compilation_time=compilation_time
                )
                
        except subprocess.TimeoutExpired:
            return CompilationResult(
                success=False,
                errors=["Compilation timeout (60s exceeded)"],
                output="Timeout"
            )
        except Exception as e:
            logger.error(f"Compilation error: {e}")
            return CompilationResult(
                success=False,
                errors=[str(e)],
                output=str(e)
            )
    
    def _extract_errors(self, output: str) -> List[str]:
        """Extract error messages from MSBuild output"""
        errors = []
        for line in output.split('\n'):
            if ': error ' in line.lower():
                errors.append(line.strip())
        return errors
    
    def _extract_warnings(self, output: str) -> List[str]:
        """Extract warning messages from MSBuild output"""
        warnings = []
        for line in output.split('\n'):
            if ': warning ' in line.lower():
                warnings.append(line.strip())
        return warnings


# =============================================================================
# TESTING
# =============================================================================

def test_multi_file_compiler():
    """Test multi-file compilation"""
    
    # Create a test project
    project = ProjectStructure(name="test_loader")
    
    # Add main.c
    main_code = """#include <stdio.h>
#include "utils.h"
#include "loader.h"

int main(int argc, char* argv[]) {
    printf("Test Loader v1.0\\n");
    
    // Initialize
    if (!initialize_loader()) {
        printf("Failed to initialize!\\n");
        return 1;
    }
    
    // Print message
    print_message("Loader initialized successfully");
    
    return 0;
}
"""
    project.add_file("main.c", main_code, "main")
    
    # Add loader.c
    loader_code = """#include "loader.h"
#include <stdio.h>
#include <windows.h>

int initialize_loader() {
    printf("[*] Initializing loader...\\n");
    return 1;
}
"""
    project.add_file("loader.c", loader_code, "source")
    
    # Add utils.c
    utils_code = """#include "utils.h"
#include <stdio.h>

void print_message(const char* msg) {
    printf("[+] %s\\n", msg);
}
"""
    project.add_file("utils.c", utils_code, "source")
    
    # Add loader.h
    loader_header = """#ifndef LOADER_H
#define LOADER_H

int initialize_loader();

#endif
"""
    project.add_file("loader.h", loader_header, "header")
    
    # Add utils.h
    utils_header = """#ifndef UTILS_H
#define UTILS_H

void print_message(const char* msg);

#endif
"""
    project.add_file("utils.h", utils_header, "header")
    
    # Compile
    print("[*] Testing multi-file compilation...")
    compiler = MultiFileCompiler()
    result = compiler.compile_project(
        project=project,
        architecture="x64",
        optimization="O2",
        output_name="test_loader"
    )
    
    if result.success:
        print(f"[+] Compilation successful!")
        print(f"[+] Binary: {result.binary_path}")
        print(f"[+] Time: {result.compilation_time:.2f}s")
        print(f"[+] Metadata: {result.metadata}")
        
        # Run the executable
        print("\n[*] Running executable...")
        import subprocess
        try:
            proc_result = subprocess.run(
                [result.binary_path],
                capture_output=True,
                text=True,
                timeout=5
            )
            print(f"[+] Output:\n{proc_result.stdout}")
        except Exception as e:
            print(f"[!] Error running: {e}")
    else:
        print(f"[!] Compilation failed!")
        print(f"[!] Errors: {result.errors}")
        print(f"[!] Output: {result.output}")


if __name__ == "__main__":
    test_multi_file_compiler()

