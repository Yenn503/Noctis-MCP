"""
Noctis-MCP Compilation Engine
==============================

Cross-platform compilation of generated malware code.

This package provides:
- Auto-detection of operating system
- Windows: MSBuild and Visual Studio
- Linux: MinGW-w64 cross-compilation
- Unified API for both platforms

Author: Noctis-MCP Community
License: MIT
"""

import platform
import logging

__version__ = "2.0.0"

logger = logging.getLogger(__name__)

# Platform-specific imports
if platform.system() == "Windows":
    from .windows_compiler import WindowsCompiler, ProjectGenerator, MSBuildDetector, ErrorParser
    __all__ = ["WindowsCompiler", "ProjectGenerator", "MSBuildDetector", "ErrorParser", "get_compiler"]
else:
    # Linux/Unix - use MinGW cross-compilation
    from .linux_compiler import LinuxCompiler, MinGWDetector, ErrorParser
    __all__ = ["LinuxCompiler", "MinGWDetector", "ErrorParser", "get_compiler"]


def get_compiler(output_dir: str = "compiled"):
    """
    Get the appropriate compiler for the current platform.
    
    Returns:
        WindowsCompiler on Windows, LinuxCompiler on Linux/Unix
    
    Example:
        compiler = get_compiler()
        result = compiler.compile(source_code, architecture="x64")
    """
    system = platform.system()
    
    if system == "Windows":
        logger.info("Detected Windows - using MSBuild compiler")
        from .windows_compiler import WindowsCompiler
        return WindowsCompiler(output_dir=output_dir)
    else:
        logger.info(f"Detected {system} - using MinGW cross-compiler")
        from .linux_compiler import LinuxCompiler
        return LinuxCompiler(output_dir=output_dir)

