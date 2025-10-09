"""Simple MinGW Compiler Wrapper"""
import subprocess
from pathlib import Path
import os

def compile_malware(source_file, target_edr, architecture="x64"):
    """
    Compile malware with auto-detected dependencies

    Args:
        source_file: Path to .c file
        target_edr: Target EDR (for optimizations)
        architecture: x64 or x86

    Returns:
        dict with success, binary_path, etc.
    """

    source_path = Path(source_file)
    if not source_path.exists():
        return {"success": False, "error": f"Source file not found: {source_file}"}

    # Output directory
    output_dir = Path("compiled")
    output_dir.mkdir(exist_ok=True)

    # Output binary name
    binary_name = source_path.stem + ".exe"
    binary_path = output_dir / binary_name

    # Detect compiler
    if architecture == "x64":
        compiler = "x86_64-w64-mingw32-gcc"
    else:
        compiler = "i686-w64-mingw32-gcc"

    # Check if compiler exists
    try:
        subprocess.run([compiler, "--version"], capture_output=True, check=True)
    except:
        return {
            "success": False,
            "error": f"{compiler} not installed",
            "install_cmd": "apt install mingw-w64"
        }

    # Auto-detect dependencies from #include statements
    dependencies = []
    techniques_used = []

    with open(source_path, 'r') as f:
        content = f.read()

        # Check for technique includes
        if 'zilean.h' in content:
            dependencies.append('techniques/sleep_obfuscation/zilean.c')
            techniques_used.append('zilean')
        if 'shellcode_fluctuation.h' in content:
            dependencies.append('techniques/sleep_obfuscation/shellcode_fluctuation.c')
            techniques_used.append('shellcode_fluctuation')
        if 'peruns_fart.h' in content:
            dependencies.append('techniques/unhooking/peruns_fart.c')
            techniques_used.append('peruns_fart')
        if 'silentmoonwalk.h' in content:
            dependencies.append('techniques/evasion/silentmoonwalk.c')
            techniques_used.append('silentmoonwalk')
        if 'syswhispers3.h' in content:
            dependencies.append('techniques/syscalls/syswhispers3.c')
            techniques_used.append('syswhispers3')
        if 'poolparty.h' in content:
            dependencies.append('techniques/injection/poolparty.c')
            techniques_used.append('poolparty')
        if 'early_cascade.h' in content:
            dependencies.append('techniques/injection/early_cascade.c')
            techniques_used.append('early_cascade')

    # Build compile command
    cmd = [
        compiler,
        str(source_path),
        *dependencies,
        "-o", str(binary_path),
        "-O2",
        "-s",  # Strip symbols
        "-lbcrypt",
        "-lwinhttp",
        "-lntdll",
        "-I", "techniques"
    ]

    # EDR-specific optimizations
    if "CrowdStrike" in target_edr or "SentinelOne" in target_edr:
        cmd.extend(["-fno-stack-protector", "-Wl,--no-seh"])

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

        if result.returncode == 0:
            binary_size = os.path.getsize(binary_path)
            return {
                "success": True,
                "source_file": source_file,
                "binary_path": str(binary_path),
                "binary_size": binary_size,
                "techniques": techniques_used,
                "logs": result.stdout + result.stderr
            }
        else:
            return {
                "success": False,
                "error": "Compilation failed",
                "logs": result.stdout + result.stderr
            }

    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "error": "Compilation timed out (60s)"
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }
