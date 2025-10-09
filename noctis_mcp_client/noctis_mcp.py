#!/usr/bin/env python3
"""
Noctis-MCP - Professional Red Team Malware Development Platform
================================================================

MCP Tools for IDE Integration (Cursor, VSCode, etc.)

Core Tools:
  1. noctis_search_techniques - Search technique knowledge base
  2. noctis_recommend_template - Get template recommendation
  3. noctis_generate_beacon - Generate C2 beacon shellcode
  4. noctis_compile - Compile malware for target OS
  5. noctis_test_binary - Test binary against 70+ AVs via VirusTotal
  6. noctis_record_result - Record attack results for learning

For authorized red team operations only.
"""

import sys
import os
import platform
import logging
from typing import Dict, Any, Optional, List
import requests
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from fastmcp import FastMCP
except ImportError:
    print("[!] FastMCP not installed. Run: pip install fastmcp")
    sys.exit(1)

mcp = FastMCP("Noctis-MCP")

SERVER_URL = "http://localhost:8888"
session = requests.Session()
CLIENT_OS = platform.system()

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
logger = logging.getLogger("noctis-mcp")


def check_server() -> bool:
    """Check if Noctis server is accessible"""
    try:
        response = session.get(f"{SERVER_URL}/health", timeout=5)
        return response.status_code == 200
    except:
        return False


@mcp.tool()
def noctis_search_techniques(query: str, target_av: str = "Windows Defender", n_results: int = 10) -> str:
    """
    Search technique knowledge base using RAG.

    Args:
        query: Search query (e.g., "bypass CrowdStrike", "process injection")
        target_av: Target antivirus (e.g., "CrowdStrike", "Defender", "SentinelOne")
        n_results: Number of results to return (default: 10)

    Returns:
        Dict with technique implementations and code snippets

    Example:
        noctis_search_techniques("bypass CrowdStrike", "CrowdStrike", 5)
    """
    if not check_server():
        return "ERROR: Noctis server not running. Start with: python3 server/noctis_server.py"

    try:
        response = session.post(f"{SERVER_URL}/api/v2/search", json={
            "query": query,
            "target_av": target_av,
            "n_results": n_results
        }, timeout=30)

        if response.status_code == 200:
            data = response.json()

            # Build clean formatted output
            output = []
            output.append("=" * 80)
            output.append("TECHNIQUE SEARCH RESULTS")
            output.append("=" * 80)

            summary = data.get('summary', {})
            output.append(f"\n🔍 Query: {summary.get('query', 'N/A')}")
            output.append(f"🎯 Target AV: {summary.get('target_av', 'N/A')}")
            output.append(f"📊 Results Found: {summary.get('results_found', 0)}")

            if data.get('tip'):
                output.append(f"\n💡 {data['tip']}")

            # Format search results
            if 'results' in data and isinstance(data['results'], list):
                output.append("\n" + "=" * 80)
                output.append("TOP RESULTS")
                output.append("=" * 80)

                for idx, result in enumerate(data['results'][:5], 1):
                    relevance = result.get('relevance_score', 0)
                    source = result.get('source_file', result.get('metadata', {}).get('source', 'unknown'))
                    content = result.get('content', '')[:250]

                    output.append(f"\n[{idx}] Relevance: {relevance:.1%}")
                    output.append(f"    Source: {source}")
                    output.append(f"    {content}...")
                    output.append("-" * 80)

            # Format next steps
            if 'next_steps' in data:
                output.append("\n" + "=" * 80)
                output.append("NEXT STEPS")
                output.append("=" * 80)
                for step in data['next_steps']:
                    output.append(f"  {step}")

            return "\n".join(output)
        else:
            return f"ERROR: Search failed - {response.text}"

    except Exception as e:
        return f"ERROR: {str(e)}"


@mcp.tool()
def noctis_recommend_template(objective: str) -> str:
    """
    Get template recommendation based on your objective.

    Args:
        objective: What you want to build (e.g., "C2 beacon", "bypass EDR", "process injection")

    Returns:
        Dict with template file, techniques, and modification instructions

    Example:
        noctis_recommend_template("C2 beacon to bypass CrowdStrike")
    """
    if not check_server():
        return "ERROR: Noctis server not running. Start with: python3 server/noctis_server.py"

    try:
        response = session.post(f"{SERVER_URL}/api/v2/recommend", json={
            "objective": objective
        }, timeout=30)

        if response.status_code == 200:
            data = response.json()

            # Build clean formatted output
            output = []
            output.append("=" * 70)
            output.append("TEMPLATE RECOMMENDATION")
            output.append("=" * 70)

            rec = data.get('recommendation', {})
            output.append(f"\n📋 Template: {rec.get('template_file', 'N/A')}")
            output.append(f"📊 OPSEC Score: {rec.get('opsec_score', 'N/A')}")
            output.append(f"⚠️  Detection Risk: {rec.get('detection_risk', 'N/A')}")

            techniques = rec.get('techniques_included', [])
            if isinstance(techniques, list):
                tech_str = ', '.join(techniques)
            else:
                tech_str = str(techniques)
            output.append(f"🎯 Techniques: {tech_str}")

            output.append(f"\n💡 Why This Template:")
            output.append(f"   {data.get('why_this_template', 'N/A')}")

            output.append(f"\n⚡ Tip: {data.get('tip', 'N/A')}")

            # Format techniques list
            if 'available_techniques' in data and isinstance(data['available_techniques'], list):
                output.append("\n" + "=" * 70)
                output.append("AVAILABLE TECHNIQUES")
                output.append("=" * 70)
                for i, tech in enumerate(data['available_techniques'], 1):
                    output.append(f"\n[{i}] {tech['name']}")
                    output.append(f"    File: {tech['file']}")
                    output.append(f"    Description: {tech['description']}")
                    output.append(f"    OPSEC: {tech['opsec_score']} | Bypasses: {tech['bypasses']}")

            # Format next steps
            if 'next_steps' in data:
                output.append("\n" + "=" * 70)
                output.append("NEXT STEPS")
                output.append("=" * 70)
                for step in data['next_steps']:
                    output.append(f"  {step}")

            return "\n".join(output)
        else:
            return f"ERROR: Recommendation failed - {response.text}"

    except Exception as e:
        return f"ERROR: {str(e)}"


@mcp.tool()
def noctis_generate_beacon(
    c2_framework: str,
    listener_host: str,
    listener_port: int = 443,
    architecture: str = "x64",
    format: str = "shellcode"
) -> Dict[str, Any]:
    """
    Generate C2 beacon shellcode for specified framework.

    Args:
        c2_framework: C2 framework to use ("sliver", "adaptix", "mythic")
        listener_host: IP address of C2 listener
        listener_port: Port of C2 listener (default: 443)
        architecture: Target architecture ("x64" or "x86", default: "x64")
        format: Output format ("shellcode", "exe", "dll", default: "shellcode")

    Returns:
        Dict with shellcode path, size, and integration instructions

    Example:
        noctis_generate_beacon("sliver", "10.0.0.1", 443, "x64", "shellcode")
    """
    if not check_server():
        return {"error": "Noctis server not running. Start with: ./start_server.sh"}

    try:
        response = session.post(f"{SERVER_URL}/api/v2/generate_beacon", json={
            "c2_framework": c2_framework,
            "listener_host": listener_host,
            "listener_port": listener_port,
            "architecture": architecture,
            "format": format
        }, timeout=60)

        if response.status_code == 200:
            return response.json()
        elif response.status_code == 503:
            data = response.json()
            return {
                "error": data.get("error"),
                "install_command": data.get("install_command"),
                "install_instructions": data.get("install_instructions")
            }
        else:
            return {"error": f"Beacon generation failed: {response.text}"}

    except Exception as e:
        return {"error": str(e)}


@mcp.tool()
def noctis_compile(
    source_file: str,
    target_os: str = "windows",
    architecture: str = "x64",
    optimization: str = "release"
) -> Dict[str, Any]:
    """
    Compile malware for target operating system.

    Args:
        source_file: Path to source code file (e.g., "malware.c")
        target_os: Target OS ("windows" or "linux", default: "windows")
        architecture: Target architecture ("x64" or "x86", default: "x64")
        optimization: Optimization level ("debug" or "release", default: "release")

    Returns:
        Dict with binary path, file size, and compilation logs

    Example:
        noctis_compile("malware.c", "windows", "x64", "release")
    """
    if not check_server():
        return {"error": "Noctis server not running. Start with: ./start_server.sh"}

    try:
        response = session.post(f"{SERVER_URL}/api/v2/compile", json={
            "source_file": source_file,
            "target_os": target_os,
            "architecture": architecture,
            "optimization": optimization
        }, timeout=120)

        if response.status_code == 200:
            return response.json()
        else:
            return {"error": f"Compilation failed: {response.text}"}

    except Exception as e:
        return {"error": str(e)}


@mcp.tool()
def noctis_record_result(
    template: str,
    techniques: List[str],
    target_av: str,
    detected: bool,
    notes: str = ""
) -> Dict[str, Any]:
    """
    Record attack result for learning system.

    Args:
        template: Template used (e.g., "integrated_loader", "beacon_stealth")
        techniques: List of techniques used (e.g., ["poolparty", "zilean"])
        target_av: Target AV tested against (e.g., "CrowdStrike", "Defender")
        detected: Whether attack was detected (True) or bypassed (False)
        notes: Optional notes about the attack (e.g., "Bypassed successfully on Windows 11")

    Returns:
        Dict with confirmation and updated statistics

    Example:
        noctis_record_result("beacon_stealth", ["poolparty", "zilean"], "CrowdStrike", False, "Bypassed successfully")
    """
    if not check_server():
        return {"error": "Noctis server not running. Start with: ./start_server.sh"}

    try:
        response = session.post(f"{SERVER_URL}/api/v2/record_result", json={
            "template": template,
            "techniques": techniques,
            "target_av": target_av,
            "detected": detected,
            "notes": notes
        }, timeout=30)

        if response.status_code == 200:
            return response.json()
        else:
            return {"error": f"Recording failed: {response.text}"}

    except Exception as e:
        return {"error": str(e)}


@mcp.tool()
def noctis_test_binary(
    binary_path: str,
    target_av: str = "Windows Defender",
    max_wait: int = 300
) -> str:
    """
    Test compiled binary against 70+ AV engines via VirusTotal.

    ⚠️  IMPORTANT WARNINGS:
    1. Requires VirusTotal API key in .env file (get free key at: https://www.virustotal.com/gui/my-apikey)
    2. DO NOT test your final production binary on VirusTotal!
       - VT shares samples with AV vendors
       - Use VT only for development/testing iterations
       - For production: Test locally, keep final binary off VT

    RECOMMENDED WORKFLOW:
    1. Test early prototypes on VT to see what's detected
    2. Iterate and improve based on VT results
    3. When happy with detection rate, compile final version
    4. DO NOT upload final version to VT
    5. Deploy final version in target environment

    Rate limits (free API):
    - 4 requests/minute (perfect for testing individual binaries)
    - 500 requests/day
    - 15.5K requests/month

    Args:
        binary_path: Path to compiled binary (e.g., "compiled/malware.exe")
        target_av: Target AV to check specifically (e.g., "CrowdStrike", "Defender")
        max_wait: Maximum seconds to wait for analysis (default: 300)

    Returns:
        Detection results with per-AV breakdown and OPSEC assessment

    Example:
        noctis_test_binary("compiled/test_v1.exe", "CrowdStrike", 300)
    """
    if not check_server():
        return "ERROR: Noctis server not running. Start with: python3 server/noctis_server.py"

    try:
        response = session.post(f"{SERVER_URL}/api/v2/test_binary", json={
            "binary_path": binary_path,
            "target_av": target_av,
            "max_wait": max_wait
        }, timeout=max_wait + 60)  # Extra buffer for network overhead

        if response.status_code == 200:
            data = response.json()

            # Build clean formatted output
            output = []
            output.append("=" * 80)
            output.append("VIRUSTOTAL DETECTION TEST")
            output.append("=" * 80)

            if not data.get('success'):
                output.append(f"\n❌ Error: {data.get('error', 'Unknown error')}")
                if 'setup_instructions' in data:
                    output.append("\n📋 SETUP INSTRUCTIONS:")
                    for key, value in data['setup_instructions'].items():
                        output.append(f"  {key}: {value}")
                return "\n".join(output)

            # Test results
            test_results = data.get('test_results', {})
            output.append(f"\n📦 Binary: {test_results.get('binary', 'N/A')}")
            output.append(f"🔑 SHA256: {test_results.get('file_hash', 'N/A')}")
            output.append(f"📅 Scan Date: {test_results.get('scan_date', 'N/A')}")
            output.append(f"💾 Cached: {'Yes (previous scan)' if test_results.get('cached') else 'No (new scan)'}")

            # Detection summary
            summary = data.get('detection_summary', {})
            output.append("\n" + "=" * 80)
            output.append("DETECTION SUMMARY")
            output.append("=" * 80)
            output.append(f"Total Engines: {summary.get('total_engines', 0)}")
            output.append(f"Detected By: {summary.get('detected_by', 0)}")
            output.append(f"Undetected By: {summary.get('undetected_by', 0)}")
            output.append(f"Detection Rate: {summary.get('detection_rate', '0%')}")
            output.append(f"\n🎯 OPSEC Assessment: {summary.get('opsec_assessment', 'Unknown')}")

            # Target AV result
            target = data.get('target_av_result', {})
            output.append("\n" + "=" * 80)
            output.append(f"TARGET AV: {target.get('av_name', 'N/A')}")
            output.append("=" * 80)
            output.append(f"Status: {target.get('status', 'Unknown')}")
            output.append(f"Result: {target.get('result', 'N/A')}")

            # Top detections
            if data.get('top_detections'):
                output.append("\n" + "=" * 80)
                output.append("TOP DETECTIONS (First 5)")
                output.append("=" * 80)
                for i, detection in enumerate(data['top_detections'][:5], 1):
                    output.append(f"{i}. {detection['av']}")
                    output.append(f"   Category: {detection['category']}")
                    output.append(f"   Signature: {detection['signature']}")

            # Insights
            if data.get('insights'):
                output.append("\n" + "=" * 80)
                output.append("INSIGHTS")
                output.append("=" * 80)
                for insight in data['insights']:
                    output.append(f"  {insight}")

            # Next steps
            if data.get('next_steps'):
                output.append("\n" + "=" * 80)
                output.append("NEXT STEPS")
                output.append("=" * 80)
                for i, step in enumerate(data['next_steps'], 1):
                    output.append(f"  {i}. {step}")

            # Tip
            if data.get('tip'):
                output.append(f"\n💡 Tip: {data['tip']}")

            # VT link
            if data.get('virustotal_link'):
                output.append(f"\n🔗 View full report: {data['virustotal_link']}")

            output.append("\n" + "=" * 80)

            return "\n".join(output)

        elif response.status_code == 503:
            data = response.json()
            output = []
            output.append("=" * 80)
            output.append("VIRUSTOTAL NOT CONFIGURED")
            output.append("=" * 80)
            output.append(f"\n❌ {data.get('error', 'VirusTotal unavailable')}")

            if 'setup_instructions' in data:
                output.append("\n📋 SETUP INSTRUCTIONS:")
                for key, value in data['setup_instructions'].items():
                    output.append(f"  {key.replace('_', ' ').title()}: {value}")

            if data.get('alternative'):
                output.append(f"\n💡 Alternative: {data['alternative']}")

            return "\n".join(output)

        else:
            return f"ERROR: Test failed with status {response.status_code}: {response.text}"

    except Exception as e:
        return f"ERROR: {str(e)}"


if __name__ == "__main__":
    logger.info("Noctis-MCP Server Starting...")
    logger.info(f"Client OS: {CLIENT_OS}")
    logger.info(f"Server URL: {SERVER_URL}")

    if check_server():
        logger.info("Noctis server is accessible")
    else:
        logger.warning("Noctis server not running. Start with: ./start_server.sh")

    mcp.run(transport='stdio')
