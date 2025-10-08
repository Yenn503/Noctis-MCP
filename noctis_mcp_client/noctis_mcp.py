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
  5. noctis_record_result - Record attack results for learning

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
def noctis_search_techniques(query: str, target_av: str = "Windows Defender", n_results: int = 10) -> Dict[str, Any]:
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
        return {"error": "Noctis server not running. Start with: ./start_server.sh"}

    try:
        response = session.post(f"{SERVER_URL}/api/v2/search", json={
            "query": query,
            "target_av": target_av,
            "n_results": n_results
        }, timeout=30)

        if response.status_code == 200:
            return response.json()
        else:
            return {"error": f"Search failed: {response.text}"}

    except Exception as e:
        return {"error": str(e)}


@mcp.tool()
def noctis_recommend_template(objective: str) -> Dict[str, Any]:
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
        return {"error": "Noctis server not running. Start with: ./start_server.sh"}

    try:
        response = session.post(f"{SERVER_URL}/api/v2/recommend", json={
            "objective": objective
        }, timeout=30)

        if response.status_code == 200:
            return response.json()
        else:
            return {"error": f"Recommendation failed: {response.text}"}

    except Exception as e:
        return {"error": str(e)}


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


if __name__ == "__main__":
    logger.info("Noctis-MCP Server Starting...")
    logger.info(f"Client OS: {CLIENT_OS}")
    logger.info(f"Server URL: {SERVER_URL}")

    if check_server():
        logger.info("Noctis server is accessible")
    else:
        logger.warning("Noctis server not running. Start with: ./start_server.sh")

    mcp.run(transport='stdio')
