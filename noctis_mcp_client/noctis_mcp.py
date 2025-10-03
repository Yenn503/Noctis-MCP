#!/usr/bin/env python3
"""
Noctis-MCP Client - FastMCP Integration for AI-Driven Malware Development
==========================================================================

Connects AI assistants (Cursor, Claude, etc.) to the Noctis-MCP server
for dynamic malware development using real techniques from MaldevAcademy.

Author: Noctis-MCP Community (@Yenn)
License: MIT
Version: 1.0.0-alpha

WARNING: For authorized security research and red team operations only.
Unauthorized use is illegal and unethical.

Architecture:
- FastMCP server exposing malware development tools
- Connects to Noctis API server (default: http://localhost:8888)
- Provides AI with access to 126+ malware techniques
- Enables intelligent code generation and assembly

Usage:
    python mcp/noctis_mcp.py --server http://localhost:8888
"""

import sys
import os
import argparse
import logging
from typing import Dict, Any, Optional, List
import requests
from datetime import datetime
import json

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from fastmcp import FastMCP
except ImportError:
    print("[!] FastMCP not installed. Installing...")
    print("[!] Run: pip install fastmcp")
    sys.exit(1)

# Initialize FastMCP server
mcp = FastMCP("Noctis-MCP")

# Global configuration
SERVER_URL = "http://localhost:8888"
session = requests.Session()


# ============================================================================
# LOGGING SETUP
# ============================================================================

class NoctisFormatter(logging.Formatter):
    """Custom formatter with timestamps and log levels"""
    
    FORMATS = {
        logging.DEBUG: "[%(asctime)s] [DEBUG] %(message)s",
        logging.INFO: "[%(asctime)s] [*] %(message)s",
        logging.WARNING: "[%(asctime)s] [!] %(message)s",
        logging.ERROR: "[%(asctime)s] [ERROR] %(message)s",
        logging.CRITICAL: "[%(asctime)s] [CRITICAL] %(message)s",
    }
    
    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt, datefmt='%H:%M:%S')
        return formatter.format(record)


def setup_logging(level: str = "INFO") -> logging.Logger:
    """Setup logging for MCP client"""
    logger = logging.getLogger("noctis-mcp")
    logger.setLevel(getattr(logging, level.upper()))
    
    # Console handler
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    ch.setFormatter(NoctisFormatter())
    
    logger.addHandler(ch)
    return logger


logger = setup_logging()


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def check_server() -> bool:
    """Check if Noctis API server is accessible"""
    try:
        response = session.get(f"{SERVER_URL}/health", timeout=5)
        return response.status_code == 200
    except Exception as e:
        logger.error(f"Cannot connect to server: {e}")
        return False


def api_get(endpoint: str, params: Optional[Dict] = None) -> Dict:
    """Make GET request to API server"""
    try:
        url = f"{SERVER_URL}{endpoint}"
        response = session.get(url, params=params, timeout=10)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        logger.error(f"API GET error: {e}")
        return {'success': False, 'error': str(e)}


def api_post(endpoint: str, data: Dict) -> Dict:
    """Make POST request to API server"""
    try:
        url = f"{SERVER_URL}{endpoint}"
        response = session.post(url, json=data, timeout=30)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        logger.error(f"API POST error: {e}")
        return {'success': False, 'error': str(e)}


# ============================================================================
# FASTMCP TOOLS - TECHNIQUE QUERYING
# ============================================================================

@mcp.tool()
def query_techniques(
    category: Optional[str] = None,
    mitre_ttp: Optional[str] = None,
    search: Optional[str] = None
) -> str:
    """
    Query available malware techniques from the Noctis database.
    
    This tool searches through 126+ real malware techniques from MaldevAcademy
    and TheSilencer. Use it to discover available evasion, injection, 
    encryption, and other offensive techniques.
    
    Args:
        category: Filter by category (api_hashing, syscalls, gpu_evasion, 
                 encryption, steganography, injection, persistence, unhooking)
        mitre_ttp: Filter by MITRE ATT&CK TTP (e.g., T1055, T1027, T1106)
        search: Search by keyword in name or description
    
    Returns:
        JSON string with matching techniques and their details
    
    Example:
        query_techniques(category="syscalls")
        query_techniques(search="API hashing")
        query_techniques(mitre_ttp="T1055")
    """
    logger.info(f"Querying techniques - category={category}, mitre={mitre_ttp}, search={search}")
    
    # Build query parameters
    params = {}
    if category:
        params['category'] = category
    if mitre_ttp:
        params['mitre'] = mitre_ttp
    if search:
        params['search'] = search
    
    # Query API
    result = api_get('/api/techniques', params=params)
    
    if not result.get('success', False):
        return json.dumps({
            'success': False,
            'error': result.get('error', 'Unknown error'),
            'techniques': []
        }, indent=2)
    
    techniques = result.get('techniques', [])
    
    # Format output
    output = {
        'success': True,
        'count': len(techniques),
        'query': {
            'category': category,
            'mitre_ttp': mitre_ttp,
            'search': search
        },
        'techniques': []
    }
    
    # Add technique details
    for tech in techniques:
        output['techniques'].append({
            'id': tech.get('technique_id'),
            'name': tech.get('name'),
            'category': tech.get('category'),
            'description': tech.get('description'),
            'mitre_ttps': tech.get('mitre_ttps', []),
            'source_files': tech.get('source_files', []),
            'complexity': tech.get('complexity', 'unknown')
        })
    
    return json.dumps(output, indent=2)


@mcp.tool()
def get_technique_details(technique_id: str) -> str:
    """
    Get detailed information about a specific technique.
    
    Returns comprehensive details including source files, functions,
    dependencies, MITRE mappings, and implementation notes.
    
    Args:
        technique_id: The technique ID (e.g., NOCTIS-T001, NOCTIS-T124)
    
    Returns:
        JSON string with complete technique details
    
    Example:
        get_technique_details("NOCTIS-T124")
    """
    logger.info(f"Getting details for technique: {technique_id}")
    
    result = api_get(f'/api/techniques/{technique_id}')
    
    if not result.get('success', False):
        return json.dumps({
            'success': False,
            'error': f'Technique {technique_id} not found'
        }, indent=2)
    
    technique = result.get('technique', {})
    
    return json.dumps({
        'success': True,
        'technique': technique
    }, indent=2)


@mcp.tool()
def list_categories() -> str:
    """
    List all available technique categories.
    
    Shows all categories of malware techniques available in the database,
    with counts of techniques in each category.
    
    Returns:
        JSON string with categories and technique counts
    
    Example:
        list_categories()
    """
    logger.info("Listing technique categories")
    
    result = api_get('/api/categories')
    
    if not result.get('success', False):
        return json.dumps({
            'success': False,
            'error': 'Failed to fetch categories'
        }, indent=2)
    
    return json.dumps({
        'success': True,
        'categories': result.get('categories', {})
    }, indent=2)


@mcp.tool()
def get_statistics() -> str:
    """
    Get comprehensive statistics about the technique database.
    
    Returns information about total techniques, categories, MITRE coverage,
    source files, and more.
    
    Returns:
        JSON string with database statistics
    
    Example:
        get_statistics()
    """
    logger.info("Getting database statistics")
    
    result = api_get('/api/stats')
    
    if not result.get('success', False):
        return json.dumps({
            'success': False,
            'error': 'Failed to fetch statistics'
        }, indent=2)
    
    return json.dumps({
        'success': True,
        'statistics': result.get('statistics', {})
    }, indent=2)


@mcp.tool()
def get_mitre_mappings(ttp: Optional[str] = None) -> str:
    """
    Get MITRE ATT&CK framework mappings for techniques.
    
    Shows which techniques map to which MITRE ATT&CK TTPs,
    useful for understanding defensive coverage and attack chains.
    
    Args:
        ttp: Optional specific TTP to filter by (e.g., T1055)
    
    Returns:
        JSON string with MITRE mappings
    
    Example:
        get_mitre_mappings()
        get_mitre_mappings(ttp="T1055")
    """
    logger.info(f"Getting MITRE mappings - TTP={ttp}")
    
    params = {'ttp': ttp} if ttp else {}
    result = api_get('/api/mitre', params=params)
    
    if not result.get('success', False):
        return json.dumps({
            'success': False,
            'error': 'Failed to fetch MITRE mappings'
        }, indent=2)
    
    return json.dumps({
        'success': True,
        'mitre_mappings': result.get('mitre_mappings', {})
    }, indent=2)


# ============================================================================
# FASTMCP TOOLS - CODE GENERATION
# ============================================================================

@mcp.tool()
def generate_malware(
    techniques: List[str],
    target_os: str = "Windows",
    target_av: Optional[str] = None,
    payload_type: str = "loader",
    architecture: str = "x64",
    obfuscate_strings: bool = False,
    obfuscate_apis: bool = False,
    encryption_method: str = "xor",
    hash_method: str = "djb2",
    flatten_control_flow: bool = False,
    insert_junk_code: bool = False,
    junk_density: str = "medium",
    polymorphic: bool = False,
    mutation_level: str = "medium"
) -> str:
    """
    Generate malware code by combining multiple techniques.
    
    This is the main code generation tool. It takes a list of technique IDs
    and intelligently combines them into working C/C++ malware code with optional obfuscation.
    
    Args:
        techniques: List of technique IDs to combine (e.g., ["NOCTIS-T124", "NOCTIS-T118"])
        target_os: Target operating system (default: "Windows")
        target_av: Target antivirus/EDR to evade (optional)
        payload_type: Type of payload (loader, shellcode_runner, injector, dropper)
        architecture: Target architecture (x86, x64, arm64)
        obfuscate_strings: Encrypt strings with XOR/AES/RC4 (default: False)
        obfuscate_apis: Hash API calls to hide imports (default: False)
        encryption_method: String encryption: xor, aes, rc4 (default: "xor")
        hash_method: API hashing: djb2, rot13xor, crc32 (default: "djb2")
        flatten_control_flow: Transform control flow into state machine (default: False)
        polymorphic: Generate unique code variant (default: False)
        mutation_level: Polymorphic mutation: low, medium, high (default: "medium")
        insert_junk_code: Add dead code for complexity (default: False)
        junk_density: Junk code amount: low, medium, high (default: "medium")
    
    Returns:
        JSON string with generated code, metadata, and compilation info
    
    Example:
        generate_malware(
            techniques=["NOCTIS-T124", "NOCTIS-T118"],
            target_os="Windows",
            target_av="Windows Defender",
            payload_type="loader",
            architecture="x64",
            obfuscate_strings=True,
            obfuscate_apis=True,
            flatten_control_flow=True,
            insert_junk_code=True,
            junk_density="high"
        )
    """
    logger.info(f"Generating malware - techniques={techniques}, obfuscation={obfuscate_strings or obfuscate_apis}")
    
    # Validate input
    if not techniques or not isinstance(techniques, list):
        return json.dumps({
            'success': False,
            'error': 'techniques must be a non-empty list of technique IDs'
        }, indent=2)
    
    # Prepare request data
    request_data = {
        'techniques': techniques,
        'target_os': target_os,
        'payload_type': payload_type,
        'obfuscate_strings': obfuscate_strings,
        'obfuscate_apis': obfuscate_apis,
        'encryption_method': encryption_method,
        'hash_method': hash_method,
        'flatten_control_flow': flatten_control_flow,
        'insert_junk_code': insert_junk_code,
        'junk_density': junk_density,
        'polymorphic': polymorphic,
        'mutation_level': mutation_level,
        'options': {
            'architecture': architecture,
            'target_av': target_av
        }
    }
    
    # Call API
    result = api_post('/api/generate', request_data)
    
    if not result.get('success', False):
        return json.dumps({
            'success': False,
            'error': result.get('error', 'Code generation failed'),
            'details': result.get('message', '')
        }, indent=2)
    
    return json.dumps({
        'success': True,
        'message': 'Code generated successfully',
        'code': result.get('code', ''),
        'metadata': {
            'techniques_used': techniques,
            'target_os': target_os,
            'payload_type': payload_type,
            'architecture': architecture,
            'generated_at': datetime.now().isoformat()
        },
        'obfuscation': result.get('obfuscation', {}),
        'compilation': {
            'compiler': result.get('compiler', 'MSBuild'),
            'flags': result.get('compiler_flags', []),
            'dependencies': result.get('dependencies', [])
        }
    }, indent=2)


@mcp.tool()
def assemble_code(
    technique_ids: List[str],
    include_main: bool = True,
    optimization: str = "basic"
) -> str:
    """
    Assemble code from techniques using the code assembler.
    
    Lower-level tool for code assembly. This extracts functions from source
    files and combines them intelligently, handling dependencies and conflicts.
    
    Args:
        technique_ids: List of technique IDs to assemble
        include_main: Whether to include main() function (default: True)
        optimization: Optimization level (none, basic, aggressive)
    
    Returns:
        JSON string with assembled code and metadata
    
    Example:
        assemble_code(
            technique_ids=["NOCTIS-T124", "NOCTIS-T118"],
            include_main=True,
            optimization="basic"
        )
    """
    logger.info(f"Assembling code - techniques={technique_ids}")
    
    # This would call the code assembler directly or via API
    # For now, we'll use the generate endpoint
    
    request_data = {
        'techniques': technique_ids,
        'options': {
            'include_main': include_main,
            'optimization': optimization
        }
    }
    
    result = api_post('/api/assemble', request_data)
    
    return json.dumps(result, indent=2)


# ============================================================================
# FASTMCP TOOLS - COMPILATION & TESTING
# ============================================================================

@mcp.tool()
def compile_code(
    source_code: str,
    architecture: str = "x64",
    optimization: str = "O2",
    output_name: str = "payload",
    auto_fix: bool = False
) -> str:
    """
    Compile generated C/C++ code into an executable.
    
    Uses MSBuild/Visual Studio to compile the generated malware code.
    Handles project file generation, dependency resolution, and compilation.
    Can automatically fix common compilation errors if auto_fix is enabled.
    
    Args:
        source_code: The C/C++ source code to compile
        architecture: Target architecture (x86, x64)
        optimization: Compiler optimization level (O0, O1, O2, O3)
        output_name: Name for the output executable (without .exe)
        auto_fix: Enable automatic error fixing (default: False)
    
    Returns:
        JSON string with compilation results and binary path
    
    Example:
        compile_code(
            source_code="<C code here>",
            architecture="x64",
            optimization="O2",
            output_name="loader",
            auto_fix=True
        )
    """
    logger.info(f"Compiling code - arch={architecture}, opt={optimization}, output={output_name}, auto_fix={auto_fix}")
    
    # Remove .exe extension if provided
    if output_name.endswith('.exe'):
        output_name = output_name[:-4]
    
    request_data = {
        'source_code': source_code,
        'architecture': architecture,
        'optimization': optimization,
        'output_name': output_name,
        'subsystem': 'Console',
        'auto_fix': auto_fix
    }
    
    result = api_post('/api/compile', request_data)
    
    if not result.get('success', False):
        return json.dumps({
            'success': False,
            'error': result.get('error', 'Compilation failed'),
            'errors': result.get('errors', []),
            'warnings': result.get('warnings', []),
            'compilation_time': result.get('compilation_time', 0),
            'help': 'Common issues: Missing Visual Studio Build Tools, syntax errors in code, missing libraries'
        }, indent=2)
    
    # Get file size if binary exists
    import os
    binary_path = result.get('binary_path', '')
    file_size = 0
    if binary_path and os.path.exists(binary_path):
        file_size = os.path.getsize(binary_path)
    
    response_data = {
        'success': True,
        'message': 'Compilation successful!',
        'binary_path': binary_path,
        'file_size_bytes': file_size,
        'file_size_kb': round(file_size / 1024, 2),
        'compilation_time': result.get('compilation_time', 0),
        'warnings': result.get('warnings', []),
        'metadata': result.get('metadata', {}),
        'next_steps': [
            'Test the binary in an isolated environment',
            'Run OPSEC analysis on the code',
            'Check for antivirus detection',
            'Validate functionality'
        ]
    }
    
    # Add auto-fix info if applied
    if result.get('auto_fix_applied', False):
        response_data['auto_fix_applied'] = True
        response_data['auto_fix_details'] = result.get('auto_fix_details', {})
        response_data['message'] = 'Compilation successful after auto-fix!'
    
    return json.dumps(response_data, indent=2)


@mcp.tool()
def analyze_opsec(code: str) -> str:
    """
    Analyze code for OPSEC issues and detection vectors.
    
    Scans code for common detection vectors like suspicious strings,
    API calls, entropy issues, and provides an OPSEC score.
    
    Args:
        code: The source code to analyze
    
    Returns:
        JSON string with OPSEC analysis and recommendations
    
    Example:
        analyze_opsec(code="<C code here>")
    """
    logger.info("Analyzing OPSEC")
    
    request_data = {'code': code}
    result = api_post('/api/analyze/opsec', request_data)
    
    if not result.get('success', False):
        return json.dumps({
            'success': False,
            'error': result.get('error', 'OPSEC analysis failed')
        }, indent=2)
    
    # Extract report
    report = result.get('opsec_report', {})
    
    return json.dumps({
        'success': True,
        'opsec_score': report.get('overall_score', 0),
        'risk_level': report.get('risk_level', 'unknown'),
        'total_issues': report.get('total_issues', 0),
        'issues_by_severity': report.get('issues_by_severity', {}),
        'top_issues': report.get('issues', [])[:10],  # Top 10 issues
        'recommendations': report.get('recommendations', []),
        'statistics': report.get('statistics', {}),
        'interpretation': {
            '10-8': 'Excellent OPSEC - Low detection risk',
            '7-6': 'Good OPSEC - Moderate detection risk',
            '5-4': 'Fair OPSEC - High detection risk',
            '3-0': 'Poor OPSEC - Very high detection risk'
        },
        'next_steps': [
            'Address critical and high severity issues first',
            'Implement recommended evasion techniques',
            'Test against target AV/EDR before deployment',
            'Consider adding more obfuscation'
        ]
    }, indent=2)


# ============================================================================
# FASTMCP PROMPTS - AI GUIDANCE
# ============================================================================

@mcp.prompt()
def malware_development_guide() -> str:
    """
    Comprehensive guide for AI-assisted malware development using Noctis-MCP.
    
    Provides best practices, workflow recommendations, and examples.
    """
    return """
# Noctis-MCP AI Development Guide

## Overview
Noctis-MCP provides 126+ real malware techniques from MaldevAcademy and TheSilencer.
Use these tools to assist in red team operations and security research.

## Workflow

### 1. Discovery Phase
First, explore available techniques:
```
query_techniques(category="syscalls")
get_statistics()
list_categories()
```

### 2. Selection Phase
Choose techniques based on:
- Target OS and architecture
- Evasion requirements (AV/EDR)
- MITRE ATT&CK coverage
- Complexity and compatibility

Example:
```
get_technique_details("NOCTIS-T124")
get_mitre_mappings(ttp="T1055")
```

### 3. Generation Phase
Generate code combining multiple techniques:
```
generate_malware(
    techniques=["NOCTIS-T124", "NOCTIS-T118", "NOCTIS-T095"],
    target_os="Windows",
    target_av="Windows Defender",
    payload_type="loader"
)
```

### 4. Compilation Phase
Compile the generated code:
```
compile_code(
    source_code="<generated code>",
    architecture="x64",
    optimization="O2"
)
```

### 5. OPSEC Analysis
Analyze for detection vectors:
```
analyze_opsec(code="<generated code>")
```

## Available Categories
- **api_hashing**: API hashing techniques (29 techniques)
- **syscalls**: Direct syscalls and unhooking (35 techniques)
- **gpu_evasion**: GPU-based evasion (16 techniques)
- **encryption**: Encryption and obfuscation (23 techniques)
- **steganography**: Steganographic payload hiding (14 techniques)
- **injection**: Process injection techniques (5 techniques)
- **persistence**: Persistence mechanisms (4 techniques)

## Best Practices

1. **Layered Evasion**: Combine multiple technique categories
2. **MITRE Coverage**: Consider full attack chain
3. **OPSEC First**: Always analyze before deployment
4. **Iterative Testing**: Compile and test incrementally
5. **Legal Compliance**: Only for authorized operations

## Example Combinations

### Basic Loader (Windows Defender Evasion)
- API Hashing (NOCTIS-T124)
- Hell's Gate Syscalls (NOCTIS-T118)
- CT-AES Encryption (NOCTIS-T095)

### Advanced Loader (EDR Evasion)
- GPU Evasion (NOCTIS-T076)
- Trap Flag Syscalls (NOCTIS-T119)
- VEH Manipulation (NOCTIS-T120)
- Stack Spoofing (NOCTIS-T121)

### Stealthy Injector
- Process Injection (NOCTIS-T001)
- API Hashing (NOCTIS-T124)
- DWT Steganography (NOCTIS-T089)

## Legal & Ethical Notice
This tool is for AUTHORIZED security research and red team operations ONLY.
Unauthorized use is illegal and unethical. Always obtain proper authorization.
"""


@mcp.prompt()
def quick_start() -> str:
    """Quick start guide for new users."""
    return """
# Noctis-MCP Quick Start

## 1. Check Server Connection
First, verify the Noctis API server is running:
```bash
python server/noctis_server.py
```

## 2. Explore Techniques
```
get_statistics()
list_categories()
query_techniques(category="syscalls")
```

## 3. Generate Your First Loader
```
generate_malware(
    techniques=["NOCTIS-T124", "NOCTIS-T118"],
    target_os="Windows",
    payload_type="loader"
)
```

## 4. Compile
```
compile_code(source_code="<your generated code>", architecture="x64")
```

That's it! You're ready to build advanced malware with AI assistance.
"""


# ============================================================================
# C2 INTEGRATION TOOLS (Phase 4)
# ============================================================================

@mcp.tool()
def generate_sliver_beacon(
    listener_host: str,
    listener_port: int,
    protocol: str = "https",
    architecture: str = "x64",
    techniques: Optional[List[str]] = None,
    obfuscate: bool = True
) -> str:
    """
    Generate a Sliver C2 beacon with Noctis obfuscation techniques.
    
    This tool creates production-ready Sliver beacons with advanced evasion.
    
    Requirements:
        - Sliver C2 must be installed and running
        - sliver-client must be in PATH
    
    Args:
        listener_host: C2 listener hostname or IP (e.g., "192.168.1.100" or "c2.example.com")
        listener_port: C2 listener port (e.g., 443 for HTTPS, 53 for DNS)
        protocol: C2 protocol - "https", "http", "dns", "tcp", or "mtls" (default: "https")
        architecture: Target architecture - "x64" or "x86" (default: "x64")
        techniques: List of Noctis technique IDs to apply (e.g., ["NOCTIS-T124", "NOCTIS-T118"])
        obfuscate: Apply Noctis obfuscation (string encryption, API hashing, polymorphic, etc.)
    
    Returns:
        JSON with beacon generation results including path, size, OPSEC score
    
    Example:
        generate_sliver_beacon(
            listener_host="192.168.1.100",
            listener_port=443,
            protocol="https",
            techniques=["NOCTIS-T124"],
            obfuscate=True
        )
    """
    logger.info(f"Generating Sliver beacon: {protocol}://{listener_host}:{listener_port}")
    
    # Prepare request data
    request_data = {
        'listener_host': listener_host,
        'listener_port': listener_port,
        'protocol': protocol,
        'architecture': architecture,
        'techniques': techniques or [],
        'obfuscate': obfuscate
    }
    
    # Call C2 API endpoint
    result = api_post('/api/c2/sliver/generate', request_data)
    
    if not result.get('success', False):
        return json.dumps({
            'success': False,
            'error': result.get('error', 'Sliver beacon generation failed'),
            'details': result.get('message', ''),
            'help': 'Make sure Sliver C2 is installed and running. See INSTALL_SLIVER.md'
        }, indent=2)
    
    return json.dumps({
        'success': True,
        'message': f'Sliver {protocol.upper()} beacon generated successfully',
        'beacon_path': result.get('beacon_path'),
        'shellcode_path': result.get('shellcode_path'),
        'beacon_size': result.get('beacon_size'),
        'opsec_score': result.get('opsec_score'),
        'techniques_applied': result.get('techniques_applied', []),
        'obfuscation_summary': result.get('obfuscation_summary', {}),
        'compilation_time': result.get('compilation_time'),
        'c2_info': {
            'protocol': protocol,
            'listener': f"{listener_host}:{listener_port}",
            'architecture': architecture
        },
        'next_steps': [
            f"1. Start Sliver listener: sliver > {protocol} -L {listener_host} -l {listener_port}",
            f"2. Deploy beacon: {result.get('beacon_path', 'beacon.exe')}",
            "3. Wait for callback in Sliver console"
        ]
    }, indent=2)


@mcp.tool()
def list_c2_frameworks() -> str:
    """
    List all supported C2 frameworks and their capabilities.
    
    Shows which C2 frameworks are integrated with Noctis-MCP,
    their status, supported protocols, and features.
    
    Returns:
        JSON with all supported C2 frameworks
    
    Example:
        list_c2_frameworks()
    """
    logger.info("Listing C2 frameworks")
    
    result = api_get('/api/c2/frameworks')
    
    if not result.get('success', False):
        return json.dumps({
            'success': False,
            'error': 'Failed to retrieve C2 frameworks'
        }, indent=2)
    
    frameworks = result.get('frameworks', [])
    
    return json.dumps({
        'success': True,
        'frameworks': frameworks,
        'total': len(frameworks),
        'implemented': len([f for f in frameworks if f.get('status') == 'implemented']),
        'summary': {
            f['name']: {
                'status': f['status'],
                'protocols': f['protocols'],
                'architectures': f['architectures']
            }
            for f in frameworks
        }
    }, indent=2)


@mcp.tool()
def generate_havoc_demon(
    listener_host: str,
    listener_port: int,
    protocol: str = "https",
    architecture: str = "x64",
    sleep_technique: str = "Ekko",
    techniques: Optional[List[str]] = None,
    obfuscate: bool = True,
    indirect_syscalls: bool = True,
    stack_duplication: bool = True
) -> str:
    """
    Generate a Havoc C2 demon with Noctis obfuscation and advanced evasion.
    
    This tool creates production-ready Havoc demons with sleep obfuscation.
    
    Requirements:
        - Havoc C2 must be installed and running
        - Havoc teamserver must be accessible
    
    Args:
        listener_host: C2 listener hostname or IP (e.g., "192.168.1.100")
        listener_port: C2 listener port (e.g., 443 for HTTPS, 445 for SMB)
        protocol: C2 protocol - "https", "http", or "smb" (default: "https")
        architecture: Target architecture - "x64" or "x86" (default: "x64")
        sleep_technique: Sleep obfuscation - "Ekko", "Foliage", or "WaitForSingleObjectEx" (default: "Ekko")
        techniques: List of Noctis technique IDs to apply (e.g., ["NOCTIS-T124", "NOCTIS-T118"])
        obfuscate: Apply Noctis obfuscation (string encryption, API hashing, etc.)
        indirect_syscalls: Enable indirect syscalls for EDR evasion
        stack_duplication: Enable stack duplication for anti-debugging
    
    Returns:
        JSON with demon generation results including path, size, OPSEC score
    
    Example:
        generate_havoc_demon(
            listener_host="192.168.1.100",
            listener_port=443,
            protocol="https",
            sleep_technique="Ekko",
            techniques=["NOCTIS-T124"],
            obfuscate=True
        )
    """
    logger.info(f"Generating Havoc demon: {protocol}://{listener_host}:{listener_port}")
    logger.info(f"Sleep technique: {sleep_technique}")
    
    # Prepare request data
    request_data = {
        'listener_host': listener_host,
        'listener_port': listener_port,
        'protocol': protocol,
        'architecture': architecture,
        'sleep_technique': sleep_technique,
        'techniques': techniques or [],
        'obfuscate': obfuscate,
        'indirect_syscalls': indirect_syscalls,
        'stack_duplication': stack_duplication
    }
    
    # Call C2 API endpoint
    result = api_post('/api/c2/havoc/generate', request_data)
    
    if not result.get('success', False):
        return json.dumps({
            'success': False,
            'error': result.get('error', 'Havoc demon generation failed'),
            'details': result.get('message', ''),
            'help': 'Make sure Havoc C2 is installed and teamserver is running. See docs/HAVOC_INTEGRATION.md'
        }, indent=2)
    
    return json.dumps({
        'success': True,
        'message': f'Havoc {protocol.upper()} demon generated successfully',
        'beacon_path': result.get('beacon_path'),
        'shellcode_path': result.get('shellcode_path'),
        'beacon_size': result.get('beacon_size'),
        'opsec_score': result.get('opsec_score'),
        'techniques_applied': result.get('techniques_applied', []),
        'obfuscation_summary': result.get('obfuscation_summary', {}),
        'compilation_time': result.get('compilation_time'),
        'evasion_features': {
            'sleep_technique': sleep_technique,
            'indirect_syscalls': indirect_syscalls,
            'stack_duplication': stack_duplication,
            'protocol': protocol,
            'architecture': architecture
        },
        'next_steps': [
            f"1. Start Havoc teamserver: ./havoc server --profile ./profiles/havoc.yaotl",
            f"2. Create listener: listener add --name test --host {listener_host} --port {listener_port}",
            f"3. Deploy demon: {result.get('beacon_path', 'demon.exe')}",
            "4. Wait for callback in Havoc client"
        ]
    }, indent=2)


@mcp.tool()
def generate_mythic_agent(
    listener_host: str,
    listener_port: int,
    api_token: str,
    agent_type: str = "apollo",
    c2_profile: str = "http",
    architecture: str = "x64",
    techniques: Optional[List[str]] = None,
    obfuscate: bool = True
) -> str:
    """
    Generate a Mythic C2 agent with Noctis obfuscation.
    
    This tool creates production-ready Mythic agents with advanced features.
    
    Requirements:
        - Mythic C2 must be installed and running
        - Docker must be running
        - API token must be valid
    
    Args:
        listener_host: C2 listener hostname or IP (e.g., "192.168.1.100")
        listener_port: C2 listener port (e.g., 80 for HTTP, 443 for HTTPS)
        api_token: Mythic API authentication token (required)
        agent_type: Agent type - "apollo", "apfell", "poseidon", "merlin", or "atlas" (default: "apollo")
        c2_profile: C2 profile - "http", "https", "websocket", "dns", or "smb" (default: "http")
        architecture: Target architecture - "x64", "x86", or "arm64" (default: "x64")
        techniques: List of Noctis technique IDs to apply (e.g., ["NOCTIS-T124", "NOCTIS-T118"])
        obfuscate: Apply Noctis obfuscation (string encryption, API hashing, etc.)
    
    Returns:
        JSON with agent generation results including path, size, OPSEC score
    
    Example:
        generate_mythic_agent(
            listener_host="192.168.1.100",
            listener_port=80,
            api_token="your_api_token_here",
            agent_type="apollo",
            c2_profile="http",
            obfuscate=True
        )
    """
    logger.info(f"Generating Mythic {agent_type} agent: {c2_profile}://{listener_host}:{listener_port}")
    
    # Prepare request data
    request_data = {
        'listener_host': listener_host,
        'listener_port': listener_port,
        'agent_type': agent_type,
        'c2_profile': c2_profile,
        'architecture': architecture,
        'api_token': api_token,
        'techniques': techniques or [],
        'obfuscate': obfuscate
    }
    
    # Call C2 API endpoint
    result = api_post('/api/c2/mythic/generate', request_data)
    
    if not result.get('success', False):
        return json.dumps({
            'success': False,
            'error': result.get('error', 'Mythic agent generation failed'),
            'details': result.get('message', ''),
            'help': 'Make sure Mythic C2 is installed and running. Visit: https://github.com/its-a-feature/Mythic'
        }, indent=2)
    
    return json.dumps({
        'success': True,
        'message': f'Mythic {agent_type} agent generated successfully',
        'beacon_path': result.get('beacon_path'),
        'shellcode_path': result.get('shellcode_path'),
        'beacon_size': result.get('beacon_size'),
        'opsec_score': result.get('opsec_score'),
        'techniques_applied': result.get('techniques_applied', []),
        'obfuscation_summary': result.get('obfuscation_summary', {}),
        'compilation_time': result.get('compilation_time'),
        'agent_info': {
            'agent_type': agent_type,
            'c2_profile': c2_profile,
            'architecture': architecture,
            'protocol': c2_profile
        },
        'next_steps': [
            f"1. Start Mythic server: sudo ./mythic-cli start",
            f"2. Access Mythic UI: https://127.0.0.1:7443",
            f"3. Deploy agent: {result.get('beacon_path', 'agent.exe')}",
            "4. Wait for callback in Mythic dashboard"
        ]
    }, indent=2)


@mcp.tool()
def get_c2_framework_info(framework_name: str) -> str:
    """
    Get detailed information about a specific C2 framework.
    
    Provides comprehensive details about a C2 framework including
    protocols, features, installation status, and usage examples.
    
    Args:
        framework_name: Name of the C2 framework ("Sliver", "Havoc", "Mythic", "Custom")
    
    Returns:
        JSON with detailed framework information
    
    Example:
        get_c2_framework_info("Sliver")
    """
    logger.info(f"Getting info for C2 framework: {framework_name}")
    
    result = api_get('/api/c2/frameworks')
    
    if not result.get('success', False):
        return json.dumps({
            'success': False,
            'error': 'Failed to retrieve C2 frameworks'
        }, indent=2)
    
    frameworks = result.get('frameworks', [])
    framework = next((f for f in frameworks if f['name'].lower() == framework_name.lower()), None)
    
    if not framework:
        return json.dumps({
            'success': False,
            'error': f'Framework "{framework_name}" not found',
            'available': [f['name'] for f in frameworks]
        }, indent=2)
    
    # Add usage example
    usage_example = None
    if framework['name'] == 'Sliver':
        usage_example = {
            'description': 'Generate HTTPS beacon with API hashing',
            'code': '''generate_sliver_beacon(
    listener_host="192.168.1.100",
    listener_port=443,
    protocol="https",
    architecture="x64",
    techniques=["NOCTIS-T124"],
    obfuscate=True
)''',
            'installation': 'curl https://sliver.sh/install | sudo bash',
            'docs': 'See INSTALL_SLIVER.md'
        }
    
    return json.dumps({
        'success': True,
        'framework': framework,
        'usage_example': usage_example,
        'ready_to_use': framework['status'] == 'implemented'
    }, indent=2)


# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

def print_banner():
    """Print Noctis-MCP banner"""
    banner = """
================================================================================
   _   _            _   _         __  __  ____ ____  
  | \\ | | ___   ___| |_(_)___    |  \\/  |/ ___|  _ \\ 
  |  \\| |/ _ \\ / __| __| / __|   | |\\/| | |   | |_) |
  | |\\  | (_) | (__| |_| \\__ \\   | |  | | |___|  __/ 
  |_| \\_|\\___/ \\___|\\__|_|___/   |_|  |_|\\____|_|    
                                                      
  AI-Driven Malware Development Platform
  FastMCP Integration for Cursor IDE
  
  Version: 1.0.0-alpha
  Techniques: 126+
  Author: @Yenn (Noctis-MCP Community)
================================================================================
"""
    print(banner)


def main():
    """Main entry point for MCP server"""
    global SERVER_URL
    
    # Parse arguments
    parser = argparse.ArgumentParser(
        description='Noctis-MCP FastMCP Server',
        epilog='WARNING: For authorized security research only!'
    )
    parser.add_argument(
        '--server',
        default='http://localhost:8888',
        help='Noctis API server URL (default: http://localhost:8888)'
    )
    parser.add_argument(
        '--debug',
        action='store_true',
        help='Enable debug logging'
    )
    
    args = parser.parse_args()
    
    # Set server URL
    SERVER_URL = args.server.rstrip('/')
    
    # Setup logging
    if args.debug:
        logger.setLevel(logging.DEBUG)
    
    # Print banner
    print_banner()
    
    # Check server connection
    logger.info(f"Connecting to Noctis API server: {SERVER_URL}")
    if not check_server():
        logger.error("Cannot connect to Noctis API server!")
        logger.error("Make sure the server is running:")
        logger.error("  python server/noctis_server.py")
        return 1
    
    logger.info("Connected to Noctis API server successfully!")
        
        # Get stats
    stats_result = api_get('/api/stats')
    if stats_result.get('success'):
        stats = stats_result.get('statistics', {})
        logger.info(f"Techniques available: {stats.get('total_techniques', 0)}")
        logger.info(f"Categories: {len(stats.get('categories', {}))}")
        logger.info(f"MITRE TTPs: {stats.get('mitre_coverage', {}).get('total_ttps', 0)}")
    
    # Start FastMCP server
    logger.info("Starting FastMCP server...")
    logger.info("Tools registered:")
    logger.info("  - query_techniques")
    logger.info("  - get_technique_details")
    logger.info("  - list_categories")
    logger.info("  - get_statistics")
    logger.info("  - get_mitre_mappings")
    logger.info("  - generate_malware")
    logger.info("  - assemble_code")
    logger.info("  - compile_code")
    logger.info("  - analyze_opsec")
    logger.info("")
    logger.info("Prompts registered:")
    logger.info("  - malware_development_guide")
    logger.info("  - quick_start")
    logger.info("")
    logger.info("MCP server ready! Connect from Cursor IDE.")
    
    # Run FastMCP server
    mcp.run()
    
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[*] Shutting down Noctis-MCP...")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

