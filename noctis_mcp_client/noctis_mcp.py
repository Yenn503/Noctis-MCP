#!/usr/bin/env python3
"""
Noctis-MCP Client - Simplified Workflow for AI-Driven Malware Development
===========================================================================

A clean, intuitive interface designed for AI assistants in Cursor IDE.

6 Core Tools:
  1. develop()  - One-stop malware creation (⭐ primary tool)
  2. browse()   - Explore available techniques
  3. compile()  - Build executables
  4. learn()    - Provide feedback for ML
  5. files()    - Manage workspace files
  6. help()     - Get workflow guidance

C2 Tools (for future Kali/WSL integration):
  7. c2_generate() - Generate C2 beacons
  8. c2_list()     - List C2 frameworks

Author: Noctis-MCP Community
License: MIT
Version: 2.0.0-alpha

WARNING: For authorized security research and red team operations only.
"""

import sys
import os
import argparse
import logging
from typing import Dict, Any, Optional, List
import requests
from datetime import datetime
import json

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from fastmcp import FastMCP
except ImportError:
    print("[!] FastMCP not installed. Run: pip install fastmcp")
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
    """Custom formatter with timestamps"""

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
    """Setup logging"""
    logger = logging.getLogger("noctis-mcp")
    logger.setLevel(getattr(logging, level.upper()))

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
        response = session.post(url, json=data, timeout=60)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        logger.error(f"API POST error: {e}")
        return {'success': False, 'error': str(e)}


# ============================================================================
# CORE TOOLS - Simplified Workflow (6 Tools)
# ============================================================================

@mcp.tool()
def develop(
    goal: str,
    target: str = "Windows Defender",
    os_type: str = "Windows",
    architecture: str = "x64",
    complexity: str = "medium",
    auto_compile: bool = False
) -> str:
    """
    🚀 PRIMARY TOOL: One-stop autonomous malware development.

    This is the MAIN tool AI should use for malware creation. It handles everything:
    - AI selects optimal techniques
    - Assembles working code
    - Optimizes OPSEC automatically
    - Saves to workspace with reports
    - Optionally compiles binary
    - Records learning feedback

    Args:
        goal: What the malware should do (e.g., "Create a stealthy loader")
        target: Target AV/EDR to evade (default: "Windows Defender")
        os_type: Target OS (Windows, Linux)
        architecture: Target arch (x86, x64, arm64)
        complexity: Difficulty level (low, medium, high)
        auto_compile: Compile to .exe automatically (default: False)

    Returns:
        Beautiful formatted output with clickable file links

    Example:
        develop(
            goal="Create a process injection loader",
            target="Windows Defender",
            auto_compile=True
        )
    """
    logger.info(f"🚀 Starting autonomous development: {goal}")

    # Call malware development agent
    result = api_post('/api/v2/agents/malware-development', {
        'goal': goal,
        'target_av': target,
        'target_os': os_type,
        'target_arch': architecture,
        'complexity': complexity,
        'compile': auto_compile
    })

    if not result.get('success'):
        return f"❌ Development failed: {result.get('error', 'Unknown error')}"

    # Extract data
    data = result.get('data', {})
    source_code = data.get('source_code', '')
    techniques = data.get('techniques_used', [])
    opsec_score = data.get('opsec_score', 0)
    binary_path = data.get('binary_path')
    compilation_success = data.get('compilation_success', False)

    # Auto-save to workspace
    output_dir = os.path.join(os.getcwd(), 'output')
    os.makedirs(output_dir, exist_ok=True)

    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f"malware_{timestamp}"

    # Save files
    code_path = os.path.abspath(os.path.join(output_dir, f"{filename}.c"))
    with open(code_path, 'w', encoding='utf-8') as f:
        f.write(source_code)

    metadata_path = os.path.abspath(os.path.join(output_dir, f"{filename}_metadata.json"))
    with open(metadata_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2)

    # Create beautiful markdown report
    report_path = os.path.abspath(os.path.join(output_dir, f"{filename}_report.md"))
    report = f"""# 🤖 AI Malware Development Report
**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

---

## 📋 Project Summary
- **Goal:** {goal}
- **Target:** {target} on {os_type}/{architecture}
- **Complexity:** {complexity}

---

## 🎯 Selected Techniques ({len(techniques)})
"""
    for i, tech_id in enumerate(techniques, 1):
        tech_details = next((t for t in data.get('technique_details', []) if t.get('technique_id') == tech_id), {})
        tech_name = tech_details.get('name', tech_id)
        tech_score = tech_details.get('effectiveness_score', 'N/A')
        report += f"{i}. **{tech_name}** (`{tech_id}`) - Effectiveness: {tech_score}\n"

    report += f"""
---

## 🛡️ OPSEC Analysis
- **Score:** {opsec_score:.1f}/10
- **Risk Level:** {'🟢 Low' if opsec_score >= 8 else '🟡 Medium' if opsec_score >= 6 else '🔴 High'}

---

## 📁 Output Files
- [Source Code]({filename}.c)
- [Metadata]({filename}_metadata.json)
- [This Report]({filename}_report.md)
"""

    if binary_path:
        report += f"- [Compiled Binary]({os.path.basename(binary_path)})\n"

    report += f"""
---

## 📝 Next Steps
1. Review source code in editor
2. {'✅ Binary ready for testing' if compilation_success else '⚡ Run compile() to build executable'}
3. Test in isolated VM/sandbox
4. Report results with learn()

---

⚠️ **SECURITY NOTICE**
This code is for **AUTHORIZED SECURITY RESEARCH ONLY**.
"""

    with open(report_path, 'w', encoding='utf-8') as f:
        f.write(report)

    # Build beautiful response
    response = f"""
=================================================================
|        🤖 AUTONOMOUS MALWARE DEVELOPMENT COMPLETE             |
=================================================================

📋 WORKFLOW SUMMARY
+------------------------------------------------------------+
| ✅ Technique Selection   | {len(techniques)} techniques selected           |
| ✅ Code Assembly         | {len(source_code.split(chr(10)))} lines generated               |
| ✅ OPSEC Optimization    | Score: {opsec_score:.1f}/10                      |
| {'✅ Compilation' if compilation_success else '⏭️  Compilation'}           | {'Success' if compilation_success else 'Skipped'}                         |
| ✅ Learning Feedback     | Recorded                          |
+------------------------------------------------------------+

🎯 SELECTED TECHNIQUES
"""
    for tech_id in techniques:
        tech_details = next((t for t in data.get('technique_details', []) if t.get('technique_id') == tech_id), {})
        tech_name = tech_details.get('name', tech_id)
        tech_score = tech_details.get('effectiveness_score', 'N/A')
        response += f"• {tech_name} ({tech_id}) - Score: {tech_score}\n"

    response += f"""
📁 OUTPUT FILES (Click to open in editor)
• Source Code: {code_path}
• Analysis Report: {report_path}
• Metadata: {metadata_path}
"""
    if binary_path:
        response += f"• Binary: {binary_path}\n"

    response += f"""
🛡️ OPSEC ANALYSIS
Risk Level: {'🟢 Excellent (Low Detection Risk)' if opsec_score >= 8 else '🟡 Good (Moderate Risk)' if opsec_score >= 6 else '🔴 Fair (High Risk)'}
Score: {opsec_score:.1f}/10

📝 NEXT STEPS
1. Click source code file above to open in editor
2. Review the generated code
"""
    if not compilation_success:
        response += f"3. Run compile(\"{code_path}\") to build executable\n"
    else:
        response += f"3. Binary ready: {binary_path}\n"

    response += f"""4. Test in isolated environment
5. Report results with learn()

⚠️  For AUTHORIZED security research only.
"""

    return response


@mcp.tool()
def browse(
    search: str = None,
    category: str = None,
    show_details: bool = False
) -> str:
    """
    🔍 Browse and explore available malware techniques.

    Use this to discover what techniques exist in the database.
    For actual malware creation, use develop() instead.

    Args:
        search: Keyword search (e.g., "syscalls", "API hashing")
        category: Filter by category (evasion, injection, persistence, etc.)
        show_details: Show detailed info for each technique

    Returns:
        Formatted list of matching techniques

    Example:
        browse(search="evasion")
        browse(category="injection", show_details=True)
    """
    logger.info(f"📚 Browsing techniques - search={search}, category={category}")

    # Build query
    params = {}
    if search:
        params['search'] = search
    if category:
        params['category'] = category

    # Query API
    result = api_get('/api/techniques', params=params)

    if not result.get('success', False):
        return f"❌ Error: {result.get('error', 'Failed to fetch techniques')}"

    techniques = result.get('techniques', [])

    if not techniques:
        return f"No techniques found matching your criteria.\n\nTry: browse() to see all techniques"

    # Format output
    response = f"""
=================================================================
|                    TECHNIQUE BROWSER                          |
=================================================================

Found {len(techniques)} technique(s)

"""

    for tech in techniques[:20]:  # Limit to 20 for readability
        tech_id = tech.get('technique_id', 'N/A')
        name = tech.get('name', 'N/A')
        category = tech.get('category', 'N/A')
        desc = tech.get('description', 'No description')

        response += f"📌 {name} ({tech_id})\n"
        response += f"   Category: {category}\n"

        if show_details:
            response += f"   Description: {desc}\n"
            mitre = tech.get('mitre_ttps', [])
            if mitre:
                response += f"   MITRE: {', '.join(mitre)}\n"

        response += "\n"

    if len(techniques) > 20:
        response += f"\n... and {len(techniques) - 20} more techniques.\n"

    response += """
💡 TIP: To create malware with these techniques, use:
   develop(goal="your objective")
"""

    return response


@mcp.tool()
def compile(
    source_file: str,
    architecture: str = "x64",
    optimization: str = "O2",
    output_name: str = None
) -> str:
    """
    🔨 Compile generated C/C++ code into executable.

    Use this AFTER develop() if you didn't use auto_compile=True.
    Automatically uses files from the workspace.

    Args:
        source_file: Path to .c file (use files() to see available files)
        architecture: Target architecture (x86, x64)
        optimization: Compiler optimization (O0, O1, O2, O3)
        output_name: Output filename (auto-generated if not provided)

    Returns:
        Compilation results with binary path

    Example:
        compile("output/malware_20241004_123456.c")
    """
    logger.info(f"🔨 Compiling: {source_file}")

    # Read source code
    if not os.path.exists(source_file):
        return f"❌ Error: File not found: {source_file}\n\nUse files() to see available source files."

    with open(source_file, 'r', encoding='utf-8') as f:
        source_code = f.read()

    # Generate output name if not provided
    if not output_name:
        base_name = os.path.splitext(os.path.basename(source_file))[0]
        output_name = f"{base_name}_compiled"

    # Call compilation API
    result = api_post('/api/compile', {
        'source_code': source_code,
        'architecture': architecture,
        'optimization': optimization,
        'output_name': output_name,
        'subsystem': 'Console'
    })

    if not result.get('success'):
        errors = result.get('errors', [])
        return f"""
❌ COMPILATION FAILED

Errors:
{chr(10).join(f'  • {e}' for e in errors)}

💡 TIP: Check the source code for syntax errors or missing dependencies.
"""

    binary_path = result.get('binary_path', '')
    warnings = result.get('warnings', [])
    compilation_time = result.get('compilation_time', 0)

    # Get file size
    file_size_kb = 0
    if os.path.exists(binary_path):
        file_size_kb = round(os.path.getsize(binary_path) / 1024, 2)

    response = f"""
=================================================================
|              ✅ COMPILATION SUCCESSFUL                        |
=================================================================

📦 Binary Details
|- Path: {binary_path}
|- Size: {file_size_kb} KB
|- Architecture: {architecture}
|- Optimization: {optimization}
+- Compilation Time: {compilation_time:.2f}s

"""

    if warnings:
        response += f"⚠️  Warnings ({len(warnings)}):\n"
        for w in warnings[:5]:
            response += f"  • {w}\n"
        if len(warnings) > 5:
            response += f"  ... and {len(warnings) - 5} more warnings\n"
        response += "\n"

    response += f"""📝 Next Steps
1. Test in isolated VM/sandbox
2. Monitor with Process Monitor
3. Report results with learn()

⚠️  For AUTHORIZED testing only.
"""

    return response


@mcp.tool()
def learn(
    source_file: str,
    av_name: str,
    detected: bool,
    notes: str = None
) -> str:
    """
    🧠 Provide feedback to improve the AI learning system.

    After testing generated malware, report the results so the system
    learns which techniques work against specific AV/EDR solutions.

    Args:
        source_file: Which malware file was tested (from workspace)
        av_name: AV/EDR name (e.g., "Windows Defender", "CrowdStrike")
        detected: Was the malware detected? (True/False)
        notes: Optional notes about the test

    Returns:
        Confirmation of recorded feedback

    Example:
        learn(
            source_file="output/malware_20241004_123456.c",
            av_name="Windows Defender",
            detected=False,
            notes="Successfully bypassed with API hashing + syscalls"
        )
    """
    logger.info(f"🧠 Recording feedback: {av_name} - Detected: {detected}")

    # Load metadata to get techniques used
    metadata_file = source_file.replace('.c', '_metadata.json')
    techniques = []

    if os.path.exists(metadata_file):
        with open(metadata_file, 'r') as f:
            metadata = json.load(f)
            techniques = metadata.get('techniques_used', [])

    # Record feedback
    result = api_post('/api/v2/agents/learning', {
        'action': 'record_detection',
        'techniques': techniques,
        'av_edr': av_name,
        'detected': detected,
        'notes': notes
    })

    if not result.get('success'):
        return f"❌ Error recording feedback: {result.get('error')}"

    data = result.get('data', {})

    response = f"""
=================================================================
|              🧠 LEARNING FEEDBACK RECORDED                    |
=================================================================

📊 Test Results
|- AV/EDR: {av_name}
|- Detected: {'❌ Yes' if detected else '✅ No (Bypassed)'}
|- Techniques Tested: {len(techniques)}
+- Status: Feedback recorded successfully

"""

    if techniques:
        response += "🎯 Techniques Tested:\n"
        for tech in techniques:
            response += f"  • {tech}\n"
        response += "\n"

    if notes:
        response += f"📝 Notes: {notes}\n\n"

    response += """💡 Your feedback helps improve future malware generation!

Next: Generate more samples with develop()
"""

    return response


@mcp.tool()
def files(
    pattern: str = "*.c",
    open_latest: bool = False
) -> str:
    """
    📁 Browse and manage workspace files.

    Lists all generated files in the output directory.

    Args:
        pattern: File pattern to match (default: "*.c" for source code)
        open_latest: Show path to latest file for easy opening

    Returns:
        List of workspace files with metadata

    Example:
        files()  # List all .c files
        files("*.exe")  # List compiled binaries
        files(open_latest=True)  # Get latest file path
    """
    import glob

    logger.info(f"📁 Listing workspace files: {pattern}")

    output_dir = os.path.join(os.getcwd(), 'output')

    if not os.path.exists(output_dir):
        return """
📁 No output directory found.

Generate malware first using:
  develop(goal="your objective")
"""

    search_path = os.path.join(output_dir, pattern)
    file_list = glob.glob(search_path)

    if not file_list:
        return f"""
📁 No files found matching: {pattern}

Try:
  files("*.c")     # Source code
  files("*.exe")   # Binaries
  files("*.md")    # Reports
"""

    # Sort by modification time (newest first)
    file_list.sort(key=os.path.getmtime, reverse=True)

    response = f"""
=================================================================
|                    WORKSPACE BROWSER                          |
=================================================================

Found {len(file_list)} file(s) in: {output_dir}

"""

    for i, filepath in enumerate(file_list[:20], 1):
        stat = os.stat(filepath)
        size_kb = round(stat.st_size / 1024, 2)
        modified = datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
        name = os.path.basename(filepath)

        response += f"{i}. {name}\n"
        response += f"   Size: {size_kb} KB | Modified: {modified}\n"
        response += f"   Path: {os.path.abspath(filepath)}\n\n"

    if len(file_list) > 20:
        response += f"... and {len(file_list) - 20} more files.\n\n"

    if open_latest and file_list:
        latest = os.path.abspath(file_list[0])
        response += f"📌 Latest file: {latest}\n\n"

    response += """💡 TIP: Click any path above to open in editor
"""

    return response


@mcp.tool()
def help(topic: str = None) -> str:
    """
    ❓ Get workflow guidance and usage examples.

    Shows how to use the Noctis-MCP system effectively.

    Args:
        topic: Specific topic (workflow, develop, browse, compile, learn, files)

    Returns:
        Help documentation

    Example:
        help()  # General help
        help("develop")  # Help for develop() tool
    """
    if topic == "develop":
        return """
=================================================================
|                    DEVELOP() - PRIMARY TOOL                   |
=================================================================

🚀 One-stop malware development tool.

USAGE:
  develop(
      goal="Create a stealthy process injection loader",
      target="Windows Defender",
      auto_compile=True
  )

PARAMETERS:
  • goal: What the malware should do (required)
  • target: AV/EDR to evade (default: "Windows Defender")
  • os_type: Target OS (default: "Windows")
  • architecture: Target arch (default: "x64")
  • complexity: low, medium, high (default: "medium")
  • auto_compile: Build binary automatically (default: False)

WHAT IT DOES:
  1. AI selects optimal techniques automatically
  2. Assembles working C code
  3. Optimizes OPSEC (detection evasion)
  4. Saves to workspace (output/ directory)
  5. Generates analysis reports
  6. Optionally compiles to .exe

OUTPUT FILES:
  • malware_TIMESTAMP.c - Source code
  • malware_TIMESTAMP_report.md - Analysis
  • malware_TIMESTAMP_metadata.json - Full metadata
  • malware_TIMESTAMP.exe - Binary (if auto_compile=True)

EXAMPLES:
  # Basic usage
  develop(goal="Create a loader")

  # Advanced usage
  develop(
      goal="Create reflective DLL injection",
      target="CrowdStrike Falcon",
      complexity="high",
      auto_compile=True
  )
"""

    elif topic == "workflow":
        return """
=================================================================
|                      WORKFLOW GUIDE                           |
=================================================================

RECOMMENDED WORKFLOW:

1️⃣  CREATE MALWARE
    develop(goal="your objective")

    This is 95% of what you need. It handles everything automatically.

2️⃣  COMPILE (if not done automatically)
    files()  # Find your source file
    compile("output/malware_TIMESTAMP.c")

3️⃣  TEST IN ISOLATED ENVIRONMENT
    - Use VM or sandbox
    - Test against target AV/EDR
    - Monitor with Process Monitor

4️⃣  PROVIDE FEEDBACK
    learn(
        source_file="output/malware_TIMESTAMP.c",
        av_name="Windows Defender",
        detected=False
    )

OPTIONAL:
  • browse() - Explore available techniques
  • files() - Manage workspace files
  • help("topic") - Get specific help

SIMPLE EXAMPLE:
  1. develop(goal="Create a stealthy loader", auto_compile=True)
  2. Test the generated .exe
  3. learn(source_file="output/malware_*.c", av_name="Windows Defender", detected=False)
"""

    # General help
    return """
=================================================================
|              NOCTIS-MCP - AI MALWARE DEVELOPMENT              |
=================================================================

🚀 6 CORE TOOLS (Simplified Workflow)

1. develop()  - ⭐ PRIMARY TOOL - Create malware automatically
2. browse()   - Explore available techniques
3. compile()  - Build executables from source
4. learn()    - Provide feedback for ML system
5. files()    - Browse workspace files
6. help()     - Get guidance (you are here!)

QUICK START:
  develop(goal="Create a stealthy loader")

That's it! Everything is automated.

For detailed help on any topic:
  help("workflow")  - Full workflow guide
  help("develop")   - develop() tool guide

For browsing techniques:
  browse()  - See all available techniques
  browse(search="evasion")  - Search by keyword

⚠️  For AUTHORIZED security research only.
"""


# ============================================================================
# C2 INTEGRATION TOOLS (Future Kali/WSL Work)
# ============================================================================

@mcp.tool()
def c2_generate(
    framework: str,
    listener_host: str,
    listener_port: int,
    protocol: str = "https",
    architecture: str = "x64",
    obfuscate: bool = True
) -> str:
    """
    🔗 Generate C2 beacon/agent (Future: Kali/WSL integration).

    Creates production-ready C2 beacons with Noctis obfuscation.

    NOTE: This requires C2 framework installation (Sliver, Havoc, Mythic).
    Currently designed for future Kali/WSL development.

    Args:
        framework: C2 framework (sliver, havoc, mythic)
        listener_host: C2 listener IP/hostname
        listener_port: C2 listener port
        protocol: Protocol (https, http, dns, tcp, mtls)
        architecture: Target arch (x64, x86)
        obfuscate: Apply Noctis obfuscation techniques

    Returns:
        C2 beacon generation results

    Example:
        c2_generate(
            framework="sliver",
            listener_host="192.168.1.100",
            listener_port=443,
            protocol="https"
        )
    """
    logger.info(f"🔗 Generating {framework} beacon: {protocol}://{listener_host}:{listener_port}")

    framework = framework.lower()

    # Map framework to endpoint
    endpoint_map = {
        'sliver': '/api/c2/sliver/generate',
        'havoc': '/api/c2/havoc/generate',
        'mythic': '/api/c2/mythic/generate'
    }

    if framework not in endpoint_map:
        return f"""
❌ Unknown C2 framework: {framework}

Supported frameworks:
  • sliver - Sliver C2
  • havoc - Havoc Framework
  • mythic - Mythic C2

Example:
  c2_generate(framework="sliver", listener_host="192.168.1.100", listener_port=443)
"""

    # Call C2 API
    result = api_post(endpoint_map[framework], {
        'listener_host': listener_host,
        'listener_port': listener_port,
        'protocol': protocol,
        'architecture': architecture,
        'obfuscate': obfuscate
    })

    if not result.get('success'):
        return f"""
❌ C2 Generation Failed

Error: {result.get('error', 'Unknown error')}

NOTE: This feature requires C2 framework installation.
      Designed for Kali/WSL development environment.

Install {framework.title()} first:
  Sliver: curl https://sliver.sh/install | sudo bash
  Havoc: https://github.com/HavocFramework/Havoc
  Mythic: https://github.com/its-a-feature/Mythic
"""

    beacon_path = result.get('beacon_path', '')
    beacon_size = result.get('beacon_size', 0)
    opsec_score = result.get('opsec_score', 0)

    response = f"""
=================================================================
|              ✅ C2 BEACON GENERATED                           |
=================================================================

📦 Beacon Details
|- Framework: {framework.title()}
|- Protocol: {protocol}
|- Listener: {listener_host}:{listener_port}
|- Architecture: {architecture}
|- Beacon Path: {beacon_path}
|- Size: {beacon_size} bytes
+- OPSEC Score: {opsec_score:.1f}/10

📝 Next Steps
1. Start {framework.title()} listener: {protocol} -L {listener_host} -l {listener_port}
2. Deploy beacon to target
3. Wait for callback

⚠️  For AUTHORIZED red team operations only.
"""

    return response


@mcp.tool()
def c2_list() -> str:
    """
    📋 List supported C2 frameworks and their status.

    Shows which C2 frameworks are integrated with Noctis-MCP
    and their current installation status.

    Returns:
        List of C2 frameworks with capabilities

    Example:
        c2_list()
    """
    logger.info("📋 Listing C2 frameworks")

    result = api_get('/api/c2/frameworks')

    if not result.get('success'):
        return f"❌ Error: {result.get('error', 'Failed to fetch frameworks')}"

    frameworks = result.get('frameworks', [])

    response = """
=================================================================
|                  C2 FRAMEWORK INTEGRATION                     |
=================================================================

"""

    for fw in frameworks:
        name = fw.get('name', 'Unknown')
        status = fw.get('status', 'unknown')
        protocols = fw.get('protocols', [])

        status_icon = '✅' if status == 'implemented' else '🚧'

        response += f"{status_icon} {name}\n"
        response += f"   Status: {status}\n"
        response += f"   Protocols: {', '.join(protocols)}\n\n"

    response += """
💡 NOTE: C2 integration requires framework installation.
         Designed for Kali/WSL development environment.

To generate beacon:
  c2_generate(framework="sliver", listener_host="IP", listener_port=443)
"""

    return response


# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

def print_banner():
    """Print Noctis-MCP banner"""
    banner = """
====================================================================
   _   _            _   _         __  __  ____ ____
  | \\ | | ___   ___| |_(_)___    |  \\/  |/ ___|  _ \\
  |  \\| |/ _ \\ / __| __| / __|   | |\\/| | |   | |_) |
  | |\\  | (_) | (__| |_| \\__ \\   | |  | | |___|  __/
  |_| \\_|\\___/ \\___|\\__|_|___/   |_|  |_|\\____|_|

  AI-Driven Malware Development Platform
  Simplified Workflow for Cursor IDE

  Version: 2.0.0-alpha
  Tools: 8 (6 core + 2 C2)
  Workflow: Streamlined for AI assistants
====================================================================
"""
    print(banner)


def main():
    """Main entry point"""
    global SERVER_URL

    # Parse arguments
    parser = argparse.ArgumentParser(
        description='Noctis-MCP v2.0 - Simplified Workflow',
        epilog='For authorized security research only'
    )
    parser.add_argument(
        '--server',
        default='http://localhost:8888',
        help='Noctis API server URL'
    )
    parser.add_argument(
        '--debug',
        action='store_true',
        help='Enable debug logging'
    )

    args = parser.parse_args()
    SERVER_URL = args.server.rstrip('/')

    if args.debug:
        logger.setLevel(logging.DEBUG)

    # Print banner
    print_banner()

    # Check server
    logger.info(f"Connecting to Noctis API server: {SERVER_URL}")
    if not check_server():
        logger.error("Cannot connect to Noctis API server!")
        logger.error("Make sure it's running:")
        logger.error("  python server/noctis_server.py")
        return 1

    logger.info("✅ Connected to Noctis API server")

    # Get stats
    stats_result = api_get('/api/stats')
    if stats_result.get('success'):
        stats = stats_result.get('statistics', {})
        logger.info(f"Techniques available: {stats.get('total_techniques', 0)}")

    # Start FastMCP server
    logger.info("Starting FastMCP server...")
    logger.info("")
    logger.info("=============================================================")
    logger.info("|          TOOLS REGISTERED (8 Total)                      |")
    logger.info("=============================================================")
    logger.info("")
    logger.info("CORE WORKFLOW (6 tools):")
    logger.info("  1. develop()  - 🚀 PRIMARY TOOL - Autonomous malware creation")
    logger.info("  2. browse()   - 🔍 Explore techniques")
    logger.info("  3. compile()  - 🔨 Build executables")
    logger.info("  4. learn()    - 🧠 Provide feedback")
    logger.info("  5. files()    - 📁 Manage workspace")
    logger.info("  6. help()     - ❓ Get guidance")
    logger.info("")
    logger.info("C2 INTEGRATION (2 tools - Future Kali/WSL):")
    logger.info("  7. c2_generate() - 🔗 Generate C2 beacons")
    logger.info("  8. c2_list()     - 📋 List C2 frameworks")
    logger.info("")
    logger.info("MCP server ready! Connect from Cursor IDE.")
    logger.info("")

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
