#!/usr/bin/env python3
"""
Noctis-MCP - Agentic Malware Development Platform
===================================================

MCP tools designed for AGENTIC AI usage across any IDE (Cursor, VSCode, etc.)

The AI in your IDE (Claude, GPT-4, etc.) acts as the AGENT.
These tools provide INTELLIGENCE - the AI provides REASONING.

Core Philosophy:
- AI decides which tools to call
- AI synthesizes information from multiple sources
- AI iterates until satisfied
- AI makes intelligent, research-driven decisions

11 Agentic Tools:
  Intelligence Gathering:
    1. search_intelligence() - Search RAG for techniques & research
    2. analyze_technique() - Deep dive into specific techniques
    3. fetch_latest() - Get cutting-edge intelligence from GitHub/arXiv/blogs

  Code Generation:
    4. generate_code() - RAG-informed dynamic code generation
    5. optimize_opsec() - Improve code stealth using intelligence
    6. validate_code() - Compile & quality check code with error feedback

  Technique Selection:
    7. select_techniques() - AI-powered technique recommendations
    8. compare_techniques() - Side-by-side analysis

  Compilation & Feedback:
    9. compile_code() - Build binaries
    10. record_feedback() - Learning from testing results

  Utilities:
    11. rag_stats() - RAG system status

Author: Noctis-MCP Community
License: MIT
Version: 3.0.0-agentic

WARNING: For authorized security research and red team operations only.
"""

import sys
import os
import logging
from typing import Dict, Any, Optional, List
import requests
import json

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from fastmcp import FastMCP
except ImportError:
    print("[!] FastMCP not installed. Run: pip install fastmcp")
    sys.exit(1)

# Initialize FastMCP server
mcp = FastMCP("Noctis-MCP-Agentic")

# Global configuration
SERVER_URL = "http://localhost:8888"
session = requests.Session()

# Setup logging
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
logger = logging.getLogger("noctis-mcp")


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def check_server() -> bool:
    """Check if Noctis API server is accessible"""
    try:
        response = session.get(f"{SERVER_URL}/health", timeout=5)
        return response.status_code == 200
    except Exception as e:
        return False


def api_post(endpoint: str, data: Dict, timeout: int = 60) -> Dict:
    """Make POST request to API server"""
    try:
        url = f"{SERVER_URL}{endpoint}"
        response = session.post(url, json=data, timeout=timeout)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        return {'error': str(e)}


def api_get(endpoint: str, timeout: int = 30) -> Dict:
    """Make GET request to API server"""
    try:
        url = f"{SERVER_URL}{endpoint}"
        response = session.get(url, timeout=timeout)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        return {'error': str(e)}


# ============================================================================
# INTELLIGENCE GATHERING TOOLS
# ============================================================================

@mcp.tool()
def search_intelligence(
    query: str,
    target_av: str = None,
    sources: str = "all",
    max_results: int = 10
) -> Dict:
    """
    🔍 Search RAG system for malware techniques, research, and intelligence.

    This is the PRIMARY intelligence gathering tool. Use this to:
    - Research evasion techniques
    - Find real-world implementations
    - Discover latest research
    - Gather context before code generation

    The AI should use this FIRST before making decisions about techniques.

    Args:
        query: What to search for (e.g., "process injection evasion techniques")
        target_av: Target AV/EDR to focus on (e.g., "Windows Defender", "CrowdStrike")
        sources: Which sources to search ("all", "knowledge", "github", "arxiv", "blogs")
        max_results: Maximum results to return

    Returns:
        {
            "results": [
                {
                    "content": "Relevant text content...",
                    "source": "knowledge_base|github|arxiv|blog",
                    "metadata": {...},
                    "relevance_score": 0.85
                }
            ],
            "total_results": 10
        }

    Example AI Workflow:
        1. search_intelligence("CrowdStrike evasion", "CrowdStrike")
        2. Review results from RAG
        3. search_intelligence("NTDLL unhooking techniques", "CrowdStrike")
        4. Synthesize both searches
        5. Make informed decision about techniques to use
    """
    sources_list = sources.split(',') if isinstance(sources, str) else [sources]

    return api_post('/api/v2/intelligence/search', {
        'query': query,
        'target_av': target_av,
        'sources': sources_list,
        'max_results': max_results
    })


@mcp.tool()
def analyze_technique(
    technique_id: str,
    target_av: str = None,
    include_code_examples: bool = True
) -> Dict:
    """
    🔬 Deep analysis of a specific technique using ALL intelligence sources.

    Use this AFTER search_intelligence() to dive deep into a specific technique.
    Combines knowledge base, GitHub implementations, research papers, and blogs.

    Args:
        technique_id: Technique to analyze (e.g., "syscalls", "injection", "encryption")
        target_av: Target AV/EDR for focused analysis
        include_code_examples: Include code snippets from GitHub repos

    Returns:
        {
            "technique_id": "syscalls",
            "conceptual_knowledge": "How it works, why effective...",
            "github_implementations": [{
                "repo": "repo-name",
                "url": "...",
                "code_snippet": "..."
            }],
            "research_papers": [{
                "title": "...",
                "summary": "...",
                "url": "..."
            }],
            "blog_posts": [...],
            "effectiveness_vs_av": {"CrowdStrike": 8.5},
            "recommended_combinations": ["unhooking", "encryption"]
        }

    Example AI Workflow:
        1. Search finds "syscalls" mentioned often
        2. analyze_technique("syscalls", "CrowdStrike", True)
        3. Review comprehensive analysis with code examples
        4. Decide if this technique meets requirements
    """
    return api_post('/api/v2/intelligence/analyze', {
        'technique_id': technique_id,
        'target_av': target_av,
        'include_code_examples': include_code_examples
    })


@mcp.tool()
def fetch_latest(
    topic: str,
    sources: str = "github,arxiv,blogs",
    days_back: int = 30
) -> Dict:
    """
    📡 Fetch and index LATEST intelligence on a topic.

    Use when you need cutting-edge, recent information not yet in RAG.
    Performs LIVE searches and auto-indexes results into RAG for future queries.

    Args:
        topic: Topic to research (e.g., "CrowdStrike bypass 2025")
        sources: Which sources to check (comma-separated: "github,arxiv,blogs")
        days_back: Only get content from last N days

    Returns:
        {
            "topic": "CrowdStrike bypass 2025",
            "new_results": 15,
            "indexed": 15,
            "sources": {"github": 8, "arxiv": 3, "blogs": 4}
        }

    Example AI Workflow:
        1. User asks for "latest CrowdStrike bypass"
        2. fetch_latest("CrowdStrike bypass", "github,blogs", 7)
        3. System fetches and indexes NEW data
        4. search_intelligence() to query the fresh intelligence
    """
    sources_list = sources.split(',') if isinstance(sources, str) else [sources]

    return api_post('/api/v2/intelligence/fetch-latest', {
        'topic': topic,
        'sources': sources_list,
        'days_back': days_back
    }, timeout=120)


# ============================================================================
# CODE GENERATION TOOLS
# ============================================================================

@mcp.tool()
def generate_code(
    technique_ids: List[str],
    target_av: str,
    target_os: str = "Windows",
    architecture: str = "x64",
    use_rag: bool = True,
    opsec_level: str = "high"
) -> Dict:
    """
    💻 Generate code using RAG-informed intelligence.

    This is DYNAMIC code generation - uses RAG to find best implementation
    patterns from real GitHub repos, research papers, and blogs.
    NOT static templates!

    Args:
        technique_ids: List of techniques to combine (e.g., ["syscalls", "injection"])
        target_av: Target AV/EDR (e.g., "CrowdStrike")
        target_os: Target OS (default: "Windows")
        architecture: x86 or x64 (default: "x64")
        use_rag: Use RAG intelligence for code generation (default: True)
        opsec_level: "low", "medium", "high", "maximum"

    Returns:
        {
            "source_code": "Complete C/C++ code",
            "header_code": "Header file",
            "techniques_used": [...],
            "rag_intelligence_used": {
                "github_patterns": 5,
                "research_insights": 3
            },
            "opsec_score": 8.5,
            "warnings": [...]
        }

    Example AI Workflow:
        1. Research with search_intelligence()
        2. Analyze techniques with analyze_technique()
        3. generate_code(["syscalls", "injection"], "CrowdStrike", opsec_level="high")
        4. Review generated code
        5. optimize_opsec() if needed
    """
    return api_post('/api/v2/code/generate', {
        'technique_ids': technique_ids,
        'target_av': target_av,
        'target_os': target_os,
        'architecture': architecture,
        'use_rag_context': use_rag,
        'opsec_level': opsec_level
    })


@mcp.tool()
def optimize_opsec(
    source_code: str,
    target_av: str,
    target_score: float = 8.0,
    max_iterations: int = 3
) -> Dict:
    """
    🛡️ Optimize code for OPSEC using RAG intelligence about detection patterns.

    Args:
        source_code: Code to optimize
        target_av: Target AV/EDR
        target_score: Target OPSEC score 0-10 (default: 8.0)
        max_iterations: Max optimization iterations (default: 3)

    Returns:
        {
            "optimized_code": "Improved code",
            "original_score": 6.5,
            "final_score": 8.7,
            "improvements_made": [
                "Added string encryption",
                "Implemented API hashing"
            ],
            "rag_insights_used": [...]
        }

    Example AI Workflow:
        1. generate_code() creates initial code
        2. Check OPSEC score
        3. If score < target, optimize_opsec(code, "CrowdStrike", 8.5)
        4. Review improvements
    """
    return api_post('/api/v2/code/optimize-opsec', {
        'source_code': source_code,
        'target_av': target_av,
        'target_score': target_score,
        'max_iterations': max_iterations
    })


# ============================================================================
# TECHNIQUE SELECTION TOOLS
# ============================================================================

@mcp.tool()
def validate_code(
    source_code: str,
    output_name: str = "payload",
    validate_functionality: bool = False
) -> Dict:
    """
    ✅ Validate code - compilation check + quality analysis + error feedback.

    This tool allows AI to verify code BEFORE final delivery and get detailed
    error feedback for fixing and retrying.

    Args:
        source_code: The C/C++ source code to validate
        output_name: Name for compiled binary (if compilation succeeds)
        validate_functionality: Whether to run basic functionality tests

    Returns:
        {
            "compilation": {
                "status": "passed|failed|error",
                "output": "path/to/binary.exe",  # if passed
                "errors": [...],  # if failed
                "suggestions": [  # AI-friendly fix suggestions
                    "Add missing variable declarations",
                    "Fix type mismatches"
                ]
            },
            "quality": {
                "score": 8.5,  # 0-10 scale
                "issues": ["Contains suspicious strings", ...],
                "strengths": ["Uses direct syscalls", ...],
                "status": "good|needs_improvement"
            },
            "overall_verdict": "ready_for_use|needs_improvement"
        }

    Example AI Workflow:
        1. generate_code() creates malware code
        2. validate_code(code) checks compilation + quality
        3. If verdict is "needs_improvement":
           - Review compilation.suggestions
           - Fix the code
           - validate_code(fixed_code) again
        4. If verdict is "ready_for_use", deliver to user
    """
    return api_post('/api/v2/code/validate', {
        'source_code': source_code,
        'output_name': output_name,
        'validate_functionality': validate_functionality
    })


# ============================================================================
# TECHNIQUE SELECTION TOOLS
# ============================================================================

@mcp.tool()
def select_techniques(
    goal: str,
    target_av: str,
    max_techniques: int = 5,
    complexity: str = "medium"
) -> Dict:
    """
    🎯 Intelligent technique selection using RAG + historical effectiveness.

    The AI can use this for recommendations, then make final decisions.
    Combines RAG intelligence with learning engine effectiveness scores.

    Args:
        goal: High-level goal (e.g., "evade CrowdStrike for process injection")
        target_av: Target AV/EDR
        max_techniques: Maximum techniques to recommend
        complexity: "low", "medium", "high"

    Returns:
        {
            "recommended_techniques": [
                {
                    "technique_id": "syscalls",
                    "name": "Direct System Calls",
                    "effectiveness_score": 8.5,
                    "rag_evidence": "Found in 15 GitHub repos, 3 research papers",
                    "rationale": "High effectiveness against CrowdStrike hooks"
                }
            ],
            "alternatives": [...]
        }

    Example AI Workflow:
        1. select_techniques("evade CrowdStrike", "CrowdStrike")
        2. Review recommendations
        3. analyze_technique() on top recommendations
        4. Make informed decision
    """
    return api_post('/api/v2/techniques/select', {
        'goal': goal,
        'target_av': target_av,
        'constraints': {
            'max_techniques': max_techniques,
            'complexity': complexity
        }
    })


@mcp.tool()
def compare_techniques(
    technique_ids: List[str],
    target_av: str,
    criteria: str = "effectiveness,stealth,complexity"
) -> Dict:
    """
    ⚖️ Compare multiple techniques using RAG intelligence.

    Args:
        technique_ids: Techniques to compare (e.g., ["syscalls", "injection"])
        target_av: Target AV/EDR
        criteria: Comparison criteria (comma-separated)

    Returns:
        {
            "comparison_table": {
                "syscalls": {"effectiveness": 8.5, "stealth": 9.0},
                "injection": {"effectiveness": 7.2, "stealth": 6.5}
            },
            "winner_by_criteria": {"effectiveness": "syscalls"},
            "recommendation": "Use syscalls for maximum effectiveness"
        }
    """
    criteria_list = criteria.split(',') if isinstance(criteria, str) else criteria

    return api_post('/api/v2/techniques/compare', {
        'technique_ids': technique_ids,
        'target_av': target_av,
        'comparison_criteria': criteria_list
    })


# ============================================================================
# COMPILATION & FEEDBACK TOOLS
# ============================================================================

@mcp.tool()
def compile_code(
    source_code: str,
    output_name: str = "payload",
    architecture: str = "x64",
    optimization: str = "O2"
) -> Dict:
    """
    🔨 Compile code to binary.

    Args:
        source_code: C/C++ code to compile
        output_name: Output filename (default: "payload")
        architecture: x86 or x64 (default: "x64")
        optimization: O0, O1, O2, O3 (default: "O2")

    Returns:
        {
            "success": True,
            "binary_path": "path/to/payload.exe",
            "size_bytes": 45056,
            "warnings": [...]
        }
    """
    return api_post('/api/compile', {
        'code': source_code,
        'output_name': output_name,
        'architecture': architecture,
        'optimization': optimization
    })


@mcp.tool()
def record_feedback(
    technique_ids: List[str],
    target_av: str,
    detected: bool,
    details: str = None
) -> Dict:
    """
    📊 Record detection feedback to improve RAG intelligence.

    The AI should prompt user to record results after testing.
    This improves future recommendations and effectiveness scores.

    Args:
        technique_ids: Techniques that were tested
        target_av: AV/EDR tested against
        detected: Was it detected? (True/False)
        details: Optional details about detection

    Returns:
        {
            "recorded": True,
            "updated_effectiveness_scores": {...},
            "indexed_to_rag": True
        }
    """
    return api_post('/api/v2/learning/record-detection', {
        'technique_ids': technique_ids,
        'target_av': target_av,
        'detected': detected,
        'detection_details': details
    })


# ============================================================================
# UTILITY TOOLS
# ============================================================================

@mcp.tool()
def rag_stats() -> Dict:
    """
    📈 Get RAG system statistics and health.

    Returns:
        {
            "enabled": True,
            "total_documents": 1247,
            "knowledge_base_chunks": 89,
            "github_repos": 45,
            "research_papers": 23,
            "blog_posts": 12,
            "detection_patterns": 8
        }
    """
    return api_get('/api/v2/rag/stats')


# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Noctis-MCP Agentic Client")
    parser.add_argument('--server', default="http://localhost:8888", help='Server URL')
    args = parser.parse_args()

    SERVER_URL = args.server

    # Check server connectivity
    if not check_server():
        print(f"[!] Cannot connect to Noctis server at {SERVER_URL}")
        print(f"[!] Start server with: python server/noctis_server.py --port 8888")
        sys.exit(1)

    print("="*70)
    print("  Noctis-MCP Agentic Client v3.0")
    print("="*70)
    print(f"\n[+] Connected to server: {SERVER_URL}")

    # Get RAG stats directly via API (can't call decorated function)
    try:
        stats = api_get('/api/v2/rag/stats')
        if stats.get('enabled'):
            print(f"[+] RAG System: ENABLED")
            print(f"    - Knowledge chunks: {stats.get('knowledge_base', 0)}")
            print(f"    - GitHub repos: {stats.get('github_repos', 0)}")
            print(f"    - Research papers: {stats.get('research_papers', 0)}")
            print(f"    - Blog posts: {stats.get('blog_posts', 0)}")
        else:
            print(f"[!] RAG System: DISABLED")
    except:
        print(f"[!] Could not fetch RAG stats")

    print(f"\n[*] 11 Agentic Tools Available:")
    print(f"    Intelligence: search_intelligence, analyze_technique, fetch_latest")
    print(f"    Code: generate_code, optimize_opsec, validate_code")
    print(f"    Selection: select_techniques, compare_techniques")
    print(f"    Build: compile_code, record_feedback")
    print(f"    Utils: rag_stats")
    print(f"\n[*] MCP server starting in STDIO mode for IDE integration...")
    print(f"[*] Tools will be exposed to Cursor/VSCode via Model Context Protocol")
    print("="*70 + "\n")

    # Run MCP server in stdio mode (required for Cursor/VSCode)
    # This allows the IDE to communicate with the MCP server via stdin/stdout
    import asyncio
    asyncio.run(mcp.run_stdio_async())
