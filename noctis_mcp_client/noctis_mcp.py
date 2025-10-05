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

11 Agentic Tools (with SMART AUTO-UPDATE):
  Intelligence Gathering:
    1. search_intelligence() - Search RAG (AUTO-UPDATES if >7 days old)
    2. analyze_technique() - Deep dive into specific techniques
    3. fetch_latest() - Get cutting-edge intelligence (24hr smart cache)

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
) -> str:
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

    response = api_post('/api/v2/intelligence/search', {
        'query': query,
        'target_av': target_av,
        'sources': sources_list,
        'max_results': max_results
    })
    return format_response(response, "search")


@mcp.tool()
def analyze_technique(
    technique_id: str,
    target_av: str = None,
    include_code_examples: bool = True
) -> str:
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
    response = api_post('/api/v2/intelligence/analyze', {
        'technique_id': technique_id,
        'target_av': target_av,
        'include_code_examples': include_code_examples
    })
    return format_response(response, "technique")


@mcp.tool()
def fetch_latest(
    topic: str,
    sources: str = "github,arxiv,blogs",
    days_back: int = 30
) -> str:
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

    response = api_post('/api/v2/intelligence/fetch-latest', {
        'topic': topic,
        'sources': sources_list,
        'days_back': days_back
    }, timeout=120)
    return format_response(response, "general")


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
) -> str:
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
    response = api_post('/api/v2/code/generate', {
        'technique_ids': technique_ids,
        'target_av': target_av,
        'target_os': target_os,
        'architecture': architecture,
        'use_rag_context': use_rag,
        'opsec_level': opsec_level
    })
    return format_response(response, 'code')


@mcp.tool()
def optimize_opsec(
    source_code: str,
    target_av: str,
    target_score: float = 8.0,
    max_iterations: int = 3
) -> str:
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
    response = api_post('/api/v2/code/optimize-opsec', {
        'source_code': source_code,
        'target_av': target_av,
        'target_score': target_score,
        'max_iterations': max_iterations
    })
    return format_response(response, 'general')


# ============================================================================
# TECHNIQUE SELECTION TOOLS
# ============================================================================

@mcp.tool()
def validate_code(
    source_code: str,
    output_name: str = "payload",
    validate_functionality: bool = False
) -> str:
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
    response = api_post('/api/v2/code/validate', {
        'source_code': source_code,
        'output_name': output_name,
        'validate_functionality': validate_functionality
    })
    return format_response(response, 'general')


# ============================================================================
# TECHNIQUE SELECTION TOOLS
# ============================================================================

@mcp.tool()
def select_techniques(
    goal: str,
    target_av: str,
    max_techniques: int = 5,
    complexity: str = "medium"
) -> str:
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
    response = api_post('/api/v2/techniques/select', {
        'goal': goal,
        'target_av': target_av,
        'constraints': {
            'max_techniques': max_techniques,
            'complexity': complexity
        }
    })
    return format_response(response, 'general')


@mcp.tool()
def compare_techniques(
    technique_ids: List[str],
    target_av: str,
    criteria: str = "effectiveness,stealth,complexity"
) -> str:
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

    response = api_post('/api/v2/techniques/compare', {
        'technique_ids': technique_ids,
        'target_av': target_av,
        'comparison_criteria': criteria_list
    })
    return format_response(response, 'comparison')


# ============================================================================
# COMPILATION & FEEDBACK TOOLS
# ============================================================================

@mcp.tool()
def compile_code(
    source_code: str,
    output_name: str = "payload",
    architecture: str = "x64",
    optimization: str = "O2"
) -> str:
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
    response = api_post('/api/compile', {
        'code': source_code,
        'output_name': output_name,
        'architecture': architecture,
        'optimization': optimization
    })
    return format_response(response, 'general')


@mcp.tool()
def record_feedback(
    technique_ids: List[str],
    target_av: str,
    detected: bool,
    details: str = None
) -> str:
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
    response = api_post('/api/v2/learning/record-detection', {
        'technique_ids': technique_ids,
        'target_av': target_av,
        'detected': detected,
        'detection_details': details
    })
    return format_response(response, 'general')


# ============================================================================
# UTILITY TOOLS
# ============================================================================

@mcp.tool()
def rag_stats() -> str:
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
    response = api_get('/api/v2/rag/stats')
    return format_response(response, 'stats')




# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

# ============================================================================
# FORMATTING FUNCTIONS - Enhanced for clean, spaced, pretty output
# ============================================================================

def format_response(data: Dict, format_type: str = "general") -> str:
    """
    Format MCP tool responses for beautiful display in IDE chat.
    Enhanced with better spacing, visual hierarchy, and clean structure.
    """
    if isinstance(data, dict) and 'error' in data:
        return _format_error(data['error'])

    if format_type == "search":
        return _format_search_results(data)
    elif format_type == "technique":
        return _format_technique_analysis(data)
    elif format_type == "code":
        return _format_code_generation(data)
    elif format_type == "comparison":
        return _format_technique_comparison(data)
    elif format_type == "stats":
        return _format_rag_stats(data)
    else:
        return _format_general(data)


def _format_error(error_msg: str) -> str:
    """Format error messages with clear visual structure"""
    lines = [
        "",
        "╔" + "═" * 78 + "╗",
        "║" + " ❌ ERROR ".center(78) + "║",
        "╠" + "═" * 78 + "╣",
        "",
    ]
    
    # Wrap error message for readability
    import textwrap
    wrapped = textwrap.wrap(str(error_msg), width=74)
    for line in wrapped:
        lines.append("║  " + line.ljust(76) + "║")
    
    lines.extend([
        "",
        "╚" + "═" * 78 + "╝",
        ""
    ])
    
    return "\n".join(lines)

def _format_search_results(data: Dict) -> str:
    """Format intelligence search results with enhanced spacing and structure"""
    lines = [
        "",
        "╔" + "═" * 78 + "╗",
        "║" + " 🔍 INTELLIGENCE SEARCH RESULTS ".ljust(78) + "║",
        "╚" + "═" * 78 + "╝",
        ""
    ]
    
    results = data.get('results', [])
    total = data.get('total_results', 0)
    
    if total > 0:
        lines.append(f"✅ Found {total} intelligence source{'s' if total != 1 else ''}")
        lines.append("")
        lines.append("─" * 80)
        lines.append("")
        
        for i, result in enumerate(results[:10], 1):
            source = result.get('source', 'unknown')
            title = result.get('title', 'No title')
            url = result.get('url', '')
            relevance = result.get('relevance_score', 0)
            content = result.get('content', '')
            
            # Source emoji
            source_emoji = {
                'knowledge_base': '📚',
                'github': '🐙', 
                'arxiv': '📄',
                'blog': '📝'
            }.get(source, '❓')
            
            # Result header
            lines.append(f"🔹 Result {i}/{min(len(results), 10)}")
            lines.append("")
            
            # Source and relevance with visual bar
            relevance_bar = '█' * int(relevance * 10) + '░' * (10 - int(relevance * 10))
            lines.append(f"   {source_emoji}  Source:     {source.upper()}")
            lines.append(f"   📊 Relevance:  {relevance:.2f}/1.0  [{relevance_bar}]")
            lines.append("")
            
            # Title
            lines.append(f"   📝 Title:")
            import textwrap
            for title_line in textwrap.wrap(title, width=70):
                lines.append(f"      {title_line}")
            lines.append("")
            
            # URL
            if url:
                lines.append(f"   🔗 URL:")
                lines.append(f"      {url}")
                lines.append("")
            
            # Content preview
            if content:
                lines.append(f"   📄 Preview:")
                preview = content[:300] + "..." if len(content) > 300 else content
                for content_line in textwrap.wrap(preview, width=70):
                    lines.append(f"      {content_line}")
                lines.append("")
            
            # Separator between results
            if i < min(len(results), 10):
                lines.append("─" * 80)
                lines.append("")
        
        lines.append("═" * 80)
    else:
        lines.append("❌ No intelligence sources found")
        lines.append("")
    
    lines.append("")
    return "\n".join(lines)

def _format_technique_analysis(data: Dict) -> str:
    """Format technique analysis results with enhanced spacing and structure"""
    import textwrap
    
    lines = [
        "",
        "╔" + "═" * 78 + "╗",
        "║" + " 🔬 TECHNIQUE ANALYSIS ".ljust(78) + "║",
        "╚" + "═" * 78 + "╝",
        ""
    ]
    
    technique_id = data.get('technique_id', 'Unknown')
    technique_name = data.get('name', technique_id)
    
    lines.append(f"🎯 Technique: {technique_name}")
    lines.append(f"   ID: {technique_id}")
    lines.append("")
    lines.append("═" * 80)
    lines.append("")
    
    # Conceptual knowledge
    knowledge = data.get('conceptual_knowledge', '')
    if knowledge:
        lines.append("📚 CONCEPTUAL KNOWLEDGE")
        lines.append("")
        for line in textwrap.wrap(knowledge, width=76):
            lines.append(f"   {line}")
        lines.append("")
        lines.append("─" * 80)
        lines.append("")
    
    # GitHub implementations
    github = data.get('github_implementations', [])
    if github:
        lines.append(f"🐙 GITHUB IMPLEMENTATIONS ({len(github)} found)")
        lines.append("")
        for i, impl in enumerate(github[:5], 1):
            repo = impl.get('repo', 'Unknown')
            url = impl.get('url', '')
            stars = impl.get('stars', 'N/A')
            description = impl.get('description', '')
            
            lines.append(f"   [{i}] {repo}")
            if stars != 'N/A':
                lines.append(f"       ⭐ Stars: {stars}")
            if url:
                lines.append(f"       🔗 {url}")
            if description:
                for desc_line in textwrap.wrap(description, width=70):
                    lines.append(f"       📝 {desc_line}")
            lines.append("")
        
        if len(github) > 5:
            lines.append(f"   ... and {len(github) - 5} more implementations")
            lines.append("")
        
        lines.append("─" * 80)
        lines.append("")
    
    # Research papers
    papers = data.get('research_papers', [])
    if papers:
        lines.append(f"📄 RESEARCH PAPERS ({len(papers)} found)")
        lines.append("")
        for i, paper in enumerate(papers[:5], 1):
            title = paper.get('title', 'Unknown')
            url = paper.get('url', '')
            summary = paper.get('summary', '')
            year = paper.get('year', '')
            
            lines.append(f"   [{i}] {title}")
            if year:
                lines.append(f"       📅 Year: {year}")
            if url:
                lines.append(f"       🔗 {url}")
            if summary:
                for sum_line in textwrap.wrap(summary, width=70):
                    lines.append(f"       📋 {sum_line}")
            lines.append("")
        
        if len(papers) > 5:
            lines.append(f"   ... and {len(papers) - 5} more papers")
            lines.append("")
        
        lines.append("─" * 80)
        lines.append("")
    
    # Blog posts
    blogs = data.get('blog_posts', [])
    if blogs:
        lines.append(f"📝 BLOG POSTS ({len(blogs)} found)")
        lines.append("")
        for i, blog in enumerate(blogs[:3], 1):
            title = blog.get('title', 'Unknown')
            url = blog.get('url', '')
            author = blog.get('author', '')
            
            lines.append(f"   [{i}] {title}")
            if author:
                lines.append(f"       ✍️  Author: {author}")
            if url:
                lines.append(f"       🔗 {url}")
            lines.append("")
        
        lines.append("─" * 80)
        lines.append("")
    
    # Effectiveness scores
    effectiveness = data.get('effectiveness_vs_av', {})
    if effectiveness:
        lines.append("🛡️ EFFECTIVENESS AGAINST AV/EDR")
        lines.append("")
        for av, score in sorted(effectiveness.items(), key=lambda x: x[1], reverse=True):
            score_val = float(score)
            bar = '█' * int(score_val) + '░' * (10 - int(score_val))
            
            # Color coding based on effectiveness
            if score_val >= 8:
                emoji = "🟢"
            elif score_val >= 6:
                emoji = "🟡"
            else:
                emoji = "🔴"
            
            lines.append(f"   {emoji} {av:<25} {score_val:.1f}/10  [{bar}]")
        
        lines.append("")
        lines.append("─" * 80)
        lines.append("")
    
    # Recommended combinations
    combinations = data.get('recommended_combinations', [])
    if combinations:
        lines.append("🔗 RECOMMENDED TECHNIQUE COMBINATIONS")
        lines.append("")
        for i, combo in enumerate(combinations, 1):
            lines.append(f"   {i}. {combo}")
        lines.append("")
        lines.append("─" * 80)
        lines.append("")
    
    # OPSEC considerations
    opsec = data.get('opsec_considerations', '')
    if opsec:
        lines.append("⚠️  OPSEC CONSIDERATIONS")
        lines.append("")
        for line in textwrap.wrap(opsec, width=76):
            lines.append(f"   {line}")
        lines.append("")
        lines.append("─" * 80)
        lines.append("")
    
    lines.append("═" * 80)
    lines.append("")
    
    return "\n".join(lines)

def _format_code_generation(data: Dict) -> str:
    """Format code generation results with enhanced spacing and structure"""
    import textwrap
    
    lines = [
        "",
        "╔" + "═" * 78 + "╗",
        "║" + " 💻 CODE GENERATION COMPLETE ".ljust(78) + "║",
        "╚" + "═" * 78 + "╝",
        ""
    ]
    
    # Summary header
    target_av = data.get('target_av', 'Unknown')
    target_os = data.get('target_os', 'Unknown')
    architecture = data.get('architecture', 'Unknown')
    
    lines.append("📋 GENERATION SUMMARY")
    lines.append("")
    lines.append(f"   🎯 Target AV/EDR:  {target_av}")
    lines.append(f"   💾 Target OS:      {target_os}")
    lines.append(f"   🏗️  Architecture:   {architecture}")
    lines.append("")
    lines.append("═" * 80)
    lines.append("")
    
    # Techniques implemented
    techniques = data.get('techniques_used', [])
    if techniques:
        lines.append("🎯 TECHNIQUES IMPLEMENTED")
        lines.append("")
        for i, tech in enumerate(techniques, 1):
            lines.append(f"   {i}. {tech}")
        lines.append("")
        lines.append("─" * 80)
        lines.append("")
    
    # OPSEC Score
    opsec_score = data.get('opsec_score', None)
    if opsec_score is not None:
        score_val = float(opsec_score)
        bar = '█' * int(score_val) + '░' * (10 - int(score_val))
        
        if score_val >= 8:
            emoji = "🟢"
            rating = "EXCELLENT"
        elif score_val >= 6:
            emoji = "🟡"
            rating = "GOOD"
        elif score_val >= 4:
            emoji = "🟠"
            rating = "MODERATE"
        else:
            emoji = "🔴"
            rating = "LOW"
        
        lines.append("🛡️ OPSEC RATING")
        lines.append("")
        lines.append(f"   {emoji} Score: {score_val:.1f}/10  [{bar}]  {rating}")
        lines.append("")
        lines.append("─" * 80)
        lines.append("")
    
    # Files saved
    files = data.get('files_saved', {})
    if files:
        lines.append("📁 GENERATED FILES")
        lines.append("")
        if 'source_file' in files:
            lines.append(f"   📄 Source Code:  {files['source_file']}")
        if 'header_file' in files:
            lines.append(f"   📋 Header File:  {files['header_file']}")
        if 'output_directory' in files:
            lines.append(f"   📂 Directory:    {files['output_directory']}")
        lines.append("")
        lines.append("─" * 80)
        lines.append("")
    
    # MITRE ATT&CK TTPs
    mitre = data.get('mitre_ttps', [])
    if mitre:
        lines.append("🎯 MITRE ATT&CK TACTICS & TECHNIQUES")
        lines.append("")
        for ttp in mitre:
            lines.append(f"   • {ttp}")
        lines.append("")
        lines.append("─" * 80)
        lines.append("")
    
    # Dependencies
    deps = data.get('dependencies', [])
    if deps:
        lines.append(f"📦 DEPENDENCIES ({len(deps)} total)")
        lines.append("")
        for dep in deps[:8]:  # Show first 8
            lines.append(f"   • {dep}")
        if len(deps) > 8:
            lines.append(f"   ... and {len(deps) - 8} more dependencies")
        lines.append("")
        lines.append("─" * 80)
        lines.append("")
    
    # RAG intelligence used
    rag = data.get('rag_intelligence_used', {})
    if rag:
        github_patterns = rag.get('github_patterns', 0)
        research_insights = rag.get('research_insights', 0)
        blog_recommendations = rag.get('blog_recommendations', 0)
        
        if any([github_patterns, research_insights, blog_recommendations]):
            lines.append("🧠 RAG INTELLIGENCE APPLIED")
            lines.append("")
            if github_patterns > 0:
                lines.append(f"   🐙 GitHub Patterns:        {github_patterns} patterns analyzed")
            if research_insights > 0:
                lines.append(f"   📄 Research Insights:      {research_insights} papers referenced")
            if blog_recommendations > 0:
                lines.append(f"   📝 Blog Recommendations:   {blog_recommendations} posts reviewed")
            lines.append("")
            lines.append("─" * 80)
            lines.append("")
    
    # Compilation info
    compilation = data.get('compilation', {})
    if compilation:
        status = compilation.get('status', 'unknown')
        if status == 'success' or status == 'passed':
            lines.append("✅ COMPILATION STATUS: SUCCESS")
            binary = compilation.get('output', '')
            if binary:
                lines.append("")
                lines.append(f"   📦 Binary Output: {binary}")
            size = compilation.get('size_bytes', 0)
            if size > 0:
                size_kb = size / 1024
                lines.append(f"   📊 Binary Size:   {size_kb:.1f} KB")
        elif status == 'failed':
            lines.append("❌ COMPILATION STATUS: FAILED")
            errors = compilation.get('errors', [])
            if errors:
                lines.append("")
                lines.append("   Errors:")
                for err in errors[:3]:
                    for err_line in textwrap.wrap(err, width=70):
                        lines.append(f"      • {err_line}")
        lines.append("")
        lines.append("─" * 80)
        lines.append("")
    
    # Warnings
    warnings = data.get('warnings', [])
    if warnings:
        lines.append("⚠️  WARNINGS & RECOMMENDATIONS")
        lines.append("")
        for warning in warnings:
            for warn_line in textwrap.wrap(warning, width=74):
                lines.append(f"   ⚠ {warn_line}")
        lines.append("")
        lines.append("─" * 80)
        lines.append("")
    
    # Code Preview
    source_code_preview = data.get('source_code', '')
    if source_code_preview:
        preview_lines = source_code_preview.split('\n')
        total_lines = len(preview_lines)
        preview_count = min(25, total_lines)
        
        lines.append(f"📝 CODE PREVIEW (showing {preview_count} of {total_lines} lines)")
        lines.append("")
        lines.append("```c")
        for i, line in enumerate(preview_lines[:preview_count], 1):
            lines.append(f"{i:4d} | {line}")
        if total_lines > preview_count:
            lines.append(f"     | ... {total_lines - preview_count} more lines ...")
        lines.append("```")
        lines.append("")
        lines.append("─" * 80)
        lines.append("")
    
    lines.append("═" * 80)
    lines.append("")
    lines.append("✅ Code generation complete! Review the generated files above.")
    lines.append("")
    
    return "\n".join(lines)

def _format_technique_comparison(data: Dict) -> str:
    """Format technique comparison results"""
    output = []
    output.append("\n⚖️ === TECHNIQUE COMPARISON ===\n")
    
    comparison = data.get('comparison_table', {})
    if comparison:
        output.append("📊 COMPARISON TABLE:")
        for technique, scores in comparison.items():
            output.append(f"\n🎯 {technique}:")
            for criterion, score in scores.items():
                bar = '█' * int(score) + '░' * (10 - int(score))
                output.append(f"    {criterion}: {score}/10 [{bar}]")
    
    winner = data.get('winner_by_criteria', {})
    if winner:
        output.append(f"\n🏆 WINNERS BY CRITERIA:")
        for criterion, technique in winner.items():
            output.append(f"    {criterion}: {technique}")
    
    recommendation = data.get('recommendation', '')
    if recommendation:
        output.append(f"\n💡 RECOMMENDATION:")
        output.append(f"    {recommendation}")
    
    return "\n".join(output)

def _format_rag_stats(data: Dict) -> str:
    """Format RAG system statistics"""
    output = []
    output.append("\n📊 === RAG INTELLIGENCE SYSTEM STATUS ===\n")
    
    enabled = data.get('enabled', False)
    status_emoji = "✅" if enabled else "❌"
    output.append(f"{status_emoji} System Status: {'ENABLED' if enabled else 'DISABLED'}")
    
    embedding_model = data.get('embedding_model', 'Unknown')
    vector_db = data.get('vector_db', 'Unknown')
    output.append(f"🧠 Embedding Model: {embedding_model}")
    output.append(f"🗄️ Vector Database: {vector_db}")
    output.append("")
    
    output.append("📚 INTELLIGENCE SOURCES:")
    knowledge_base = data.get('knowledge_base', 0)
    github_repos = data.get('github_repos', 0)
    research_papers = data.get('research_papers', 0)
    blog_posts = data.get('blog_posts', 0)
    detection_intel = data.get('detection_intel', 0)
    
    output.append(f" 📖 Knowledge Base: {knowledge_base} chunks indexed")
    output.append(f" 🐙 GitHub Repositories: {github_repos} indexed")
    output.append(f" 📄 Research Papers: {research_papers} indexed")
    output.append(f" 📝 Blog Posts: {blog_posts} indexed")
    output.append(f" 🛡️ Detection Intelligence: {detection_intel} patterns")
    output.append("")
    
    total = knowledge_base + github_repos + research_papers + blog_posts + detection_intel
    output.append(f"📈 TOTAL INTELLIGENCE: {total} sources indexed")
    output.append("")
    
    output.append("Status: UNKNOWN")
    
    return "\n".join(output)

def _format_general(data: Dict) -> str:
    """Format general responses"""
    if isinstance(data, dict):
        output = []
        for key, value in data.items():
            if isinstance(value, (dict, list)):
                output.append(f"{key}: {str(value)[:100]}...")
            else:
                output.append(f"{key}: {value}")
        return "\n".join(output)
    else:
        return str(data)

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
    except Exception as e:
        # Expected on first run before server starts
        print(f"[!] Could not fetch RAG stats (server not running or RAG disabled)")

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
