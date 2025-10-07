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

20 Agentic Tools (with SMART AUTO-UPDATE):
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

  Interactive Learning:
    11. list_learning_topics() - Browse curriculum
    12. start_lesson() - Begin learning a technique
    13. get_lesson_module() - Get module content
    14. complete_module() - Mark module as done
    15. check_understanding() - Take quiz
    16. submit_quiz() - Submit quiz answers
    17. get_learning_progress() - View progress
    18. get_recommended_lesson() - Get next suggestion
    19. search_lessons() - Search for topics

  Utilities:
    20. rag_stats() - RAG system status

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
    🧠 Get intelligence to write malware code. YOU (the AI) must write the code.

    ⚠️ CRITICAL: This returns GUIDANCE, not code. After calling this tool:
    → IMMEDIATELY start writing C/C++ code in the editor
    → Use the OPSEC recommendations (avoid detected techniques)
    → Follow the implementation patterns (function call order matters)
    → Use the function signatures provided
    → Apply the synthesis recommendations

    Returns intelligence from 4 sources:
    - Knowledge: OPSEC scores, what techniques work best
    - Blogs: What's currently detected by target AV
    - GitHub: How real malware implements techniques (patterns, not code)
    - VX-API: Function signatures you need

    Args:
        technique_ids: Techniques to use (e.g., ["syscalls", "injection"])
        target_av: Target AV/EDR (e.g., "CrowdStrike", "Defender")
        target_os: Target OS (default: "Windows")
        architecture: x86 or x64 (default: "x64")
        use_rag: Use RAG intelligence (default: True)
        opsec_level: "low", "medium", "high"

    After receiving results:
    1. ✅ Check MITRE TTPs to tag your code
    2. ✅ Read OPSEC recommendations - use high-score techniques
    3. ✅ Read warnings - AVOID these detected methods
    4. ✅ Review patterns - follow these function call sequences
    5. ✅ START WRITING CODE using all this guidance
    6. ✅ Include comments explaining OPSEC decisions

    Example:
        After getting results with "OPSEC 8/10: Indirect syscalls" and
        "Warning: Avoid CreateRemoteThread", you should write code that:
        - Uses indirect syscalls (per recommendation)
        - Does NOT use CreateRemoteThread (per warning)
        - Follows the RW→RX memory pattern (per patterns)
        - Uses provided NtAllocate... function signatures
    """
    response = api_post('/api/v2/code/generate', {
        'technique_ids': technique_ids,
        'objective': f"Implement {', '.join(technique_ids)}",
        'target_av': target_av,
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
def test_detection(
    binary_path: str,
    target_av: str = None,
    environment: str = "Windows 10 64-bit"
) -> str:
    """
    🔬 Test binary in live sandbox against real AV/EDR.

    Upload binary to Hybrid Analysis sandbox and get detection results.
    This validates if your malware actually evades the target defenses.

    ⚠️ CRITICAL OPSEC WARNING:
    Hybrid Analysis submissions are PUBLIC. AV vendors monitor it for samples.
    DO NOT upload your final undetected version - it will get signatured!

    SAFE WORKFLOW:
        1-3. Test early iterations (detected = safe to upload)
        4. When close to working: use validate_code() (local, no upload)
        5. If undetected: STOP testing, deliver to user
        6. User tests in controlled/offline environment
        7. User confirms success → record_feedback() to teach system

    UNSAFE WORKFLOW (DON'T DO THIS):
        ❌ Test v1 → detected → improve
        ❌ Test v2 → detected → improve
        ❌ Test v3 → UNDETECTED → upload to Hybrid Analysis
        ❌ Result: AV vendors now have your sample, technique burned

    Args:
        binary_path: Path to compiled binary (from compile_code)
        target_av: Target AV/EDR name (e.g., "CrowdStrike Falcon", "Defender")
        environment: OS environment (default: "Windows 10 64-bit")

    Returns:
        {
            "detected": False,
            "verdict": "no_threats",
            "opsec_score": 9,
            "threat_score": 5,
            "av_detections": 0,
            "detected_by": [],
            "target_detected": False,
            "signatures": [],
            "recommendations": [...]
        }

    RECOMMENDED USAGE:
        - Test EARLY versions to iterate (detected versions are safe)
        - Once OPSEC score hits 7-8, STOP uploading
        - Use validate_code() for final local validation
        - Deliver to user for real-world testing
        - record_feedback() after user confirms success

    Example:
        User: "Build a CrowdStrike bypass and test it"
        AI:
        1. search_intelligence("CrowdStrike bypass")
        2. generate_code(["syscalls"], "CrowdStrike")
        3. Write code v1
        4. compile_code(code_v1)
        5. test_detection() → Detected (OPSEC 4/10) ✓ Safe to upload
        6. Improve based on recommendations
        7. compile_code(code_v2)
        8. test_detection() → Detected (OPSEC 6/10) ✓ Safe to upload
        9. Improve based on recommendations
        10. compile_code(code_v3)
        11. validate_code(code_v3) → Local check (NO UPLOAD) ✓
        12. Looks good! Deliver to user WITHOUT uploading
        13. User: "Tested offline - works!"
        14. record_feedback(["syscalls"], "CrowdStrike", False)
    """
    response = api_post('/api/v2/detection/test', {
        'binary_path': binary_path,
        'target_av': target_av,
        'environment': environment
    })
    return format_response(response, 'detection_result')


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
# EDUCATION TOOLS - Interactive Learning System
# ============================================================================

@mcp.tool()
def list_learning_topics(sort_by: str = "difficulty", difficulty: str = None, category: str = None) -> str:
    """
    📚 List all available malware development techniques you can learn.

    Use this when the user wants to learn about malware techniques or asks
    what topics are available. This shows a curated curriculum of 10 techniques.

    Args:
        sort_by: How to sort (difficulty, category, or title). Default: difficulty
        difficulty: Filter by difficulty level (beginner, intermediate, advanced)
        category: Filter by category (e.g., "Code Injection", "Defense Evasion")

    Returns:
        List of available topics with descriptions, difficulty, and estimated time.

    Example usage:
        - User: "I want to learn malware development"
        - AI calls: list_learning_topics()
        - AI shows the list and asks what they want to learn
    """
    params = {"sort_by": sort_by}
    if difficulty:
        params["difficulty"] = difficulty
    if category:
        params["category"] = category

    response = api_get(f'/api/v2/education/topics?{_build_query_string(params)}')
    return format_response(response, 'learning_topics')


@mcp.tool()
def start_lesson(technique_id: str) -> str:
    """
    🎓 Start learning a specific technique and get lesson overview.

    Call this after the user selects a topic from list_learning_topics().
    This provides an overview of the lesson and its modules.

    Args:
        technique_id: ID of the technique (e.g., 'process_injection', 'shellcode_injection')

    Returns:
        Lesson overview with module list, prerequisites, and difficulty.

    Example flow:
        1. User: "I want to learn process injection"
        2. AI calls: start_lesson('process_injection')
        3. AI shows overview and asks which module to start with
    """
    response = api_get(f'/api/v2/education/topic/{technique_id}')
    return format_response(response, 'lesson_overview')


@mcp.tool()
def get_lesson_module(technique_id: str, module_number: int) -> str:
    """
    📖 Get the content for a specific lesson module.

    Each lesson has multiple modules (theory, code, labs, etc.). Use this to
    deliver the actual teaching content to the user.

    Args:
        technique_id: ID of the technique
        module_number: Module number (starts at 1)

    Returns:
        Module content with theory, code examples, and exercises.

    Example teaching flow:
        1. AI calls: get_lesson_module('process_injection', 1)
        2. AI teaches the content interactively
        3. AI asks if user has questions
        4. When ready, AI moves to next module
    """
    response = api_get(f'/api/v2/education/lesson/{technique_id}/module/{module_number}')
    return format_response(response, 'lesson_module')


@mcp.tool()
def complete_module(technique_id: str, module_number: int) -> str:
    """
    ✅ Mark a module as completed and track progress.

    Call this after the user has finished a module and you've confirmed
    they understand the material.

    Args:
        technique_id: ID of the technique
        module_number: Module number that was completed

    Returns:
        Updated progress and any achievements earned.
    """
    response = api_post(f'/api/v2/education/progress/{technique_id}/module/{module_number}/complete', {})
    return format_response(response, 'module_complete')


@mcp.tool()
def check_understanding(technique_id: str) -> str:
    """
    🧠 Get quiz questions to test understanding of a technique.

    Use this to assess if the user has learned the material. Present
    questions one at a time or all together based on user preference.

    Args:
        technique_id: ID of the technique to quiz on

    Returns:
        Quiz questions (multiple choice, true/false) without answers.

    Teaching flow:
        1. After completing all modules, AI suggests taking the quiz
        2. AI calls: check_understanding('process_injection')
        3. AI presents questions interactively
        4. AI collects answers and calls submit_quiz()
    """
    response = api_get(f'/api/v2/education/quiz/{technique_id}')
    return format_response(response, 'quiz')


@mcp.tool()
def submit_quiz(technique_id: str, answers: Dict[str, int]) -> str:
    """
    📝 Submit quiz answers and get score with explanations.

    Args:
        technique_id: ID of the technique
        answers: Dictionary mapping question IDs to selected option indices
                 Example: {"pi_q1": 0, "pi_q2": 1, "pi_q3": 2}

    Returns:
        Score, correct answers, explanations, and whether user passed.

    Example:
        AI collects user's answers: {"pi_q1": 0, "pi_q2": 1, ...}
        AI calls: submit_quiz('process_injection', answers)
        AI shows score and reviews incorrect answers with explanations
    """
    response = api_post(f'/api/v2/education/quiz/{technique_id}/submit', {"answers": answers})
    return format_response(response, 'quiz_results')


@mcp.tool()
def get_learning_progress() -> str:
    """
    📊 Get overall learning progress across all techniques.

    Shows what techniques the user has started, completed, quiz scores,
    and time spent learning.

    Returns:
        Complete progress summary with achievements.

    Use when:
        - User asks "What have I learned?"
        - User wants to see their progress
        - Recommending what to learn next
    """
    response = api_get('/api/v2/education/progress')
    return format_response(response, 'learning_progress')


@mcp.tool()
def get_recommended_lesson() -> str:
    """
    💡 Get recommended next lesson based on completed topics.

    Analyzes prerequisites and completed lessons to suggest what to
    learn next. Great for guiding the learning path.

    Returns:
        Recommended technique with explanation of why it's suggested.

    Example:
        User: "What should I learn next?"
        AI calls: get_recommended_lesson()
        AI suggests the recommended topic
    """
    response = api_get('/api/v2/education/recommend')
    return format_response(response, 'recommendation')


@mcp.tool()
def search_lessons(query: str) -> str:
    """
    🔍 Search for lessons by keyword.

    Helps users find specific topics they want to learn about.

    Args:
        query: Search term (e.g., "injection", "evasion", "syscalls")

    Returns:
        Matching techniques with descriptions.

    Example:
        User: "How do I learn about hooking?"
        AI calls: search_lessons("hooking")
        AI shows matching techniques
    """
    response = api_get(f'/api/v2/education/search?q={query}')
    return format_response(response, 'search_results')


def _build_query_string(params: Dict) -> str:
    """Helper to build URL query string"""
    return "&".join(f"{k}={v}" for k, v in params.items() if v is not None)


# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

# Formatting functions for beautiful MCP tool responses
def format_response(data: Dict, format_type: str = "general") -> str:
    """
    Format MCP tool responses for beautiful display in IDE chat.
    """
    if isinstance(data, dict) and 'error' in data:
        return f"\n[ERROR] {data['error']}\n"

    if format_type == "search":
        return _format_search_results(data)
    elif format_type == "technique":
        return _format_technique_analysis(data)
    elif format_type == "code":
        return _format_code_generation(data)
    elif format_type == "comparison":
        return _format_technique_comparison(data)
    elif format_type == "detection_result":
        return _format_detection_result(data)
    elif format_type == "stats":
        return _format_rag_stats(data)
    elif format_type == "learning_topics":
        return _format_learning_topics(data)
    elif format_type == "lesson_overview":
        return _format_lesson_overview(data)
    elif format_type == "lesson_module":
        return _format_lesson_module(data)
    elif format_type == "quiz":
        return _format_quiz(data)
    elif format_type == "quiz_results":
        return _format_quiz_results(data)
    elif format_type == "learning_progress":
        return _format_learning_progress(data)
    elif format_type == "recommendation":
        return _format_recommendation(data)
    elif format_type == "module_complete":
        return _format_module_complete(data)
    elif format_type == "search_results":
        return _format_lesson_search(data)
    else:
        return _format_general(data)

def _format_search_results(data: Dict) -> str:
    """Format intelligence search results"""
    output = []
    output.append("\n🔍 === INTELLIGENCE SEARCH RESULTS ===\n")
    
    results = data.get('results', [])
    total = data.get('total_results', 0)
    
    if total > 0:
        output.append(f"✅ Found {total} intelligence sources:\n")
        
        for i, result in enumerate(results[:10], 1):  # Show top 10
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
            
            output.append(f"\n📋 [{i}] {source_emoji} {source.upper()}")
            output.append(f" 📊 Relevance: {relevance:.2f} [{'█' * int(relevance * 10):<10}]")
            output.append(f" 📝 Title: {title}")
            
            if url:
                output.append(f" 🔗 URL: {url}")
            
            # Content preview
            if content:
                preview = content[:200] + "..." if len(content) > 200 else content
                output.append(f" 📄 Content: {preview}")
    else:
        output.append("❌ No intelligence sources found")
    
    return "\n".join(output)

def _format_technique_analysis(data: Dict) -> str:
    """Format technique analysis results"""
    output = []
    output.append("\n🔬 === TECHNIQUE ANALYSIS ===\n")
    
    technique_id = data.get('technique_id', 'Unknown')
    output.append(f"🎯 Technique: {technique_id}")
    
    # Conceptual knowledge
    knowledge = data.get('conceptual_knowledge', '')
    if knowledge:
        output.append(f"\n📚 CONCEPTUAL KNOWLEDGE:")
        output.append(f"    {knowledge}")
    
    # GitHub implementations
    github = data.get('github_implementations', [])
    if github:
        output.append(f"\n🐙 GITHUB IMPLEMENTATIONS ({len(github)}):")
        for i, impl in enumerate(github[:5], 1):
            repo = impl.get('repo', 'Unknown')
            url = impl.get('url', '')
            output.append(f"    [{i}] {repo}")
            if url:
                output.append(f"        🔗 {url}")
    
    # Research papers
    papers = data.get('research_papers', [])
    if papers:
        output.append(f"\n📄 RESEARCH PAPERS ({len(papers)}):")
        for i, paper in enumerate(papers[:3], 1):
            title = paper.get('title', 'Unknown')
            url = paper.get('url', '')
            output.append(f"    [{i}] {title}")
            if url:
                output.append(f"        🔗 {url}")
    
    # Effectiveness scores
    effectiveness = data.get('effectiveness_vs_av', {})
    if effectiveness:
        output.append(f"\n🛡️ EFFECTIVENESS SCORES:")
        for av, score in effectiveness.items():
            bar = '█' * int(score) + '░' * (10 - int(score))
            output.append(f"    {av}: {score}/10 [{bar}]")
    
    # Recommended combinations
    combinations = data.get('recommended_combinations', [])
    if combinations:
        output.append(f"\n🔗 RECOMMENDED COMBINATIONS:")
        for combo in combinations:
            output.append(f"    • {combo}")
    
    return "\n".join(output)

def _format_code_generation(data: Dict) -> str:
    """Format intelligence-driven code generation guidance (NEW HYBRID SYSTEM)"""
    output = []
    output.append("\n🧠 === INTELLIGENCE-DRIVEN CODE GENERATION GUIDANCE ===\n")
    output.append("⚠️  IMPORTANT: This returns INTELLIGENCE for YOU (the AI) to write code.")
    output.append("    DO NOT expect ready-made code files. Use this guidance to write custom code.\n")

    # Objective
    objective = data.get('objective', '')
    if objective:
        output.append(f"🎯 OBJECTIVE: {objective}")

    target_av = data.get('target_av', '')
    opsec_level = data.get('opsec_level', '')
    if target_av or opsec_level:
        output.append(f"🎯 TARGET: {target_av} | OPSEC: {opsec_level}")
        output.append("")

    # Intelligence gathered
    intelligence = data.get('intelligence', {})
    if intelligence:
        output.append("📚 === STRATEGIC INTELLIGENCE ===\n")
        for tech_id, intel in intelligence.items():
            output.append(f"🔹 Technique: {tech_id}")

            # MITRE TTPs
            mitre_ttps = intel.get('mitre_ttps', [])
            if mitre_ttps:
                output.append(f"   📌 MITRE ATT&CK: {', '.join(mitre_ttps)}")

            # Recommendations
            recommendations = intel.get('recommendations', [])
            if recommendations:
                output.append("   ✅ RECOMMENDATIONS:")
                for rec in recommendations[:3]:
                    technique = rec.get('technique', 'Unknown')
                    opsec = rec.get('opsec_score', 0)
                    reason = rec.get('reasoning', rec.get('reason', ''))[:100]
                    output.append(f"      • {technique} (OPSEC: {opsec}/10)")
                    if reason:
                        output.append(f"        → {reason}")

            # Warnings
            warnings = intel.get('warnings', [])
            if warnings:
                output.append("   ⚠️  WARNINGS:")
                for warning in warnings[:3]:
                    output.append(f"      • {warning[:150]}")

            output.append("")

    # Implementation patterns
    patterns = data.get('patterns', {})
    if patterns:
        output.append("🔧 === IMPLEMENTATION PATTERNS ===\n")
        for tech_id, tech_patterns in patterns.items():
            output.append(f"🔹 {tech_id} patterns:")

            # Function sequences
            sequences = tech_patterns.get('function_sequences', [])
            if sequences:
                output.append("   📝 Function Call Sequences:")
                for seq in sequences[:2]:
                    sequence = seq.get('sequence', '')
                    desc = seq.get('description', '')
                    if sequence:
                        output.append(f"      • {sequence}")
                    if desc:
                        output.append(f"        → {desc}")

            # Memory patterns
            mem_patterns = tech_patterns.get('memory_patterns', [])
            if mem_patterns:
                output.append("   💾 Memory Patterns:")
                for pattern in mem_patterns[:3]:
                    output.append(f"      • {pattern}")

            output.append("")

    # VX-API Functions
    vx_functions = data.get('vx_api_functions', [])
    if vx_functions:
        output.append("🔨 === VX-API FUNCTION SIGNATURES ===\n")
        for func in vx_functions[:5]:
            content = func.get('content', '')
            if content:
                # Extract function name
                lines = content.split('\n')
                func_line = lines[0] if lines else content
                output.append(f"   • {func_line[:100]}")
        output.append("")

    # Synthesis (Overall approach)
    synthesis = data.get('synthesis', {})
    if synthesis:
        output.append("💡 === OVERALL APPROACH ===\n")

        approach = synthesis.get('recommended_approach', [])
        if approach:
            output.append("   ✅ Recommended:")
            for item in approach[:3]:
                output.append(f"      • {item}")

        opsec_warnings = synthesis.get('opsec_warnings', [])
        if opsec_warnings:
            output.append("\n   ⚠️  OPSEC Warnings:")
            for warning in opsec_warnings[:3]:
                output.append(f"      • {warning}")

        impl_order = synthesis.get('implementation_order', [])
        if impl_order:
            output.append("\n   📋 Implementation Order:")
            for i, step in enumerate(impl_order[:5], 1):
                output.append(f"      {i}. {step}")

        output.append("")

    output.append("\n" + "═" * 70)
    output.append("⚡ ACTION REQUIRED: START WRITING CODE NOW")
    output.append("═" * 70)
    output.append("\n📝 NEXT STEPS:")
    output.append("   1. Create a new .c file or open existing code")
    output.append("   2. Start writing code using the guidance above")
    output.append("   3. Follow OPSEC recommendations (high scores)")
    output.append("   4. AVOID warned techniques (CreateRemoteThread, etc.)")
    output.append("   5. Use provided function signatures")
    output.append("   6. Add comments explaining OPSEC decisions")
    output.append("   7. After writing, call validate_code() to check")
    output.append("   8. Then call compile_code() to build\n")

    return "\n".join(output)

def _format_detection_result(data: Dict) -> str:
    """Format live detection testing results"""
    output = []
    output.append("\n🔬 === SANDBOX DETECTION TEST RESULTS ===\n")

    detected = data.get('detected', False)
    verdict = data.get('verdict', 'unknown')
    opsec_score = data.get('opsec_score', 0)
    threat_score = data.get('threat_score', 0)

    # Overall verdict
    if detected:
        output.append("⚠️  VERDICT: DETECTED")
    else:
        output.append("✅ VERDICT: UNDETECTED")

    output.append(f"   Classification: {verdict}")
    output.append(f"   Threat Score: {threat_score}/100")
    output.append("")

    # OPSEC Score (visual bar)
    bar = '█' * opsec_score + '░' * (10 - opsec_score)
    output.append(f"🎯 OPSEC SCORE: {opsec_score}/10 [{bar}]")
    output.append("")

    # AV Detections
    av_detections = data.get('av_detections', 0)
    detected_by = data.get('detected_by', [])
    target_av = data.get('target_av')
    target_detected = data.get('target_detected', False)

    output.append(f"🛡️  AV DETECTIONS: {av_detections}/")

    if detected_by:
        output.append("   Detected by:")
        for av in detected_by[:5]:
            emoji = "🎯" if target_av and target_av.lower() in av.lower() else "   "
            output.append(f"   {emoji} {av}")
        if len(detected_by) > 5:
            output.append(f"   ... and {len(detected_by) - 5} more")
    else:
        output.append("   No AV detections reported")

    output.append("")

    # Target AV result
    if target_av:
        if target_detected:
            output.append(f"🎯 TARGET AV ({target_av}): DETECTED ⚠️")
        else:
            output.append(f"🎯 TARGET AV ({target_av}): CLEAN ✅")
        output.append("")

    # Top signatures
    signatures = data.get('signatures', [])
    if signatures:
        output.append("🔍 TOP TRIGGERED SIGNATURES:")
        for sig in signatures[:5]:
            name = sig.get('name', 'Unknown')
            severity = sig.get('severity', 'unknown')
            output.append(f"   • [{severity}] {name}")
        output.append("")

    # Recommendations
    recommendations = data.get('recommendations', [])
    if recommendations:
        output.append("💡 OPSEC RECOMMENDATIONS:")
        for i, rec in enumerate(recommendations[:5], 1):
            if "CRITICAL" in rec:
                output.append(f"   ⚠️  {i}. {rec}")
            else:
                output.append(f"   {i}. {rec}")
        output.append("")

    # Environment info
    environment = data.get('environment')
    if environment:
        output.append(f"🖥️  Test Environment: {environment}")

    sha256 = data.get('sha256')
    if sha256:
        output.append(f"📄 SHA256: {sha256[:16]}...")

    output.append("")
    output.append("═" * 70)

    if detected or target_detected:
        output.append("⚠️  ACTION REQUIRED: IMPROVE OPSEC")
        output.append("═" * 70)
        output.append("\n📝 NEXT STEPS:")
        output.append("   1. Review triggered signatures and recommendations")
        output.append("   2. Call optimize_opsec() for improvement suggestions")
        output.append("   3. Modify code to address detection issues")
        output.append("   4. Recompile with compile_code()")
        output.append("   5. Test again with test_detection() (safe - already detected)")
    else:
        output.append("✅ SUCCESS: UNDETECTED")
        output.append("═" * 70)
        output.append("\n⚠️  CRITICAL OPSEC WARNING:")
        output.append("   This binary is undetected! DO NOT upload it again.")
        output.append("   Hybrid Analysis is PUBLIC - AV vendors monitor it.")
        output.append("   Uploading = giving them your technique to signature.")
        output.append("")
        output.append("📝 NEXT STEPS:")
        output.append("   1. STOP testing - don't burn this technique")
        output.append("   2. Deliver binary to user for controlled testing")
        output.append("   3. User tests in offline/isolated environment")
        output.append("   4. If user confirms success:")
        output.append("      → Call record_feedback() to teach the system")
        output.append("      → System learns without burning the technique")
        output.append("")
        output.append("   Alternative: Use validate_code() for local checks (no upload)")

    output.append("")

    return "\n".join(output)


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


# ============================================================================
# EDUCATION FORMATTING FUNCTIONS
# ============================================================================

def _format_learning_topics(data: Dict) -> str:
    """Format list of learning topics"""
    output = []
    output.append("\n📚 === MALWARE DEVELOPMENT CURRICULUM ===\n")

    topics = data.get('topics', [])
    count = data.get('count', 0)

    if count == 0:
        return "\n[!] No topics available\n"

    output.append(f"✅ {count} techniques available:\n")

    # Group by difficulty
    beginner = [t for t in topics if t['difficulty'] == 'beginner']
    intermediate = [t for t in topics if t['difficulty'] == 'intermediate']
    advanced = [t for t in topics if t['difficulty'] == 'advanced']

    if beginner:
        output.append("🟢 BEGINNER LEVEL:")
        for t in beginner:
            output.append(f"  • {t['title']} ({t['estimated_minutes']} min)")
            output.append(f"    ID: {t['id']}")
            output.append(f"    {t['description']}\n")

    if intermediate:
        output.append("🟡 INTERMEDIATE LEVEL:")
        for t in intermediate:
            prereq_str = f" [Requires: {', '.join(t['prerequisites'])}]" if t['prerequisites'] else ""
            output.append(f"  • {t['title']} ({t['estimated_minutes']} min){prereq_str}")
            output.append(f"    ID: {t['id']}")
            output.append(f"    {t['description']}\n")

    if advanced:
        output.append("🔴 ADVANCED LEVEL:")
        for t in advanced:
            prereq_str = f" [Requires: {', '.join(t['prerequisites'])}]" if t['prerequisites'] else ""
            output.append(f"  • {t['title']} ({t['estimated_minutes']} min){prereq_str}")
            output.append(f"    ID: {t['id']}")
            output.append(f"    {t['description']}\n")

    return "\n".join(output)


def _format_lesson_overview(data: Dict) -> str:
    """Format lesson overview"""
    output = []
    topic = data.get('topic', {})

    if not topic:
        return "\n[!] Topic not found\n"

    output.append(f"\n🎓 === {topic['title']} ===\n")
    output.append(f"Difficulty: {topic['difficulty'].upper()}")
    output.append(f"Category: {topic['category']}")
    output.append(f"Estimated Time: {topic['estimated_minutes']} minutes")

    if topic.get('prerequisites'):
        output.append(f"Prerequisites: {', '.join(topic['prerequisites'])}")

    output.append(f"\nDescription:")
    output.append(topic['description'])

    output.append(f"\nModules ({len(topic['modules'])}):")
    for mod in topic['modules']:
        mod_emoji = {'theory': '📖', 'code': '💻', 'lab': '🧪', 'quiz': '🧠'}.get(mod['type'], '📄')
        output.append(f"  {mod['module_number']}. {mod_emoji} {mod['title']} ({mod['type']})")

    output.append("\nTo start learning, use: get_lesson_module('" + topic['id'] + "', 1)")

    return "\n".join(output)


def _format_lesson_module(data: Dict) -> str:
    """Format lesson module content"""
    module = data.get('module', {})

    if not module:
        return "\n[!] Module not found\n"

    output = []
    output.append(f"\n📖 Module {module['module_number']}: {module['title']}")
    output.append("=" * 70)
    output.append(f"Type: {module['type'].upper()}\n")

    # Main content
    output.append(module['content'])

    # Code examples if present
    if module.get('code_examples'):
        output.append("\n" + "=" * 70)
        output.append("📁 CODE EXAMPLES:")
        for ex in module['code_examples']:
            output.append(f"\n  • {ex['title']} ({ex['language']})")
            output.append(f"    {ex['description']}")

    output.append("\n" + "=" * 70)
    output.append("When ready for next module, use: get_lesson_module() with next module number")
    output.append("To mark as complete: complete_module()")

    return "\n".join(output)


def _format_quiz(data: Dict) -> str:
    """Format quiz questions"""
    output = []

    output.append(f"\n🧠 === QUIZ: {data.get('technique_title', 'Unknown')} ===\n")
    output.append(f"Total Questions: {data.get('total_questions', 0)}")
    output.append(f"Passing Score: {data.get('passing_score', 70)}%\n")

    questions = data.get('questions', [])

    for i, q in enumerate(questions, 1):
        output.append(f"\nQuestion {i} [{q['difficulty'].upper()}]:")
        output.append(q['question'])
        output.append("\nOptions:")
        for idx, opt in enumerate(q['options']):
            output.append(f"  {idx}. {opt}")
        output.append(f"\n[Question ID: {q['id']}]")

    output.append("\n" + "=" * 70)
    output.append("To submit answers: submit_quiz(technique_id, answers_dict)")
    output.append("Example: submit_quiz('process_injection', {'pi_q1': 0, 'pi_q2': 1, ...})")

    return "\n".join(output)


def _format_quiz_results(data: Dict) -> str:
    """Format quiz results"""
    output = []

    score = data.get('score', 0)
    passed = data.get('passed', False)
    correct = data.get('correct_count', 0)
    total = data.get('total_questions', 0)

    output.append("\n📝 === QUIZ RESULTS ===\n")

    if passed:
        output.append(f"✅ PASSED! Score: {score}% ({correct}/{total} correct)")
    else:
        output.append(f"❌ Not passed. Score: {score}% ({correct}/{total} correct)")
        output.append(f"   Required: {data.get('passing_score', 70)}%")

    output.append("\nDetailed Results:")

    results = data.get('results', [])
    for i, r in enumerate(results, 1):
        status = "✅" if r['is_correct'] else "❌"
        output.append(f"\n{status} Question {i}:")
        output.append(f"   Your answer: {r['user_answer']}")
        output.append(f"   Correct answer: {r['correct_answer']}")
        output.append(f"   💡 {r['explanation']}")

    achievements = data.get('new_achievements', [])
    if achievements:
        output.append("\n🏆 NEW ACHIEVEMENTS UNLOCKED:")
        for ach in achievements:
            output.append(f"  • {ach}")

    return "\n".join(output)


def _format_learning_progress(data: Dict) -> str:
    """Format learning progress"""
    output = []
    progress_list = data.get('progress', [])

    output.append("\n📊 === YOUR LEARNING PROGRESS ===\n")

    if not progress_list:
        output.append("No progress yet. Start learning with: list_learning_topics()")
        return "\n".join(output)

    completed = [p for p in progress_list if p.get('completed')]
    in_progress = [p for p in progress_list if not p.get('completed')]

    output.append(f"✅ Completed: {len(completed)}")
    output.append(f"📖 In Progress: {len(in_progress)}\n")

    if completed:
        output.append("COMPLETED TECHNIQUES:")
        for p in completed:
            output.append(f"  ✅ {p['technique_id']} - Quiz Score: {p.get('quiz_score', 'N/A')}%")

    if in_progress:
        output.append("\nIN PROGRESS:")
        for p in in_progress:
            completed_modules = p.get('completed_modules', [])
            current = p.get('current_module', 1)
            output.append(f"  📖 {p['technique_id']} - Module {current} (completed: {completed_modules.count(True)} modules)")

    return "\n".join(output)


def _format_recommendation(data: Dict) -> str:
    """Format lesson recommendation"""
    output = []
    recommendation = data.get('recommendation')
    completed_count = data.get('completed_count', 0)

    output.append("\n💡 === RECOMMENDED NEXT LESSON ===\n")
    output.append(f"You've completed {completed_count} techniques\n")

    if not recommendation:
        output.append("🎉 Great work! You've completed all available prerequisites.")
        output.append("Consider reviewing advanced topics or exploring specific areas.")
    else:
        output.append(f"📚 Recommended: {recommendation['title']}")
        output.append(f"   Difficulty: {recommendation['difficulty'].upper()}")
        output.append(f"   Time: {recommendation['estimated_minutes']} minutes")
        output.append(f"\n   {recommendation['description']}")
        output.append(f"\nTo start: start_lesson('{recommendation['id']}')")

    return "\n".join(output)


def _format_module_complete(data: Dict) -> str:
    """Format module completion"""
    output = []

    output.append(f"\n✅ Module {data.get('module_number')} completed!")

    achievements = data.get('new_achievements', [])
    if achievements:
        output.append("\n🏆 NEW ACHIEVEMENTS:")
        for ach in achievements:
            output.append(f"  • {ach}")

    progress = data.get('progress', {})
    if progress:
        completed = progress.get('completed_modules', [])
        output.append(f"\nProgress: {completed.count(True)} modules completed")

    return "\n".join(output)


def _format_lesson_search(data: Dict) -> str:
    """Format lesson search results"""
    output = []
    results = data.get('results', [])
    query = data.get('query', '')

    output.append(f"\n🔍 Search results for: '{query}'\n")

    if not results:
        output.append("No matching lessons found.")
    else:
        output.append(f"Found {len(results)} matching techniques:\n")
        for r in results:
            output.append(f"• {r['title']} ({r['difficulty']})")
            output.append(f"  ID: {r['id']}")
            output.append(f"  {r['description']}\n")

    return "\n".join(output)

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

    print(f"\n[*] 20 Agentic Tools Available:")
    print(f"    Intelligence: search_intelligence, analyze_technique, fetch_latest")
    print(f"    Code: generate_code, optimize_opsec, validate_code")
    print(f"    Selection: select_techniques, compare_techniques")
    print(f"    Build: compile_code, record_feedback")
    print(f"    Education: list_learning_topics, start_lesson, get_lesson_module,")
    print(f"               complete_module, check_understanding, submit_quiz,")
    print(f"               get_learning_progress, get_recommended_lesson, search_lessons")
    print(f"    Utils: rag_stats")
    print(f"\n[*] MCP server starting in STDIO mode for IDE integration...")
    print(f"[*] Tools will be exposed to Cursor/VSCode via Model Context Protocol")
    print("="*70 + "\n")

    # Run MCP server in stdio mode (required for Cursor/VSCode)
    # This allows the IDE to communicate with the MCP server via stdin/stdout
    import asyncio
    asyncio.run(mcp.run_stdio_async())
