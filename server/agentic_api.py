#!/usr/bin/env python3
"""
Noctis-MCP Agentic API Endpoints
==================================

Flask API endpoints that power the agentic MCP tools.
These endpoints use RAG intelligence to provide dynamic responses.
"""

from flask import Blueprint, request, jsonify
import logging
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

# Create blueprint
agentic_bp = Blueprint('agentic', __name__, url_prefix='/api/v2')

# Technique ID mapping (friendly names → NOCTIS IDs)
TECHNIQUE_ID_MAP = {
    'syscalls': 'NOCTIS-T004',
    'injection': 'NOCTIS-T008',
    'encryption': 'NOCTIS-T002',
    'unhooking': 'NOCTIS-T005',
    'api_hashing': 'NOCTIS-T003',
    'stack_spoof': 'NOCTIS-T006',
    'veh': 'NOCTIS-T007',
    'steganography': 'NOCTIS-T001',
    'gpu_evasion': 'NOCTIS-T009',
    'persistence': 'NOCTIS-T010'
}

def normalize_technique_id(tech_id: str) -> str:
    """Normalize technique ID (handles friendly names and NOCTIS IDs)"""
    if not tech_id:
        return tech_id

    # Already a NOCTIS ID
    if tech_id.upper().startswith('NOCTIS-T'):
        return tech_id.upper()

    # Map friendly name to NOCTIS ID
    return TECHNIQUE_ID_MAP.get(tech_id.lower(), tech_id)


def init_agentic_api(app, rag_engine, technique_manager, code_assembler, learning_engine):
    """
    Initialize agentic API with required dependencies

    Args:
        app: Flask app
        rag_engine: RAGEngine instance
        technique_manager: TechniqueManager instance
        code_assembler: CodeAssembler instance
        learning_engine: AgenticLearningEngine instance
    """
    # Store dependencies in blueprint
    agentic_bp.rag_engine = rag_engine
    agentic_bp.technique_manager = technique_manager
    agentic_bp.code_assembler = code_assembler
    agentic_bp.learning_engine = learning_engine

    # Register blueprint
    app.register_blueprint(agentic_bp)
    logger.info("Agentic API endpoints registered")


# ================================================================
# INTELLIGENCE SEARCH ENDPOINTS
# ================================================================

@agentic_bp.route('/intelligence/search', methods=['POST'])
def search_intelligence():
    """
    Search RAG system for malware intelligence

    POST /api/v2/intelligence/search
    {
        "query": "process injection evasion",
        "target_av": "Windows Defender",
        "sources": ["knowledge", "github"],
        "max_results": 10
    }
    """
    try:
        data = request.json
        query = data.get('query')
        target_av = data.get('target_av')
        sources = data.get('sources', ['all'])
        max_results = data.get('max_results', 10)

        if not query:
            return jsonify({"error": "query parameter required"}), 400

        # Search RAG
        results = agentic_bp.rag_engine.search_knowledge(
            query=query,
            target_av=target_av,
            n_results=max_results
        )

        # Format results
        formatted_results = []
        for result in results:
            formatted_results.append({
                "content": result.get('content', result.get('document', '')),
                "source": result.get('source', 'unknown'),
                "metadata": result.get('metadata', {}),
                "relevance_score": 1.0 - result.get('distance', 0.5)  # Convert distance to similarity
            })

        return jsonify({
            "results": formatted_results,
            "query_used": query,
            "sources_searched": sources,
            "total_results": len(formatted_results)
        })

    except Exception as e:
        logger.exception(f"Intelligence search failed: {e}")
        return jsonify({"error": str(e)}), 500


@agentic_bp.route('/intelligence/analyze', methods=['POST'])
def analyze_technique():
    """
    Deep analysis of specific technique using all intelligence sources

    POST /api/v2/intelligence/analyze
    {
        "technique_id": "syscalls",
        "target_av": "CrowdStrike",
        "include_code_examples": true
    }
    """
    try:
        data = request.json
        technique_id = data.get('technique_id')
        target_av = data.get('target_av')
        include_code = data.get('include_code_examples', True)

        if not technique_id:
            return jsonify({"error": "technique_id required"}), 400

        # Normalize technique ID (handles friendly names like "syscalls" → "NOCTIS-T004")
        technique_id = normalize_technique_id(technique_id)

        # Get technique metadata
        technique = agentic_bp.technique_manager.get_by_id(technique_id)
        if not technique:
            return jsonify({"error": f"Technique {technique_id} not found"}), 404

        # Search RAG for this technique
        knowledge_results = agentic_bp.rag_engine.search_knowledge(
            query=f"{technique.get('name')} {technique_id}",
            target_av=target_av,
            n_results=10
        )

        # Separate by source type
        conceptual = []
        github = []
        research = []
        blogs = []

        for result in knowledge_results:
            source = result.get('source', 'unknown')
            if source == 'knowledge_base':
                conceptual.append(result)
            elif source == 'github':
                github.append(result)
            elif source == 'research':
                research.append(result)
            elif source == 'blog':
                blogs.append(result)

        # Get effectiveness score
        effectiveness = agentic_bp.learning_engine.get_effectiveness_score(
            technique_id,
            target_av or "Windows Defender"
        )

        # Build comprehensive analysis
        analysis = {
            "technique_id": technique_id,
            "name": technique.get('name'),
            "category": technique.get('category'),
            "description": technique.get('description'),
            "conceptual_knowledge": {
                "summary": conceptual[0].get('content', '')[:500] if conceptual else "No knowledge base entry",
                "full_chunks": len(conceptual),
                "key_concepts": _extract_key_concepts(conceptual)
            },
            "github_implementations": [
                {
                    "repo": r.get('metadata', {}).get('name', 'unknown'),
                    "url": r.get('metadata', {}).get('url', ''),
                    "snippet": r.get('content', '')[:300] if include_code else None
                }
                for r in github[:5]
            ],
            "research_papers": [
                {
                    "title": r.get('metadata', {}).get('title', 'Unknown'),
                    "summary": r.get('content', '')[:200],
                    "url": r.get('metadata', {}).get('url', '')
                }
                for r in research[:3]
            ],
            "blog_posts": [
                {
                    "title": r.get('metadata', {}).get('title', 'Unknown'),
                    "summary": r.get('content', '')[:200],
                    "url": r.get('metadata', {}).get('url', '')
                }
                for r in blogs[:3]
            ],
            "effectiveness_vs_av": {
                target_av or "Windows Defender": effectiveness
            },
            "recommended_combinations": _get_recommended_combinations(technique_id),
            "total_intelligence_sources": len(knowledge_results)
        }

        return jsonify(analysis)

    except Exception as e:
        logger.exception(f"Technique analysis failed: {e}")
        return jsonify({"error": str(e)}), 500


@agentic_bp.route('/intelligence/fetch-latest', methods=['POST'])
def fetch_latest_intelligence():
    """
    Fetch latest intelligence and index into RAG

    POST /api/v2/intelligence/fetch-latest
    {
        "topic": "CrowdStrike bypass 2025",
        "sources": ["github", "blogs"],
        "days_back": 30
    }
    """
    try:
        data = request.json
        topic = data.get('topic')
        sources = data.get('sources', ['github', 'arxiv', 'blogs'])
        days_back = data.get('days_back', 30)

        if not topic:
            return jsonify({"error": "topic required"}), 400

        # Import live intelligence module
        from server.intelligence import LiveIntelligence
        intel = LiveIntelligence(rag_engine=agentic_bp.rag_engine)

        results_summary = {
            "topic": topic,
            "new_results": 0,
            "indexed": 0,
            "sources": {}
        }

        # Fetch from each source
        if 'github' in sources or 'all' in sources:
            repos = intel.search_github_repos(topic, max_results=10, min_stars=5)
            results_summary['sources']['github'] = len(repos)
            for repo in repos:
                readme = intel.fetch_github_readme(repo['name'])
                if readme and intel.index_github_repo(repo, readme):
                    results_summary['indexed'] += 1

        if 'arxiv' in sources or 'all' in sources:
            papers = intel.search_arxiv_papers(topic, max_results=5, days_back=days_back)
            results_summary['sources']['arxiv'] = len(papers)
            for paper in papers:
                if intel.index_research_paper(paper):
                    results_summary['indexed'] += 1

        if 'blogs' in sources or 'all' in sources:
            posts = intel.fetch_security_blogs(max_posts_per_blog=3, days_back=days_back)
            results_summary['sources']['blogs'] = len(posts)
            for post in posts:
                if intel.index_blog_post(post):
                    results_summary['indexed'] += 1

        results_summary['new_results'] = sum(results_summary['sources'].values())

        return jsonify(results_summary)

    except Exception as e:
        logger.exception(f"Fetch latest intelligence failed: {e}")
        return jsonify({"error": str(e)}), 500


# ================================================================
# CODE GENERATION ENDPOINTS
# ================================================================

@agentic_bp.route('/code/generate', methods=['POST'])
def generate_code():
    """
    Generate code using RAG-informed intelligence

    POST /api/v2/code/generate
    {
        "technique_ids": ["syscalls", "injection"],
        "target_av": "CrowdStrike",
        "use_rag_context": true,
        "opsec_level": "high"
    }
    """
    try:
        data = request.json
        technique_ids = data.get('technique_ids', [])
        target_av = data.get('target_av', 'Windows Defender')
        use_rag = data.get('use_rag_context', True)
        opsec_level = data.get('opsec_level', 'high')

        if not technique_ids:
            return jsonify({"error": "technique_ids required"}), 400

        # If using RAG, gather intelligence first
        rag_intelligence = {}
        if use_rag:
            for tech_id in technique_ids:
                results = agentic_bp.rag_engine.search_knowledge(
                    query=f"{tech_id} implementation",
                    target_av=target_av,
                    n_results=5
                )
                rag_intelligence[tech_id] = results

        # Generate code using code assembler
        generated = agentic_bp.code_assembler.assemble(
            technique_ids=technique_ids,
            options={
                'target_av': target_av,
                'opsec_level': opsec_level
            }
        )

        # Add RAG intelligence summary
        response = generated.to_dict()
        if use_rag:
            response['rag_intelligence_used'] = {
                "github_patterns": sum(1 for tech in rag_intelligence.values()
                                      for r in tech if r.get('source') == 'github'),
                "research_insights": sum(1 for tech in rag_intelligence.values()
                                        for r in tech if r.get('source') == 'research'),
                "blog_recommendations": sum(1 for tech in rag_intelligence.values()
                                           for r in tech if r.get('source') == 'blog')
            }

        return jsonify(response)

    except Exception as e:
        logger.exception(f"Code generation failed: {e}")
        return jsonify({"error": str(e)}), 500


# ================================================================
# TECHNIQUE SELECTION ENDPOINTS
# ================================================================

@agentic_bp.route('/techniques/select', methods=['POST'])
def select_techniques():
    """
    Intelligent technique selection using RAG + learning

    POST /api/v2/techniques/select
    {
        "goal": "evade CrowdStrike for process injection",
        "target_av": "CrowdStrike",
        "constraints": {"max_techniques": 3}
    }
    """
    try:
        data = request.json
        goal = data.get('goal')
        target_av = data.get('target_av', 'Windows Defender')
        constraints = data.get('constraints', {})

        if not goal:
            return jsonify({"error": "goal required"}), 400

        # Search RAG for relevant techniques based on goal
        rag_results = agentic_bp.rag_engine.search_knowledge(
            query=goal,
            target_av=target_av,
            n_results=10
        )

        # Get all techniques
        all_techniques = agentic_bp.technique_manager.get_all()

        # Score techniques based on RAG + effectiveness
        scored_techniques = []
        for tech in all_techniques:
            tech_id = tech.get('technique_id')

            # Base score from learning engine
            base_score = agentic_bp.learning_engine.get_effectiveness_score(tech_id, target_av)

            # Boost from RAG mentions
            rag_boost = 0.0
            for result in rag_results:
                content = result.get('content', '').lower()
                if tech_id.lower() in content or tech.get('name', '').lower() in content:
                    rag_boost += 0.2

            final_score = min(base_score + rag_boost, 10.0)

            scored_techniques.append({
                "technique_id": tech_id,
                "name": tech.get('name'),
                "effectiveness_score": final_score,
                "rag_evidence": f"Mentioned in {int(rag_boost / 0.2)} intelligence sources",
                "rationale": _generate_rationale(tech, target_av, rag_results)
            })

        # Sort by score
        scored_techniques.sort(key=lambda x: x['effectiveness_score'], reverse=True)

        # Apply constraints
        max_techniques = constraints.get('max_techniques', 5)
        recommended = scored_techniques[:max_techniques]

        return jsonify({
            "recommended_techniques": recommended,
            "rag_intelligence_summary": f"Analyzed {len(rag_results)} intelligence sources",
            "alternatives": scored_techniques[max_techniques:max_techniques+3],
            "total_techniques_analyzed": len(all_techniques)
        })

    except Exception as e:
        logger.exception(f"Technique selection failed: {e}")
        return jsonify({"error": str(e)}), 500


# ================================================================
# RAG STATS ENDPOINT
# ================================================================

@agentic_bp.route('/rag/stats', methods=['GET'])
def rag_stats():
    """Get RAG system statistics"""
    try:
        stats = agentic_bp.rag_engine.get_stats()
        return jsonify(stats)
    except Exception as e:
        logger.exception(f"RAG stats failed: {e}")
        return jsonify({"error": str(e)}), 500


# ================================================================
# HELPER FUNCTIONS
# ================================================================

def _extract_key_concepts(knowledge_chunks: List[Dict]) -> List[str]:
    """Extract key concepts from knowledge chunks"""
    # Simple extraction - look for headings in metadata
    concepts = []
    for chunk in knowledge_chunks[:5]:
        section = chunk.get('metadata', {}).get('section', '')
        if section and section not in concepts:
            concepts.append(section)
    return concepts


def _get_recommended_combinations(technique_id: str) -> List[str]:
    """Get recommended technique combinations"""
    # Hardcoded combinations for now - could be RAG-powered later
    combinations = {
        'syscalls': ['unhooking', 'encryption'],
        'injection': ['syscalls', 'encryption'],
        'encryption': ['api_hashing', 'steganography'],
        'unhooking': ['syscalls', 'stack_spoof']
    }
    return combinations.get(technique_id, [])


def _generate_rationale(technique: Dict, target_av: str, rag_results: List[Dict]) -> str:
    """Generate rationale for technique selection"""
    name = technique.get('name', 'Unknown')
    category = technique.get('category', '')

    # Check if mentioned in RAG
    mention_count = 0
    for result in rag_results:
        if technique.get('technique_id', '').lower() in result.get('content', '').lower():
            mention_count += 1

    if mention_count > 2:
        return f"{name} is highly recommended based on {mention_count} recent intelligence sources for {target_av}"
    elif mention_count > 0:
        return f"{name} shows promise with evidence from {mention_count} sources"
    else:
        return f"{name} is a {category} technique suitable for general use"


@agentic_bp.route('/code/validate', methods=['POST'])
def validate_code():
    """Validate generated code - compilation check, error analysis, quality metrics

    This endpoint helps AI models verify code quality BEFORE final delivery.
    Returns detailed error feedback so AI can fix and retry.
    """
    data = request.get_json()
    source_code = data.get('source_code')
    output_name = data.get('output_name', 'payload')
    validate_functionality = data.get('validate_functionality', False)

    if not source_code:
        return jsonify({'error': 'source_code is required'}), 400

    validation_results = {
        'compilation': {'status': 'pending'},
        'quality': {'status': 'pending'},
        'warnings': [],
        'suggestions': []
    }

    # Step 1: Compilation validation
    try:
        compile_endpoint = agentic_bp.technique_manager  # Has access to compilation
        # Save temp file
        import tempfile
        import os
        with tempfile.NamedTemporaryFile(mode='w', suffix='.c', delete=False, encoding='utf-8') as f:
            f.write(source_code)
            temp_path = f.name

        # Attempt compilation using existing compilation logic
        try:
            # Import compilation module
            from compilation.compiler import Compiler
            compiler = Compiler()
            compile_result = compiler.compile_file(temp_path, output_name)

            if compile_result.get('success'):
                validation_results['compilation'] = {
                    'status': 'passed',
                    'output': compile_result.get('output_path'),
                    'size_bytes': compile_result.get('size'),
                    'warnings': compile_result.get('warnings', [])
                }
            else:
                validation_results['compilation'] = {
                    'status': 'failed',
                    'errors': compile_result.get('errors', []),
                    'suggestions': _analyze_compilation_errors(compile_result.get('errors', []))
                }
        except Exception as compile_error:
            validation_results['compilation'] = {
                'status': 'error',
                'message': str(compile_error),
                'suggestions': ['Ensure compiler is installed', 'Check code syntax']
            }
        finally:
            # Cleanup temp file
            if os.path.exists(temp_path):
                os.remove(temp_path)

    except Exception as e:
        validation_results['compilation'] = {
            'status': 'error',
            'message': f"Validation system error: {str(e)}"
        }

    # Step 2: Code quality analysis
    quality_score = _analyze_code_quality(source_code)
    validation_results['quality'] = quality_score

    # Step 3: Overall verdict
    validation_results['overall_verdict'] = (
        'ready_for_use' if validation_results['compilation']['status'] == 'passed' and quality_score['score'] >= 7.0
        else 'needs_improvement'
    )

    return jsonify(validation_results), 200


def _analyze_compilation_errors(errors: List[str]) -> List[str]:
    """Analyze compilation errors and provide actionable suggestions"""
    suggestions = []

    for error in errors:
        error_lower = error.lower()
        if 'undeclared' in error_lower or 'not declared' in error_lower:
            suggestions.append("Add missing variable declarations or function prototypes")
        elif 'syntax error' in error_lower:
            suggestions.append("Check for missing semicolons, braces, or parentheses")
        elif 'undefined reference' in error_lower or 'unresolved external' in error_lower:
            suggestions.append("Link required libraries or define missing functions")
        elif 'incompatible type' in error_lower:
            suggestions.append("Fix type mismatches - check function signatures and casts")
        elif 'permission denied' in error_lower:
            suggestions.append("Check file permissions or run as administrator")

    if not suggestions:
        suggestions.append("Review compiler output carefully and fix syntax errors")

    return list(set(suggestions))  # Remove duplicates


def _analyze_code_quality(source_code: str) -> Dict:
    """Analyze code quality - OPSEC, structure, best practices"""
    score = 10.0
    issues = []
    strengths = []

    # Check for good OPSEC practices
    if '#include <windows.h>' in source_code.lower():
        strengths.append("Uses Windows API")

    if 'syscall' in source_code.lower() or 'ntdll' in source_code.lower():
        strengths.append("Uses direct syscalls (good OPSEC)")
        score += 1.0

    if 'virtualalloc' in source_code.lower() and 'virtualprotect' in source_code.lower():
        strengths.append("Proper memory management")

    # Check for bad OPSEC practices
    if 'system(' in source_code or 'exec(' in source_code:
        issues.append("Uses suspicious system() calls (poor OPSEC)")
        score -= 2.0

    if source_code.count('printf') > 5 or source_code.count('cout') > 5:
        issues.append("Excessive debug output (remove for production)")
        score -= 1.0

    if 'malware' in source_code.lower() or 'payload' in source_code.lower():
        issues.append("Contains suspicious string literals (obfuscate)")
        score -= 1.5

    # Basic structure checks
    if 'int main' not in source_code and 'WINAPI' not in source_code:
        issues.append("Missing entry point (main or WinMain)")
        score -= 2.0

    if source_code.count('{') != source_code.count('}'):
        issues.append("Mismatched braces - likely syntax error")
        score -= 3.0

    # Cap score
    score = max(0.0, min(10.0, score))

    return {
        'score': round(score, 1),
        'issues': issues,
        'strengths': strengths,
        'status': 'good' if score >= 7.0 else 'needs_improvement'
    }


# ================================================================
# TECHNIQUE COMPARISON ENDPOINT
# ================================================================

@agentic_bp.route('/techniques/compare', methods=['POST'])
def compare_techniques():
    """
    Compare multiple techniques side-by-side using RAG intelligence

    Request body:
        technique_ids: List of technique IDs to compare
        target_av: Target AV/EDR (e.g., "Windows Defender")
        criteria: Comparison criteria (e.g., "effectiveness,stealth,complexity")

    Returns:
        comparison: List of techniques with scores and analysis
    """
    data = request.get_json()
    technique_ids = data.get('technique_ids', [])
    target_av = data.get('target_av', 'Windows Defender')
    criteria = data.get('criteria', 'effectiveness,stealth')

    if not technique_ids or len(technique_ids) < 2:
        return jsonify({'error': 'At least 2 technique IDs required'}), 400

    # Get RAG intelligence for each technique
    comparison = []

    for tech_id in technique_ids:
        # Search RAG for this technique
        query = f"{tech_id} {target_av} effectiveness"
        rag_results = agentic_bp.rag_engine.search_knowledge(query, target_av, n_results=3)

        # Get effectiveness score from learning engine
        effectiveness = agentic_bp.learning_engine.get_effectiveness_score(tech_id, target_av)

        # Calculate scores
        stealth_score = effectiveness * 0.9  # Simplified for now
        complexity_score = 5.0  # Default medium complexity

        comparison.append({
            'technique_id': tech_id,
            'effectiveness_score': round(effectiveness, 2),
            'stealth_score': round(stealth_score, 2),
            'complexity_score': complexity_score,
            'overall_score': round((effectiveness + stealth_score) / 2, 2),
            'rag_insights': len(rag_results),
            'recommendation': _generate_recommendation(effectiveness, stealth_score, target_av)
        })

    # Sort by overall score
    comparison.sort(key=lambda x: x['overall_score'], reverse=True)

    return jsonify({
        'comparison': comparison,
        'target_av': target_av,
        'criteria': criteria,
        'recommendation': comparison[0]['technique_id'] if comparison else None
    }), 200


def _generate_recommendation(effectiveness: float, stealth: float, target_av: str) -> str:
    """Generate recommendation based on scores"""
    if effectiveness >= 8.0 and stealth >= 8.0:
        return f"Excellent choice for {target_av} - high effectiveness and stealth"
    elif effectiveness >= 7.0:
        return f"Good effectiveness against {target_av}, moderate stealth"
    elif stealth >= 7.0:
        return f"High stealth but lower effectiveness - good for patient operations"
    else:
        return f"Consider combining with other techniques for better results"


# ================================================================
# OPSEC OPTIMIZATION ENDPOINT
# ================================================================

@agentic_bp.route('/code/optimize-opsec', methods=['POST'])
def optimize_opsec():
    """
    Optimize code for OPSEC using RAG intelligence about detection patterns

    Request body:
        source_code: Code to optimize
        target_av: Target AV/EDR
        target_score: Desired OPSEC score (0-10)
        max_iterations: Maximum optimization attempts

    Returns:
        optimized_code: Improved code
        original_score: Initial OPSEC score
        final_score: Final OPSEC score
        improvements_made: List of improvements applied
    """
    data = request.get_json()
    source_code = data.get('source_code', '')
    target_av = data.get('target_av', 'Windows Defender')
    target_score = data.get('target_score', 8.0)
    max_iterations = data.get('max_iterations', 3)

    if not source_code:
        return jsonify({'error': 'source_code is required'}), 400

    # Get initial OPSEC score
    original_score = _analyze_code_quality(source_code)['score']

    # Search RAG for OPSEC improvement techniques
    query = f"{target_av} detection evasion OPSEC improvements"
    rag_results = agentic_bp.rag_engine.search_knowledge(query, target_av, n_results=5)

    # Apply improvements based on RAG intelligence
    optimized_code = source_code
    improvements_made = []

    # Check for common issues and apply fixes
    if 'system(' in source_code:
        optimized_code = optimized_code.replace('system(', '// OPSEC: Avoid system() - use direct syscalls\n// system(')
        improvements_made.append("Flagged suspicious system() calls")

    if source_code.count('printf') > 3:
        improvements_made.append("Recommended reducing debug output")

    if 'malware' in source_code.lower() or 'payload' in source_code.lower():
        improvements_made.append("Recommended obfuscating string literals")

    # Add OPSEC-improving headers if not present
    if '#include <windows.h>' in source_code and 'VirtualAlloc' not in source_code:
        improvements_made.append("Suggested using VirtualAlloc for dynamic memory")

    # Calculate final score
    final_score = _analyze_code_quality(optimized_code)['score']

    # Add RAG-based suggestions
    rag_suggestions = []
    for result in rag_results[:3]:
        content = result.get('content', '')
        if 'syscall' in content.lower():
            rag_suggestions.append("Consider using direct syscalls to bypass hooks")
        if 'encrypt' in content.lower():
            rag_suggestions.append("Add payload encryption for better evasion")

    return jsonify({
        'optimized_code': optimized_code,
        'original_score': round(original_score, 2),
        'final_score': round(final_score, 2),
        'improvements_made': improvements_made,
        'rag_suggestions': list(set(rag_suggestions)),
        'target_score': target_score,
        'target_reached': final_score >= target_score
    }), 200


# ================================================================
# LEARNING FEEDBACK ENDPOINT
# ================================================================

@agentic_bp.route('/learning/record-detection', methods=['POST'])
def record_detection():
    """
    Record detection feedback to improve RAG intelligence

    Request body:
        technique_ids: Techniques that were tested
        target_av: AV/EDR tested against
        detected: Was it detected? (True/False)
        detection_details: Optional details about detection

    Returns:
        recorded: Boolean indicating success
        updated_effectiveness_scores: New scores for techniques
    """
    data = request.get_json()
    technique_ids = data.get('technique_ids', [])
    target_av = data.get('target_av')
    detected = data.get('detected', False)
    details = data.get('detection_details', '')

    if not technique_ids or not target_av:
        return jsonify({'error': 'technique_ids and target_av are required'}), 400

    # Record feedback in learning engine
    updated_scores = {}

    for tech_id in technique_ids:
        try:
            # Record detection result
            agentic_bp.learning_engine.record_detection(
                technique_id=tech_id,
                target_av=target_av,
                detected=detected,
                metadata={'details': details}
            )

            # Get updated effectiveness score
            new_score = agentic_bp.learning_engine.get_effectiveness_score(tech_id, target_av)
            updated_scores[tech_id] = round(new_score, 2)

            logger.info(f"Recorded feedback: {tech_id} vs {target_av} - detected={detected}")

        except Exception as e:
            logger.error(f"Failed to record feedback for {tech_id}: {e}")

    # Index feedback to RAG for future intelligence
    feedback_text = f"Detection test: {', '.join(technique_ids)} against {target_av}. "
    feedback_text += f"Result: {'DETECTED' if detected else 'NOT DETECTED'}. {details}"

    try:
        # Add to detection intelligence collection
        import time
        agentic_bp.rag_engine.detection_intel.upsert(
            ids=[f"feedback_{int(time.time())}"],
            documents=[feedback_text],
            metadatas=[{
                'techniques': ','.join(technique_ids),
                'target_av': target_av,
                'detected': detected,
                'date': time.strftime('%Y-%m-%d')
            }]
        )
    except Exception as e:
        logger.warning(f"Could not index feedback to RAG: {e}")

    return jsonify({
        'recorded': True,
        'updated_effectiveness_scores': updated_scores,
        'indexed_to_rag': True,
        'techniques_updated': len(updated_scores)
    }), 200
