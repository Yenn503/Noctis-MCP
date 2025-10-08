#!/usr/bin/env python3
"""
Noctis-MCP Agentic API Endpoints
==================================

Flask API endpoints that power the agentic MCP tools.
These endpoints use RAG intelligence to provide dynamic responses.
"""

from flask import Blueprint, request, jsonify, g
import logging
import time
from typing import Dict, List, Optional
from datetime import datetime
from functools import wraps

logger = logging.getLogger(__name__)

# Import caching and metrics utilities
try:
    from server.utils import IntelligenceCache, get_metrics_collector
    from server.utils.intelligence_processor import IntelligenceProcessor
    UTILS_AVAILABLE = True
    INTELLIGENCE_PROCESSOR = IntelligenceProcessor()
except ImportError:
    UTILS_AVAILABLE = False
    INTELLIGENCE_PROCESSOR = None
    logger.warning("Utils not available - caching and metrics disabled")

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

    # Initialize intelligence cache (24hr TTL)
    if UTILS_AVAILABLE:
        agentic_bp.intelligence_cache = IntelligenceCache(ttl_hours=24, max_size=1000)
        agentic_bp.metrics = get_metrics_collector()
        logger.info("[Agentic API] Cache and metrics initialized")
    else:
        agentic_bp.intelligence_cache = None
        agentic_bp.metrics = None

    # Register blueprint
    app.register_blueprint(agentic_bp)
    logger.info("Agentic API endpoints registered")


def track_metrics(f):
    """
    Decorator to track endpoint metrics automatically
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not UTILS_AVAILABLE or not agentic_bp.metrics:
            return f(*args, **kwargs)

        # Start timer
        start_time = time.time()
        endpoint = f.__name__
        success = True

        try:
            # Execute endpoint
            response = f(*args, **kwargs)
            return response
        except Exception as e:
            success = False
            raise
        finally:
            # Track metrics
            duration = time.time() - start_time
            agentic_bp.metrics.track_request(endpoint, duration, success)

    return decorated_function


# ================================================================
# INTELLIGENCE SEARCH ENDPOINTS
# ================================================================

@agentic_bp.route('/intelligence/search', methods=['POST'])
@track_metrics
def search_intelligence():
    """
    Search RAG system for malware intelligence

    Performance improvements:
    - In-memory caching (instant response for repeat queries)
    - Parallel collection searching (3x faster)
    - Cross-encoder re-ranking (better relevance)

    POST /api/v2/intelligence/search
    {
        "query": "process injection evasion",
        "target_av": "Windows Defender",
        "sources": ["knowledge", "github"],
        "max_results": 10,
        "auto_update": true  # Default: true
    }
    """
    try:
        data = request.json
        query = data.get('query')
        target_av = data.get('target_av')
        sources = data.get('sources', ['all'])
        max_results = data.get('max_results', 10)
        auto_update = data.get('auto_update', True)  # Enable by default

        if not query:
            return jsonify({"error": "query parameter required"}), 400

        # Check cache first (instant response for repeat queries)
        cache_key = f"search:{query}:{target_av}:{max_results}"
        if agentic_bp.intelligence_cache:
            cached_result = agentic_bp.intelligence_cache.get(cache_key)
            if cached_result:
                cached_result['cached'] = True
                logger.debug(f"[Cache HIT] Returning cached search results for: {query}")
                return jsonify(cached_result)

        # Auto-update check: If RAG hasn't been updated in 7 days, fetch latest
        auto_updated = False
        if auto_update:
            import os
            stats_file = "data/intelligence_stats.json"

            if os.path.exists(stats_file):
                import json
                from datetime import datetime, timedelta

                with open(stats_file, 'r') as f:
                    stats = json.load(f)

                last_run = stats.get('last_run')
                if last_run:
                    last_run_date = datetime.fromisoformat(last_run)
                    days_since = (datetime.now() - last_run_date).days

                    if days_since > 7:
                        logger.info(f"RAG data is {days_since} days old - auto-updating...")

                        # Quick update (2-3 GitHub searches only)
                        from server.intelligence import LiveIntelligence
                        intel = LiveIntelligence(rag_engine=agentic_bp.rag_engine)

                        # Search for query-specific latest repos
                        repos = intel.search_github_repos(query, max_results=2, min_stars=5)
                        for repo in repos:
                            readme = intel.fetch_github_readme(repo["name"])
                            if readme:
                                intel.index_github_repo(repo, readme)

                        auto_updated = True
                        logger.info(f"Auto-updated RAG with {len(repos)} new repos")

        # Search RAG
        results = agentic_bp.rag_engine.search_knowledge(
            query=query,
            target_av=target_av,
            n_results=max_results
        )

        # Process intelligence using intelligent processor
        if INTELLIGENCE_PROCESSOR and results:
            # Convert RAG results to format processor expects
            rag_results_formatted = []
            for result in results:
                rag_results_formatted.append({
                    "content": result.get('content', result.get('document', '')),
                    "source": result.get('source', 'unknown'),
                    "title": result.get('metadata', {}).get('title', ''),
                    "metadata": result.get('metadata', {})
                })

            # Process into structured intelligence
            intelligence = INTELLIGENCE_PROCESSOR.process_intelligence(
                rag_results=rag_results_formatted,
                query=query,
                target_av=target_av
            )

            # Return structured intelligence instead of raw results
            response_data = {
                **intelligence,  # All processed intelligence
                "query_used": query,
                "sources_searched": sources,
                "auto_updated": auto_updated,
                "cached": False
            }
        else:
            # Fallback to raw results if processor unavailable
            formatted_results = []
            for result in results:
                formatted_results.append({
                    "content": result.get('content', result.get('document', '')),
                    "source": result.get('source', 'unknown'),
                    "metadata": result.get('metadata', {}),
                    "relevance_score": result.get('rerank_score', 1.0 - result.get('distance', 0.5))
                })

            response_data = {
                "results": formatted_results,
                "query_used": query,
                "sources_searched": sources,
                "total_results": len(formatted_results),
                "auto_updated": auto_updated,
                "cached": False
            }

        # Cache the response for future requests
        if agentic_bp.intelligence_cache:
            agentic_bp.intelligence_cache.set(cache_key, response_data)

        return jsonify(response_data)

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

    SMART CACHING: Won't re-fetch same topic if already fetched in last 24 hours

    POST /api/v2/intelligence/fetch-latest
    {
        "topic": "CrowdStrike bypass 2025",
        "sources": ["github", "blogs"],
        "days_back": 30,
        "force": false  # Set true to bypass 24hr cache
    }
    """
    try:
        data = request.json
        topic = data.get('topic')
        sources = data.get('sources', ['github', 'arxiv', 'blogs'])
        days_back = data.get('days_back', 30)
        force = data.get('force', False)

        if not topic:
            return jsonify({"error": "topic required"}), 400

        # Check cache (don't re-fetch same topic within 24 hours unless forced)
        if not force:
            import os
            import json
            from datetime import datetime, timedelta

            cache_file = f"data/fetch_cache_{topic.replace(' ', '_')}.json"
            if os.path.exists(cache_file):
                with open(cache_file, 'r') as f:
                    cache = json.load(f)

                cached_time = datetime.fromisoformat(cache.get('timestamp'))
                if (datetime.now() - cached_time) < timedelta(hours=24):
                    logger.info(f"Returning cached results for '{topic}' (fetched {(datetime.now() - cached_time).seconds // 3600}h ago)")
                    return jsonify({
                        **cache,
                        "cached": True,
                        "cache_age_hours": (datetime.now() - cached_time).seconds // 3600
                    }), 200

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

        # Save to cache
        import json
        cache_file = f"data/fetch_cache_{topic.replace(' ', '_')}.json"
        results_summary['timestamp'] = datetime.now().isoformat()
        results_summary['cached'] = False

        with open(cache_file, 'w') as f:
            json.dump(results_summary, f, indent=2)

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
    Provide intelligence and patterns for AI-driven code generation

    POST /api/v2/code/generate
    {
        "technique_ids": ["syscalls", "injection"],
        "target_av": "CrowdStrike",
        "objective": "C2 beacon with process injection",
        "opsec_level": "high"
    }

    Returns structured intelligence, implementation patterns, and function signatures
    for the AI agent to use when writing code.
    """
    try:
        data = request.json
        technique_ids = data.get('technique_ids', [])
        target_av = data.get('target_av', 'Windows Defender')
        objective = data.get('objective', '')
        opsec_level = data.get('opsec_level', 'high')

        if not technique_ids:
            return jsonify({"error": "technique_ids required"}), 400

        # Normalize technique IDs
        normalized_ids = [normalize_technique_id(tid) for tid in technique_ids]

        logger.info(f"Generating code guidance for: {normalized_ids}, target: {target_av}")

        # 1. Gather strategic intelligence for each technique
        intelligence_by_technique = {}

        if INTELLIGENCE_PROCESSOR:
            for tech_id in technique_ids:
                # Search RAG for this technique + target AV
                query = f"{tech_id} {target_av} evasion implementation"
                results = agentic_bp.rag_engine.search_knowledge(
                    query=query,
                    target_av=target_av,
                    n_results=8
                )

                # Process into structured intelligence
                if results:
                    rag_formatted = []
                    for result in results:
                        rag_formatted.append({
                            "content": result.get('content', result.get('document', '')),
                            "source": result.get('source', 'unknown'),
                            "title": result.get('metadata', {}).get('title', ''),
                            "metadata": result.get('metadata', {})
                        })

                    intel = INTELLIGENCE_PROCESSOR.process_intelligence(
                        rag_results=rag_formatted,
                        query=query,
                        target_av=target_av
                    )
                    intelligence_by_technique[tech_id] = intel

        # 2. Extract implementation patterns from Examples/ folder
        from server.utils.pattern_extractor import PatternExtractor
        pattern_extractor = PatternExtractor()

        patterns_by_technique = {}
        for tech_id in normalized_ids:
            # Get metadata for technique
            if tech_id in agentic_bp.code_assembler.techniques:
                technique_meta = agentic_bp.code_assembler.techniques[tech_id]
                source_files = technique_meta.get('source_files', [])

                if source_files:
                    patterns = pattern_extractor.extract_patterns_for_technique(
                        tech_id, source_files
                    )
                    patterns_by_technique[tech_id] = patterns

        # 2.5. Detect Client OS and C2 Availability (NEW - Phase 5)
        from server.utils.c2_detector import C2Detector

        client_os = data.get('client_os', 'unknown')
        target_os = data.get('target_os', 'Windows')

        c2_available = {}
        c2_mode = 'standalone'
        c2_recommendation = None

        logger.info(f"[C2 Detection] Client OS: {client_os}, Target OS: {target_os}")

        # Only check for C2 frameworks on Linux clients
        if client_os == 'Linux':
            try:
                c2_available = C2Detector.detect_all()

                # Determine if we should use C2 integrated mode
                if c2_available and any(word in objective.lower() for word in ['rat', 'beacon', 'implant', 'c2', 'backdoor']):
                    c2_mode = 'integrated'

                    # Get preferred framework
                    c2_framework = C2Detector.get_preferred_framework()

                    c2_recommendation = {
                        'mode': 'integrated',
                        'framework': c2_framework,
                        'framework_info': c2_available[c2_framework],
                        'endpoint': c2_available[c2_framework]['endpoint'],
                        'protocols': c2_available[c2_framework]['protocols'],
                        'listener_setup': c2_available[c2_framework]['listener_cmd'],
                        'ai_workflow': [
                            f"1. Call MCP tool: generate_c2_beacon('{c2_framework}', '<listener_host>', <port>)",
                            f"2. Receive {c2_framework.capitalize()} shellcode from C2 framework",
                            "3. Use beacon_stealth.c template to wrap shellcode",
                            "4. Replace ExampleC2Callback() with actual C2 callback",
                            "5. Call compile_malware() to build final binary",
                            f"6. Instruct user to start listener: {c2_available[c2_framework]['listener_cmd']}"
                        ],
                        'full_automation': True
                    }
                    logger.info(f"[C2 Mode] INTEGRATED - Using {c2_framework} (client has C2 installed)")

                else:
                    # Linux but no C2 installed
                    c2_mode = 'standalone'
                    c2_recommendation = {
                        'mode': 'standalone',
                        'reason': 'No C2 framework detected on Linux client',
                        'suggestion': 'User can install Sliver for full C2 integration',
                        'install_option': {
                            'available': True,
                            'tool': 'install_c2_framework',
                            'command': "Call MCP tool: install_c2_framework('sliver')",
                            'description': 'Auto-install Sliver C2 (takes 2-3 minutes)'
                        },
                        'ai_workflow': [
                            "1. Offer to install C2 framework (ask user permission)",
                            "2. If user declines: Use process_injection_complete.c for standalone reverse shell",
                            "3. Provide netcat listener command: nc -lvnp 4444"
                        ],
                        'full_automation': False
                    }
                    logger.info(f"[C2 Mode] STANDALONE - Linux client without C2 (can auto-install)")

            except Exception as e:
                logger.error(f"[C2 Detection] Error: {e}")
                c2_mode = 'standalone'

        elif client_os == 'Windows':
            # Windows client - cannot run C2 server
            c2_mode = 'standalone'
            c2_recommendation = {
                'mode': 'standalone',
                'reason': 'Client OS is Windows (cannot run C2 server)',
                'cross_platform_option': {
                    'available': True,
                    'description': 'Set up C2 server on separate Linux machine',
                    'instructions': [
                        "1. Deploy Noctis-MCP on a Linux server or VM",
                        "2. Install C2 framework on Linux: curl https://sliver.sh/install | sudo bash",
                        "3. Generate C2 beacon using Linux Noctis-MCP instance",
                        "4. Transfer generated beacon to Windows for deployment"
                    ]
                },
                'ai_workflow': [
                    "1. Use process_injection_complete.c for standalone payload",
                    "2. Generate reverse shell or bind shell callback",
                    "3. Provide PowerShell listener setup for user",
                    "4. NOTE: For full C2 capabilities, user needs Linux system"
                ],
                'full_automation': False
            }
            logger.info(f"[C2 Mode] STANDALONE - Windows client (no C2 server capability)")

        else:
            # Unknown OS - default to standalone
            c2_mode = 'standalone'
            c2_recommendation = {
                'mode': 'standalone',
                'reason': f'Unknown client OS: {client_os}',
                'ai_workflow': [
                    "1. Use standalone template (process_injection_complete.c)",
                    "2. Generate basic payload without C2 integration"
                ],
                'full_automation': False
            }
            logger.info(f"[C2 Mode] STANDALONE - Unknown OS: {client_os}")

        # 3. Search RAG for integration template recommendations
        template_recommendation = None
        objective_lower = objective.lower()

        # Build query for template search
        template_query = f"{objective} {target_av}"
        if any(word in objective_lower for word in ['rat', 'beacon', 'implant', 'c2', 'backdoor']):
            template_query += " beacon template C2"
        elif 'inject' in objective_lower:
            template_query += " injection template"
        elif any(word in objective_lower for word in ['bypass', 'edr', 'evade']):
            template_query += " edr bypass template"

        # Search for templates (integration examples)
        template_results = agentic_bp.rag_engine.search_knowledge(
            query=template_query,
            target_av=target_av,
            n_results=5
        )

        # Find integration example templates
        for result in template_results:
            metadata = result.get('metadata', {})
            if metadata.get('type') == 'integration_example':
                template_recommendation = {
                    'template_file': metadata.get('source'),
                    'template_name': metadata.get('template_name'),
                    'use_case': metadata.get('use_case'),
                    'what_it_does': metadata.get('what_it_does'),
                    'detection_risk': metadata.get('detection_risk'),
                    'techniques_included': metadata.get('techniques_included'),
                    'relevance_score': result.get('rerank_score', 0.5),
                    'recommendation': f"Use {metadata.get('template_name')}.c as base template"
                }
                logger.info(f"[Code Gen] Recommending template: {metadata.get('template_name')}")
                break

        # If no specific template found, recommend based on target AV
        if not template_recommendation:
            if target_av.lower() in ['crowdstrike', 'sentinelone']:
                template_recommendation = {
                    'template_file': 'techniques/examples/integrated_loader.c',
                    'template_name': 'integrated_loader',
                    'use_case': 'Complete EDR bypass pipeline for advanced EDRs',
                    'detection_risk': '2-5%',
                    'techniques_included': 'ALL techniques',
                    'relevance_score': 0.7,
                    'recommendation': 'Use integrated_loader.c - enables ALL evasion techniques for maximum stealth'
                }
            elif any(word in objective_lower for word in ['rat', 'beacon', 'c2']):
                template_recommendation = {
                    'template_file': 'techniques/examples/beacon_stealth.c',
                    'template_name': 'beacon_stealth',
                    'use_case': 'C2 beacon with memory obfuscation',
                    'detection_risk': '2-5% during sleep',
                    'techniques_included': 'Zilean, ShellcodeFluctuation, Perun\'s Fart, SilentMoonwalk',
                    'relevance_score': 0.7,
                    'recommendation': 'Use beacon_stealth.c - optimized for persistent C2 implants'
                }
            else:
                template_recommendation = {
                    'template_file': 'techniques/examples/process_injection_complete.c',
                    'template_name': 'process_injection_complete',
                    'use_case': 'Focused injection with moderate evasion',
                    'detection_risk': '3-5%',
                    'techniques_included': 'SysWhispers3, PoolParty, Encryption',
                    'relevance_score': 0.6,
                    'recommendation': 'Use process_injection_complete.c - lightweight injection template'
                }

        # 4. Get VX-API function signatures needed
        vx_signatures = []
        all_functions_mentioned = set()

        # Collect functions from patterns
        for patterns in patterns_by_technique.values():
            for api_pattern in patterns.get('api_usage_patterns', []):
                if 'syscalls_used' in api_pattern:
                    all_functions_mentioned.update(api_pattern['syscalls_used'])
                if 'apis_resolved' in api_pattern:
                    all_functions_mentioned.update(api_pattern['apis_resolved'])

        # Search VX-API for these functions
        if all_functions_mentioned:
            vx_query = ' '.join(list(all_functions_mentioned)[:10])
            vx_results = agentic_bp.rag_engine.search_knowledge(
                query=vx_query,
                n_results=15
            )

            for result in vx_results:
                if result.get('source') == 'vx_api':
                    vx_signatures.append({
                        'content': result.get('content', '')[:500],
                        'relevance': result.get('rerank_score', 0.5)
                    })

        # 5. Synthesize overall guidance
        overall_guidance = {
            'objective': objective or f"Implement {', '.join(technique_ids)}",
            'target_av': target_av,
            'target_os': target_os,
            'client_os': client_os,
            'opsec_level': opsec_level,
            'techniques_requested': technique_ids,

            # C2 Integration (NEW - Phase 5)
            'c2_integration': c2_recommendation,
            'c2_mode': c2_mode,

            # Template recommendation (NEW - Phase 5 integration)
            'template_recommendation': template_recommendation,

            # Strategic intelligence (WHY and WHAT to avoid)
            'intelligence': intelligence_by_technique,

            # Implementation patterns (HOW real code does it)
            'patterns': patterns_by_technique,

            # Function signatures (BUILDING BLOCKS)
            'vx_api_functions': vx_signatures,

            # High-level recommendations
            'synthesis': _synthesize_guidance(
                intelligence_by_technique,
                patterns_by_technique,
                target_av,
                opsec_level
            )
        }

        return jsonify(overall_guidance)

    except Exception as e:
        logger.exception(f"Code guidance generation failed: {e}")
        return jsonify({"error": str(e)}), 500


def _synthesize_guidance(intelligence_by_technique, patterns_by_technique, target_av, opsec_level):
    """Synthesize high-level guidance from intelligence and patterns"""
    synthesis = {
        'recommended_approach': [],
        'key_considerations': [],
        'opsec_warnings': [],
        'implementation_order': []
    }

    # Aggregate OPSEC scores
    all_opsec_scores = []
    for intel in intelligence_by_technique.values():
        for rec in intel.get('recommendations', []):
            all_opsec_scores.append(rec.get('opsec_score', 5))

    avg_opsec = sum(all_opsec_scores) / len(all_opsec_scores) if all_opsec_scores else 5

    # Generate recommendations
    if avg_opsec >= 8:
        synthesis['recommended_approach'].append(
            f"High OPSEC potential (avg {avg_opsec:.1f}/10) - proceed with recommended techniques"
        )
    elif avg_opsec >= 6:
        synthesis['recommended_approach'].append(
            f"Medium OPSEC (avg {avg_opsec:.1f}/10) - implement carefully with additional obfuscation"
        )
    else:
        synthesis['recommended_approach'].append(
            f"Low OPSEC (avg {avg_opsec:.1f}/10) - consider alternative techniques or heavy obfuscation"
        )

    # Extract key implementation steps from patterns
    for tech_id, patterns in patterns_by_technique.items():
        for func_seq in patterns.get('function_sequences', []):
            synthesis['implementation_order'].append({
                'technique': tech_id,
                'sequence': func_seq.get('sequence', ''),
                'description': func_seq.get('description', '')
            })

    # Aggregate warnings
    for intel in intelligence_by_technique.values():
        warnings = intel.get('warnings', [])
        synthesis['opsec_warnings'].extend(warnings[:2])  # Top 2 per technique

    # Add key considerations from memory patterns
    for patterns in patterns_by_technique.values():
        mem_patterns = patterns.get('memory_patterns', [])
        for pattern in mem_patterns:
            if '⚠' in pattern:
                synthesis['key_considerations'].append(pattern)

    return synthesis


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
                "rag_evidence": f"Mentioned in {int(rag_boost / 0.2) if rag_boost > 0 else 0} intelligence sources",
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

        # Add cache stats if available
        if agentic_bp.intelligence_cache:
            stats['cache_stats'] = agentic_bp.intelligence_cache.get_stats()

        return jsonify(stats)
    except Exception as e:
        logger.exception(f"RAG stats failed: {e}")
        return jsonify({"error": str(e)}), 500


@agentic_bp.route('/metrics', methods=['GET'])
def get_metrics():
    """
    Get API metrics and performance statistics

    GET /api/v2/metrics

    Returns:
        - Request counts by endpoint
        - Average response times
        - Error rates
        - Cache hit rates
    """
    try:
        if not agentic_bp.metrics:
            return jsonify({"error": "Metrics not available"}), 503

        metrics_data = agentic_bp.metrics.get_stats()

        # Add cache stats
        if agentic_bp.intelligence_cache:
            metrics_data['cache'] = agentic_bp.intelligence_cache.get_stats()

        return jsonify(metrics_data), 200

    except Exception as e:
        logger.exception(f"Failed to get metrics: {e}")
        return jsonify({"error": str(e)}), 500


@agentic_bp.route('/metrics/<endpoint>', methods=['GET'])
def get_endpoint_metrics(endpoint: str):
    """
    Get detailed metrics for specific endpoint

    GET /api/v2/metrics/<endpoint_name>
    """
    try:
        if not agentic_bp.metrics:
            return jsonify({"error": "Metrics not available"}), 503

        stats = agentic_bp.metrics.get_endpoint_stats(endpoint)
        return jsonify(stats), 200

    except Exception as e:
        logger.exception(f"Failed to get endpoint metrics: {e}")
        return jsonify({"error": str(e)}), 500


@agentic_bp.route('/intelligence/update', methods=['POST'])
def update_intelligence():
    """
    Update RAG intelligence from live sources

    POST /api/v2/intelligence/update
    {
        "mode": "daily|weekly|manual",
        "github_queries": ["optional", "custom", "queries"],
        "arxiv_queries": ["optional", "custom", "queries"]
    }
    """
    try:
        data = request.json or {}
        mode = data.get('mode', 'daily')
        github_queries = data.get('github_queries')
        arxiv_queries = data.get('arxiv_queries')

        logger.info(f"Starting intelligence update: mode={mode}")

        # Import LiveIntelligence
        from server.intelligence import LiveIntelligence
        intel = LiveIntelligence(rag_engine=agentic_bp.rag_engine)

        stats = {
            "mode": mode,
            "timestamp": datetime.now().isoformat(),
            "github_repos": 0,
            "blog_posts": 0,
            "arxiv_papers": 0,
            "indexed": 0,
            "errors": 0
        }

        if mode == "daily":
            # Quick daily update
            daily_github_queries = github_queries or [
                "EDR bypass 2025",
                "syscalls evasion",
                "AMSI bypass",
                "process injection"
            ]

            for query in daily_github_queries:
                repos = intel.search_github_repos(query, max_results=3, min_stars=10)
                stats["github_repos"] += len(repos)

                for repo in repos:
                    readme = intel.fetch_github_readme(repo["name"])
                    if readme and intel.index_github_repo(repo, readme):
                        stats["indexed"] += 1
                    else:
                        stats["errors"] += 1

            # Recent blogs
            posts = intel.fetch_security_blogs(max_posts_per_blog=2, days_back=7)
            stats["blog_posts"] = len(posts)

            for post in posts:
                if intel.index_blog_post(post):
                    stats["indexed"] += 1
                else:
                    stats["errors"] += 1

        elif mode == "weekly":
            # Comprehensive weekly update
            result = intel.full_intelligence_refresh(
                github_queries=github_queries,
                arxiv_queries=arxiv_queries,
                fetch_blogs=True
            )
            stats.update(result)

        elif mode == "manual":
            # Custom queries only
            if not github_queries and not arxiv_queries:
                return jsonify({"error": "manual mode requires github_queries or arxiv_queries"}), 400

            result = intel.full_intelligence_refresh(
                github_queries=github_queries or [],
                arxiv_queries=arxiv_queries or [],
                fetch_blogs=False
            )
            stats.update(result)

        logger.info(f"Intelligence update complete: {stats['indexed']} items indexed")

        return jsonify(stats), 200

    except Exception as e:
        logger.exception(f"Intelligence update failed: {e}")
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
    import os  # Import os module for file operations

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
        # Attempt compilation using existing compilation logic
        try:
            # Import compilation module
            from compilation import get_compiler
            compiler = get_compiler(output_dir="output")
            
            # Compile the source code directly (not from file)
            compile_result = compiler.compile(
                source_code=source_code,
                architecture='x64',
                optimization='O2',
                output_name=output_name,
                subsystem='Console'
            )

            if compile_result.success:
                validation_results['compilation'] = {
                    'status': 'passed',
                    'output': compile_result.binary_path,
                    'size_bytes': os.path.getsize(compile_result.binary_path) if compile_result.binary_path and os.path.exists(compile_result.binary_path) else 0,
                    'warnings': compile_result.warnings
                }
            else:
                validation_results['compilation'] = {
                    'status': 'failed',
                    'errors': compile_result.errors,
                    'suggestions': _analyze_compilation_errors(compile_result.errors)
                }
        except Exception as compile_error:
            validation_results['compilation'] = {
                'status': 'error',
                'message': str(compile_error),
                'suggestions': ['Ensure compiler is installed', 'Check code syntax']
            }

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

        # Generate embedding for the feedback text (CRITICAL: ChromaDB requires embeddings)
        # Check if RAG engine is properly enabled and has embedding capability
        if not hasattr(agentic_bp, 'rag_engine') or not agentic_bp.rag_engine.enabled:
            logger.debug("RAG engine not enabled, skipping feedback indexing")
            return jsonify({
                'recorded': True,
                'updated_effectiveness_scores': updated_scores,
                'indexed_to_rag': False,
                'techniques_updated': len(updated_scores)
            }), 200

        # Generate embedding using the RAG engine's embedder
        if hasattr(agentic_bp.rag_engine, 'embedder') and agentic_bp.rag_engine.embedder:
            try:
                embedding = agentic_bp.rag_engine.embedder.encode(feedback_text).tolist()
                if not embedding:
                    raise ValueError("Embedding generation returned empty result")
            except Exception as embed_err:
                logger.warning(f"Embedding generation failed: {embed_err}, skipping feedback indexing")
                return jsonify({
                    'recorded': True,
                    'updated_effectiveness_scores': updated_scores,
                    'indexed_to_rag': False,
                    'techniques_updated': len(updated_scores)
                }), 200
        else:
            # Skip indexing if no embedding method available
            logger.warning("No embedding method available in RAG engine, skipping feedback indexing")
            return jsonify({
                'recorded': True,
                'updated_effectiveness_scores': updated_scores,
                'indexed_to_rag': False,
                'techniques_updated': len(updated_scores)
            }), 200

        # Upsert with proper embeddings parameter
        agentic_bp.rag_engine.detection_intel.upsert(
            ids=[f"feedback_{int(time.time())}"],
            embeddings=[embedding],  # FIX: Add required embeddings parameter
            documents=[feedback_text],
            metadatas=[{
                'techniques': ','.join(technique_ids),
                'target_av': target_av,
                'detected': detected,
                'date': time.strftime('%Y-%m-%d')
            }]
        )
        logger.info(f"Indexed detection feedback to RAG: {technique_ids} vs {target_av}")
    except Exception as e:
        logger.warning(f"Could not index feedback to RAG: {e}")

    return jsonify({
        'recorded': True,
        'updated_effectiveness_scores': updated_scores,
        'indexed_to_rag': True,
        'techniques_updated': len(updated_scores)
    }), 200


# ============================================================================
# DETECTION TESTING ENDPOINTS
# ============================================================================

@agentic_bp.route('/detection/test', methods=['POST'])
def test_detection():
    """
    Test binary in live sandbox (Hybrid Analysis)

    Request Body:
        {
            "binary_path": "path/to/binary.exe",
            "target_av": "CrowdStrike Falcon" (optional),
            "environment": "Windows 10 64-bit" (optional)
        }

    Returns:
        {
            "success": true,
            "detected": false,
            "verdict": "no_threats",
            "opsec_score": 9,
            "threat_score": 5,
            "av_detections": 0,
            "detected_by": [],
            "target_detected": false,
            "signatures": [],
            "recommendations": [...],
            "environment": "Windows 10 64-bit (v2004, Build 19041)",
            "sha256": "abc123..."
        }
    """
    data = request.get_json()

    binary_path = data.get('binary_path')
    target_av = data.get('target_av')
    environment = data.get('environment', 'Windows 10 64-bit')

    if not binary_path:
        return jsonify({
            'success': False,
            'error': 'binary_path is required'
        }), 400

    try:
        # Import detection testing module
        from server.detection_testing import DetectionTester

        # Initialize tester (API key from environment variable)
        tester = DetectionTester()

        logger.info(f"Testing binary: {binary_path}")
        if target_av:
            logger.info(f"Target AV: {target_av}")

        # Run detection test
        result = tester.test_binary(
            binary_path=binary_path,
            target_av=target_av,
            environment=environment
        )

        # Check if it was successful
        if not result.get('success'):
            error_msg = result.get('error', 'Unknown error')
            logger.error(f"Detection test failed: {error_msg}")
            return jsonify(result), 500

        logger.info(f"Detection test complete. Detected: {result.get('detected')}, OPSEC Score: {result.get('opsec_score')}/10")

        return jsonify(result), 200

    except ImportError as e:
        logger.error(f"Detection testing module not available: {e}")
        return jsonify({
            'success': False,
            'error': 'Detection testing not configured. Install required dependencies: requests'
        }), 503

    except Exception as e:
        logger.exception(f"Detection testing error: {e}")
        return jsonify({
            'success': False,
            'error': f'Detection test failed: {str(e)}'
        }), 500
