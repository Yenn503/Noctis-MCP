"""
C2 Framework Detector
=====================

Detects which C2 frameworks are installed on the system (Linux only).
Used to determine if integrated C2 beacons can be generated.

Author: Noctis-MCP Team
Phase: 5 - C2 Integration
"""

import os
import subprocess
import shutil
import logging
from typing import Dict, Optional, List
from pathlib import Path

logger = logging.getLogger(__name__)


class C2Detector:
    """Detect installed C2 frameworks and their capabilities"""

    @staticmethod
    def detect_all() -> Dict[str, dict]:
        """
        Detect all installed C2 frameworks

        Returns:
            Dict of framework_name → framework_details
            {
                'sliver': {
                    'installed': True,
                    'client_path': '/usr/local/bin/sliver-client',
                    'server_path': '/usr/local/bin/sliver-server',
                    'version': '1.5.42',
                    'endpoint': '/api/c2/sliver/generate',
                    'protocols': ['https', 'http', 'dns', 'mtls', 'tcp'],
                    'listener_cmd': 'sliver > https --lhost <IP> --lport 443'
                },
                ...
            }
        """
        frameworks = {}

        # Check Sliver
        sliver_info = C2Detector.detect_sliver()
        if sliver_info:
            frameworks['sliver'] = sliver_info

        # Check Mythic
        mythic_info = C2Detector.detect_mythic()
        if mythic_info:
            frameworks['mythic'] = mythic_info

        # Check Adaptix
        adaptix_info = C2Detector.detect_adaptix()
        if adaptix_info:
            frameworks['adaptix'] = adaptix_info

        logger.info(f"[C2 Detector] Found {len(frameworks)} frameworks: {list(frameworks.keys())}")
        return frameworks

    @staticmethod
    def detect_sliver() -> Optional[Dict]:
        """Detect Sliver C2 framework"""
        try:
            # Check for sliver-client binary
            client_path = shutil.which('sliver-client')
            if not client_path:
                # Try common install locations
                common_paths = [
                    '/usr/local/bin/sliver-client',
                    '/usr/bin/sliver-client',
                    str(Path.home() / '.sliver' / 'sliver-client')
                ]
                for path in common_paths:
                    if os.path.exists(path):
                        client_path = path
                        break

            if not client_path:
                return None

            # Get version
            try:
                result = subprocess.run(
                    [client_path, 'version'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                version = result.stdout.strip() if result.returncode == 0 else 'unknown'
            except Exception:
                version = 'unknown'

            # Check for server
            server_path = shutil.which('sliver-server')
            if not server_path:
                server_path = client_path.replace('client', 'server')
                if not os.path.exists(server_path):
                    server_path = None

            return {
                'installed': True,
                'client_path': client_path,
                'server_path': server_path,
                'version': version,
                'endpoint': '/api/c2/sliver/generate',
                'protocols': ['https', 'http', 'dns', 'mtls', 'tcp'],
                'listener_cmd': 'sliver > https --lhost <IP> --lport 443',
                'setup_cmd': 'sliver-server',
                'detection_method': 'binary_check'
            }

        except Exception as e:
            logger.debug(f"[C2 Detector] Sliver detection failed: {e}")
            return None

    @staticmethod
    def detect_mythic() -> Optional[Dict]:
        """Detect Mythic C2 framework"""
        try:
            # Check for Mythic installation directory
            mythic_paths = [
                '/opt/Mythic',
                str(Path.home() / 'Mythic'),
                '/usr/local/Mythic'
            ]

            mythic_dir = None
            for path in mythic_paths:
                if os.path.exists(path) and os.path.isdir(path):
                    # Verify it's actually Mythic by checking for mythic-cli
                    if os.path.exists(os.path.join(path, 'mythic-cli')):
                        mythic_dir = path
                        break

            if not mythic_dir:
                # Check for mythic-cli in PATH
                mythic_cli = shutil.which('mythic-cli')
                if mythic_cli:
                    mythic_dir = os.path.dirname(mythic_cli)

            if not mythic_dir:
                return None

            # Check if Mythic is running
            running = False
            try:
                import requests
                response = requests.get('https://127.0.0.1:7443', verify=False, timeout=2)
                running = True
            except:
                pass

            return {
                'installed': True,
                'path': mythic_dir,
                'cli_path': os.path.join(mythic_dir, 'mythic-cli'),
                'endpoint': '/api/c2/mythic/generate',
                'protocols': ['https', 'http', 'websocket', 'dns', 'smb'],
                'listener_cmd': 'Create listener in Mythic UI: https://127.0.0.1:7443',
                'setup_cmd': f'cd {mythic_dir} && sudo ./mythic-cli start',
                'running': running,
                'ui_url': 'https://127.0.0.1:7443',
                'detection_method': 'directory_check'
            }

        except Exception as e:
            logger.debug(f"[C2 Detector] Mythic detection failed: {e}")
            return None

    @staticmethod
    def detect_adaptix() -> Optional[Dict]:
        """Detect Adaptix C2 framework"""
        try:
            # Check for Adaptix server binary
            adaptix_paths = [
                'adaptix-server',
                'adaptix',
                '/opt/adaptix/adaptix-server'
            ]

            adaptix_path = None
            for name in adaptix_paths:
                path = shutil.which(name)
                if path:
                    adaptix_path = path
                    break
                # Check as direct path
                if os.path.exists(name):
                    adaptix_path = name
                    break

            if not adaptix_path:
                return None

            return {
                'installed': True,
                'server_path': adaptix_path,
                'endpoint': '/api/c2/adaptix/generate',
                'protocols': ['https', 'http', 'tcp', 'named_pipe'],
                'listener_cmd': 'Start Adaptix server (refer to documentation)',
                'setup_cmd': 'adaptix-server start',
                'detection_method': 'binary_check'
            }

        except Exception as e:
            logger.debug(f"[C2 Detector] Adaptix detection failed: {e}")
            return None

    @staticmethod
    def is_any_c2_available() -> bool:
        """Quick check if ANY C2 framework is available"""
        frameworks = C2Detector.detect_all()
        return len(frameworks) > 0

    @staticmethod
    def get_preferred_framework() -> Optional[str]:
        """
        Get the preferred C2 framework (prioritize Sliver > Mythic > Adaptix)

        Returns:
            Framework name or None
        """
        frameworks = C2Detector.detect_all()

        if not frameworks:
            return None

        # Priority order
        if 'sliver' in frameworks:
            return 'sliver'
        elif 'mythic' in frameworks:
            return 'mythic'
        elif 'adaptix' in frameworks:
            return 'adaptix'
        else:
            return list(frameworks.keys())[0]

    @staticmethod
    def get_framework_info(framework_name: str) -> Optional[Dict]:
        """Get detailed info about a specific framework"""
        frameworks = C2Detector.detect_all()
        return frameworks.get(framework_name)


# CLI test function
if __name__ == '__main__':
    import json

    print("=== Noctis-MCP C2 Framework Detector ===\n")

    frameworks = C2Detector.detect_all()

    if not frameworks:
        print("[!] No C2 frameworks detected")
        print("\nTo install Sliver:")
        print("  curl https://sliver.sh/install | sudo bash")
        print("\nTo install Mythic:")
        print("  git clone https://github.com/its-a-feature/Mythic.git")
        print("  cd Mythic && sudo ./install_docker_ubuntu.sh && sudo ./mythic-cli start")
    else:
        print(f"[+] Found {len(frameworks)} C2 framework(s):\n")
        for name, info in frameworks.items():
            print(f"  {name.upper()}:")
            print(f"    Installed: ✓")
            if 'version' in info:
                print(f"    Version: {info['version']}")
            if 'client_path' in info:
                print(f"    Client: {info['client_path']}")
            if 'path' in info:
                print(f"    Path: {info['path']}")
            if 'running' in info:
                print(f"    Running: {'✓' if info['running'] else '✗'}")
            print(f"    Endpoint: {info['endpoint']}")
            print(f"    Protocols: {', '.join(info['protocols'])}")
            print()

        preferred = C2Detector.get_preferred_framework()
        print(f"[*] Preferred framework: {preferred.upper()}")

    print("\n=== JSON Output ===")
    print(json.dumps(frameworks, indent=2))
