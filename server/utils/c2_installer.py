"""
C2 Framework Auto-Installer
============================

Automatically installs C2 frameworks on Linux for seamless malware factory operation.

Author: Noctis-MCP Team
Phase: 5 - C2 Integration
"""

import os
import subprocess
import logging
import time
import shutil
from typing import Dict, Optional, Tuple
from pathlib import Path

logger = logging.getLogger(__name__)


class C2Installer:
    """Auto-install C2 frameworks on Linux"""

    @staticmethod
    def install_sliver(verbose: bool = True) -> Dict:
        """
        Install Sliver C2 framework using official installer

        Args:
            verbose: Show installation progress

        Returns:
            {
                'success': bool,
                'message': str,
                'install_path': str,
                'install_time': float
            }
        """
        if verbose:
            logger.info("[C2 Installer] Installing Sliver C2 framework...")

        start_time = time.time()

        try:
            # Check if already installed
            if shutil.which('sliver-client'):
                return {
                    'success': True,
                    'message': 'Sliver already installed',
                    'install_path': shutil.which('sliver-client'),
                    'install_time': 0.0
                }

            # Download and run official Sliver installer
            install_cmd = 'curl https://sliver.sh/install | sudo bash'

            if verbose:
                logger.info("[C2 Installer] Running: curl https://sliver.sh/install | sudo bash")
                logger.info("[C2 Installer] This may take 2-3 minutes...")

            process = subprocess.run(
                install_cmd,
                shell=True,
                capture_output=not verbose,
                text=True,
                timeout=300  # 5 minute timeout
            )

            if process.returncode != 0:
                return {
                    'success': False,
                    'message': f'Sliver installation failed: {process.stderr}',
                    'install_path': None,
                    'install_time': time.time() - start_time
                }

            # Verify installation
            client_path = shutil.which('sliver-client')
            if not client_path:
                # Check common locations
                common_paths = [
                    '/usr/local/bin/sliver-client',
                    '/usr/bin/sliver-client'
                ]
                for path in common_paths:
                    if os.path.exists(path) and os.access(path, os.X_OK):
                        client_path = path
                        break

            if not client_path:
                return {
                    'success': False,
                    'message': 'Sliver installation completed but binary not found',
                    'install_path': None,
                    'install_time': time.time() - start_time
                }

            install_time = time.time() - start_time

            if verbose:
                logger.info(f"[C2 Installer] Sliver installed successfully in {install_time:.1f}s")
                logger.info(f"[C2 Installer] Client: {client_path}")

            return {
                'success': True,
                'message': 'Sliver installed successfully',
                'install_path': client_path,
                'install_time': install_time
            }

        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'message': 'Sliver installation timed out (>5 minutes)',
                'install_path': None,
                'install_time': time.time() - start_time
            }
        except Exception as e:
            logger.error(f"[C2 Installer] Sliver installation error: {e}")
            return {
                'success': False,
                'message': f'Sliver installation error: {str(e)}',
                'install_path': None,
                'install_time': time.time() - start_time
            }

    @staticmethod
    def install_mythic(install_dir: str = "/opt/Mythic", verbose: bool = True) -> Dict:
        """
        Install Mythic C2 framework

        Args:
            install_dir: Where to install Mythic
            verbose: Show installation progress

        Returns:
            {
                'success': bool,
                'message': str,
                'install_path': str,
                'install_time': float,
                'ui_url': str
            }
        """
        if verbose:
            logger.info("[C2 Installer] Installing Mythic C2 framework...")

        start_time = time.time()

        try:
            # Check if already installed
            if os.path.exists(install_dir) and os.path.exists(os.path.join(install_dir, 'mythic-cli')):
                return {
                    'success': True,
                    'message': 'Mythic already installed',
                    'install_path': install_dir,
                    'install_time': 0.0,
                    'ui_url': 'https://127.0.0.1:7443'
                }

            # Clone Mythic repository
            if verbose:
                logger.info(f"[C2 Installer] Cloning Mythic to {install_dir}...")

            parent_dir = os.path.dirname(install_dir)
            os.makedirs(parent_dir, exist_ok=True)

            # Use shell=False to prevent command injection via install_dir
            process = subprocess.run(
                ['sudo', 'git', 'clone', 'https://github.com/its-a-feature/Mythic.git', install_dir],
                shell=False,
                capture_output=not verbose,
                text=True,
                timeout=180
            )

            if process.returncode != 0:
                return {
                    'success': False,
                    'message': f'Mythic clone failed: {process.stderr}',
                    'install_path': None,
                    'install_time': time.time() - start_time,
                    'ui_url': None
                }

            # Install Docker (required for Mythic)
            if verbose:
                logger.info("[C2 Installer] Installing Docker...")

            # Use shell=False and cwd parameter to prevent command injection
            subprocess.run(
                ['sudo', './install_docker_ubuntu.sh'],
                cwd=install_dir,
                shell=False,
                capture_output=True,
                timeout=300
            )

            # Start Mythic
            if verbose:
                logger.info("[C2 Installer] Starting Mythic server...")

            start_cmd = f'cd {install_dir} && sudo ./mythic-cli start'
            process = subprocess.run(
                start_cmd,
                shell=True,
                capture_output=not verbose,
                text=True,
                timeout=120
            )

            install_time = time.time() - start_time

            if verbose:
                logger.info(f"[C2 Installer] Mythic installed in {install_time:.1f}s")
                logger.info(f"[C2 Installer] UI: https://127.0.0.1:7443")

            return {
                'success': True,
                'message': 'Mythic installed successfully',
                'install_path': install_dir,
                'install_time': install_time,
                'ui_url': 'https://127.0.0.1:7443'
            }

        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'message': 'Mythic installation timed out',
                'install_path': None,
                'install_time': time.time() - start_time,
                'ui_url': None
            }
        except Exception as e:
            logger.error(f"[C2 Installer] Mythic installation error: {e}")
            return {
                'success': False,
                'message': f'Mythic installation error: {str(e)}',
                'install_path': None,
                'install_time': time.time() - start_time,
                'ui_url': None
            }

    @staticmethod
    def check_prerequisites() -> Dict[str, bool]:
        """
        Check if system has prerequisites for C2 installation

        Returns:
            {
                'curl': bool,
                'git': bool,
                'sudo': bool,
                'internet': bool
            }
        """
        import shutil

        prereqs = {}

        # Check for curl
        prereqs['curl'] = shutil.which('curl') is not None

        # Check for git
        prereqs['git'] = shutil.which('git') is not None

        # Check for sudo
        prereqs['sudo'] = shutil.which('sudo') is not None

        # Check internet connectivity
        try:
            import socket
            socket.create_connection(("8.8.8.8", 53), timeout=3)
            prereqs['internet'] = True
        except OSError:
            prereqs['internet'] = False

        return prereqs

    @staticmethod
    def auto_install_best_framework(verbose: bool = True) -> Dict:
        """
        Automatically install the best available C2 framework

        Priority: Sliver (easiest install)

        Returns:
            {
                'success': bool,
                'framework': str,
                'message': str,
                'install_info': dict
            }
        """
        if verbose:
            logger.info("[C2 Installer] Auto-installing best C2 framework...")

        # Check prerequisites
        prereqs = C2Installer.check_prerequisites()
        if not all(prereqs.values()):
            missing = [k for k, v in prereqs.items() if not v]
            return {
                'success': False,
                'framework': None,
                'message': f'Missing prerequisites: {", ".join(missing)}',
                'install_info': None
            }

        # Try Sliver first (easiest and fastest)
        logger.info("[C2 Installer] Attempting Sliver installation...")
        result = C2Installer.install_sliver(verbose=verbose)

        if result['success']:
            return {
                'success': True,
                'framework': 'sliver',
                'message': 'Sliver installed successfully',
                'install_info': result
            }

        # If Sliver fails, inform user
        return {
            'success': False,
            'framework': None,
            'message': f'Auto-install failed: {result["message"]}',
            'install_info': result
        }


# Import shutil at the top
import shutil


# CLI test function
if __name__ == '__main__':
    import sys

    print("=== Noctis-MCP C2 Auto-Installer ===\n")

    # Check prerequisites
    print("[*] Checking prerequisites...")
    prereqs = C2Installer.check_prerequisites()

    for prereq, available in prereqs.items():
        status = "✓" if available else "✗"
        print(f"    {prereq}: {status}")

    if not all(prereqs.values()):
        print("\n[!] Missing prerequisites. Cannot install C2 frameworks.")
        sys.exit(1)

    print("\n[*] Prerequisites OK\n")

    # Ask user which framework to install
    print("Available frameworks:")
    print("  1. Sliver (recommended - fast install)")
    print("  2. Mythic (requires Docker)")
    print("  3. Auto (install best available)")

    choice = input("\nSelect framework [1-3]: ").strip()

    if choice == '1':
        result = C2Installer.install_sliver(verbose=True)
    elif choice == '2':
        result = C2Installer.install_mythic(verbose=True)
    elif choice == '3':
        result = C2Installer.auto_install_best_framework(verbose=True)
    else:
        print("[!] Invalid choice")
        sys.exit(1)

    print("\n=== Installation Result ===")
    print(f"Success: {result['success']}")
    print(f"Message: {result['message']}")
    if result.get('install_path'):
        print(f"Install Path: {result['install_path']}")
    if result.get('install_time'):
        print(f"Install Time: {result['install_time']:.1f}s")
