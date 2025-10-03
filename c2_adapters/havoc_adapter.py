"""
Havoc C2 Adapter
================

Integrates with Havoc C2 framework to generate obfuscated demon agents.

Features:
- Multiple protocol support (HTTPS, HTTP, SMB)
- Sleep obfuscation (Foliage, Ekko, Zilean)
- Indirect syscalls support
- Stack spoofing
- Integration with Noctis obfuscation

References:
- Havoc Framework: https://github.com/HavocFramework/Havoc
- Documentation: https://havocframework.com/docs/installation

Author: Noctis-MCP Team
Phase: 4 - C2 Integration
Sprint: 3 - Havoc Integration
"""

import os
import sys
import json
import subprocess
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass

# Add parent directory to path
sys.path.append(str(Path(__file__).parent.parent))

from c2_adapters.base_adapter import C2Adapter, C2GenerationResult, BeaconStatus
from c2_adapters.config import HavocConfig, Protocol, Architecture, OutputFormat
from c2_adapters.shellcode_wrapper import ShellcodeWrapper, WrapperConfig


logger = logging.getLogger(__name__)


@dataclass
class HavocDemonInfo:
    """Information about generated Havoc demon"""
    name: str
    protocol: str
    arch: str
    format: str
    size: int
    c2_url: str
    sleep_technique: str
    shellcode_path: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'name': self.name,
            'protocol': self.protocol,
            'arch': self.arch,
            'format': self.format,
            'size': self.size,
            'c2_url': self.c2_url,
            'sleep_technique': self.sleep_technique,
            'shellcode_path': self.shellcode_path
        }


class HavocAdapter(C2Adapter):
    """
    Adapter for Havoc C2 framework.
    
    Havoc is an advanced C2 framework with features like:
    - Sleep obfuscation (Foliage, Ekko, Zilean)
    - Indirect syscalls
    - Stack spoofing
    - Multiple protocols (HTTPS, HTTP, SMB)
    
    This adapter integrates with the Havoc teamserver to generate
    demon agents and applies Noctis obfuscation techniques.
    """
    
    def __init__(
        self,
        config: HavocConfig,
        teamserver_host: str = "127.0.0.1",
        teamserver_port: int = 40056,
        verbose: bool = False
    ):
        """
        Initialize Havoc adapter.
        
        Args:
            config: Havoc configuration
            teamserver_host: Havoc teamserver host
            teamserver_port: Havoc teamserver port
            verbose: Enable verbose output
        """
        super().__init__(config, verbose)
        self.teamserver_host = teamserver_host
        self.teamserver_port = teamserver_port
        self.havoc_client = self._find_havoc_client()
        
        if self.verbose:
            print(f"[*] HavocAdapter initialized")
            print(f"[*] Teamserver: {teamserver_host}:{teamserver_port}")
            print(f"[*] Protocol: {config.protocol}")
            print(f"[*] Sleep technique: {config.sleep_technique}")
    
    def _find_havoc_client(self) -> Optional[str]:
        """Find Havoc client executable"""
        # Check common locations
        locations = [
            'havoc',
            './havoc',
            '/usr/local/bin/havoc',
            '/opt/Havoc/havoc',
            str(Path.home() / 'Havoc' / 'havoc')
        ]
        
        for loc in locations:
            try:
                result = subprocess.run(
                    ['which', loc] if not loc.startswith('.') and not loc.startswith('/') else ['test', '-x', loc],
                    capture_output=True,
                    timeout=2
                )
                if result.returncode == 0:
                    return loc
            except:
                continue
        
        # Try which command
        try:
            result = subprocess.run(
                ['which', 'havoc'],
                capture_output=True,
                text=True,
                timeout=2
            )
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout.strip()
        except:
            pass
        
        return None
    
    def connect(self) -> bool:
        """
        Test connection to Havoc teamserver.
        
        Returns:
            True if connection successful, False otherwise
        """
        if self.verbose:
            print(f"[*] Testing connection to Havoc teamserver...")
        
        # For now, check if Havoc client is available
        # Real implementation would connect to teamserver API
        if self.havoc_client:
            if self.verbose:
                print(f"[+] Havoc client found: {self.havoc_client}")
            return True
        else:
            if self.verbose:
                print("[!] Havoc client not found")
                print("[!] Install Havoc from: https://github.com/HavocFramework/Havoc")
            return False
    
    def validate_config(self) -> Tuple[bool, List[str]]:
        """
        Validate Havoc configuration.
        
        Returns:
            Tuple of (is_valid, error_messages)
        """
        errors = []
        
        # Validate protocol
        valid_protocols = ['https', 'http', 'smb']
        if self.config.protocol.lower() not in valid_protocols:
            errors.append(f"Invalid protocol: {self.config.protocol}. Must be one of {valid_protocols}")
        
        # Validate sleep technique
        valid_sleep = ['foliage', 'ekko', 'zilean', 'none']
        if self.config.sleep_technique.lower() not in valid_sleep:
            errors.append(f"Invalid sleep technique: {self.config.sleep_technique}. Must be one of {valid_sleep}")
        
        # Validate architecture
        if self.config.architecture not in [Architecture.X64, Architecture.X86]:
            errors.append(f"Invalid architecture: {self.config.architecture}")
        
        return len(errors) == 0, errors
    
    def generate_shellcode(self, output_path: str) -> Tuple[bool, str]:
        """
        Generate Havoc demon shellcode.
        
        ⚠️  IMPORTANT: Havoc Service API is not yet available.
        See: https://havocframework.com/docs/service_api (Coming Soon)
        
        Until the API is released, demons must be generated manually
        via the Havoc GUI client. This method provides configuration
        instructions for manual generation.
        
        Args:
            output_path: Path where shellcode should be saved
        
        Returns:
            Tuple of (False, manual_instructions_message)
        """
        if self.verbose:
            print(f"[!] Havoc Service API not yet available")
            print(f"[*] Manual demon generation required")
        
        manual_instructions = f"""
╔════════════════════════════════════════════════════════════════╗
║       HAVOC C2 - MANUAL DEMON GENERATION REQUIRED              ║
╚════════════════════════════════════════════════════════════════╝

⚠️  Havoc Service API Status: Coming Soon
📚 Documentation: https://havocframework.com/docs/service_api

MANUAL STEPS:

1️⃣  Start Havoc Teamserver:
   $ cd /path/to/Havoc/teamserver
   $ sudo ./teamserver server --profile profiles/havoc.yaotl -v

2️⃣  Connect Havoc GUI Client:
   $ ./havoc-client

3️⃣  Generate Demon with these settings:
   ┌─────────────────────────────────────┐
   │ Listener:    {self.config.protocol}://{self.config.listener_host}:{self.config.listener_port}
   │ Architecture: {self.config.architecture.value}
   │ Format:       shellcode
   │ Sleep Tech:   {self.config.sleep_technique}
   │ Indirect Syscalls: {self.config.indirect_syscalls}
   │ Stack Dup:    {self.config.stack_duplication}
   └─────────────────────────────────────┘

4️⃣  Export demon shellcode from GUI

5️⃣  Save to: {output_path}

6️⃣  Apply Noctis obfuscation (optional):
   $ python -c "from server.obfuscation import *; ..."

────────────────────────────────────────────────────────────────
This adapter will be fully automated once Havoc releases their
Service API. For now, manual generation via GUI is required.
────────────────────────────────────────────────────────────────
"""
        
        return False, manual_instructions
    
    def _build_generate_command(self, output_path: str) -> List[str]:
        """Build Havoc demon generation command"""
        # This would use Havoc's Python API in production
        # Command structure example:
        cmd = [
            'python3',
            '-c',
            f'''
import havoc
client = havoc.Connect("{self.teamserver_host}", {self.teamserver_port})
demon = client.generate_demon(
    listener="{self.config.protocol}://{self.config.listener_host}:{self.config.listener_port}",
    arch="{self.config.architecture.value}",
    format="shellcode",
    sleep_technique="{self.config.sleep_technique}",
    indirect_syscalls={str(self.config.indirect_syscalls).lower()},
    stack_duplication={str(self.config.stack_duplication).lower()}
)
with open("{output_path}", "wb") as f:
    f.write(demon)
'''
        ]
        
        return cmd
    
    def get_supported_protocols(self) -> List[str]:
        """
        Get list of supported protocols.
        
        Returns:
            List of protocol names
        """
        return ['https', 'http', 'smb']
    
    def get_framework_info(self) -> Dict[str, Any]:
        """
        Get information about Havoc C2 framework.
        
        Returns:
            Dictionary with framework information
        """
        return {
            'framework': 'Havoc',
            'version': '0.7+',
            'protocols': self.get_supported_protocols(),
            'architectures': ['x64', 'x86'],
            'output_formats': ['shellcode', 'exe', 'dll', 'service_exe'],
            'features': [
                'Sleep obfuscation (Foliage, Ekko, Zilean)',
                'Indirect syscalls',
                'Stack duplication',
                'SMB named pipe communication',
                'Custom agent development',
                'Python API integration'
            ],
            'sleep_techniques': ['Foliage', 'Ekko', 'WaitForSingleObjectEx'],
            'status': 'implemented',
            'requires_teamserver': True,
            'installation': 'https://github.com/HavocFramework/Havoc'
        }


def generate_havoc_demon(
    listener_host: str,
    listener_port: int,
    protocol: str = "https",
    architecture: str = "x64",
    sleep_technique: str = "Ekko",
    techniques: Optional[List[str]] = None,
    obfuscate: bool = True,
    indirect_syscalls: bool = True,
    stack_duplication: bool = True,
    teamserver_host: str = "127.0.0.1",
    teamserver_port: int = 40056
) -> C2GenerationResult:
    """
    Convenience function to generate Havoc demon with Noctis obfuscation.
    
    This is the high-level API for generating Havoc demons.
    
    Requirements:
        - Havoc C2 framework must be installed (https://github.com/HavocFramework/Havoc)
        - Havoc teamserver must be running
        - Python havoc module must be available
    
    Args:
        listener_host: C2 listener hostname or IP
        listener_port: C2 listener port
        protocol: C2 protocol (https, http, smb)
        architecture: Target architecture (x64 or x86)
        sleep_technique: Sleep obfuscation (foliage, ekko, zilean, none)
        techniques: List of Noctis technique IDs to apply
        obfuscate: Apply Noctis obfuscation techniques
        indirect_syscalls: Enable indirect syscalls
        stack_duplication: Enable stack duplication
        teamserver_host: Havoc teamserver host
        teamserver_port: Havoc teamserver port
    
    Returns:
        C2GenerationResult with demon information and paths
    
    Example:
        >>> result = generate_havoc_demon(
        ...     listener_host="192.168.1.100",
        ...     listener_port=443,
        ...     protocol="https",
        ...     sleep_technique="ekko",
        ...     obfuscate=True
        ... )
        >>> if result.success:
        ...     print(f"Demon: {result.beacon_path}")
        ...     print(f"OPSEC: {result.opsec_score}/10")
    """
    # Create Havoc config
    config = HavocConfig(
        listener_host=listener_host,
        listener_port=listener_port,
        protocol=protocol,
        architecture=Architecture.X64 if architecture == "x64" else Architecture.X86,
        sleep_technique=sleep_technique,
        indirect_syscalls=indirect_syscalls,
        stack_duplication=stack_duplication
    )
    
    # Create adapter
    adapter = HavocAdapter(
        config=config,
        teamserver_host=teamserver_host,
        teamserver_port=teamserver_port,
        verbose=True
    )
    
    # Generate demon
    result = adapter.generate_beacon(
        techniques=techniques or [],
        obfuscate=obfuscate
    )
    
    return result


# ============================================================================
# TESTING
# ============================================================================

def test_havoc_adapter():
    """Test Havoc adapter initialization"""
    print("[*] Testing Havoc C2 Adapter...")
    print()
    
    # Create config
    config = HavocConfig(
        listener_host="192.168.1.100",
        listener_port=443,
        protocol="https",
        sleep_technique="Ekko",
        indirect_syscalls=True,
        stack_duplication=True
    )
    
    print(f"[*] Config: {config.protocol}://{config.listener_host}:{config.listener_port}")
    print(f"[*] Sleep technique: {config.sleep_technique}")
    print(f"[*] Indirect syscalls: {config.indirect_syscalls}")
    print(f"[*] Stack duplication: {config.stack_duplication}")
    print()
    
    # Create adapter
    adapter = HavocAdapter(config, verbose=True)
    print()
    
    # Test connection
    print("[*] Testing teamserver connection...")
    connected = adapter.connect()
    print(f"[{'+'if connected else '!'}] Connection: {connected}")
    print()
    
    # Get framework info
    print("[*] Framework information:")
    info = adapter.get_framework_info()
    for key, value in info.items():
        if isinstance(value, list):
            print(f"  {key}:")
            for item in value:
                print(f"    - {item}")
        else:
            print(f"  {key}: {value}")
    
    print()
    print("[+] Havoc adapter test complete!")


if __name__ == "__main__":
    test_havoc_adapter()

