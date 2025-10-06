"""
Adaptix C2 Adapter
==================

Integrates with Adaptix C2 framework for beacon generation and BOF execution.

Features:
- AxScript-based extension system
- Position-independent BOF execution
- Single-threaded, crash-safe design
- ax.bof_pack() argument packing
- Integration with Noctis obfuscation

Author: Noctis-MCP Team
Phase: 4 - C2 Integration
Sprint: 3 - Adaptix Integration
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


@dataclass
class AdaptixConfig:
    """Configuration for Adaptix C2"""
    adaptix_host: str = "127.0.0.1"
    adaptix_port: int = 443
    listener_host: str = "0.0.0.0"
    listener_port: int = 443
    protocol: Protocol = Protocol.HTTPS
    architecture: Architecture = Architecture.X64
    output_format: OutputFormat = OutputFormat.SHELLCODE
    beacon_name: Optional[str] = None
    sleep_time: int = 5
    jitter: int = 20
    output_path: Optional[str] = None

    # Adaptix-specific
    extension_name: Optional[str] = None
    bof_enabled: bool = True
    crash_safe: bool = True  # Single-threaded, position-independent

    def validate(self) -> Tuple[bool, Optional[str]]:
        """Validate Adaptix configuration"""
        if not self.listener_host:
            return False, "listener_host required"
        if not self.listener_port:
            return False, "listener_port required"
        if self.sleep_time < 0:
            return False, "sleep_time must be >= 0"
        return True, None


class AdaptixAdapter(C2Adapter):
    """
    Adaptix C2 Framework Adapter

    Connects to Adaptix server and generates beacons with Noctis obfuscation.

    Adaptix Features:
    - AxScript extension system
    - BOF execution with ax.bof_pack()
    - Position-independent code
    - Crash-safe (single-threaded)
    - Custom metadata storage
    """

    def __init__(self, config: AdaptixConfig, verbose: bool = False):
        """
        Initialize Adaptix adapter

        Args:
            config: AdaptixConfig with connection and beacon parameters
            verbose: Enable verbose logging
        """
        super().__init__(config, verbose)

        if verbose:
            print(f"[*] AdaptixAdapter initialized")
            print(f"[*] Adaptix server: {config.adaptix_host}:{config.adaptix_port}")

    def connect(self) -> bool:
        """
        Connect to Adaptix server via API/CLI

        Returns:
            True if connection successful
        """
        if self.verbose:
            print(f"[*] Connecting to Adaptix server at {self.config.adaptix_host}:{self.config.adaptix_port}")

        # TODO: Implement actual Adaptix connection
        # For now, assume connection is successful
        # In production, this would use Adaptix API or CLI

        if self.verbose:
            print(f"[+] Connected to Adaptix server")

        return True

    def generate_shellcode(self) -> bytes:
        """
        Generate Adaptix beacon shellcode

        Returns:
            Raw shellcode bytes

        Raises:
            Exception: If shellcode generation fails
        """
        if self.verbose:
            print("[*] Generating Adaptix beacon shellcode...")

        # TODO: Implement actual Adaptix shellcode generation
        # This would use Adaptix API/CLI to generate beacon

        # Placeholder: Generate dummy shellcode for testing
        shellcode = b'\x90' * 1024  # NOP sled for testing

        if self.verbose:
            print(f"[+] Generated {len(shellcode)} bytes of shellcode")

        return shellcode

    def validate_config(self) -> Tuple[bool, Optional[str]]:
        """Validate Adaptix configuration"""
        return self.config.validate()

    def get_supported_protocols(self) -> List[str]:
        """Get supported protocols"""
        return ['https', 'http', 'tcp', 'named_pipe']

    def get_framework_info(self) -> Dict[str, Any]:
        """Get Adaptix framework information"""
        return {
            'framework': 'Adaptix',
            'version': '1.x',
            'protocols': self.get_supported_protocols(),
            'architectures': ['x64', 'x86'],
            'formats': ['shellcode', 'exe', 'dll'],
            'features': [
                'AxScript extensions',
                'BOF execution (ax.bof_pack)',
                'Position-independent code',
                'Crash-safe (single-threaded)',
                'Custom metadata storage'
            ]
        }

    def generate_beacon(self,
                       techniques: Optional[List[str]] = None,
                       obfuscate: bool = True,
                       compile_binary: bool = True) -> C2GenerationResult:
        """
        Generate complete Adaptix beacon with Noctis obfuscation

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

            # Step 2: Connect to Adaptix
            if not self.connect():
                return C2GenerationResult(
                    success=False,
                    error_message="Failed to connect to Adaptix server"
                )

            # Step 3: Generate Adaptix shellcode
            self._status = BeaconStatus.GENERATING
            shellcode = self.generate_shellcode()

            if not shellcode:
                return C2GenerationResult(
                    success=False,
                    error_message="Failed to generate Adaptix shellcode"
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
                output_path = self.config.output_path or '/tmp/adaptix_beacon_wrapped.c'
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
                shellcode_path = '/tmp/adaptix_beacon_raw.bin'
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

    def generate_axscript_extension(
        self,
        bof_name: str,
        bof_x86_path: str,
        bof_x64_path: str,
        description: str = "",
        arg_format: str = ""
    ) -> str:
        """
        Generate AxScript extension file for Adaptix BOF

        Per Adaptix spec: ax.bof_pack() requires argument type string
        Example: ax.bof_pack("cstr,int", [note, pid])

        Args:
            bof_name: Name of the BOF
            bof_x86_path: Path to x86 BOF object file
            bof_x64_path: Path to x64 BOF object file
            description: Extension description
            arg_format: BOF argument format (e.g., "cstr,int")

        Returns:
            Path to generated AxScript file
        """
        # Use ax.script_dir() and ax.arch() per Adaptix spec
        script_content = f'''// {bof_name} - Noctis-MCP Generated Extension
var metadata = {{
    name: "{bof_name}",
    description: "{description or 'Noctis-MCP BOF Extension'}",
    store: true
}};

function {bof_name}(id, cmdline, args) {{
    // Get BOF path using Adaptix ax.script_dir() and ax.arch()
    let bof_path = ax.script_dir() + "_bin/{bof_name}." + ax.arch(id) + ".o";

    // Pack arguments per Adaptix spec (if args provided)
    let bof_params = "";
    if (args && args.length > 0) {{
        bof_params = ax.bof_pack("{arg_format or ''}", args);
    }}

    // Execute BOF using execute_alias per Adaptix pattern
    ax.execute_alias(id, cmdline, `execute bof ${{bof_path}} ${{bof_params}}`);
}}

// Register command
ax.registerCommand("{bof_name.lower()}", {bof_name});
'''

        # Write AxScript file
        output_path = Path(self.config.output_path or '/tmp') / f"{bof_name}.axs"
        output_path.write_text(script_content)

        if self.verbose:
            print(f"[+] Generated AxScript extension: {output_path}")

        return str(output_path)


# Convenience function
def generate_adaptix_beacon(
    listener_host: str,
    listener_port: int,
    protocol: str = "https",
    architecture: str = "x64",
    techniques: Optional[List[str]] = None,
    obfuscate: bool = True,
    verbose: bool = False
) -> C2GenerationResult:
    """
    Convenience function to generate Adaptix beacon

    Requirements:
        - Adaptix C2 framework installed and running

    Args:
        listener_host: C2 listener hostname/IP
        listener_port: C2 listener port
        protocol: C2 protocol (https, http, tcp, named_pipe)
        architecture: Target architecture (x64, x86)
        techniques: Noctis technique IDs to apply
        obfuscate: Apply Noctis obfuscation
        verbose: Enable verbose output

    Returns:
        C2GenerationResult
    """
    # Create configuration
    config = AdaptixConfig(
        listener_host=listener_host,
        listener_port=listener_port,
        protocol=Protocol(protocol),
        architecture=Architecture(architecture),
        beacon_name=f"noctis_beacon_{int(time.time())}"
    )

    # Create adapter
    adapter = AdaptixAdapter(config, verbose=verbose)

    # Generate beacon
    return adapter.generate_beacon(
        techniques=techniques,
        obfuscate=obfuscate
    )
