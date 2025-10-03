"""
C2 Configuration System
=======================

Configuration dataclasses for all supported C2 frameworks.
Provides type-safe, validated configurations for beacon generation.

Author: Noctis-MCP Team
Phase: 4 - C2 Integration
Sprint: 1 - Base Framework
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, List, Dict, Any


class Protocol(Enum):
    """Supported C2 protocols"""
    HTTPS = "https"
    HTTP = "http"
    DNS = "dns"
    TCP = "tcp"
    MTLS = "mtls"
    UDP = "udp"
    WEBSOCKET = "websocket"
    SMB = "smb"
    NAMED_PIPE = "namedpipe"


class Architecture(Enum):
    """Target architecture"""
    X64 = "x64"
    X86 = "x86"
    ARM64 = "arm64"
    ARM = "arm"


class OutputFormat(Enum):
    """Output format for generated payload"""
    SHELLCODE = "shellcode"
    EXE = "exe"
    DLL = "dll"
    SERVICE_EXE = "service-exe"
    SHARED_LIB = "shared"


@dataclass
class C2Config:
    """
    Base configuration for all C2 frameworks
    
    Common parameters shared across all C2 frameworks
    """
    # Target information
    listener_host: str
    listener_port: int
    protocol: Protocol = Protocol.HTTPS
    architecture: Architecture = Architecture.X64
    
    # Output configuration
    output_format: OutputFormat = OutputFormat.EXE
    output_path: Optional[str] = None
    
    # Connection settings
    sleep_time: int = 60  # Beacon sleep time in seconds
    jitter: int = 30  # Sleep jitter percentage (0-100)
    max_connection_errors: int = 1000
    connection_timeout: int = 60
    
    # Evasion settings
    skip_proxy: bool = False
    proxy_url: Optional[str] = None
    user_agent: Optional[str] = None
    
    # Noctis integration
    apply_obfuscation: bool = True
    apply_polymorphic: bool = True
    techniques: List[str] = field(default_factory=list)
    
    def validate(self) -> tuple[bool, Optional[str]]:
        """
        Validate configuration parameters
        
        Returns:
            (is_valid, error_message)
        """
        if not self.listener_host:
            return False, "listener_host is required"
        
        if self.listener_port <= 0 or self.listener_port > 65535:
            return False, f"Invalid port: {self.listener_port}"
        
        if self.jitter < 0 or self.jitter > 100:
            return False, f"Jitter must be 0-100, got {self.jitter}"
        
        if self.sleep_time < 0:
            return False, f"Sleep time cannot be negative"
        
        return True, None


@dataclass
class SliverConfig(C2Config):
    """
    Configuration for Sliver C2 framework
    
    Sliver-specific parameters:
    - Multiple protocol support (HTTPS, DNS, TCP, mTLS)
    - Beacon/Session modes
    - Advanced evasion features
    """
    # Sliver server connection
    sliver_host: str = "127.0.0.1"
    sliver_port: int = 31337
    operator_config: Optional[str] = None  # Path to operator config file
    
    # Beacon configuration
    beacon_name: Optional[str] = None
    kill_date: Optional[str] = None  # Format: "2025-12-31"
    reconnect_interval: int = 60
    poll_timeout: int = 360
    
    # Protocol-specific settings
    # For HTTPS/HTTP
    http_c2_url: Optional[str] = None
    http_host_header: Optional[str] = None
    
    # For DNS
    dns_canary_domain: Optional[str] = None
    dns_parent_domain: Optional[str] = None
    
    # For mTLS
    mtls_ca_cert: Optional[str] = None
    mtls_cert: Optional[str] = None
    mtls_key: Optional[str] = None
    
    # Evasion features
    obfuscate_symbols: bool = True
    debug: bool = False
    evasion: bool = True
    skip_symbols: bool = False
    
    # Limits
    limit_domainjoined: bool = False
    limit_hostname: Optional[str] = None
    limit_username: Optional[str] = None
    limit_datetime: Optional[str] = None
    
    def validate(self) -> tuple[bool, Optional[str]]:
        """Validate Sliver-specific configuration"""
        base_valid, base_error = super().validate()
        if not base_valid:
            return base_valid, base_error
        
        # Validate protocol-specific settings
        if self.protocol == Protocol.DNS:
            if not self.dns_parent_domain:
                return False, "dns_parent_domain required for DNS protocol"
        
        if self.protocol == Protocol.MTLS:
            if not all([self.mtls_ca_cert, self.mtls_cert, self.mtls_key]):
                return False, "mTLS requires ca_cert, cert, and key"
        
        return True, None


@dataclass
class HavocConfig(C2Config):
    """
    Configuration for Havoc C2 framework
    
    Havoc-specific parameters:
    - Demon agent configuration
    - Sleep obfuscation techniques (Foliage, Ekko, WaitForSingleObjectEx)
    - Stack spoofing and indirect syscalls
    """
    # Havoc server connection
    havoc_host: str = "127.0.0.1"
    havoc_port: int = 40056
    username: str = "noctis"
    password: str = "noctis123"
    
    # Demon configuration
    demon_name: Optional[str] = None
    listener_name: Optional[str] = None
    
    # Sleep obfuscation
    sleep_technique: str = "WaitForSingleObjectEx"  # Options: Foliage, Ekko, WaitForSingleObjectEx
    sleep_mask: bool = True  # Encrypt beacon memory during sleep
    
    # Evasion techniques
    indirect_syscalls: bool = True
    stack_duplication: bool = True
    sleep_obfuscation: bool = True
    module_stomping: bool = False
    
    # Injection settings
    injection_technique: str = "Syscall"  # Options: Syscall, NtCreateSection
    injection_spawn_to: str = "C:\\Windows\\System32\\notepad.exe"
    
    # OPSEC features
    proxy_loading: bool = True
    amsi_patch: bool = True
    etw_patch: bool = True
    
    def validate(self) -> tuple[bool, Optional[str]]:
        """Validate Havoc-specific configuration"""
        base_valid, base_error = super().validate()
        if not base_valid:
            return base_valid, base_error
        
        valid_sleep_techniques = ["Foliage", "Ekko", "WaitForSingleObjectEx"]
        if self.sleep_technique not in valid_sleep_techniques:
            return False, f"Invalid sleep_technique. Must be one of: {valid_sleep_techniques}"
        
        return True, None


@dataclass
class MythicConfig(C2Config):
    """
    Configuration for Mythic C2 framework
    
    Mythic-specific parameters:
    - Agent-based architecture
    - Modular payload types
    - Multiple C2 profiles
    """
    # Mythic server connection
    mythic_host: str = "127.0.0.1"
    mythic_port: int = 7443
    api_key: str = ""
    
    # Agent configuration
    payload_type: str = "apollo"  # apollo, merlin, poseidon, etc.
    c2_profile: str = "http"  # http, https, websocket, etc.
    callback_host: Optional[str] = None
    callback_port: Optional[int] = None
    
    # Build parameters
    build_parameters: Dict[str, Any] = field(default_factory=dict)
    commands: List[str] = field(default_factory=list)  # Commands to include
    
    # Encryption
    encrypted_exchange_check: bool = True
    crypto_type: str = "aes256_hmac"
    
    def validate(self) -> tuple[bool, Optional[str]]:
        """Validate Mythic-specific configuration"""
        base_valid, base_error = super().validate()
        if not base_valid:
            return base_valid, base_error
        
        if not self.api_key:
            return False, "Mythic API key is required"
        
        if not self.payload_type:
            return False, "payload_type is required"
        
        return True, None


@dataclass
class CustomC2Config(C2Config):
    """
    Configuration for custom C2 implementations
    
    Flexible configuration for building custom beacons with
    arbitrary protocols and features.
    """
    # Custom protocol settings
    custom_protocol: str = "custom"
    protocol_handler: Optional[str] = None  # Path to custom protocol handler
    
    # Beacon behavior
    beacon_type: str = "reverse"  # reverse, bind, hybrid
    command_handler: str = "default"
    
    # Custom headers/encryption
    custom_headers: Dict[str, str] = field(default_factory=dict)
    encryption_algorithm: str = "aes256"
    encryption_key: Optional[str] = None
    
    # Shellcode template
    shellcode_template: Optional[str] = None  # Path to custom shellcode template
    loader_template: Optional[str] = None  # Path to custom loader template
    
    def validate(self) -> tuple[bool, Optional[str]]:
        """Validate custom C2 configuration"""
        base_valid, base_error = super().validate()
        if not base_valid:
            return base_valid, base_error
        
        if self.beacon_type not in ["reverse", "bind", "hybrid"]:
            return False, f"Invalid beacon_type: {self.beacon_type}"
        
        return True, None


# Configuration factory function
def create_c2_config(framework: str, **kwargs) -> C2Config:
    """
    Factory function to create appropriate C2 config
    
    Args:
        framework: C2 framework name ('sliver', 'havoc', 'mythic', 'custom')
        **kwargs: Configuration parameters
        
    Returns:
        Appropriate C2Config subclass instance
        
    Raises:
        ValueError: If framework is not supported
    """
    framework_map = {
        'sliver': SliverConfig,
        'havoc': HavocConfig,
        'mythic': MythicConfig,
        'custom': CustomC2Config
    }
    
    framework_lower = framework.lower()
    if framework_lower not in framework_map:
        raise ValueError(f"Unsupported framework: {framework}. Supported: {list(framework_map.keys())}")
    
    config_class = framework_map[framework_lower]
    return config_class(**kwargs)

