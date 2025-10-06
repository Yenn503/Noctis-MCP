"""
Noctis-MCP C2 Integration Module
==================================

This module provides adapters for various Command & Control frameworks,
allowing Noctis to generate operational beacons/agents with full evasion techniques.

Supported Frameworks:
- Sliver: Modern C2 with multiple protocols (HTTPS, DNS, TCP, mTLS) + BOF
- Adaptix: AxScript BOF execution with crash-safe design
- Mythic: Agent-based architecture with Forge BOF integration
- Custom: Generic beacon builder for custom C2 protocols

Architecture:
- Base C2Adapter provides common interface
- Framework-specific adapters extend base class
- Configuration system handles all C2 parameters
- Shellcode wrapper integrates with Noctis obfuscation techniques
- BOF compiler for Beacon Object Files

Author: Noctis-MCP Team
Phase: 4 - C2 Integration
Version: 2.0.0 - BOF Support
"""

from .base_adapter import C2Adapter, C2GenerationResult, BeaconStatus
from .config import (
    C2Config,
    SliverConfig,
    MythicConfig,
    CustomC2Config,
    Protocol,
    Architecture,
    OutputFormat
)
from .shellcode_wrapper import ShellcodeWrapper, WrapperConfig
from .sliver_adapter import SliverAdapter, generate_sliver_beacon
from .adaptix_adapter import AdaptixAdapter, generate_adaptix_beacon, AdaptixConfig
from .mythic_adapter import MythicAdapter, generate_mythic_agent

__all__ = [
    'C2Adapter',
    'C2GenerationResult',
    'BeaconStatus',
    'C2Config',
    'SliverConfig',
    'AdaptixConfig',
    'MythicConfig',
    'CustomC2Config',
    'Protocol',
    'Architecture',
    'OutputFormat',
    'ShellcodeWrapper',
    'WrapperConfig',
    'SliverAdapter',
    'generate_sliver_beacon',
    'AdaptixAdapter',
    'generate_adaptix_beacon',
    'MythicAdapter',
    'generate_mythic_agent'
]

__version__ = '2.0.0'

