"""
Noctis-MCP C2 Integration Module
==================================

This module provides adapters for various Command & Control frameworks,
allowing Noctis to generate operational beacons/agents with full evasion techniques.

Supported Frameworks:
- Sliver: Modern C2 with multiple protocols (HTTPS, DNS, TCP, mTLS)
- Havoc: Advanced sleep obfuscation and demon agents
- Mythic: Agent-based architecture with modular design
- Custom: Generic beacon builder for custom C2 protocols

Architecture:
- Base C2Adapter provides common interface
- Framework-specific adapters extend base class
- Configuration system handles all C2 parameters
- Shellcode wrapper integrates with Noctis obfuscation techniques

Author: Noctis-MCP Team
Phase: 4 - C2 Integration
Sprint: 1 - Base Framework
"""

from .base_adapter import C2Adapter, C2GenerationResult, BeaconStatus
from .config import (
    C2Config,
    SliverConfig,
    HavocConfig,
    MythicConfig,
    CustomC2Config,
    Protocol,
    Architecture,
    OutputFormat
)
from .shellcode_wrapper import ShellcodeWrapper, WrapperConfig
from .sliver_adapter import SliverAdapter, generate_sliver_beacon
from .havoc_adapter import HavocAdapter, generate_havoc_demon
from .mythic_adapter import MythicAdapter, generate_mythic_agent

__all__ = [
    'C2Adapter',
    'C2GenerationResult',
    'BeaconStatus',
    'C2Config',
    'SliverConfig',
    'HavocConfig',
    'MythicConfig',
    'CustomC2Config',
    'Protocol',
    'Architecture',
    'OutputFormat',
    'ShellcodeWrapper',
    'WrapperConfig',
    'SliverAdapter',
    'generate_sliver_beacon',
    'HavocAdapter',
    'generate_havoc_demon',
    'MythicAdapter',
    'generate_mythic_agent'
]

__version__ = '1.0.0'

