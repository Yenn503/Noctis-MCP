"""
Base C2 Adapter - Abstract Interface
=====================================

Provides the abstract base class that all C2 framework adapters must implement.
This ensures a consistent interface across different C2 frameworks.

Author: Noctis-MCP Team
Phase: 4 - C2 Integration
Sprint: 1 - Base Framework
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from datetime import datetime
from enum import Enum


class BeaconStatus(Enum):
    """Status of beacon generation"""
    PENDING = "pending"
    GENERATING = "generating"
    WRAPPING = "wrapping"
    OBFUSCATING = "obfuscating"
    COMPILING = "compiling"
    SUCCESS = "success"
    FAILED = "failed"


@dataclass
class C2GenerationResult:
    """
    Result of C2 beacon/agent generation
    
    Attributes:
        success: Whether generation succeeded
        beacon_path: Path to generated beacon executable
        shellcode_path: Path to raw shellcode (if applicable)
        beacon_size: Size of final beacon in bytes
        metadata: Additional metadata about the generation
        techniques_applied: List of Noctis technique IDs applied
        obfuscation_summary: Summary of obfuscation applied
        opsec_score: OPSEC analysis score (0-10)
        compilation_time: Time taken to compile (seconds)
        error_message: Error message if generation failed
        timestamp: When the beacon was generated
    """
    success: bool
    beacon_path: Optional[str] = None
    shellcode_path: Optional[str] = None
    beacon_size: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)
    techniques_applied: List[str] = field(default_factory=list)
    obfuscation_summary: Dict[str, Any] = field(default_factory=dict)
    opsec_score: float = 0.0
    compilation_time: float = 0.0
    error_message: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary for JSON serialization"""
        return {
            'success': self.success,
            'beacon_path': self.beacon_path,
            'shellcode_path': self.shellcode_path,
            'beacon_size': self.beacon_size,
            'metadata': self.metadata,
            'techniques_applied': self.techniques_applied,
            'obfuscation_summary': self.obfuscation_summary,
            'opsec_score': self.opsec_score,
            'compilation_time': self.compilation_time,
            'error_message': self.error_message,
            'timestamp': self.timestamp.isoformat()
        }


class C2Adapter(ABC):
    """
    Abstract base class for all C2 framework adapters
    
    Each C2 framework (Sliver, Havoc, Mythic, Custom) must implement
    this interface to integrate with Noctis-MCP.
    """
    
    def __init__(self, config: Any, verbose: bool = False):
        """
        Initialize C2 adapter
        
        Args:
            config: Framework-specific configuration object
            verbose: Enable verbose logging
        """
        self.config = config
        self.verbose = verbose
        self._status = BeaconStatus.PENDING
        
    @abstractmethod
    def connect(self) -> bool:
        """
        Connect to C2 server/framework
        
        Returns:
            True if connection successful, False otherwise
        """
        pass
    
    @abstractmethod
    def generate_shellcode(self) -> bytes:
        """
        Generate raw shellcode from C2 framework
        
        Returns:
            Raw shellcode bytes
            
        Raises:
            C2GenerationError: If shellcode generation fails
        """
        pass
    
    @abstractmethod
    def validate_config(self) -> tuple[bool, Optional[str]]:
        """
        Validate the configuration before generation
        
        Returns:
            (is_valid, error_message)
        """
        pass
    
    @abstractmethod
    def get_supported_protocols(self) -> List[str]:
        """
        Get list of supported C2 protocols for this framework
        
        Returns:
            List of protocol names (e.g., ['https', 'dns', 'tcp'])
        """
        pass
    
    @abstractmethod
    def get_framework_info(self) -> Dict[str, Any]:
        """
        Get information about the C2 framework
        
        Returns:
            Dictionary with framework name, version, capabilities, etc.
        """
        pass
    
    def generate_beacon(self, 
                       techniques: Optional[List[str]] = None,
                       obfuscate: bool = True,
                       compile_binary: bool = True) -> C2GenerationResult:
        """
        Main method to generate a complete C2 beacon
        
        This is the high-level workflow that coordinates:
        1. Validation
        2. Connection to C2 server
        3. Shellcode generation
        4. Technique integration
        5. Obfuscation
        6. Compilation
        
        Args:
            techniques: List of Noctis technique IDs to apply
            obfuscate: Whether to apply obfuscation
            compile_binary: Whether to compile to executable
            
        Returns:
            C2GenerationResult with all generation details
        """
        try:
            self._status = BeaconStatus.GENERATING
            
            # Step 1: Validate configuration
            is_valid, error_msg = self.validate_config()
            if not is_valid:
                return C2GenerationResult(
                    success=False,
                    error_message=f"Configuration validation failed: {error_msg}"
                )
            
            # Step 2: Connect to C2 server
            if not self.connect():
                return C2GenerationResult(
                    success=False,
                    error_message="Failed to connect to C2 server"
                )
            
            # Step 3: Generate base shellcode
            shellcode = self.generate_shellcode()
            if not shellcode:
                return C2GenerationResult(
                    success=False,
                    error_message="Failed to generate shellcode from C2 framework"
                )
            
            # Step 4-6: Handled by shellcode_wrapper (implemented next)
            # This will integrate with Noctis obfuscation and compilation
            
            return C2GenerationResult(
                success=True,
                shellcode_path="/tmp/beacon_shellcode.bin",
                beacon_size=len(shellcode),
                metadata=self.get_framework_info()
            )
            
        except Exception as e:
            self._status = BeaconStatus.FAILED
            return C2GenerationResult(
                success=False,
                error_message=f"Beacon generation failed: {str(e)}"
            )
    
    def get_status(self) -> BeaconStatus:
        """Get current generation status"""
        return self._status
    
    def disconnect(self):
        """Disconnect from C2 server (optional override)"""
        pass


class C2GenerationError(Exception):
    """Exception raised when C2 beacon generation fails"""
    pass

