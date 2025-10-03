"""
Obfuscation Engine for Noctis-MCP
==================================

Advanced code obfuscation techniques for malware evasion.

Modules:
- string_encryption: Encrypt strings in code
- api_hashing: Hide API calls with hashing (TODO)
- control_flow: Flatten control flow (TODO)
- junk_code: Insert dead code (TODO)
"""

from server.obfuscation.string_encryption import StringEncryptor
from server.obfuscation.api_hashing import APIHasher
from server.obfuscation.control_flow import ControlFlowFlattener, JunkCodeInserter, flatten_control_flow, insert_junk_code

__all__ = [
    'StringEncryptor', 
    'APIHasher', 
    'ControlFlowFlattener', 
    'JunkCodeInserter',
    'flatten_control_flow',
    'insert_junk_code'
]

