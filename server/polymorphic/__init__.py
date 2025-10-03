"""
Polymorphic Engine for Noctis-MCP
==================================

Code mutation and polymorphism for generating unique malware variants.

Modules:
- engine: Main polymorphic engine
- mutator: Code mutation and transformation
- variable_renamer: Variable and function renaming
- instruction_sub: Instruction substitution (future)
"""

from .engine import PolymorphicEngine
from .mutator import CodeMutator

__all__ = ['PolymorphicEngine', 'CodeMutator']

