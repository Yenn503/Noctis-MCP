#!/usr/bin/env python3
"""
Advanced Noctis-MCP Technique Indexer
======================================

Enhanced version with:
- Deep function extraction with full signatures
- Automatic MITRE ATT&CK mapping
- Enhanced dependency categorization
- Code quality metrics
- Better function body extraction

Author: Noctis-MCP Community
License: MIT
"""

import os
import json
import re
import hashlib
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, asdict, field
from datetime import datetime
import argparse

# Import base indexer
from technique_indexer import TechniqueIndexer, TechniqueMetadata


@dataclass
class FunctionDefinition:
    """Represents a complete function definition"""
    name: str
    return_type: str
    parameters: List[Tuple[str, str]]  # [(type, name), ...]
    body: str
    line_start: int
    line_end: int
    complexity: int  # Cyclomatic complexity estimate
    calls: List[str]  # Functions called within this function

    def signature(self) -> str:
        """Get full function signature"""
        params = ", ".join([f"{ptype} {pname}" for ptype, pname in self.parameters])
        return f"{self.return_type} {self.name}({params})"


@dataclass
class EnhancedDependencies:
    """Enhanced dependency information"""
    system_headers: List[str] = field(default_factory=list)  # <Windows.h>, <stdio.h>
    project_headers: List[str] = field(default_factory=list)  # "Common.h", "Structs.h"
    external_libs: List[str] = field(default_factory=list)  # ntdll.dll, kernel32.dll
    functions_called: List[str] = field(default_factory=list)  # NtAllocate, GetProcAddress
    structs_used: List[str] = field(default_factory=list)  # UNICODE_STRING, etc.

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class CodeQualityMetrics:
    """Code quality metrics"""
    total_lines: int = 0
    code_lines: int = 0
    comment_lines: int = 0
    function_count: int = 0
    average_function_complexity: float = 0.0
    max_function_complexity: int = 0

    def to_dict(self) -> Dict:
        return asdict(self)


class AdvancedTechniqueIndexer(TechniqueIndexer):
    """
    Enhanced technique indexer with deep code analysis.

    Improvements over base indexer:
    - Extracts complete function definitions with parameters and bodies
    - Auto-maps techniques to MITRE ATT&CK framework
    - Categorizes dependencies (system/project/external)
    - Calculates code quality metrics
    - Better pattern matching for techniques
    """

    # MITRE ATT&CK mapping for techniques
    MITRE_MAPPINGS = {
        'api_hashing': ['T1027.007'],  # Obfuscated Files or Information: Dynamic API Resolution
        'syscalls': ['T1106'],  # Native API
        'unhooking': ['T1562.001'],  # Impair Defenses: Disable or Modify Tools
        'injection': ['T1055'],  # Process Injection (generic)
        'encryption': ['T1027'],  # Obfuscated Files or Information
        'steganography': ['T1027.003'],  # Obfuscated Files or Information: Steganography
        'gpu_evasion': ['T1564'],  # Hide Artifacts
        'stack_spoof': ['T1027'],  # Obfuscated Files or Information
        'veh': ['T1562.001'],  # Impair Defenses: Disable or Modify Tools
        'persistence': ['T1547', 'T1053'],  # Boot/Logon Autostart, Scheduled Task/Job
    }

    # Enhanced technique patterns with more comprehensive detection
    ENHANCED_PATTERNS = {
        'api_hashing': [
            r'GetProcAddress[A-Z]',
            r'GetModuleHandle[A-Z]',
            r'DJB2|djb2',
            r'HASH_[A-Z]+',
            r'HashString|CalculateHash',
            r'ProcAddress.*hash',
        ],
        'syscalls': [
            r'syscall|Syscall',
            r'NtAllocate|NtWrite|NtProtect|NtCreate',
            r'HellsHall|HellsGate|HalosGate',
            r'__syscall|SYSCALL',
            r'SW2_',  # SysWhispers2 prefix
        ],
        'unhooking': [
            r'unhook|Unhook',
            r'KnownDlls',
            r'RtlCopyMemory.*MappedDll',
            r'RefreshDll|ReloadDll',
        ],
        'injection': [
            r'inject|Inject',
            r'WriteProcessMemory',
            r'CreateRemoteThread',
            r'QueueUserAPC',
            r'NtMapViewOfSection',
            r'ProcessHollowing',
        ],
        'encryption': [
            r'AES|aes',
            r'XOR|xor',
            r'RC4|rc4',
            r'[Cc]rypt|[Dd]ecrypt',
            r'Cipher|cipher',
        ],
        'steganography': [
            r'steg|Steg',
            r'DWT|dwt',
            r'LSB|lsb',
            r'embed|Embed',
            r'watermark',
        ],
        'gpu_evasion': [
            r'D3D11|DirectX',
            r'GPU|gpu',
            r'ID3D11Device',
            r'CreateDevice',
            r'CopyResource',
        ],
        'stack_spoof': [
            r'stack.*spoof',
            r'CallStackMasker',
            r'SpoofCallStack',
            r'ReturnAddress',
        ],
        'veh': [
            r'VEH|veh',
            r'AddVectoredExceptionHandler',
            r'RemoveVectoredExceptionHandler',
            r'EXCEPTION_CONTINUE',
        ],
        'persistence': [
            r'registry|Registry',
            r'RegSetValue|RegCreateKey',
            r'scheduled.*task|ScheduledTask',
            r'service.*create|CreateService',
            r'Run\s*key|RunOnce',
        ],
    }

    def __init__(self, examples_root: str = "Examples"):
        super().__init__(examples_root)
        # Override with enhanced patterns
        self.technique_patterns = {
            name: '|'.join(patterns)
            for name, patterns in self.ENHANCED_PATTERNS.items()
        }

    def _create_technique_metadata(
        self,
        technique_name: str,
        file_path: Path,
        project_path: Path,
        content: str
    ) -> TechniqueMetadata:
        """Create enhanced metadata object for a technique"""

        # Generate technique ID
        technique_id = f"NOCTIS-T{self.technique_counter:03d}"
        self.technique_counter += 1

        # Extract MITRE ATT&CK (from code + auto-mapping)
        mitre_refs = self._extract_mitre_mappings(content, technique_name)

        # Extract enhanced dependencies
        dependencies_obj = self._extract_enhanced_dependencies(content)

        # Extract OPSEC info
        opsec_info = self._extract_opsec_info(content)

        # Extract function definitions
        functions = self._extract_function_definitions(content)

        # Calculate code quality metrics
        metrics = self._calculate_code_metrics(content, functions)

        # Determine category
        category = self._determine_category(technique_name)

        # Get project author
        author = self._extract_author(project_path)

        # Get description
        description = self._generate_description(technique_name, content)

        # Create enhanced code_blocks with full function info
        code_blocks = {
            "file": str(file_path.name),
            "functions": [
                {
                    "name": func.name,
                    "signature": func.signature(),
                    "line_start": func.line_start,
                    "line_end": func.line_end,
                    "complexity": func.complexity,
                    "calls": func.calls
                }
                for func in functions
            ],
            "total_functions": len(functions),
            "quality_metrics": metrics.to_dict()
        }

        # Enhanced OPSEC with quality data
        opsec_info['code_quality'] = metrics.to_dict()
        opsec_info['dependencies'] = dependencies_obj.to_dict()

        return TechniqueMetadata(
            technique_id=technique_id,
            name=technique_name.replace('_', ' ').title(),
            category=category,
            description=description,
            source_files=[str(file_path.relative_to(self.examples_root))],
            mitre_attack=mitre_refs,
            dependencies=dependencies_obj.system_headers + dependencies_obj.project_headers + dependencies_obj.external_libs,
            compatible_with=[],
            incompatible_with=[],
            opsec=opsec_info,
            code_blocks=code_blocks,
            variants=[],
            author=author,
            source_project=project_path.name,
            last_updated=datetime.now().isoformat()
        )

    def _extract_mitre_mappings(self, content: str, technique_name: str) -> List[str]:
        """
        Extract MITRE ATT&CK references from code AND auto-map technique.

        Combines:
        1. Explicit MITRE references in comments (T1027, etc.)
        2. Auto-mapping based on technique type
        """
        mitre_refs = set()

        # 1. Extract explicit references from comments
        pattern = r'T\d{4}(?:\.\d{3})?'
        matches = re.findall(pattern, content)
        mitre_refs.update(matches)

        # 2. Auto-map based on technique name
        if technique_name in self.MITRE_MAPPINGS:
            mitre_refs.update(self.MITRE_MAPPINGS[technique_name])

        return sorted(list(mitre_refs))

    def _extract_enhanced_dependencies(self, content: str) -> EnhancedDependencies:
        """
        Extract and categorize all dependencies.

        Returns:
            EnhancedDependencies with categorized includes, libs, functions, etc.
        """
        deps = EnhancedDependencies()

        # 1. Extract #include statements and categorize
        include_pattern = r'#include\s+([<"])([^>"]+)[>"]'
        for match in re.finditer(include_pattern, content):
            delimiter = match.group(1)
            header = match.group(2)

            if delimiter == '<':
                # System header
                deps.system_headers.append(header)
            else:
                # Project header
                deps.project_headers.append(header)

        # 2. Extract DLL references
        dll_pattern = r'\b(kernel32|ntdll|user32|advapi32|ws2_32|wininet|urlmon|ole32|shell32|crypt32)\.dll\b'
        for match in re.finditer(dll_pattern, content, re.IGNORECASE):
            dll_name = match.group(1).lower()
            if f"{dll_name}.dll" not in deps.external_libs:
                deps.external_libs.append(f"{dll_name}.dll")

        # 3. Extract Windows API function calls
        api_pattern = r'\b(Nt[A-Z]\w+|Zw[A-Z]\w+|Rtl[A-Z]\w+|Get[A-Z]\w+|Set[A-Z]\w+|Create[A-Z]\w+|Open[A-Z]\w+|Write[A-Z]\w+|Read[A-Z]\w+|Virtual[A-Z]\w+)\s*\('
        for match in re.finditer(api_pattern, content):
            func_name = match.group(1)
            if func_name not in deps.functions_called:
                deps.functions_called.append(func_name)

        # 4. Extract struct definitions
        struct_pattern = r'(?:typedef\s+)?struct\s+(\w+)\s*{'
        for match in re.finditer(struct_pattern, content):
            struct_name = match.group(1)
            if struct_name not in deps.structs_used:
                deps.structs_used.append(struct_name)

        # Also look for struct usage
        struct_usage_pattern = r'\b(UNICODE_STRING|OBJECT_ATTRIBUTES|CLIENT_ID|PEB|TEB|LIST_ENTRY|PROCESS_BASIC_INFORMATION)\b'
        for match in re.finditer(struct_usage_pattern, content):
            struct_name = match.group(1)
            if struct_name not in deps.structs_used:
                deps.structs_used.append(struct_name)

        # Deduplicate and sort
        deps.system_headers = sorted(list(set(deps.system_headers)))
        deps.project_headers = sorted(list(set(deps.project_headers)))
        deps.external_libs = sorted(list(set(deps.external_libs)))
        deps.functions_called = sorted(list(set(deps.functions_called)))
        deps.structs_used = sorted(list(set(deps.structs_used)))

        return deps

    def _extract_function_definitions(self, content: str) -> List[FunctionDefinition]:
        """
        Extract complete function definitions with signatures and bodies.

        Uses regex-based parsing (robust enough for most C code).
        Returns list of FunctionDefinition objects.
        """
        functions = []

        # Pattern for function definition:
        # RETURN_TYPE FunctionName(PARAMS) { ... }
        # This is a simplified pattern - real C parsing is complex

        # Split content into lines for line number tracking
        lines = content.split('\n')

        # Pattern to match function start
        # Matches: BOOL MyFunction(int x, char* y) {
        func_start_pattern = r'^(\w+(?:\s+\w+)*)\s+(\w+)\s*\(([^)]*)\)\s*\{'

        i = 0
        while i < len(lines):
            match = re.match(func_start_pattern, lines[i].strip())
            if match:
                return_type = match.group(1).strip()
                func_name = match.group(2)
                params_str = match.group(3).strip()

                # Parse parameters
                parameters = self._parse_parameters(params_str)

                # Extract function body (find matching closing brace)
                body_start = i
                body_lines = [lines[i]]
                brace_count = 1
                i += 1

                while i < len(lines) and brace_count > 0:
                    line = lines[i]
                    body_lines.append(line)

                    # Count braces (simplified - doesn't handle strings/comments perfectly)
                    brace_count += line.count('{') - line.count('}')
                    i += 1

                body = '\n'.join(body_lines)

                # Calculate complexity (count decision points)
                complexity = self._calculate_cyclomatic_complexity(body)

                # Extract function calls
                calls = self._extract_function_calls(body)

                functions.append(FunctionDefinition(
                    name=func_name,
                    return_type=return_type,
                    parameters=parameters,
                    body=body,
                    line_start=body_start + 1,  # 1-indexed
                    line_end=i,
                    complexity=complexity,
                    calls=calls
                ))
            else:
                i += 1

        return functions

    def _parse_parameters(self, params_str: str) -> List[Tuple[str, str]]:
        """Parse function parameters from parameter string"""
        if not params_str or params_str == 'void':
            return []

        parameters = []
        for param in params_str.split(','):
            param = param.strip()
            if not param:
                continue

            # Split into type and name
            # Handle cases like: "int x", "char* name", "DWORD dwFlags"
            parts = param.rsplit(None, 1)
            if len(parts) == 2:
                ptype, pname = parts
                # Handle pointer stars
                pname = pname.lstrip('*')
                if '*' in param:
                    ptype += '*' * param.count('*')
                parameters.append((ptype, pname))
            elif len(parts) == 1:
                # Just type, no name (e.g., function pointer)
                parameters.append((parts[0], ''))

        return parameters

    def _calculate_cyclomatic_complexity(self, body: str) -> int:
        """
        Calculate cyclomatic complexity (decision points).

        Counts: if, else, while, for, case, && , ||, ?
        Returns: complexity estimate
        """
        complexity = 1  # Base complexity

        # Count control flow keywords
        keywords = ['if', 'else', 'while', 'for', 'case', 'default']
        for keyword in keywords:
            complexity += len(re.findall(r'\b' + keyword + r'\b', body))

        # Count logical operators
        complexity += body.count('&&')
        complexity += body.count('||')
        complexity += body.count('?')  # Ternary operator

        return complexity

    def _extract_function_calls(self, body: str) -> List[str]:
        """Extract function calls from function body"""
        calls = set()

        # Pattern to match function calls: FunctionName(...)
        pattern = r'\b([A-Z][a-zA-Z0-9_]*)\s*\('
        for match in re.finditer(pattern, body):
            calls.add(match.group(1))

        return sorted(list(calls))

    def _calculate_code_metrics(self, content: str, functions: List[FunctionDefinition]) -> CodeQualityMetrics:
        """Calculate code quality metrics"""
        lines = content.split('\n')

        metrics = CodeQualityMetrics()
        metrics.total_lines = len(lines)
        metrics.function_count = len(functions)

        # Count code vs comment lines
        code_lines = 0
        comment_lines = 0
        in_block_comment = False

        for line in lines:
            stripped = line.strip()

            # Block comments
            if '/*' in stripped:
                in_block_comment = True
            if '*/' in stripped:
                in_block_comment = False
                comment_lines += 1
                continue

            if in_block_comment:
                comment_lines += 1
            elif stripped.startswith('//'):
                comment_lines += 1
            elif stripped:
                code_lines += 1

        metrics.code_lines = code_lines
        metrics.comment_lines = comment_lines

        # Function complexity stats
        if functions:
            complexities = [f.complexity for f in functions]
            if complexities:  # Check if complexities list is not empty
                metrics.average_function_complexity = sum(complexities) / len(complexities)
                metrics.max_function_complexity = max(complexities)

        return metrics


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Advanced Noctis-MCP Technique Indexer - Enhanced code analysis'
    )
    parser.add_argument(
        '--examples',
        default='Examples',
        help='Path to Examples directory (default: Examples)'
    )
    parser.add_argument(
        '--output',
        default='techniques/metadata',
        help='Output directory for metadata (default: techniques/metadata)'
    )
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Verbose output'
    )

    args = parser.parse_args()

    print("""
====================================================================
         ADVANCED NOCTIS-MCP TECHNIQUE INDEXER
      Enhanced Code Analysis & MITRE Mapping v2.0
====================================================================
    """)

    # Create advanced indexer and scan
    indexer = AdvancedTechniqueIndexer(examples_root=args.examples)
    techniques = indexer.scan_all()

    if techniques:
        # Save metadata
        indexer.save_metadata(output_dir=args.output)

        # Print summary
        indexer.print_summary()

        # Print enhancement stats
        print("\n" + "=" * 70)
        print("ENHANCEMENT STATISTICS")
        print("=" * 70)

        total_functions = sum(len(t.code_blocks.get('functions', [])) for t in techniques)
        total_deps = sum(len(t.dependencies) for t in techniques)
        total_mitre = sum(len(t.mitre_attack) for t in techniques)

        print(f"  Total Functions Extracted: {total_functions}")
        print(f"  Total Dependencies Cataloged: {total_deps}")
        print(f"  Total MITRE ATT&CK Mappings: {total_mitre}")
        print("=" * 70)
    else:
        print("[!] No techniques found!")
        return 1

    print("\n[+] Advanced indexing complete!")
    return 0


if __name__ == '__main__':
    exit(main())
