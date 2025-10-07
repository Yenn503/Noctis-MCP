"""
Pattern Extractor - Extracts reusable patterns from Examples/ code

Instead of copying code directly, this extracts:
- Implementation approaches (HOW things are done)
- Function call sequences (WHAT order operations happen)
- Memory management patterns (HOW memory is allocated/protected)
- Error handling patterns (HOW errors are caught)
- Key code snippets (small, reusable pieces)

AI uses these patterns as reference when writing new code.
"""

import re
from pathlib import Path
from typing import Dict, List, Optional
import logging

logger = logging.getLogger(__name__)


class PatternExtractor:
    """Extracts implementation patterns from source code"""

    def __init__(self, examples_root: str = "Examples"):
        self.examples_root = Path(examples_root)

    def extract_patterns_for_technique(self, technique_id: str, source_files: List[str]) -> Dict:
        """
        Extract patterns from source files for a technique

        Args:
            technique_id: Technique identifier
            source_files: List of source file paths from metadata

        Returns:
            Dict containing extracted patterns
        """
        patterns = {
            'technique_id': technique_id,
            'implementation_approach': [],
            'function_sequences': [],
            'memory_patterns': [],
            'api_usage_patterns': [],
            'error_handling': [],
            'key_snippets': []
        }

        for source_file in source_files:
            # Normalize path
            file_path = self.examples_root / source_file.replace('\\', '/')

            if not file_path.exists():
                logger.warning(f"Source file not found: {file_path}")
                continue

            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()

                # Extract different pattern types
                self._extract_implementation_approach(content, patterns)
                self._extract_function_sequences(content, patterns)
                self._extract_memory_patterns(content, patterns)
                self._extract_api_patterns(content, patterns)
                self._extract_error_handling(content, patterns)
                self._extract_key_snippets(content, patterns)

            except Exception as e:
                logger.error(f"Error extracting patterns from {file_path}: {e}")

        # Deduplicate and limit
        patterns['implementation_approach'] = list(set(patterns['implementation_approach']))[:5]
        patterns['function_sequences'] = patterns['function_sequences'][:5]
        patterns['memory_patterns'] = list(set(patterns['memory_patterns']))[:5]
        patterns['api_usage_patterns'] = patterns['api_usage_patterns'][:10]
        patterns['error_handling'] = list(set(patterns['error_handling']))[:3]
        patterns['key_snippets'] = patterns['key_snippets'][:5]

        return patterns

    def _extract_implementation_approach(self, content: str, patterns: Dict):
        """Extract high-level implementation approach from comments"""
        # Look for block comments explaining approach
        comment_blocks = re.findall(r'/\*\*?(.*?)\*/', content, re.DOTALL)

        for block in comment_blocks:
            clean = ' '.join(line.strip().lstrip('*').strip() for line in block.split('\n'))
            clean = clean.strip()

            # Must be substantial and explain approach
            if 50 < len(clean) < 300 and any(word in clean.lower() for word in
                                             ['approach', 'method', 'technique', 'how', 'implements']):
                patterns['implementation_approach'].append(clean)

        # Look for inline comments that describe steps
        step_comments = re.findall(r'//\s*Step\s*\d+:(.+)', content, re.IGNORECASE)
        if len(step_comments) >= 3:
            approach = "Steps: " + " → ".join(s.strip()[:50] for s in step_comments[:5])
            patterns['implementation_approach'].append(approach)

    def _extract_function_sequences(self, content: str, patterns: Dict):
        """Extract sequences of API calls (the ORDER matters)"""
        # Common malware API call sequences
        api_calls = re.findall(r'\b((?:Nt|Zw)\w+|VirtualAlloc\w*|CreateThread\w*|WriteProcessMemory|'
                              r'LoadLibrary\w*|GetProcAddress|OpenProcess|CreateRemoteThread|'
                              r'VirtualProtect\w*|WinHttp\w+)\s*\(', content)

        if len(api_calls) >= 3:
            # Group into sequence
            sequence = ' → '.join(api_calls[:8])
            patterns['function_sequences'].append({
                'sequence': sequence,
                'description': f"API call order for {api_calls[0]}-based implementation"
            })

    def _extract_memory_patterns(self, content: str, patterns: Dict):
        """Extract memory allocation/protection patterns"""
        # Pattern 1: Allocate RW, then change to RX
        if re.search(r'VirtualAlloc.*PAGE_READWRITE', content, re.IGNORECASE):
            if re.search(r'VirtualProtect.*PAGE_EXECUTE_READ', content, re.IGNORECASE):
                patterns['memory_patterns'].append(
                    "Allocate as RW (PAGE_READWRITE), write payload, change to RX (PAGE_EXECUTE_READ) - OPSEC safe"
                )

        # Pattern 2: Direct RWX allocation (bad OPSEC)
        if re.search(r'VirtualAlloc.*PAGE_EXECUTE_READWRITE', content, re.IGNORECASE):
            patterns['memory_patterns'].append(
                "⚠ Direct RWX allocation (PAGE_EXECUTE_READWRITE) - easily detected, use RW→RX instead"
            )

        # Pattern 3: NtAllocateVirtualMemory usage
        if 'NtAllocateVirtualMemory' in content:
            patterns['memory_patterns'].append(
                "Uses NtAllocateVirtualMemory (direct syscall) instead of VirtualAllocEx"
            )

        # Pattern 4: Memory cleanup
        if re.search(r'VirtualFree|NtFreeVirtualMemory', content):
            patterns['memory_patterns'].append(
                "Includes memory cleanup (VirtualFree/NtFreeVirtualMemory)"
            )

    def _extract_api_patterns(self, content: str, patterns: Dict):
        """Extract API resolution/obfuscation patterns"""
        # Pattern 1: GetProcAddress usage
        getproc_calls = re.findall(r'GetProcAddress\s*\([^,]+,\s*["\'](\w+)["\']', content)
        if getproc_calls:
            patterns['api_usage_patterns'].append({
                'pattern': 'Dynamic API Resolution',
                'apis_resolved': getproc_calls[:5],
                'description': 'Resolves APIs at runtime using GetProcAddress'
            })

        # Pattern 2: API hashing
        if re.search(r'(hash|djb2|fnv|crc)', content, re.IGNORECASE):
            patterns['api_usage_patterns'].append({
                'pattern': 'API Hashing',
                'description': 'Uses API hashing to avoid import table'
            })

        # Pattern 3: Syscall usage
        syscall_functions = re.findall(r'\b(Nt\w+|Zw\w+)\s*\(', content)
        if len(syscall_functions) >= 3:
            unique_syscalls = list(set(syscall_functions))[:5]
            patterns['api_usage_patterns'].append({
                'pattern': 'Direct Syscalls',
                'syscalls_used': unique_syscalls,
                'description': 'Bypasses user-mode hooks via direct syscalls'
            })

    def _extract_error_handling(self, content: str, patterns: Dict):
        """Extract error handling patterns"""
        # Pattern 1: Check return values
        if re.search(r'if\s*\([^)]*==\s*NULL\)', content):
            patterns['error_handling'].append("Checks for NULL returns")

        if re.search(r'if\s*\(!\s*NT_SUCCESS', content):
            patterns['error_handling'].append("Validates NTSTATUS with NT_SUCCESS macro")

        if re.search(r'GetLastError\(\)', content):
            patterns['error_handling'].append("Uses GetLastError() for error diagnostics")

        # Pattern 2: Cleanup on failure
        if re.search(r'(goto\s+cleanup|goto\s+error|CloseHandle.*return)', content, re.IGNORECASE):
            patterns['error_handling'].append("Implements cleanup on error (resource management)")

    def _extract_key_snippets(self, content: str, patterns: Dict):
        """Extract small, reusable code snippets"""
        # Snippet 1: Syscall stub structure (if found)
        syscall_stub = re.search(
            r'(typedef\s+NTSTATUS.*?\n.*?;.*?\n.*?NTSTATUS.*?\{.*?\})',
            content, re.DOTALL
        )
        if syscall_stub and len(syscall_stub.group(1)) < 500:
            patterns['key_snippets'].append({
                'name': 'Syscall Stub Structure',
                'code': syscall_stub.group(1)[:400]
            })

        # Snippet 2: Function pointer typedef (common pattern)
        typedef_match = re.search(r'typedef\s+\w+\s*\(\s*\*\s*(\w+)\s*\)\s*\([^)]+\);', content)
        if typedef_match:
            # Find full typedef
            typedef_lines = []
            for line in content.split('\n'):
                if 'typedef' in line and typedef_match.group(1) in line:
                    typedef_lines.append(line.strip())
                    if ';' in line:
                        break
            if typedef_lines:
                patterns['key_snippets'].append({
                    'name': f'Function Pointer: {typedef_match.group(1)}',
                    'code': ' '.join(typedef_lines)
                })

        # Snippet 3: Initialization pattern (if compact)
        init_func = re.search(
            r'(BOOL|NTSTATUS)\s+Init\w+\s*\([^)]*\)\s*\{([^\}]{0,400})\}',
            content, re.DOTALL
        )
        if init_func:
            patterns['key_snippets'].append({
                'name': 'Initialization Pattern',
                'code': init_func.group(0)[:400]
            })

    def get_function_list(self, source_files: List[str]) -> List[Dict]:
        """
        Get list of functions defined in source files

        Returns:
            List of {name, signature, file} for each function
        """
        functions = []

        for source_file in source_files:
            file_path = self.examples_root / source_file.replace('\\', '/')

            if not file_path.exists():
                continue

            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()

                # Find function definitions
                func_matches = re.finditer(
                    r'^\s*(BOOL|NTSTATUS|DWORD|HANDLE|LPVOID|void|int)\s+(\w+)\s*\(([^\)]*)\)',
                    content, re.MULTILINE
                )

                for match in func_matches:
                    return_type, func_name, params = match.groups()

                    # Skip if it's just a declaration (followed by ;)
                    rest_of_line = content[match.end():match.end()+10]
                    if ';' in rest_of_line.split('\n')[0]:
                        continue

                    functions.append({
                        'name': func_name,
                        'return_type': return_type,
                        'parameters': params.strip() if params else 'void',
                        'file': file_path.name
                    })

            except Exception as e:
                logger.error(f"Error reading {file_path}: {e}")

        return functions
