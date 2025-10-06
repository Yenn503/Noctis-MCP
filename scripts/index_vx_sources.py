#!/usr/bin/env python3
"""
VX-Underground Source Indexer for Noctis-MCP
=============================================

Indexes VX-API production code into RAG with semantic understanding.
Let

s RAG's semantic search naturally find the right code.

Usage:
    python scripts/index_vx_sources.py
"""

import sys
import re
import logging
from pathlib import Path

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from server.rag import RAGEngine

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class VXAPIIndexer:
    """Indexes VX-API code into RAG with natural semantic understanding"""

    def __init__(self, vx_api_path: str = "external/VX-API/VX-API"):
        self.vx_api_path = Path(vx_api_path)
        self.rag = RAGEngine()
        self.indexed_count = 0
        self.failed_count = 0
        self.failed_files = []  # Track which files failed

    def extract_semantic_info(self, cpp_code: str, filename: str) -> dict:
        """
        Extract function and understand what it does semantically
        No complex mappings - just extract meaningful info
        """
        # Get function name from filename (VX-API convention)
        function_name = filename.replace('.cpp', '')

        # Extract any comments that explain the function
        comments = []
        comment_patterns = [
            r'/\*(.*?)\*/',  # Multi-line comments
            r'//(.*?)$'       # Single line comments
        ]
        for pattern in comment_patterns:
            matches = re.findall(pattern, cpp_code, re.DOTALL | re.MULTILINE)
            comments.extend([c.strip() for c in matches if len(c.strip()) > 10])

        # Extract the main function - try multiple patterns
        function_match = None

        # Pattern 1: Exact filename match (most common)
        # Include optional __stdcall, __cdecl, __fastcall calling conventions
        # Use DOTALL to handle multiline function signatures (common in VX-API)
        # Match: RETURN_TYPE FunctionName( ... parameters ... ) {
        # Also try with W/A suffix for wide/ansi variants
        function_match = re.search(
            rf'(\w+)\s+(?:__stdcall\s+|__cdecl\s+|__fastcall\s+)?{re.escape(function_name)}[WA]?\s*\((.*?)\)\s*\{{',
            cpp_code,
            re.MULTILINE | re.DOTALL
        )

        # Pattern 2: Multiple functions in file or VOID return types (use first valid one)
        if not function_match:
            # Find any function that looks like it belongs here
            # Extended pattern to catch all Windows types including LONG, ULONG, LONGLONG
            all_functions = list(re.finditer(
                r'(BOOL|DWORD|DWORD64|VOID|NTSTATUS|HANDLE|PVOID|LPVOID|SIZE_T|PBYTE|PCHAR|INT|UINT|INT32|UINT32|UINT64|HMODULE|FARPROC|HRESULT|LONG|ULONG|LONGLONG)\s+(?:__stdcall\s+|__cdecl\s+|__fastcall\s+)?([_A-Z]\w+)\s*\([^\{]*\)\s*\{',
                cpp_code,
                re.MULTILINE
            ))
            if all_functions:
                function_match = all_functions[0]
                # Update function_name to match what we actually found
                function_name = function_match.group(2)

        if not function_match:
            return None

        return_type = function_match.group(1)
        func_start = function_match.start()

        # Find function body
        brace_count = 0
        func_end = func_start
        in_function = False

        for i in range(func_start, len(cpp_code)):
            if cpp_code[i] == '{':
                brace_count += 1
                in_function = True
            elif cpp_code[i] == '}':
                brace_count -= 1
                if in_function and brace_count == 0:
                    func_end = i + 1
                    break

        if func_end == func_start:
            return None

        function_code = cpp_code[func_start:func_end]

        # Extract signature
        sig_match = re.search(r'([^\{]+)\{', function_code)
        signature = sig_match.group(1).strip() if sig_match else f"{return_type} {function_name}(...)"

        # Extract includes
        includes = re.findall(r'#include\s+[<"]([^>"]+)[>"]', cpp_code)

        # Auto-detect what this function does from its name
        purpose = self.infer_purpose_from_name(function_name)

        return {
            'function_name': function_name,
            'function_code': function_code,
            'signature': signature,
            'return_type': return_type,
            'includes': includes,
            'comments': comments[:3],  # Top 3 comments
            'purpose': purpose,
            'full_source': cpp_code
        }

    def infer_purpose_from_name(self, name: str) -> dict:
        """
        Infer what the function does from its name
        Returns natural language description + keywords for RAG search
        """
        name_lower = name.lower()

        # Defense Evasion
        if 'amsi' in name_lower and 'bypass' in name_lower:
            return {
                'category': 'defense_evasion',
                'description': 'Bypasses AMSI (Antimalware Scan Interface) to evade detection',
                'keywords': ['AMSI bypass', 'defense evasion', 'antivirus bypass', 'Windows Defender']
            }
        elif 'etw' in name_lower and 'bypass' in name_lower:
            return {
                'category': 'defense_evasion',
                'description': 'Bypasses ETW (Event Tracing for Windows) to avoid behavioral detection',
                'keywords': ['ETW bypass', 'event tracing', 'telemetry evasion', 'logging bypass']
            }
        elif 'uac' in name_lower and 'bypass' in name_lower:
            return {
                'category': 'privilege_escalation',
                'description': 'Bypasses UAC (User Account Control) for privilege escalation',
                'keywords': ['UAC bypass', 'privilege escalation', 'admin rights', 'elevation']
            }
        elif 'unhook' in name_lower or ('hook' in name_lower and 'engine' in name_lower):
            return {
                'category': 'defense_evasion',
                'description': 'Unhooks or manipulates API hooks to evade EDR/AV monitoring',
                'keywords': ['unhooking', 'API hooks', 'EDR bypass', 'function hooking']
            }

        # Process Injection
        elif 'inject' in name_lower:
            return {
                'category': 'execution',
                'description': 'Injects code or shellcode into remote process for execution',
                'keywords': ['process injection', 'code injection', 'shellcode execution', 'remote thread']
            }
        elif 'reflection' in name_lower and 'process' in name_lower:
            return {
                'category': 'execution',
                'description': 'Process reflection technique for stealthy code execution',
                'keywords': ['process reflection', 'process doppelganging', 'injection', 'evasion']
            }

        # Process Creation
        elif 'createprocess' in name_lower:
            method = 'alternative' if any(x in name_lower for x in ['hotkey', 'inf', 'wmi', 'com']) else 'standard'
            return {
                'category': 'execution',
                'description': f'Creates new process using {method} Windows API methods',
                'keywords': ['process creation', 'CreateProcess', 'execution', 'spawn process']
            }

        # API Resolution
        elif 'getprocaddress' in name_lower or 'apihas' in name_lower:
            return {
                'category': 'defense_evasion',
                'description': 'Dynamically resolves API addresses to evade static analysis',
                'keywords': ['API hashing', 'dynamic resolution', 'GetProcAddress', 'obfuscation']
            }

        # Cryptography
        elif any(x in name_lower for x in ['md5', 'sha', 'hash', 'aes', 'encrypt', 'decrypt']):
            return {
                'category': 'cryptography',
                'description': 'Cryptographic operations for encryption, hashing, or obfuscation',
                'keywords': ['encryption', 'hashing', 'crypto', 'obfuscation', 'AES', 'MD5']
            }

        # String/Memory utilities
        elif any(x in name_lower for x in ['string', 'convert', 'copy', 'memory']):
            return {
                'category': 'utility',
                'description': 'Utility function for string or memory manipulation',
                'keywords': ['utility', 'string operations', 'memory operations', 'helper function']
            }

        # Default - generic utility
        else:
            return {
                'category': 'utility',
                'description': f'Windows API utility function: {name}',
                'keywords': ['utility', 'Windows API', 'helper']
            }

    def create_natural_document(self, func_info: dict, filename: str) -> str:
        """
        Create a natural language document that RAG can semantically understand
        No rigid structure - just clear, searchable content
        """
        purpose = func_info['purpose']

        # Build document with natural language
        doc_parts = [
            f"# {func_info['function_name']}",
            f"\n{purpose['description']}",
            f"\nCategory: {purpose['category'].replace('_', ' ').title()}",
            f"\nKeywords: {', '.join(purpose['keywords'])}",
            f"\nFunction Signature: {func_info['signature']}",
            f"\nSource: VX-API Production Code (VX-Underground)",
            f"\nFile: {filename}",
        ]

        # Add comments if available
        if func_info['comments']:
            doc_parts.append("\n\n## Developer Notes:")
            for comment in func_info['comments']:
                doc_parts.append(f"- {comment[:200]}")

        # Add includes
        if func_info['includes']:
            doc_parts.append("\n\n## Dependencies:")
            for inc in func_info['includes']:
                doc_parts.append(f"#include <{inc}>")

        # Add the actual code
        doc_parts.append("\n\n## Implementation Code:\n")
        doc_parts.append("```cpp")
        doc_parts.append(func_info['function_code'])
        doc_parts.append("```")

        doc_parts.append("\n\nThis is production-grade malware development code from VX-Underground.")
        doc_parts.append("Compatible with Windows C/C++ malware projects.")
        doc_parts.append(f"Can be used for: {', '.join(purpose['keywords'])}")

        return "\n".join(doc_parts)

    def index_vx_api(self):
        """Index all VX-API C++ files into RAG with semantic understanding"""
        if not self.vx_api_path.exists():
            logger.error(f"VX-API path not found: {self.vx_api_path}")
            logger.error("Run: git clone https://github.com/vxunderground/VX-API.git external/VX-API")
            return False

        logger.info(f"Starting VX-API indexing from {self.vx_api_path}")
        logger.info("Using semantic understanding - no rigid mappings needed")
        logger.info("="*70)

        cpp_files = list(self.vx_api_path.glob("*.cpp"))
        logger.info(f"Found {len(cpp_files)} C++ files to index")

        for cpp_file in cpp_files:
            try:
                # Read file
                code = cpp_file.read_text(encoding='utf-8', errors='ignore')
                filename = cpp_file.name

                # Extract semantic info
                func_info = self.extract_semantic_info(code, filename)
                if not func_info:
                    logger.warning(f"  ⚠️  Could not extract function from {filename}")
                    self.failed_count += 1
                    self.failed_files.append(filename)
                    continue

                # Create natural language document
                document = self.create_natural_document(func_info, filename)

                # Index into RAG - let semantic search do its magic
                doc_id = f"vxapi_{filename.replace('.cpp', '')}"

                self.rag.knowledge.add(
                    ids=[doc_id],
                    documents=[document],
                    metadatas=[{
                        "source": "VX-API",
                        "type": "production_code",
                        "category": func_info['purpose']['category'],
                        "function_name": func_info['function_name'],
                        "filename": filename,
                        "language": "C++",
                        "extractable": "true",
                        "keywords": ','.join(func_info['purpose']['keywords'])
                    }]
                )

                self.indexed_count += 1
                if self.indexed_count % 25 == 0:
                    logger.info(f"  Indexed {self.indexed_count} functions...")

            except Exception as e:
                logger.error(f"  ❌ Failed to index {cpp_file.name}: {e}")
                self.failed_count += 1
                self.failed_files.append(cpp_file.name)

        logger.info("="*70)
        logger.info(f"✅ VX-API indexing complete!")
        logger.info(f"  Successfully indexed: {self.indexed_count} functions")
        logger.info(f"  Failed: {self.failed_count} files")

        if self.failed_files:
            logger.info(f"\n  Failed files:")
            for fname in self.failed_files:
                logger.info(f"    - {fname}")

        logger.info(f"\n  RAG can now semantically find the right code for any query!")
        logger.info(f"  Just ask naturally: 'AMSI bypass', 'process injection', etc.")

        return True


def main():
    """Main indexing workflow"""
    print("="*70)
    print("  Noctis-MCP: VX-API Indexer")
    print("  Semantic indexing of production malware code")
    print("="*70)
    print()

    indexer = VXAPIIndexer()

    if not indexer.rag.enabled:
        logger.error("RAG engine not enabled. Check ChromaDB installation.")
        return 1

    success = indexer.index_vx_api()

    if success:
        print()
        print("="*70)
        print("🎉 Success! VX-API code is now semantically searchable")
        print()
        print("Try asking naturally:")
        print("  💬 'How do I bypass AMSI?'")
        print("  💬 'Show me process injection code'")
        print("  💬 'I need UAC bypass techniques'")
        print("  💬 'Give me API hashing implementation'")
        print()
        print("RAG will find the right VX-API code automatically!")
        print("="*70)
        return 0
    else:
        return 1


if __name__ == '__main__':
    sys.exit(main())
