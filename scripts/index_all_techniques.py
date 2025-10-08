#!/usr/bin/env python3
"""
Comprehensive Technique Indexer for Noctis-MCP
==============================================

Indexes ALL technique implementations into RAG so the AI can find them.

This script indexes:
- techniques/injection/*.c (PoolParty, Phantom DLL, Early Cascade)
- techniques/syscalls/*.c (SysWhispers3)
- techniques/amsi/*.c (VEH² bypass)
- techniques/unhooking/*.c (Perun's Fart)
- techniques/sleep_obfuscation/*.c (Zilean, ShellcodeFluctuation)
- techniques/crypto/*.c (Encryption implementations)
- techniques/evasion/*.c (Evasion techniques)

Usage:
    python scripts/index_all_techniques.py
"""

import sys
import re
import logging
from pathlib import Path
from typing import Dict, List, Optional

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from server.rag import RAGEngine

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class TechniqueIndexer:
    """Indexes all technique implementations into RAG"""

    def __init__(self, techniques_root: str = "techniques"):
        self.techniques_root = Path(techniques_root)
        self.rag = RAGEngine()
        self.indexed_count = 0
        self.failed_count = 0
        self.technique_folders = [
            'injection',
            'syscalls',
            'amsi',
            'unhooking',
            'sleep_obfuscation',
            'crypto',
            'evasion'
        ]

    def extract_technique_info(self, file_path: Path) -> Optional[Dict]:
        """Extract information from technique implementation file"""
        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')

            # Get technique category from folder
            category = file_path.parent.name
            technique_name = file_path.stem  # filename without extension

            # Extract documentation comments (first block comment)
            doc_comment = ""
            doc_match = re.search(r'/\*\*(.*?)\*/', content, re.DOTALL)
            if doc_match:
                doc_comment = doc_match.group(1).strip()
            elif re.search(r'/\*(.*?)\*/', content, re.DOTALL):
                doc_match = re.search(r'/\*(.*?)\*/', content, re.DOTALL)
                doc_comment = doc_match.group(1).strip()

            # Extract single-line comments at top of file
            top_comments = []
            for line in content.split('\n')[:20]:
                if line.strip().startswith('//'):
                    top_comments.append(line.strip()[2:].strip())
                elif line.strip() and not line.strip().startswith('#'):
                    break

            if not doc_comment and top_comments:
                doc_comment = '\n'.join(top_comments)

            # Extract function signatures
            functions = []
            # Match: RETURNTYPE FunctionName(params) {
            func_pattern = r'(\w+[\s\*]+)(\w+)\s*\([^)]*\)\s*\{'
            for match in re.finditer(func_pattern, content):
                return_type = match.group(1).strip()
                func_name = match.group(2)

                # Skip common keywords
                if func_name.lower() in ['if', 'while', 'for', 'switch']:
                    continue

                functions.append(func_name)

            # Extract includes
            includes = re.findall(r'#include\s+[<"]([^>"]+)[>"]', content)

            # Detect technique purpose from name
            purpose = self.detect_purpose(technique_name, category, content)

            return {
                'filename': file_path.name,
                'technique_name': technique_name,
                'category': category,
                'purpose': purpose,
                'documentation': doc_comment[:500] if doc_comment else '',
                'functions': functions[:10],  # Top 10 functions
                'includes': includes,
                'file_content': content,
                'file_path': str(file_path.relative_to(self.techniques_root.parent))
            }

        except Exception as e:
            logger.error(f"Error extracting info from {file_path}: {e}")
            return None

    def detect_purpose(self, technique_name: str, category: str, content: str) -> Dict:
        """Detect what the technique does from name, category, and content"""
        name_lower = technique_name.lower()

        # Category-based detection
        category_purposes = {
            'injection': {
                'description': 'Process injection technique for code execution in remote process',
                'keywords': ['process injection', 'code injection', 'remote execution', 'shellcode'],
                'mitre': ['T1055']
            },
            'syscalls': {
                'description': 'Direct syscall execution to bypass userland hooks',
                'keywords': ['syscalls', 'EDR bypass', 'API hooks', 'NTDLL'],
                'mitre': ['T1106', 'T1055']
            },
            'amsi': {
                'description': 'AMSI bypass technique to evade antimalware scanning',
                'keywords': ['AMSI bypass', 'antimalware', 'Windows Defender', 'memory patching'],
                'mitre': ['T1562.001']
            },
            'unhooking': {
                'description': 'Removes or bypasses API hooks placed by EDR/AV',
                'keywords': ['unhooking', 'EDR bypass', 'API hooks', 'NTDLL'],
                'mitre': ['T1562.001']
            },
            'sleep_obfuscation': {
                'description': 'Obfuscates beacon/implant during sleep to evade memory scans',
                'keywords': ['sleep obfuscation', 'memory hiding', 'beacon stealth', 'EDR evasion'],
                'mitre': ['T1027', 'T1055']
            },
            'crypto': {
                'description': 'Cryptographic operations for payload encryption/obfuscation',
                'keywords': ['encryption', 'AES', 'XOR', 'obfuscation', 'payload protection'],
                'mitre': ['T1027']
            },
            'evasion': {
                'description': 'General evasion technique to bypass detection',
                'keywords': ['evasion', 'defense evasion', 'anti-analysis', 'EDR bypass'],
                'mitre': ['T1562']
            }
        }

        base_purpose = category_purposes.get(category, {
            'description': f'{category.title()} technique',
            'keywords': [category],
            'mitre': []
        })

        # Specific technique detection
        if 'poolparty' in name_lower:
            return {
                'description': 'PoolParty: Thread pool-based injection (100% EDR bypass documented)',
                'keywords': ['PoolParty', 'thread pool', 'injection', '100% EDR bypass', 'TP_WAIT', 'worker factory'],
                'mitre': ['T1055'],
                'opsec_score': 9.5,
                'detection_risk': '0-5%',
                'edr_bypass': ['CrowdStrike', 'SentinelOne', 'Palo Alto Cortex XDR']
            }
        elif 'syswhispers3' in name_lower or 'sys_whispers' in name_lower:
            return {
                'description': 'SysWhispers3: Randomized syscall invocation (15-20% detection vs 20-25% Hell\'s Gate)',
                'keywords': ['SysWhispers3', 'syscalls', 'randomization', 'EDR bypass', 'indirect syscalls'],
                'mitre': ['T1106'],
                'opsec_score': 8.5,
                'detection_risk': '15-20%',
                'improvement_over': 'Hell\'s Gate (20-25% detection)'
            }
        elif 'veh' in name_lower and 'bypass' in name_lower:
            return {
                'description': 'VEH²: Hardware breakpoint AMSI bypass (Windows 11 24H2 compatible)',
                'keywords': ['VEH', 'hardware breakpoint', 'AMSI bypass', 'Windows 11 24H2', 'zero memory patching'],
                'mitre': ['T1562.001'],
                'opsec_score': 9.0,
                'detection_risk': '5-10%',
                'compatible': 'Windows 11 24H2'
            }
        elif 'zilean' in name_lower:
            return {
                'description': 'Zilean: Thread pool wait-based sleep obfuscation (5-10% vs 30-35% ROP chains)',
                'keywords': ['Zilean', 'sleep obfuscation', 'thread pool', 'memory hiding', 'no ROP artifacts'],
                'mitre': ['T1027'],
                'opsec_score': 9.0,
                'detection_risk': '5-10%',
                'improvement_over': 'Ekko/ROP chains (30-35% detection)'
            }
        elif 'phantom' in name_lower and 'dll' in name_lower:
            return {
                'description': 'Phantom DLL Hollowing: Transactional NTFS for backed memory without disk file',
                'keywords': ['Phantom DLL', 'hollowing', 'TxF', 'transactional NTFS', 'diskless'],
                'mitre': ['T1055.012'],
                'opsec_score': 8.5,
                'detection_risk': '10-15%'
            }
        elif 'early' in name_lower and 'cascade' in name_lower:
            return {
                'description': 'Early Cascade: Pre-EDR timing attack, injects before EDR hooks load',
                'keywords': ['Early Cascade', 'timing attack', 'pre-EDR', 'hook bypass', 'early injection'],
                'mitre': ['T1055'],
                'opsec_score': 8.0,
                'detection_risk': '15-20%'
            }
        elif 'perun' in name_lower or 'fart' in name_lower:
            return {
                'description': 'Perun\'s Fart: Memory-based NTDLL unhooking (reads from process memory, not disk)',
                'keywords': ['Perun\'s Fart', 'unhooking', 'memory-based', 'NTDLL', 'no disk read'],
                'mitre': ['T1562.001'],
                'opsec_score': 8.5,
                'detection_risk': '10-15%'
            }
        elif 'shellcode' in name_lower and 'fluctuation' in name_lower:
            return {
                'description': 'ShellcodeFluctuation: PAGE_NOACCESS memory hiding during sleep',
                'keywords': ['ShellcodeFluctuation', 'memory protection', 'PAGE_NOACCESS', 'sleep hiding'],
                'mitre': ['T1027'],
                'opsec_score': 8.5,
                'detection_risk': '10-15%'
            }
        else:
            return base_purpose

    def create_rag_document(self, technique_info: Dict) -> str:
        """Create natural language document for RAG indexing"""
        purpose = technique_info['purpose']

        doc_parts = [
            f"# {technique_info['technique_name']} ({technique_info['category'].title()})",
            f"\n**File:** {technique_info['file_path']}",
            f"\n**Category:** {technique_info['category'].replace('_', ' ').title()}",
            f"\n## Description",
            f"\n{purpose.get('description', 'No description available')}",
        ]

        # OPSEC information
        if 'opsec_score' in purpose:
            doc_parts.append(f"\n## OPSEC Profile")
            doc_parts.append(f"\n- **OPSEC Score:** {purpose['opsec_score']}/10")
            doc_parts.append(f"- **Detection Risk:** {purpose.get('detection_risk', 'Unknown')}")
            if 'edr_bypass' in purpose:
                doc_parts.append(f"- **EDR Bypass:** {', '.join(purpose['edr_bypass'])}")
            if 'improvement_over' in purpose:
                doc_parts.append(f"- **Improvement Over:** {purpose['improvement_over']}")
            if 'compatible' in purpose:
                doc_parts.append(f"- **Compatible:** {purpose['compatible']}")

        # Keywords
        keywords = purpose.get('keywords', [])
        if keywords:
            doc_parts.append(f"\n## Keywords")
            doc_parts.append(f"\n{', '.join(keywords)}")

        # MITRE ATT&CK
        mitre = purpose.get('mitre', [])
        if mitre:
            doc_parts.append(f"\n## MITRE ATT&CK")
            doc_parts.append(f"\n{', '.join(mitre)}")

        # Documentation from comments
        if technique_info['documentation']:
            doc_parts.append(f"\n## Implementation Notes")
            doc_parts.append(f"\n{technique_info['documentation'][:500]}")

        # Functions
        if technique_info['functions']:
            doc_parts.append(f"\n## Key Functions")
            for func in technique_info['functions'][:5]:
                doc_parts.append(f"\n- {func}()")

        # Includes (dependencies)
        if technique_info['includes']:
            doc_parts.append(f"\n## Dependencies")
            for inc in technique_info['includes'][:5]:
                doc_parts.append(f"\n- #include <{inc}>")

        # Usage guidance
        doc_parts.append(f"\n## Usage")
        doc_parts.append(f"\nThis is a production-grade {technique_info['category']} implementation.")
        doc_parts.append(f"\nUse this technique when you need: {', '.join(keywords[:3])}")
        doc_parts.append(f"\nRead the source file for implementation details: {technique_info['file_path']}")

        return "\n".join(doc_parts)

    def index_techniques(self):
        """Index all technique implementations"""
        if not self.rag.enabled:
            logger.error("RAG engine not enabled. Install dependencies: pip install chromadb sentence-transformers")
            return False

        logger.info("="*70)
        logger.info("  NOCTIS-MCP: Comprehensive Technique Indexer")
        logger.info("  Indexing ALL technique implementations into RAG")
        logger.info("="*70)
        logger.info("")

        total_files = 0

        # Index each technique folder
        for folder in self.technique_folders:
            folder_path = self.techniques_root / folder

            if not folder_path.exists():
                logger.warning(f"Folder not found: {folder_path}")
                continue

            logger.info(f"\n📂 Indexing: {folder}/")
            logger.info("-" * 60)

            # Find all .c, .cpp, .h files
            files = list(folder_path.glob("*.c")) + list(folder_path.glob("*.cpp")) + list(folder_path.glob("*.h"))

            if not files:
                logger.info(f"  ⚠️  No files found in {folder}/")
                continue

            for file in files:
                try:
                    # Extract technique information
                    technique_info = self.extract_technique_info(file)

                    if not technique_info:
                        logger.warning(f"  ⚠️  Could not extract info from {file.name}")
                        self.failed_count += 1
                        continue

                    # Create RAG document
                    document = self.create_rag_document(technique_info)

                    # Index into RAG
                    doc_id = f"technique_{folder}_{file.stem}"

                    self.rag.knowledge.add(
                        ids=[doc_id],
                        documents=[document],
                        metadatas=[{
                            "source": "technique_implementation",
                            "category": technique_info['category'],
                            "technique_name": technique_info['technique_name'],
                            "filename": technique_info['filename'],
                            "file_path": technique_info['file_path'],
                            "language": "C/C++",
                            "opsec_score": str(technique_info['purpose'].get('opsec_score', 'unknown')),
                            "detection_risk": technique_info['purpose'].get('detection_risk', 'unknown'),
                            "keywords": ','.join(technique_info['purpose'].get('keywords', []))
                        }]
                    )

                    self.indexed_count += 1
                    total_files += 1

                    opsec = technique_info['purpose'].get('opsec_score', '?')
                    logger.info(f"  ✅ {file.name:<30} OPSEC: {opsec}/10")

                except Exception as e:
                    logger.error(f"  ❌ Failed to index {file.name}: {e}")
                    self.failed_count += 1

        logger.info("\n" + "="*70)
        logger.info("✅ INDEXING COMPLETE!")
        logger.info("="*70)
        logger.info(f"  Successfully indexed: {self.indexed_count} technique files")
        logger.info(f"  Failed: {self.failed_count} files")
        logger.info(f"\n  🎉 AI can now find ALL technique implementations!")
        logger.info(f"  Try searching: 'PoolParty injection', 'SysWhispers3', 'VEH AMSI bypass'")
        logger.info("="*70)

        return True


def main():
    """Main indexing workflow"""
    indexer = TechniqueIndexer()

    if not indexer.rag.enabled:
        logger.error("RAG engine not enabled. Check ChromaDB installation.")
        return 1

    success = indexer.index_techniques()

    if success:
        return 0
    else:
        return 1


if __name__ == '__main__':
    sys.exit(main())
