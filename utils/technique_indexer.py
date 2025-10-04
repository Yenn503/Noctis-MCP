#!/usr/bin/env python3
"""
Noctis-MCP Technique Indexer
=============================

Scans the Examples/ directory and extracts technique metadata.
This is the core of Phase 1 - creating a searchable knowledge base
of all available malware development techniques.

Author: Noctis-MCP Community
License: MIT
"""

import os
import json
import re
import hashlib
from pathlib import Path
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, asdict
from datetime import datetime
import argparse

# Try to import C parser (optional)
try:
    from pycparser import parse_file, c_ast
    C_PARSER_AVAILABLE = True
except ImportError:
    C_PARSER_AVAILABLE = False
    print("⚠️  pycparser not available - using regex-based parsing")


@dataclass
class TechniqueMetadata:
    """Metadata for a single technique"""
    technique_id: str
    name: str
    category: str
    description: str
    source_files: List[str]
    mitre_attack: List[str]
    dependencies: List[str]
    compatible_with: List[str]
    incompatible_with: List[str]
    opsec: Dict[str, any]
    code_blocks: Dict[str, any]
    variants: List[Dict[str, str]]
    author: str
    source_project: str
    last_updated: str


class TechniqueIndexer:
    """
    Indexes malware techniques from source code examples.
    
    This class scans C/C++ source files and extracts:
    - Function definitions
    - MITRE ATT&CK references (from comments)
    - Dependencies (includes, libraries)
    - OPSEC notes (from comments)
    """
    
    def __init__(self, examples_root: str = "Examples"):
        self.examples_root = Path(examples_root)
        self.techniques: List[TechniqueMetadata] = []
        self.technique_counter = 1
        self.total_instances = 0  # Track total detections
        
        # Known technique patterns to look for
        self.technique_patterns = {
            'api_hashing': r'GetProcAddress[A-Z]|GetModuleHandle[A-Z]|DJB2|HASH',
            'syscalls': r'syscall|NtAllocate|NtWrite|NtProtect|HellsHall|HellsGate',
            'unhooking': r'unhook|KnownDlls',
            'injection': r'inject|WriteProcessMemory|CreateRemoteThread|QueueUserAPC',
            'encryption': r'AES|XOR|RC4|crypt',
            'steganography': r'steg|DWT|LSB|embed',
            'gpu_evasion': r'D3D11|GPU|DirectX',
            'stack_spoof': r'stack.*spoof|CallStackMasker',
            'veh': r'VEH|AddVectoredExceptionHandler',
            'persistence': r'registry|RegSetValue|scheduled.*task|service.*create',
        }
    
    def scan_all(self) -> List[TechniqueMetadata]:
        """Scan all examples and extract techniques"""
        print(f"[*] Scanning {self.examples_root} for techniques...")
        
        if not self.examples_root.exists():
            print(f"[!] Examples directory not found: {self.examples_root}")
            return []
        
        # Scan each subdirectory
        for project_dir in self.examples_root.iterdir():
            if project_dir.is_dir() and not project_dir.name.startswith('.'):
                print(f"\n[+] Scanning project: {project_dir.name}")
                self._scan_project(project_dir)
        
        print(f"\n[+] Found {len(self.techniques)} unique techniques ({self.total_instances} total detections across source files)")
        return self.techniques
    
    def _scan_project(self, project_path: Path):
        """Scan a single project directory"""
        # Find all C/C++ source files
        source_files = []
        for ext in ['.c', '.cpp', '.h', '.hpp']:
            source_files.extend(project_path.rglob(f'*{ext}'))
        
        if not source_files:
            return
        
        print(f"   Found {len(source_files)} source files")
        
        # Process each source file
        for source_file in source_files:
            techniques = self._extract_techniques_from_file(source_file, project_path)
            self.techniques.extend(techniques)
    
    def _extract_techniques_from_file(self, file_path: Path, project_path: Path) -> List[TechniqueMetadata]:
        """Extract techniques from a single source file"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception as e:
            print(f"   ⚠️  Could not read {file_path.name}: {e}")
            return []
        
        techniques = []
        
        # Detect which techniques are present
        for technique_name, pattern in self.technique_patterns.items():
            if re.search(pattern, content, re.IGNORECASE):
                self.total_instances += 1
                
                # Check if we already have this technique GLOBALLY
                existing = next(
                    (t for t in self.techniques if t.name == technique_name.replace('_', ' ').title()),
                    None
                )
                
                if existing:
                    # Add this file to existing technique's source files
                    relative_path = str(file_path.relative_to(self.examples_root))
                    if relative_path not in existing.source_files:
                        existing.source_files.append(relative_path)
                        print(f"   [+] Found: {technique_name} in {file_path.name} (added to existing)")
                else:
                    # Create new technique
                    technique = self._create_technique_metadata(
                        technique_name,
                        file_path,
                        project_path,
                        content
                    )
                    techniques.append(technique)
                    print(f"   [+] Found: {technique_name} in {file_path.name} (NEW)")
        
        return techniques
    
    def _create_technique_metadata(
        self, 
        technique_name: str, 
        file_path: Path,
        project_path: Path,
        content: str
    ) -> TechniqueMetadata:
        """Create metadata object for a technique"""
        
        # Generate technique ID
        technique_id = f"NOCTIS-T{self.technique_counter:03d}"
        self.technique_counter += 1
        
        # Extract MITRE ATT&CK references from comments
        mitre_refs = self._extract_mitre_refs(content)
        
        # Extract dependencies (includes, libraries)
        dependencies = self._extract_dependencies(content)
        
        # Extract OPSEC notes from comments
        opsec_info = self._extract_opsec_info(content)
        
        # Determine category
        category = self._determine_category(technique_name)
        
        # Get project author from README if available
        author = self._extract_author(project_path)
        
        # Get description
        description = self._generate_description(technique_name, content)
        
        return TechniqueMetadata(
            technique_id=technique_id,
            name=technique_name.replace('_', ' ').title(),
            category=category,
            description=description,
            source_files=[str(file_path.relative_to(self.examples_root))],
            mitre_attack=mitre_refs,
            dependencies=dependencies,
            compatible_with=[],  # Will be populated later
            incompatible_with=[],
            opsec=opsec_info,
            code_blocks={
                "file": str(file_path.name),
                "functions": self._extract_function_names(content)
            },
            variants=[],
            author=author,
            source_project=project_path.name,
            last_updated=datetime.now().isoformat()
        )
    
    def _extract_mitre_refs(self, content: str) -> List[str]:
        """Extract MITRE ATT&CK references from code comments"""
        # Look for patterns like T1027, T1055, etc.
        pattern = r'T\d{4}(?:\.\d{3})?'
        matches = re.findall(pattern, content)
        return list(set(matches))  # Unique references
    
    def _extract_dependencies(self, content: str) -> List[str]:
        """Extract #include dependencies and required DLLs"""
        deps = []
        
        # Extract #include statements
        includes = re.findall(r'#include\s+[<"]([^>"]+)[>"]', content)
        deps.extend(includes)
        
        # Extract common DLL references
        dll_pattern = r'(kernel32|ntdll|user32|advapi32|ws2_32)\.dll'
        dlls = re.findall(dll_pattern, content, re.IGNORECASE)
        deps.extend([f"{dll}.dll" for dll in dlls])
        
        return list(set(deps))  # Unique dependencies
    
    def _extract_opsec_info(self, content: str) -> Dict[str, any]:
        """Extract OPSEC information from comments"""
        opsec = {
            "detection_risk": "unknown",
            "stability": "unknown",
            "tested_on": [],
            "bypasses": [],
            "detected_by": []
        }
        
        # Look for OPSEC comments
        opsec_comments = re.findall(r'OPSEC[:\s]+([^\n]+)', content, re.IGNORECASE)
        if opsec_comments:
            # Parse first OPSEC comment
            comment = opsec_comments[0].lower()
            if 'high' in comment or 'stealth' in comment:
                opsec["detection_risk"] = "low"
            elif 'medium' in comment:
                opsec["detection_risk"] = "medium"
            elif 'detected' in comment:
                opsec["detection_risk"] = "high"
        
        # Look for "Tested:" comments
        tested = re.findall(r'Tested[:\s]+([^\n]+)', content, re.IGNORECASE)
        if tested:
            # Extract Windows versions
            for test in tested:
                if 'win' in test.lower() or 'windows' in test.lower():
                    opsec["tested_on"].append(test.strip())
        
        # Look for "Bypasses:" comments
        bypasses = re.findall(r'Bypasses[:\s]+([^\n]+)', content, re.IGNORECASE)
        if bypasses:
            opsec["bypasses"] = [b.strip() for b in bypasses[0].split(',')]
        
        # Look for "Detected by:" comments
        detected = re.findall(r'Detected by[:\s]+([^\n]+)', content, re.IGNORECASE)
        if detected:
            opsec["detected_by"] = [d.strip() for d in detected[0].split(',')]
        
        return opsec
    
    def _extract_function_names(self, content: str) -> List[str]:
        """Extract function names from C code"""
        # Simple regex for function definitions
        # Matches: RETURN_TYPE FunctionName(PARAMS)
        pattern = r'\b(?:BOOL|DWORD|VOID|FARPROC|HMODULE|NTSTATUS|LPVOID|HANDLE|int|void|char\*)\s+(\w+)\s*\([^)]*\)'
        matches = re.findall(pattern, content)
        return list(set(matches))
    
    def _determine_category(self, technique_name: str) -> str:
        """Determine technique category based on name"""
        category_map = {
            'api_hashing': 'evasion/obfuscation',
            'syscalls': 'evasion/unhooking',
            'unhooking': 'evasion/unhooking',
            'injection': 'injection',
            'encryption': 'encryption',
            'steganography': 'steganography',
            'gpu_evasion': 'evasion/advanced',
            'stack_spoof': 'evasion/advanced',
            'veh': 'evasion/advanced',
            'persistence': 'persistence'
        }
        return category_map.get(technique_name, 'other')
    
    def _extract_author(self, project_path: Path) -> str:
        """Extract author from README or comments"""
        readme_files = list(project_path.rglob('README.md'))
        if readme_files:
            try:
                with open(readme_files[0], 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    # Look for author patterns
                    author_match = re.search(r'[Aa]uthor[:\s]+([^\n]+)', content)
                    if author_match:
                        return author_match.group(1).strip()
            except:
                pass
        
        # Default to project name
        if 'MaldevAcademy' in str(project_path):
            return 'MalDev Academy'
        elif 'TheSilencer' in str(project_path):
            return 'Yenn'
        else:
            return 'Unknown'
    
    def _generate_description(self, technique_name: str, content: str) -> str:
        """Generate a description for the technique"""
        descriptions = {
            'api_hashing': 'Obfuscates API calls by hashing function names to evade static analysis',
            'syscalls': 'Direct system call execution to bypass user-mode API hooks',
            'unhooking': 'Removes EDR/AV hooks from DLLs to restore original functionality',
            'injection': 'Injects code into remote processes for execution',
            'encryption': 'Encrypts payloads to evade signature-based detection',
            'steganography': 'Hides payloads in legitimate files using steganographic techniques',
            'gpu_evasion': 'Moves malicious code to GPU memory to evade memory scanners',
            'stack_spoof': 'Masks call stacks to hide malicious execution chains',
            'veh': 'Manipulates vectored exception handlers to bypass EDR monitoring',
            'persistence': 'Establishes persistence mechanisms for long-term access'
        }
        return descriptions.get(technique_name, f'Technique: {technique_name}')
    
    def save_metadata(self, output_dir: str = "techniques/metadata"):
        """Save all technique metadata to JSON files"""
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        print(f"\n[*] Saving metadata to {output_path}/")
        
        for technique in self.techniques:
            # Create filename from technique name
            filename = f"{technique.name.lower().replace(' ', '_')}.json"
            filepath = output_path / filename
            
            # Convert to dict and save
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(asdict(technique), f, indent=2)
            
            print(f"   [+] Saved: {filename}")
        
        # Also save a master index
        index_file = output_path / "index.json"
        index_data = {
            "total_techniques": len(self.techniques),
            "categories": self._get_category_summary(),
            "last_updated": datetime.now().isoformat(),
            "techniques": [
                {
                    "id": t.technique_id,
                    "name": t.name,
                    "category": t.category,
                    "author": t.author,
                    "source_project": t.source_project
                }
                for t in self.techniques
            ]
        }
        
        with open(index_file, 'w', encoding='utf-8') as f:
            json.dump(index_data, f, indent=2)
        
        print(f"\n[+] Metadata saved! Total: {len(self.techniques)} techniques")
        print(f"[*] Index file: {index_file}")
    
    def _get_category_summary(self) -> Dict[str, int]:
        """Get count of techniques per category"""
        categories = {}
        for t in self.techniques:
            categories[t.category] = categories.get(t.category, 0) + 1
        return categories
    
    def print_summary(self):
        """Print a summary of indexed techniques"""
        print("\n" + "=" * 70)
        print("TECHNIQUE INDEXING SUMMARY")
        print("=" * 70)
        
        # Group by category
        by_category = {}
        for t in self.techniques:
            if t.category not in by_category:
                by_category[t.category] = []
            by_category[t.category].append(t)
        
        for category, techniques in sorted(by_category.items()):
            print(f"\n{category.upper()}: ({len(techniques)} techniques)")
            for t in techniques:
                print(f"  • {t.name} ({t.source_project}) - {t.technique_id}")
        
        print("\n" + "=" * 70)
        print(f"Total Techniques: {len(self.techniques)}")
        print("=" * 70)


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Noctis-MCP Technique Indexer - Index malware development techniques'
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
              NOCTIS-MCP TECHNIQUE INDEXER                     
       Indexing Malware Development Techniques v2.0             
====================================================================
    """)
    
    # Create indexer and scan
    indexer = TechniqueIndexer(examples_root=args.examples)
    techniques = indexer.scan_all()
    
    if techniques:
        # Save metadata
        indexer.save_metadata(output_dir=args.output)
        
        # Print summary
        indexer.print_summary()
    else:
        print("[!] No techniques found!")
        return 1
    
    print("\n[+] Indexing complete!")
    return 0


if __name__ == '__main__':
    exit(main())

