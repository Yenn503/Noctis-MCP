#!/usr/bin/env python3
"""
Noctis-MCP Code Assembler
===========================

Intelligently combines malware techniques into working C/C++ code.

This module:
- Reads source files from Examples folder
- Extracts function definitions
- Resolves dependencies
- Detects conflicts
- Generates combined code

Author: Noctis-MCP Community
License: MIT
"""

import re
import json
from pathlib import Path
from typing import Dict, List, Set, Optional, Tuple
from dataclasses import dataclass, field
from collections import defaultdict
import logging

logger = logging.getLogger(__name__)


@dataclass
class FunctionDefinition:
    """Represents a C/C++ function definition"""
    name: str
    return_type: str
    parameters: str
    body: str
    source_file: str
    line_number: int
    technique_id: str
    
    def signature(self) -> str:
        """Get function signature"""
        return f"{self.return_type} {self.name}({self.parameters})"


@dataclass
class SourceFile:
    """Represents a parsed C/C++ source file"""
    path: Path
    content: str
    includes: List[str] = field(default_factory=list)
    defines: List[str] = field(default_factory=list)
    functions: List[FunctionDefinition] = field(default_factory=list)
    structs: List[str] = field(default_factory=list)
    global_vars: List[str] = field(default_factory=list)


@dataclass
class GeneratedCode:
    """Result of code assembly"""
    source_code: str
    header_code: str
    technique_ids: List[str]
    dependencies: List[str]
    conflicts: List[str]
    warnings: List[str]
    opsec_notes: List[str]
    mitre_ttps: List[str]
    
    def to_dict(self) -> dict:
        """Convert to dictionary"""
        return {
            'source_code': self.source_code,
            'header_code': self.header_code,
            'techniques_used': self.technique_ids,
            'dependencies': self.dependencies,
            'conflicts': self.conflicts,
            'warnings': self.warnings,
            'opsec_notes': self.opsec_notes,
            'mitre_ttps': self.mitre_ttps
        }


class SourceFileReader:
    """Reads and parses C/C++ source files"""

    def __init__(self, examples_root: str = "Examples", rag_engine=None):
        self.examples_root = Path(examples_root)
        self.rag_engine = rag_engine
    
    def read_file(self, file_path: Path) -> Optional[SourceFile]:
        """Read and parse a source file"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            source_file = SourceFile(path=file_path, content=content)
            
            # Extract components
            source_file.includes = self._extract_includes(content)
            source_file.defines = self._extract_defines(content)
            source_file.functions = self._extract_functions(content, file_path)
            source_file.structs = self._extract_structs(content)
            source_file.global_vars = self._extract_global_vars(content)
            
            return source_file
            
        except Exception as e:
            logger.error(f"Error reading {file_path}: {e}")
            return None
    
    def _extract_includes(self, content: str) -> List[str]:
        """Extract #include statements"""
        pattern = r'#include\s+[<"]([^>"]+)[>"]'
        return re.findall(pattern, content)
    
    def _extract_defines(self, content: str) -> List[str]:
        """Extract #define statements"""
        pattern = r'#define\s+([^\n]+)'
        return re.findall(pattern, content)
    
    def _extract_functions(self, content: str, file_path: Path) -> List[FunctionDefinition]:
        """Extract function definitions"""
        functions = []
        
        # Simple pattern for function definitions
        # Matches: RETURN_TYPE FunctionName(PARAMS) {
        pattern = r'((?:BOOL|DWORD|VOID|FARPROC|HMODULE|NTSTATUS|LPVOID|HANDLE|PVOID|int|void|char\*?)\s+)(\w+)\s*\(([^)]*)\)\s*\{'
        
        matches = re.finditer(pattern, content, re.MULTILINE)
        
        for match in matches:
            return_type = match.group(1).strip()
            func_name = match.group(2)
            params = match.group(3).strip()
            
            # Extract function body (simplified - finds matching braces)
            start_pos = match.end()
            body = self._extract_function_body(content, start_pos)
            
            # Get line number
            line_num = content[:match.start()].count('\n') + 1
            
            functions.append(FunctionDefinition(
                name=func_name,
                return_type=return_type,
                parameters=params,
                body=body,
                source_file=str(file_path),
                line_number=line_num,
                technique_id=""  # Will be set by assembler
            ))
        
        return functions
    
    def _extract_function_body(self, content: str, start_pos: int) -> str:
        """Extract function body by matching braces"""
        brace_count = 1
        pos = start_pos
        
        while pos < len(content) and brace_count > 0:
            if content[pos] == '{':
                brace_count += 1
            elif content[pos] == '}':
                brace_count -= 1
            pos += 1
        
        return content[start_pos:pos-1] if brace_count == 0 else ""
    
    def _extract_structs(self, content: str) -> List[str]:
        """Extract struct definitions"""
        # Match typedef struct { ... } NAME;
        pattern = r'typedef\s+struct\s*\{[^}]+\}\s*(\w+);'
        return re.findall(pattern, content, re.DOTALL)
    
    def _extract_global_vars(self, content: str) -> List[str]:
        """Extract global variable declarations"""
        # Simple pattern for global vars (outside functions)
        # This is a simplified version
        pattern = r'^(?:extern\s+)?(?:static\s+)?(?:DWORD|PVOID|HANDLE)\s+(\w+)\s*[;=]'
        return re.findall(pattern, content, re.MULTILINE)


class DependencyResolver:
    """Resolves dependencies between techniques"""
    
    def resolve(self, techniques: List[Dict], all_functions: Dict[str, FunctionDefinition]) -> Tuple[Set[str], List[str]]:
        """
        Resolve dependencies for selected techniques
        
        Returns:
            (required_includes, required_functions)
        """
        includes = set()
        required_funcs = []
        
        for technique in techniques:
            # Add technique dependencies
            for dep in technique.get('dependencies', []):
                if dep.endswith('.h') or dep.endswith('.dll'):
                    includes.add(dep)
            
            # Add required functions
            funcs = technique.get('code_blocks', {}).get('functions', [])
            for func in funcs:
                # Handle both string and dict formats
                if isinstance(func, dict):
                    func_name = func.get('name', '')
                else:
                    func_name = func
                if func_name and func_name in all_functions:
                    required_funcs.append(func_name)
        
        return includes, required_funcs
    
    def detect_conflicts(self, techniques: List[Dict]) -> List[str]:
        """Detect conflicts between techniques"""
        conflicts = []
        
        # Check incompatible combinations
        for i, tech1 in enumerate(techniques):
            for tech2 in techniques[i+1:]:
                if tech2['technique_id'] in tech1.get('incompatible_with', []):
                    conflicts.append(
                        f"{tech1['name']} is incompatible with {tech2['name']}"
                    )
        
        # Check for duplicate functions
        all_functions = []
        for tech in techniques:
            funcs = tech.get('code_blocks', {}).get('functions', [])
            # Handle both list of strings and list of dicts
            for func in funcs:
                if isinstance(func, dict):
                    func_name = func.get('name', '')
                else:
                    func_name = func
                if func_name:
                    all_functions.append(func_name)

        # Now all_functions contains only strings, safe for set()
        duplicates = [f for f in set(all_functions) if all_functions.count(f) > 1]
        if duplicates:
            conflicts.append(f"Duplicate functions detected: {', '.join(duplicates)}")
        
        return conflicts


class CodeAssembler:
    """
    Main code assembler that combines techniques into working code
    """

    def __init__(self, examples_root: str = "Examples", metadata_path: str = "techniques/metadata", rag_engine=None):
        self.examples_root = Path(examples_root)
        self.metadata_path = Path(metadata_path)
        self.rag_engine = rag_engine
        self.file_reader = SourceFileReader(examples_root, rag_engine=rag_engine)
        self.dependency_resolver = DependencyResolver()

        # Cache for parsed files
        self.parsed_files: Dict[str, SourceFile] = {}
        self.all_functions: Dict[str, FunctionDefinition] = {}

        # Load technique metadata
        self.techniques = self._load_techniques()

        # Load knowledge base if RAG available
        if self.rag_engine:
            self._index_knowledge_base()
    
    def _load_techniques(self) -> Dict[str, Dict]:
        """Load all technique metadata"""
        techniques = {}
        
        if not self.metadata_path.exists():
            print(f"[!] Metadata path not found: {self.metadata_path}")
            return techniques
        
        for json_file in self.metadata_path.glob('*.json'):
            if json_file.name == 'index.json':
                continue
            
            try:
                with open(json_file, 'r', encoding='utf-8') as f:
                    # Each file contains ONE technique (but may have been overwritten multiple times)
                    # We just take the last version
                    technique_data = json.load(f)
                    technique_id = technique_data.get('technique_id')
                    if technique_id:
                        techniques[technique_id] = technique_data
                        print(f"[+] Loaded: {technique_id} - {technique_data.get('name')}")
            except Exception as e:
                print(f"[!] Error loading {json_file}: {e}")
        
        print(f"[*] Loaded {len(techniques)} technique definitions")
        return techniques
    
    def assemble(self, technique_ids: List[str], options: Optional[Dict] = None) -> GeneratedCode:
        """
        Assemble code from multiple techniques
        
        Args:
            technique_ids: List of technique IDs to combine
            options: Optional assembly options
                - include_main: Include main() function (default: True)
                - target_arch: x86 or x64 (default: x64)
                - optimization: none, basic, aggressive (default: basic)
        
        Returns:
            GeneratedCode object with assembled code and metadata
        """
        options = options or {}
        include_main = options.get('include_main', True)
        
        logger.info(f"Assembling code for techniques: {technique_ids}")
        
        # Get technique metadata
        selected_techniques = []
        for tech_id in technique_ids:
            if tech_id in self.techniques:
                selected_techniques.append(self.techniques[tech_id])
            else:
                logger.warning(f"Technique {tech_id} not found")
        
        if not selected_techniques:
            return self._empty_result("No valid techniques selected")
        
        # Detect conflicts
        conflicts = self.dependency_resolver.detect_conflicts(selected_techniques)
        if conflicts:
            logger.warning(f"Conflicts detected: {conflicts}")
        
        # Parse source files for selected techniques
        for technique in selected_techniques:
            for source_file_path in technique.get('source_files', []):
                full_path = self.examples_root / source_file_path
                if full_path.exists() and str(full_path) not in self.parsed_files:
                    parsed = self.file_reader.read_file(full_path)
                    if parsed:
                        self.parsed_files[str(full_path)] = parsed
                        
                        # Index functions
                        for func in parsed.functions:
                            func.technique_id = technique['technique_id']
                            self.all_functions[func.name] = func
        
        # Resolve dependencies
        includes, required_funcs = self.dependency_resolver.resolve(
            selected_techniques, 
            self.all_functions
        )
        
        # Generate code
        source_code = self._generate_source_code(
            selected_techniques,
            required_funcs,
            includes,
            include_main
        )
        
        header_code = self._generate_header_code(selected_techniques, includes)
        
        # Collect MITRE TTPs
        mitre_ttps = []
        for tech in selected_techniques:
            mitre_ttps.extend(tech.get('mitre_attack', []))
        mitre_ttps = list(set(mitre_ttps))  # Unique
        
        # Collect OPSEC notes
        opsec_notes = []
        for tech in selected_techniques:
            opsec = tech.get('opsec', {})
            if opsec.get('detection_risk') == 'high':
                opsec_notes.append(f"WARNING: {tech['name']} has high detection risk")
            if opsec.get('detected_by'):
                opsec_notes.append(f"{tech['name']} detected by: {', '.join(opsec['detected_by'])}")
        
        return GeneratedCode(
            source_code=source_code,
            header_code=header_code,
            technique_ids=technique_ids,
            dependencies=list(includes),
            conflicts=conflicts,
            warnings=[],
            opsec_notes=opsec_notes,
            mitre_ttps=mitre_ttps
        )
    
    def _generate_source_code(
        self, 
        techniques: List[Dict], 
        required_funcs: List[str],
        includes: Set[str],
        include_main: bool
    ) -> str:
        """Generate the main source code file"""
        
        code_parts = []
        
        # Header comment
        code_parts.append(f"""/*
 * Auto-Generated Malware Code
 * Generated by Noctis-MCP v2.0
 * 
 * Techniques Used:
{chr(10).join(f' *   - {t["name"]} ({t["technique_id"]})' for t in techniques)}
 * 
 * MITRE ATT&CK TTPs:
{chr(10).join(f' *   - {ttp}' for tech in techniques for ttp in tech.get("mitre_attack", []))}
 * 
 * WARNING: For authorized security research only
 */
""")
        
        # Includes
        code_parts.append("\n// Required includes")
        for inc in sorted(includes):
            if inc.endswith('.h'):
                code_parts.append(f'#include <{inc}>')
        
        code_parts.append("")
        
        # Add function implementations
        code_parts.append("// ============================================================================")
        code_parts.append("// TECHNIQUE IMPLEMENTATIONS")
        code_parts.append("// ============================================================================\n")
        
        added_functions = set()
        for func_name in required_funcs:
            if func_name in self.all_functions and func_name not in added_functions:
                func_def = self.all_functions[func_name]
                code_parts.append(f"// From: {Path(func_def.source_file).name} (Line {func_def.line_number})")
                code_parts.append(f"// Technique: {func_def.technique_id}")
                code_parts.append(f"{func_def.return_type} {func_def.name}({func_def.parameters}) {{")
                code_parts.append(f"{func_def.body}")
                code_parts.append("}\n")
                added_functions.add(func_name)
        
        # Add main() if requested
        if include_main:
            code_parts.append(self._generate_main_function(techniques))
        
        return '\n'.join(code_parts)
    
    def _generate_header_code(self, techniques: List[Dict], includes: Set[str]) -> str:
        """Generate header file"""
        
        header_parts = []
        
        header_parts.append("/*")
        header_parts.append(" * Auto-Generated Header File")
        header_parts.append(" * Generated by Noctis-MCP")
        header_parts.append(" */\n")
        
        header_parts.append("#ifndef NOCTIS_GENERATED_H")
        header_parts.append("#define NOCTIS_GENERATED_H\n")
        
        # Add function declarations
        header_parts.append("// Function declarations")
        for func_name, func_def in self.all_functions.items():
            header_parts.append(f"{func_def.signature()};")
        
        header_parts.append("\n#endif // NOCTIS_GENERATED_H")
        
        return '\n'.join(header_parts)
    
    def _generate_main_function(self, techniques: List[Dict]) -> str:
        """Generate a main() function"""
        main_code = """
// ============================================================================
// MAIN ENTRY POINT
// ============================================================================

int main(int argc, char* argv[]) {
    
    // TODO: Initialize techniques
    // TODO: Execute payload
    // TODO: Cleanup
    
    return 0;
}
"""
        return main_code
    
    def _index_knowledge_base(self):
        """Index knowledge base markdown files into RAG system"""
        knowledge_path = Path("techniques/knowledge")
        if not knowledge_path.exists():
            logger.warning("Knowledge base path not found")
            return

        try:
            for md_file in knowledge_path.glob("*.md"):
                logger.info(f"Indexing knowledge: {md_file.name}")

                with open(md_file, 'r', encoding='utf-8') as f:
                    content = f.read()

                # Extract technique ID from filename or content
                tech_id = md_file.stem  # e.g., "syscalls" from "syscalls.md"

                # Add to RAG
                self.rag_engine.add_markdown_knowledge(
                    title=f"Knowledge: {tech_id.title()}",
                    content=content,
                    technique_id=f"NOCTIS-{tech_id.upper()}",
                    metadata={
                        'source': 'knowledge_base',
                        'file': str(md_file)
                    }
                )

            logger.info("Knowledge base indexing complete")

        except Exception as e:
            logger.error(f"Failed to index knowledge base: {e}")

    def _empty_result(self, error_msg: str) -> GeneratedCode:
        """Return empty result with error"""
        return GeneratedCode(
            source_code=f"// ERROR: {error_msg}",
            header_code="",
            technique_ids=[],
            dependencies=[],
            conflicts=[],
            warnings=[error_msg],
            opsec_notes=[],
            mitre_ttps=[]
        )


# ============================================================================
# TESTING
# ============================================================================

def test_code_assembler():
    """Test the code assembler"""
    assembler = CodeAssembler()
    
    print("\n[*] Available techniques:")
    for tech_id, tech_data in list(assembler.techniques.items())[:5]:
        print(f"    - {tech_id}: {tech_data['name']}")
    
    # Test with actual technique IDs (API Hashing + Syscalls)
    print("\n[*] Testing code assembly with API Hashing + Syscalls...")
    result = assembler.assemble(['NOCTIS-T124', 'NOCTIS-T118'])
    
    print("\n" + "=" * 70)
    print("GENERATED CODE:")
    print("=" * 70)
    print(result.source_code[:2000] if result.source_code else "No code generated")
    print("=" * 70)
    print(f"\nTechniques Used: {result.technique_ids}")
    print(f"Dependencies: {result.dependencies}")
    print(f"Conflicts: {result.conflicts}")
    print(f"MITRE ATT&CK TTPs: {result.mitre_ttps}")
    print(f"OPSEC Notes: {result.opsec_notes}")


if __name__ == '__main__':
    test_code_assembler()

