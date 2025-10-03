#!/usr/bin/env python3
"""
Code Mutator - Polymorphic Code Transformation
Generates unique code variants while preserving functionality
"""

import re
import random
import string
import logging
from typing import List, Dict, Tuple, Set

logger = logging.getLogger(__name__)


class CodeMutator:
    """Mutates code to generate unique variants"""
    
    def __init__(self, seed: int = None):
        """
        Initialize code mutator
        
        Args:
            seed: Random seed for reproducible mutations (None = random)
        """
        if seed is not None:
            random.seed(seed)
        
        self.renamed_vars = {}
        self.renamed_funcs = {}
        self.mutation_count = 0
    
    def mutate(self, code: str, mutation_level: str = "medium") -> Tuple[str, Dict]:
        """
        Apply polymorphic mutations to code
        
        Args:
            code: Source code to mutate
            mutation_level: low, medium, high (affects mutation intensity)
        
        Returns:
            (mutated_code, mutation_info)
        """
        mutation_map = {
            "low": 0.3,
            "medium": 0.6,
            "high": 0.9
        }
        
        intensity = mutation_map.get(mutation_level, 0.6)
        
        logger.info(f"Mutating code with level: {mutation_level} (intensity: {intensity})")
        
        mutations_applied = []
        mutated = code
        
        # 1. Rename variables
        if random.random() < intensity:
            mutated, var_renames = self._rename_variables(mutated)
            if var_renames:
                mutations_applied.append(f"renamed_{len(var_renames)}_variables")
        
        # 2. Rename functions
        if random.random() < intensity:
            mutated, func_renames = self._rename_functions(mutated)
            if func_renames:
                mutations_applied.append(f"renamed_{len(func_renames)}_functions")
        
        # 3. Reorder independent statements
        if random.random() < intensity * 0.8:
            mutated, reorders = self._reorder_statements(mutated)
            if reorders > 0:
                mutations_applied.append(f"reordered_{reorders}_statements")
        
        # 4. Add equivalent code transformations
        if random.random() < intensity:
            mutated, transforms = self._transform_expressions(mutated)
            if transforms > 0:
                mutations_applied.append(f"transformed_{transforms}_expressions")
        
        mutation_info = {
            'level': mutation_level,
            'intensity': intensity,
            'mutations': mutations_applied,
            'variables_renamed': len(self.renamed_vars),
            'functions_renamed': len(self.renamed_funcs),
            'total_mutations': len(mutations_applied)
        }
        
        logger.info(f"Mutations applied: {mutations_applied}")
        
        return mutated, mutation_info
    
    def _rename_variables(self, code: str) -> Tuple[str, Dict[str, str]]:
        """Rename local variables to random names"""
        
        # Find variable declarations (simplified)
        var_pattern = r'\b(int|DWORD|BOOL|HANDLE|PVOID|char\*?|void\*?)\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*[=;,\[]'
        
        variables = {}
        for match in re.finditer(var_pattern, code):
            var_type = match.group(1)
            var_name = match.group(2)
            
            # Skip common names and already renamed
            if var_name in ['main', 'argc', 'argv', 'i', 'j', 'k'] or var_name in self.renamed_vars:
                continue
            
            # Generate random name
            prefix = self._get_prefix_for_type(var_type)
            new_name = f"{prefix}_{self._generate_random_name(8)}"
            variables[var_name] = new_name
            self.renamed_vars[var_name] = new_name
        
        # Replace variables (whole word only)
        mutated = code
        for old_name, new_name in variables.items():
            mutated = re.sub(rf'\b{re.escape(old_name)}\b', new_name, mutated)
        
        return mutated, variables
    
    def _rename_functions(self, code: str) -> Tuple[str, Dict[str, str]]:
        """Rename function definitions and calls"""
        
        # Find function definitions
        func_pattern = r'\b((?:static\s+)?(?:int|DWORD|BOOL|void|HANDLE|PVOID|FARPROC|HMODULE)\s+)([a-zA-Z_][a-zA-Z0-9_]*)\s*\('
        
        functions = {}
        for match in re.finditer(func_pattern, code):
            return_type = match.group(1).strip()
            func_name = match.group(2)
            
            # Skip main and already renamed
            if func_name == 'main' or func_name in self.renamed_funcs:
                continue
            
            # Generate random function name
            new_name = f"Func_{self._generate_random_name(12)}"
            functions[func_name] = new_name
            self.renamed_funcs[func_name] = new_name
        
        # Replace function names (whole word only)
        mutated = code
        for old_name, new_name in functions.items():
            mutated = re.sub(rf'\b{re.escape(old_name)}\b', new_name, mutated)
        
        return mutated, functions
    
    def _reorder_statements(self, code: str) -> Tuple[str, int]:
        """Reorder independent variable declarations"""
        
        # Find consecutive variable declarations
        lines = code.split('\n')
        reorders = 0
        
        i = 0
        while i < len(lines):
            # Find groups of variable declarations
            group_start = i
            group = []
            
            while i < len(lines) and self._is_var_declaration(lines[i]):
                group.append(lines[i])
                i += 1
            
            # Reorder if group has 2+ items
            if len(group) >= 2:
                random.shuffle(group)
                lines[group_start:group_start + len(group)] = group
                reorders += 1
            
            i += 1
        
        return '\n'.join(lines), reorders
    
    def _transform_expressions(self, code: str) -> Tuple[str, int]:
        """Apply equivalent expression transformations"""
        
        transforms = 0
        mutated = code
        
        # Transform: x = 0 → x = (1 - 1) or x = (2 - 2)
        zero_pattern = r'=\s*0\s*;'
        for match in re.finditer(zero_pattern, mutated):
            if random.random() < 0.5:
                a = random.randint(1, 10)
                replacement = f'= ({a} - {a});'
                mutated = mutated[:match.start()] + replacement + mutated[match.end():]
                transforms += 1
        
        # Transform: x = 1 → x = (2 - 1) or x = (3 - 2)
        one_pattern = r'=\s*1\s*;'
        for match in re.finditer(one_pattern, mutated):
            if random.random() < 0.5:
                a = random.randint(2, 10)
                replacement = f'= ({a} - {a-1});'
                mutated = mutated[:match.start()] + replacement + mutated[match.end():]
                transforms += 1
        
        return mutated, transforms
    
    def _is_var_declaration(self, line: str) -> bool:
        """Check if line is a variable declaration"""
        line = line.strip()
        if not line or line.startswith('//') or line.startswith('/*'):
            return False
        
        var_types = ['int', 'DWORD', 'BOOL', 'HANDLE', 'PVOID', 'char', 'void', 'BYTE', 'WORD']
        return any(line.strip().startswith(vtype + ' ') for vtype in var_types)
    
    def _get_prefix_for_type(self, var_type: str) -> str:
        """Get appropriate prefix for variable type"""
        type_map = {
            'int': 'i',
            'DWORD': 'dw',
            'BOOL': 'b',
            'HANDLE': 'h',
            'PVOID': 'p',
            'void*': 'p',
            'char*': 'sz',
            'char': 'c',
            'BYTE': 'by',
            'WORD': 'w'
        }
        return type_map.get(var_type.replace('*', ''), 'var')
    
    def _generate_random_name(self, length: int = 8) -> str:
        """Generate random variable/function name"""
        # Use mix of uppercase and lowercase for readability
        chars = string.ascii_letters + string.digits
        name = ''.join(random.choices(chars, k=length))
        
        # Ensure it starts with a letter
        if name[0].isdigit():
            name = random.choice(string.ascii_letters) + name[1:]
        
        return name
    
    def reset(self):
        """Reset mutation state"""
        self.renamed_vars = {}
        self.renamed_funcs = {}
        self.mutation_count = 0


# Example usage
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    test_code = """
int main(int argc, char* argv[]) {
    int result = 0;
    DWORD counter = 0;
    BOOL success = 1;
    
    result = process_data();
    counter = get_count();
    
    if (success) {
        cleanup();
    }
    
    return 0;
}

int process_data() {
    int value = 0;
    return value;
}
"""
    
    print("=== ORIGINAL CODE ===")
    print(test_code)
    
    mutator = CodeMutator()
    
    print("\n=== MUTATED (LOW) ===")
    mutated_low, info = mutator.mutate(test_code, "low")
    print(mutated_low)
    print(f"\nMutations: {info}")
    
    mutator.reset()
    
    print("\n=== MUTATED (HIGH) ===")
    mutated_high, info = mutator.mutate(test_code, "high")
    print(mutated_high)
    print(f"\nMutations: {info}")

