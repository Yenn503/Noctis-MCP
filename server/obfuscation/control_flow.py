#!/usr/bin/env python3
"""
Control Flow Flattening Obfuscation
Transforms linear control flow into a state machine dispatcher
"""

import re
import random
import logging
from typing import List, Tuple, Dict

logger = logging.getLogger(__name__)


class ControlFlowFlattener:
    """Flattens control flow to make code harder to analyze"""
    
    def __init__(self):
        self.state_var = f"state_{random.randint(1000, 9999)}"
        self.dispatcher_var = f"dispatcher_{random.randint(1000, 9999)}"
    
    def flatten(self, code: str, function_name: str = None) -> str:
        """
        Apply control flow flattening to code
        
        Args:
            code: Source code to flatten
            function_name: Specific function to flatten (if None, flattens main)
        
        Returns:
            Flattened code
        """
        logger.info(f"Applying control flow flattening to: {function_name or 'main()'}")
        
        if function_name:
            # Flatten specific function
            return self._flatten_function(code, function_name)
        else:
            # Flatten main() by default
            return self._flatten_main(code)
    
    def _flatten_main(self, code: str) -> str:
        """Flatten the main() function"""
        
        # Find main() function
        main_pattern = r'(int\s+main\s*\([^)]*\)\s*\{)([^}]*?)(\n\s*return\s+[^;]+;?\s*\n\})'
        match = re.search(main_pattern, code, re.DOTALL)
        
        if not match:
            logger.warning("main() function not found for control flow flattening")
            return code
        
        prefix = match.group(1)
        body = match.group(2)
        suffix = match.group(3)
        
        # Split body into basic blocks
        blocks = self._split_into_blocks(body)
        
        if len(blocks) < 2:
            logger.info("main() too simple for control flow flattening (need 2+ blocks)")
            return code
        
        # Generate flattened version
        flattened_body = self._generate_dispatcher(blocks)
        
        # Replace original main with flattened version
        flattened_main = prefix + flattened_body + suffix
        flattened_code = code[:match.start()] + flattened_main + code[match.end():]
        
        logger.info(f"Control flow flattened: {len(blocks)} blocks")
        return flattened_code
    
    def _flatten_function(self, code: str, function_name: str) -> str:
        """Flatten a specific function"""
        
        # Find function with various return types
        func_pattern = rf'((?:int|void|BOOL|DWORD|HANDLE|PVOID|LPVOID|NTSTATUS)\s+{re.escape(function_name)}\s*\([^)]*\)\s*\{{)([^}}]*?)(\n\s*(?:return\s+[^;]+;?)?\s*\n\}})'
        match = re.search(func_pattern, code, re.DOTALL)
        
        if not match:
            logger.warning(f"Function {function_name} not found")
            return code
        
        prefix = match.group(1)
        body = match.group(2)
        suffix = match.group(3)
        
        # Split into blocks
        blocks = self._split_into_blocks(body)
        
        if len(blocks) < 2:
            logger.info(f"{function_name} too simple for flattening")
            return code
        
        # Generate flattened version
        flattened_body = self._generate_dispatcher(blocks)
        
        # Replace
        flattened_func = prefix + flattened_body + suffix
        flattened_code = code[:match.start()] + flattened_func + code[match.end():]
        
        logger.info(f"Function {function_name} flattened: {len(blocks)} blocks")
        return flattened_code
    
    def _split_into_blocks(self, body: str) -> List[str]:
        """Split function body into basic blocks"""
        
        # Remove leading/trailing whitespace
        body = body.strip()
        
        # Split on statement boundaries (simplified approach)
        # Look for: semicolons, closing braces followed by newlines
        lines = body.split('\n')
        
        blocks = []
        current_block = []
        brace_depth = 0
        
        for line in lines:
            line = line.strip()
            if not line or line.startswith('//') or line.startswith('/*'):
                continue
            
            # Track brace depth
            brace_depth += line.count('{') - line.count('}')
            current_block.append(line)
            
            # End block on semicolon or closing brace at depth 0
            if (line.endswith(';') or line.endswith('}')) and brace_depth == 0:
                if current_block:
                    blocks.append('\n        '.join(current_block))
                    current_block = []
        
        # Add remaining lines as final block
        if current_block:
            blocks.append('\n        '.join(current_block))
        
        return [b for b in blocks if b.strip()]
    
    def _generate_dispatcher(self, blocks: List[str]) -> str:
        """Generate state machine dispatcher code"""
        
        # Generate random state values (non-sequential to confuse analysis)
        num_blocks = len(blocks)
        states = random.sample(range(100, 100 + num_blocks * 10), num_blocks)
        
        # Add a final "exit" state
        exit_state = random.randint(1000, 9999)
        
        # Build dispatcher code
        lines = [
            "",
            f"    // Control flow flattening - State machine dispatcher",
            f"    int {self.state_var} = {states[0]};",
            f"    int {self.dispatcher_var} = 1;",
            "",
            f"    while ({self.dispatcher_var}) {{",
            f"        switch ({self.state_var}) {{"
        ]
        
        # Generate case blocks
        for i, (state, block) in enumerate(zip(states, blocks)):
            next_state = states[i + 1] if i < len(states) - 1 else exit_state
            
            lines.extend([
                f"            case {state}:",
                f"                // Block {i}",
            ])
            
            # Add block code (indented)
            for block_line in block.split('\n'):
                lines.append(f"                {block_line}")
            
            lines.extend([
                f"                {self.state_var} = {next_state};",
                f"                break;",
                ""
            ])
        
        # Add exit case
        lines.extend([
            f"            case {exit_state}:",
            f"                {self.dispatcher_var} = 0;",
            f"                break;",
            "",
            f"            default:",
            f"                {self.dispatcher_var} = 0;",
            f"                break;",
            "        }",
            "    }",
            ""
        ])
        
        return '\n'.join(lines)


class JunkCodeInserter:
    """Inserts junk code to increase complexity"""
    
    def __init__(self):
        self.junk_counter = 0
    
    def insert(self, code: str, density: str = "medium") -> Tuple[str, int]:
        """
        Insert junk code into source
        
        Args:
            code: Source code
            density: low, medium, high (affects how much junk to insert)
        
        Returns:
            (modified_code, num_insertions)
        """
        density_map = {
            "low": 0.1,      # 10% of lines
            "medium": 0.25,  # 25% of lines
            "high": 0.5      # 50% of lines
        }
        
        insertion_prob = density_map.get(density, 0.25)
        
        logger.info(f"Inserting junk code with density: {density} ({insertion_prob*100:.0f}%)")
        
        lines = code.split('\n')
        modified_lines = []
        insertions = 0
        
        for line in lines:
            modified_lines.append(line)
            
            # Insert junk after certain lines (not in comments or preprocessor)
            if line.strip() and not line.strip().startswith('//') and \
               not line.strip().startswith('#') and not line.strip().startswith('/*'):
                
                if random.random() < insertion_prob:
                    junk = self._generate_junk_code(line)
                    modified_lines.append(junk)
                    insertions += 1
        
        logger.info(f"Inserted {insertions} junk code blocks")
        return '\n'.join(modified_lines), insertions
    
    def _generate_junk_code(self, context_line: str) -> str:
        """Generate a line of junk code"""
        
        self.junk_counter += 1
        
        junk_templates = [
            # Useless variable operations
            f"    volatile int __junk_{self.junk_counter} = (int)GetTickCount() ^ 0x{random.randint(0, 0xFFFF):04X};",
            
            # Useless conditionals (always false due to GetTickCount)
            f"    if (GetTickCount() == 0x{random.randint(0x10000000, 0xFFFFFFFF):08X}) {{ return -1; }}",
            
            # Useless function calls
            f"    (void)GetCurrentThreadId();  // Junk",
            
            # Useless pointer arithmetic
            f"    volatile void* __ptr_{self.junk_counter} = (void*)((DWORD_PTR)&__ptr_{self.junk_counter} ^ GetTickCount());",
            
            # Useless math operations
            f"    volatile int __tmp_{self.junk_counter} = ({random.randint(1, 100)} * {random.randint(1, 100)}) % {random.randint(10, 99)};",
            
            # Timing-based junk
            f"    if ((GetTickCount() & 0x{random.randint(1, 15):X}) == 0x{random.randint(16, 255):X}) {{ Sleep(0); }}",
        ]
        
        return random.choice(junk_templates)


def flatten_control_flow(code: str, function_name: str = None) -> str:
    """
    Convenience function to flatten control flow
    
    Args:
        code: Source code
        function_name: Function to flatten (None = main)
    
    Returns:
        Flattened code
    """
    flattener = ControlFlowFlattener()
    return flattener.flatten(code, function_name)


def insert_junk_code(code: str, density: str = "medium") -> Tuple[str, int]:
    """
    Convenience function to insert junk code
    
    Args:
        code: Source code
        density: low, medium, high
    
    Returns:
        (modified_code, num_insertions)
    """
    inserter = JunkCodeInserter()
    return inserter.insert(code, density)


# Example usage
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    # Test code
    test_code = """
int main(int argc, char* argv[]) {
    
    // TODO: Initialize techniques
    printf("Starting payload\\n");
    
    // TODO: Execute payload
    int result = execute_payload();
    
    // TODO: Cleanup
    cleanup_resources();
    
    return 0;
}
"""
    
    print("=== ORIGINAL CODE ===")
    print(test_code)
    
    print("\n=== CONTROL FLOW FLATTENED ===")
    flattened = flatten_control_flow(test_code)
    print(flattened)
    
    print("\n=== WITH JUNK CODE (MEDIUM) ===")
    junk_code, insertions = insert_junk_code(flattened, "medium")
    print(junk_code)
    print(f"\nInserted {insertions} junk code blocks")

