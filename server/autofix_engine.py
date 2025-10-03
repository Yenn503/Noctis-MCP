#!/usr/bin/env python3
"""
Auto-Fix Engine for Compilation Errors
========================================

Automatically fixes common compilation errors in generated malware code.

This module provides:
- Compilation error parsing
- Automatic fix strategies
- Code patching
- Iterative fix attempts

Author: Noctis-MCP Community
License: MIT
"""

import re
import logging
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass, field


# Setup logging
logger = logging.getLogger(__name__)


@dataclass
class CompilationError:
    """Represents a compilation error"""
    file: str
    line: Optional[int] = None
    column: Optional[int] = None
    error_code: Optional[str] = None
    message: str = ""
    severity: str = "error"  # error, warning, note
    
    def __str__(self):
        location = f"{self.file}"
        if self.line:
            location += f":{self.line}"
        if self.column:
            location += f":{self.column}"
        return f"{location}: {self.severity}: {self.message}"


@dataclass
class FixAttempt:
    """Represents a fix attempt"""
    error: CompilationError
    fix_type: str
    description: str
    applied: bool = False
    success: bool = False
    modified_code: Optional[str] = None


@dataclass
class AutoFixResult:
    """Result of auto-fix operation"""
    success: bool
    fixed_code: Optional[str] = None
    original_errors: List[CompilationError] = field(default_factory=list)
    fix_attempts: List[FixAttempt] = field(default_factory=list)
    iterations: int = 0
    message: str = ""
    
    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            'success': self.success,
            'message': self.message,
            'iterations': self.iterations,
            'original_error_count': len(self.original_errors),
            'fixes_applied': sum(1 for f in self.fix_attempts if f.applied),
            'fixes_successful': sum(1 for f in self.fix_attempts if f.success),
            'fix_attempts': [
                {
                    'fix_type': f.fix_type,
                    'description': f.description,
                    'applied': f.applied,
                    'success': f.success,
                    'error': str(f.error)
                }
                for f in self.fix_attempts
            ]
        }


class ErrorParser:
    """Parses compilation errors from compiler output"""
    
    # MSBuild/MSVC error format: file(line,col): error C####: message
    MSVC_ERROR_PATTERN = r'(.+?)\((\d+),(\d+)\)\s*:\s*(error|warning|note)\s+([A-Z]\d+)\s*:\s*(.+)'
    
    # GCC/Clang error format: file:line:col: error: message
    GCC_ERROR_PATTERN = r'(.+?):(\d+):(\d+):\s*(error|warning|note):\s*(.+)'
    
    def parse(self, output: str) -> List[CompilationError]:
        """Parse compilation errors from output"""
        errors = []
        
        for line in output.split('\n'):
            line = line.strip()
            if not line:
                continue
            
            # Try MSVC format
            match = re.match(self.MSVC_ERROR_PATTERN, line)
            if match:
                errors.append(CompilationError(
                    file=match.group(1),
                    line=int(match.group(2)),
                    column=int(match.group(3)),
                    severity=match.group(4),
                    error_code=match.group(5),
                    message=match.group(6)
                ))
                continue
            
            # Try GCC format
            match = re.match(self.GCC_ERROR_PATTERN, line)
            if match:
                errors.append(CompilationError(
                    file=match.group(1),
                    line=int(match.group(2)),
                    column=int(match.group(3)),
                    severity=match.group(4),
                    message=match.group(5)
                ))
                continue
        
        return errors


class FixStrategy:
    """Base class for fix strategies"""
    
    def can_fix(self, error: CompilationError, code: str) -> bool:
        """Check if this strategy can fix the error"""
        raise NotImplementedError
    
    def apply_fix(self, error: CompilationError, code: str) -> Tuple[bool, str, str]:
        """
        Apply fix to code
        
        Returns:
            (success, modified_code, description)
        """
        raise NotImplementedError


class UndeclaredIdentifierFix(FixStrategy):
    """Fixes undeclared identifier errors"""
    
    ERROR_PATTERNS = [
        r"undeclared identifier",
        r"not declared in this scope",
        r"identifier .* is undefined",
        r"C2065",  # MSVC undeclared identifier
    ]
    
    # Common missing headers and their identifiers
    HEADER_MAP = {
        'printf': 'stdio.h',
        'sprintf': 'stdio.h',
        'fprintf': 'stdio.h',
        'malloc': 'stdlib.h',
        'free': 'stdlib.h',
        'strlen': 'string.h',
        'strcpy': 'string.h',
        'strcmp': 'string.h',
        'memcpy': 'string.h',
        'memset': 'string.h',
    }
    
    def can_fix(self, error: CompilationError, code: str) -> bool:
        """Check if this is an undeclared identifier error"""
        message = error.message.lower()
        return any(re.search(pattern, message, re.IGNORECASE) for pattern in self.ERROR_PATTERNS)
    
    def apply_fix(self, error: CompilationError, code: str) -> Tuple[bool, str, str]:
        """Add missing header"""
        # Extract identifier name from error message
        match = re.search(r"'(\w+)'|`(\w+)`|identifier '?(\w+)'?", error.message)
        if not match:
            return False, code, "Could not extract identifier name"
        
        identifier = match.group(1) or match.group(2) or match.group(3)
        
        # Check if we know the header for this identifier
        if identifier in self.HEADER_MAP:
            header = self.HEADER_MAP[identifier]
            include_line = f'#include <{header}>'
            
            # Check if header already included
            if include_line in code:
                return False, code, f"Header {header} already included"
            
            # Add header at the top (after other includes)
            lines = code.split('\n')
            insert_pos = 0
            
            # Find last #include line
            for i, line in enumerate(lines):
                if line.strip().startswith('#include'):
                    insert_pos = i + 1
            
            lines.insert(insert_pos, include_line)
            modified_code = '\n'.join(lines)
            
            return True, modified_code, f"Added #include <{header}> for '{identifier}'"
        
        return False, code, f"Unknown header for identifier '{identifier}'"


class MissingHeaderFix(FixStrategy):
    """Fixes missing header errors"""
    
    ERROR_PATTERNS = [
        r"windows\.h.*no such file",
        r"cannot open.*windows\.h",
    ]
    
    def can_fix(self, error: CompilationError, code: str) -> bool:
        message = error.message.lower()
        return any(re.search(pattern, message, re.IGNORECASE) for pattern in self.ERROR_PATTERNS)
    
    def apply_fix(self, error: CompilationError, code: str) -> Tuple[bool, str, str]:
        """Add windows.h if missing"""
        if '#include <windows.h>' not in code:
            lines = code.split('\n')
            lines.insert(0, '#include <windows.h>')
            return True, '\n'.join(lines), "Added #include <windows.h>"
        return False, code, "windows.h already included"


class SyntaxErrorFix(FixStrategy):
    """Fixes common syntax errors"""
    
    def can_fix(self, error: CompilationError, code: str) -> bool:
        message = error.message.lower()
        return 'syntax error' in message or 'expected' in message
    
    def apply_fix(self, error: CompilationError, code: str) -> Tuple[bool, str, str]:
        """Fix common syntax errors"""
        if not error.line:
            return False, code, "No line number provided"
        
        lines = code.split('\n')
        if error.line > len(lines):
            return False, code, "Line number out of range"
        
        line_idx = error.line - 1
        line = lines[line_idx]
        original_line = line
        
        # Missing semicolon
        if 'expected' in error.message.lower() and ';' in error.message:
            if not line.rstrip().endswith(';') and not line.rstrip().endswith('{'):
                lines[line_idx] = line.rstrip() + ';'
                return True, '\n'.join(lines), "Added missing semicolon"
        
        # Missing closing brace
        if 'expected' in error.message.lower() and '}' in error.message:
            # Count braces in code
            open_braces = code.count('{')
            close_braces = code.count('}')
            if open_braces > close_braces:
                lines.append('}')
                return True, '\n'.join(lines), "Added missing closing brace"
        
        return False, code, "Could not determine syntax fix"


class TypeMismatchFix(FixStrategy):
    """Fixes type mismatch errors"""
    
    def can_fix(self, error: CompilationError, code: str) -> bool:
        message = error.message.lower()
        return 'type mismatch' in message or 'cannot convert' in message
    
    def apply_fix(self, error: CompilationError, code: str) -> Tuple[bool, str, str]:
        """Add type casts"""
        if not error.line:
            return False, code, "No line number provided"
        
        lines = code.split('\n')
        if error.line > len(lines):
            return False, code, "Line number out of range"
        
        # This is complex and context-dependent
        # For now, just suggest explicit casting
        return False, code, "Type mismatch requires manual fix"


class AutoFixEngine:
    """
    Automatic code fix engine
    
    Attempts to automatically fix common compilation errors.
    """
    
    def __init__(self, max_iterations: int = 3):
        self.max_iterations = max_iterations
        self.error_parser = ErrorParser()
        self.strategies = [
            MissingHeaderFix(),
            UndeclaredIdentifierFix(),
            SyntaxErrorFix(),
            TypeMismatchFix(),
        ]
    
    def fix(self, code: str, compiler_output: str) -> AutoFixResult:
        """
        Attempt to automatically fix compilation errors
        
        Args:
            code: Source code with errors
            compiler_output: Compiler output with errors
        
        Returns:
            AutoFixResult with fixed code or error information
        """
        logger.info("Starting auto-fix engine")
        
        # Parse errors
        errors = self.error_parser.parse(compiler_output)
        if not errors:
            return AutoFixResult(
                success=False,
                message="No compilation errors found in output"
            )
        
        logger.info(f"Found {len(errors)} compilation errors")
        
        result = AutoFixResult(
            success=False,
            original_errors=errors,
            iterations=0
        )
        
        current_code = code
        fixed_any = False
        
        # Try to fix errors
        for error in errors[:5]:  # Limit to first 5 errors
            logger.info(f"Attempting to fix: {error}")
            
            # Try each strategy
            for strategy in self.strategies:
                if strategy.can_fix(error, current_code):
                    success, modified_code, description = strategy.apply_fix(error, current_code)
                    
                    attempt = FixAttempt(
                        error=error,
                        fix_type=strategy.__class__.__name__,
                        description=description,
                        applied=success,
                        success=success,
                        modified_code=modified_code if success else None
                    )
                    
                    result.fix_attempts.append(attempt)
                    
                    if success:
                        logger.info(f"Applied fix: {description}")
                        current_code = modified_code
                        fixed_any = True
                        break
        
        result.iterations = 1
        
        if fixed_any:
            result.success = True
            result.fixed_code = current_code
            result.message = f"Applied {sum(1 for f in result.fix_attempts if f.applied)} fixes"
            logger.info(f"Auto-fix successful: {result.message}")
        else:
            result.success = False
            result.message = "Could not automatically fix errors"
            logger.warning("Auto-fix failed: no fixes could be applied")
        
        return result
    
    def fix_with_recompile(self, code: str, compiler_func) -> AutoFixResult:
        """
        Fix code with iterative recompilation
        
        Args:
            code: Source code
            compiler_func: Function that compiles and returns (success, output)
        
        Returns:
            AutoFixResult
        """
        current_code = code
        all_attempts = []
        
        for iteration in range(self.max_iterations):
            logger.info(f"Fix iteration {iteration + 1}/{self.max_iterations}")
            
            # Compile
            success, output = compiler_func(current_code)
            
            if success:
                return AutoFixResult(
                    success=True,
                    fixed_code=current_code,
                    iterations=iteration + 1,
                    fix_attempts=all_attempts,
                    message=f"Successfully fixed after {iteration + 1} iteration(s)"
                )
            
            # Try to fix errors
            fix_result = self.fix(current_code, output)
            all_attempts.extend(fix_result.fix_attempts)
            
            if not fix_result.success:
                return AutoFixResult(
                    success=False,
                    iterations=iteration + 1,
                    fix_attempts=all_attempts,
                    original_errors=fix_result.original_errors,
                    message=f"Could not fix errors after {iteration + 1} iteration(s)"
                )
            
            current_code = fix_result.fixed_code
        
        return AutoFixResult(
            success=False,
            iterations=self.max_iterations,
            fix_attempts=all_attempts,
            message=f"Max iterations ({self.max_iterations}) reached"
        )


# ============================================================================
# TESTING
# ============================================================================

def test_autofix_engine():
    """Test auto-fix engine"""
    
    # Test code with missing header
    test_code = """
int main() {
    printf("Hello World\\n");
    return 0;
}
"""
    
    # Simulated compiler error
    compiler_output = """
test.c(2,5): error C2065: 'printf': undeclared identifier
"""
    
    print("[*] Testing Auto-Fix Engine...")
    print()
    
    engine = AutoFixEngine()
    result = engine.fix(test_code, compiler_output)
    
    print(f"[*] Success: {result.success}")
    print(f"[*] Iterations: {result.iterations}")
    print(f"[*] Message: {result.message}")
    print(f"[*] Fixes Applied: {sum(1 for f in result.fix_attempts if f.applied)}")
    
    if result.success:
        print(f"\n[*] Fixed Code:")
        print("=" * 60)
        print(result.fixed_code)
        print("=" * 60)
        
        for attempt in result.fix_attempts:
            if attempt.applied:
                print(f"\n[+] {attempt.fix_type}: {attempt.description}")
    
    return result


if __name__ == "__main__":
    test_autofix_engine()

