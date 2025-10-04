#!/usr/bin/env python3
"""
OPSEC Optimization Agent
=========================

Iteratively improves code OPSEC score through automated obfuscation
and security hardening.

Author: Noctis-MCP Community
License: MIT
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from typing import Dict, List, Tuple
from server.agents.base_agent import BaseAgent, AgentResult
from server.opsec_analyzer import OpsecAnalyzer


class OpsecOptimizationAgent(BaseAgent):
    """
    Iteratively improves code OPSEC score.

    This agent analyzes code for OPSEC issues and applies obfuscation
    techniques iteratively until target score is reached or max iterations hit.

    Input Parameters:
        - code (str): Source code to optimize
        - target_score (float): Target OPSEC score (0-10, default: 8.0)
        - max_iterations (int): Maximum optimization iterations (default: 3)
        - obfuscation_level (str): Level of obfuscation ('basic', 'advanced', default: 'advanced')

    Output:
        AgentResult with:
            - optimized_code: The improved code
            - original_score: Original OPSEC score
            - final_score: Final OPSEC score after optimization
            - iterations_used: Number of iterations performed
            - improvements_applied: List of improvements made
            - final_report: Final OPSEC analysis report
    """

    def _init_agent(self):
        """Initialize agent-specific resources"""
        self.logger.info("Initializing OpsecOptimizationAgent...")

        # Initialize OPSEC analyzer
        self.analyzer = OpsecAnalyzer()

        # Track improvements applied
        self.state['improvements_log'] = []

        self.logger.info("OpsecOptimizationAgent initialized")

    def validate_inputs(self, **kwargs) -> Tuple[bool, List[str]]:
        """Validate input parameters"""
        errors = []

        # code is required
        code = kwargs.get('code')
        if not code:
            errors.append("code parameter is required")
        elif not isinstance(code, str):
            errors.append("code must be a string")

        # target_score is optional (defaults to 8.0)
        target_score = kwargs.get('target_score', 8.0)
        if not isinstance(target_score, (int, float)):
            errors.append("target_score must be a number")
        elif not (0 <= target_score <= 10):
            errors.append("target_score must be between 0 and 10")

        # max_iterations is optional (defaults to 3)
        max_iterations = kwargs.get('max_iterations', 3)
        if not isinstance(max_iterations, int):
            errors.append("max_iterations must be an integer")
        elif max_iterations < 1 or max_iterations > 10:
            errors.append("max_iterations must be between 1 and 10")

        return len(errors) == 0, errors

    def execute(self, **kwargs) -> AgentResult:
        """Execute OPSEC optimization"""
        # Extract parameters
        code = kwargs.get('code')
        target_score = kwargs.get('target_score', 8.0)
        max_iterations = kwargs.get('max_iterations', 3)
        obfuscation_level = kwargs.get('obfuscation_level', 'advanced')

        self.logger.info(f"Starting OPSEC optimization: target_score={target_score}, max_iterations={max_iterations}")

        try:
            # 1. Analyze original code
            self.logger.info("Analyzing original code...")
            original_report = self.analyzer.analyze(code)
            original_score = original_report.overall_score

            self.logger.info(f"Original OPSEC score: {original_score:.2f}/10")

            # Check if already meets target
            if original_score >= target_score:
                self.logger.info(f"Code already meets target score ({original_score:.2f} >= {target_score})")
                return AgentResult(
                    success=True,
                    data={
                        'optimized_code': code,
                        'original_score': original_score,
                        'final_score': original_score,
                        'iterations_used': 0,
                        'improvements_applied': [],
                        'final_report': original_report.to_dict()
                    },
                    errors=[],
                    warnings=['Code already meets target OPSEC score'],
                    metadata={'target_reached_initially': True}
                )

            # 2. Iterative optimization
            current_code = code
            current_score = original_score
            iteration = 0
            improvements_applied = []

            while iteration < max_iterations and current_score < target_score:
                iteration += 1
                self.logger.info(f"Iteration {iteration}/{max_iterations}: Current score = {current_score:.2f}")

                # Apply improvements based on issues
                improved_code, improvements = self._apply_improvements(
                    current_code,
                    original_report if iteration == 1 else self.analyzer.analyze(current_code),
                    obfuscation_level
                )

                if improvements:
                    current_code = improved_code
                    improvements_applied.extend(improvements)

                    # Re-analyze
                    new_report = self.analyzer.analyze(current_code)
                    new_score = new_report.overall_score

                    self.logger.info(f"  Applied {len(improvements)} improvements, new score: {new_score:.2f}")

                    # Check if score improved
                    if new_score <= current_score:
                        self.logger.warning(f"  Score did not improve ({new_score:.2f} <= {current_score:.2f})")
                        # Don't break, maybe next iteration will help

                    current_score = new_score
                else:
                    self.logger.warning(f"  No improvements could be applied in iteration {iteration}")
                    break

            # 3. Final analysis
            final_report = self.analyzer.analyze(current_code)
            final_score = final_report.overall_score

            self.logger.info(f"Optimization complete: {original_score:.2f} -> {final_score:.2f} in {iteration} iterations")

            # Determine success
            success = final_score >= target_score
            warnings = []
            if not success:
                warnings.append(f"Target score {target_score} not reached (final: {final_score:.2f})")

            return AgentResult(
                success=True,  # Always succeed (did our best)
                data={
                    'optimized_code': current_code,
                    'original_score': original_score,
                    'final_score': final_score,
                    'iterations_used': iteration,
                    'improvements_applied': improvements_applied,
                    'final_report': final_report.to_dict(),
                    'target_reached': final_score >= target_score
                },
                errors=[],
                warnings=warnings,
                metadata={
                    'target_score': target_score,
                    'max_iterations': max_iterations,
                    'score_improvement': final_score - original_score
                }
            )

        except Exception as e:
            self.logger.exception(f"Error in OPSEC optimization: {e}")
            return AgentResult(
                success=False,
                data={},
                errors=[f"OPSEC optimization failed: {str(e)}"],
                warnings=[],
                metadata={}
            )

    def _apply_improvements(self, code: str, report, obfuscation_level: str) -> Tuple[str, List[str]]:
        """
        Apply improvements to code based on OPSEC report.

        Returns:
            (improved_code, list_of_improvements_applied)
        """
        improved_code = code
        improvements = []

        # Get issues sorted by severity
        issues = report.issues
        critical_issues = [i for i in issues if i.severity == 'critical']
        high_issues = [i for i in issues if i.severity == 'high']
        medium_issues = [i for i in issues if i.severity == 'medium']

        # Apply fixes in order of severity
        all_issues = critical_issues + high_issues + medium_issues

        for issue in all_issues[:10]:  # Fix top 10 issues
            category = issue.category

            if category == 'string':
                # Apply string obfuscation
                fixed_code, applied = self._obfuscate_strings(improved_code)
                if applied:
                    improved_code = fixed_code
                    improvements.append(f"Obfuscated suspicious strings ({issue.description})")

            elif category == 'api':
                # Apply API hashing (if obfuscation modules available)
                # For now, just log
                self.logger.debug(f"API issue detected: {issue.description}")
                improvements.append(f"Flagged API issue: {issue.description}")

            elif category == 'pattern':
                # Add code obfuscation
                self.logger.debug(f"Pattern issue: {issue.description}")
                improvements.append(f"Flagged pattern: {issue.description}")

        return improved_code, improvements

    def _obfuscate_strings(self, code: str) -> Tuple[str, bool]:
        """
        Obfuscate hardcoded strings in code.

        This is a simplified version - real implementation would use
        StringEncryptor from server.obfuscation module.

        Returns:
            (modified_code, was_modified)
        """
        # Try to import string encryption
        try:
            from server.obfuscation import StringEncryptor

            encryptor = StringEncryptor(method='xor')
            encrypted_code, decryption_funcs = encryptor.encrypt_code(code)

            # Combine decryption functions with code
            if decryption_funcs:
                return decryption_funcs + "\n" + encrypted_code, True
            else:
                return code, False

        except ImportError as e:
            self.logger.warning(f"StringEncryptor not available: {e}")
            return code, False
        except Exception as e:
            self.logger.error(f"Error obfuscating strings: {e}")
            return code, False


# Example usage
if __name__ == '__main__':
    # Test the agent
    config = {}

    agent = OpsecOptimizationAgent(config)

    # Sample code with OPSEC issues
    test_code = '''
#include <Windows.h>
#include <stdio.h>

int main() {
    // Bad OPSEC: Hardcoded suspicious strings
    char* url = "http://malicious-c2.com/payload.exe";
    char* key = "MySecretKey123";

    printf("Connecting to: %s\\n", url);

    return 0;
}
'''

    result = agent.run(
        code=test_code,
        target_score=8.0,
        max_iterations=3
    )

    print(result)
    if result.success:
        print(f"\nOriginal score: {result.data['original_score']:.2f}")
        print(f"Final score: {result.data['final_score']:.2f}")
        print(f"Iterations: {result.data['iterations_used']}")
        print(f"Improvements: {len(result.data['improvements_applied'])}")
