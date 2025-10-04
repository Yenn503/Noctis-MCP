#!/usr/bin/env python3
"""
Learning Agent
===============

Manages feedback collection, learning from results, and continuous improvement
of technique effectiveness scores.

Author: Noctis-MCP Community
License: MIT
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from typing import Dict, List, Tuple
from datetime import datetime
from server.agents.base_agent import BaseAgent, AgentResult
from server.learning_engine import LearningEngine, DetectionFeedback, CompilationFeedback, AgenticLearningEngine


class LearningAgent(BaseAgent):
    """
    Manages learning from user feedback and test results.

    This agent handles all feedback collection and learning operations,
    updating the knowledge base with real-world effectiveness data.

    Supported Actions:
        - record_detection: Record AV/EDR detection results
        - record_compilation: Record compilation success/failure
        - analyze_patterns: Analyze patterns in historical data
        - get_recommendations: Get technique recommendations based on learned data

    Input Parameters (vary by action):
        For 'record_detection':
            - techniques (list): List of technique IDs used
            - av_edr (str): AV/EDR tested against
            - detected (bool): Whether malware was detected
            - detection_type (str): 'static', 'dynamic', 'behavioral'
            - obfuscation_level (str): 'none', 'basic', 'advanced'
            - notes (str): Additional notes

        For 'record_compilation':
            - techniques (list): List of technique IDs used
            - success (bool): Whether compilation succeeded
            - compiler (str): Compiler used
            - error_type (str): Type of error if failed

        For 'get_recommendations':
            - target_av (str): Target AV/EDR
            - category (str): Optional category filter
            - min_success_rate (float): Minimum success rate

    Output:
        AgentResult with action-specific data
    """

    def _init_agent(self):
        """Initialize agent-specific resources"""
        self.logger.info("Initializing LearningAgent...")

        # Initialize learning engines
        db_path = self.config.get('db_path', 'data/knowledge_base.db')
        self.learning_engine = LearningEngine(db_path)
        self.agentic_engine = AgenticLearningEngine(db_path)

        self.logger.info("LearningAgent initialized")

    def validate_inputs(self, **kwargs) -> Tuple[bool, List[str]]:
        """Validate input parameters"""
        errors = []

        # action is required
        action = kwargs.get('action')
        if not action:
            errors.append("action parameter is required")
            return False, errors

        valid_actions = ['record_detection', 'record_compilation', 'analyze_patterns', 'get_recommendations']
        if action not in valid_actions:
            errors.append(f"action must be one of {valid_actions}")
            return False, errors

        # Validate based on action
        if action == 'record_detection':
            if 'techniques' not in kwargs:
                errors.append("techniques is required for record_detection")
            if 'av_edr' not in kwargs:
                errors.append("av_edr is required for record_detection")
            if 'detected' not in kwargs:
                errors.append("detected is required for record_detection")

        elif action == 'record_compilation':
            if 'techniques' not in kwargs:
                errors.append("techniques is required for record_compilation")
            if 'success' not in kwargs:
                errors.append("success is required for record_compilation")

        return len(errors) == 0, errors

    def execute(self, **kwargs) -> AgentResult:
        """Execute learning action"""
        action = kwargs.get('action')

        self.logger.info(f"Executing learning action: {action}")

        try:
            if action == 'record_detection':
                return self._record_detection(**kwargs)
            elif action == 'record_compilation':
                return self._record_compilation(**kwargs)
            elif action == 'analyze_patterns':
                return self._analyze_patterns(**kwargs)
            elif action == 'get_recommendations':
                return self._get_recommendations(**kwargs)
            else:
                return AgentResult(
                    success=False,
                    data={},
                    errors=[f"Unknown action: {action}"],
                    warnings=[],
                    metadata={}
                )

        except Exception as e:
            self.logger.exception(f"Error in learning action {action}: {e}")
            return AgentResult(
                success=False,
                data={},
                errors=[f"Learning action failed: {str(e)}"],
                warnings=[],
                metadata={'action': action}
            )

    def _record_detection(self, **kwargs) -> AgentResult:
        """Record AV/EDR detection results"""
        techniques = kwargs.get('techniques', [])
        av_edr = kwargs.get('av_edr')
        detected = kwargs.get('detected')
        detection_type = kwargs.get('detection_type', 'static')
        obfuscation_level = kwargs.get('obfuscation_level', 'none')
        notes = kwargs.get('notes', '')

        self.logger.info(f"Recording detection: {av_edr} - Detected: {detected} - Techniques: {techniques}")

        # Create feedback object
        feedback = DetectionFeedback(
            timestamp=datetime.now().isoformat(),
            techniques_used=techniques,
            av_edr=av_edr,
            detected=detected,
            detection_type=detection_type,
            obfuscation_level=obfuscation_level,
            notes=notes
        )

        # Record in database
        self.learning_engine.record_detection(feedback)

        # Get updated stats for techniques
        stats = {}
        for tech_id in techniques:
            tech_stats = self.learning_engine.get_technique_stats(tech_id)
            if tech_stats:
                stats[tech_id] = {
                    'total_uses': tech_stats.total_uses,
                    'compilation_success_rate': round(tech_stats.compilation_success_rate, 3),
                    'detection_rate': {
                        av: round(rate, 3)
                        for av, rate in tech_stats.detection_rate.items()
                    }
                }

        return AgentResult(
            success=True,
            data={
                'feedback_recorded': True,
                'techniques_tested': len(techniques),
                'av_edr': av_edr,
                'detected': detected,
                'updated_stats': stats
            },
            errors=[],
            warnings=[],
            metadata={'action': 'record_detection', 'timestamp': feedback.timestamp}
        )

    def _record_compilation(self, **kwargs) -> AgentResult:
        """Record compilation results"""
        techniques = kwargs.get('techniques', [])
        success = kwargs.get('success')
        compiler = kwargs.get('compiler', 'MSBuild')
        error_type = kwargs.get('error_type')
        auto_fixed = kwargs.get('auto_fixed', False)

        self.logger.info(f"Recording compilation: Success: {success} - Techniques: {techniques}")

        # Create feedback object
        feedback = CompilationFeedback(
            timestamp=datetime.now().isoformat(),
            techniques_used=techniques,
            success=success,
            compiler=compiler,
            error_type=error_type,
            auto_fixed=auto_fixed
        )

        # Record in database
        self.learning_engine.record_compilation(feedback)

        # Get updated stats
        stats = {}
        for tech_id in techniques:
            tech_stats = self.learning_engine.get_technique_stats(tech_id)
            if tech_stats:
                stats[tech_id] = {
                    'total_uses': tech_stats.total_uses,
                    'compilation_success_rate': round(tech_stats.compilation_success_rate, 3)
                }

        return AgentResult(
            success=True,
            data={
                'feedback_recorded': True,
                'compilation_success': success,
                'techniques_tested': len(techniques),
                'updated_stats': stats
            },
            errors=[],
            warnings=[],
            metadata={'action': 'record_compilation', 'timestamp': feedback.timestamp}
        )

    def _analyze_patterns(self, **kwargs) -> AgentResult:
        """Analyze patterns in historical data"""
        self.logger.info("Analyzing historical patterns...")

        # Get all technique stats
        all_stats = []

        # This requires iterating through techniques
        # For now, return placeholder
        patterns = {
            'most_used_techniques': [],
            'highest_success_rate': [],
            'most_detected': [],
            'analysis_timestamp': datetime.now().isoformat()
        }

        return AgentResult(
            success=True,
            data={'patterns': patterns},
            errors=[],
            warnings=['Pattern analysis not fully implemented yet'],
            metadata={'action': 'analyze_patterns'}
        )

    def _get_recommendations(self, **kwargs) -> AgentResult:
        """Get technique recommendations based on learned data"""
        target_av = kwargs.get('target_av')
        category = kwargs.get('category')
        min_success_rate = kwargs.get('min_success_rate', 0.7)

        self.logger.info(f"Getting recommendations for {target_av}")

        # Use learning engine to get recommendations
        recommendations = self.learning_engine.recommend_techniques(
            target_av=target_av,
            category=category,
            min_success_rate=min_success_rate
        )

        # Format results
        results = []
        for technique_id, score in recommendations[:10]:  # Top 10
            tech_stats = self.learning_engine.get_technique_stats(technique_id)
            if tech_stats:
                results.append({
                    'technique_id': technique_id,
                    'name': tech_stats.name,
                    'score': round(score, 3),
                    'total_uses': tech_stats.total_uses,
                    'compilation_success_rate': round(tech_stats.compilation_success_rate, 3),
                    'detection_rates': {
                        av: round(rate, 3)
                        for av, rate in tech_stats.detection_rate.items()
                    }
                })

        return AgentResult(
            success=True,
            data={
                'recommendations': results,
                'total_recommended': len(results),
                'criteria': {
                    'target_av': target_av,
                    'category': category,
                    'min_success_rate': min_success_rate
                }
            },
            errors=[],
            warnings=[],
            metadata={'action': 'get_recommendations'}
        )


# Example usage
if __name__ == '__main__':
    # Test the agent
    config = {
        'db_path': 'data/knowledge_base.db'
    }

    agent = LearningAgent(config)

    # Test recording detection
    result = agent.run(
        action='record_detection',
        techniques=['NOCTIS-T001', 'NOCTIS-T002'],
        av_edr='Windows Defender',
        detected=False,
        detection_type='static',
        obfuscation_level='advanced',
        notes='Successfully bypassed with API hashing and syscalls'
    )

    print(result)
    if result.success:
        print(f"\nFeedback recorded for {result.data['techniques_tested']} techniques")
        print(f"Updated stats: {result.data['updated_stats']}")
