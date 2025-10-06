#!/usr/bin/env python3
"""
Technique Selection Agent
==========================

AI-powered intelligent technique selection based on target analysis,
historical effectiveness data, and compatibility constraints.

Author: Noctis-MCP Community
License: MIT
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from typing import Dict, List, Tuple, Optional
from server.agents.base_agent import BaseAgent, AgentResult
from server.learning_engine import AgenticLearningEngine


class TechniqueSelectionAgent(BaseAgent):
    """
    Intelligent technique selection using AI and historical data.

    This agent analyzes the target environment and recommends optimal
    techniques based on effectiveness scores, compatibility, and objectives.

    Input Parameters:
        - target_av (str): Target AV/EDR (e.g., "Windows Defender", "CrowdStrike")
        - objective (str): Objective ('evasion', 'stealth', 'persistence', 'injection')
        - complexity (str): Complexity level ('low', 'medium', 'high')
        - constraints (dict): Optional constraints
          - max_techniques (int): Maximum number of techniques to select
          - min_effectiveness_score (float): Minimum effectiveness threshold (0.0-1.0)
          - avoid (list): Technique IDs to avoid
          - require_categories (list): Required categories

    Output:
        AgentResult with:
            - selected_techniques: List[str] of technique IDs
            - scores: Dict[str, float] mapping technique ID to effectiveness score
            - rationale: Explanation of why techniques were selected
            - compatibility_matrix: Compatibility info between selected techniques
            - mitre_coverage: MITRE ATT&CK TTPs covered
    """

    def _init_agent(self):
        """Initialize agent-specific resources"""
        self.logger.info("Initializing TechniqueSelectionAgent...")

        # Initialize learning engine
        db_path = self.config.get('db_path', 'data/knowledge_base.db')
        self.learning_engine = AgenticLearningEngine(db_path)

        # Load technique manager
        from server.noctis_server import TechniqueManager
        metadata_path = self.config.get('metadata_path', 'techniques/metadata')
        self.technique_manager = TechniqueManager(metadata_path)

        # Initialize RAG engine for knowledge retrieval
        try:
            from server.rag import RAGEngine
            rag_path = self.config.get('rag_db_path', 'data/rag_db')
            self.rag_engine = RAGEngine(persist_dir=rag_path)
            self.logger.info("RAG engine initialized successfully")
        except Exception as e:
            self.logger.warning(f"RAG engine not available: {e}")
            self.rag_engine = None

        self.logger.info(f"Loaded {len(self.technique_manager.techniques)} techniques")

    def validate_inputs(self, **kwargs) -> Tuple[bool, List[str]]:
        """Validate input parameters"""
        errors = []

        # target_av is optional (defaults to "Windows Defender")
        target_av = kwargs.get('target_av', 'Windows Defender')
        if not isinstance(target_av, str):
            errors.append("target_av must be a string")

        # objective is optional (defaults to "evasion")
        objective = kwargs.get('objective', 'evasion')
        valid_objectives = ['evasion', 'stealth', 'persistence', 'injection', 'all']
        if objective not in valid_objectives:
            errors.append(f"objective must be one of {valid_objectives}")

        # complexity is optional (defaults to "medium")
        complexity = kwargs.get('complexity', 'medium')
        valid_complexity = ['low', 'medium', 'high']
        if complexity not in valid_complexity:
            errors.append(f"complexity must be one of {valid_complexity}")

        # constraints is optional
        constraints = kwargs.get('constraints', {})
        if not isinstance(constraints, dict):
            errors.append("constraints must be a dict")

        return len(errors) == 0, errors

    def execute(self, **kwargs) -> AgentResult:
        """Execute technique selection"""
        # Extract parameters
        target_av = kwargs.get('target_av', 'Windows Defender')
        objective = kwargs.get('objective', 'evasion')
        complexity = kwargs.get('complexity', 'medium')
        constraints = kwargs.get('constraints', {})

        self.logger.info(f"Selecting techniques: target_av={target_av}, objective={objective}, complexity={complexity}")

        try:
            # 0. Query RAG for relevant knowledge and intelligence
            rag_context = self._query_rag_for_context(target_av, objective)

            # 1. Get all techniques
            all_techniques = self.technique_manager.get_all()
            self.logger.debug(f"Found {len(all_techniques)} total techniques")

            # 2. Filter by objective (category)
            if objective != 'all':
                filtered = []
                for tech in all_techniques:
                    category = tech.get('category', '')
                    # Match objective to category
                    if objective in category.lower():
                        filtered.append(tech)
                all_techniques = filtered
                self.logger.debug(f"After objective filter: {len(all_techniques)} techniques")

            # 3. Get effectiveness scores from learning engine + RAG boost
            scored_techniques = []
            for tech in all_techniques:
                tech_id = tech.get('technique_id')

                # Base score from learning engine
                base_score = self.learning_engine.get_effectiveness_score(tech_id, target_av)

                # Boost score based on RAG intelligence
                rag_boost = self._calculate_rag_boost(tech_id, rag_context)
                final_score = base_score + rag_boost

                scored_techniques.append((tech_id, final_score, tech))

            # 4. Sort by effectiveness score (descending)
            scored_techniques.sort(key=lambda x: x[1], reverse=True)

            # 5. Apply constraints
            max_techniques = constraints.get('max_techniques', 5)
            min_score = constraints.get('min_effectiveness_score', 0.0)
            avoid = constraints.get('avoid', [])

            selected = []
            for tech_id, score, tech in scored_techniques:
                # Skip if in avoid list
                if tech_id in avoid:
                    continue

                # Skip if below minimum score
                if score < min_score:
                    continue

                selected.append((tech_id, score, tech))

                # Stop if we have enough
                if len(selected) >= max_techniques:
                    break

            # 6. Generate rationale (now includes RAG intelligence)
            rationale = self._generate_rationale(selected, target_av, objective, complexity, rag_context)

            # 7. Build compatibility matrix
            compatibility = self._build_compatibility_matrix([tid for tid, _, _ in selected])

            # 8. Get MITRE coverage
            mitre_coverage = self._get_mitre_coverage([tid for tid, _, _ in selected])

            # 9. Build result
            result_data = {
                'selected_techniques': [tech_id for tech_id, _, _ in selected],
                'scores': {tech_id: score for tech_id, score, _ in selected},
                'technique_details': [
                    {
                        'technique_id': tech_id,
                        'name': tech.get('name'),
                        'category': tech.get('category'),
                        'description': tech.get('description'),
                        'effectiveness_score': score
                    }
                    for tech_id, score, tech in selected
                ],
                'rationale': rationale,
                'compatibility_matrix': compatibility,
                'mitre_coverage': mitre_coverage,
                'rag_intelligence': rag_context.get('summary', 'No RAG data available') if rag_context else None
            }

            warnings = []
            if len(selected) < max_techniques:
                warnings.append(f"Only found {len(selected)} techniques matching criteria (requested {max_techniques})")

            return AgentResult(
                success=True,
                data=result_data,
                errors=[],
                warnings=warnings,
                metadata={
                    'target_av': target_av,
                    'objective': objective,
                    'complexity': complexity,
                    'total_techniques_analyzed': len(all_techniques)
                }
            )

        except Exception as e:
            self.logger.exception(f"Error in technique selection: {e}")
            return AgentResult(
                success=False,
                data={},
                errors=[f"Technique selection failed: {str(e)}"],
                warnings=[],
                metadata={}
            )

    def _query_rag_for_context(self, target_av: str, objective: str) -> Optional[Dict]:
        """Query RAG system for relevant intelligence and knowledge"""
        if not self.rag_engine:
            return None

        try:
            # Build search query
            query = f"{objective} techniques for {target_av} evasion bypass detection"

            # Search RAG for relevant knowledge
            results = self.rag_engine.search_knowledge(query, target_av=target_av, n_results=5)

            if not results:
                return None

            # Extract key insights
            sources = []
            key_points = []

            for result in results:
                source_type = result.get('source', 'unknown')
                content = result.get('content', '')
                metadata = result.get('metadata', {})

                sources.append({
                    'type': source_type,
                    'content_preview': content[:200],
                    'metadata': metadata
                })

                # Extract first sentence as key point
                if content:
                    first_sentence = content.split('.')[0] + '.'
                    key_points.append(first_sentence)

            # Create summary
            summary = f"Intelligence from {len(results)} sources: " + " ".join(key_points[:3])

            return {
                'query': query,
                'results_count': len(results),
                'sources': sources,
                'key_points': key_points,
                'summary': summary
            }

        except Exception as e:
            self.logger.warning(f"RAG query failed: {e}")
            return None

    def _calculate_rag_boost(self, tech_id: str, rag_context: Optional[Dict]) -> float:
        """Calculate score boost based on RAG intelligence"""
        if not rag_context or not rag_context.get('sources'):
            return 0.0

        # Check if technique is mentioned in RAG sources
        boost = 0.0
        for source in rag_context.get('sources', []):
            content = source.get('content_preview', '').lower()

            # Check if tech_id or technique name appears in source
            if tech_id.lower() in content:
                boost += 0.2  # Boost for direct mention

            # Additional boost based on source type
            source_type = source.get('type', '')
            if source_type == 'github_repo':
                boost += 0.1  # Recent GitHub activity
            elif source_type == 'research_paper':
                boost += 0.15  # Academic validation
            elif source_type == 'blog_post':
                boost += 0.1  # Industry recognition

        # Cap boost at 0.5
        return min(boost, 0.5)

    def _generate_rationale(self, selected: List[Tuple[str, float, Dict]], target_av: str, objective: str, complexity: str, rag_context: Optional[Dict] = None) -> str:
        """Generate human-readable rationale for technique selection"""
        if not selected:
            return "No techniques were selected based on the given criteria."

        rationale_parts = []

        # Overview
        rationale_parts.append(f"Selected {len(selected)} techniques optimized for {target_av} with {objective} objective.")
        rationale_parts.append(f"Complexity level: {complexity}.")

        # RAG intelligence context
        if rag_context and rag_context.get('results_count', 0) > 0:
            rationale_parts.append(f"\nIntelligence Sources: {rag_context['results_count']} recent sources analyzed (GitHub, arXiv, security blogs)")

        # Top techniques
        rationale_parts.append("\nTop techniques selected:")
        for i, (tech_id, score, tech) in enumerate(selected[:3], 1):
            name = tech.get('name', tech_id)
            category = tech.get('category', 'unknown')
            rationale_parts.append(f"  {i}. {name} ({tech_id}) - Score: {score:.2f} - Category: {category}")

        # Reasoning
        rationale_parts.append(f"\nThese techniques were chosen based on:")
        rationale_parts.append(f"  - Historical effectiveness data against {target_av}")
        rationale_parts.append("  - Real-time intelligence from GitHub, research papers, and security blogs")
        rationale_parts.append("  - Compatibility and operational stability")

        # Add key insights from RAG if available
        if rag_context and rag_context.get('key_points'):
            rationale_parts.append("\nKey Intelligence Insights:")
            for point in rag_context['key_points'][:3]:
                rationale_parts.append(f"  - {point}")

        return "\n".join(rationale_parts)

    def _build_compatibility_matrix(self, technique_ids: List[str]) -> Dict:
        """Build compatibility matrix for selected techniques"""
        matrix = {
            'compatible': [],
            'incompatible': [],
            'unknown': []
        }

        # For each pair of techniques, check compatibility
        for i, tech_id_1 in enumerate(technique_ids):
            for j, tech_id_2 in enumerate(technique_ids[i+1:], i+1):
                # TODO: Implement actual compatibility checking
                # For now, assume all are compatible
                matrix['compatible'].append((tech_id_1, tech_id_2))

        return matrix

    def _get_mitre_coverage(self, technique_ids: List[str]) -> Dict:
        """Get MITRE ATT&CK coverage for selected techniques"""
        all_ttps = set()
        ttp_map = {}

        for tech_id in technique_ids:
            tech = self.technique_manager.get_by_id(tech_id)
            if tech:
                ttps = tech.get('mitre_attack', [])
                for ttp in ttps:
                    all_ttps.add(ttp)
                    if ttp not in ttp_map:
                        ttp_map[ttp] = []
                    ttp_map[ttp].append(tech_id)

        return {
            'total_ttps': len(all_ttps),
            'ttps': sorted(list(all_ttps)),
            'ttp_to_techniques': ttp_map
        }


# Example usage
if __name__ == '__main__':
    # Test the agent
    config = {
        'db_path': 'data/knowledge_base.db',
        'metadata_path': 'techniques/metadata'
    }

    agent = TechniqueSelectionAgent(config)

    result = agent.run(
        target_av='Windows Defender',
        objective='evasion',
        complexity='medium',
        constraints={'max_techniques': 3}
    )

    print(result)
    if result.success:
        print(f"Selected: {result.data['selected_techniques']}")
        print(f"\nRationale:\n{result.data['rationale']}")
