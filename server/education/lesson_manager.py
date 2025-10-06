"""
Lesson Manager - Loads and serves curated lessons from lessons.json

This module provides simple access to the structured curriculum
without any RAG or dynamic generation.
"""

import json
import logging
from typing import Dict, List, Optional
from pathlib import Path
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class CodeExample:
    """Code example within a lesson"""
    language: str
    title: str
    filename: str
    description: str


@dataclass
class LessonModule:
    """Individual module within a lesson"""
    module_number: int
    title: str
    type: str  # theory, code, lab, quiz
    content: str
    code_examples: List[CodeExample] = field(default_factory=list)


@dataclass
class Technique:
    """Complete technique/lesson"""
    id: str
    title: str
    category: str
    difficulty: str
    estimated_minutes: int
    prerequisites: List[str]
    description: str
    modules: List[LessonModule]


class LessonManager:
    """Manages loading and serving curated lessons"""

    def __init__(self, lessons_file: str = None):
        if lessons_file is None:
            # Default to data/lessons.json
            lessons_file = Path(__file__).parent.parent.parent / "data" / "lessons.json"

        self.lessons_file = Path(lessons_file)
        self.techniques: Dict[str, Technique] = {}
        self._load_lessons()

    def _load_lessons(self):
        """Load all lessons from JSON file"""
        try:
            if not self.lessons_file.exists():
                logger.error(f"Lessons file not found: {self.lessons_file}")
                return

            with open(self.lessons_file, 'r', encoding='utf-8') as f:
                data = json.load(f)

            for tech_data in data.get('techniques', []):
                # Parse modules
                modules = []
                for mod_data in tech_data.get('modules', []):
                    # Parse code examples if present
                    code_examples = []
                    for ex_data in mod_data.get('code_examples', []):
                        code_examples.append(CodeExample(**ex_data))

                    modules.append(LessonModule(
                        module_number=mod_data['module_number'],
                        title=mod_data['title'],
                        type=mod_data['type'],
                        content=mod_data['content'],
                        code_examples=code_examples
                    ))

                # Create technique
                technique = Technique(
                    id=tech_data['id'],
                    title=tech_data['title'],
                    category=tech_data['category'],
                    difficulty=tech_data['difficulty'],
                    estimated_minutes=tech_data['estimated_minutes'],
                    prerequisites=tech_data['prerequisites'],
                    description=tech_data['description'],
                    modules=modules
                )

                self.techniques[technique.id] = technique

            logger.info(f"Loaded {len(self.techniques)} techniques from {self.lessons_file}")

        except Exception as e:
            logger.error(f"Failed to load lessons: {e}", exc_info=True)

    def list_all_techniques(self, sort_by: str = 'difficulty') -> List[Dict]:
        """
        Get list of all available techniques

        Args:
            sort_by: 'difficulty', 'category', or 'title'

        Returns:
            List of technique summaries
        """
        techniques = list(self.techniques.values())

        # Sort based on requested field
        if sort_by == 'difficulty':
            difficulty_order = {'beginner': 1, 'intermediate': 2, 'advanced': 3}
            techniques.sort(key=lambda t: difficulty_order.get(t.difficulty, 99))
        elif sort_by == 'category':
            techniques.sort(key=lambda t: t.category)
        elif sort_by == 'title':
            techniques.sort(key=lambda t: t.title)

        return [
            {
                'id': t.id,
                'title': t.title,
                'category': t.category,
                'difficulty': t.difficulty,
                'estimated_minutes': t.estimated_minutes,
                'prerequisites': t.prerequisites,
                'description': t.description,
                'module_count': len(t.modules)
            }
            for t in techniques
        ]

    def get_technique(self, technique_id: str) -> Optional[Technique]:
        """Get complete technique by ID"""
        return self.techniques.get(technique_id)

    def get_technique_summary(self, technique_id: str) -> Optional[Dict]:
        """Get technique summary without full content"""
        technique = self.techniques.get(technique_id)
        if not technique:
            return None

        return {
            'id': technique.id,
            'title': technique.title,
            'category': technique.category,
            'difficulty': technique.difficulty,
            'estimated_minutes': technique.estimated_minutes,
            'prerequisites': technique.prerequisites,
            'description': technique.description,
            'modules': [
                {
                    'module_number': m.module_number,
                    'title': m.title,
                    'type': m.type
                }
                for m in technique.modules
            ]
        }

    def get_module(self, technique_id: str, module_number: int) -> Optional[LessonModule]:
        """Get specific module from a technique"""
        technique = self.techniques.get(technique_id)
        if not technique:
            return None

        for module in technique.modules:
            if module.module_number == module_number:
                return module

        return None

    def get_module_content(self, technique_id: str, module_number: int) -> Optional[Dict]:
        """Get module content in dictionary format"""
        module = self.get_module(technique_id, module_number)
        if not module:
            return None

        return {
            'module_number': module.module_number,
            'title': module.title,
            'type': module.type,
            'content': module.content,
            'code_examples': [
                {
                    'language': ex.language,
                    'title': ex.title,
                    'filename': ex.filename,
                    'description': ex.description
                }
                for ex in module.code_examples
            ]
        }

    def search_techniques(self, query: str) -> List[Dict]:
        """
        Search techniques by keyword in title or description

        Args:
            query: Search term

        Returns:
            List of matching technique summaries
        """
        query_lower = query.lower()
        results = []

        for technique in self.techniques.values():
            # Search in title and description
            if (query_lower in technique.title.lower() or
                query_lower in technique.description.lower() or
                query_lower in technique.category.lower()):

                results.append({
                    'id': technique.id,
                    'title': technique.title,
                    'category': technique.category,
                    'difficulty': technique.difficulty,
                    'description': technique.description
                })

        return results

    def get_recommended_next(self, completed_ids: List[str]) -> Optional[Dict]:
        """
        Get recommended next technique based on completed lessons

        Args:
            completed_ids: List of completed technique IDs

        Returns:
            Recommended technique summary or None
        """
        completed_set = set(completed_ids)

        # Find techniques where all prerequisites are completed
        available = []
        for technique in self.techniques.values():
            if technique.id in completed_set:
                continue  # Already completed

            # Check if all prerequisites are met
            prereqs_met = all(
                prereq in completed_set
                for prereq in technique.prerequisites
            )

            if prereqs_met:
                available.append(technique)

        if not available:
            return None

        # Sort by difficulty (beginner first)
        difficulty_order = {'beginner': 1, 'intermediate': 2, 'advanced': 3}
        available.sort(key=lambda t: difficulty_order.get(t.difficulty, 99))

        # Return first available
        next_tech = available[0]
        return {
            'id': next_tech.id,
            'title': next_tech.title,
            'category': next_tech.category,
            'difficulty': next_tech.difficulty,
            'estimated_minutes': next_tech.estimated_minutes,
            'description': next_tech.description
        }

    def get_techniques_by_category(self) -> Dict[str, List[Dict]]:
        """Group techniques by category"""
        categories = {}

        for technique in self.techniques.values():
            if technique.category not in categories:
                categories[technique.category] = []

            categories[technique.category].append({
                'id': technique.id,
                'title': technique.title,
                'difficulty': technique.difficulty,
                'estimated_minutes': technique.estimated_minutes
            })

        # Sort each category by difficulty
        difficulty_order = {'beginner': 1, 'intermediate': 2, 'advanced': 3}
        for category in categories:
            categories[category].sort(
                key=lambda t: difficulty_order.get(t['difficulty'], 99)
            )

        return categories

    def get_techniques_by_difficulty(self, difficulty: str) -> List[Dict]:
        """Get all techniques of a specific difficulty level"""
        techniques = [
            t for t in self.techniques.values()
            if t.difficulty == difficulty
        ]

        return [
            {
                'id': t.id,
                'title': t.title,
                'category': t.category,
                'estimated_minutes': t.estimated_minutes,
                'description': t.description
            }
            for t in techniques
        ]

    def validate_learning_path(self, technique_id: str, completed_ids: List[str]) -> Dict:
        """
        Check if user can start a technique based on prerequisites

        Args:
            technique_id: Technique to check
            completed_ids: List of completed technique IDs

        Returns:
            Dictionary with 'allowed' boolean and 'missing_prerequisites' list
        """
        technique = self.techniques.get(technique_id)
        if not technique:
            return {'allowed': False, 'error': 'Technique not found'}

        completed_set = set(completed_ids)
        missing = [
            prereq for prereq in technique.prerequisites
            if prereq not in completed_set
        ]

        return {
            'allowed': len(missing) == 0,
            'missing_prerequisites': missing,
            'technique_title': technique.title
        }

    def get_stats(self) -> Dict:
        """Get statistics about the curriculum"""
        total_minutes = sum(t.estimated_minutes for t in self.techniques.values())

        by_difficulty = {}
        by_category = {}

        for technique in self.techniques.values():
            # Count by difficulty
            by_difficulty[technique.difficulty] = by_difficulty.get(technique.difficulty, 0) + 1

            # Count by category
            by_category[technique.category] = by_category.get(technique.category, 0) + 1

        return {
            'total_techniques': len(self.techniques),
            'total_estimated_hours': round(total_minutes / 60, 1),
            'by_difficulty': by_difficulty,
            'by_category': by_category
        }
