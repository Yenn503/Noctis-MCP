#!/usr/bin/env python3
"""
Noctis-MCP Educational System
==============================

Interactive learning system for offensive security techniques.

Features:
- Structured curriculum with difficulty progression
- Curated lessons with fixed content (no RAG for consistency)
- Interactive lessons with code examples
- Progress tracking and quizzes
- Hands-on labs and challenges

Author: Noctis-MCP Community
License: MIT
"""

from .learning_engine import LearningCurriculum, ProgressTracker
from .lesson_manager import LessonManager

__all__ = [
    'LearningCurriculum',
    'ProgressTracker',
    'LessonManager'
]
