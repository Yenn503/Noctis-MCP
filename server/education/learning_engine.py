#!/usr/bin/env python3
"""
Noctis-MCP Learning Engine
===========================

Core educational system providing structured learning paths,
progress tracking, and AI-powered tutoring.

Author: Noctis-MCP Community
License: MIT
"""

import sqlite3
import json
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class LessonModule:
    """Represents a single module within a lesson"""
    number: int
    title: str
    content_type: str  # theory, technical, code_walkthrough, lab, quiz
    duration_minutes: int
    topics: List[str] = field(default_factory=list)
    rag_queries: List[str] = field(default_factory=list)
    github_examples: List[str] = field(default_factory=list)
    challenge: Dict = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return {
            'number': self.number,
            'title': self.title,
            'content_type': self.content_type,
            'duration_minutes': self.duration_minutes,
            'topics': self.topics,
            'rag_queries': self.rag_queries,
            'github_examples': self.github_examples,
            'challenge': self.challenge
        }


@dataclass
class Lesson:
    """Complete lesson for a technique"""
    technique_id: str
    title: str
    difficulty: str  # beginner, intermediate, advanced
    estimated_minutes: int
    prerequisites: List[str] = field(default_factory=list)
    modules: List[LessonModule] = field(default_factory=list)
    description: str = ""
    learning_objectives: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            'technique_id': self.technique_id,
            'title': self.title,
            'difficulty': self.difficulty,
            'estimated_minutes': self.estimated_minutes,
            'prerequisites': self.prerequisites,
            'description': self.description,
            'learning_objectives': self.learning_objectives,
            'modules': [m.to_dict() for m in self.modules]
        }


@dataclass
class UserProgress:
    """Tracks user progress for a lesson"""
    technique_id: str
    modules_completed: List[int] = field(default_factory=list)
    quiz_score: int = 0
    quiz_attempts: int = 0
    completed_at: Optional[str] = None
    time_spent_minutes: int = 0
    status: str = "not_started"  # not_started, in_progress, completed
    current_module: int = 1

    def completion_percentage(self, total_modules: int) -> int:
        """Calculate completion percentage"""
        if total_modules == 0:
            return 0
        return int((len(self.modules_completed) / total_modules) * 100)


@dataclass
class Achievement:
    """User achievement/badge"""
    id: str
    name: str
    description: str
    icon: str
    earned_at: Optional[str] = None

    def to_dict(self) -> Dict:
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'icon': self.icon,
            'earned_at': self.earned_at
        }


class ProgressTracker:
    """Manages user learning progress and achievements"""

    def __init__(self, db_path: str = "data/learning_progress.db"):
        # Handle in-memory database for testing
        if db_path == ':memory:':
            self.db_path = ':memory:'
            self._memory_conn = None  # Will store persistent connection for in-memory DB
        else:
            self.db_path = Path(db_path)
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            self._memory_conn = None
        self._init_database()

    def _get_connection(self):
        """Get database connection (reuses in-memory connection)"""
        if self.db_path == ':memory:':
            if self._memory_conn is None:
                self._memory_conn = sqlite3.connect(':memory:', check_same_thread=False)
            return self._memory_conn
        else:
            return sqlite3.connect(self.db_path)

    def _close_connection(self, conn):
        """Close connection (except for in-memory which stays open)"""
        if self.db_path != ':memory:':
            conn.close()

    def _init_database(self):
        """Initialize SQLite database"""
        conn = self._get_connection()
        cursor = conn.cursor()

        # User progress table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS user_progress (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                technique_id TEXT NOT NULL UNIQUE,
                modules_completed TEXT NOT NULL,
                quiz_score INTEGER DEFAULT 0,
                quiz_attempts INTEGER DEFAULT 0,
                completed_at TEXT,
                time_spent_minutes INTEGER DEFAULT 0,
                status TEXT DEFAULT 'not_started',
                current_module INTEGER DEFAULT 1,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Achievements table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS achievements (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT,
                icon TEXT,
                earned_at TEXT
            )
        ''')

        # Quiz attempts table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS quiz_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                technique_id TEXT NOT NULL,
                total_questions INTEGER,
                correct_answers INTEGER,
                score INTEGER,
                timestamp TEXT DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        conn.commit()
        self._close_connection(conn)
        logger.info("Learning progress database initialized")

    def get_progress(self, technique_id: str) -> Optional[UserProgress]:
        """Get progress for a specific technique"""
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute('''
            SELECT technique_id, modules_completed, quiz_score, quiz_attempts,
                   completed_at, time_spent_minutes, status, current_module
            FROM user_progress
            WHERE technique_id = ?
        ''', (technique_id,))

        row = cursor.fetchone()
        self._close_connection(conn)

        if not row:
            return UserProgress(technique_id=technique_id)

        return UserProgress(
            technique_id=row[0],
            modules_completed=json.loads(row[1]),
            quiz_score=row[2],
            quiz_attempts=row[3],
            completed_at=row[4],
            time_spent_minutes=row[5],
            status=row[6],
            current_module=row[7]
        )

    def update_progress(self, progress: UserProgress):
        """Update user progress"""
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute('''
            INSERT OR REPLACE INTO user_progress
            (technique_id, modules_completed, quiz_score, quiz_attempts,
             completed_at, time_spent_minutes, status, current_module, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        ''', (
            progress.technique_id,
            json.dumps(progress.modules_completed),
            progress.quiz_score,
            progress.quiz_attempts,
            progress.completed_at,
            progress.time_spent_minutes,
            progress.status,
            progress.current_module
        ))

        conn.commit()
        self._close_connection(conn)
        logger.info(f"Progress updated for {progress.technique_id}")

    def complete_module(self, technique_id: str, module_number: int, time_minutes: int = 0):
        """Mark a module as completed"""
        progress = self.get_progress(technique_id)

        if module_number not in progress.modules_completed:
            progress.modules_completed.append(module_number)
            progress.modules_completed.sort()

        progress.current_module = module_number + 1
        progress.time_spent_minutes += time_minutes
        progress.status = "in_progress"

        self.update_progress(progress)
        logger.info(f"Module {module_number} completed for {technique_id}")

    def record_quiz_attempt(self, technique_id: str, total: int, correct: int):
        """Record a quiz attempt"""
        conn = self._get_connection()
        cursor = conn.cursor()

        score = int((correct / total) * 100) if total > 0 else 0

        # Record attempt
        cursor.execute('''
            INSERT INTO quiz_attempts (technique_id, total_questions, correct_answers, score)
            VALUES (?, ?, ?, ?)
        ''', (technique_id, total, correct, score))

        # Update progress
        progress = self.get_progress(technique_id)
        progress.quiz_score = score
        progress.quiz_attempts += 1

        # Mark complete if passed (70% threshold)
        if score >= 70:
            progress.status = "completed"
            progress.completed_at = datetime.now().isoformat()

        self.update_progress(progress)

        conn.commit()
        self._close_connection(conn)

        logger.info(f"Quiz attempt recorded: {technique_id} - {score}%")
        return score

    def get_all_progress(self) -> List[UserProgress]:
        """Get progress for all techniques"""
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute('''
            SELECT technique_id, modules_completed, quiz_score, quiz_attempts,
                   completed_at, time_spent_minutes, status, current_module
            FROM user_progress
            ORDER BY updated_at DESC
        ''')

        rows = cursor.fetchall()
        self._close_connection(conn)

        progress_list = []
        for row in rows:
            progress_list.append(UserProgress(
                technique_id=row[0],
                modules_completed=json.loads(row[1]),
                quiz_score=row[2],
                quiz_attempts=row[3],
                completed_at=row[4],
                time_spent_minutes=row[5],
                status=row[6],
                current_module=row[7]
            ))

        return progress_list

    def earn_achievement(self, achievement: Achievement):
        """Award an achievement to user"""
        conn = self._get_connection()
        cursor = conn.cursor()

        achievement.earned_at = datetime.now().isoformat()

        cursor.execute('''
            INSERT OR REPLACE INTO achievements (id, name, description, icon, earned_at)
            VALUES (?, ?, ?, ?, ?)
        ''', (achievement.id, achievement.name, achievement.description,
              achievement.icon, achievement.earned_at))

        conn.commit()
        self._close_connection(conn)

        logger.info(f"Achievement earned: {achievement.name}")
        return achievement

    def get_achievements(self) -> List[Achievement]:
        """Get all earned achievements"""
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute('SELECT id, name, description, icon, earned_at FROM achievements')
        rows = cursor.fetchall()
        self._close_connection(conn)

        return [Achievement(id=r[0], name=r[1], description=r[2],
                           icon=r[3], earned_at=r[4]) for r in rows]

    def get_all_achievements(self) -> List[Dict]:
        """Get all earned achievements as dictionaries for API response"""
        achievements = self.get_achievements()
        return [
            {
                'id': ach.id,
                'name': ach.name,
                'description': ach.description,
                'icon': ach.icon,
                'earned_at': ach.earned_at
            }
            for ach in achievements
        ]

    def get_quiz_history(self) -> List[Dict]:
        """Get quiz attempt history"""
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute('''
            SELECT technique_id, total_questions, correct_answers, timestamp
            FROM quiz_attempts
            ORDER BY timestamp DESC
        ''')

        rows = cursor.fetchall()
        self._close_connection(conn)

        return [
            {
                'technique_id': r[0],
                'total_questions': r[1],
                'correct_answers': r[2],
                'score': round((r[2] / r[1]) * 100) if r[1] > 0 else 0,
                'timestamp': r[3]
            }
            for r in rows
        ]

    def check_and_award_achievements(self, technique_id: str, progress: UserProgress):
        """Check if user earned any achievements"""
        achievements = []

        # First lesson completed
        all_progress = self.get_all_progress()
        completed = [p for p in all_progress if p.status == 'completed']

        if len(completed) == 1 and progress.status == 'completed':
            achievements.append(self.earn_achievement(Achievement(
                id="first_lesson",
                name="First Lesson",
                description="Complete your first technique",
                icon="🏆"
            )))

        # Perfect score
        if progress.quiz_score == 100:
            achievements.append(self.earn_achievement(Achievement(
                id=f"perfect_{progress.technique_id}",
                name=f"{progress.technique_id} Master",
                description="Score 100% on quiz",
                icon="💯"
            )))

        # Speed learner (complete in under estimated time)
        # Add more achievement logic here

        return achievements


class LearningCurriculum:
    """Manages the complete learning curriculum"""

    def __init__(self, lessons_file: str = "data/lessons.json", rag_engine=None):
        self.lessons_file = Path(lessons_file)
        self.rag_engine = rag_engine
        self.lessons: Dict[str, Lesson] = {}
        self._load_curriculum()

    def _load_curriculum(self):
        """Load curriculum from JSON file"""
        if not self.lessons_file.exists():
            logger.warning(f"Lessons file not found: {self.lessons_file}")
            return

        with open(self.lessons_file, 'r') as f:
            data = json.load(f)

        for lesson_data in data:
            modules = [
                LessonModule(**module_data)
                for module_data in lesson_data.get('modules', [])
            ]

            lesson = Lesson(
                technique_id=lesson_data['technique_id'],
                title=lesson_data['title'],
                difficulty=lesson_data['difficulty'],
                estimated_minutes=lesson_data['estimated_minutes'],
                prerequisites=lesson_data.get('prerequisites', []),
                modules=modules,
                description=lesson_data.get('description', ''),
                learning_objectives=lesson_data.get('learning_objectives', [])
            )

            self.lessons[lesson.technique_id] = lesson

        logger.info(f"Loaded {len(self.lessons)} lessons from curriculum")

    def get_lesson(self, technique_id: str) -> Optional[Lesson]:
        """Get a lesson by technique ID"""
        return self.lessons.get(technique_id)

    def list_all_lessons(self) -> List[Lesson]:
        """Get all lessons sorted by difficulty"""
        difficulty_order = {'beginner': 1, 'intermediate': 2, 'advanced': 3}
        return sorted(
            self.lessons.values(),
            key=lambda l: (difficulty_order.get(l.difficulty, 99), l.technique_id)
        )

    def get_lessons_by_difficulty(self, difficulty: str) -> List[Lesson]:
        """Get lessons filtered by difficulty"""
        return [l for l in self.lessons.values() if l.difficulty == difficulty]

    def get_recommended_next(self, completed_ids: List[str]) -> Optional[Lesson]:
        """Get recommended next lesson based on completed lessons"""
        for lesson in self.list_all_lessons():
            # Skip if already completed
            if lesson.technique_id in completed_ids:
                continue

            # Check if prerequisites are met
            if all(prereq in completed_ids for prereq in lesson.prerequisites):
                return lesson

        return None

    def search_lessons(self, query: str) -> List[Lesson]:
        """Search lessons by keyword"""
        query_lower = query.lower()
        results = []

        for lesson in self.lessons.values():
            if (query_lower in lesson.title.lower() or
                query_lower in lesson.description.lower() or
                query_lower in lesson.technique_id.lower()):
                results.append(lesson)

        return results
