"""
Education API - Flask endpoints for the learning system

Provides RESTful API for accessing curated lessons, tracking progress,
and managing the educational experience.
"""

from flask import Blueprint, request, jsonify
import logging
from typing import Dict, Optional
import time

from server.education.learning_engine import ProgressTracker
from server.education.lesson_manager import LessonManager
import json
from pathlib import Path

logger = logging.getLogger(__name__)

# Create blueprint
education_bp = Blueprint('education', __name__, url_prefix='/api/v2/education')

# Global instances (will be initialized in init_education_api)
education_bp.lesson_manager: Optional[LessonManager] = None
education_bp.progress_tracker: Optional[ProgressTracker] = None
education_bp.quiz_data: Optional[Dict] = None


def init_education_api(config: dict):
    """
    Initialize education system

    Args:
        config: Configuration dictionary
    """
    try:
        # Initialize lesson manager
        lessons_path = config.get('lessons_path', 'data/lessons.json')
        education_bp.lesson_manager = LessonManager(lessons_path)

        # Initialize progress tracker
        db_path = config.get('education_db', 'data/education_progress.db')
        education_bp.progress_tracker = ProgressTracker(db_path)

        # Load quiz data
        quizzes_path = config.get('quizzes_path', 'data/quizzes.json')
        quizzes_file = Path(quizzes_path)
        if quizzes_file.exists():
            with open(quizzes_file, 'r', encoding='utf-8') as f:
                education_bp.quiz_data = json.load(f)
        else:
            logger.warning(f"Quiz file not found: {quizzes_path}")
            education_bp.quiz_data = {"quizzes": {}}

        logger.info("Education API initialized successfully")

    except Exception as e:
        logger.error(f"Failed to initialize education API: {e}", exc_info=True)
        raise


# ============================================================================
# LESSON ENDPOINTS
# ============================================================================

@education_bp.route('/topics', methods=['GET'])
def list_topics():
    """
    List all available learning topics

    Query params:
        sort_by: difficulty (default), category, or title
        difficulty: Filter by difficulty (beginner/intermediate/advanced)
        category: Filter by category

    Returns:
        JSON list of topics with metadata
    """
    try:
        sort_by = request.args.get('sort_by', 'difficulty')
        difficulty_filter = request.args.get('difficulty')
        category_filter = request.args.get('category')

        # Get all techniques
        topics = education_bp.lesson_manager.list_all_techniques(sort_by=sort_by)

        # Apply filters
        if difficulty_filter:
            topics = [t for t in topics if t['difficulty'] == difficulty_filter]

        if category_filter:
            topics = [t for t in topics if t['category'] == category_filter]

        return jsonify({
            'success': True,
            'count': len(topics),
            'topics': topics
        })

    except Exception as e:
        logger.error(f"Error listing topics: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500


@education_bp.route('/topics/categories', methods=['GET'])
def list_by_category():
    """Get topics grouped by category"""
    try:
        categories = education_bp.lesson_manager.get_techniques_by_category()

        return jsonify({
            'success': True,
            'categories': categories
        })

    except Exception as e:
        logger.error(f"Error listing categories: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500


@education_bp.route('/topic/<technique_id>', methods=['GET'])
def get_topic(technique_id: str):
    """
    Get overview of a specific topic (without full content)

    Returns:
        Topic metadata and module list
    """
    try:
        summary = education_bp.lesson_manager.get_technique_summary(technique_id)

        if not summary:
            return jsonify({
                'success': False,
                'error': f'Topic not found: {technique_id}'
            }), 404

        return jsonify({
            'success': True,
            'topic': summary
        })

    except Exception as e:
        logger.error(f"Error getting topic {technique_id}: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500


@education_bp.route('/lesson/<technique_id>/module/<int:module_number>', methods=['GET'])
def get_lesson_module(technique_id: str, module_number: int):
    """
    Get specific lesson module content

    Returns:
        Module content with theory, code examples, etc.
    """
    try:
        module = education_bp.lesson_manager.get_module_content(technique_id, module_number)

        if not module:
            return jsonify({
                'success': False,
                'error': f'Module {module_number} not found for {technique_id}'
            }), 404

        # Record that user started this module
        progress = education_bp.progress_tracker.get_progress(technique_id)
        if progress is None:
            from server.education.learning_engine import UserProgress
            progress = UserProgress(technique_id=technique_id)
        progress.current_module = module_number
        progress.status = 'in_progress'
        education_bp.progress_tracker.update_progress(progress)

        return jsonify({
            'success': True,
            'technique_id': technique_id,
            'module': module
        })

    except Exception as e:
        logger.error(f"Error getting module {module_number} for {technique_id}: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500


@education_bp.route('/search', methods=['GET'])
def search_topics():
    """
    Search topics by keyword

    Query params:
        q: Search query

    Returns:
        Matching topics
    """
    try:
        query = request.args.get('q', '')

        if not query:
            return jsonify({
                'success': False,
                'error': 'Query parameter "q" is required'
            }), 400

        results = education_bp.lesson_manager.search_techniques(query)

        return jsonify({
            'success': True,
            'query': query,
            'count': len(results),
            'results': results
        })

    except Exception as e:
        logger.error(f"Error searching topics: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500


# ============================================================================
# PROGRESS TRACKING ENDPOINTS
# ============================================================================

@education_bp.route('/progress', methods=['GET'])
def get_progress():
    """
    Get overall learning progress

    Returns:
        List of all progress records
    """
    try:
        progress = education_bp.progress_tracker.get_all_progress()

        return jsonify({
            'success': True,
            'progress': progress
        })

    except Exception as e:
        logger.error(f"Error getting progress: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500


@education_bp.route('/progress/<technique_id>', methods=['GET'])
def get_technique_progress(technique_id: str):
    """Get progress for specific technique"""
    try:
        progress = education_bp.progress_tracker.get_progress(technique_id)

        if not progress:
            return jsonify({
                'success': True,
                'technique_id': technique_id,
                'progress': None,
                'message': 'Not started'
            })

        return jsonify({
            'success': True,
            'technique_id': technique_id,
            'progress': {
                'current_module': progress.current_module,
                'completed_modules': progress.completed_modules,
                'quiz_score': progress.quiz_score,
                'time_spent_minutes': progress.time_spent_minutes,
                'last_accessed': progress.last_accessed,
                'completed': progress.completed
            }
        })

    except Exception as e:
        logger.error(f"Error getting progress for {technique_id}: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500


@education_bp.route('/progress/<technique_id>/module/<int:module_number>/complete', methods=['POST'])
def complete_module(technique_id: str, module_number: int):
    """Mark a module as completed"""
    try:
        # Validate technique and module exist
        module = education_bp.lesson_manager.get_module(technique_id, module_number)
        if not module:
            return jsonify({
                'success': False,
                'error': f'Module {module_number} not found for {technique_id}'
            }), 404

        # Mark as complete
        education_bp.progress_tracker.complete_module(technique_id, module_number)

        # Get updated progress
        progress = education_bp.progress_tracker.get_progress(technique_id)

        # Check and award achievements
        achievements = education_bp.progress_tracker.check_and_award_achievements(
            technique_id, progress
        )

        return jsonify({
            'success': True,
            'technique_id': technique_id,
            'module_number': module_number,
            'completed': True,
            'new_achievements': achievements,
            'progress': {
                'completed_modules': progress.completed_modules,
                'current_module': progress.current_module
            }
        })

    except Exception as e:
        logger.error(f"Error completing module: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500


@education_bp.route('/recommend', methods=['GET'])
def get_recommendation():
    """
    Get recommended next topic based on completed lessons

    Returns:
        Recommended topic or null if none available
    """
    try:
        # Get all progress
        all_progress = education_bp.progress_tracker.get_all_progress()

        # Get completed technique IDs
        completed_ids = [
            p['technique_id'] for p in all_progress
            if p['completed']
        ]

        # Get recommendation
        recommendation = education_bp.lesson_manager.get_recommended_next(completed_ids)

        return jsonify({
            'success': True,
            'completed_count': len(completed_ids),
            'recommendation': recommendation
        })

    except Exception as e:
        logger.error(f"Error getting recommendation: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500


# ============================================================================
# QUIZ ENDPOINTS
# ============================================================================

@education_bp.route('/quiz/<technique_id>', methods=['GET'])
def get_quiz(technique_id: str):
    """
    Get quiz for a technique

    Returns:
        Quiz questions (without correct answers)
    """
    try:
        quiz = education_bp.quiz_data.get('quizzes', {}).get(technique_id)

        if not quiz:
            return jsonify({
                'success': False,
                'error': f'Quiz not found for {technique_id}'
            }), 404

        # Remove correct answers from response (client shouldn't see them)
        questions_without_answers = []
        for q in quiz['questions']:
            questions_without_answers.append({
                'id': q['id'],
                'type': q['type'],
                'difficulty': q['difficulty'],
                'question': q['question'],
                'options': q['options']
                # Note: correct_index and explanation excluded
            })

        return jsonify({
            'success': True,
            'technique_id': technique_id,
            'technique_title': quiz['technique_title'],
            'total_questions': quiz['total_questions'],
            'passing_score': quiz['passing_score'],
            'questions': questions_without_answers
        })

    except Exception as e:
        logger.error(f"Error getting quiz for {technique_id}: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500


@education_bp.route('/quiz/<technique_id>/submit', methods=['POST'])
def submit_quiz(technique_id: str):
    """
    Submit quiz answers

    Request body:
        {
            "answers": {
                "pi_q1": 0,
                "pi_q2": 1,
                ...
            }
        }

    Returns:
        Score, correct answers, and explanations
    """
    try:
        data = request.get_json()
        if not data or 'answers' not in data:
            return jsonify({
                'success': False,
                'error': 'Missing "answers" in request body'
            }), 400

        user_answers = data['answers']

        # Get quiz
        quiz = education_bp.quiz_data.get('quizzes', {}).get(technique_id)
        if not quiz:
            return jsonify({
                'success': False,
                'error': f'Quiz not found for {technique_id}'
            }), 404

        # Grade quiz
        results = []
        correct_count = 0
        total_questions = len(quiz['questions'])

        for question in quiz['questions']:
            q_id = question['id']
            user_answer = user_answers.get(q_id)
            correct_answer = question['correct_index']

            is_correct = (user_answer == correct_answer)
            if is_correct:
                correct_count += 1

            results.append({
                'question_id': q_id,
                'question': question['question'],
                'user_answer': user_answer,
                'correct_answer': correct_answer,
                'is_correct': is_correct,
                'explanation': question['explanation']
            })

        # Calculate score
        score = round((correct_count / total_questions) * 100)
        passed = score >= quiz['passing_score']

        # Record attempt
        education_bp.progress_tracker.record_quiz_attempt(
            technique_id=technique_id,
            total_questions=total_questions,
            correct_answers=correct_count
        )

        # If passed, mark technique as completed
        if passed:
            progress = education_bp.progress_tracker.get_progress(technique_id)
            if progress:
                progress.status = 'completed'
                progress.quiz_score = score
                from datetime import datetime
                progress.completed_at = datetime.now().isoformat()
                education_bp.progress_tracker.update_progress(progress)

                # Award achievements
                achievements = education_bp.progress_tracker.check_and_award_achievements(
                    technique_id, progress
                )
            else:
                achievements = []
        else:
            achievements = []

        return jsonify({
            'success': True,
            'technique_id': technique_id,
            'score': score,
            'correct_count': correct_count,
            'total_questions': total_questions,
            'passed': passed,
            'passing_score': quiz['passing_score'],
            'results': results,
            'new_achievements': achievements
        })

    except Exception as e:
        logger.error(f"Error submitting quiz for {technique_id}: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500


# ============================================================================
# ACHIEVEMENTS ENDPOINTS
# ============================================================================

@education_bp.route('/achievements', methods=['GET'])
def get_achievements():
    """Get all earned achievements"""
    try:
        achievements = education_bp.progress_tracker.get_all_achievements()

        return jsonify({
            'success': True,
            'count': len(achievements),
            'achievements': achievements
        })

    except Exception as e:
        logger.error(f"Error getting achievements: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500


# ============================================================================
# STATS ENDPOINTS
# ============================================================================

@education_bp.route('/stats', methods=['GET'])
def get_stats():
    """Get overall learning statistics"""
    try:
        # Curriculum stats
        curriculum_stats = education_bp.lesson_manager.get_stats()

        # User progress stats
        all_progress = education_bp.progress_tracker.get_all_progress()
        completed_count = sum(1 for p in all_progress if p['completed'])
        in_progress_count = sum(1 for p in all_progress if not p['completed'])

        total_time = sum(p['time_spent_minutes'] for p in all_progress)
        total_quiz_attempts = len(education_bp.progress_tracker.get_quiz_history())

        achievements = education_bp.progress_tracker.get_all_achievements()

        return jsonify({
            'success': True,
            'curriculum': curriculum_stats,
            'progress': {
                'completed_techniques': completed_count,
                'in_progress_techniques': in_progress_count,
                'total_time_minutes': total_time,
                'total_quiz_attempts': total_quiz_attempts,
                'achievements_earned': len(achievements)
            }
        })

    except Exception as e:
        logger.error(f"Error getting stats: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500


# ============================================================================
# VALIDATION ENDPOINT
# ============================================================================

@education_bp.route('/validate/<technique_id>', methods=['GET'])
def validate_access(technique_id: str):
    """
    Check if user can access a technique based on prerequisites

    Returns:
        Whether access is allowed and missing prerequisites
    """
    try:
        # Get completed techniques
        all_progress = education_bp.progress_tracker.get_all_progress()
        completed_ids = [
            p['technique_id'] for p in all_progress
            if p['completed']
        ]

        # Validate
        validation = education_bp.lesson_manager.validate_learning_path(
            technique_id, completed_ids
        )

        return jsonify({
            'success': True,
            **validation
        })

    except Exception as e:
        logger.error(f"Error validating access to {technique_id}: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500
