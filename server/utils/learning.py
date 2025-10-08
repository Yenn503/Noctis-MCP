"""
Noctis-MCP Learning Tracker
============================
Tracks attack results to improve recommendations over time.

Stores:
- Template used
- Techniques combined
- Target AV
- Detection result (success/failure)
- Timestamp
- Notes

Database: SQLite (server/learning/attack_history.db)
"""

import sqlite3
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime
import json

logger = logging.getLogger(__name__)


class LearningTracker:
    """Track attack results for learning and improvement"""

    def __init__(self, db_path: Optional[str] = None):
        """Initialize learning tracker with SQLite database"""
        if db_path is None:
            db_dir = Path(__file__).parent.parent / 'learning'
            db_dir.mkdir(exist_ok=True)
            db_path = str(db_dir / 'attack_history.db')

        self.db_path = db_path
        self._init_database()

    def _init_database(self):
        """Initialize database schema"""
        with sqlite3.connect(self.db_path, timeout=5.0) as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS attacks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    template TEXT NOT NULL,
                    techniques TEXT NOT NULL,
                    target_av TEXT NOT NULL,
                    detected INTEGER NOT NULL,
                    notes TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            conn.execute('''
                CREATE INDEX IF NOT EXISTS idx_target_av
                ON attacks(target_av)
            ''')

            conn.execute('''
                CREATE INDEX IF NOT EXISTS idx_template
                ON attacks(template)
            ''')

            conn.execute('''
                CREATE INDEX IF NOT EXISTS idx_detected
                ON attacks(detected)
            ''')

            conn.commit()

        logger.info(f"Learning tracker initialized: {self.db_path}")

    def record_attack(
        self,
        template: str,
        techniques: List[str],
        target_av: str,
        detected: bool,
        notes: str = ''
    ) -> int:
        """
        Record attack result.

        Args:
            template: Template used (e.g., "integrated_loader")
            techniques: List of techniques (e.g., ["poolparty", "zilean"])
            target_av: Target AV (e.g., "CrowdStrike")
            detected: True if detected, False if bypassed
            notes: Optional notes

        Returns:
            Attack ID
        """
        timestamp = datetime.utcnow().isoformat()
        techniques_json = json.dumps(techniques)

        with sqlite3.connect(self.db_path, timeout=5.0) as conn:
            cursor = conn.execute(
                '''
                INSERT INTO attacks (timestamp, template, techniques, target_av, detected, notes)
                VALUES (?, ?, ?, ?, ?, ?)
                ''',
                (timestamp, template, techniques_json, target_av, int(detected), notes)
            )
            attack_id = cursor.lastrowid
            conn.commit()

        result_str = "DETECTED" if detected else "BYPASSED"
        logger.info(f"[Learning] Recorded: {template} vs {target_av} = {result_str}")

        return attack_id

    def get_stats(self, target_av: Optional[str] = None, template: Optional[str] = None) -> Dict[str, Any]:
        """
        Get statistics for learning.

        Args:
            target_av: Optional filter by target AV
            template: Optional filter by template

        Returns:
            Statistics dictionary
        """
        with sqlite3.connect(self.db_path, timeout=5.0) as conn:
            query = 'SELECT template, target_av, detected FROM attacks WHERE 1=1'
            params = []

            if target_av:
                query += ' AND target_av = ?'
                params.append(target_av)

            if template:
                query += ' AND template = ?'
                params.append(template)

            cursor = conn.execute(query, params)
            results = cursor.fetchall()

        if not results:
            return {
                'total_attacks': 0,
                'bypass_rate': 0.0,
                'detection_rate': 0.0
            }

        total = len(results)
        detected_count = sum(1 for r in results if r[2] == 1)
        bypassed_count = total - detected_count

        bypass_rate = (bypassed_count / total) * 100 if total > 0 else 0.0
        detection_rate = (detected_count / total) * 100 if total > 0 else 0.0

        stats = {
            'total_attacks': total,
            'bypassed': bypassed_count,
            'detected': detected_count,
            'bypass_rate': round(bypass_rate, 2),
            'detection_rate': round(detection_rate, 2)
        }

        if target_av:
            stats['target_av'] = target_av

        if template:
            stats['template'] = template

        return stats

    def get_best_techniques(self, target_av: str, limit: int = 5) -> List[Dict[str, Any]]:
        """
        Get best techniques against specific AV.

        Args:
            target_av: Target AV name
            limit: Maximum results

        Returns:
            List of technique combinations with success rates
        """
        with sqlite3.connect(self.db_path, timeout=5.0) as conn:
            cursor = conn.execute(
                '''
                SELECT template, techniques,
                       COUNT(*) as total,
                       SUM(CASE WHEN detected = 0 THEN 1 ELSE 0 END) as bypassed
                FROM attacks
                WHERE target_av = ?
                GROUP BY template, techniques
                ORDER BY bypassed DESC, total DESC
                LIMIT ?
                ''',
                (target_av, limit)
            )
            results = cursor.fetchall()

        best = []
        for row in results:
            template, techniques_json, total, bypassed = row
            techniques = json.loads(techniques_json)
            success_rate = (bypassed / total) * 100 if total > 0 else 0.0

            best.append({
                'template': template,
                'techniques': techniques,
                'total_attempts': total,
                'successful_bypasses': bypassed,
                'success_rate': round(success_rate, 2)
            })

        return best

    def get_recent_attacks(self, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Get recent attack records.

        Args:
            limit: Maximum results

        Returns:
            List of recent attacks
        """
        with sqlite3.connect(self.db_path, timeout=5.0) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(
                '''
                SELECT * FROM attacks
                ORDER BY created_at DESC
                LIMIT ?
                ''',
                (limit,)
            )
            results = cursor.fetchall()

        attacks = []
        for row in results:
            attacks.append({
                'id': row['id'],
                'timestamp': row['timestamp'],
                'template': row['template'],
                'techniques': json.loads(row['techniques']),
                'target_av': row['target_av'],
                'detected': bool(row['detected']),
                'notes': row['notes'],
                'created_at': row['created_at']
            })

        return attacks
