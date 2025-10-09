"""Simple Learning Tracker - SQLite database"""
import sqlite3
from pathlib import Path
from datetime import datetime

DB_PATH = Path("data/learning.db")
DB_PATH.parent.mkdir(exist_ok=True)


def init_db():
    """Initialize learning database"""
    conn = sqlite3.connect(DB_PATH)
    conn.execute('''
        CREATE TABLE IF NOT EXISTS attacks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            target_edr TEXT,
            techniques TEXT,
            detected INTEGER,
            notes TEXT
        )
    ''')
    conn.commit()
    conn.close()


def record_attack(target_edr, techniques, detected, notes=""):
    """Record attack result"""
    init_db()

    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "INSERT INTO attacks (timestamp, target_edr, techniques, detected, notes) VALUES (?, ?, ?, ?, ?)",
        (datetime.now().isoformat(), target_edr, ','.join(techniques), 1 if detected else 0, notes)
    )
    conn.commit()
    conn.close()


def get_stats(target_edr):
    """Get statistics for EDR"""
    init_db()

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Total tests
    cursor.execute("SELECT COUNT(*) FROM attacks WHERE target_edr = ?", (target_edr,))
    total = cursor.fetchone()[0]

    # Bypassed tests
    cursor.execute("SELECT COUNT(*) FROM attacks WHERE target_edr = ? AND detected = 0", (target_edr,))
    bypassed = cursor.fetchone()[0]

    conn.close()

    bypass_rate = int((bypassed / total * 100)) if total > 0 else 0

    return {
        "total": total,
        "bypassed": bypassed,
        "bypass_rate": bypass_rate
    }
