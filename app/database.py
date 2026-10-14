import os
import sqlite3
from pathlib import Path

DB_PATH = os.getenv("SENTINELOPS_DB", "sentinelops.db")

def connect():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True) if os.path.dirname(DB_PATH) else None
    with connect() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                source_ip TEXT NOT NULL,
                event_type TEXT NOT NULL,
                target TEXT NOT NULL,
                details TEXT NOT NULL,
                severity TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'new'
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id INTEGER NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                assessment TEXT NOT NULL,
                confidence TEXT NOT NULL,
                evidence TEXT NOT NULL,
                response_action TEXT NOT NULL,
                response_status TEXT NOT NULL,
                FOREIGN KEY(alert_id) REFERENCES alerts(id)
            )
        """)
