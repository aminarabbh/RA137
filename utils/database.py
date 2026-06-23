"""
SQLite database layer for RA137.

Uses the centralized config system for paths, context-managed connections,
WAL journal mode for better concurrent read performance, and target-scoped
report storage.
"""

import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import List, Optional, Tuple

# ---------------------------------------------------------------------------
# Module-level state
# ---------------------------------------------------------------------------

_lock = threading.Lock()
_db_path: Optional[Path] = None


def _resolve_db_path() -> Path:
    """Resolve the database path from the config system."""
    global _db_path
    if _db_path is None:
        from utils.config import get_config
        config = get_config()
        output_dir = config.paths.output_base
        output_dir.mkdir(parents=True, exist_ok=True)
        _db_path = output_dir / "recon.db"
    return _db_path


# ---------------------------------------------------------------------------
# Connection management
# ---------------------------------------------------------------------------

@contextmanager
def _get_connection():
    """
    Yield a SQLite connection with WAL mode and automatic close.

    Thread-safe: uses a module-level lock so that concurrent callers
    get serialised access (SQLite is not truly concurrent for writes).
    """
    with _lock:
        conn = sqlite3.connect(_resolve_db_path(), timeout=10)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def init_db() -> None:
    """
    Initialise the database schema.

    Creates the ``reports`` table if it does not exist.  Safe to call
    multiple times (idempotent).
    """
    with _get_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS reports (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                target     TEXT    NOT NULL DEFAULT '',
                module     TEXT    NOT NULL,
                content    TEXT    NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        # Migration: add 'target' column if missing from an older DB
        try:
            conn.execute("SELECT target FROM reports LIMIT 1")
        except sqlite3.OperationalError:
            conn.execute("ALTER TABLE reports ADD COLUMN target TEXT NOT NULL DEFAULT ''")


def save_report(module: str, content: str, target: str = "") -> None:
    """
    Persist an AI-generated report.

    Parameters
    ----------
    module : str
        Module name (e.g. ``"Subdomain Enumeration"``).
    content : str
        Report body (Markdown).
    target : str
        Target domain the report belongs to.
    """
    with _get_connection() as conn:
        conn.execute(
            "INSERT INTO reports (target, module, content) VALUES (?, ?, ?)",
            (target, module, content),
        )


def get_all_reports(target: Optional[str] = None) -> List[Tuple[str, str]]:
    """
    Return saved AI reports as ``(module, content)`` pairs.

    Parameters
    ----------
    target : str, optional
        If provided, only reports for that target are returned.
        Otherwise all reports are returned (backward compatible).
    """
    with _get_connection() as conn:
        if target:
            cursor = conn.execute(
                "SELECT module, content FROM reports WHERE target = ? ORDER BY created_at",
                (target,),
            )
        else:
            cursor = conn.execute(
                "SELECT module, content FROM reports ORDER BY created_at"
            )
        return cursor.fetchall()


def get_reports_for_target(target: str) -> List[Tuple[str, str]]:
    """Return reports scoped to a specific target domain."""
    return get_all_reports(target=target)
