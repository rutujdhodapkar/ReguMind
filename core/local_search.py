"""
Phantom Compliance — Local Search Engine
Offline search index across all circulars, evidence, and logs.
Uses TF-IDF + SQLite FTS for fast local search.
No internet, no external services.
"""

import json
import logging
import re
from pathlib import Path

logger = logging.getLogger("phantom_compliance.local_search")


def _create_fts_tables():
    conn = __import__("utils.database", fromlist=["get_connection"]).get_connection()
    conn.executescript("""
        CREATE VIRTUAL TABLE IF NOT EXISTS circulars_fts USING fts5(
            circular_number, subject_line, body_text, department_code,
            content='circulars', content_rowid='id'
        );
        CREATE VIRTUAL TABLE IF NOT EXISTS maps_fts USING fts5(
            map_text, evidence_text, assigned_to,
            content='maps', content_rowid='id'
        );
        CREATE VIRTUAL TABLE IF NOT EXISTS audit_log_fts USING fts5(
            username, action, details,
            content='audit_log', content_rowid='id'
        );
    """)
    conn.commit()
    conn.close()


def rebuild_search_index():
    """Rebuild all FTS indexes from source tables."""
    _create_fts_tables()
    conn = __import__("utils.database", fromlist=["get_connection"]).get_connection()

    conn.execute("INSERT INTO circulars_fts(circulars_fts) VALUES('rebuild')")
    conn.execute("INSERT INTO maps_fts(maps_fts) VALUES('rebuild')")
    conn.execute("INSERT INTO audit_log_fts(audit_log_fts) VALUES('rebuild')")

    conn.commit()
    conn.close()
    logger.info("FTS search indexes rebuilt")


def search_all(query: str, limit: int = 20) -> dict:
    """Search across all indexed entities."""
    conn = __import__("utils.database", fromlist=["get_connection"]).get_connection()
    results = {"circulars": [], "maps": [], "audit_logs": []}

    if not query.strip():
        conn.close()
        return results

    safe_query = query.replace('"', '""')

    try:
        circs = conn.execute(
            "SELECT id, circular_number, subject_line, department_code, issue_date, "
            "rank FROM circulars_fts WHERE circulars_fts MATCH ? ORDER BY rank LIMIT ?",
            (safe_query, limit),
        ).fetchall()
        results["circulars"] = [dict(r) for r in circs]
    except Exception:
        pass

    try:
        maps = conn.execute(
            "SELECT id, map_text, assigned_to, status, deadline_date, "
            "rank FROM maps_fts WHERE maps_fts MATCH ? ORDER BY rank LIMIT ?",
            (safe_query, limit),
        ).fetchall()
        results["maps"] = [dict(r) for r in maps]
    except Exception:
        pass

    try:
        logs = conn.execute(
            "SELECT id, username, action, details, created_at, "
            "rank FROM audit_log_fts WHERE audit_log_fts MATCH ? ORDER BY rank LIMIT ?",
            (safe_query, limit),
        ).fetchall()
        results["audit_logs"] = [dict(r) for r in logs]
    except Exception:
        pass

    conn.close()
    results["total"] = len(results["circulars"]) + len(results["maps"]) + len(results["audit_logs"])
    return results


def search_circulars(query: str, limit: int = 20) -> list[dict]:
    conn = __import__("utils.database", fromlist=["get_connection"]).get_connection()
    safe_query = query.replace('"', '""')
    try:
        rows = conn.execute(
            "SELECT id, circular_number, subject_line, department_code, issue_date, "
            "rank FROM circulars_fts WHERE circulars_fts MATCH ? ORDER BY rank LIMIT ?",
            (safe_query, limit),
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except Exception:
        conn.close()
        return []


def search_maps(query: str, limit: int = 20) -> list[dict]:
    conn = __import__("utils.database", fromlist=["get_connection"]).get_connection()
    safe_query = query.replace('"', '""')
    try:
        rows = conn.execute(
            "SELECT id, map_text, assigned_to, status, deadline_date, "
            "rank FROM maps_fts WHERE maps_fts MATCH ? ORDER BY rank LIMIT ?",
            (safe_query, limit),
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except Exception:
        conn.close()
        return []
