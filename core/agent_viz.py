"""
Phantom Compliance — Multi-Agent Collaboration Visualization
Provides status and flow data for the 8 compliance agents.
"""

import logging
from datetime import datetime
from utils.database import get_connection

logger = logging.getLogger("phantom_compliance.agent_viz")

AGENT_NAMES = [
    "Ingestion Agent",
    "LLM Agent",
    "Routing Agent",
    "Conflict Detector",
    "Deadline Parser",
    "Acknowledgement Agent",
    "Validation Agent",
    "Risk Scorer",
    "Escalation Agent",
]

def ensure_agent_viz_tables():
    conn = get_connection()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS agent_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_name TEXT NOT NULL,
            status TEXT NOT NULL,
            started_at TEXT NOT NULL,
            completed_at TEXT,
            duration_secs REAL,
            tasks_processed INTEGER DEFAULT 0,
            error TEXT
        )
    """)
    conn.commit()
    conn.close()
    logger.debug("agent_runs table ensured.")

def get_agent_statuses() -> list[dict]:
    ensure_agent_viz_tables()
    conn = get_connection()
    results = []
    for name in AGENT_NAMES:
        row = conn.execute(
            "SELECT id, agent_name, status, started_at, completed_at, duration_secs, tasks_processed, error "
            "FROM agent_runs WHERE agent_name=? ORDER BY started_at DESC LIMIT 1",
            (name,)
        ).fetchone()
        if row:
            st = row["status"]
            if st == "COMPLETED" and row["tasks_processed"] == 0:
                st = "SKIPPED"
            results.append({
                "agent_name": row["agent_name"],
                "status": st,
                "last_run": row["started_at"],
                "duration_secs": row["duration_secs"],
                "tasks_processed": row["tasks_processed"],
                "last_error": row["error"] or "",
            })
        else:
            results.append({
                "agent_name": name,
                "status": "IDLE",
                "last_run": "",
                "duration_secs": 0,
                "tasks_processed": 0,
                "last_error": "",
            })
    conn.close()
    return results

def record_agent_run(agent_name: str, status: str, tasks_processed: int = 0, error: str = "") -> int:
    ensure_agent_viz_tables()
    now = datetime.utcnow().isoformat()
    conn = get_connection()
    effective_status = status
    if status == "COMPLETED" and tasks_processed == 0:
        effective_status = "SKIPPED"
    cur = conn.execute(
        "INSERT INTO agent_runs (agent_name, status, started_at, completed_at, duration_secs, tasks_processed, error) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (agent_name, effective_status, now, now, 0.0, tasks_processed, error)
    )
    row_id = cur.lastrowid
    conn.commit()
    conn.close()
    logger.info(f"Recorded agent run: {agent_name} -> {effective_status} (id={row_id})")
    return row_id

def get_agent_flow() -> list[dict]:
    ensure_agent_viz_tables()
    conn = get_connection()
    rows = conn.execute(
        "SELECT id, agent_name, status, started_at, completed_at, duration_secs, tasks_processed, error "
        "FROM agent_runs ORDER BY started_at DESC LIMIT 50"
    ).fetchall()
    conn.close()
    return [
        {
            "id": r["id"],
            "agent_name": r["agent_name"],
            "status": r["status"],
            "started_at": r["started_at"],
            "completed_at": r["completed_at"],
            "duration_secs": r["duration_secs"],
            "tasks_processed": r["tasks_processed"],
            "error": r["error"] or "",
        }
        for r in rows
    ]
