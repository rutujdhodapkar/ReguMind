"""
PHANTOM COMPLIANCE — Compliance Risk Score Engine
Calculates real-time risk scores per department and bank-wide.
Stores score history in SQLite for trend analysis.
"""

import logging
import json
from datetime import datetime, date, timedelta
from typing import Optional

from utils.database import get_connection
from utils.db_extensions import audit_log, create_notification

logger = logging.getLogger("phantom_compliance.risk_scorer")

DEPARTMENT_WEIGHTS = {
    "IT_Security": 0.25,
    "KYC": 0.25,
    "Treasury": 0.20,
    "Credit_Risk": 0.15,
    "Forex": 0.15,
    "Payments": 0.10,
}

DEPARTMENT_DISPLAY = {
    "IT_Security": "IT Security / Audit",
    "KYC": "KYC / Compliance",
    "Payments": "Payments / IT",
    "Treasury": "Treasury / Risk",
    "Forex": "Forex / Treasury",
    "Credit_Risk": "Credit / Stressed Assets",
}


def _get_maps_for_dept(dept_role: str) -> list[dict]:
    conn = get_connection()
    rows = conn.execute(
        """SELECT m.*, c.circular_number, c.subject_line
           FROM maps m JOIN circulars c ON m.circular_id = c.id
           WHERE m.assigned_to = ?""",
        (dept_role,),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def _calculate_department_score(dept_role: str) -> dict:
    """Calculate risk score for a single department (0-100)."""
    maps = _get_maps_for_dept(dept_role)
    base = 100
    penalties = []

    now = datetime.now()
    for m in maps:
        status = m.get("status", "PENDING")
        deadline_str = m.get("deadline_date", "")
        deadline = None
        if deadline_str:
            try:
                deadline = datetime.strptime(deadline_str[:10], "%Y-%m-%d")
            except (ValueError, IndexError):
                pass

        if status == "VALIDATED":
            continue

        elif status == "BREACHED":
            penalties.append(("BREACHED", 40, m.get("map_text", "")))
            base -= 40

        elif status == "ESCALATED":
            penalties.append(("OVERDUE", 25, m.get("map_text", "")))
            base -= 25

        elif status in ("PENDING", "ASSIGNED", "ASSIGNED_UNACKNOWLEDGED", "ASSIGNED_ACKNOWLEDGED"):
            if deadline:
                days_until = (deadline - now).days
                if days_until < 0:
                    penalties.append(("OVERDUE", 25, m.get("map_text", "")))
                    base -= 25
                elif days_until <= 7:
                    penalties.append(("DUE_SOON", 15, m.get("map_text", "")))
                    base -= 15
                elif days_until <= 30:
                    penalties.append(("APPROACHING", 8, m.get("map_text", "")))
                    base -= 8
                else:
                    penalties.append(("PENDING_OK", 2, m.get("map_text", "")))
                    base -= 2
            else:
                penalties.append(("NO_DEADLINE", 5, m.get("map_text", "")))
                base -= 5

    score = max(0, base)
    return {
        "department": dept_role,
        "display_name": DEPARTMENT_DISPLAY.get(dept_role, dept_role),
        "score": score,
        "total_maps": len(maps),
        "validated": sum(1 for m in maps if m.get("status") == "VALIDATED"),
        "pending": sum(1 for m in maps if m.get("status", "PENDING") in (
            "PENDING", "ASSIGNED", "ASSIGNED_UNACKNOWLEDGED", "ASSIGNED_ACKNOWLEDGED"
        )),
        "overdue": sum(1 for m in maps if m.get("status") in ("BREACHED", "ESCALATED")),
        "penalties": penalties[:5],
        "weight": DEPARTMENT_WEIGHTS.get(dept_role, 0.1),
    }


def calculate_bank_score() -> dict:
    """Calculate full bank-wide risk score."""
    departments = list(DEPARTMENT_WEIGHTS.keys())
    dept_scores = []

    for dept in departments:
        ds = _calculate_department_score(dept)
        dept_scores.append(ds)

    weighted_sum = sum(ds["score"] * ds["weight"] for ds in dept_scores)
    total_weight = sum(ds["weight"] for ds in dept_scores)
    bank_score = round(weighted_sum / (total_weight or 1), 1)
    bank_score = max(0, min(100, bank_score))

    for ds in dept_scores:
        ds["score"] = max(0, min(100, ds["score"]))

    yesterday_scores = get_score_history(days=2)
    prev_bank = yesterday_scores[0]["bank_score"] if len(yesterday_scores) > 1 else bank_score
    delta = round(bank_score - prev_bank, 1)

    threshold = "GREEN" if bank_score >= 90 else "YELLOW" if bank_score >= 70 else "ORANGE" if bank_score >= 50 else "RED"
    threshold_labels = {
        "GREEN": "Audit Ready",
        "YELLOW": "Needs Attention",
        "ORANGE": "At Risk",
        "RED": "Critical — Regulatory Exposure",
    }

    worst_dept = min(dept_scores, key=lambda d: d["score"])
    worst_penalty = (worst_dept.get("penalties") or [None])[0]
    insight = ""
    if worst_penalty and worst_dept["score"] < 70:
        insight = (
            f"{worst_dept['display_name']} score dropped to {worst_dept['score']}: "
            f"'{worst_penalty[2][:80]}' is {worst_penalty[1]} points overdue."
        )

    result = {
        "bank_score": bank_score,
        "delta": delta,
        "threshold": threshold,
        "threshold_label": threshold_labels[threshold],
        "departments": dept_scores,
        "insight": insight,
        "calculated_at": datetime.now().isoformat(),
    }

    _store_score_history(bank_score, dept_scores)
    return result


def _store_score_history(bank_score: float, dept_scores: list[dict]):
    conn = get_connection()
    today = date.today().isoformat()
    existing = conn.execute(
        "SELECT id FROM score_history WHERE date = ?", (today,)
    ).fetchone()
    dept_json = json.dumps({d["department"]: d["score"] for d in dept_scores})
    if existing:
        conn.execute(
            "UPDATE score_history SET bank_score=?, dept_scores=?, updated_at=datetime('now') WHERE date=?",
            (bank_score, dept_json, today),
        )
    else:
        conn.execute(
            "INSERT INTO score_history (date, bank_score, dept_scores) VALUES (?, ?, ?)",
            (today, bank_score, dept_json),
        )
    conn.commit()
    conn.close()


def get_score_history(days: int = 30) -> list[dict]:
    conn = get_connection()
    rows = conn.execute(
        "SELECT date, bank_score, dept_scores FROM score_history ORDER BY date DESC LIMIT ?",
        (days,),
    ).fetchall()
    conn.close()
    result = []
    for r in rows:
        item = {"date": r["date"], "bank_score": r["bank_score"]}
        if r["dept_scores"]:
            try:
                item["dept_scores"] = json.loads(r["dept_scores"])
            except (json.JSONDecodeError, TypeError):
                item["dept_scores"] = {}
        result.append(item)
    return result


def get_department_score(department: str) -> dict:
    return _calculate_department_score(department)


def ensure_score_history_table():
    conn = get_connection()
    conn.execute("""CREATE TABLE IF NOT EXISTS score_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        date TEXT UNIQUE NOT NULL,
        bank_score REAL NOT NULL,
        dept_scores TEXT DEFAULT '{}',
        created_at TEXT DEFAULT (datetime('now')),
        updated_at TEXT DEFAULT (datetime('now'))
    )""")
    conn.commit()
    conn.close()
