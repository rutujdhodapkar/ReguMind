"""
PHANTOM COMPLIANCE — Violation Predictor
Statistical model to predict deadline misses and compliance risks.
Stores prediction history in SQLite for accuracy tracking.
"""

import logging
import json
from datetime import datetime, timedelta, date
from typing import Optional

from utils.database import get_connection

logger = logging.getLogger("phantom_compliance.predictor")

def _parse_dt(val):
    if not val:
        return None
    s = val.strip()
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(s[:19] if len(s) >= 19 else s, fmt)
        except ValueError:
            continue
    return None

DEPARTMENT_ROLES = [
    "IT_Security", "KYC", "Treasury", "Credit_Risk", "Forex", "Payments",
]

DEPARTMENT_DISPLAY = {
    "IT_Security": "IT Security / Audit",
    "KYC": "KYC / Compliance",
    "Payments": "Payments / IT",
    "Treasury": "Treasury / Risk",
    "Forex": "Forex / Treasury",
    "Credit_Risk": "Credit / Stressed Assets",
}


def _fetch_maps(department_code: str = "", since: Optional[date] = None) -> list[dict]:
    conn = get_connection()
    if since:
        since_str = since.isoformat()
        if department_code:
            rows = conn.execute(
                """SELECT m.*, c.circular_number, c.subject_line
                   FROM maps m JOIN circulars c ON m.circular_id = c.id
                   WHERE date(m.created_at) >= ? AND m.assigned_to = ?
                   ORDER BY m.id""",
                (since_str, department_code),
            ).fetchall()
        else:
            rows = conn.execute(
                """SELECT m.*, c.circular_number, c.subject_line
                   FROM maps m JOIN circulars c ON m.circular_id = c.id
                   WHERE date(m.created_at) >= ?
                   ORDER BY m.id""",
                (since_str,),
            ).fetchall()
    else:
        if department_code:
            rows = conn.execute(
                """SELECT m.*, c.circular_number, c.subject_line
                   FROM maps m JOIN circulars c ON m.circular_id = c.id
                   WHERE m.assigned_to = ?
                   ORDER BY m.id""",
                (department_code,),
            ).fetchall()
        else:
            rows = conn.execute(
                """SELECT m.*, c.circular_number, c.subject_line
                   FROM maps m JOIN circulars c ON m.circular_id = c.id
                   ORDER BY m.id""",
            ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def _calculate_recency_factor(dept_maps: list[dict]) -> float:
    thirty_days_ago = datetime.now() - timedelta(days=30)
    recent_breaches = [
        m for m in dept_maps
        if m.get("status") in ("BREACHED", "ESCALATED")
        and (_parse_dt(m.get("validated_at")) or _parse_dt(m.get("created_at", "")) or datetime.min) >= thirty_days_ago
    ]
    if not recent_breaches:
        oldest = None
        for m in dept_maps:
            ts = _parse_dt(m.get("validated_at")) or _parse_dt(m.get("created_at"))
            if ts and ts >= thirty_days_ago:
                if oldest is None or ts < oldest:
                    oldest = ts
        if oldest is None:
            return 0
        days_since = (datetime.now() - oldest).days
        return max(0, 30 - days_since) if days_since < 30 else 0
    return 100


def _compute_trend(dept_code: str) -> str:
    now = datetime.now()
    recent_start = (now - timedelta(days=30)).isoformat()
    prior_start = (now - timedelta(days=60)).isoformat()

    recent_maps = _fetch_maps(dept_code, since=now - timedelta(days=30))
    prior_maps = _fetch_maps(dept_code, since=now - timedelta(days=60))

    recent_breaches = sum(1 for m in recent_maps if m.get("status") in ("BREACHED", "ESCALATED"))
    prior_breaches = sum(1 for m in prior_maps if m.get("status") in ("BREACHED", "ESCALATED"))

    recent_rate = recent_breaches / max(len(recent_maps), 1)
    prior_rate = prior_breaches / max(len(prior_maps), 1)

    if recent_rate < prior_rate * 0.8:
        return "IMPROVING"
    elif recent_rate > prior_rate * 1.2:
        return "DETERIORATING"
    return "STABLE"


def predict_violation_risk(department_code: str = "") -> dict:
    six_months_ago = (datetime.now() - timedelta(days=180)).date()
    all_maps = _fetch_maps(department_code, since=six_months_ago)

    if not all_maps:
        return {
            "risk_score": 50,
            "confidence": "LOW",
            "message": "Insufficient historical data",
            "next_violation_probability": 0,
            "trend": "STABLE",
            "departments": [],
        }

    if department_code:
        depts_to_check = [department_code]
    else:
        depts_to_check = DEPARTMENT_ROLES

    departments = []
    for dept in depts_to_check:
        dept_maps = [m for m in all_maps if m.get("assigned_to") == dept]
        if not dept_maps:
            continue

        total = len(dept_maps)
        breached = sum(1 for m in dept_maps if m.get("status") == "BREACHED")
        escalated = sum(1 for m in dept_maps if m.get("status") == "ESCALATED")
        validated = sum(1 for m in dept_maps if m.get("status") == "VALIDATED")
        pending = sum(1 for m in dept_maps if m.get("status") in ("PENDING", "ASSIGNED"))

        historical_breach_rate = (breached + escalated) / max(total, 1)

        completion_days_list = []
        delay_days_list = []
        for m in dept_maps:
            if m.get("status") == "VALIDATED" and m.get("validated_at") and m.get("deadline_date"):
                created = _parse_dt(m.get("created_at"))
                validated_at = _parse_dt(m.get("validated_at"))
                if created and validated_at:
                    days_taken = (validated_at - created).days
                    completion_days_list.append(max(0, days_taken))

            if m.get("status") in ("BREACHED", "ESCALATED") and m.get("deadline_date"):
                deadline = _parse_dt(m["deadline_date"])
                if deadline:
                    event_date = _parse_dt(m.get("validated_at")) or datetime.now()
                    delay = (event_date - deadline).days
                    delay_days_list.append(max(0, delay))

        avg_completion_days = round(sum(completion_days_list) / max(len(completion_days_list), 1), 1)
        avg_delay = round(sum(delay_days_list) / max(len(delay_days_list), 1), 1)

        overdue_count = pending
        for m in dept_maps:
            if m.get("status") in ("PENDING", "ASSIGNED") and m.get("deadline_date"):
                try:
                    if datetime.strptime(m["deadline_date"][:10], "%Y-%m-%d") < datetime.now():
                        overdue_count += 0
                except (ValueError, IndexError):
                    pass

        overdue_rate = overdue_count / max(total, 1)

        recency = _calculate_recency_factor(dept_maps)

        raw_risk = historical_breach_rate * 40 + overdue_rate * 30 + (recency / 100) * 30
        risk_score = round(min(100, max(0, raw_risk)), 1)

        breach_maps = [m for m in dept_maps if m.get("status") in ("BREACHED", "ESCALATED")]
        breach_rate_recent = len(breach_maps) / max(total, 1)
        next_violation_probability = round(min(100, max(0, breach_rate_recent * 100 + (avg_delay / 30) * 10)), 1)

        trend = _compute_trend(dept)

        pred_delay_days = round(avg_delay, 1)

        departments.append({
            "department_code": dept,
            "display_name": DEPARTMENT_DISPLAY.get(dept, dept),
            "total_maps": total,
            "breached": breached,
            "escalated": escalated,
            "validated": validated,
            "pending": pending,
            "historical_breach_rate": round(historical_breach_rate, 3),
            "avg_completion_days": avg_completion_days,
            "overdue_rate": round(overdue_rate, 3),
            "risk_score": risk_score,
            "predicted_delay_days": pred_delay_days,
            "next_violation_probability": next_violation_probability,
            "trend": trend,
        })

    if not departments:
        return {
            "risk_score": 50,
            "confidence": "LOW",
            "message": "Insufficient historical data",
            "next_violation_probability": 0,
            "trend": "STABLE",
            "departments": [],
        }

    overall_risk = round(
        sum(d["risk_score"] for d in departments) / len(departments), 1
    )
    overall_probability = round(
        sum(d["next_violation_probability"] for d in departments) / len(departments), 1
    )
    trends = [d["trend"] for d in departments]
    if all(t == "IMPROVING" for t in trends):
        overall_trend = "IMPROVING"
    elif all(t == "DETERIORATING" for t in trends):
        overall_trend = "DETERIORATING"
    else:
        overall_trend = "STABLE"

    result = {
        "risk_score": overall_risk,
        "confidence": "HIGH" if len(all_maps) >= 30 else "MEDIUM" if len(all_maps) >= 10 else "LOW",
        "message": None,
        "next_violation_probability": overall_probability,
        "trend": overall_trend,
        "departments": departments,
        "total_maps_analyzed": len(all_maps),
    }
    return result


def predict_circular_impact(circular_id: int) -> dict:
    conn = get_connection()
    circ = conn.execute(
        "SELECT id, department_code, circular_number, subject_line FROM circulars WHERE id=?",
        (circular_id,),
    ).fetchone()
    conn.close()

    if not circ:
        return {"error": "Circular not found"}

    circ = dict(circ)
    dept_code = circ.get("department_code", "")
    if not dept_code:
        return {"error": "Circular has no department code", "circular_id": circular_id}

    risk = predict_violation_risk(department_code=dept_code)
    dept_data = None
    for d in risk.get("departments", []):
        if d["department_code"] == dept_code:
            dept_data = d
            break

    if not dept_data:
        workload_increase = 10
        risk_change = 5
        new_maps_estimated = 3
    else:
        breach_rate = dept_data.get("historical_breach_rate", 0)
        workload_increase = round(min(50, max(5, breach_rate * 100 * 0.5)), 1)
        risk_change = round(min(20, max(-5, breach_rate * 40)), 1)
        new_maps_estimated = max(1, round(breach_rate * 10 + 2))

    return {
        "circular_id": circular_id,
        "circular_number": circ.get("circular_number", ""),
        "department_code": dept_code,
        "current_risk_score": dept_data["risk_score"] if dept_data else 50,
        "predicted_workload_increase_pct": workload_increase,
        "predicted_risk_score_change": risk_change,
        "predicted_new_maps_needed": new_maps_estimated,
        "confidence": risk.get("confidence", "LOW"),
    }


def get_prediction_model_accuracy() -> dict:
    conn = get_connection()
    rows = conn.execute(
        """SELECT predicted_risk, actual_outcome, prediction_date
           FROM violation_predictions
           WHERE actual_outcome IS NOT NULL
           ORDER BY prediction_date DESC LIMIT 100"""
    ).fetchall()
    conn.close()

    if not rows:
        six_months_ago = (datetime.now() - timedelta(days=180)).date()
        all_maps = _fetch_maps(since=six_months_ago)

        if not all_maps:
            return {
                "accuracy_pct": 0,
                "total_predictions": 0,
                "correct_predictions": 0,
                "message": "No historical data for accuracy calculation",
            }

        dept_stats = {}
        for m in all_maps:
            dept = m.get("assigned_to") or "UNKNOWN"
            if dept not in dept_stats:
                dept_stats[dept] = {"total": 0, "breached": 0, "validated": 0, "predicted_breach": 0}
            s = dept_stats[dept]
            s["total"] += 1
            if m.get("status") in ("BREACHED", "ESCALATED"):
                s["breached"] += 1
            if m.get("status") == "VALIDATED":
                s["validated"] += 1

        total_correct = 0
        total_predictions = 0
        for dept, s in dept_stats.items():
            actual_breach_rate = s["breached"] / max(s["total"], 1)
            predicted_breach = 1 if actual_breach_rate > 0.3 else 0
            correct = 0
            for m in all_maps:
                if m.get("assigned_to") != dept:
                    continue
                total_predictions += 1
                if predicted_breach and m.get("status") in ("BREACHED", "ESCALATED"):
                    correct += 1
                elif not predicted_breach and m.get("status") == "VALIDATED":
                    correct += 1
                elif not predicted_breach and m.get("status") in ("PENDING", "ASSIGNED"):
                    correct += 1
            total_correct += correct

        accuracy = round((total_correct / max(total_predictions, 1)) * 100, 1)
        return {
            "accuracy_pct": accuracy,
            "total_predictions": total_predictions,
            "correct_predictions": total_correct,
            "method": "mock_historical_comparison",
            "dept_count": len(dept_stats),
        }

    correct = sum(1 for r in rows if r["actual_outcome"] == r["predicted_risk"])
    total = len(rows)
    return {
        "accuracy_pct": round((correct / max(total, 1)) * 100, 1),
        "total_predictions": total,
        "correct_predictions": correct,
        "method": "database_comparison",
    }


def ensure_predictor_table():
    conn = get_connection()
    conn.execute("""CREATE TABLE IF NOT EXISTS violation_predictions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        department_code TEXT NOT NULL,
        predicted_risk REAL NOT NULL,
        predicted_delay_days REAL DEFAULT 0,
        probability REAL DEFAULT 0,
        trend TEXT DEFAULT 'STABLE',
        prediction_date TEXT DEFAULT (datetime('now')),
        actual_outcome TEXT,
        actual_delay_days REAL,
        evaluated_at TEXT,
        created_at TEXT DEFAULT (datetime('now'))
    )""")
    conn.commit()
    conn.close()
    logger.info("Ensured violation_predictions table exists")
