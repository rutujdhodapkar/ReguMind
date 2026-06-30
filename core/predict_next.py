"""
Phantom Compliance — Predict Next Circulars
Analyzes historical circular topics and predicts upcoming compliance requirements.
"""

import logging
from datetime import datetime, timedelta
from utils.database import get_connection

logger = logging.getLogger("phantom_compliance.predict_next")

MOCK_PREDICTIONS = [
    {
        "topic": "UPI Fraud Prevention Update",
        "confidence_pct": 92,
        "reasoning": "RBI has been increasing UPI transaction limits and fraud incidence is rising; regulatory update expected next quarter.",
        "likely_timeline": "Next 3 months",
        "affected_departments": ["Digital Banking", "IT Security", "Fraud Monitoring"],
        "preparation_recommendation": "Review current UPI fraud detection systems and enhance real-time monitoring capabilities.",
    },
    {
        "topic": "Data Localization Requirements",
        "confidence_pct": 88,
        "reasoning": "Increasing regulatory focus on data sovereignty; multiple regulators pushing for stricter data localization norms.",
        "likely_timeline": "Next 6 months",
        "affected_departments": ["IT", "Legal", "Data Governance", "Risk Management"],
        "preparation_recommendation": "Audit current data storage locations and begin migration planning for on-shore data hosting.",
    },
    {
        "topic": "Cyber Incident Reporting Framework",
        "confidence_pct": 85,
        "reasoning": "CERT-In and RBI mandating stricter incident reporting timelines; comprehensive framework expected.",
        "likely_timeline": "Next 3 months",
        "affected_departments": ["IT Security", "Compliance", "Legal"],
        "preparation_recommendation": "Establish incident response playbooks and automated reporting workflows.",
    },
    {
        "topic": "KYC Norms Revision",
        "confidence_pct": 78,
        "reasoning": "Periodic KYC norm updates expected; video KYC and digital onboarding processes likely to be revised.",
        "likely_timeline": "Next 6-9 months",
        "affected_departments": ["Retail Banking", "Compliance", "Operations"],
        "preparation_recommendation": "Review current KYC processes and assess readiness for enhanced digital KYC requirements.",
    },
    {
        "topic": "Basel III Implementation Guidelines",
        "confidence_pct": 72,
        "reasoning": "RBI gradually phasing in Basel III norms; additional implementation guidelines anticipated.",
        "likely_timeline": "Next 12 months",
        "affected_departments": ["Risk Management", "Treasury", "Finance", "Compliance"],
        "preparation_recommendation": "Strengthen capital adequacy frameworks and stress testing capabilities.",
    },
]

def predict_next_circulars() -> list[dict]:
    conn = get_connection()
    dept_counts = {}
    try:
        rows = conn.execute(
            "SELECT assigned_to as department_code, count(*) as cnt FROM maps WHERE assigned_to IS NOT NULL AND assigned_to != '' GROUP BY assigned_to"
        ).fetchall()
        for r in rows:
            dept_counts[r["department_code"]] = r["cnt"]
    except Exception:
        logger.warning("Could not fetch department counts", exc_info=True)
    conn.close()
    predictions = []
    for p in MOCK_PREDICTIONS:
        dept_activity = []
        for dept in p["affected_departments"]:
            dept_activity.append({
                "department": dept,
                "current_maps": dept_counts.get(dept, 0),
            })
        entry = dict(p)
        entry["department_activity"] = dept_activity
        predictions.append(entry)
    predictions.sort(key=lambda x: x["confidence_pct"], reverse=True)
    return predictions

def get_topic_trends() -> list[dict]:
    conn = get_connection()
    trends = []
    try:
        rows = conn.execute("""
            SELECT strftime('%Y-%m', created_at) as month, count(*) as cnt
            FROM circulars
            WHERE created_at IS NOT NULL
            GROUP BY month ORDER BY month
        """).fetchall()
        for r in rows:
            trends.append({"month": r["month"], "circulars_count": r["cnt"]})
    except Exception:
        logger.warning("Could not fetch trend data", exc_info=True)
    if not trends:
        now = datetime.now()
        for i in range(11, -1, -1):
            m = now - timedelta(days=30 * i)
            month_str = m.strftime("%Y-%m")
            trends.append({"month": month_str, "circulars_count": 0})
    conn.close()
    return trends
