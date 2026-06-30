"""
PHANTOM COMPLIANCE — Deadline Intelligence Engine
Parses natural language deadline expressions from RBI circulars.
Uses regex patterns first, falls back to LLM for complex cases.
Manages reminder thresholds and deadline breach detection.
"""

import re
import json
import logging
from datetime import datetime, date, timedelta
from typing import Optional
from calendar import monthrange

from utils.database import get_connection

logger = logging.getLogger("phantom_compliance.deadline_parser")

URGENCY_MAP = {
    "urgent": "URGENT",
    "high": "HIGH",
    "normal": "NORMAL",
}


def _call_llm_for_deadline(text: str) -> dict:
    """Fallback: send deadline snippet to LLM for parsing."""
    from agents.llm_agent import _call_llm
    prompt = f"""[INST] Extract the compliance deadline from this regulatory text.
Return JSON only:
{{"deadline_type": "exact|relative|ongoing", "days": int|null, "date": "YYYY-MM-DD"|null, "urgency": "urgent|high|normal"}}

Text: {text[:500]}
[/INST]"""
    raw = _call_llm(prompt)
    if raw:
        try:
            result = json.loads(raw.strip().removeprefix("```json").removesuffix("```").strip())
            if isinstance(result, dict):
                return result
        except (json.JSONDecodeError, AttributeError):
            pass
    return {"deadline_type": "relative", "days": 30, "urgency": "normal"}


def parse_deadline(text: str) -> dict:
    """
    Parse a deadline expression from circular text.
    Returns dict with: deadline_date (str YYYY-MM-DD), urgency (str), deadline_type (str).
    """
    text_lower = text.lower().strip()

    # Pattern 1: "by DD/MM/YYYY" or "by DD Month YYYY"
    patterns = [
        (r"(\d{1,2})[/-](\d{1,2})[/-](\d{4})", "exact"),
        (r"by\s+(\d{1,2})(?:st|nd|rd|th)?\s+(\w+)\s+(\d{4})", "exact"),
        (r"by\s+(\d{1,2})(?:st|nd|rd|th)?\s+(\w+)", "exact_yearless"),
    ]
    for pat, ptype in patterns:
        m = re.search(pat, text_lower)
        if m:
            if ptype == "exact":
                if m.lastindex == 3:
                    # DD/MM/YYYY
                    try:
                        d = datetime.strptime(f"{m.group(1)}/{m.group(2)}/{m.group(3)}", "%d/%m/%Y")
                        return {"deadline_date": d.strftime("%Y-%m-%d"), "urgency": "NORMAL", "deadline_type": "exact"}
                    except ValueError:
                        try:
                            d = datetime.strptime(f"{m.group(1)}/{m.group(2)}/{m.group(3)}", "%m/%d/%Y")
                            return {"deadline_date": d.strftime("%Y-%m-%d"), "urgency": "NORMAL", "deadline_type": "exact"}
                        except ValueError:
                            pass
                elif m.lastindex == 3:
                    month_map = {"january":1,"february":2,"march":3,"april":4,"may":5,"june":6,"july":7,"august":8,"september":9,"october":10,"november":11,"december":12}
                    day, month_name, year = int(m.group(1)), m.group(2).lower(), int(m.group(3))
                    if month_name in month_map:
                        d = date(year, month_map[month_name], day)
                        return {"deadline_date": d.isoformat(), "urgency": "NORMAL", "deadline_type": "exact"}
            elif ptype == "exact_yearless":
                month_map = {"january":1,"february":2,"march":3,"april":4,"may":5,"june":6,"july":7,"august":8,"september":9,"october":10,"november":11,"december":12}
                day, month_name = int(m.group(1)), m.group(2).lower()
                if month_name in month_map:
                    this_year = date.today().year
                    d = date(this_year, month_map[month_name], day)
                    if d < date.today():
                        d = date(this_year + 1, month_map[month_name], day)
                    return {"deadline_date": d.isoformat(), "urgency": "NORMAL", "deadline_type": "exact"}

    # Pattern 2: "immediately", "with immediate effect", "at the earliest"
    if re.search(r"\bimmediately\b|\bwith immediate effect\b", text_lower):
        d = date.today() + timedelta(days=7)
        return {"deadline_date": d.isoformat(), "urgency": "URGENT", "deadline_type": "relative"}

    if re.search(r"\bat the earliest\b", text_lower):
        d = date.today() + timedelta(days=7)
        return {"deadline_date": d.isoformat(), "urgency": "HIGH", "deadline_type": "relative"}

    # Pattern 3: "henceforth" → ongoing
    if re.search(r"\bhenceforth\b", text_lower):
        return {"deadline_date": None, "urgency": "NORMAL", "deadline_type": "ongoing"}

    # Pattern 4: "within N days"
    m = re.search(r"within\s+(\d+)\s*days?", text_lower)
    if m:
        days = int(m.group(1))
        d = date.today() + timedelta(days=days)
        return {"deadline_date": d.isoformat(), "urgency": "NORMAL", "deadline_type": "relative"}

    # Pattern 5: "within N months"
    m = re.search(r"within\s+(\d+)\s*months?", text_lower)
    if m:
        months = int(m.group(1))
        d = date.today()
        for _ in range(months):
            d = date(d.year + (d.month // 12), (d.month % 12) + 1, 1)
            last_day = monthrange(d.year, d.month)[1]
            d = d.replace(day=min(d.day, last_day))
        return {"deadline_date": d.isoformat(), "urgency": "NORMAL", "deadline_type": "relative"}

    # Pattern 6: "within fortnight"
    if re.search(r"\bfortnight\b", text_lower):
        d = date.today() + timedelta(days=14)
        return {"deadline_date": d.isoformat(), "urgency": "NORMAL", "deadline_type": "relative"}

    # Pattern 7: "by end of current FY" → March 31 of current year
    if re.search(r"end\s+of\s+(?:current\s+)?(?:financial\s+)?(?:year|fy)", text_lower):
        today = date.today()
        fy_end = date(today.year, 3, 31)
        if today > fy_end:
            fy_end = date(today.year + 1, 3, 31)
        return {"deadline_date": fy_end.isoformat(), "urgency": "NORMAL", "deadline_type": "relative"}

    # Pattern 8: "next financial year" → April 1 of next FY
    if re.search(r"next\s+(?:financial\s+)?(?:year|fy)", text_lower):
        today = date.today()
        fy_start = date(today.year, 4, 1)
        if today >= fy_start:
            fy_start = date(today.year + 1, 4, 1)
        else:
            fy_start = date(today.year, 4, 1)
        return {"deadline_date": fy_start.isoformat(), "urgency": "NORMAL", "deadline_type": "relative"}

    # Fallback to LLM
    result = _call_llm_for_deadline(text)
    if result.get("date"):
        return {"deadline_date": result["date"], "urgency": URGENCY_MAP.get(result.get("urgency", ""), "NORMAL"), "deadline_type": result.get("deadline_type", "relative")}
    days = result.get("days", 30)
    d = date.today() + timedelta(days=days)
    return {"deadline_date": d.isoformat(), "urgency": URGENCY_MAP.get(result.get("urgency", ""), "NORMAL"), "deadline_type": result.get("deadline_type", "relative")}


def check_reminders() -> dict:
    """
    Check all pending MAPs against their deadlines.
    Insert reminder records when thresholds are crossed.
    Returns count of new reminders triggered.
    """
    conn = get_connection()
    today = date.today()
    triggered = {"t30": 0, "t7": 0, "t1": 0, "breached": 0}

    rows = conn.execute(
        """SELECT m.id, m.map_text, m.deadline_date, m.status, m.assigned_to, c.circular_number
           FROM maps m JOIN circulars c ON m.circular_id = c.id
           WHERE m.status IN ('PENDING', 'ASSIGNED', 'ASSIGNED_UNACKNOWLEDGED', 'ASSIGNED_ACKNOWLEDGED')""",
    ).fetchall()

    for row in rows:
        deadline_str = row["deadline_date"]
        if not deadline_str:
            continue
        try:
            deadline = datetime.strptime(deadline_str[:10], "%Y-%m-%d").date()
        except (ValueError, IndexError):
            continue

        days_until = (deadline - today).days

        if days_until < 0:
            # Breach
            existing = conn.execute(
                "SELECT id FROM reminders WHERE map_id=? AND reminder_type=?",
                (row["id"], "DEADLINE_BREACHED"),
            ).fetchone()
            if not existing:
                conn.execute(
                    "INSERT INTO reminders (map_id, reminder_type, days_until, triggered_at) VALUES (?, ?, ?, datetime('now'))",
                    (row["id"], "DEADLINE_BREACHED", days_until),
                )
                triggered["breached"] += 1

        elif days_until == 0:
            existing = conn.execute(
                "SELECT id FROM reminders WHERE map_id=? AND reminder_type=?",
                (row["id"], "DUE_TODAY"),
            ).fetchone()
            if not existing:
                conn.execute(
                    "INSERT INTO reminders (map_id, reminder_type, days_until, triggered_at) VALUES (?, ?, ?, datetime('now'))",
                    (row["id"], "DUE_TODAY", 0),
                )
                triggered["t1"] += 1

        elif days_until <= 7:
            existing = conn.execute(
                "SELECT id FROM reminders WHERE map_id=? AND reminder_type=?",
                (row["id"], "DUE_SOON"),
            ).fetchone()
            if not existing:
                conn.execute(
                    "INSERT INTO reminders (map_id, reminder_type, days_until, triggered_at) VALUES (?, ?, ?, datetime('now'))",
                    (row["id"], "DUE_SOON", days_until),
                )
                triggered["t7"] += 1

        elif days_until <= 30:
            existing = conn.execute(
                "SELECT id FROM reminders WHERE map_id=? AND reminder_type=?",
                (row["id"], "APPROACHING"),
            ).fetchone()
            if not existing:
                conn.execute(
                    "INSERT INTO reminders (map_id, reminder_type, days_until, triggered_at) VALUES (?, ?, ?, datetime('now'))",
                    (row["id"], "APPROACHING", days_until),
                )
                triggered["t30"] += 1

    conn.commit()
    conn.close()
    return triggered


def get_reminders_for_department(role: str) -> list[dict]:
    conn = get_connection()
    rows = conn.execute(
        """SELECT r.*, m.map_text, m.deadline_date, m.status, c.circular_number
           FROM reminders r
           JOIN maps m ON r.map_id = m.id
           JOIN circulars c ON m.circular_id = c.id
           WHERE m.assigned_to = ?
           ORDER BY r.triggered_at DESC LIMIT 50""",
        (role,),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def ensure_reminders_table():
    conn = get_connection()
    conn.execute("""CREATE TABLE IF NOT EXISTS reminders (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        map_id INTEGER NOT NULL,
        reminder_type TEXT NOT NULL,
        days_until INTEGER DEFAULT 0,
        triggered_at TEXT DEFAULT (datetime('now')),
        is_dismissed INTEGER DEFAULT 0,
        FOREIGN KEY(map_id) REFERENCES maps(id)
    )""")
    conn.commit()
    conn.close()
