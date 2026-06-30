"""
PHANTOM COMPLIANCE — Regulatory Impact Simulator
Simulates financial, reputational, and operational impact
when an RBI circular is ignored or delayed.
Uses deterministic calculations based on actual MAP data.
"""

import logging
import hashlib
from datetime import datetime, timedelta

from utils.database import get_connection

logger = logging.getLogger("phantom_compliance.impact")

DEPT_PENALTY_RANGES = {
    "KYC": (5_000_000, 50_000_000),
    "KYC/AML": (5_000_000, 50_000_000),
    "Payments": (2_000_000, 20_000_000),
    "Payments/DPSS": (2_000_000, 20_000_000),
    "DPSS": (2_000_000, 20_000_000),
    "IT_Security": (10_000_000, 100_000_000),
    "IT/Cyber": (10_000_000, 100_000_000),
    "Treasury": (1_000_000, 10_000_000),
    "Forex": (3_000_000, 30_000_000),
    "Credit_Risk": (4_000_000, 40_000_000),
    "Credit": (4_000_000, 40_000_000),
}

REPUTATIONAL_THRESHOLDS = [
    (25, "CRITICAL"),
    (20, "HIGH"),
    (10, "MEDIUM"),
    (0, "LOW"),
]

TIMELINE_MILESTONES = [
    (30, "Reminder notice issued by RBI; informal query from regional office."),
    (60, "Show-cause notice served; bank must submit written explanation within 14 days."),
    (90, "Penalty order may be passed under Section 47(A) of BR Act; fine levied."),
    (180, "Enforcement action escalates — RBI may restrict branch expansion, freeze dividend payout, or initiate director disqualification proceedings."),
]


def _dept_category(dept_code: str) -> str:
    if not dept_code:
        return "Default"
    code_upper = dept_code.upper()
    if "AML" in code_upper or "KYC" in code_upper or "DOR" in code_upper:
        if "STR" in code_upper:
            return "Credit_Risk"
        return "KYC"
    if "DPSS" in code_upper or "PAY" in code_upper or "CO" == code_upper.split(".")[0]:
        return "Payments"
    if "CYBER" in code_upper or "IT" in code_upper or "DoS" in code_upper or code_upper.startswith("DOS"):
        return "IT_Security"
    if "TREASURY" in code_upper or "DBR" in code_upper or "BP" in code_upper:
        return "Treasury"
    if "FOREX" in code_upper or "A.P" in code_upper or "FEMA" in code_upper:
        return "Forex"
    if "CREDIT" in code_upper or "STR" in code_upper or "STRE" in code_upper:
        return "Credit_Risk"
    if dept_code in DEPT_PENALTY_RANGES:
        return dept_code
    return "Default"


def _get_penalty_range(dept_code: str) -> tuple[int, int]:
    cat = _dept_category(dept_code)
    return DEPT_PENALTY_RANGES.get(cat, (1_000_000, 1_000_000))


def _deterministic_factor(seed_key: str) -> float:
    """Return a deterministic value in [0.3, 0.95] based on a seed string."""
    h = hashlib.md5(seed_key.encode()).hexdigest()
    val = int(h[:8], 16) % 1000 / 1000.0
    return 0.3 + val * 0.65


def _estimate_score_drop(maps_breach_rate: float, overdue_rate: float) -> int:
    """Score drop based on real MAP data: higher breach/overdue = bigger drop."""
    base = 5
    drop = base + int(maps_breach_rate * 20) + int(overdue_rate * 15)
    return min(drop, 30)


def _reputational_risk(score_drop: int) -> str:
    for threshold, label in REPUTATIONAL_THRESHOLDS:
        if score_drop >= threshold:
            return label
    return "LOW"


def _build_timeline(ignore_days: int) -> list[dict]:
    timeline = []
    for offset, description in TIMELINE_MILESTONES:
        if ignore_days >= offset:
            timeline.append({
                "days": offset,
                "event": description,
                "triggered": True,
            })
        else:
            timeline.append({
                "days": offset,
                "event": description,
                "triggered": False,
            })
    return timeline


def _build_regulatory_actions(score_drop: int, ignore_days: int) -> list[str]:
    actions = []
    if ignore_days >= 30:
        actions.append("Show cause notice under Section 47(A)(1) of BR Act 1949")
    if ignore_days >= 60:
        actions.append("Penalty order — monetary fine imposed")
    if ignore_days >= 90:
        actions.append("Direction to rectify within stipulated timeline")
    if ignore_days >= 120:
        actions.append("Restriction on branch expansion / new business")
    if ignore_days >= 150:
        actions.append("Freeze on dividend declaration")
    if ignore_days >= 180:
        actions.append("Director disqualification proceedings under Section 36AB")
    if score_drop >= 20:
        actions.append("Special audit ordered by RBI")
    if score_drop >= 25:
        actions.append("Public warning / regulatory notice on RBI website")
    return actions


def ensure_impact_table():
    conn = get_connection()
    conn.execute("""CREATE TABLE IF NOT EXISTS impact_simulations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        circular_id INTEGER NOT NULL,
        ignore_days INTEGER NOT NULL DEFAULT 90,
        penalty_estimate REAL NOT NULL,
        score_drop REAL NOT NULL,
        reputational_risk TEXT NOT NULL,
        details TEXT DEFAULT '{}',
        created_at TEXT DEFAULT (datetime('now')),
        FOREIGN KEY(circular_id) REFERENCES circulars(id)
    )""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_impact_circular ON impact_simulations(circular_id)")
    conn.commit()
    conn.close()
    logger.info("Ensured impact_simulations table exists")


def simulate_impact(circular_id: int, ignore_days: int = 90, blockchain=None) -> dict:
    logger.info("Simulating impact for circular_id=%s ignore_days=%s", circular_id, ignore_days)

    conn = get_connection()
    row = conn.execute(
        "SELECT id, circular_number, subject_line, department_code, issue_date FROM circulars WHERE id=?",
        (circular_id,),
    ).fetchone()

    # Count MAPs for this circular and their statuses
    maps_count = 0
    breached_count = 0
    overdue_count = 0
    try:
        maps_rows = conn.execute(
            "SELECT status, deadline_date FROM maps WHERE circular_id=?",
            (circular_id,),
        ).fetchall()
        maps_count = len(maps_rows)
        today = datetime.now().strftime("%Y-%m-%d")
        for m in maps_rows:
            s = m["status"] or ""
            if s in ("BREACHED", "ESCALATED"):
                breached_count += 1
            if m["deadline_date"] and m["deadline_date"] < today and s not in ("VALIDATED", "SUPERSEDED"):
                overdue_count += 1
    except Exception:
        pass

    conn.close()

    if not row:
        logger.error("Circular %s not found", circular_id)
        return {"error": f"Circular with id {circular_id} not found"}

    circular = dict(row)
    dept_code = circular.get("department_code", "") or ""

    min_p, max_p = _get_penalty_range(dept_code)
    scale = ignore_days / 90.0

    # Deterministic penalty based on circular_id + ignore_days
    factor = _deterministic_factor(f"{circular_id}-{ignore_days}-{dept_code}")
    penalty_range = max_p - min_p
    base_penalty = min_p + int(penalty_range * factor)
    # Scale penalty based on MAP breach rate
    breach_rate = breached_count / max(maps_count, 1)
    severity_mult = 1.0 + breach_rate * 1.0
    estimated_penalty_inr = int(base_penalty * scale * severity_mult)

    overdue_rate = overdue_count / max(maps_count, 1)
    score_drop = _estimate_score_drop(breach_rate, overdue_rate)
    rep_risk = _reputational_risk(score_drop)

    timeline = _build_timeline(ignore_days)
    regulatory_actions = _build_regulatory_actions(score_drop, ignore_days)

    # Affected departments from actual MAP assignments
    affected = []
    if maps_count > 0:
        conn2 = get_connection()
        try:
            assigned_depts = conn2.execute(
                "SELECT DISTINCT assigned_to FROM maps WHERE circular_id=? AND assigned_to IS NOT NULL",
                (circular_id,),
            ).fetchall()
            for d in assigned_depts:
                dept = d["assigned_to"]
                share = _deterministic_factor(f"share-{circular_id}-{dept}")
                affected.append({
                    "department_code": dept,
                    "estimated_penalty_share_inr": round(estimated_penalty_inr * share * 0.3),
                    "compliance_impact": f"{dept} will face increased scrutiny and reporting burden",
                })
            conn2.close()
        except Exception:
            conn2.close()
    if not affected:
        cat = _dept_category(dept_code)
        depts = [cat] if cat != "Default" else ["Operations"]
        for d in depts:
            share = _deterministic_factor(f"dept-{circular_id}-{d}")
            affected.append({
                "department_code": d,
                "estimated_penalty_share_inr": round(estimated_penalty_inr * share * 0.3),
                "compliance_impact": f"{d} will face increased scrutiny and reporting burden",
            })

    financial_risk_estimate = {
        "min_inr": int(min_p * scale),
        "max_inr": int(max_p * scale),
        "best_case": int(min_p * scale * 0.5),
        "worst_case": int(max_p * scale * 1.5),
    }

    result = {
        "circular_id": circular_id,
        "circular_number": circular.get("circular_number", ""),
        "subject_line": circular.get("subject_line", ""),
        "department_code": dept_code,
        "issue_date": circular.get("issue_date", ""),
        "maps_count": maps_count,
        "breached_count": breached_count,
        "overdue_count": overdue_count,
        "ignore_days": ignore_days,
        "estimated_penalty_inr": estimated_penalty_inr,
        "compliance_score_drop": score_drop,
        "reputational_risk": rep_risk,
        "affected_departments": affected,
        "customer_impact": f"Based on {maps_count} compliance action(s) for this circular",
        "timeline_impact": timeline,
        "regulatory_actions": regulatory_actions,
        "financial_risk_estimate": financial_risk_estimate,
        "simulated_at": datetime.now().isoformat(),
    }

    ensure_impact_table()
    conn = get_connection()
    conn.execute(
        """INSERT INTO impact_simulations
           (circular_id, ignore_days, penalty_estimate, score_drop, reputational_risk, details)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (circular_id, ignore_days, estimated_penalty_inr, score_drop, rep_risk, str(result)),
    )
    conn.commit()
    conn.close()

    if blockchain is not None:
        try:
            blockchain.add_entry("IMPACT_SIMULATED", {
                "circular_id": circular_id,
                "circular_number": circular.get("circular_number", ""),
                "ignore_days": ignore_days,
                "penalty_estimate": estimated_penalty_inr,
                "score_drop": score_drop,
                "reputational_risk": rep_risk,
            })
            logger.debug("Blockchain entry added for IMPACT_SIMULATED")
        except Exception as e:
            logger.warning("Failed to add blockchain entry: %s", e)

    return result


def get_impact_history(circular_id: int) -> list[dict]:
    ensure_impact_table()
    conn = get_connection()
    rows = conn.execute(
        """SELECT id, circular_id, ignore_days, penalty_estimate, score_drop,
                  reputational_risk, details, created_at
           FROM impact_simulations
           WHERE circular_id = ?
           ORDER BY created_at DESC""",
        (circular_id,),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]
