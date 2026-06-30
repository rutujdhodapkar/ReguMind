"""
Phantom Compliance — Compliance Checker Agent
Comprehensive compliance checking across all dimensions:
- Overdue items
- Pending approvals
- Missing evidence
- Unresolved conflicts
- Critical circulars
- Generates overall compliance score
"""

import json
import logging
from datetime import datetime, timedelta

logger = logging.getLogger("phantom_compliance.compliance_checker")


def run_full_compliance_check() -> dict:
    """
    Run a full compliance check across all dimensions.
    Returns comprehensive compliance report.
    """
    conn = __import__("utils.database", fromlist=["get_connection"]).get_connection()

    # 1. Overdue items
    overdue = conn.execute(
        "SELECT count(*) FROM maps WHERE deadline_date < date('now') AND status NOT IN ('VALIDATED', 'SUPERSEDED')"
    ).fetchone()[0]

    # 2. Total maps
    total_maps = conn.execute("SELECT count(*) FROM maps").fetchone()[0]

    # 3. Validated maps
    validated = conn.execute("SELECT count(*) FROM maps WHERE status='VALIDATED'").fetchone()[0]

    # 4. Escalated/breached
    breached = conn.execute("SELECT count(*) FROM maps WHERE status IN ('BREACHED', 'ESCALATED')").fetchone()[0]

    # 5. Pending approval (acknowledgement)
    pending_ack = conn.execute(
        "SELECT count(*) FROM maps WHERE acknowledged=0 OR acknowledged IS NULL"
    ).fetchone()[0] if 'acknowledged' in [r[1] for r in conn.execute("PRAGMA table_info(maps)").fetchall()] else 0

    # 6. Unresolved conflicts
    try:
        unresolved_conflicts = conn.execute(
            "SELECT count(*) FROM conflicts WHERE resolved=0"
        ).fetchone()[0]
    except Exception:
        unresolved_conflicts = 0

    # 7. Missing evidence
    missing_evidence = conn.execute(
        "SELECT count(*) FROM maps WHERE (evidence_text IS NULL OR evidence_text = '') AND status != 'SUPERSEDED'"
    ).fetchone()[0]

    # 8. Critical circulars (last 30 days with unaddressed MAPs)
    critical_unaddressed = conn.execute("""
        SELECT count(*) FROM circulars c
        WHERE c.issue_date > date('now', '-30 days')
        AND EXISTS (SELECT 1 FROM maps m WHERE m.circular_id=c.id AND m.status NOT IN ('VALIDATED', 'SUPERSEDED'))
    """).fetchone()[0]

    conn.close()

    # Calculate scores (0-100, higher = better)
    completion_rate = (validated / max(total_maps, 1)) * 100
    overdue_penalty = min(overdue * 5, 30)
    breach_penalty = min(breached * 10, 40)
    evidence_penalty = min(missing_evidence * 3, 15)
    conflict_penalty = min(unresolved_conflicts * 5, 15)

    compliance_score = max(0, min(100,
        100 - overdue_penalty - breach_penalty - evidence_penalty - conflict_penalty
    ))

    status = "COMPLIANT" if compliance_score >= 80 else "AT_RISK" if compliance_score >= 50 else "CRITICAL"

    return {
        "compliance_score": round(compliance_score, 1),
        "status": status,
        "metrics": {
            "total_maps": total_maps,
            "validated": validated,
            "overdue": overdue,
            "breached": breached,
            "pending_acknowledgement": pending_ack,
            "unresolved_conflicts": unresolved_conflicts,
            "missing_evidence": missing_evidence,
            "critical_unaddressed": critical_unaddressed,
        },
        "penalties": {
            "overdue_penalty": overdue_penalty,
            "breach_penalty": breach_penalty,
            "evidence_penalty": evidence_penalty,
            "conflict_penalty": conflict_penalty,
        },
        "completion_rate": round(completion_rate, 1),
    }


def get_department_compliance(dept_code: str) -> dict:
    """Get compliance status for a specific department."""
    conn = __import__("utils.database", fromlist=["get_connection"]).get_connection()

    total = conn.execute(
        "SELECT count(*) FROM maps WHERE assigned_to=? OR department_code=?",
        (dept_code, dept_code),
    ).fetchone()[0]

    validated = conn.execute(
        "SELECT count(*) FROM maps WHERE (assigned_to=? OR department_code=?) AND status='VALIDATED'",
        (dept_code, dept_code),
    ).fetchone()[0]

    overdue = conn.execute(
        "SELECT count(*) FROM maps WHERE (assigned_to=? OR department_code=?) AND deadline_date < date('now') AND status NOT IN ('VALIDATED', 'SUPERSEDED')",
        (dept_code, dept_code),
    ).fetchone()[0]

    breached = conn.execute(
        "SELECT count(*) FROM maps WHERE (assigned_to=? OR department_code=?) AND status IN ('BREACHED', 'ESCALATED')",
        (dept_code, dept_code),
    ).fetchone()[0]

    conn.close()

    score = (validated / max(total, 1)) * 100 if total > 0 else 100
    score -= min(overdue * 5, 30)
    score = max(0, score)

    return {
        "department": dept_code,
        "total_maps": total,
        "validated": validated,
        "overdue": overdue,
        "breached": breached,
        "compliance_score": round(score, 1),
        "status": "COMPLIANT" if score >= 80 else "AT_RISK" if score >= 50 else "CRITICAL",
    }
