"""
PHANTOM COMPLIANCE — Executive Panic Button
One-click "Prepare for RBI Inspection" package generator.
Gathers all compliance data for CCO review ahead of regulatory inspection.
"""

import json
import hashlib
import logging
from datetime import datetime
from typing import Optional

from utils.database import get_connection, get_all_circulars, get_all_maps
from utils.db_extensions import audit_log, create_notification
from agents.risk_scorer import calculate_bank_score, get_score_history

logger = logging.getLogger("phantom_compliance.panic_button")

try:
    from agents.implementation_planner import get_plan
    HAS_PLANNER = True
except ImportError:
    HAS_PLANNER = False
    logger.warning("implementation_planner not available — plan data will be empty")

STATUS_GROUPS = [
    "PENDING", "ASSIGNED", "VALIDATED", "BREACHED", "ESCALATED", "SUPERSEDED",
]


def _get_circular_counts(conn) -> dict:
    total = conn.execute("SELECT count(*) FROM circulars").fetchone()[0]
    return {"total": total}


def _get_maps_grouped(conn) -> dict:
    grouped = {}
    for status in STATUS_GROUPS:
        count = conn.execute(
            "SELECT count(*) FROM maps WHERE status=?", (status,)
        ).fetchone()[0]
        grouped[status] = count
    return grouped


def _get_all_evidence(conn) -> list[dict]:
    rows = conn.execute(
        """SELECT m.id, m.map_text, m.evidence_text, m.evidence_file_path,
                  m.status, m.assigned_to, c.circular_number
           FROM maps m JOIN circulars c ON m.circular_id = c.id
           WHERE m.evidence_text IS NOT NULL AND m.evidence_text != ''
           ORDER BY m.id"""
    ).fetchall()
    return [dict(r) for r in rows]


def _get_deadlines(conn) -> list[dict]:
    rows = conn.execute(
        """SELECT m.id, m.map_text, m.deadline_date, m.status, m.assigned_to,
                  c.circular_number
           FROM maps m JOIN circulars c ON m.circular_id = c.id
           ORDER BY m.deadline_date ASC"""
    ).fetchall()
    result = []
    today = datetime.now().strftime("%Y-%m-%d")
    for r in rows:
        rd = dict(r)
        dl = rd.get("deadline_date", "") or ""
        rd["is_breached"] = (
            rd.get("status") in ("BREACHED", "ESCALATED") or
            (dl < today and rd.get("status") not in ("VALIDATED", "SUPERSEDED"))
        )
        result.append(rd)
    return result


def _get_all_conflicts(conn) -> list[dict]:
    rows = conn.execute(
        "SELECT * FROM conflicts ORDER BY created_at DESC"
    ).fetchall()
    return [dict(r) for r in rows]


def _get_all_users(conn) -> list[dict]:
    rows = conn.execute(
        "SELECT id, username, role, department_code, is_active FROM users_v2 ORDER BY id"
    ).fetchall()
    return [dict(r) for r in rows]


def _get_acknowledgements(conn) -> list[dict]:
    rows = conn.execute(
        """SELECT m.id, m.map_text, m.status, m.assigned_to, m.assigned_to_user_id,
                  m.created_at, c.circular_number
           FROM maps m JOIN circulars c ON m.circular_id = c.id
           WHERE m.status LIKE 'ASSIGNED%'
           ORDER BY m.id DESC"""
    ).fetchall()
    return [dict(r) for r in rows]


def _get_implementation_plans() -> list[dict]:
    if not HAS_PLANNER:
        return []
    try:
        plans = []
        conn = get_connection()
        map_ids = conn.execute("SELECT id FROM maps").fetchall()
        conn.close()
        for mid in map_ids:
            plan = get_plan(mid["id"])
            if plan:
                plans.append(plan)
        return plans
    except Exception as e:
        logger.error(f"Error fetching implementation plans: {e}")
        return []


def _verify_blockchain_integrity(blockchain) -> dict:
    if blockchain is None:
        return {"verified": False, "errors": ["No blockchain provided"], "block_count": 0}
    try:
        chain = blockchain.get_chain()
        valid, errors = blockchain.verify_chain()
        return {
            "verified": valid,
            "errors": errors,
            "block_count": len(chain),
            "last_block_index": chain[-1]["index"] if chain else 0,
            "last_block_hash": chain[-1]["block_hash"] if chain else "",
        }
    except Exception as e:
        logger.error(f"Blockchain verification failed: {e}")
        return {"verified": False, "errors": [str(e)], "block_count": 0}


def generate_inspection_package(cco_user_id: int, cco_username: str, blockchain=None) -> dict:
    conn = get_connection()

    circulars = get_all_circulars()
    maps_data = get_all_maps()
    circular_counts = _get_circular_counts(conn)
    maps_grouped = _get_maps_grouped(conn)
    evidence_list = _get_all_evidence(conn)
    deadlines = _get_deadlines(conn)
    conflicts = _get_all_conflicts(conn)
    risk_scores = calculate_bank_score()
    score_history = get_score_history(days=30)
    users = _get_all_users(conn)
    acknowledgements = _get_acknowledgements(conn)
    plans = _get_implementation_plans()
    blockchain_status = _verify_blockchain_integrity(blockchain)

    package = {
        "prepared_at": datetime.now().isoformat(),
        "prepared_by": cco_username,
        "prepared_by_user_id": cco_user_id,
        "circulars": {
            "total": circular_counts["total"],
            "items": [
                {
                    "id": c["id"],
                    "circular_number": c.get("circular_number", ""),
                    "department_code": c.get("department_code", ""),
                    "issue_date": c.get("issue_date", ""),
                    "subject_line": c.get("subject_line", ""),
                }
                for c in circulars
            ],
        },
        "maps": {
            "total": len(maps_data),
            "by_status": maps_grouped,
            "items": [
                {
                    "id": m["id"],
                    "circular_id": m["circular_id"],
                    "circular_number": m.get("circular_number", ""),
                    "map_text": m.get("map_text", ""),
                    "assigned_to": m.get("assigned_to") or "UNASSIGNED",
                    "status": m.get("status", "PENDING"),
                    "deadline_date": m.get("deadline_date", ""),
                    "deadline_days": m.get("deadline_days"),
                    "has_evidence": bool(m.get("evidence_text")),
                }
                for m in maps_data
            ],
        },
        "evidence": {
            "total": len(evidence_list),
            "items": evidence_list,
        },
        "deadlines": {
            "total": len(deadlines),
            "breached_count": sum(1 for d in deadlines if d.get("is_breached")),
            "items": deadlines,
        },
        "conflicts": {
            "total": len(conflicts),
            "resolved_count": sum(1 for c in conflicts if c.get("resolved")),
            "unresolved_count": sum(1 for c in conflicts if not c.get("resolved")),
            "items": [
                {
                    "id": c["id"],
                    "circular_a": c.get("circular_a_id"),
                    "circular_b": c.get("circular_b_id"),
                    "relationship": c.get("relationship", ""),
                    "resolved": bool(c.get("resolved")),
                    "resolution": c.get("resolution", ""),
                }
                for c in conflicts
            ],
        },
        "risk_scores": risk_scores,
        "score_history": score_history,
        "users": {
            "total": len(users),
            "items": users,
        },
        "acknowledgements": {
            "total": len(acknowledgements),
            "items": acknowledgements,
        },
        "implementation_plans": {
            "total": len(plans),
            "items": plans[:50],
        },
        "blockchain": blockchain_status,
    }

    summary = {
        "prepared_at": package["prepared_at"],
        "prepared_by": cco_username,
        "circulars_total": circular_counts["total"],
        "maps_total": len(maps_data),
        "maps_by_status": maps_grouped,
        "evidence_total": len(evidence_list),
        "deadlines_total": len(deadlines),
        "deadlines_breached": sum(1 for d in deadlines if d.get("is_breached")),
        "conflicts_total": len(conflicts),
        "conflicts_unresolved": sum(1 for c in conflicts if not c.get("resolved")),
        "bank_risk_score": risk_scores.get("bank_score", 0),
        "bank_risk_threshold": risk_scores.get("threshold_label", "UNKNOWN"),
        "users_total": len(users),
        "acknowledgements_pending": len(acknowledgements),
        "implementation_plans_total": len(plans),
        "blockchain_verified": blockchain_status.get("verified", False),
        "blockchain_block_count": blockchain_status.get("block_count", 0),
    }

    package_json_str = json.dumps(package, indent=2, default=str)
    summary_json_str = json.dumps(summary, indent=2, default=str)

    blockchain_hash = ""
    if blockchain is not None:
        try:
            block = blockchain.add_entry("INSPECTION_PACKAGE_PREPARED", {
                "prepared_by": cco_username,
                "prepared_by_user_id": cco_user_id,
                "circulars_count": circular_counts["total"],
                "maps_count": len(maps_data),
                "evidence_count": len(evidence_list),
                "breaches": sum(1 for d in deadlines if d.get("is_breached")),
                "bank_score": risk_scores.get("bank_score", 0),
            })
            blockchain_hash = block.get("block_hash", "")
        except Exception as e:
            logger.error(f"Failed to add blockchain entry: {e}")

    conn.execute(
        """INSERT INTO inspection_packages
           (prepared_by, prepared_by_user_id, summary, package_json, blockchain_hash)
           VALUES (?, ?, ?, ?, ?)""",
        (cco_username, cco_user_id, summary_json_str, package_json_str, blockchain_hash),
    )
    conn.commit()
    package_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.close()

    audit_log(cco_user_id, cco_username, "INSPECTION_PACKAGE_PREPARED", "package", package_id,
              f"Inspection package #{package_id} prepared — {circular_counts['total']} circulars, {len(maps_data)} MAPs")
    create_notification(
        "Inspection Package Ready",
        f"RBI Inspection package #{package_id} prepared by {cco_username}",
        "INFO", role="CCO",
    )

    logger.info(f"Inspection package #{package_id} prepared by {cco_username}")
    return {
        "ok": True,
        "package_id": package_id,
        "summary": summary,
        "blockchain_hash": blockchain_hash,
    }


def get_inspection_package(package_id: int) -> dict:
    conn = get_connection()
    row = conn.execute(
        "SELECT * FROM inspection_packages WHERE id=?", (package_id,)
    ).fetchone()
    conn.close()

    if not row:
        return {"ok": False, "error": "Package not found"}

    pkg = dict(row)
    result = {
        "id": pkg["id"],
        "prepared_at": pkg["prepared_at"],
        "prepared_by": pkg["prepared_by"],
        "blockchain_hash": pkg.get("blockchain_hash", ""),
    }
    if pkg.get("summary"):
        try:
            result["summary"] = json.loads(pkg["summary"])
        except (json.JSONDecodeError, TypeError):
            result["summary"] = pkg["summary"]
    if pkg.get("package_json"):
        try:
            result["package"] = json.loads(pkg["package_json"])
        except (json.JSONDecodeError, TypeError):
            result["package"] = pkg["package_json"]
    return result


def list_inspection_packages(limit: int = 10) -> list[dict]:
    conn = get_connection()
    rows = conn.execute(
        "SELECT id, prepared_at, prepared_by, blockchain_hash FROM inspection_packages ORDER BY id DESC LIMIT ?",
        (limit,),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def ensure_panic_table():
    conn = get_connection()
    conn.execute("""CREATE TABLE IF NOT EXISTS inspection_packages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        prepared_at TEXT DEFAULT (datetime('now')),
        prepared_by TEXT NOT NULL,
        prepared_by_user_id INTEGER NOT NULL,
        summary TEXT DEFAULT '{}',
        package_json TEXT DEFAULT '{}',
        blockchain_hash TEXT DEFAULT '',
        created_at TEXT DEFAULT (datetime('now'))
    )""")
    conn.commit()
    conn.close()
    logger.info("Ensured inspection_packages table exists")
