"""
PHANTOM COMPLIANCE — Acknowledgement System
24-hour acknowledgement window for assigned MAPs.
Auto-escalates unacknowledged MAPs to department head and CCO.
Immutably records acknowledgement timestamp in blockchain.
"""

import hashlib
import logging
from datetime import datetime, timedelta

from utils.database import get_connection, get_maps_for_department
from utils.db_extensions import create_notification, audit_log
from p_crypto.blockchain import Blockchain

logger = logging.getLogger("phantom_compliance.acknowledgement")

ACKNOWLEDGEMENT_WINDOW_HOURS = 24


def assign_map_with_acknowledgement(map_id: int, department: str, blockchain: Blockchain) -> bool:
    """Assign a MAP and set status to ASSIGNED_UNACKNOWLEDGED with 24h timer."""
    conn = get_connection()
    conn.execute(
        "UPDATE maps SET assigned_to=?, status='ASSIGNED_UNACKNOWLEDGED', assigned_at=datetime('now'), acknowledged_at=NULL WHERE id=?",
        (department, map_id),
    )
    conn.commit()
    conn.close()

    block = blockchain.add_entry("MAP_ASSIGNED_UNACKNOWLEDGED", {
        "map_id": map_id,
        "department": department,
        "acknowledgement_window_hours": ACKNOWLEDGEMENT_WINDOW_HOURS,
    })
    audit_log(0, "SYSTEM", "MAP_ASSIGNED_UNACKNOWLEDGED", "map", map_id,
              f"Assigned to {department}, awaiting acknowledgement")
    create_notification(
        "New MAP Assigned — Acknowledge Required",
        f"MAP #{map_id} assigned to {department}. Acknowledge within {ACKNOWLEDGEMENT_WINDOW_HOURS}h.",
        "WARNING", role=department,
    )
    return True


def acknowledge_map(map_id: int, user_id: int, username: str, password_hash: str, blockchain: Blockchain) -> dict:
    """
    Department officer acknowledges a MAP.
    Requires password re-verification for legal timestamp.
    Returns {"ok": True/False, "error": str}
    """
    from auth.password import verify_password

    conn = get_connection()
    row = conn.execute(
        "SELECT password_hash FROM users_v2 WHERE id = ?", (user_id,)
    ).fetchone()
    if not row:
        conn.close()
        return {"ok": False, "error": "User not found"}

    if not verify_password(password_hash.encode("utf-8"), row["password_hash"].encode("utf-8")):
        conn.close()
        return {"ok": False, "error": "Password verification failed"}

    now = datetime.utcnow().isoformat()
    ack_hash = hashlib.sha256(f"{username}:{map_id}:{now}".encode()).hexdigest()

    conn.execute(
        "UPDATE maps SET status='ASSIGNED_ACKNOWLEDGED', acknowledged_by=?, acknowledged_hash=?, acknowledged_at=? WHERE id=?",
        (username, ack_hash, now, map_id),
    )
    conn.commit()
    conn.close()

    block = blockchain.add_entry("MAP_ACKNOWLEDGED", {
        "map_id": map_id,
        "acknowledged_by_hash": ack_hash,
        "acknowledged_by": username,
        "timestamp": now,
    })
    audit_log(user_id, username, "MAP_ACKNOWLEDGED", "map", map_id,
              f"Acknowledged. Block: {block['index']}")
    return {"ok": True, "block_index": block["index"], "hash": ack_hash}


def check_unacknowledged_maps(blockchain: Blockchain) -> dict:
    """
    Check all ASSIGNED_UNACKNOWLEDGED MAPs.
    If > 24h elapsed, escalate to department head and CCO.
    """
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM maps WHERE status='ASSIGNED_UNACKNOWLEDGED'",
    ).fetchall()
    escalated = 0

    for row in rows:
        row = dict(row)
        assigned_at = row.get("assigned_at") or row.get("created_at") or row.get("ingested_at", "")
        if not assigned_at:
            continue
        try:
            assigned_time = datetime.strptime(assigned_at[:19], "%Y-%m-%d %H:%M:%S")
        except (ValueError, IndexError):
            try:
                assigned_time = datetime.strptime(assigned_at[:19], "%Y-%m-%dT%H:%M:%S")
            except (ValueError, IndexError):
                continue

        elapsed = datetime.utcnow() - assigned_time
        if elapsed.total_seconds() > ACKNOWLEDGEMENT_WINDOW_HOURS * 3600:
            conn.execute(
                "UPDATE maps SET status='ACKNOWLEDGEMENT_OVERDUE' WHERE id=?",
                (row["id"],),
            )
            department = row.get("assigned_to", "UNKNOWN")
            block = blockchain.add_entry("ACKNOWLEDGEMENT_BREACHED", {
                "map_id": row["id"],
                "department": department,
                "elapsed_hours": round(elapsed.total_seconds() / 3600, 1),
            })
            audit_log(0, "SYSTEM", "ACKNOWLEDGEMENT_BREACHED", "map", row["id"],
                      f"Not acknowledged by {department} within {ACKNOWLEDGEMENT_WINDOW_HOURS}h")
            create_notification(
                "Acknowledgement Breached",
                f"MAP #{row['id']} not acknowledged by {department} within 24h. Escalated to CCO.",
                "ESCALATION", role="CCO",
            )
            create_notification(
                "Acknowledgement Overdue — Immediate Action Required",
                f"MAP #{row['id']} acknowledgement overdue. Action required.",
                "WARNING", role=department,
            )
            escalated += 1

    conn.commit()
    conn.close()
    return {"escalated": escalated}


def get_unacknowledged_count(department: str = None) -> dict:
    conn = get_connection()
    if department:
        count = conn.execute(
            "SELECT count(*) FROM maps WHERE status='ASSIGNED_UNACKNOWLEDGED' AND assigned_to=?",
            (department,),
        ).fetchone()[0]
        total = conn.execute(
            "SELECT count(*) FROM maps WHERE status='ASSIGNED_UNACKNOWLEDGED'",
        ).fetchone()[0]
    else:
        count = conn.execute(
            "SELECT count(*) FROM maps WHERE status='ASSIGNED_UNACKNOWLEDGED'",
        ).fetchone()[0]
        total = count
    conn.close()
    return {"unacknowledged": count, "total_unacknowledged": total}


def get_oldest_unacknowledged(department: str) -> dict | None:
    conn = get_connection()
    row = conn.execute(
        """SELECT m.*, c.circular_number
           FROM maps m JOIN circulars c ON m.circular_id = c.id
           WHERE m.status='ASSIGNED_UNACKNOWLEDGED' AND m.assigned_to=?
           ORDER BY m.id ASC LIMIT 1""",
        (department,),
    ).fetchone()
    conn.close()
    if row:
        row = dict(row)
        assigned_at = row.get("assigned_at") or row.get("created_at") or ""
        if assigned_at:
            try:
                assigned_time = datetime.strptime(assigned_at[:19], "%Y-%m-%d %H:%M:%S")
                remaining = timedelta(hours=ACKNOWLEDGEMENT_WINDOW_HOURS) - (datetime.utcnow() - assigned_time)
                row["remaining_seconds"] = max(0, int(remaining.total_seconds()))
            except (ValueError, IndexError):
                row["remaining_seconds"] = ACKNOWLEDGEMENT_WINDOW_HOURS * 3600
        else:
            row["remaining_seconds"] = ACKNOWLEDGEMENT_WINDOW_HOURS * 3600
        return row
    return None
