"""
Phantom Compliance — Policy Drift Detector
Flags when internal policy diverges from RBI circular requirements.
Tracks supersession: which circular replaces which.
"""

import json
import re
import logging
from datetime import datetime

logger = logging.getLogger("phantom_compliance.policy_drift")


def detect_policy_drift(policy_text: str, circular_id: int) -> dict:
    """
    Compare internal policy text against circular requirements.
    Returns drift analysis with mismatches.
    """
    conn = __import__("utils.database", fromlist=["get_connection"]).get_connection()
    circ = conn.execute(
        "SELECT id, circular_number, subject_line, body_text, department_code FROM circulars WHERE id=?",
        (circular_id,),
    ).fetchone()
    conn.close()

    if not circ:
        return {"error": "Circular not found"}

    circ = dict(circ)
    circ_text = (circ.get("body_text", "") or "") + " " + (circ.get("subject_line", "") or "")
    drift_points = []

    # Check for key requirement patterns in both
    requirement_patterns = [
        (r"within \d+ days?", "deadline"),
        (r"(?:shall|must|will|required to) (?:ensure|report|maintain|implement|submit|provide|update|train)",
         "obligation"),
        (r"(?:policy|procedure|process|system|framework|mechanism)", "system_change"),
        (r"(?:report|submit|file|send) (?:to|with|before|by)", "reporting"),
        (r"(?:train|training|awareness|capacity building)", "training"),
        (r"(?:audit|inspect|review|verify|check)", "audit"),
    ]

    for pattern, req_type in requirement_patterns:
        in_circular = bool(re.search(pattern, circ_text, re.IGNORECASE))
        in_policy = bool(re.search(pattern, policy_text, re.IGNORECASE))

        if in_circular and not in_policy:
            drift_points.append({
                "type": req_type,
                "severity": "HIGH",
                "detail": f"Circular requires {req_type} but internal policy does not address it",
                "circular_requirement": True,
                "policy_has": False,
            })
        elif not in_circular and in_policy:
            drift_points.append({
                "type": req_type,
                "severity": "LOW",
                "detail": f"Policy mentions {req_type} but circular does not require it",
                "circular_requirement": False,
                "policy_has": True,
            })

    drift_score = sum(1 for d in drift_points if d["severity"] == "HIGH") * 25
    drift_score = min(drift_score, 100)

    return {
        "circular_id": circular_id,
        "circular_number": circ["circular_number"],
        "drift_points": drift_points,
        "drift_score": drift_score,
        "drift_level": "CRITICAL" if drift_score >= 75 else "HIGH" if drift_score >= 50 else "MEDIUM" if drift_score >= 25 else "LOW",
        "recommendation": f"Policy needs update in {sum(1 for d in drift_points if d['severity'] == 'HIGH')} areas"
                          if drift_points else "Policy is aligned with circular",
    }


def track_supersession(old_circular_id: int, new_circular_id: int, relationship: str = "supersedes") -> dict:
    """
    Track which circular supersedes which.
    Relationship: 'supersedes', 'replaces', 'amends', 'overrides'
    """
    conn = __import__("utils.database", fromlist=["get_connection"]).get_connection()

    old_circ = conn.execute(
        "SELECT circular_number, subject_line FROM circulars WHERE id=?", (old_circular_id,)
    ).fetchone()
    new_circ = conn.execute(
        "SELECT circular_number, subject_line FROM circulars WHERE id=?", (new_circular_id,)
    ).fetchone()

    if not old_circ or not new_circ:
        conn.close()
        return {"error": "One or both circulars not found"}

    # Store in supersession table
    conn.execute("""
        INSERT OR REPLACE INTO supersessions
        (old_circular_id, new_circular_id, old_circular_number, new_circular_number,
         relationship, detected_at)
        VALUES (?, ?, ?, ?, ?, datetime('now'))
    """, (old_circular_id, new_circular_id, old_circ["circular_number"],
          new_circ["circular_number"], relationship))
    conn.commit()
    conn.close()

    logger.info(f"Supersession tracked: {old_circ['circular_number']} {relationship} {new_circ['circular_number']}")

    # Also mark old MAPs as SUPERSEDED
    try:
        conn = __import__("utils.database", fromlist=["get_connection"]).get_connection()
        conn.execute(
            "UPDATE maps SET status='SUPERSEDED' WHERE circular_id=? AND status NOT IN ('VALIDATED', 'SUPERSEDED')",
            (old_circular_id,),
        )
        conn.commit()
        conn.close()
    except Exception:
        pass

    return {
        "old": old_circ["circular_number"],
        "new": new_circ["circular_number"],
        "relationship": relationship,
        "old_map_superseded": True,
    }


def get_supersession_chain(circular_id: int) -> list[dict]:
    """Get the full supersession chain for a circular (both directions)."""
    conn = __import__("utils.database", fromlist=["get_connection"]).get_connection()
    chain = []

    # Forward: what this circular supersedes
    forward = conn.execute("""
        SELECT * FROM supersessions WHERE new_circular_id=?
        ORDER BY detected_at DESC
    """, (circular_id,)).fetchall()
    for r in forward:
        chain.append(dict(r))

    # Backward: what supersedes this circular
    backward = conn.execute("""
        SELECT * FROM supersessions WHERE old_circular_id=?
        ORDER BY detected_at DESC
    """, (circular_id,)).fetchall()
    for r in backward:
        chain.append(dict(r))

    conn.close()
    return chain


def ensure_policy_tables():
    conn = __import__("utils.database", fromlist=["get_connection"]).get_connection()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS supersessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            old_circular_id INTEGER NOT NULL,
            new_circular_id INTEGER NOT NULL,
            old_circular_number TEXT DEFAULT '',
            new_circular_number TEXT DEFAULT '',
            relationship TEXT DEFAULT 'supersedes',
            detected_at TEXT DEFAULT (datetime('now')),
            FOREIGN KEY(old_circular_id) REFERENCES circulars(id),
            FOREIGN KEY(new_circular_id) REFERENCES circulars(id)
        )
    """)
    conn.commit()
    conn.close()
