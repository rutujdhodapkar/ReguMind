"""
Phantom Compliance — Auto-Draft Compliance Evidence
Generates draft compliance evidence documents for audit readiness.
"""

import logging
from datetime import datetime
from utils.database import get_connection

logger = logging.getLogger("phantom_compliance.evidence_drafter")

def ensure_drafts_table():
    conn = get_connection()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS evidence_drafts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            map_id INTEGER NOT NULL,
            draft_type TEXT NOT NULL,
            title TEXT,
            content TEXT,
            word_count INTEGER DEFAULT 0,
            created_at TEXT DEFAULT (datetime('now'))
        )
    """)
    conn.commit()
    conn.close()
    logger.debug("evidence_drafts table ensured.")

def draft_board_minutes(map_id: int) -> str:
    conn = get_connection()
    map_row = conn.execute("SELECT * FROM maps WHERE id=?", (map_id,)).fetchone()
    conn.close()
    if not map_row:
        return ""
    circ_id = map_row.get("circular_id", "Unknown")
    conn = get_connection()
    circ = conn.execute("SELECT * FROM circulars WHERE id=?", (circ_id,)).fetchone()
    conn.close()
    circ_number = circ["number"] if circ else str(circ_id)
    today = datetime.now().strftime("%B %d, %Y")
    text = (
        f"BOARD MEETING MINUTES\n"
        f"Date: {today}\n"
        f"Subject: Compliance with RBI Circular {circ_number}\n\n"
        f"The board reviewed the requirements outlined in RBI Circular {circ_number}. "
        f"After discussion, the board resolved to implement the necessary changes as outlined in MAP #{map_id}. "
        f"The compliance team is directed to complete implementation within the stipulated timeline. "
        f"A progress report shall be presented at the next board meeting.\n\n"
        f"Resolution Passed: Unanimously.\n"
    )
    return text

def draft_implementation_report(map_id: int) -> str:
    conn = get_connection()
    map_row = conn.execute("SELECT * FROM maps WHERE id=?", (map_id,)).fetchone()
    conn.close()
    if not map_row:
        return ""
    circ_id = map_row.get("circular_id", "Unknown")
    conn = get_connection()
    circ = conn.execute("SELECT * FROM circulars WHERE id=?", (circ_id,)).fetchone()
    conn.close()
    circ_number = circ["number"] if circ else str(circ_id)
    today = datetime.now().strftime("%B %d, %Y")
    text = (
        f"IMPLEMENTATION REPORT\n"
        f"Date: {today}\n"
        f"Reference: RBI Circular {circ_number} / MAP #{map_id}\n\n"
        f"Implementation Status: In Progress\n\n"
        f"Activities Undertaken:\n"
        f"1. Reviewed circular requirements and mapped to existing controls.\n"
        f"2. Identified gaps in current compliance posture.\n"
        f"3. Assigned ownership to respective department heads.\n"
        f"4. Initiated system changes as per implementation plan.\n\n"
        f"Next Steps:\n"
        f"- Complete system updates by next review cycle.\n"
        f"- Conduct internal testing of new controls.\n"
        f"- Prepare for regulatory inspection.\n"
    )
    return text

def draft_audit_response(map_id: int) -> str:
    conn = get_connection()
    map_row = conn.execute("SELECT * FROM maps WHERE id=?", (map_id,)).fetchone()
    conn.close()
    if not map_row:
        return ""
    circ_id = map_row.get("circular_id", "Unknown")
    conn = get_connection()
    circ = conn.execute("SELECT * FROM circulars WHERE id=?", (circ_id,)).fetchone()
    conn.close()
    circ_number = circ["number"] if circ else str(circ_id)
    today = datetime.now().strftime("%B %d, %Y")
    text = (
        f"AUDIT RESPONSE\n"
        f"Date: {today}\n"
        f"Audit Reference: Circular {circ_number} / MAP #{map_id}\n\n"
        f"Observation: Compliance implementation for the above-referenced circular was reviewed.\n\n"
        f"Management Response:\n"
        f"The organization has implemented the required controls as per MAP #{map_id}. "
        f"All system changes have been validated and tested. "
        f"Evidence of implementation is attached for review.\n\n"
        f"Action Taken:\n"
        f"- Control implementation verified.\n"
        f"- Employee training completed.\n"
        f"- Monitoring mechanisms established.\n\n"
        f"Status: Compliant.\n"
    )
    return text

def draft_employee_communication(map_id: int) -> str:
    conn = get_connection()
    map_row = conn.execute("SELECT * FROM maps WHERE id=?", (map_id,)).fetchone()
    conn.close()
    if not map_row:
        return ""
    circ_id = map_row.get("circular_id", "Unknown")
    conn = get_connection()
    circ = conn.execute("SELECT * FROM circulars WHERE id=?", (circ_id,)).fetchone()
    conn.close()
    circ_number = circ["number"] if circ else str(circ_id)
    today = datetime.now().strftime("%B %d, %Y")
    text = (
        f"EMPLOYEE COMMUNICATION\n"
        f"Date: {today}\n"
        f"Subject: Important Compliance Update - RBI Circular {circ_number}\n\n"
        f"Dear Team,\n\n"
        f"Please be advised that the organization is implementing changes in response to RBI Circular {circ_number}. "
        f"As part of MAP #{map_id}, all relevant departments are required to adhere to the updated procedures.\n\n"
        f"Key Actions Required:\n"
        f"1. Review the updated compliance guidelines.\n"
        f"2. Complete the mandatory training module.\n"
        f"3. Update your departmental procedures accordingly.\n\n"
        f"Please direct any questions to the compliance team.\n\n"
        f"Regards,\nCompliance Department\n"
    )
    return text

def draft_evidence(map_id: int) -> dict:
    ensure_drafts_table()
    conn = get_connection()
    map_row = conn.execute("SELECT * FROM maps WHERE id=?", (map_id,)).fetchone()
    if not map_row:
        conn.close()
        return {"map_id": map_id, "circular_number": "Unknown", "drafts": [], "error": "MAP not found"}
    circ_id = map_row.get("circular_id", "Unknown")
    circ = conn.execute("SELECT * FROM circulars WHERE id=?", (circ_id,)).fetchone()
    conn.close()
    circ_number = circ["number"] if circ else str(circ_id)
    drafts = []
    draft_configs = [
        ("board_minutes", "Board Meeting Minutes", draft_board_minutes),
        ("implementation_report", "Implementation Report", draft_implementation_report),
        ("audit_response", "Audit Response", draft_audit_response),
        ("employee_communication", "Employee Communication", draft_employee_communication),
    ]
    for dtype, dtitle, dfunc in draft_configs:
        content = dfunc(map_id)
        wc = len(content.split())
        drafts.append({
            "type": dtype,
            "title": dtitle,
            "content": content,
            "word_count": wc,
        })
    return {
        "map_id": map_id,
        "circular_number": circ_number,
        "drafts": drafts,
    }
