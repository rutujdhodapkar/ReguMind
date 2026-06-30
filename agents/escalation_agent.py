"""
ESCALATION AGENT
Any MAP with status = BREACHED or PENDING past deadline
gets flagged in the CCO Escalation view.
Appends blockchain block: ESCALATED_TO_CCO.
"""

import json
import logging
from datetime import datetime

from utils.database import get_escalated_maps, escalate_map, check_deadlines, get_all_maps
from p_crypto.blockchain import Blockchain

logger = logging.getLogger("phantom_compliance.escalation")


def escalate_overdue_maps(blockchain: Blockchain):
    """
    Find overdue maps not yet escalated and escalate them.
    Returns list of escalated map IDs.
    """
    escalated = []
    all_maps = get_all_maps()
    today = datetime.now().strftime("%Y-%m-%d")

    for mp in all_maps:
        if mp["status"] in ("BREACHED", "ESCALATED"):
            continue
        if mp["status"] in ("PENDING", "ASSIGNED", "ASSIGNED_UNACKNOWLEDGED", "ASSIGNED_ACKNOWLEDGED", "ACKNOWLEDGEMENT_OVERDUE") and mp.get("deadline_date", "9999-12-31") < today:
            escalate_map(mp["id"])
            payload = {
                "map_id": mp["id"],
                "map_text": mp["map_text"],
                "department": mp["assigned_to"],
                "deadline_date": mp["deadline_date"],
                "escalated_at": datetime.now().isoformat(),
            }
            blockchain.add_entry("ESCALATED_TO_CCO", payload)
            escalated.append(mp["id"])
            logger.warning(f"MAP #{mp['id']} escalated to CCO")

    return escalated


def get_escalation_view():
    """Get all escalated/breached maps for CCO view."""
    return get_escalated_maps()
