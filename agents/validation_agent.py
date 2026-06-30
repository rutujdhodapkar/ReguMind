"""
VALIDATION AGENT
- Checks each MAP's deadline vs current date
- If overdue and no evidence: marks as BREACHED
- If evidence exists: sends to LLM for validation
- If LLM confirms: marks as VALIDATED
- Appends blockchain blocks for each action
"""

import json
import logging
from datetime import datetime

from utils.database import (
    get_pending_maps,
    validate_map,
    breach_map,
    get_all_maps,
    check_deadlines,
)
from agents.llm_agent import validate_evidence
from p_crypto.blockchain import Blockchain

logger = logging.getLogger("phantom_compliance.validation")


def run_validation_cycle(blockchain: Blockchain):
    """
    Run one complete validation cycle:
    1. Check all maps for breached deadlines
    2. For maps with evidence, validate via LLM
    3. Append blockchain blocks
    """
    breached_ids = check_deadlines()
    for mid in breached_ids:
        breach_map(mid)
        payload = {"map_id": mid, "breached_at": datetime.now().isoformat()}
        blockchain.add_entry("DEADLINE_BREACHED", payload)
        logger.warning(f"MAP #{mid} deadline breached")

    all_maps = get_all_maps()
    validated_count = 0
    for mp in all_maps:
        if mp["status"] not in ("ASSIGNED", "ASSIGNED_ACKNOWLEDGED"):
            continue
        if not mp.get("evidence_text"):
            continue

        is_valid, reasoning = validate_evidence(
            mp["map_text"],
            mp["evidence_text"],
            mp.get("evidence_required", ""),
        )

        if is_valid:
            validate_map(mp["id"])
            payload = {
                "map_id": mp["id"],
                "reasoning": reasoning,
                "validated_at": datetime.now().isoformat(),
            }
            blockchain.add_entry("MAP_VALIDATED", payload)
            validated_count += 1
            logger.info(f"MAP #{mp['id']} validated by LLM")

    return {
        "breaches": len(breached_ids),
        "validated": validated_count,
    }
