"""
ROUTING AGENT
Routes each MAP to the correct department using LLM analysis first,
falls back to static dept_mapping if LLM is unavailable.
Assigns each MAP to the appropriate department and sets deadline dates.
Appends blockchain block for each assignment.
"""

import json
import logging
import os
from datetime import datetime, timedelta

from utils.dept_mapping import map_department, get_display_name
from utils.database import assign_map, get_pending_maps, get_connection
from p_crypto.blockchain import Blockchain
from utils.llm_queue import check_llm_health
from agents.llm_agent import _call_llm as llm_call

logger = logging.getLogger("phantom_compliance.routing")

VALID_DEPARTMENTS = {
    "KYC": "KYC",
    "PAYMENTS": "Payments",
    "IT_SECURITY": "IT_Security",
    "TREASURY": "Treasury",
    "FOREX": "Forex",
    "CREDIT_RISK": "Credit_Risk",
}


def _llm_routing_map(mp) -> str:
    """Use LLM to decide which department should handle this MAP."""
    prompt = f"""[INST] You are a compliance routing officer for an Indian bank.
Given this compliance action item (MAP), decide which single department must handle it.
Departments: KYC, Payments, IT_Security, Treasury, Forex, Credit_Risk

MAP text: {mp.get('map_text','')}
Department hint from extraction: {mp.get('department_hint','')}
Circular department code: {mp.get('circular_department','')}

Return ONLY the department name from the list above, no other text.
[/INST]"""
    try:
        resp = llm_call(prompt, max_tokens=32)
        if resp:
            resp = resp.strip().upper()
            for d, canonical in VALID_DEPARTMENTS.items():
                if d in resp:
                    return canonical
    except Exception:
        pass
    return ""


def route_all_pending(blockchain: Blockchain):
    """Route all pending MAPs to their respective departments."""
    pending = get_pending_maps()
    routed_count = 0
    use_llm = os.environ.get("PHANTOM_NO_LLM") != "1" and check_llm_health()

    for mp in pending:
        if mp["status"] != "PENDING":
            continue

        if use_llm:
            dept_role = _llm_routing_map(mp)
        else:
            dept_role = ""

        if not dept_role:
            dept_hint = mp.get("department_hint", "KYC")
            dept_role = map_department(dept_hint)

        try:
            from agents.acknowledgement_agent import assign_map_with_acknowledgement
            assign_map_with_acknowledgement(mp["id"], dept_role, blockchain)
        except Exception:
            assign_map(mp["id"], dept_role, user_id=0)

        payload = {
            "map_id": mp["id"],
            "map_text": mp["map_text"],
            "assigned_to": dept_role,
            "department": get_display_name(dept_role),
            "deadline_date": mp["deadline_date"],
        }
        blockchain.add_entry("MAP_ASSIGNED", payload)
        logger.info(
            f"MAP #{mp['id']} assigned to {get_display_name(dept_role)} "
            f"(deadline: {mp['deadline_date']})"
        )
        routed_count += 1

    if routed_count == 0:
        logger.info("No pending MAPs to route")
    return routed_count
