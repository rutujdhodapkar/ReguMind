"""SQL fallback MAP generator — creates basic MAPs from circulars without LLM."""
import json
import logging
from datetime import datetime, timedelta

from utils.database import get_all_circulars, store_map, get_connection
from p_crypto.encryptor import encrypt

logger = logging.getLogger("phantom_compliance.fallback_generator")

def generate_maps_sql_fallback(mk: bytes) -> dict:
    """Generate basic MAPs for all circulars that have none. Returns count."""
    circs = get_all_circulars()
    conn = get_connection()
    generated = 0
    for c in circs:
        cid = c["id"]
        existing = conn.execute("SELECT COUNT(*) as cnt FROM maps WHERE circular_id=?", (cid,)).fetchone()
        if existing and existing["cnt"] > 0:
            continue
        subject = c.get("subject_line", "") or ""
        dept_code = c.get("department_code", "") or "KYC"
        circ_num = c.get("circular_number", "") or ""
        now_str = datetime.now().strftime("%Y-%m-%d")
        dept_hint = "KYC"
        if "IT" in dept_code.upper() or "TECH" in dept_code.upper() or "DIGITAL" in dept_code.upper():
            dept_hint = "IT_Security"
        elif "PAY" in dept_code.upper() or "SETTLE" in dept_code.upper():
            dept_hint = "Payments"
        elif "TREAS" in dept_code.upper() or "FOREX" in dept_code.upper():
            dept_hint = "Treasury"
        elif "CREDIT" in dept_code.upper() or "RISK" in dept_code.upper():
            dept_hint = "Credit_Risk"
        elif "KYC" in dept_code.upper() or "AML" in dept_code.upper() or "COMPLY" in dept_code.upper():
            dept_hint = "KYC"
        text = subject[:80] if subject else f"Comply with circular {circ_num or ('#'+str(cid))}"
        detail = {"what": text, "department_hint": dept_hint, "deadline_days_from_date": 30, "evidence_required": f"Signed compliance report for {text}"}
        detail_json = json.dumps(detail, ensure_ascii=False)
        ciphertext, nonce, auth_tag = encrypt(detail_json, mk)
        store_map(cid, text, ciphertext, nonce, auth_tag, dept_hint, 30, frequency="One-time", evidence_required=detail.get("evidence_required",""), map_id_label=f"RBI-{circ_num or 'MAP'}-{cid}")
        generated += 1
    conn.close()
    return {"generated": generated}
