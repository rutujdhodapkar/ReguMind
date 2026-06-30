"""
Phantom Compliance — Cross-Regulator Support
Supports RBI, SEBI, IRDAI, and MEITY circulars with cross-regulator impact analysis.
"""

import logging
import re
from utils.database import get_connection

logger = logging.getLogger("phantom_compliance.cross_regulator")

REGULATORS = [
    {"code": "RBI", "name": "Reserve Bank of India", "color": "#1a3c6e"},
    {"code": "SEBI", "name": "Securities and Exchange Board of India", "color": "#2e7d32"},
    {"code": "IRDAI", "name": "Insurance Regulatory and Development Authority of India", "color": "#e65100"},
    {"code": "MEITY", "name": "Ministry of Electronics and Information Technology", "color": "#6a1b9a"},
]

def ensure_regulator_column():
    conn = get_connection()
    try:
        conn.execute("ALTER TABLE circulars ADD COLUMN regulator_code TEXT DEFAULT 'RBI'")
        conn.commit()
        logger.info("Added regulator_code column to circulars.")
    except Exception:
        conn.rollback()
        logger.debug("regulator_code column already exists.")
    conn.close()

def get_supported_regulators() -> list[dict]:
    ensure_regulator_column()
    conn = get_connection()
    result = []
    for reg in REGULATORS:
        row = conn.execute(
            "SELECT count(*) as cnt FROM circulars WHERE regulator_code=?", (reg["code"],)
        ).fetchone()
        entry = dict(reg)
        entry["circulars_count"] = row["cnt"] if row else 0
        result.append(entry)
    conn.close()
    return result

def get_regulator_circulars(regulator_code: str) -> list[dict]:
    ensure_regulator_column()
    conn = get_connection()
    rows = conn.execute(
        "SELECT id, title, number, date, status FROM circulars WHERE regulator_code=? ORDER BY date DESC",
        (regulator_code,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]

def cross_regulator_impact(circular_id: int) -> dict:
    conn = get_connection()
    circ = conn.execute("SELECT * FROM circulars WHERE id=?", (circular_id,)).fetchone()
    if not circ:
        conn.close()
        return {"circular_id": circular_id, "affected_regulators": [], "primary_regulator": "Unknown"}
    title = (circ.get("title") or "").lower()
    description = (circ.get("description") or "").lower()
    body = (circ.get("body") or "").lower()
    text = f"{title} {description} {body}"
    primary = circ.get("regulator_code", "RBI")
    affected = []
    if "kyc" in text or "know your customer" in text:
        affected.append({
            "regulator": "SEBI",
            "reason": "KYC norms affect SEBI-registered intermediaries and mutual funds",
            "impact_level": "HIGH",
        })
        if primary != "RBI":
            affected.append({
                "regulator": "RBI",
                "reason": "KYC is a core RBI regulatory requirement for all regulated entities",
                "impact_level": "HIGH",
            })
    if "information technology" in text or "it" in text.split() or "cyber" in text:
        if primary != "MEITY":
            affected.append({
                "regulator": "MEITY",
                "reason": "IT and cybersecurity circulars fall under MEITY's purview",
                "impact_level": "MEDIUM",
            })
        if primary != "RBI":
            affected.append({
                "regulator": "RBI",
                "reason": "RBI mandates IT governance for banks and financial institutions",
                "impact_level": "MEDIUM",
            })
    if "insurance" in text or "irda" in text:
        if primary != "IRDAI":
            affected.append({
                "regulator": "IRDAI",
                "reason": "Insurance-related circulars require IRDAI compliance alignment",
                "impact_level": "HIGH",
            })
    if "securities" in text or "stock" in text or "market" in text:
        if primary != "SEBI":
            affected.append({
                "regulator": "SEBI",
                "reason": "Securities market circulars require SEBI compliance",
                "impact_level": "HIGH",
            })
    conn.close()
    return {
        "circular_id": circular_id,
        "circular_title": circ.get("title", ""),
        "primary_regulator": primary,
        "affected_regulators": affected,
        "total_affected": len(affected),
    }
