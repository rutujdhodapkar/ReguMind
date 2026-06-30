"""
PHANTOM COMPLIANCE — Circular Conflict Detector
Compares new circulars against existing ones to detect overrides,
contradictions, and complementary relationships using the LLM.
Marks affected MAPs as SUPERSEDED when an override is detected.
"""

import json
import logging
import re
from collections import Counter
from typing import Optional

from utils.database import get_connection
from utils.db_extensions import create_notification, audit_log
from p_crypto.blockchain import Blockchain

logger = logging.getLogger("phantom_compliance.conflict_detector")

SIMILARITY_THRESHOLD = 0.6
KEYWORD_COUNT = 10


def _extract_keywords(text: str, top_n: int = KEYWORD_COUNT) -> set[str]:
    stopwords = {
        "the", "a", "an", "is", "are", "was", "were", "be", "been", "being",
        "have", "has", "had", "do", "does", "did", "will", "would", "shall",
        "should", "may", "might", "must", "can", "could", "to", "of", "in",
        "for", "on", "by", "with", "at", "from", "as", "into", "through",
        "during", "before", "after", "above", "below", "between", "under",
        "this", "that", "these", "those", "it", "its", "or", "and", "but",
        "not", "no", "nor", "so", "if", "then", "than", "too", "very",
        "just", "about", "also", "per", "each", "all", "any", "both",
        "every", "few", "more", "most", "other", "some", "such",
    }
    words = re.findall(r"[a-zA-Z_]+", text.lower())
    filtered = [w for w in words if w not in stopwords and len(w) > 3]
    return set(Counter(filtered).most_common(top_n))


def _jaccard_similarity(a: set, b: set) -> float:
    intersection = a & b
    union = a | b
    if not union:
        return 0.0
    return len(intersection) / len(union)


def _call_llm_for_conflict(summary_a: str, summary_b: str) -> dict:
    from agents.llm_agent import _call_llm
    prompt = f"""[INST] You are a banking compliance expert.
Compare these two RBI circulars and identify:
1. Does Circular B override or supersede Circular A?
2. Do they contradict each other on any specific instruction?
3. Do they complement each other?

Circular A (older): {summary_a[:800]}
Circular B (newer): {summary_b[:800]}

Return JSON only:
{{"relationship": "override|conflict|complement|unrelated", "affected_maps": ["MAP description"], "recommendation": "one sentence action for CCO", "confidence": 0.0-1.0}}
[/INST]"""
    raw = _call_llm(prompt)
    if raw:
        try:
            cleaned = raw.strip().removeprefix("```json").removesuffix("```").strip()
            result = json.loads(cleaned)
            if isinstance(result, dict) and "relationship" in result:
                return result
        except (json.JSONDecodeError, AttributeError):
            pass
    return {"relationship": "unrelated", "affected_maps": [], "recommendation": "", "confidence": 0.0}


def _get_maps_for_circular(circular_id: int) -> list[dict]:
    conn = get_connection()
    rows = conn.execute(
        "SELECT id, map_text, status FROM maps WHERE circular_id=?",
        (circular_id,),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def _get_circular_summary(circular_id: int) -> str:
    conn = get_connection()
    row = conn.execute(
        "SELECT circular_number, subject_line, department_code, issue_date FROM circulars WHERE id=?",
        (circular_id,),
    ).fetchone()
    conn.close()
    if row:
        return f"[{row['circular_number']}] {row['subject_line']} — Dept: {row['department_code']}, Date: {row['issue_date']}"
    return ""


def detect_conflicts(new_circular_id: int, blockchain: Blockchain) -> dict:
    conn = get_connection()
    new_row = conn.execute(
        "SELECT * FROM circulars WHERE id=?", (new_circular_id,)
    ).fetchone()
    if not new_row:
        conn.close()
        return {"conflicts": [], "error": "Circular not found"}
    new_row = dict(new_row)
    conn.close()

    new_text = (new_row.get("subject_line", "") or "") + " " + (new_row.get("department_code", "") or "")
    new_keywords = _extract_keywords(new_text)
    new_dept = new_row.get("department_code", "")

    conn = get_connection()
    existing = conn.execute(
        """SELECT id, circular_number, subject_line, department_code, issue_date
           FROM circulars WHERE id != ? AND department_code = ?
           ORDER BY issue_date DESC LIMIT 20""",
        (new_circular_id, new_dept),
    ).fetchall()
    conn.close()

    conflicts = []
    for old_row in existing:
        old_row = dict(old_row)
        old_text = (old_row.get("subject_line", "") or "") + " " + (old_row.get("department_code", "") or "")
        old_keywords = _extract_keywords(old_text)
        similarity = _jaccard_similarity(new_keywords, old_keywords)

        if similarity >= SIMILARITY_THRESHOLD:
            summary_a = _get_circular_summary(old_row["id"])
            summary_b = _get_circular_summary(new_circular_id)
            result = _call_llm_for_conflict(summary_a, summary_b)

            if result["relationship"] in ("override", "conflict"):
                affected = _get_maps_for_circular(old_row["id"])

                if result["relationship"] == "override":
                    for m in affected:
                        if m["status"] not in ("VALIDATED", "SUPERSEDED"):
                            conn = get_connection()
                            conn.execute("UPDATE maps SET status='SUPERSEDED' WHERE id=?", (m["id"],))
                            conn.commit()
                            conn.close()
                            audit_log(0, "SYSTEM", "MAP_SUPERSEDED", "map", m["id"],
                                      f"Superseded by new circular #{new_circular_id}")

                conflict_record = {
                    "circular_a_id": old_row["id"],
                    "circular_a": old_row["circular_number"],
                    "circular_b_id": new_circular_id,
                    "circular_b": new_row.get("circular_number", ""),
                    "relationship": result["relationship"],
                    "recommendation": result.get("recommendation", ""),
                    "confidence": result.get("confidence", 0.0),
                    "similarity": round(similarity, 2),
                    "affected_maps": [m["id"] for m in affected],
                    "resolved": False,
                }

                conn = get_connection()
                conn.execute(
                    """INSERT INTO conflicts (circular_a_id, circular_b_id, relationship, recommendation,
                       confidence, similarity, affected_map_ids)
                       VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (old_row["id"], new_circular_id, result["relationship"],
                     result.get("recommendation", ""), result.get("confidence", 0.0),
                     round(similarity, 2), json.dumps([m["id"] for m in affected])),
                )
                conn.commit()
                conflict_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
                conn.close()

                block = blockchain.add_entry("CONFLICT_DETECTED", {
                    "conflict_id": conflict_id,
                    "type": result["relationship"],
                    "circular_a": old_row["circular_number"],
                    "circular_b": new_row.get("circular_number", ""),
                    "confidence": result.get("confidence", 0.0),
                })
                audit_log(0, "SYSTEM", "CONFLICT_DETECTED", "conflict", conflict_id,
                          f"{result['relationship']}: {old_row['circular_number']} vs {new_row.get('circular_number', '')}")
                create_notification(
                    f"Circular Conflict Detected — {result['relationship'].upper()}",
                    f"Circular {new_row.get('circular_number', '')} {result['relationship']}s "
                    f"{old_row['circular_number']}. {result.get('recommendation', '')}",
                    "WARNING", role="CCO",
                )
                conflict_record["id"] = conflict_id
                conflicts.append(conflict_record)

    return {"conflicts": conflicts, "count": len(conflicts)}


def get_all_conflicts(resolved: Optional[bool] = None) -> list[dict]:
    conn = get_connection()
    if resolved is not None:
        rows = conn.execute(
            "SELECT * FROM conflicts WHERE resolved=? ORDER BY created_at DESC",
            (1 if resolved else 0,),
        ).fetchall()
    else:
        rows = conn.execute("SELECT * FROM conflicts ORDER BY created_at DESC").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def resolve_conflict(conflict_id: int, resolution: str, user_id: int,
                    username: str, blockchain: Blockchain) -> dict:
    conn = get_connection()
    conn.execute(
        "UPDATE conflicts SET resolved=1, resolution=?, resolved_by=?, "
        "resolved_at=datetime('now') WHERE id=?",
        (resolution, username, conflict_id),
    )
    conn.commit()
    conn.close()

    block = blockchain.add_entry("CONFLICT_RESOLVED", {
        "conflict_id": conflict_id,
        "resolution": resolution,
        "resolved_by": username,
    })
    audit_log(user_id, username, "CONFLICT_RESOLVED", "conflict", conflict_id, resolution)
    return {"ok": True, "block_index": block["index"]}


def ensure_conflicts_table():
    conn = get_connection()
    conn.execute("""CREATE TABLE IF NOT EXISTS conflicts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        circular_a_id INTEGER NOT NULL,
        circular_b_id INTEGER NOT NULL,
        relationship TEXT NOT NULL CHECK(relationship IN ('override','conflict','complement','unrelated')),
        recommendation TEXT DEFAULT '',
        confidence REAL DEFAULT 0.0,
        similarity REAL DEFAULT 0.0,
        affected_map_ids TEXT DEFAULT '[]',
        resolved INTEGER DEFAULT 0,
        resolution TEXT DEFAULT '',
        resolved_by TEXT DEFAULT '',
        resolved_at TEXT,
        created_at TEXT DEFAULT (datetime('now')),
        FOREIGN KEY(circular_a_id) REFERENCES circulars(id),
        FOREIGN KEY(circular_b_id) REFERENCES circulars(id)
    )""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_conflicts_circular ON conflicts(circular_a_id, circular_b_id)")
    conn.commit()
    conn.close()
