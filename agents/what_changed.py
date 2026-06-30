import difflib
import json
import logging
import re
from datetime import datetime, timezone

from utils.database import get_connection, get_circular_body

logger = logging.getLogger("phantom_compliance.what_changed")


def ensure_changes_table():
    conn = get_connection()
    try:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS circular_changes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                old_circular_id INTEGER NOT NULL,
                new_circular_id INTEGER NOT NULL,
                summary TEXT,
                changes_json TEXT,
                severity TEXT,
                created_at TEXT
            )
        """)
        conn.commit()
    except Exception:
        logger.exception("Failed to create circular_changes table")
        raise
    finally:
        conn.close()


def _fetch_circular(circular_id: int) -> dict | None:
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT id, circular_number, subject_line, department_code, issue_date "
            "FROM circulars WHERE id = ?",
            (circular_id,),
        )
        row = cur.fetchone()
        if row:
            body = get_circular_body(circular_id) or ""
            return {
                "id": row[0],
                "circular_number": row[1],
                "subject_line": row[2],
                "department_code": row[3],
                "issue_date": row[4],
                "body_text": body,
            }
        return None
    except Exception:
        logger.exception("Failed to fetch circular %s", circular_id)
        raise
    finally:
        conn.close()


def _extract_policy_points(text: str) -> dict:
    points = {
        "deadlines": [],
        "numerics": [],
        "action_phrases": [],
    }

    deadline_patterns = [
        r"within\s+\d+\s+(day|month|week|year)s?",
        r"(?:by|before|until)\s+\d{1,2}[/-]\d{1,2}[/-]\d{2,4}",
        r"(?:by|before|until)\s+\d{1,2}(?:st|nd|rd|th)?\s+(?:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*\s+\d{4}",
        r"effective\s+(?:from|date)\s+\d{1,2}[/-]\d{1,2}[/-]\d{2,4}",
        r"not\s+later\s+than\s+\d+\s+(day|month|week)s?",
        r"immediately",
        r"with\s+immediate\s+effect",
        r"w\.e\.f\.?\s+\d{1,2}[/-]\d{1,2}[/-]\d{2,4}",
    ]
    for pattern in deadline_patterns:
        matches = re.finditer(pattern, text, re.IGNORECASE)
        for m in matches:
            points["deadlines"].append(m.group(0).strip())

    number_patterns = [
        r"\b\d+%\s*(?:per\s*centum)?\b",
        r"(?:rs\.?\s*|inr\s*)\d[\d,]*",
        r"penalty\s+of\s+\d[\d,]*",
        r"minimum\s+(?:amount\s+)?(?:of\s+)?\d[\d,]*",
        r"maximum\s+(?:amount\s+)?(?:of\s+)?\d[\d,]*",
        r"(?:increased|decreased|reduced|raised|lowered)\s+(?:from\s+\d[\d,.]*\s+)?(?:to\s+\d[\d,.]*)?",
        r"\b\d+\s*(?:days?|months?|years?)\b",
        r"\b(?:ratio|rate|limit|threshold|ceiling|floor)\s+(?:of\s+)?\d[\d,.]*",
    ]
    for pattern in number_patterns:
        matches = re.finditer(pattern, text, re.IGNORECASE)
        for m in matches:
            points["numerics"].append(m.group(0).strip())

    action_verbs = [
        r"(?:shall|must|will|should|may|required|mandatory|obligatory)\s+\w+",
        r"every\s+\w+\s+(?:shall|must|will|should)",
        r"(?:directed|instructed|ordered|advised)\s+(?:that\s+)?",
        r"no\s+\w+\s+(?:shall|may|should|must)",
        r"(?:to\s+)?ensure\s+(?:that\s+)?",
        r"(?:comply|compliance|adhere)\s+(?:with\s+)?(?:to\s+)?",
        r"report(?:ing)?\s+(?:shall|must|will|should)",
    ]
    for pattern in action_verbs:
        matches = re.finditer(pattern, text, re.IGNORECASE)
        for m in matches:
            points["action_phrases"].append(m.group(0).strip())

    points["deadlines"] = list(set(points["deadlines"]))
    points["numerics"] = list(set(points["numerics"]))
    points["action_phrases"] = list(set(points["action_phrases"]))

    return points


def _compute_severity(
    deadline_changes: list, numeric_changes: list, additions: list, removals: list
) -> str:
    severity_score = 0

    if deadline_changes:
        severity_score += 2

    if numeric_changes:
        severity_score += 2

    if additions:
        severity_score += 1

    if removals:
        severity_score += 1

    combined_text = " ".join(
        str(x) for x in deadline_changes + numeric_changes + additions + removals
    ).lower()
    critical_keywords = [
        "penalty",
        "fine",
        "imprisonment",
        "criminal",
        "immediate",
        "cease",
        "revoke",
        "cancel",
    ]
    for kw in critical_keywords:
        if kw in combined_text:
            severity_score += 3
            break

    high_keywords = [
        "mandatory",
        "required",
        "must",
        "shall",
        "deadline",
        "threshold",
        "limit",
    ]
    for kw in high_keywords:
        if kw in combined_text:
            severity_score += 1
            break

    if severity_score >= 5:
        return "CRITICAL"
    elif severity_score >= 3:
        return "HIGH"
    elif severity_score >= 2:
        return "MEDIUM"
    else:
        return "LOW"


def detect_changes(old_circular_id: int, new_circular_id: int, blockchain=None) -> dict:
    old = _fetch_circular(old_circular_id)
    new = _fetch_circular(new_circular_id)

    if not old:
        raise ValueError(f"Circular with id={old_circular_id} not found")
    if not new:
        raise ValueError(f"Circular with id={new_circular_id} not found")

    old_points = _extract_policy_points(old["body_text"])
    new_points = _extract_policy_points(new["body_text"])

    old_deadlines_set = set(d.lower() for d in old_points["deadlines"])
    new_deadlines_set = set(d.lower() for d in new_points["deadlines"])

    deadline_removed = sorted(old_deadlines_set - new_deadlines_set)
    deadline_added = sorted(new_deadlines_set - old_deadlines_set)
    deadline_changes = list(deadline_removed) + list(deadline_added)

    old_numerics_set = set(n.lower() for n in old_points["numerics"])
    new_numerics_set = set(n.lower() for n in new_points["numerics"])
    numeric_changes = []

    common_nums = old_numerics_set & new_numerics_set
    old_filtered = {
        re.sub(r"\s+", " ", n.replace("\n", " ")).strip()
        for n in (old_numerics_set - common_nums)
    }
    new_filtered = {
        re.sub(r"\s+", " ", n.replace("\n", " ")).strip()
        for n in (new_numerics_set - common_nums)
    }

    for old_val in sorted(old_filtered):
        numeric_changes.append(f"Removed: {old_val}")
    for new_val in sorted(new_filtered):
        numeric_changes.append(f"Added: {new_val}")

    old_action_set = set(a.lower() for a in old_points["action_phrases"])
    new_action_set = set(a.lower() for a in new_points["action_phrases"])
    policy_removals = sorted(old_action_set - new_action_set)
    policy_additions = sorted(new_action_set - old_action_set)

    severity = _compute_severity(
        deadline_changes, numeric_changes, policy_additions, policy_removals
    )

    diff_summary_parts = []
    if deadline_changes:
        diff_summary_parts.append(f"{len(deadline_changes)} deadline change(s)")
    if numeric_changes:
        diff_summary_parts.append(f"{len(numeric_changes)} numeric change(s)")
    if policy_additions:
        diff_summary_parts.append(f"{len(policy_additions)} policy addition(s)")
    if policy_removals:
        diff_summary_parts.append(f"{len(policy_removals)} policy removal(s)")

    if diff_summary_parts:
        summary = (
            f"Circular {new['circular_number']} vs {old['circular_number']}: "
            + "; ".join(diff_summary_parts)
        )
    else:
        summary = (
            f"No significant changes detected between "
            f"{old['circular_number']} and {new['circular_number']}"
        )

    impact_on_existing_maps = []
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT id, map_name FROM maps WHERE circular_id = ?",
            (old_circular_id,),
        )
        maps = cur.fetchall()
        for row in maps:
            impact_on_existing_maps.append(
                {
                    "map_id": row[0],
                    "map_name": row[1],
                    "needs_update": True,
                    "reason": (
                        f"Circular {old['circular_number']} has been superseded "
                        f"by {new['circular_number']}"
                    ),
                }
            )
    except Exception:
        logger.exception("Failed to query maps for circular %s", old_circular_id)
    finally:
        conn.close()

    result = {
        "old_circular_id": old_circular_id,
        "new_circular_id": new_circular_id,
        "summary": summary,
        "severity": severity,
        "deadline_changes": deadline_changes,
        "numeric_changes": numeric_changes,
        "policy_additions": policy_additions,
        "policy_removals": policy_removals,
        "impact_on_existing_maps": impact_on_existing_maps,
    }

    if blockchain is not None:
        try:
            blockchain.add_entry(
                "WHAT_CHANGED_DETECTED",
                {
                    "old_circular_id": old_circular_id,
                    "new_circular_id": new_circular_id,
                    "summary": summary,
                    "severity": severity,
                },
            )
        except Exception:
            logger.exception("Failed to add blockchain entry")

    ensure_changes_table()
    conn2 = get_connection()
    try:
        cur = conn2.cursor()
        cur.execute(
            "INSERT INTO circular_changes "
            "(old_circular_id, new_circular_id, summary, changes_json, severity, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                old_circular_id,
                new_circular_id,
                summary,
                json.dumps(result, default=str),
                severity,
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        conn2.commit()
    except Exception:
        logger.exception("Failed to store change record")
        raise
    finally:
        conn2.close()

    return result


def get_changes_for_circular(circular_id: int) -> list[dict]:
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT id, old_circular_id, new_circular_id, summary, changes_json, "
            "severity, created_at "
            "FROM circular_changes "
            "WHERE old_circular_id = ? OR new_circular_id = ? "
            "ORDER BY created_at DESC",
            (circular_id, circular_id),
        )
        rows = cur.fetchall()
        results = []
        for row in rows:
            changes_data = json.loads(row[4]) if row[4] else {}
            results.append(
                {
                    "id": row[0],
                    "old_circular_id": row[1],
                    "new_circular_id": row[2],
                    "summary": row[3],
                    "changes": changes_data,
                    "severity": row[5],
                    "created_at": row[6],
                }
            )
        return results
    except Exception:
        logger.exception(
            "Failed to get changes for circular %s", circular_id
        )
        raise
    finally:
        conn.close()


def _make_html_diff(old_text: str, new_text: str) -> str:
    old_lines = old_text.splitlines(keepends=True)
    new_lines = new_text.splitlines(keepends=True)
    matcher = difflib.SequenceMatcher(None, old_lines, new_lines)
    output_parts = []
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            output_parts.extend(old_lines[i1:i2])
        elif tag == "delete":
            for line in old_lines[i1:i2]:
                stripped = line.rstrip("\n\r")
                output_parts.append(f"<del>{stripped}</del>\n")
        elif tag == "insert":
            for line in new_lines[j1:j2]:
                stripped = line.rstrip("\n\r")
                output_parts.append(f"<ins>{stripped}</ins>\n")
        elif tag == "replace":
            for line in old_lines[i1:i2]:
                stripped = line.rstrip("\n\r")
                output_parts.append(f"<del>{stripped}</del>\n")
            for line in new_lines[j1:j2]:
                stripped = line.rstrip("\n\r")
                output_parts.append(f"<ins>{stripped}</ins>\n")
    return "".join(output_parts)


def generate_diff_html(old_id: int, new_id: int) -> str:
    old = _fetch_circular(old_id)
    new = _fetch_circular(new_id)

    if not old:
        raise ValueError(f"Circular with id={old_id} not found")
    if not new:
        raise ValueError(f"Circular with id={new_id} not found")

    subject_diff = _make_html_diff(
        old.get("subject_line", ""), new.get("subject_line", "")
    )
    body_diff = _make_html_diff(
        old.get("body_text", ""), new.get("body_text", "")
    )

    html_parts = [
        "<html><head><style>",
        "body { font-family: Arial, sans-serif; margin: 20px; }",
        "del { background-color: #fdd; color: #a00; text-decoration: line-through; }",
        "ins { background-color: #dfd; color: #0a0; text-decoration: none; }",
        "h2 { color: #333; }",
        ".diff-section { margin-bottom: 20px; }",
        "</style></head><body>",
        "<h1>Diff: ",
        f"{old.get('circular_number', old_id)} vs {new.get('circular_number', new_id)}",
        "</h1>",
        "<div class='diff-section'>",
        "<h2>Subject Line</h2>",
        "<pre>",
        subject_diff,
        "</pre></div>",
        "<div class='diff-section'>",
        "<h2>Body Text</h2>",
        "<pre>",
        body_diff,
        "</pre></div>",
        "</body></html>",
    ]

    return "".join(html_parts)
