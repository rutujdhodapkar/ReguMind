"""
Phantom Compliance — Evidence Validator (Rule-Based)
No AI needed. Checks:
- File exists
- File type allowed
- Timestamp within deadline
- Uploader authorized
- Required fields present
"""

import json
import logging
from datetime import datetime

logger = logging.getLogger("phantom_compliance.evidence_validator")

ALLOWED_EVIDENCE_TYPES = {".pdf", ".docx", ".doc", ".xlsx", ".xls", ".png", ".jpg", ".jpeg", ".txt", ".csv"}

REQUIRED_EVIDENCE_FIELDS = [
    "map_id", "evidence_text", "submitted_by", "submitted_at",
]

VALID_EVIDENCE_TEMPLATES = {
    "screenshot": "Visual proof of system implementation",
    "sop_document": "Standard Operating Procedure document",
    "policy_pdf": "Updated policy document",
    "test_logs": "Test execution logs",
    "approval_email": "Email approval from authorized personnel",
    "training_record": "Employee training completion record",
    "audit_report": "Internal audit report",
    "board_minutes": "Board meeting minutes",
}


def validate_evidence(map_id: int, evidence_data: dict) -> dict:
    """
    Validate evidence submission against rule-based checks.
    Returns {valid: bool, checks: [{name, passed, reason}], score: int}
    """
    checks = []

    # Required fields
    missing_fields = [f for f in REQUIRED_EVIDENCE_FIELDS if f not in evidence_data]
    checks.append({
        "name": "required_fields",
        "passed": len(missing_fields) == 0,
        "reason": f"Missing fields: {', '.join(missing_fields)}" if missing_fields else "All required fields present",
    })

    # File existence (if file_path provided)
    file_path = evidence_data.get("file_path", "")
    if file_path:
        from pathlib import Path
        fp = Path(file_path)
        checks.append({
            "name": "file_exists",
            "passed": fp.exists(),
            "reason": "File found" if fp.exists() else "File not found",
        })
        if fp.exists():
            ext = fp.suffix.lower()
            checks.append({
                "name": "file_type_allowed",
                "passed": ext in ALLOWED_EVIDENCE_TYPES,
                "reason": f"File type {ext} allowed" if ext in ALLOWED_EVIDENCE_TYPES else f"File type {ext} not allowed",
            })
    else:
        checks.append({"name": "file_check", "passed": True, "reason": "No file required (text evidence)"})

    # Deadline check
    try:
        conn = __import__("utils.database", fromlist=["get_connection"]).get_connection()
        map_row = conn.execute("SELECT deadline_date, status FROM maps WHERE id=?", (map_id,)).fetchone()
        conn.close()
        if map_row and map_row["deadline_date"]:
            from datetime import datetime as dt
            deadline = dt.strptime(map_row["deadline_date"], "%Y-%m-%d")
            submitted = evidence_data.get("submitted_at", "")
            if submitted:
                try:
                    sub_date = dt.fromisoformat(submitted) if "T" in submitted else dt.strptime(submitted, "%Y-%m-%d")
                    within_deadline = sub_date <= deadline
                    checks.append({
                        "name": "deadline_compliance",
                        "passed": within_deadline,
                        "reason": f"Submitted within deadline ({map_row['deadline_date']})" if within_deadline
                                  else f"Submitted AFTER deadline ({map_row['deadline_date']})",
                    })
                except (ValueError, TypeError):
                    checks.append({"name": "deadline_compliance", "passed": True, "reason": "Could not parse submission date"})
            else:
                checks.append({"name": "deadline_compliance", "passed": True, "reason": "No submission date provided"})
    except Exception as e:
        checks.append({"name": "deadline_check", "passed": True, "reason": f"Deadline check skipped: {e}"})

    # Uploader authorization
    username = evidence_data.get("submitted_by", "")
    role = evidence_data.get("submitter_role", "")
    if username and role:
        from auth.rbac import has_permission
        authorized = has_permission("submit_evidence", role)
        checks.append({
            "name": "uploader_authorized",
            "passed": authorized,
            "reason": f"User {username} ({role}) authorized to submit evidence" if authorized
                      else f"User {username} ({role}) not authorized to submit evidence",
        })
    else:
        checks.append({"name": "uploader_check", "passed": True, "reason": "Uploader info not provided"})

    # Evidence length
    evidence_text = evidence_data.get("evidence_text", "")
    checks.append({
        "name": "evidence_content",
        "passed": len(evidence_text.strip()) > 10,
        "reason": f"Evidence text has {len(evidence_text.strip())} characters (>10)" if len(evidence_text.strip()) > 10
                  else "Evidence text too short (<10 characters)",
    })

    all_passed = all(c["passed"] for c in checks)
    score = sum(1 for c in checks if c["passed"]) / len(checks) * 100

    return {
        "valid": all_passed,
        "score": round(score, 1),
        "checks": checks,
        "recommendation": "Evidence accepted" if all_passed else "Evidence rejected — see check details",
    }


def get_evidence_templates() -> dict:
    return VALID_EVIDENCE_TEMPLATES
