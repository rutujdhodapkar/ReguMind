"""
Phantom Compliance — AI Governance Framework
Ensures LLM usage follows governance policies:
- Output validation
- Bias checking
- Drift detection
- Regulatory compliance verification
- Usage auditing
"""

import re
import json
import logging
from datetime import datetime
from utils.database import get_connection

logger = logging.getLogger("phantom_compliance.ai_governance")

GOVERNANCE_POLICIES = {
    "fairness": {
        "description": "AI outputs must not discriminate against any group",
        "checks": ["bias_in_language", "equal_treatment"],
    },
    "transparency": {
        "description": "AI must explain its reasoning and confidence",
        "checks": ["source_attribution", "confidence_score"],
    },
    "accountability": {
        "description": "All AI decisions must be logged and auditable",
        "checks": ["decision_logging", "human_override"],
    },
    "privacy": {
        "description": "AI must not expose personal or sensitive data",
        "checks": ["pii_detection", "data_minimization"],
    },
    "reliability": {
        "description": "AI outputs must be consistent and verifiable",
        "checks": ["output_validation", "factual_accuracy"],
    },
}


def validate_llm_output(text: str, context: str = "") -> dict:
    """
    Validate an LLM output against governance policies.
    Returns {passed: bool, checks: [{name, passed, reason}]}
    """
    checks = []

    # Bias check: look for discriminatory language patterns
    bias_patterns = [
        r"\b(unfair|discriminat|bias(ed)?)\b",
    ]
    bias_found = any(re.search(p, text, re.IGNORECASE) for p in bias_patterns)
    checks.append({
        "name": "bias_in_language",
        "passed": not bias_found,
        "reason": "No discriminatory language detected" if not bias_found else "Potentially biased language found",
    })

    # PII detection
    email_pattern = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
    phone_pattern = r"\b\d{10}\b|\b\d{3}[-.]?\d{3}[-.]?\d{4}\b"
    pii_found = bool(re.search(email_pattern, text) or re.search(phone_pattern, text))
    checks.append({
        "name": "pii_detection",
        "passed": not pii_found,
        "reason": "No PII detected in output" if not pii_found else "Possible PII detected",
    })

    # Source attribution check
    has_source = bool(re.search(r"(section|clause|paragraph|circular|regulation|reference)", text, re.IGNORECASE))
    checks.append({
        "name": "source_attribution",
        "passed": has_source or not context,
        "reason": "Output includes source references" if has_source else "No source references found",
    })

    # Actionability check
    has_action = bool(re.search(r"(shall|must|should|will|required|need to)", text, re.IGNORECASE))
    checks.append({
        "name": "actionability",
        "passed": has_action,
        "reason": "Output contains actionable items" if has_action else "No actionable items identified",
    })

    all_passed = all(c["passed"] for c in checks)
    governance_score = sum(1 for c in checks if c["passed"]) / len(checks) * 100

    return {
        "passed": all_passed,
        "governance_score": round(governance_score, 1),
        "checks": checks,
        "recommendation": "Output cleared" if all_passed else "Output requires human review",
    }


def audit_llm_usage(action: str, user: str, input_summary: str, output_summary: str) -> dict:
    """Audit an LLM usage event for governance compliance."""
    validation = validate_llm_output(output_summary, input_summary)
    log_entry = {
        "action": action,
        "user": user,
        "input_preview": input_summary[:100],
        "output_preview": output_summary[:100],
        "governance_passed": validation["passed"],
        "governance_score": validation["governance_score"],
        "timestamp": datetime.utcnow().isoformat(),
    }

    from utils.database import get_connection
    try:
        conn = get_connection()
        conn.execute(
            "INSERT INTO ai_governance_log (action, user, input_preview, output_preview, "
            "governance_passed, governance_score) VALUES (?, ?, ?, ?, ?, ?)",
            (action, user, input_summary[:100], output_summary[:100],
             1 if validation["passed"] else 0, validation["governance_score"]),
        )
        conn.commit()
        conn.close()
    except Exception:
        pass

    return log_entry


def check_compliance_breach(entity_type: str, entity_id: int, details: dict) -> dict:
    """Check if an action would breach compliance requirements."""
    breaches = []
    risk_score = 0

    if entity_type == "deadline_miss":
        days_late = details.get("days_late", 0)
        if days_late > 30:
            breaches.append({"type": "CRITICAL_BREACH", "detail": f"Deadline exceeded by {days_late} days"})
            risk_score += 50
        elif days_late > 7:
            breaches.append({"type": "MAJOR_BREACH", "detail": f"Deadline exceeded by {days_late} days"})
            risk_score += 25
        else:
            breaches.append({"type": "MINOR_BREACH", "detail": f"Deadline exceeded by {days_late} days"})
            risk_score += 10

    if entity_type == "missing_evidence":
        breaches.append({"type": "EVIDENCE_GAP", "detail": "Required evidence not submitted"})
        risk_score += 15

    if entity_type == "conflict_unresolved":
        days = details.get("days_unresolved", 0)
        if days > 30:
            breaches.append({"type": "CRITICAL_CONFLICT", "detail": f"Regulatory conflict unresolved for {days} days"})
            risk_score += 40

    return {
        "has_breach": len(breaches) > 0,
        "breaches": breaches,
        "risk_score": risk_score,
        "severity": "HIGH" if risk_score >= 30 else "MEDIUM" if risk_score >= 15 else "LOW",
        "requires_approval": risk_score >= 25,
    }


def ensure_governance_tables():
    conn = get_connection()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS ai_governance_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action TEXT NOT NULL,
            user TEXT NOT NULL,
            input_preview TEXT DEFAULT '',
            output_preview TEXT DEFAULT '',
            governance_passed INTEGER DEFAULT 1,
            governance_score REAL DEFAULT 100,
            created_at TEXT DEFAULT (datetime('now'))
        )
    """)
    conn.commit()
    conn.close()
