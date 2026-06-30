"""
Phantom Compliance — Internal AI Red Team
Identifies bypass vectors, access control weaknesses, and insider threat scenarios.
"""

import logging
import re
from utils.database import get_connection

logger = logging.getLogger("phantom_compliance.red_team")

def find_policy_bypass_vectors(policy_text: str) -> dict:
    risks = []
    text_lower = policy_text.lower()
    if "no exceptions" in text_lower or "no exemption" in text_lower:
        risks.append({
            "vector": "Absence of exception process",
            "severity": "HIGH",
            "likelihood": "MEDIUM",
            "recommendation": "Implement formal exception and waiver process with approval workflow",
        })
    if "manual review" in text_lower or "manual approval" in text_lower:
        risks.append({
            "vector": "Manual review bypass",
            "severity": "MEDIUM",
            "likelihood": "HIGH",
            "recommendation": "Automate review process where possible; implement audit trails for manual overrides",
        })
    if "self-certify" in text_lower or "self attest" in text_lower:
        risks.append({
            "vector": "Self-certification without verification",
            "severity": "HIGH",
            "likelihood": "MEDIUM",
            "recommendation": "Require independent verification of self-certified compliance claims",
        })
    if "email" in text_lower and ("approval" in text_lower or "confirm" in text_lower):
        risks.append({
            "vector": "Email-based approval forgery",
            "severity": "MEDIUM",
            "likelihood": "LOW",
            "recommendation": "Use digitally signed approvals within the compliance system instead of email",
        })
    if not any("enforce" in text_lower for _ in [1]):
        risks.append({
            "vector": "Missing enforcement mechanism",
            "severity": "HIGH",
            "likelihood": "HIGH",
            "recommendation": "Add automated enforcement with escalation for non-compliance",
        })
    if "audit" not in text_lower:
        risks.append({
            "vector": "No audit trail requirement",
            "severity": "MEDIUM",
            "likelihood": "MEDIUM",
            "recommendation": "Mandate audit logging for all compliance-related actions",
        })
    overall = 0
    for r in risks:
        severity_map = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}
        overall += severity_map.get(r["severity"], 0)
    overall_score = min(100, overall * 10)
    return {"risks": risks, "overall_risk_score": overall_score}

def audit_access_controls() -> dict:
    conn = get_connection()
    findings = []
    try:
        users = conn.execute("SELECT * FROM users").fetchall()
    except Exception:
        conn.close()
        return {"findings": [{"finding": "users table not found"}], "risk_level": "HIGH", "recommendations": ["Create users table with proper access controls"]}
    cco_count = 0
    no_dept = []
    for u in users:
        if u.get("role", "").upper() == "CCO":
            cco_count += 1
        if not u.get("department_code"):
            no_dept.append(u.get("username", u.get("id", "unknown")))
    if cco_count > 2:
        findings.append({
            "finding": f"Multiple CCO accounts detected ({cco_count})",
            "severity": "MEDIUM",
            "detail": "Multiple Chief Compliance Officers may lead to confusion in accountability",
        })
    if no_dept:
        findings.append({
            "finding": f"Users without department assignment: {len(no_dept)}",
            "severity": "LOW",
            "detail": f"Users: {', '.join(str(x) for x in no_dept[:5])}",
        })
    try:
        inactive = conn.execute("SELECT count(*) as c FROM users WHERE is_active=0 OR is_active IS NULL").fetchone()
        if inactive and inactive["c"] > 0:
            findings.append({
                "finding": f"{inactive['c']} inactive user accounts exist",
                "severity": "LOW",
                "detail": "Inactive accounts should be disabled or removed",
            })
    except Exception:
        pass
    conn.close()
    risk_level = "LOW"
    severity_scores = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}
    max_sev = max((severity_scores.get(f.get("severity", "LOW"), 0) for f in findings), default=0)
    if max_sev >= 3:
        risk_level = "HIGH"
    elif max_sev >= 2:
        risk_level = "MEDIUM"
    recommendations = [
        "Limit CCO accounts to maximum of 2",
        "Assign department codes to all users",
        "Review and disable inactive accounts quarterly",
        "Implement role-based access control with least privilege",
    ]
    return {"findings": findings, "risk_level": risk_level, "recommendations": recommendations}

def simulate_insider_threat(scenario: str) -> dict:
    s = scenario.lower()
    if "bypass" in s and "evidence" in s:
        return {
            "scenario": scenario,
            "detection": "Evidence validation is mandatory and logged. Any attempt to mark evidence as validated without proper checks triggers an alert to the compliance officer.",
            "prevention": "Multiple approval workflow required for evidence validation. System logs all validation actions with user identity and timestamp.",
            "severity": "HIGH",
            "mitigation": "Implement quarterly review of all validated evidence packages.",
        }
    elif "delet" in s and "audit" in s:
        return {
            "scenario": scenario,
            "detection": "Audit logs are append-only and cannot be deleted. Any DELETE operation triggers immediate alert to system administrators.",
            "prevention": "Database triggers prevent deletion of audit records. Access to audit logs is restricted to read-only for all users except designated auditors.",
            "severity": "CRITICAL",
            "mitigation": "Implement immutable audit log storage with cryptographic chain of custody.",
        }
    elif "access" in s and ("other" in s or "unauthor" in s):
        return {
            "scenario": scenario,
            "detection": "Row-level security restricts users to their department data. Cross-department access attempts are logged and flagged.",
            "prevention": "Department-based data isolation enforced at database level. All queries filtered by user's department_code.",
            "severity": "MEDIUM",
            "mitigation": "Regular access reviews and periodic penetration testing of data isolation controls.",
        }
    else:
        return {
            "scenario": scenario,
            "detection": "General anomaly detection monitors unusual patterns in system access and data modification.",
            "prevention": "Standard access controls and audit logging apply.",
            "severity": "MEDIUM",
            "mitigation": "Enhance monitoring rules based on specific threat patterns.",
        }
