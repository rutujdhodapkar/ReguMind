"""
Phantom Compliance — Role-Based Access Control
5 roles with granular permissions. Read-only auditor mode.
"""

import logging
from functools import wraps
from flask import session as flask_session, jsonify

logger = logging.getLogger("phantom_compliance.rbac")

ROLES = {
    "CCO": {
        "rank": 100,
        "label": "Chief Compliance Officer",
        "permissions": [
            "view_all", "edit_all", "delete_all",
            "manage_users", "manage_roles", "view_audit",
            "generate_reports", "run_agents", "panic_button",
            "view_financial", "approve_exceptions", "sign_off",
            "view_blockchain", "corrupt_chain_test",
        ],
    },
    "COMPLIANCE_OFFICER": {
        "rank": 75,
        "label": "Compliance Officer",
        "permissions": [
            "view_all", "edit_maps", "view_audit",
            "generate_reports", "submit_evidence",
            "view_department_scores",
        ],
    },
    "ADMIN": {
        "rank": 90,
        "label": "System Administrator",
        "permissions": [
            "view_all", "manage_users", "view_audit",
            "manage_backups", "view_system_config",
            "restore_backup", "view_blockchain",
        ],
    },
    "DEPARTMENT_USER": {
        "rank": 25,
        "label": "Department User",
        "permissions": [
            "view_own_dept", "edit_own_maps", "submit_evidence",
            "view_own_scores", "acknowledge_maps",
        ],
    },
    "AUDITOR": {
        "rank": 50,
        "label": "External Auditor",
        "permissions": [
            "view_all", "view_audit", "view_blockchain",
            "view_reports", "read_only",
        ],
        "read_only": True,
    },
}

# Map old roles to new roles for migration
ROLE_MIGRATION_MAP = {
    "CCO": "CCO",
    "KYC": "DEPARTMENT_USER",
    "Payments": "DEPARTMENT_USER",
    "IT_Security": "DEPARTMENT_USER",
    "Treasury": "DEPARTMENT_USER",
    "Credit_Risk": "DEPARTMENT_USER",
    "Forex": "DEPARTMENT_USER",
}


def has_permission(permission: str, role: str = None) -> bool:
    """Check if a role has a specific permission."""
    if role is None:
        role = flask_session.get("role", "")
    role_config = ROLES.get(role, ROLES["DEPARTMENT_USER"])
    return permission in role_config.get("permissions", [])


def is_read_only(role: str = None) -> bool:
    if role is None:
        role = flask_session.get("role", "")
    role_config = ROLES.get(role, {})
    return role_config.get("read_only", False)


def get_role_label(role: str) -> str:
    return ROLES.get(role, {}).get("label", role)


def get_role_rank(role: str) -> int:
    return ROLES.get(role, {}).get("rank", 0)


def check_access(required_permission: str):
    """Decorator to check permission. Returns 403 if denied."""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            role = flask_session.get("role", "")
            if is_read_only(role) and required_permission not in ["view_all", "view_audit", "view_blockchain", "view_reports"]:
                return jsonify({"error": "Auditors are read-only. Cannot modify data."}), 403
            if not has_permission(required_permission, role):
                return jsonify({"error": f"Insufficient permissions. Required: {required_permission}"}), 403
            return f(*args, **kwargs)
        return decorated
    return decorator


def get_effective_role(role: str) -> str:
    """Migrate old role names to new system."""
    return ROLE_MIGRATION_MAP.get(role, role)


def get_allowed_departments(user_role: str, user_dept: str = "") -> list:
    """Return list of department codes a user can access."""
    if has_permission("view_all", user_role):
        return []  # empty = all
    if user_dept:
        return [user_dept]
    return []


def filter_data_by_role(data: list, user_role: str, user_dept: str = "",
                        dept_field: str = "assigned_to") -> list:
    """Filter a list of dicts by what the role can see."""
    if has_permission("view_all", user_role):
        return data
    if has_permission("view_own_dept", user_role) and user_dept:
        return [d for d in data if d.get(dept_field, "") == user_dept or d.get("department_code", "") == user_dept]
    return data


# Ensure the users_v2 table has the new role column
def ensure_new_roles():
    conn = get_connection()
    cols = [r[1] for r in conn.execute("PRAGMA table_info(users_v2)").fetchall()]
    if 'new_role' not in cols:
        conn.execute("ALTER TABLE users_v2 ADD COLUMN new_role TEXT DEFAULT ''")
    if 'read_only' not in cols:
        conn.execute("ALTER TABLE users_v2 ADD COLUMN read_only INTEGER DEFAULT 0")
    conn.commit()
    conn.close()


def migrate_old_roles():
    ensure_new_roles()
    conn = get_connection()
    users = conn.execute("SELECT id, role, new_role FROM users_v2 WHERE new_role IS NULL OR new_role = ''").fetchall()
    for u in users:
        new_role = ROLE_MIGRATION_MAP.get(u["role"], "DEPARTMENT_USER")
        conn.execute("UPDATE users_v2 SET new_role=? WHERE id=?", (new_role, u["id"]))
    conn.commit()
    conn.close()
