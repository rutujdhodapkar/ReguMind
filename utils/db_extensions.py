"""
Extended database operations for V2 production features.
User management, notifications, LLM queue, audit logging, config, backup.
"""

import json
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

from utils.database import get_connection
from auth.password import hash_password, verify_password


# ═══════════════════════════════════════════════════════════════
# SCHEMA MIGRATION
# ═══════════════════════════════════════════════════════════════

def apply_v2_schema():
    conn = get_connection()
    schema_path = Path(__file__).parent.parent / "config" / "schema_v2.sql"
    if schema_path.exists():
        conn.executescript(schema_path.read_text(encoding="utf-8"))
        conn.execute("INSERT OR IGNORE INTO schema_version (version) VALUES (2)")
    conn.commit()
    conn.close()
    apply_security_columns()
    _apply_feature_tables()
    _add_maps_status_v3()


def migrate_users_to_v2():
    """Copy existing users to users_v2 if needed."""
    conn = get_connection()
    existing = conn.execute("SELECT count(*) FROM users_v2").fetchone()[0]
    if existing == 0:
        cols = {r[1] for r in conn.execute("PRAGMA table_info(users)").fetchall()}
        dept_expr = "department_code" if "department_code" in cols else "'ALL'"
        conn.execute(f"""
            INSERT OR IGNORE INTO users_v2 (id, username, password_hash, role, department_code, is_active)
            SELECT id, username, password_hash, role, {dept_expr}, 1 FROM users
        """)
        conn.commit()
    conn.close()


# ═══════════════════════════════════════════════════════════════
# USER MANAGEMENT (V2)
# ═══════════════════════════════════════════════════════════════

ROLES = ['CCO', 'KYC', 'Payments', 'IT_Security', 'Treasury', 'Credit_Risk', 'Forex']


def get_all_users_v2():
    conn = get_connection()
    rows = conn.execute(
        "SELECT id, username, display_name, role, department_code, email, is_active, last_login, created_at "
        "FROM users_v2 ORDER BY id"
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_user_v2(user_id: int) -> Optional[dict]:
    conn = get_connection()
    row = conn.execute("SELECT * FROM users_v2 WHERE id = ?", (user_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def create_user(username: str, password: str, role: str, display_name: str = "",
                department_code: str = "", email: str = "", created_by: int = 0,
                security_question: str = "", security_answer: str = "") -> int:
    pwd_hash = hash_password(password).decode("utf-8")
    sec_hash = hash_password(security_answer).decode("utf-8") if security_answer else ""
    conn = get_connection()
    conn.execute(
        """INSERT INTO users_v2 (username, display_name, password_hash, role, department_code, email,
                                 created_by, security_question, security_answer_hash)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (username, display_name or username, pwd_hash, role, department_code, email,
         created_by, security_question, sec_hash),
    )
    conn.commit()
    uid = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.close()
    return uid


def apply_security_columns():
    """Add security_question and security_answer_hash columns if missing (V3 migration)."""
    conn = get_connection()
    cols = [r[1] for r in conn.execute("PRAGMA table_info(users_v2)").fetchall()]
    if 'security_question' not in cols:
        conn.execute("ALTER TABLE users_v2 ADD COLUMN security_question TEXT DEFAULT ''")
    if 'security_answer_hash' not in cols:
        conn.execute("ALTER TABLE users_v2 ADD COLUMN security_answer_hash TEXT DEFAULT ''")
    conn.execute("INSERT OR IGNORE INTO schema_version (version) VALUES (3)")
    conn.commit()
    conn.close()


def get_security_question(username: str) -> tuple[Optional[str], Optional[int]]:
    """Get security question for a username. Returns (question, user_id) or (None, None)."""
    conn = get_connection()
    row = conn.execute(
        "SELECT id, security_question FROM users_v2 WHERE username = ? AND is_active = 1 AND security_question != ''",
        (username,),
    ).fetchone()
    conn.close()
    if row:
        return (row["security_question"], row["id"])
    return (None, None)


def verify_security_answer(user_id: int, answer: str) -> bool:
    """Verify security answer for a user."""
    conn = get_connection()
    row = conn.execute(
        "SELECT security_answer_hash FROM users_v2 WHERE id = ?", (user_id,)
    ).fetchone()
    conn.close()
    if row and row["security_answer_hash"]:
        return verify_password(answer, row["security_answer_hash"].encode("utf-8"))
    return False


def update_security_question(user_id: int, question: str, answer: str):
    """Update security question and answer for a user."""
    sec_hash = hash_password(answer).decode("utf-8") if answer else ""
    conn = get_connection()
    conn.execute(
        "UPDATE users_v2 SET security_question=?, security_answer_hash=? WHERE id=?",
        (question, sec_hash, user_id),
    )
    conn.commit()
    conn.close()


def change_own_password(user_id: int, old_password: str, new_password: str) -> bool:
    """Change password when user knows their current password."""
    conn = get_connection()
    row = conn.execute("SELECT password_hash FROM users_v2 WHERE id = ?", (user_id,)).fetchone()
    conn.close()
    if not row:
        return False
    if not verify_password(old_password, row["password_hash"].encode("utf-8")):
        return False
    new_hash = hash_password(new_password).decode("utf-8")
    conn = get_connection()
    conn.execute("UPDATE users_v2 SET password_hash=?, updated_at=datetime('now') WHERE id=?", (new_hash, user_id))
    conn.commit()
    conn.close()
    return True


def create_reset_token(user_id: int) -> str:
    """Create a one-time password reset token (valid 15 minutes)."""
    import secrets
    from datetime import datetime, timedelta
    token = secrets.token_urlsafe(32)
    expires = (datetime.now() + timedelta(minutes=15)).strftime("%Y-%m-%d %H:%M:%S")
    conn = get_connection()
    conn.execute(
        "INSERT INTO password_reset_tokens (user_id, token, expires_at) VALUES (?, ?, ?)",
        (user_id, token, expires),
    )
    conn.commit()
    conn.close()
    return token


def verify_reset_token(token: str) -> Optional[int]:
    """Verify a reset token. Returns user_id if valid, None otherwise."""
    from datetime import datetime
    conn = get_connection()
    row = conn.execute(
        "SELECT user_id FROM password_reset_tokens WHERE token = ? AND used = 0 AND expires_at > datetime('now')",
        (token,),
    ).fetchone()
    conn.close()
    if row:
        conn = get_connection()
        conn.execute("UPDATE password_reset_tokens SET used = 1 WHERE token = ?", (token,))
        conn.commit()
        conn.close()
        return row["user_id"]
    return None


def reset_password_with_token(token: str, new_password: str) -> bool:
    """Reset password using a valid reset token. Returns True on success."""
    user_id = verify_reset_token(token)
    if not user_id:
        return False
    new_hash = hash_password(new_password).decode("utf-8")
    conn = get_connection()
    conn.execute("UPDATE users_v2 SET password_hash=?, updated_at=datetime('now') WHERE id=?", (new_hash, user_id))
    conn.commit()
    conn.close()
    return True


def update_user(user_id: int, **kwargs):
    allowed = {'display_name', 'role', 'department_code', 'email', 'is_active'}
    updates = {k: v for k, v in kwargs.items() if k in allowed and v is not None}
    if not updates:
        return
    sets = ', '.join(f"{k}=?" for k in updates)
    vals = list(updates.values()) + [user_id]
    conn = get_connection()
    conn.execute(f"UPDATE users_v2 SET {sets}, updated_at=datetime('now') WHERE id=?", vals)
    conn.commit()
    conn.close()


def reset_password(user_id: int, new_password: str):
    pwd_hash = hash_password(new_password).decode("utf-8")
    conn = get_connection()
    conn.execute("UPDATE users_v2 SET password_hash=?, updated_at=datetime('now') WHERE id=?", (pwd_hash, user_id))
    conn.commit()
    conn.close()


def authenticate_user_v2(username: str, password: str) -> Optional[dict]:
    conn = get_connection()
    row = conn.execute(
        "SELECT * FROM users_v2 WHERE username = ? AND is_active = 1", (username,)
    ).fetchone()
    conn.close()
    if not row:
        return None
    user = dict(row)
    stored_hash = user["password_hash"].encode("utf-8")
    if not verify_password(password, stored_hash):
        return None
    conn = get_connection()
    conn.execute("UPDATE users_v2 SET last_login=datetime('now') WHERE id=?", (user["id"],))
    conn.commit()
    conn.close()
    return user


# ═══════════════════════════════════════════════════════════════
# NOTIFICATIONS
# ═══════════════════════════════════════════════════════════════

def create_notification(title: str, message: str, ntype: str = "INFO",
                        user_id: Optional[int] = None, role: Optional[str] = None,
                        link: Optional[str] = None):
    conn = get_connection()
    conn.execute(
        """INSERT INTO notifications (user_id, role, title, message, type, link)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (user_id, role, title, message, ntype, link),
    )
    conn.commit()
    conn.close()


def get_notifications(user_id: Optional[int] = None, role: Optional[str] = None,
                      unread_only: bool = False, limit: int = 50):
    conn = get_connection()
    parts = ["1=1"]
    params = []
    if user_id:
        parts.append("(user_id = ? OR user_id IS NULL)")
        params.append(user_id)
    if role:
        parts.append("(role = ? OR role IS NULL)")
        params.append(role)
    if unread_only:
        parts.append("is_read = 0")
    sql = f"SELECT * FROM notifications WHERE {' AND '.join(parts)} ORDER BY created_at DESC LIMIT ?"
    params.append(limit)
    rows = conn.execute(sql, params).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def mark_notification_read(notif_id: int):
    conn = get_connection()
    conn.execute("UPDATE notifications SET is_read = 1 WHERE id = ?", (notif_id,))
    conn.commit()
    conn.close()


def mark_all_read(user_id: Optional[int] = None, role: Optional[str] = None):
    conn = get_connection()
    parts = []
    params = []
    if user_id:
        parts.append("(user_id = ? OR user_id IS NULL)")
        params.append(user_id)
    if role:
        parts.append("(role = ? OR role IS NULL)")
        params.append(role)
    where = " AND ".join(parts) if parts else "1=1"
    conn.execute(f"UPDATE notifications SET is_read = 1 WHERE {where}", params)
    conn.commit()
    conn.close()


def get_unread_count(user_id: Optional[int] = None, role: Optional[str] = None) -> int:
    conn = get_connection()
    parts = []
    params = []
    if user_id:
        parts.append("(user_id = ? OR user_id IS NULL)")
        params.append(user_id)
    if role:
        parts.append("(role = ? OR role IS NULL)")
        params.append(role)
    where = " AND ".join(parts) if parts else "1=1"
    count = conn.execute(f"SELECT count(*) FROM notifications WHERE is_read = 0 AND {where}", params).fetchone()[0]
    conn.close()
    return count


# ═══════════════════════════════════════════════════════════════
# LLM QUEUE
# ═══════════════════════════════════════════════════════════════

def enqueue_llm_task(circular_id: int, action: str, payload: Optional[dict] = None):
    conn = get_connection()
    conn.execute(
        "INSERT INTO llm_queue (circular_id, action, payload) VALUES (?, ?, ?)",
        (circular_id, action, json.dumps(payload) if payload else None),
    )
    conn.commit()
    conn.close()


def get_pending_llm_tasks(limit: int = 10):
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM llm_queue WHERE status = 'PENDING' AND retry_count < max_retries "
        "ORDER BY priority DESC, created_at ASC LIMIT ?",
        (limit,),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def update_llm_task(task_id: int, status: str, error: str = ""):
    conn = get_connection()
    if status in ('FAILED',):
        conn.execute(
            "UPDATE llm_queue SET status=?, retry_count=retry_count+1, error=?, updated_at=datetime('now') WHERE id=?",
            (status, error, task_id),
        )
    else:
        conn.execute(
            "UPDATE llm_queue SET status=?, updated_at=datetime('now') WHERE id=?",
            (status, task_id),
        )
    conn.commit()
    conn.close()


def get_llm_queue_stats():
    conn = get_connection()
    pending = conn.execute("SELECT count(*) FROM llm_queue WHERE status='PENDING'").fetchone()[0]
    processing = conn.execute("SELECT count(*) FROM llm_queue WHERE status='PROCESSING'").fetchone()[0]
    failed = conn.execute("SELECT count(*) FROM llm_queue WHERE status='FAILED'").fetchone()[0]
    done = conn.execute("SELECT count(*) FROM llm_queue WHERE status='DONE'").fetchone()[0]
    conn.close()
    return {"pending": pending, "processing": processing, "failed": failed, "done": done}


# ═══════════════════════════════════════════════════════════════
# AUDIT LOG
# ═══════════════════════════════════════════════════════════════

def audit_log(user_id: int, username: str, action: str, entity_type: str = "",
              entity_id: int = 0, details: str = ""):
    conn = get_connection()
    conn.execute(
        "INSERT INTO audit_log (user_id, username, action, entity_type, entity_id, details) VALUES (?, ?, ?, ?, ?, ?)",
        (user_id, username, action, entity_type, entity_id, details),
    )
    conn.commit()
    conn.close()


def get_audit_logs(limit: int = 100):
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM audit_log ORDER BY created_at DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ═══════════════════════════════════════════════════════════════
# CONFIG
# ═══════════════════════════════════════════════════════════════

def get_config(key: str, default: str = "") -> str:
    conn = get_connection()
    row = conn.execute("SELECT value FROM config WHERE key=?", (key,)).fetchone()
    conn.close()
    return row["value"] if row else default


def set_config(key: str, value: str):
    conn = get_connection()
    conn.execute(
        "INSERT OR REPLACE INTO config (key, value, updated_at) VALUES (?, ?, datetime('now'))",
        (key, value),
    )
    conn.commit()
    conn.close()


def get_all_config():
    conn = get_connection()
    rows = conn.execute("SELECT * FROM config ORDER BY key").fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ═══════════════════════════════════════════════════════════════
# BACKUP LOG
# ═══════════════════════════════════════════════════════════════

def log_backup(path: str, size_bytes: int, checksum: str):
    conn = get_connection()
    conn.execute(
        "INSERT INTO backup_log (backup_path, size_bytes, checksum) VALUES (?, ?, ?)",
        (path, size_bytes, checksum),
    )
    conn.commit()
    conn.close()


def get_backup_history(limit: int = 20):
    conn = get_connection()
    rows = conn.execute("SELECT * FROM backup_log ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def _safe_add_column(conn, table, column, coltype):
    try:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {coltype}")
    except Exception:
        pass  # column already exists

def _apply_feature_tables():
    """Create tables for all feature modules (V4 + V5 + V6 schema)."""
    conn = get_connection()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS score_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            date TEXT UNIQUE NOT NULL,
            bank_score REAL NOT NULL,
            dept_scores TEXT DEFAULT '{}',
            created_at TEXT DEFAULT (datetime('now')),
            updated_at TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS reminders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            map_id INTEGER NOT NULL,
            reminder_type TEXT NOT NULL,
            days_until INTEGER DEFAULT 0,
            triggered_at TEXT DEFAULT (datetime('now')),
            is_dismissed INTEGER DEFAULT 0,
            FOREIGN KEY(map_id) REFERENCES maps(id)
        );
        CREATE TABLE IF NOT EXISTS conflicts (
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
        );
        CREATE INDEX IF NOT EXISTS idx_score_history_date ON score_history(date);
        CREATE INDEX IF NOT EXISTS idx_reminders_map ON reminders(map_id);
        CREATE INDEX IF NOT EXISTS idx_conflicts_circular ON conflicts(circular_a_id, circular_b_id);

        -- V5: Impact Simulations + other features
        CREATE TABLE IF NOT EXISTS impact_simulations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            circular_id INTEGER NOT NULL,
            ignore_days INTEGER DEFAULT 90,
            penalty_estimate REAL DEFAULT 0,
            score_drop REAL DEFAULT 0,
            reputational_risk TEXT DEFAULT 'LOW',
            details TEXT DEFAULT '{}',
            created_at TEXT DEFAULT (datetime('now')),
            FOREIGN KEY(circular_id) REFERENCES circulars(id)
        );
        CREATE TABLE IF NOT EXISTS circular_changes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            old_circular_id INTEGER NOT NULL,
            new_circular_id INTEGER NOT NULL,
            summary TEXT DEFAULT '',
            changes_json TEXT DEFAULT '{}',
            severity TEXT DEFAULT 'LOW',
            created_at TEXT DEFAULT (datetime('now')),
            FOREIGN KEY(old_circular_id) REFERENCES circulars(id),
            FOREIGN KEY(new_circular_id) REFERENCES circulars(id)
        );
        CREATE TABLE IF NOT EXISTS implementation_plans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            map_id INTEGER NOT NULL,
            steps_json TEXT DEFAULT '[]',
            total_hours REAL DEFAULT 0,
            estimated_completion TEXT,
            progress_pct REAL DEFAULT 0,
            created_at TEXT DEFAULT (datetime('now')),
            updated_at TEXT DEFAULT (datetime('now')),
            FOREIGN KEY(map_id) REFERENCES maps(id)
        );
        CREATE TABLE IF NOT EXISTS violation_predictions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            department_code TEXT DEFAULT '',
            risk_score REAL DEFAULT 50,
            breach_probability REAL DEFAULT 0,
            predicted_delay_days REAL DEFAULT 0,
            trend TEXT DEFAULT 'STABLE',
            created_at TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS inspection_packages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            prepared_by TEXT DEFAULT '',
            prepared_at TEXT DEFAULT (datetime('now')),
            summary TEXT DEFAULT '{}',
            package_json TEXT DEFAULT '{}',
            blockchain_hash TEXT DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS copilot_actions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            api_endpoint TEXT DEFAULT '',
            description TEXT DEFAULT '',
            created_at TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS agent_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_name TEXT NOT NULL,
            status TEXT DEFAULT 'IDLE',
            started_at TEXT,
            completed_at TEXT,
            duration_secs REAL DEFAULT 0,
            tasks_processed INTEGER DEFAULT 0,
            error TEXT DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS evidence_drafts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            map_id INTEGER NOT NULL,
            draft_type TEXT NOT NULL,
            title TEXT DEFAULT '',
            content TEXT DEFAULT '',
            created_at TEXT DEFAULT (datetime('now')),
            FOREIGN KEY(map_id) REFERENCES maps(id)
        );

        -- V6: Security & Governance tables
        CREATE TABLE IF NOT EXISTS signed_audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT NOT NULL,
            user TEXT NOT NULL,
            details TEXT DEFAULT '{}',
            entity_type TEXT DEFAULT '',
            entity_id INTEGER DEFAULT 0,
            entry_hash TEXT NOT NULL UNIQUE,
            previous_hash TEXT DEFAULT '',
            timestamp TEXT NOT NULL,
            created_at TEXT DEFAULT (datetime('now'))
        );
        CREATE INDEX IF NOT EXISTS idx_signed_log_hash ON signed_audit_log(entry_hash);
        CREATE INDEX IF NOT EXISTS idx_signed_log_event ON signed_audit_log(event_type);

        CREATE TABLE IF NOT EXISTS compliance_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            pattern TEXT NOT NULL,
            category TEXT DEFAULT '',
            action TEXT DEFAULT '',
            description TEXT DEFAULT '',
            severity TEXT DEFAULT 'MEDIUM',
            created_at TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS knowledge_queries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            query TEXT NOT NULL,
            answer TEXT,
            result_count INTEGER DEFAULT 0,
            created_at TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS ai_governance_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action TEXT NOT NULL,
            user TEXT NOT NULL,
            input_preview TEXT DEFAULT '',
            output_preview TEXT DEFAULT '',
            governance_passed INTEGER DEFAULT 1,
            governance_score REAL DEFAULT 100,
            created_at TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS supersessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            old_circular_id INTEGER NOT NULL,
            new_circular_id INTEGER NOT NULL,
            old_circular_number TEXT DEFAULT '',
            new_circular_number TEXT DEFAULT '',
            relationship TEXT DEFAULT 'supersedes',
            detected_at TEXT DEFAULT (datetime('now')),
            FOREIGN KEY(old_circular_id) REFERENCES circulars(id),
            FOREIGN KEY(new_circular_id) REFERENCES circulars(id)
        );
    """)
    conn.execute("INSERT OR IGNORE INTO schema_version (version) VALUES (4)")
    conn.execute("INSERT OR IGNORE INTO schema_version (version) VALUES (5)")
    conn.execute("INSERT OR IGNORE INTO schema_version (version) VALUES (6)")
    conn.commit()

    # V5 column additions
    cols = [r[1] for r in conn.execute("PRAGMA table_info(circulars)").fetchall()]
    if 'regulator_code' not in cols:
        conn.execute("ALTER TABLE circulars ADD COLUMN regulator_code TEXT DEFAULT 'RBI'")
    if 'analysis' not in cols:
        conn.execute("ALTER TABLE circulars ADD COLUMN analysis TEXT DEFAULT ''")
    # V7: maps columns
    mcols = [r[1] for r in conn.execute("PRAGMA table_info(maps)").fetchall()]
    if 'frequency' not in mcols:
        conn.execute("ALTER TABLE maps ADD COLUMN frequency TEXT DEFAULT 'One-time'")
    if 'evidence_required' not in mcols:
        conn.execute("ALTER TABLE maps ADD COLUMN evidence_required TEXT DEFAULT ''")
    if 'map_id_label' not in mcols:
        conn.execute("ALTER TABLE maps ADD COLUMN map_id_label TEXT DEFAULT ''")
    if 'acknowledged_by' not in mcols:
        conn.execute("ALTER TABLE maps ADD COLUMN acknowledged_by TEXT DEFAULT ''")
    if 'acknowledged_hash' not in mcols:
        conn.execute("ALTER TABLE maps ADD COLUMN acknowledged_hash TEXT DEFAULT ''")
    if 'acknowledged_at' not in mcols:
        conn.execute("ALTER TABLE maps ADD COLUMN acknowledged_at TEXT")
    conn.commit()
    conn.close()


# Fix circular import at top
def _add_maps_status_v3():
    """Add workflow statuses used by routing, acknowledgement, validation and escalation."""
    import logging
    log = logging.getLogger("phantom_compliance.db")
    conn = get_connection()
    cur = conn.execute("PRAGMA table_info(maps)")
    cols = [r[1] for r in cur.fetchall()]
    if 'assigned_by' not in cols:
        conn.execute("ALTER TABLE maps ADD COLUMN assigned_by TEXT DEFAULT ''")
    if 'assigned_at' not in cols:
        conn.execute("ALTER TABLE maps ADD COLUMN assigned_at TEXT")
    if 'rejected_by' not in cols:
        conn.execute("ALTER TABLE maps ADD COLUMN rejected_by TEXT DEFAULT ''")
    if 'rejected_reason' not in cols:
        conn.execute("ALTER TABLE maps ADD COLUMN rejected_reason TEXT DEFAULT ''")
    if 'completed_by' not in cols:
        conn.execute("ALTER TABLE maps ADD COLUMN completed_by TEXT DEFAULT ''")
    if 'completed_at' not in cols:
        conn.execute("ALTER TABLE maps ADD COLUMN completed_at TEXT")
    if 'acknowledged_by' not in cols:
        conn.execute("ALTER TABLE maps ADD COLUMN acknowledged_by TEXT DEFAULT ''")
    if 'acknowledged_hash' not in cols:
        conn.execute("ALTER TABLE maps ADD COLUMN acknowledged_hash TEXT DEFAULT ''")
    if 'acknowledged_at' not in cols:
        conn.execute("ALTER TABLE maps ADD COLUMN acknowledged_at TEXT")

    table_sql = conn.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='maps'"
    ).fetchone()
    table_sql = table_sql["sql"] if table_sql else ""
    if "ASSIGNED_UNACKNOWLEDGED" in table_sql and "ACKNOWLEDGEMENT_OVERDUE" in table_sql:
        conn.close()
        return

    # Recreate table with the full pipeline CHECK constraint.
    try:
        conn.execute("PRAGMA foreign_keys=OFF")
        conn.execute("DROP TABLE IF EXISTS maps_v2")
        conn.execute("""
            CREATE TABLE maps_v2 (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                circular_id INTEGER NOT NULL,
                map_text TEXT,
                encrypted_detail BLOB,
                detail_nonce BLOB,
                detail_auth_tag BLOB,
                department_hint TEXT,
                deadline_days INTEGER,
                deadline_date TEXT,
                assigned_to TEXT,
                assigned_to_user_id INTEGER,
                evidence_text TEXT,
                evidence_file_path TEXT,
                status TEXT DEFAULT 'PENDING' CHECK(status IN (
                    'PENDING','ASSIGNED','ASSIGNED_UNACKNOWLEDGED','ASSIGNED_ACKNOWLEDGED',
                    'ACKNOWLEDGEMENT_OVERDUE','VALIDATED','BREACHED','ESCALATED','COMPLETED',
                    'REJECTED','SUPERSEDED'
                )),
                validated_at TEXT,
                frequency TEXT DEFAULT 'One-time',
                evidence_required TEXT DEFAULT '',
                map_id_label TEXT DEFAULT '',
                assigned_by TEXT DEFAULT '',
                assigned_at TEXT,
                rejected_by TEXT DEFAULT '',
                rejected_reason TEXT DEFAULT '',
                completed_by TEXT DEFAULT '',
                completed_at TEXT,
                acknowledged_by TEXT DEFAULT '',
                acknowledged_hash TEXT DEFAULT '',
                acknowledged_at TEXT,
                created_at TEXT DEFAULT (datetime('now')),
                FOREIGN KEY(circular_id) REFERENCES circulars(id)
            )
        """)
        existing = conn.execute("SELECT count(*) FROM maps").fetchone()[0]
        if existing > 0:
            conn.execute("""
                INSERT OR IGNORE INTO maps_v2
                SELECT id, circular_id, map_text, encrypted_detail, detail_nonce, detail_auth_tag,
                       department_hint, deadline_days, deadline_date, assigned_to, assigned_to_user_id,
                       evidence_text, evidence_file_path, status, validated_at,
                       COALESCE(frequency,'One-time'), COALESCE(evidence_required,''), COALESCE(map_id_label,''),
                       COALESCE(assigned_by,''), assigned_at, COALESCE(rejected_by,''), COALESCE(rejected_reason,''),
                       COALESCE(completed_by,''), completed_at,
                       COALESCE(acknowledged_by,''), COALESCE(acknowledged_hash,''), acknowledged_at,
                       created_at
                FROM maps
            """)
        conn.execute("DROP TABLE IF EXISTS maps")
        conn.execute("ALTER TABLE maps_v2 RENAME TO maps")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("INSERT OR IGNORE INTO schema_version (version) VALUES (9)")
        conn.commit()
    except Exception as e:
        conn.rollback()
        conn.execute("PRAGMA foreign_keys=ON")
        log.warning(f"maps table migration failed (may already be migrated): {e}")
    conn.close()
