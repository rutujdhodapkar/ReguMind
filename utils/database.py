"""
SQLite database layer for Phantom Compliance.
Handles initialization, connection management, and CRUD operations.
All sensitive columns are stored as AES-256-GCM encrypted blobs.
"""

import sqlite3
import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

from config.settings import get_app_paths
from p_crypto.encryptor import encrypt, decrypt
from p_crypto.dpapi import protect_key, unprotect_key
from auth.password import hash_password


_MASTER_KEY_CACHE = None


def _get_master_key() -> bytes:
    global _MASTER_KEY_CACHE
    if _MASTER_KEY_CACHE is not None:
        return _MASTER_KEY_CACHE
    paths = get_app_paths()
    key_dir = paths["CONFIG_DIR"]
    key_path = key_dir / "master_key.dpapi"
    if key_path.exists():
        _MASTER_KEY_CACHE = unprotect_key(key_dir)
    else:
        import secrets
        _MASTER_KEY_CACHE = secrets.token_bytes(32)
        protect_key(_MASTER_KEY_CACHE, key_dir)
    return _MASTER_KEY_CACHE


def get_connection() -> sqlite3.Connection:
    paths = get_app_paths()
    conn = sqlite3.connect(str(paths["DB_PATH"]))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_database():
    """Initialize the SQLite schema from schema.sql."""
    conn = get_connection()
    schema_path = Path(__file__).parent.parent / "config" / "schema.sql"
    if schema_path.exists():
        conn.executescript(schema_path.read_text(encoding="utf-8"))
    conn.commit()
    conn.close()


def seed_admin_user(password: str):
    """Create or update the admin CCO user with the provided password."""
    conn = get_connection()
    pwd_hash = hash_password(password).decode("utf-8")
    cols = {r[1] for r in conn.execute("PRAGMA table_info(users)").fetchall()}
    if "department_code" in cols:
        conn.execute(
            """INSERT OR REPLACE INTO users (id, username, password_hash, role, department_code)
               VALUES (1, 'admin', ?, 'CCO', 'ALL')""",
            (pwd_hash,),
        )
    else:
        conn.execute(
            """INSERT OR REPLACE INTO users (id, username, password_hash, role)
               VALUES (1, 'admin', ?, 'CCO')""",
            (pwd_hash,),
        )
    conn.commit()
    conn.close()


def user_exists(username: str) -> bool:
    conn = get_connection()
    row = conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()
    return row is not None


def get_user(username: str) -> Optional[dict]:
    conn = get_connection()
    row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()
    if row:
        return dict(row)
    return None


def store_circular(circular_number, dept_code, issue_date, addressee, subject, body_text: str):
    mk = _get_master_key()
    ciphertext, nonce, auth_tag = encrypt(body_text, mk)
    conn = get_connection()
    conn.execute(
        """INSERT INTO circulars
           (circular_number, department_code, issue_date, addressee, subject_line,
            encrypted_body, nonce, auth_tag)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (circular_number, dept_code, issue_date, addressee, subject, ciphertext, nonce, auth_tag),
    )
    conn.commit()
    cid = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.close()
    return cid


def get_all_circulars():
    conn = get_connection()
    rows = conn.execute(
        "SELECT id, circular_number, department_code, issue_date, addressee, subject_line, ingested_at FROM circulars ORDER BY id DESC"
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_circular_body(circular_id: int) -> str:
    mk = _get_master_key()
    conn = get_connection()
    row = conn.execute(
        "SELECT encrypted_body, nonce, auth_tag FROM circulars WHERE id = ?", (circular_id,)
    ).fetchone()
    conn.close()
    if row:
        plaintext = decrypt(bytes(row["encrypted_body"]), bytes(row["nonce"]), bytes(row["auth_tag"]), mk)
        return plaintext
    return ""


def store_map(circular_id, map_text, encrypted_detail, detail_nonce, detail_auth_tag, dept_hint, deadline_days, frequency="One-time", evidence_required="", map_id_label=""):
    conn = get_connection()
    deadline_date = (datetime.now() + timedelta(days=int(deadline_days))).strftime("%Y-%m-%d")
    conn.execute(
        """INSERT INTO maps
           (circular_id, map_text, encrypted_detail, detail_nonce, detail_auth_tag,
            department_hint, deadline_days, deadline_date, frequency, evidence_required, map_id_label, status)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'PENDING')""",
        (circular_id, map_text, encrypted_detail, detail_nonce, detail_auth_tag, dept_hint, int(deadline_days), deadline_date, frequency, evidence_required, map_id_label),
    )
    conn.commit()
    mid = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.close()
    return mid


def assign_map(map_id: int, department_role: str, user_id: int):
    conn = get_connection()
    conn.execute(
        "UPDATE maps SET status='ASSIGNED', assigned_to=?, assigned_to_user_id=? WHERE id=?",
        (department_role, user_id, map_id),
    )
    conn.commit()
    conn.close()


def update_map_evidence(map_id: int, evidence_text: str, file_path: str = ""):
    conn = get_connection()
    conn.execute(
        "UPDATE maps SET evidence_text=?, evidence_file_path=? WHERE id=?",
        (evidence_text, file_path, map_id),
    )
    conn.commit()
    conn.close()


def validate_map(map_id: int):
    conn = get_connection()
    conn.execute(
        "UPDATE maps SET status='VALIDATED', validated_at=datetime('now') WHERE id=?",
        (map_id,),
    )
    conn.commit()
    conn.close()


def breach_map(map_id: int):
    conn = get_connection()
    conn.execute("UPDATE maps SET status='BREACHED' WHERE id=?", (map_id,))
    conn.commit()
    conn.close()


def escalate_map(map_id: int):
    conn = get_connection()
    conn.execute("UPDATE maps SET status='ESCALATED' WHERE id=?", (map_id,))
    conn.commit()
    conn.close()


def get_maps_for_department(dept_role: str):
    conn = get_connection()
    rows = conn.execute(
        """SELECT m.*, c.circular_number, c.subject_line
           FROM maps m JOIN circulars c ON m.circular_id = c.id
           WHERE m.assigned_to = ?
           ORDER BY m.deadline_date ASC""",
        (dept_role,),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_all_maps():
    conn = get_connection()
    rows = conn.execute(
        """SELECT m.*, c.circular_number, c.subject_line
           FROM maps m JOIN circulars c ON m.circular_id = c.id
           ORDER BY m.id DESC""",
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_pending_maps():
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM maps WHERE status='PENDING' OR status='ASSIGNED'"
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_escalated_maps():
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM maps WHERE status='ESCALATED' OR status='BREACHED'"
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def check_deadlines():
    conn = get_connection()
    rows = conn.execute(
        "SELECT id FROM maps WHERE status IN ('PENDING','ASSIGNED') AND deadline_date < date('now')"
    ).fetchall()
    conn.close()
    return [r["id"] for r in rows]


# ═══════════════════════════════════════════════════════════════
# SEARCH / FILTER / PAGINATION
# ═══════════════════════════════════════════════════════════════

def get_filtered_circulars(search="", status="", dept="", page=1, per_page=50):
    conn = get_connection()
    conditions = []
    params = []
    if search:
        conditions.append("(circular_number LIKE ? OR subject_line LIKE ?)")
        params.extend([f"%{search}%", f"%{search}%"])
    if dept:
        conditions.append("department_code = ?")
        params.append(dept)
    where = " AND ".join(conditions) if conditions else "1=1"
    offset = (page - 1) * per_page
    count_row = conn.execute(f"SELECT count(*) FROM circulars WHERE {where}", params).fetchone()
    total = count_row[0]
    rows = conn.execute(
        f"SELECT * FROM circulars WHERE {where} ORDER BY ingested_at DESC LIMIT ? OFFSET ?",
        params + [per_page, offset],
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows], total


def get_filtered_maps(search="", status="", dept="", page=1, per_page=50):
    conn = get_connection()
    conditions = []
    params = []
    if search:
        conditions.append("(m.map_text LIKE ? OR c.circular_number LIKE ?)")
        params.extend([f"%{search}%", f"%{search}%"])
    if status:
        conditions.append("m.status = ?")
        params.append(status)
    if dept:
        conditions.append("m.assigned_to = ?")
        params.append(dept)
    where = " AND ".join(conditions) if conditions else "1=1"
    offset = (page - 1) * per_page
    count_row = conn.execute(
        f"SELECT count(*) FROM maps m JOIN circulars c ON m.circular_id = c.id WHERE {where}", params
    ).fetchone()
    total = count_row[0]
    rows = conn.execute(
        f"""SELECT m.*, c.circular_number, c.subject_line
            FROM maps m JOIN circulars c ON m.circular_id = c.id
            WHERE {where} ORDER BY m.id DESC LIMIT ? OFFSET ?""",
        params + [per_page, offset],
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows], total


def search_circulars(query: str, limit=20):
    conn = get_connection()
    rows = conn.execute(
        """SELECT id, circular_number, subject_line, department_code, issue_date, ingested_at
           FROM circulars
           WHERE circular_number LIKE ? OR subject_line LIKE ? OR department_code LIKE ?
           ORDER BY ingested_at DESC LIMIT ?""",
        [f"%{query}%", f"%{query}%", f"%{query}%", limit],
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def search_maps(query: str, limit=20):
    conn = get_connection()
    rows = conn.execute(
        """SELECT m.id, m.map_text, m.status, m.deadline_date, c.circular_number
           FROM maps m JOIN circulars c ON m.circular_id = c.id
           WHERE m.map_text LIKE ? OR c.circular_number LIKE ? OR m.assigned_to LIKE ?
           ORDER BY m.id DESC LIMIT ?""",
        [f"%{query}%", f"%{query}%", f"%{query}%", limit],
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]
