-- Phantom Compliance V2 Schema Extensions
-- Adds production-grade features: user management, notifications, LLM queue, audit logs

CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY,
    applied_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS users_v2 (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    display_name TEXT,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('CCO','KYC','Payments','IT_Security','Treasury','Credit_Risk','Forex')),
    department_code TEXT,
    email TEXT,
    is_active INTEGER DEFAULT 1,
    last_login TEXT,
    created_by INTEGER,
    security_question TEXT DEFAULT '',
    security_answer_hash TEXT DEFAULT '',
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    token TEXT NOT NULL UNIQUE,
    expires_at TEXT NOT NULL,
    used INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY(user_id) REFERENCES users_v2(id)
);

CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    role TEXT,
    title TEXT NOT NULL,
    message TEXT NOT NULL,
    type TEXT NOT NULL CHECK(type IN ('INFO','WARNING','ERROR','BREACH','ESCALATION','BACKUP','SYSTEM')),
    is_read INTEGER DEFAULT 0,
    link TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY(user_id) REFERENCES users_v2(id)
);

CREATE TABLE IF NOT EXISTS llm_queue (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    circular_id INTEGER NOT NULL,
    action TEXT NOT NULL CHECK(action IN ('GENERATE_MAPS','VALIDATE_EVIDENCE')),
    payload TEXT,
    status TEXT DEFAULT 'PENDING' CHECK(status IN ('PENDING','PROCESSING','DONE','FAILED')),
    retry_count INTEGER DEFAULT 0,
    max_retries INTEGER DEFAULT 5,
    error TEXT,
    priority INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY(circular_id) REFERENCES circulars(id)
);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    username TEXT,
    action TEXT NOT NULL,
    entity_type TEXT,
    entity_id INTEGER,
    details TEXT,
    ip_address TEXT,
    created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS backup_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    backup_path TEXT NOT NULL,
    size_bytes INTEGER,
    checksum TEXT,
    status TEXT DEFAULT 'COMPLETED' CHECK(status IN ('COMPLETED','FAILED','RESTORED')),
    created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS config (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT DEFAULT (datetime('now'))
);

-- Default configuration values
INSERT OR IGNORE INTO config (key, value) VALUES ('retention_days_circulars', '365');
INSERT OR IGNORE INTO config (key, value) VALUES ('retention_days_notifications', '90');
INSERT OR IGNORE INTO config (key, value) VALUES ('llm_max_retries', '5');
INSERT OR IGNORE INTO config (key, value) VALUES ('llm_retry_interval_sec', '60');
INSERT OR IGNORE INTO config (key, value) VALUES ('backup_enabled', 'true');
INSERT OR IGNORE INTO config (key, value) VALUES ('backup_interval_hours', '24');
INSERT OR IGNORE INTO config (key, value) VALUES ('auto_purge_enabled', 'true');
INSERT OR IGNORE INTO config (key, value) VALUES ('llm_url', 'http://localhost:8080/completion');

CREATE INDEX IF NOT EXISTS idx_notifications_user ON notifications(user_id, is_read);
CREATE INDEX IF NOT EXISTS idx_notifications_role ON notifications(role, is_read);
CREATE INDEX IF NOT EXISTS idx_llm_queue_status ON llm_queue(status);
CREATE INDEX IF NOT EXISTS idx_audit_log_user ON audit_log(user_id, created_at);
CREATE INDEX IF NOT EXISTS idx_maps_status ON maps(status);
