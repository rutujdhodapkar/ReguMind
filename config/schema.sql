-- Phantom Compliance SQLite Schema
-- All PII and circular content stored as AES-256-GCM encrypted blobs

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,          -- bcrypt hash
    role TEXT NOT NULL CHECK(role IN ('CCO','KYC','Payments','IT_Security','Treasury','Credit_Risk','Forex')),
    department_code TEXT,
    created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS circulars (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    circular_number TEXT,
    department_code TEXT,
    issue_date TEXT,
    addressee TEXT,
    subject_line TEXT,
    encrypted_body BLOB NOT NULL,         -- AES-256-GCM ciphertext
    nonce BLOB NOT NULL,
    auth_tag BLOB NOT NULL,
    ingested_at TEXT DEFAULT (datetime('now')),
    created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS maps (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    circular_id INTEGER NOT NULL,
    map_text TEXT,                         -- plaintext stored for dashboard display
    encrypted_detail BLOB,                -- full MAP JSON encrypted
    detail_nonce BLOB,
    detail_auth_tag BLOB,
    department_hint TEXT,
    deadline_days INTEGER,
    deadline_date TEXT,
    assigned_to TEXT,                     -- department role
    assigned_to_user_id INTEGER,
    evidence_text TEXT,
    evidence_file_path TEXT,
    status TEXT DEFAULT 'PENDING' CHECK(status IN ('PENDING','ASSIGNED','VALIDATED','BREACHED','ESCALATED')),
    validated_at TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY(circular_id) REFERENCES circulars(id)
);

CREATE TABLE IF NOT EXISTS blockchain_meta (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    last_index INTEGER DEFAULT 0,
    updated_at TEXT DEFAULT (datetime('now'))
);

INSERT OR IGNORE INTO blockchain_meta (id, last_index) VALUES (1, 0);
