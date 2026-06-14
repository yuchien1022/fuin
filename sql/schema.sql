PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;

CREATE TABLE IF NOT EXISTS secrets (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    name_nonce BLOB NOT NULL,
    encrypted_name BLOB NOT NULL,
    version INTEGER NOT NULL DEFAULT 1,
    algorithm TEXT NOT NULL,
    ciphertext BLOB NOT NULL,
    encrypted_dek BLOB NOT NULL,
    nonce BLOB NOT NULL,
    dek_nonce BLOB NOT NULL,
    key_commitment BLOB NOT NULL,
    nonce_counter INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    expires_at TEXT,
    rotation_interval_seconds INTEGER,
    tags TEXT,
    is_archived INTEGER NOT NULL DEFAULT 0,
    CHECK (algorithm IN ('AES-256-GCM', 'XChaCha20-Poly1305', 'AEGIS-256')),
    CHECK (rotation_interval_seconds IS NULL OR rotation_interval_seconds > 0),
    CHECK (is_archived IN (0, 1)),
    UNIQUE (name, version)
);

CREATE TABLE IF NOT EXISTS audit_log (
    entry_id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    action TEXT NOT NULL,
    actor TEXT NOT NULL DEFAULT 'user:default',
    target TEXT NOT NULL,
    target_version INTEGER,
    result TEXT NOT NULL,
    prev_hash BLOB NOT NULL,
    entry_hash BLOB NOT NULL,
    hmac_signature BLOB NOT NULL,
    CHECK (action IN ('CREATE', 'READ', 'UPDATE', 'DELETE', 'ROLLBACK', 'ROTATE_KEK', 'ROTATE_DEK', 'TOKEN_ISSUE', 'TOKEN_REVOKE')),
    CHECK (result IN ('SUCCESS', 'FAILURE'))
);

CREATE TABLE IF NOT EXISTS metadata (
    key TEXT PRIMARY KEY,
    value BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS auth_failures (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    result TEXT NOT NULL,
    CHECK (result IN ('FAILURE'))
);

CREATE INDEX IF NOT EXISTS idx_secrets_name ON secrets (name);
CREATE UNIQUE INDEX IF NOT EXISTS idx_secrets_name_active
    ON secrets (name)
    WHERE is_archived = 0;
CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log (timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_log_target ON audit_log (target, target_version);
CREATE INDEX IF NOT EXISTS idx_auth_failures_timestamp ON auth_failures (timestamp);
