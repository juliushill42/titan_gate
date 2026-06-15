"""
Titan Gate — Database Layer
Append-only audit log + credential vault + agent registry
"""
import sqlite3
import os
from pathlib import Path

DB_PATH = os.environ.get("TITAN_DB", str(Path.home() / ".titan-gate" / "titan.db"))


def get_db() -> sqlite3.Connection:
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db():
    conn = get_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS agents (
            id          TEXT PRIMARY KEY,
            name        TEXT NOT NULL UNIQUE,
            description TEXT,
            manifest    TEXT NOT NULL,
            status      TEXT NOT NULL DEFAULT 'active',
            created_at  TEXT NOT NULL DEFAULT (datetime('now')),
            revoked_at  TEXT
        );

        CREATE TABLE IF NOT EXISTS credentials (
            id          TEXT PRIMARY KEY,
            agent_id    TEXT NOT NULL REFERENCES agents(id),
            scope       TEXT NOT NULL,
            label       TEXT NOT NULL,
            secret_enc  TEXT NOT NULL,
            created_at  TEXT NOT NULL DEFAULT (datetime('now')),
            expires_at  TEXT,
            revoked     INTEGER NOT NULL DEFAULT 0,
            revoked_at  TEXT
        );

        CREATE TABLE IF NOT EXISTS tool_calls (
            id          TEXT PRIMARY KEY,
            agent_id    TEXT NOT NULL REFERENCES agents(id),
            tool        TEXT NOT NULL,
            args        TEXT NOT NULL,
            status      TEXT NOT NULL DEFAULT 'pending',
            result      TEXT,
            error       TEXT,
            approved_by TEXT,
            started_at  TEXT NOT NULL DEFAULT (datetime('now')),
            completed_at TEXT,
            replay_of   TEXT
        );

        CREATE TABLE IF NOT EXISTS permissions (
            id          TEXT PRIMARY KEY,
            agent_id    TEXT NOT NULL REFERENCES agents(id),
            tool        TEXT NOT NULL,
            scope       TEXT NOT NULL,
            granted     INTEGER NOT NULL DEFAULT 0,
            created_at  TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS audit_log (
            id          TEXT PRIMARY KEY,
            event_type  TEXT NOT NULL,
            agent_id    TEXT,
            tool_call_id TEXT,
            credential_id TEXT,
            actor       TEXT,
            detail      TEXT,
            ts          TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS users (
            id          TEXT PRIMARY KEY,
            username    TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role        TEXT NOT NULL DEFAULT 'operator',
            created_at  TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE INDEX IF NOT EXISTS idx_tool_calls_agent ON tool_calls(agent_id);
        CREATE INDEX IF NOT EXISTS idx_tool_calls_status ON tool_calls(status);
        CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts);
        CREATE INDEX IF NOT EXISTS idx_credentials_agent ON credentials(agent_id);
    """)
    conn.commit()
    conn.close()


def dict_from_row(row) -> dict:
    return dict(row) if row else None
