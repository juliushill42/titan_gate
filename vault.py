"""
Titan Gate — Credential Vault
Encrypts credentials at rest using Fernet (AES-128-CBC + HMAC-SHA256).
Agents never see raw secrets — they receive a scoped injection token.
"""
import os
import base64
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from cryptography.fernet import Fernet
from db import get_db, dict_from_row


VAULT_KEY_PATH = os.environ.get(
    "TITAN_VAULT_KEY", str(Path.home() / ".titan-gate" / "vault.key")
)


def _load_or_create_key() -> bytes:
    p = Path(VAULT_KEY_PATH)
    p.parent.mkdir(parents=True, exist_ok=True)
    if p.exists():
        return p.read_bytes()
    key = Fernet.generate_key()
    p.write_bytes(key)
    p.chmod(0o600)
    return key


def _fernet() -> Fernet:
    return Fernet(_load_or_create_key())


def encrypt_secret(secret: str) -> str:
    return _fernet().encrypt(secret.encode()).decode()


def decrypt_secret(encrypted: str) -> str:
    return _fernet().decrypt(encrypted.encode()).decode()


def store_credential(agent_id: str, scope: str, label: str, secret: str,
                     expires_at: str = None) -> dict:
    conn = get_db()
    cred_id = str(uuid.uuid4())
    encrypted = encrypt_secret(secret)
    conn.execute(
        """INSERT INTO credentials (id, agent_id, scope, label, secret_enc, expires_at)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (cred_id, agent_id, scope, label, encrypted, expires_at)
    )
    _audit(conn, "credential_stored", agent_id=agent_id,
           credential_id=cred_id, detail=f"scope={scope} label={label}")
    conn.commit()
    conn.close()
    return {"id": cred_id, "scope": scope, "label": label}


def inject_credential(agent_id: str, scope: str) -> str | None:
    """
    Returns decrypted secret if agent has a valid, non-revoked credential
    for the requested scope. Returns None if denied.
    """
    conn = get_db()
    now = datetime.now(timezone.utc).isoformat()
    row = conn.execute(
        """SELECT * FROM credentials
           WHERE agent_id=? AND scope=? AND revoked=0
             AND (expires_at IS NULL OR expires_at > ?)
           ORDER BY created_at DESC LIMIT 1""",
        (agent_id, scope, now)
    ).fetchone()
    conn.close()
    if not row:
        return None
    return decrypt_secret(row["secret_enc"])


def revoke_credential(cred_id: str, actor: str = "operator") -> bool:
    conn = get_db()
    now = datetime.now(timezone.utc).isoformat()
    cur = conn.execute(
        "UPDATE credentials SET revoked=1, revoked_at=? WHERE id=? AND revoked=0",
        (now, cred_id)
    )
    if cur.rowcount:
        _audit(conn, "credential_revoked", credential_id=cred_id,
               actor=actor, detail="revoked by operator")
        conn.commit()
        conn.close()
        return True
    conn.close()
    return False


def list_credentials(agent_id: str) -> list[dict]:
    conn = get_db()
    rows = conn.execute(
        """SELECT id, scope, label, created_at, expires_at, revoked, revoked_at
           FROM credentials WHERE agent_id=? ORDER BY created_at DESC""",
        (agent_id,)
    ).fetchall()
    conn.close()
    return [dict_from_row(r) for r in rows]


def _audit(conn, event_type, agent_id=None, credential_id=None,
           actor=None, detail=None):
    conn.execute(
        """INSERT INTO audit_log (id, event_type, agent_id, credential_id, actor, detail)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (str(uuid.uuid4()), event_type, agent_id, credential_id, actor, detail)
    )
