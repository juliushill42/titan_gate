"""
Titan Gate — Permission Engine
Default-deny. Every tool call is checked against the agent's signed manifest.
Manifest format is YAML. Unknown tools = denied.
"""
import yaml
import uuid
import json
from db import get_db, dict_from_row


BUILTIN_TOOLS = {
    "shell": ["read", "write", "execute"],
    "browser": ["navigate", "click", "type", "screenshot", "download"],
    "api": ["get", "post", "put", "delete", "patch"],
    "file": ["read", "write", "delete", "list"],
    "email": ["send", "read", "delete"],
    "calendar": ["read", "write", "delete"],
}


def parse_manifest(manifest_yaml: str) -> dict:
    """
    Parse and validate agent manifest.
    Returns parsed dict or raises ValueError.
    """
    try:
        m = yaml.safe_load(manifest_yaml)
    except yaml.YAMLError as e:
        raise ValueError(f"Invalid YAML: {e}")

    if not isinstance(m, dict):
        raise ValueError("Manifest must be a YAML dict")
    if "tools" not in m:
        raise ValueError("Manifest must declare 'tools'")
    if not isinstance(m["tools"], dict):
        raise ValueError("'tools' must be a dict of tool: [scopes]")

    for tool, scopes in m["tools"].items():
        if tool not in BUILTIN_TOOLS:
            raise ValueError(
                f"Unknown tool '{tool}'. Allowed: {list(BUILTIN_TOOLS.keys())}"
            )
        if not isinstance(scopes, list):
            raise ValueError(f"Scopes for '{tool}' must be a list")
        for scope in scopes:
            if scope not in BUILTIN_TOOLS[tool]:
                raise ValueError(
                    f"Unknown scope '{scope}' for tool '{tool}'. "
                    f"Allowed: {BUILTIN_TOOLS[tool]}"
                )
    return m


def check_permission(agent_id: str, tool: str, scope: str) -> tuple[bool, str]:
    """
    Returns (allowed: bool, reason: str).
    Checks agent status, then manifest permissions.
    """
    conn = get_db()
    agent = conn.execute(
        "SELECT manifest, status FROM agents WHERE id=?", (agent_id,)
    ).fetchone()
    conn.close()

    if not agent:
        return False, "Agent not found"
    if agent["status"] != "active":
        return False, f"Agent is {agent['status']}"

    try:
        manifest = parse_manifest(agent["manifest"])
    except ValueError as e:
        return False, f"Manifest error: {e}"

    tools = manifest.get("tools", {})
    if tool not in tools:
        return False, f"Tool '{tool}' not in manifest (default deny)"

    allowed_scopes = tools[tool]
    if scope not in allowed_scopes:
        return False, f"Scope '{scope}' not allowed for tool '{tool}'"

    return True, "permitted"


def register_agent(name: str, description: str, manifest_yaml: str) -> dict:
    manifest = parse_manifest(manifest_yaml)  # raises on invalid
    conn = get_db()
    agent_id = str(uuid.uuid4())

    existing = conn.execute(
        "SELECT id FROM agents WHERE name=?", (name,)
    ).fetchone()
    if existing:
        conn.close()
        raise ValueError(f"Agent '{name}' already exists")

    conn.execute(
        """INSERT INTO agents (id, name, description, manifest)
           VALUES (?, ?, ?, ?)""",
        (agent_id, name, description, manifest_yaml)
    )
    _audit(conn, "agent_registered", agent_id=agent_id,
           detail=f"tools={list(manifest['tools'].keys())}")
    conn.commit()
    conn.close()
    return {"id": agent_id, "name": name, "manifest": manifest}


def revoke_agent(agent_id: str, actor: str = "operator") -> bool:
    from datetime import datetime, timezone
    conn = get_db()
    now = datetime.now(timezone.utc).isoformat()
    cur = conn.execute(
        "UPDATE agents SET status='revoked', revoked_at=? WHERE id=? AND status='active'",
        (now, agent_id)
    )
    if cur.rowcount:
        _audit(conn, "agent_revoked", agent_id=agent_id, actor=actor)
        conn.commit()
        conn.close()
        return True
    conn.close()
    return False


def suspend_agent(agent_id: str, actor: str = "operator") -> bool:
    conn = get_db()
    cur = conn.execute(
        "UPDATE agents SET status='suspended' WHERE id=? AND status='active'",
        (agent_id,)
    )
    if cur.rowcount:
        _audit(conn, "agent_suspended", agent_id=agent_id, actor=actor)
        conn.commit()
        conn.close()
        return True
    conn.close()
    return False


def resume_agent(agent_id: str, actor: str = "operator") -> bool:
    conn = get_db()
    cur = conn.execute(
        "UPDATE agents SET status='active' WHERE id=? AND status='suspended'",
        (agent_id,)
    )
    if cur.rowcount:
        _audit(conn, "agent_resumed", agent_id=agent_id, actor=actor)
        conn.commit()
        conn.close()
        return True
    conn.close()
    return False


def list_agents() -> list[dict]:
    conn = get_db()
    rows = conn.execute(
        "SELECT id, name, description, status, created_at, revoked_at FROM agents ORDER BY created_at DESC"
    ).fetchall()
    conn.close()
    return [dict_from_row(r) for r in rows]


def get_agent(agent_id: str) -> dict | None:
    conn = get_db()
    row = conn.execute("SELECT * FROM agents WHERE id=?", (agent_id,)).fetchone()
    conn.close()
    return dict_from_row(row)


def _audit(conn, event_type, agent_id=None, actor=None, detail=None):
    conn.execute(
        "INSERT INTO audit_log (id, event_type, agent_id, actor, detail) VALUES (?, ?, ?, ?, ?)",
        (str(uuid.uuid4()), event_type, agent_id, actor, detail)
    )
