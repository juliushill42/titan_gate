"""
Titan Gate — REST API
All endpoints require JWT auth except /health and /setup/init.
"""
import json
import os
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional

import jwt
from fastapi import FastAPI, HTTPException, Depends, Header, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse
from pydantic import BaseModel
from passlib.hash import bcrypt

from db import get_db, init_db, dict_from_row
from vault import store_credential, revoke_credential, list_credentials
from permissions import (
    parse_manifest, register_agent, revoke_agent,
    suspend_agent, resume_agent, list_agents, get_agent, BUILTIN_TOOLS
)
from executor import execute_tool, replay_call


JWT_SECRET = os.environ.get(
    "TITAN_JWT_SECRET",
    str(Path.home() / ".titan-gate" / ".jwt_secret")
)


def _get_jwt_secret() -> str:
    p = Path(JWT_SECRET)
    if p.exists() and p.stat().st_size > 10:
        return p.read_text().strip()
    secret = uuid.uuid4().hex + uuid.uuid4().hex
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(secret)
    p.chmod(0o600)
    return secret


def _make_token(user_id: str, username: str, role: str) -> str:
    payload = {
        "sub": user_id,
        "username": username,
        "role": role,
        "iat": datetime.now(timezone.utc),
        "exp": datetime.now(timezone.utc) + timedelta(hours=24),
    }
    return jwt.encode(payload, _get_jwt_secret(), algorithm="HS256")


def _verify_token(authorization: str = Header(None)) -> dict:
    if not authorization:
        raise HTTPException(401, "Missing Authorization header")
    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(401, "Invalid Authorization format")
    try:
        return jwt.decode(parts[1], _get_jwt_secret(), algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        raise HTTPException(401, "Token expired")
    except jwt.InvalidTokenError as e:
        raise HTTPException(401, f"Invalid token: {e}")


app = FastAPI(
    title="Titan Gate",
    description="SOA-governed agent permission and audit platform",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
async def startup():
    init_db()


# ── Health ─────────────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return {"status": "ok", "version": "1.0.0"}


# ── Auth ──────────────────────────────────────────────────────────────────────

class LoginRequest(BaseModel):
    username: str
    password: str


class SetupRequest(BaseModel):
    username: str
    password: str


@app.post("/setup/init")
def setup_init(req: SetupRequest):
    """Create the first admin user. Only works if no users exist."""
    conn = get_db()
    count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    if count > 0:
        conn.close()
        raise HTTPException(400, "Setup already complete. Use /auth/login.")
    user_id = str(uuid.uuid4())
    hashed = bcrypt.hash(req.password)
    conn.execute(
        "INSERT INTO users (id, username, password_hash, role) VALUES (?, ?, ?, 'admin')",
        (user_id, req.username, hashed)
    )
    conn.commit()
    conn.close()
    token = _make_token(user_id, req.username, "admin")
    return {"token": token, "username": req.username, "role": "admin"}


@app.post("/auth/login")
def login(req: LoginRequest):
    conn = get_db()
    user = conn.execute(
        "SELECT * FROM users WHERE username=?", (req.username,)
    ).fetchone()
    conn.close()
    if not user or not bcrypt.verify(req.password, user["password_hash"]):
        raise HTTPException(401, "Invalid credentials")
    token = _make_token(user["id"], user["username"], user["role"])
    return {"token": token, "username": user["username"], "role": user["role"]}


@app.get("/auth/me")
def me(claims: dict = Depends(_verify_token)):
    return {"user_id": claims["sub"], "username": claims["username"], "role": claims["role"]}


# ── Agents ────────────────────────────────────────────────────────────────────

class AgentCreate(BaseModel):
    name: str
    description: str = ""
    manifest: str


class AgentUpdate(BaseModel):
    description: Optional[str] = None
    manifest: Optional[str] = None


@app.get("/agents")
def agents_list(claims: dict = Depends(_verify_token)):
    return list_agents()


@app.post("/agents")
def agents_create(req: AgentCreate, claims: dict = Depends(_verify_token)):
    try:
        return register_agent(req.name, req.description, req.manifest)
    except ValueError as e:
        raise HTTPException(400, str(e))


@app.get("/agents/{agent_id}")
def agents_get(agent_id: str, claims: dict = Depends(_verify_token)):
    agent = get_agent(agent_id)
    if not agent:
        raise HTTPException(404, "Agent not found")
    return agent


@app.patch("/agents/{agent_id}")
def agents_update(agent_id: str, req: AgentUpdate, claims: dict = Depends(_verify_token)):
    conn = get_db()
    agent = conn.execute("SELECT * FROM agents WHERE id=?", (agent_id,)).fetchone()
    if not agent:
        conn.close()
        raise HTTPException(404, "Agent not found")
    updates = {}
    if req.description is not None:
        updates["description"] = req.description
    if req.manifest is not None:
        try:
            parse_manifest(req.manifest)
        except ValueError as e:
            conn.close()
            raise HTTPException(400, f"Invalid manifest: {e}")
        updates["manifest"] = req.manifest
    if updates:
        set_clause = ", ".join(f"{k}=?" for k in updates)
        conn.execute(
            f"UPDATE agents SET {set_clause} WHERE id=?",
            (*updates.values(), agent_id)
        )
        conn.commit()
    conn.close()
    return get_agent(agent_id)


@app.post("/agents/{agent_id}/revoke")
def agents_revoke(agent_id: str, claims: dict = Depends(_verify_token)):
    if not revoke_agent(agent_id, actor=claims["username"]):
        raise HTTPException(400, "Agent not found or already revoked")
    return {"status": "revoked"}


@app.post("/agents/{agent_id}/suspend")
def agents_suspend(agent_id: str, claims: dict = Depends(_verify_token)):
    if not suspend_agent(agent_id, actor=claims["username"]):
        raise HTTPException(400, "Agent not found or not active")
    return {"status": "suspended"}


@app.post("/agents/{agent_id}/resume")
def agents_resume(agent_id: str, claims: dict = Depends(_verify_token)):
    if not resume_agent(agent_id, actor=claims["username"]):
        raise HTTPException(400, "Agent not active or not found")
    return {"status": "active"}


# ── Permissions / Manifest ─────────────────────────────────────────────────────

@app.get("/tools")
def tools_list(claims: dict = Depends(_verify_token)):
    return BUILTIN_TOOLS


@app.post("/agents/{agent_id}/permissions/check")
def permission_check(agent_id: str, body: dict, claims: dict = Depends(_verify_token)):
    from permissions import check_permission
    tool = body.get("tool")
    scope = body.get("scope")
    if not tool or not scope:
        raise HTTPException(400, "Requires 'tool' and 'scope'")
    allowed, reason = check_permission(agent_id, tool, scope)
    return {"allowed": allowed, "reason": reason}


# ── Credentials ───────────────────────────────────────────────────────────────

class CredentialCreate(BaseModel):
    scope: str
    label: str
    secret: str
    expires_at: Optional[str] = None


@app.get("/agents/{agent_id}/credentials")
def creds_list(agent_id: str, claims: dict = Depends(_verify_token)):
    return list_credentials(agent_id)


@app.post("/agents/{agent_id}/credentials")
def creds_create(agent_id: str, req: CredentialCreate,
                 claims: dict = Depends(_verify_token)):
    agent = get_agent(agent_id)
    if not agent:
        raise HTTPException(404, "Agent not found")
    return store_credential(
        agent_id, req.scope, req.label, req.secret, req.expires_at
    )


@app.delete("/credentials/{cred_id}")
def creds_revoke(cred_id: str, claims: dict = Depends(_verify_token)):
    if not revoke_credential(cred_id, actor=claims["username"]):
        raise HTTPException(400, "Credential not found or already revoked")
    return {"status": "revoked"}


# ── Tool Execution ─────────────────────────────────────────────────────────────

class ToolCallRequest(BaseModel):
    tool: str
    scope: str
    args: dict = {}


@app.post("/agents/{agent_id}/execute")
async def agents_execute(agent_id: str, req: ToolCallRequest,
                          claims: dict = Depends(_verify_token)):
    agent = get_agent(agent_id)
    if not agent:
        raise HTTPException(404, "Agent not found")
    result = await execute_tool(agent_id, req.tool, req.scope, req.args)
    return result


# ── Tool Call History ──────────────────────────────────────────────────────────

@app.get("/agents/{agent_id}/calls")
def calls_list(agent_id: str, limit: int = 50, offset: int = 0,
               status: Optional[str] = None,
               claims: dict = Depends(_verify_token)):
    conn = get_db()
    query = "SELECT * FROM tool_calls WHERE agent_id=?"
    params = [agent_id]
    if status:
        query += " AND status=?"
        params.append(status)
    query += " ORDER BY started_at DESC LIMIT ? OFFSET ?"
    params += [limit, offset]
    rows = conn.execute(query, params).fetchall()
    conn.close()
    return [dict_from_row(r) for r in rows]


@app.get("/calls")
def calls_all(limit: int = 100, offset: int = 0,
              status: Optional[str] = None,
              claims: dict = Depends(_verify_token)):
    conn = get_db()
    query = "SELECT * FROM tool_calls"
    params = []
    if status:
        query += " WHERE status=?"
        params.append(status)
    query += " ORDER BY started_at DESC LIMIT ? OFFSET ?"
    params += [limit, offset]
    rows = conn.execute(query, params).fetchall()
    conn.close()
    return [dict_from_row(r) for r in rows]


@app.get("/calls/{call_id}")
def calls_get(call_id: str, claims: dict = Depends(_verify_token)):
    conn = get_db()
    row = conn.execute("SELECT * FROM tool_calls WHERE id=?", (call_id,)).fetchone()
    conn.close()
    if not row:
        raise HTTPException(404, "Call not found")
    return dict_from_row(row)


@app.post("/calls/{call_id}/replay")
async def calls_replay(call_id: str, body: dict = {},
                        claims: dict = Depends(_verify_token)):
    dry_run = body.get("dry_run", False)
    result = await replay_call(call_id, dry_run=dry_run)
    if "error" in result and result.get("error", "").startswith("Call"):
        raise HTTPException(404, result["error"])
    return result


# ── Audit Log ─────────────────────────────────────────────────────────────────

@app.get("/audit")
def audit_list(limit: int = 200, offset: int = 0,
               agent_id: Optional[str] = None,
               event_type: Optional[str] = None,
               claims: dict = Depends(_verify_token)):
    conn = get_db()
    query = "SELECT * FROM audit_log WHERE 1=1"
    params = []
    if agent_id:
        query += " AND agent_id=?"
        params.append(agent_id)
    if event_type:
        query += " AND event_type=?"
        params.append(event_type)
    query += " ORDER BY ts DESC LIMIT ? OFFSET ?"
    params += [limit, offset]
    rows = conn.execute(query, params).fetchall()
    conn.close()
    return [dict_from_row(r) for r in rows]


# ── Stats / Dashboard data ─────────────────────────────────────────────────────

@app.get("/stats")
def stats(claims: dict = Depends(_verify_token)):
    conn = get_db()
    total_agents = conn.execute("SELECT COUNT(*) FROM agents").fetchone()[0]
    active_agents = conn.execute("SELECT COUNT(*) FROM agents WHERE status='active'").fetchone()[0]
    total_calls = conn.execute("SELECT COUNT(*) FROM tool_calls").fetchone()[0]
    success_calls = conn.execute("SELECT COUNT(*) FROM tool_calls WHERE status='success'").fetchone()[0]
    error_calls = conn.execute("SELECT COUNT(*) FROM tool_calls WHERE status='error'").fetchone()[0]
    denied_calls = conn.execute("SELECT COUNT(*) FROM tool_calls WHERE status='denied'").fetchone()[0]
    total_creds = conn.execute("SELECT COUNT(*) FROM credentials WHERE revoked=0").fetchone()[0]
    audit_events = conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
    recent_calls = conn.execute(
        "SELECT tool, status, started_at FROM tool_calls ORDER BY started_at DESC LIMIT 10"
    ).fetchall()
    conn.close()
    return {
        "agents": {"total": total_agents, "active": active_agents},
        "calls": {"total": total_calls, "success": success_calls,
                  "error": error_calls, "denied": denied_calls},
        "credentials": {"active": total_creds},
        "audit_events": audit_events,
        "recent_calls": [dict_from_row(r) for r in recent_calls],
    }


# ── WebSocket live feed ────────────────────────────────────────────────────────

active_ws: list[WebSocket] = []


@app.websocket("/ws/live")
async def websocket_live(ws: WebSocket):
    await ws.accept()
    active_ws.append(ws)
    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        active_ws.remove(ws)


async def broadcast(event: dict):
    dead = []
    for ws in active_ws:
        try:
            await ws.send_json(event)
        except Exception:
            dead.append(ws)
    for ws in dead:
        active_ws.remove(ws)


# ── Serve dashboard UI ────────────────────────────────────────────────────────

UI_DIR = Path(__file__).parent / "ui"

if UI_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(UI_DIR / "static")), name="static")

    @app.get("/", response_class=HTMLResponse)
    def dashboard():
        index = UI_DIR / "index.html"
        return index.read_text()
