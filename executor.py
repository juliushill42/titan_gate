"""
Titan Gate — Tool Executor
Executes shell commands, browser actions, and API calls.
Every call is logged before execution (intent log) and after (result log).
Credentials are injected at runtime — agents never see raw secrets.
"""
import asyncio
import json
import os
import uuid
import subprocess
import aiofiles
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx

from db import get_db, dict_from_row
from permissions import check_permission
from vault import inject_credential


# Playwright is optional — installed separately
try:
    from playwright.async_api import async_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False


def _now():
    return datetime.now(timezone.utc).isoformat()


def _log_call(conn, call_id, agent_id, tool, scope, args):
    conn.execute(
        """INSERT INTO tool_calls (id, agent_id, tool, args, status, started_at)
           VALUES (?, ?, ?, ?, 'running', ?)""",
        (call_id, agent_id, f"{tool}:{scope}", json.dumps(args), _now())
    )
    conn.execute(
        """INSERT INTO audit_log (id, event_type, agent_id, tool_call_id, detail, ts)
           VALUES (?, 'tool_call_started', ?, ?, ?, ?)""",
        (str(uuid.uuid4()), agent_id, call_id, f"{tool}:{scope} args={json.dumps(args)[:200]}", _now())
    )
    conn.commit()


def _complete_call(conn, call_id, agent_id, result=None, error=None):
    status = "success" if error is None else "error"
    conn.execute(
        """UPDATE tool_calls SET status=?, result=?, error=?, completed_at=?
           WHERE id=?""",
        (status, json.dumps(result) if result is not None else None,
         error, _now(), call_id)
    )
    conn.execute(
        """INSERT INTO audit_log (id, event_type, agent_id, tool_call_id, detail, ts)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (str(uuid.uuid4()),
         "tool_call_success" if error is None else "tool_call_error",
         agent_id, call_id,
         f"result_len={len(str(result or ''))} error={error or 'none'}", _now())
    )
    conn.commit()


async def execute_tool(agent_id: str, tool: str, scope: str,
                       args: dict, replay_of: str = None) -> dict:
    """
    Main entry point. Returns:
      {"call_id": str, "status": "success"|"error", "result": any, "error": str|None}
    """
    allowed, reason = check_permission(agent_id, tool, scope)
    if not allowed:
        return {
            "call_id": None,
            "status": "denied",
            "result": None,
            "error": f"DENIED: {reason}"
        }

    call_id = str(uuid.uuid4())
    conn = get_db()
    _log_call(conn, call_id, agent_id, tool, scope, args)

    if replay_of:
        conn.execute(
            "UPDATE tool_calls SET replay_of=? WHERE id=?",
            (replay_of, call_id)
        )
        conn.commit()
    conn.close()

    try:
        if tool == "shell":
            result = await _exec_shell(agent_id, scope, args)
        elif tool == "browser":
            result = await _exec_browser(agent_id, scope, args)
        elif tool == "api":
            result = await _exec_api(agent_id, scope, args)
        elif tool == "file":
            result = await _exec_file(agent_id, scope, args)
        elif tool == "email":
            result = await _exec_email(agent_id, scope, args)
        else:
            raise ValueError(f"Executor not implemented for tool: {tool}")

        conn = get_db()
        _complete_call(conn, call_id, agent_id, result=result)
        conn.close()
        return {"call_id": call_id, "status": "success", "result": result, "error": None}

    except Exception as e:
        conn = get_db()
        _complete_call(conn, call_id, agent_id, error=str(e))
        conn.close()
        return {"call_id": call_id, "status": "error", "result": None, "error": str(e)}


# ── Shell ─────────────────────────────────────────────────────────────────────

async def _exec_shell(agent_id: str, scope: str, args: dict) -> dict:
    cmd = args.get("command")
    if not cmd:
        raise ValueError("shell requires 'command' arg")

    cwd = args.get("cwd", str(Path.home()))
    timeout = min(int(args.get("timeout", 30)), 300)  # cap at 5 min

    # Scope enforcement
    if scope == "read":
        # Only allow read-type commands
        safe_prefixes = ("cat ", "ls ", "find ", "grep ", "head ", "tail ",
                         "wc ", "file ", "stat ", "echo ", "pwd", "whoami",
                         "du ", "df ", "env", "printenv")
        if not any(cmd.lstrip().startswith(p) for p in safe_prefixes):
            raise PermissionError(
                f"shell:read scope only allows read commands. Got: {cmd}"
            )

    proc = await asyncio.create_subprocess_shell(
        cmd, stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE, cwd=cwd
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        raise TimeoutError(f"Command timed out after {timeout}s")

    return {
        "returncode": proc.returncode,
        "stdout": stdout.decode(errors="replace")[:50000],
        "stderr": stderr.decode(errors="replace")[:10000],
    }


# ── Browser ───────────────────────────────────────────────────────────────────

async def _exec_browser(agent_id: str, scope: str, args: dict) -> dict:
    if not PLAYWRIGHT_AVAILABLE:
        raise RuntimeError(
            "Browser tool requires Playwright. Run: pip install playwright && playwright install chromium"
        )

    url = args.get("url")
    selector = args.get("selector")
    text = args.get("text")
    screenshot_path = args.get("screenshot_path",
                                str(Path.home() / ".titan-gate" / "screenshots" /
                                    f"{uuid.uuid4()}.png"))

    Path(screenshot_path).parent.mkdir(parents=True, exist_ok=True)

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()

        if scope == "navigate":
            if not url:
                raise ValueError("browser:navigate requires 'url'")
            await page.goto(url, wait_until="networkidle", timeout=30000)
            title = await page.title()
            content = await page.content()
            await browser.close()
            return {"url": url, "title": title, "content_len": len(content), "content": content[:10000]}

        elif scope == "screenshot":
            if not url:
                raise ValueError("browser:screenshot requires 'url'")
            await page.goto(url, wait_until="networkidle", timeout=30000)
            await page.screenshot(path=screenshot_path, full_page=True)
            await browser.close()
            return {"screenshot_path": screenshot_path}

        elif scope == "click":
            if not url or not selector:
                raise ValueError("browser:click requires 'url' and 'selector'")
            await page.goto(url, wait_until="networkidle", timeout=30000)
            await page.click(selector)
            await page.screenshot(path=screenshot_path)
            await browser.close()
            return {"clicked": selector, "screenshot_path": screenshot_path}

        elif scope == "type":
            if not url or not selector or text is None:
                raise ValueError("browser:type requires 'url', 'selector', 'text'")
            await page.goto(url, wait_until="networkidle", timeout=30000)
            await page.fill(selector, text)
            await page.screenshot(path=screenshot_path)
            await browser.close()
            return {"typed": text, "selector": selector, "screenshot_path": screenshot_path}

        elif scope == "download":
            if not url:
                raise ValueError("browser:download requires 'url'")
            download_path = args.get("download_path",
                                      str(Path.home() / ".titan-gate" / "downloads"))
            Path(download_path).mkdir(parents=True, exist_ok=True)
            async with page.expect_download() as dl_info:
                await page.goto(url)
            dl = await dl_info.value
            save_path = str(Path(download_path) / dl.suggested_filename)
            await dl.save_as(save_path)
            await browser.close()
            return {"downloaded_to": save_path}

        await browser.close()
        raise ValueError(f"Unknown browser scope: {scope}")


# ── API ───────────────────────────────────────────────────────────────────────

async def _exec_api(agent_id: str, scope: str, args: dict) -> dict:
    url = args.get("url")
    if not url:
        raise ValueError("api tool requires 'url'")

    headers = dict(args.get("headers", {}))
    payload = args.get("body")
    params = args.get("params")
    credential_scope = args.get("credential_scope")
    timeout = min(int(args.get("timeout", 30)), 120)

    # Inject credential if agent has one for this scope
    if credential_scope:
        secret = inject_credential(agent_id, credential_scope)
        if secret:
            auth_header = args.get("auth_header", "Authorization")
            auth_prefix = args.get("auth_prefix", "Bearer")
            headers[auth_header] = f"{auth_prefix} {secret}"

    async with httpx.AsyncClient(timeout=timeout) as client:
        method = scope.upper()
        response = await client.request(
            method, url, headers=headers,
            json=payload if isinstance(payload, dict) else None,
            content=payload if isinstance(payload, str) else None,
            params=params
        )

    try:
        body = response.json()
    except Exception:
        body = response.text[:50000]

    return {
        "status_code": response.status_code,
        "headers": dict(response.headers),
        "body": body,
    }


# ── File ──────────────────────────────────────────────────────────────────────

async def _exec_file(agent_id: str, scope: str, args: dict) -> dict:
    path = args.get("path")
    if not path:
        raise ValueError("file tool requires 'path'")

    # Sandbox to home by default
    allowed_root = args.get("allowed_root", str(Path.home()))
    resolved = str(Path(path).resolve())
    if not resolved.startswith(str(Path(allowed_root).resolve())):
        raise PermissionError(f"Path '{path}' is outside allowed root '{allowed_root}'")

    if scope == "read":
        async with aiofiles.open(resolved, "r", errors="replace") as f:
            content = await f.read()
        return {"path": resolved, "content": content[:100000], "size": len(content)}

    elif scope == "write":
        content = args.get("content", "")
        mode = "a" if args.get("append") else "w"
        async with aiofiles.open(resolved, mode) as f:
            await f.write(content)
        return {"path": resolved, "written": len(content), "mode": mode}

    elif scope == "delete":
        os.remove(resolved)
        return {"deleted": resolved}

    elif scope == "list":
        p = Path(resolved)
        if not p.is_dir():
            raise ValueError(f"'{resolved}' is not a directory")
        entries = []
        for item in sorted(p.iterdir()):
            entries.append({
                "name": item.name,
                "type": "dir" if item.is_dir() else "file",
                "size": item.stat().st_size if item.is_file() else None,
            })
        return {"path": resolved, "entries": entries}

    raise ValueError(f"Unknown file scope: {scope}")


# ── Email (SMTP) ──────────────────────────────────────────────────────────────

async def _exec_email(agent_id: str, scope: str, args: dict) -> dict:
    """
    Requires credential stored with scope 'email_smtp'.
    Credential format: "host:port:username:password"
    """
    import smtplib
    import imaplib
    from email.mime.text import MIMEText
    from email.mime.multipart import MIMEMultipart

    smtp_cred = inject_credential(agent_id, "email_smtp")
    if not smtp_cred:
        raise PermissionError("No email_smtp credential found for this agent")

    parts = smtp_cred.split(":", 3)
    if len(parts) != 4:
        raise ValueError("email_smtp credential format: host:port:username:password")
    host, port, username, password = parts
    port = int(port)

    if scope == "send":
        to_addr = args.get("to")
        subject = args.get("subject", "(no subject)")
        body = args.get("body", "")
        if not to_addr:
            raise ValueError("email:send requires 'to'")

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = username
        msg["To"] = to_addr
        msg.attach(MIMEText(body, "plain"))

        with smtplib.SMTP_SSL(host, port) as server:
            server.login(username, password)
            server.sendmail(username, [to_addr], msg.as_string())

        return {"sent_to": to_addr, "subject": subject}

    elif scope == "read":
        imap_cred = inject_credential(agent_id, "email_imap")
        if not imap_cred:
            raise PermissionError("No email_imap credential for read scope")
        iparts = imap_cred.split(":", 3)
        ihost, iport, iuser, ipass = iparts
        limit = int(args.get("limit", 10))

        mail = imaplib.IMAP4_SSL(ihost, int(iport))
        mail.login(iuser, ipass)
        mail.select("inbox")
        _, data = mail.search(None, "ALL")
        ids = data[0].split()[-limit:]
        messages = []
        for eid in ids:
            _, msg_data = mail.fetch(eid, "(RFC822)")
            import email as email_lib
            msg = email_lib.message_from_bytes(msg_data[0][1])
            messages.append({
                "id": eid.decode(),
                "from": msg.get("From"),
                "subject": msg.get("Subject"),
                "date": msg.get("Date"),
            })
        mail.logout()
        return {"messages": messages}

    raise ValueError(f"Unknown email scope: {scope}")


# ── Replay ────────────────────────────────────────────────────────────────────

async def replay_call(call_id: str, dry_run: bool = False) -> dict:
    """Re-execute a logged tool call by its ID."""
    conn = get_db()
    row = conn.execute(
        "SELECT * FROM tool_calls WHERE id=?", (call_id,)
    ).fetchone()
    conn.close()

    if not row:
        return {"error": f"Call {call_id} not found"}

    call = dict_from_row(row)
    tool_parts = call["tool"].split(":", 1)
    tool = tool_parts[0]
    scope = tool_parts[1] if len(tool_parts) > 1 else ""
    args = json.loads(call["args"])

    if dry_run:
        return {
            "dry_run": True,
            "call_id": call_id,
            "agent_id": call["agent_id"],
            "tool": tool,
            "scope": scope,
            "args": args,
            "original_status": call["status"],
            "original_result": call.get("result"),
        }

    return await execute_tool(
        call["agent_id"], tool, scope, args, replay_of=call_id
    )
