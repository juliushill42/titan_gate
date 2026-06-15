Titan Gate — Agent Permission & Governance Engine

Titan Gate is a secure, default-deny governance and execution platform for AI agents. It acts as an enterprise-grade firewalled gateway between an AI agent and the real world, ensuring that every command, API call, or browser action the agent wants to perform is authenticated, checked against a strict permission manifest, and recorded in an immutable audit trail.
🛑 The Non-Technical Guide (Executive Summary)
What is Titan Gate?

Think of an AI agent as a highly capable, autonomous corporate assistant. If you give that assistant access to your computer, your files, and your email, they could accidentally delete a crucial database, read sensitive payroll files, or respond to a phishing email.

Titan Gate is the strict digital security guard standing over that assistant's shoulder. Before the assistant can type a single command, open a webpage, or send an email, it must show Titan Gate its written permission slip (called a Manifest). If the action isn't explicitly approved on that slip, Titan Gate instantly blocks it.
Why do businesses need it?

    Preventing "Rogue AI" Actions: AI models can sometimes misunderstand instructions (hallucinate) or behave unpredictably. Titan Gate enforces strict boundaries so an AI can never do more than it was hired to do.

    Total Black-Box Accountability: Every single thing the AI attempts to do—whether successful, failed, or blocked—is written down forever in an un-erasable Audit Log. You will always know exactly why and when an AI took an action.

    Secret Protection (The Vault): When an AI needs to log into a system (like your corporate email or a database), it is never given the actual password. Titan Gate safely keeps passwords hidden in a digital vault and logs the AI into systems behind the scenes. The AI never sees or handles raw secrets.

Key Capabilities in Plain English

    💻 Shell (Computer Commands): Limits the AI to only reading safe data, preventing it from running destructive software.

    🌐 Web Browser: Allows the AI to browse the web safely, click buttons, fill out forms, and download items while keeping a record of its activities.

    📂 File Control: Restricts the AI to a specific sandbox folder so it cannot snoop around your entire hard drive.

    ✉️ Email Monitoring: Enables regulated emailing privileges while tracking every message sent or read.

🛠️ The Technical Guide (Architecture & Specs)

Titan Gate is designed as a lightweight, Service-Oriented Architecture (SOA) platform written in Python, powered by FastAPI, and backed by a write-ahead-logged (WAL) SQLite engine.
Core Components

                [ User / Frontend UI ]
                         │
                         ▼ (JWT Authentication)
                 [ FastAPI REST API ]
                         │
        ┌────────────────┼────────────────┐
        ▼                ▼                ▼
[ Permission Engine ] [ Vault System ] [ Tool Executor ]
 (YAML Manifests)     (Fernet AES-128)  (Playwright/Subprocess)
        └────────────────┼────────────────┘
                         ▼
                [ SQLite DB + WAL ]

    db.py (Database Layer): Employs SQLite with WAL (journal_mode=WAL) and foreign keys enforced. It manages tables for agents, credentials, tool calls, and append-only audit trails.

    permissions.py (Policy Gatekeeper): Validates incoming YAML manifests using a strict default-deny paradigm. If an agent's lifecycle state is not explicitly active, or if a tool/scope combination is omitted from its manifest, the action is blocked.

    vault.py (Credential Isolation): Implements symmetric encryption at rest using Fernet (AES-128-CBC + HMAC-SHA256 authentication). It resolves runtime API/Email tokens via a scoped credential injection workflow, ensuring plain-text keys are never exposed to the LLM agent context.

    executor.py (Secure Runtime Environments): Executes the actual code for shell, web, API, or file manipulation.

    api.py (REST API Gateway): Exposes management, monitoring, and execution routes over HTTP/WebSockets with standard JWT role-based claims (admin vs operator).

📊 Tool & Scope Capability Matrix

Every interaction must resolve to a specific tool and a specific scope. If it is not in this matrix, it does not exist to Titan Gate.
Tool	Scope	Technical Enforcement Mechanics
shell	read	Restricted to a safe prefix whitelist (cat, ls, grep, pwd, etc.).
	write, execute	Raw asyncio.create_subprocess_shell bounded by a maximum 5-minute timeout.
browser	Maps, screenshot	Spawns headless Chromium instances via Playwright.
	click, type, download	Interacts with selectors; automatically outputs full-page tracing screenshots.
api	get, post, put, delete, patch	Asynchronous network requests managed via httpx.AsyncClient with custom header/credential injection.
file	read, write, delete, list	Enforces path sandboxing via Path.resolve(). Blocks attempts to cross out of the defined root path.
email	send, read, delete	Enforces SMTP_SSL for delivery and IMAP_SSL for processing text/multipart contents.
📄 Manifest Specification

Agents must be registered with a YAML configuration file detailing their required scope allocations.
Example Manifest (agent_manifest.yaml)
YAML

description: "Customer support data processing agent"
tools:
  file:
    - "read"
    - "list"
  api:
    - "get"
    - "post"
  browser:
    - "navigate"
    - "screenshot"

Note: If this agent attempts to execute a shell command, or attempts a file:delete action, Titan Gate rejects it at the permission layers without hitting the runtime executor.
🚀 Technical Quickstart
Prerequisites

    Python 3.10+

    SQLite3

1. Installation & Environment Setup

Clone the codebase into your environment, then install dependencies:
Bash

pip install fastapi uvicorn PyYAML PyJWT passlib cryptography httpx aiofiles

# Optional: Needed if using the browser web-automation suite
pip install playwright && playwright install chromium

2. Run the Application Server

Spin up the FastAPI server using Uvicorn. The database will automatically initialize itself on startup.
Bash

# Sets custom paths (Optional, defaults to ~/.titan-gate/)
export TITAN_DB="./titan.db"
export TITAN_JWT_SECRET="super-secure-dev-token-string-here"

uvicorn api:app --host 0.0.0.0 --port 8000

3. Initialize the Bootstrap Admin Account

Because the platform follows a zero-trust model, your first order of business is to set up an administrative operator via the initialization route. This endpoint accepts requests only if the user database is entirely empty.
Bash

curl -X POST http://localhost:8000/setup/init \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "YourSecurePasswordHere"}'

This returns your initialization JWT bearer token. Append this token to the Authorization: Bearer <token> header for all subsequent API communications.
4. Register an Agent and Execute a Tool

Submit the YAML manifest via the API to spawn an active tracking ID:
Bash

curl -X POST http://localhost:8000/agents \
  -H "Authorization: Bearer <YOUR_JWT_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "explorer_agent",
    "description": "Read-only file explorer",
    "manifest": "tools:\n  file:\n    - \"read\"\n    - \"list\""
  }'

To execute a scoped tool run, pass the target agent_id inside the command request payload:
Bash

curl -X POST http://localhost:8000/agents/<AGENT_UUID_HERE>/execute \
  -H "Authorization: Bearer <YOUR_JWT_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{
    "tool": "file",
    "scope": "list",
    "args": {"path": "."}
  }'

🔒 Security Operations Reference

    Audit Verification Engine: The endpoint /audit exposes all low-level system shifts, token lifecycle registrations, and security failures.

    Active Isolation Switch: Operators can immediately trigger an agent suspension or a total privilege revocation via POST /agents/{agent_id}/suspend and POST /agents/{agent_id}/revoke. This forces immediate 400 / 401 errors on any ongoing or queued asynchronous tool chains associated with that agent.

    The Replay Engine: A distinct security capability of Titan Gate is the /calls/{call_id}/replay endpoint. If an anomalous execution occurs, developers can trigger a dry_run=True replay simulation to isolate, inspect, and evaluate the specific environment variables and argument trees present at the moment of execution.
