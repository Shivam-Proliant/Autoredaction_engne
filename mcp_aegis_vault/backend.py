"""Local Aegis API and MCP service. Binds to loopback through run_demo.ps1."""
from __future__ import annotations

import json
import os
import secrets
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, Field

from crypto_enclave import Vault

ROOT = Path(__file__).resolve().parent
DB_PATH = Path(os.environ.get("AEGIS_DB_PATH", ROOT / "aegis_vault.sqlite3"))
MCP_HOST = "127.0.0.1"
MCP_PORT = 8000
vault: Vault | None = None
session_token: str | None = None

mcp_server = FastMCP(
    "Aegis Action Gateway",
    instructions="Aegis applies human approval and transaction policy before agent actions. This local demo uses fake credentials and a no-network simulator.",
    host=MCP_HOST,
    port=MCP_PORT,
    stateless_http=True,
)


def _active_vault() -> Vault | None:
    return vault


@mcp_server.tool(name="mcp_vault_list_handles")
def mcp_vault_list_handles() -> dict[str, Any]:
    """List credential metadata. Secret values are never returned."""
    current = _active_vault()
    if current is None:
        return {"status": "LOCKED", "credentials_metadata": [], "secrets_exposed": False}
    return {"status": "OK", "credentials_metadata": current.items(), "secrets_exposed": False}


@mcp_server.tool(name="mcp_vault_request_lease")
def mcp_vault_request_lease(cred_id: str, target_domain: str, expected_payload: dict[str, Any]) -> dict[str, Any]:
    """Request a transaction-scoped lease; high-risk requests wait for browser approval."""
    current = _active_vault()
    if current is None:
        return {"status": "LOCKED", "reason": "Unlock the local vault first."}
    return current.create_approval_request(cred_id, target_domain, expected_payload)


@mcp_server.tool(name="mcp_vault_approval_status")
def mcp_vault_approval_status(approval_request_id: str) -> dict[str, Any]:
    """Check whether a human approved a request and retrieve its short-lived lease."""
    current = _active_vault()
    if current is None:
        return {"status": "LOCKED", "reason": "Unlock the local vault first."}
    return current.approval_status(approval_request_id)


@mcp_server.tool(name="mcp_vault_blind_execute")
def mcp_vault_blind_execute(lease_token: str, target_url: str, http_method: str = "POST", request_body: dict[str, Any] | None = None) -> dict[str, Any]:
    """Run a local checkout simulation under a lease; never sends network traffic or injects a secret."""
    current = _active_vault()
    if current is None:
        return {"status": "LOCKED", "reason": "Unlock the local vault first."}
    return current.execute_mock(lease_token, target_url, http_method, request_body)


class UnlockRequest(BaseModel):
    password: str = Field(min_length=12, max_length=1024)
    confirm_password: str | None = Field(default=None, max_length=1024)


class CodeRequest(BaseModel):
    code: str = Field(min_length=6, max_length=6)


class ApprovalRequest(BaseModel):
    approval_request_id: str = Field(min_length=10, max_length=100)
    totp_code: str = Field(min_length=6, max_length=6)


@asynccontextmanager
async def lifespan(app: FastAPI):
    async with mcp_server.session_manager.run():
        yield


app = FastAPI(title="Aegis local backend", version="0.2.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:8502", "http://localhost:8502"],
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "X-Aegis-Session"],
)


def require_session(x_aegis_session: str | None = Header(default=None)) -> Vault:
    if vault is None or session_token is None or not x_aegis_session or not secrets.compare_digest(x_aegis_session, session_token):
        raise HTTPException(status_code=401, detail="Unlock Aegis in the browser first.")
    return vault


@app.get("/health")
def health():
    return {"status": "ok", "service": "aegis-local", "mcp_endpoint": "/mcp", "network_execution": False}


@app.get("/api/setup")
def setup_info():
    return {"first_use": not DB_PATH.exists()}


@app.post("/api/unlock")
def unlock(request: UnlockRequest):
    global vault, session_token
    if not DB_PATH.exists() and request.password != request.confirm_password:
        raise HTTPException(status_code=400, detail="Confirm the same master password when creating the vault.")
    try:
        if vault is not None:
            vault.conn.close()
        vault = Vault(str(DB_PATH), request.password)
    except ValueError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc
    session_token = secrets.token_urlsafe(32)
    response: dict[str, Any] = {"session_token": session_token, "totp_enrolled": vault.totp_enrolled}
    if not vault.totp_enrolled:
        response["enrollment_seed"] = vault.totp_seed
        response["enrollment_message"] = "Add this seed to an authenticator, enter its current code, then it will be hidden."
    return response


@app.post("/api/lock")
def lock_session(current: Vault = Depends(require_session)):
    global vault, session_token
    current.conn.close()
    vault = None
    session_token = None
    return {"status": "locked"}


@app.post("/api/enroll/confirm")
def confirm_enrollment(request: CodeRequest, current: Vault = Depends(require_session)):
    if not current.confirm_totp_enrollment(request.code):
        raise HTTPException(status_code=400, detail="That authenticator code is not valid. Try the current six-digit code.")
    return {"status": "enrolled"}


@app.get("/api/state")
def state(current: Vault = Depends(require_session)):
    return {"status": "unlocked", "totp_enrolled": current.totp_enrolled, "mcp_endpoint": f"http://{MCP_HOST}:{MCP_PORT}/mcp"}


@app.post("/api/demo/seed")
def seed_demo(current: Vault = Depends(require_session)):
    return {"added": current.seed_shopping_demo_credentials(), "credentials_metadata": current.items()}


@app.post("/api/approve")
def approve(request: ApprovalRequest, current: Vault = Depends(require_session)):
    result = current.approve_request(request.approval_request_id, request.totp_code)
    if result.get("status") == "STEP_UP_REQUIRED":
        raise HTTPException(status_code=400, detail=result.get("reason", "Approval was not granted."))
    if result.get("status") not in ("LEASE_GRANTED",):
        raise HTTPException(status_code=400, detail=result.get("reason", result.get("status", "Approval was not granted.")))
    return result


@app.get("/api/audit")
def audit(current: Vault = Depends(require_session)):
    return {"events": current.audit_rows()}


app.mount("/", mcp_server.streamable_http_app())
