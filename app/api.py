"""FastAPI application — internal RPC surface for the FlameBot backend.

All routes require an HMAC-SHA512 signature matching what
``flame-backend/vps_routes._orchestrator_call`` produces.
"""
from __future__ import annotations

import base64
import logging
from typing import Any, Dict

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse

from . import crypto, state, worker
from .security import InvalidSignature, verify_backend_rpc_signature
from .settings import SETTINGS

_LOGGER = logging.getLogger("flame_vps.api")

app = FastAPI(title="flame-vps-orchestrator", version="0.1.0")


@app.on_event("startup")
def _startup() -> None:
    state.init()
    crypto.init()
    worker.start_workers()


@app.on_event("shutdown")
def _shutdown() -> None:
    worker.stop_workers()


async def _verified_body(request: Request,
                         x_flame_timestamp: str,
                         x_flame_nonce: str,
                         x_flame_signature: str) -> Dict[str, Any]:
    raw = await request.body()
    try:
        verify_backend_rpc_signature(
            raw_body=raw,
            timestamp=x_flame_timestamp or "",
            nonce=x_flame_nonce or "",
            provided_signature=x_flame_signature or "",
        )
    except InvalidSignature as exc:
        raise HTTPException(status_code=403, detail=str(exc))
    try:
        import json
        obj = json.loads(raw.decode("utf-8") or "{}")
    except Exception:
        raise HTTPException(status_code=400, detail="invalid json")
    if not isinstance(obj, dict):
        raise HTTPException(status_code=400, detail="invalid json")
    return obj


def _capacity_guard() -> None:
    if state.count_terminals() >= int(SETTINGS.max_terminals_total):
        raise HTTPException(status_code=503, detail="orchestrator at capacity")


# ---------------------------------------------------------------------------
# RPC routes
# ---------------------------------------------------------------------------

@app.get("/health")
def health() -> JSONResponse:
    return JSONResponse({"status": "OK", "version": "0.1.0", "terminals": state.count_terminals()})


@app.get("/pubkey")
def pubkey() -> JSONResponse:
    """Return the orchestrator's libsodium sealed-box public key (base64).

    The public key is non-sensitive — exposing it lets the backend proxy it
    to clients so they can seal broker credentials. Decryption requires the
    private key, which never leaves this host.
    """
    return JSONResponse({"status": "OK", "public_key_b64": crypto.public_key_b64(), "algorithm": "libsodium_sealedbox_v1"})


@app.post("/internal/terminal/create")
async def terminal_create(
    request: Request,
    x_flame_timestamp: str = Header(default=""),
    x_flame_nonce: str = Header(default=""),
    x_flame_signature: str = Header(default=""),
) -> JSONResponse:
    body = await _verified_body(request, x_flame_timestamp, x_flame_nonce, x_flame_signature)
    terminal_id = str(body.get("terminal_id") or "").strip()
    platform = str(body.get("platform") or "").strip().lower()
    account_type = str(body.get("account_type") or "normal").strip().lower()
    owner = str(body.get("owner") or "").strip()
    if not terminal_id or platform not in {"mt4", "mt5"} or not owner:
        raise HTTPException(status_code=400, detail="bad request")
    _capacity_guard()
    state.upsert_terminal(terminal_id=terminal_id, owner=owner, platform=platform, account_type=account_type)
    state.enqueue_job(terminal_id=terminal_id, kind="provision",
                      payload={"platform": platform, "account_type": account_type})
    return JSONResponse({"status": "OK"})


@app.post("/internal/terminal/login")
async def terminal_login(
    request: Request,
    x_flame_timestamp: str = Header(default=""),
    x_flame_nonce: str = Header(default=""),
    x_flame_signature: str = Header(default=""),
) -> JSONResponse:
    body = await _verified_body(request, x_flame_timestamp, x_flame_nonce, x_flame_signature)
    terminal_id = str(body.get("terminal_id") or "").strip()
    sealed_b64 = str(body.get("sealed_payload_b64") or "").strip()
    if not terminal_id or not sealed_b64:
        raise HTTPException(status_code=400, detail="bad request")
    try:
        sealed = base64.b64decode(sealed_b64, validate=True)
    except Exception:
        raise HTTPException(status_code=400, detail="invalid sealed_payload_b64")
    state.store_sealed_credentials(terminal_id, sealed)
    state.enqueue_job(terminal_id=terminal_id, kind="broker_login")
    return JSONResponse({"status": "OK"})


@app.post("/internal/terminal/attach_ea")
async def terminal_attach_ea(
    request: Request,
    x_flame_timestamp: str = Header(default=""),
    x_flame_nonce: str = Header(default=""),
    x_flame_signature: str = Header(default=""),
) -> JSONResponse:
    body = await _verified_body(request, x_flame_timestamp, x_flame_nonce, x_flame_signature)
    terminal_id = str(body.get("terminal_id") or "").strip()
    if not terminal_id:
        raise HTTPException(status_code=400, detail="bad request")
    state.enqueue_job(terminal_id=terminal_id, kind="attach_ea", payload={
        "account_type": str(body.get("account_type") or "normal"),
        "ea_user_id": str(body.get("ea_user_id") or ""),
        "ea_license_key": str(body.get("ea_license_key") or ""),
        "reason": str(body.get("reason") or ""),
    })
    return JSONResponse({"status": "OK"})


@app.post("/internal/terminal/detach_ea")
async def terminal_detach_ea(
    request: Request,
    x_flame_timestamp: str = Header(default=""),
    x_flame_nonce: str = Header(default=""),
    x_flame_signature: str = Header(default=""),
) -> JSONResponse:
    body = await _verified_body(request, x_flame_timestamp, x_flame_nonce, x_flame_signature)
    terminal_id = str(body.get("terminal_id") or "").strip()
    if not terminal_id:
        raise HTTPException(status_code=400, detail="bad request")
    state.enqueue_job(terminal_id=terminal_id, kind="detach_ea")
    return JSONResponse({"status": "OK"})


@app.post("/internal/terminal/restart")
async def terminal_restart(
    request: Request,
    x_flame_timestamp: str = Header(default=""),
    x_flame_nonce: str = Header(default=""),
    x_flame_signature: str = Header(default=""),
) -> JSONResponse:
    body = await _verified_body(request, x_flame_timestamp, x_flame_nonce, x_flame_signature)
    terminal_id = str(body.get("terminal_id") or "").strip()
    if not terminal_id:
        raise HTTPException(status_code=400, detail="bad request")
    state.enqueue_job(terminal_id=terminal_id, kind="restart")
    return JSONResponse({"status": "OK"})


@app.post("/internal/terminal/stop")
async def terminal_stop(
    request: Request,
    x_flame_timestamp: str = Header(default=""),
    x_flame_nonce: str = Header(default=""),
    x_flame_signature: str = Header(default=""),
) -> JSONResponse:
    body = await _verified_body(request, x_flame_timestamp, x_flame_nonce, x_flame_signature)
    terminal_id = str(body.get("terminal_id") or "").strip()
    if not terminal_id:
        raise HTTPException(status_code=400, detail="bad request")
    state.enqueue_job(terminal_id=terminal_id, kind="stop")
    return JSONResponse({"status": "OK"})


@app.post("/internal/terminal/forget")
async def terminal_forget(
    request: Request,
    x_flame_timestamp: str = Header(default=""),
    x_flame_nonce: str = Header(default=""),
    x_flame_signature: str = Header(default=""),
) -> JSONResponse:
    body = await _verified_body(request, x_flame_timestamp, x_flame_nonce, x_flame_signature)
    terminal_id = str(body.get("terminal_id") or "").strip()
    if not terminal_id:
        raise HTTPException(status_code=400, detail="bad request")
    state.enqueue_job(terminal_id=terminal_id, kind="destroy")
    return JSONResponse({"status": "OK"})
