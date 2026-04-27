"""Outbound state-change webhooks to the FlameBot backend.

Mirrors the verifier in flame-backend/vps_routes.py:_verify_webhook_signature.
"""
from __future__ import annotations

import json
import logging
import threading
import urllib.error
import urllib.request
from typing import Any, Dict, Optional

from .security import sign_webhook_payload
from .settings import SETTINGS

_LOGGER = logging.getLogger("flame_vps.webhook")


def _post(raw_body: bytes) -> tuple[bool, Optional[str]]:
    url = SETTINGS.backend_webhook_url
    if not url:
        return True, None  # webhook disabled in dev — no-op success
    sig = sign_webhook_payload(raw_body)
    if not sig:
        return False, "webhook secret not configured"
    req = urllib.request.Request(
        url=url,
        data=raw_body,
        headers={"Content-Type": "application/json", "x-flame-vps-sig": sig},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=float(SETTINGS.webhook_timeout_sec)) as resp:  # nosec B310
            resp.read()
        return True, None
    except urllib.error.HTTPError as exc:
        return False, f"HTTP {exc.code}"
    except Exception as exc:
        return False, str(exc)


def push_status(
    *,
    terminal_id: str,
    status: Optional[str] = None,
    event_type: str = "status_changed",
    message: str = "",
    severity: str = "info",
    heartbeat: bool = False,
    ea_attached: Optional[bool] = None,
    meta: Optional[Dict[str, Any]] = None,
) -> None:
    """Fire-and-forget signed POST to the backend webhook."""
    payload: Dict[str, Any] = {
        "terminal_id": terminal_id,
        "event_type": event_type,
        "severity": severity,
        "message": message,
    }
    if status is not None:
        payload["status"] = status
    if heartbeat:
        payload["heartbeat"] = True
    if ea_attached is not None:
        payload["ea_attached"] = bool(ea_attached)
    if meta:
        payload["meta"] = meta

    raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")

    def _bg() -> None:
        ok, err = _post(raw)
        if not ok:
            _LOGGER.warning("webhook push failed terminal=%s err=%s", terminal_id, err)

    threading.Thread(target=_bg, name=f"vps-webhook-{terminal_id[:8]}", daemon=True).start()
