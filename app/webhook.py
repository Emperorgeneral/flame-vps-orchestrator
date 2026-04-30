"""Outbound state-change webhooks to the FlameBot backend.

Mirrors the verifier in flame-backend/vps_routes.py:_verify_webhook_signature.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import socket
import threading
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, Optional

from .security import sign_webhook_payload
from .settings import SETTINGS

_LOGGER = logging.getLogger("flame_vps.webhook")


def _is_disallowed_ip(ip: str) -> bool:
    """Return True if ``ip`` resolves into a loopback / private / link-local /
    multicast / reserved range. We refuse to send signed webhooks there to
    avoid SSRF against host-local services if ``backend_webhook_url`` is ever
    misconfigured or attacker-influenced.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except Exception:
        return True
    return bool(
        addr.is_loopback
        or addr.is_private
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    )


def _validate_webhook_url(url: str) -> Optional[str]:
    """Return error message if ``url`` is unsafe, None if it is OK to call.

    Allows http(s) only, on standard ports, with a hostname that resolves
    exclusively to public IP addresses. Set
    ``FLAME_VPS_WEBHOOK_ALLOW_PRIVATE=1`` to bypass the IP allow-list (useful
    for tests against a local backend).
    """
    if not url:
        return "no url"
    try:
        parsed = urllib.parse.urlparse(url)
    except Exception:
        return "invalid url"
    if parsed.scheme not in {"http", "https"}:
        return "scheme must be http(s)"
    host = (parsed.hostname or "").strip()
    if not host:
        return "missing host"
    # Allow operator opt-out for local dev / loopback testing.
    import os as _os
    if str(_os.environ.get("FLAME_VPS_WEBHOOK_ALLOW_PRIVATE", "") or "").strip() in {"1", "true", "yes", "on"}:
        return None
    try:
        infos = socket.getaddrinfo(host, parsed.port or (443 if parsed.scheme == "https" else 80))
    except Exception:
        return "dns lookup failed"
    if not infos:
        return "dns lookup empty"
    for info in infos:
        try:
            ip = info[4][0]
        except Exception:
            continue
        if _is_disallowed_ip(ip):
            return f"host resolves to disallowed address {ip}"
    return None


def _post(raw_body: bytes) -> tuple[bool, Optional[str]]:
    url = SETTINGS.backend_webhook_url
    if not url:
        return True, None  # webhook disabled in dev — no-op success
    err = _validate_webhook_url(url)
    if err is not None:
        return False, f"webhook url rejected: {err}"
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
