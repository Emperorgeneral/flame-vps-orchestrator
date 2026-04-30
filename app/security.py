"""HMAC-SHA512 signing and verification.

Inbound RPCs from the backend are signed exactly the way
``vps_routes._orchestrator_call`` produces them:
    signature = HMAC-SHA512(secret, f"{ts}.{nonce}.".encode() + raw_body)
Headers: X-Flame-Timestamp, X-Flame-Nonce, X-Flame-Signature.

Outbound webhooks back to the backend mirror the existing NowPayments-style
verifier: HMAC-SHA512 over the raw body, header ``x-flame-vps-sig``.
"""
from __future__ import annotations

import hmac
import hashlib
import os
import re
import threading
import time
from collections import OrderedDict
from typing import Optional

from .settings import SETTINGS


class InvalidSignature(Exception):
    pass


class InvalidTerminalId(Exception):
    """Raised when a terminal_id contains unsafe characters."""


# ---------------------------------------------------------------------------
# Nonce replay protection
# ---------------------------------------------------------------------------
# Within the configured ``rpc_max_skew_sec`` window an attacker who captures
# a signed request can otherwise replay it verbatim. We track every nonce we
# accept for slightly longer than the skew window and reject duplicates.
_NONCE_LOCK = threading.Lock()
_NONCE_SEEN: "OrderedDict[str, float]" = OrderedDict()
_NONCE_MAX_ENTRIES = 50_000


def _nonce_remember(nonce: str, ttl_sec: float) -> bool:
    """Record ``nonce`` and return True if it is fresh, False if it was a replay."""
    if not nonce:
        return False
    now = time.time()
    expires = now + max(60.0, float(ttl_sec))
    with _NONCE_LOCK:
        # Drop expired entries.
        while _NONCE_SEEN:
            k, exp = next(iter(_NONCE_SEEN.items()))
            if exp <= now:
                _NONCE_SEEN.popitem(last=False)
            else:
                break
        if nonce in _NONCE_SEEN:
            return False
        _NONCE_SEEN[nonce] = expires
        # Bound memory: drop oldest if we somehow exceed the cap.
        while len(_NONCE_SEEN) > _NONCE_MAX_ENTRIES:
            _NONCE_SEEN.popitem(last=False)
    return True


def verify_backend_rpc_signature(
    *,
    raw_body: bytes,
    timestamp: str,
    nonce: str,
    provided_signature: str,
    secret: Optional[str] = None,
    max_skew_sec: Optional[int] = None,
) -> None:
    """Raise InvalidSignature if the inbound RPC signature is wrong/expired."""
    used_secret = (secret if secret is not None else SETTINGS.backend_rpc_secret) or ""
    if not used_secret:
        raise InvalidSignature("orchestrator secret not configured")
    if not timestamp or not nonce or not provided_signature:
        raise InvalidSignature("missing signature headers")

    try:
        ts_int = int(timestamp)
    except Exception as exc:
        raise InvalidSignature("invalid timestamp") from exc
    skew = max_skew_sec if max_skew_sec is not None else SETTINGS.rpc_max_skew_sec
    if abs(int(time.time()) - ts_int) > int(skew):
        raise InvalidSignature("timestamp out of allowed skew")

    # Bound nonce length so an attacker can't pump junk into the seen-set.
    if len(nonce) > 128 or not re.fullmatch(r"[A-Za-z0-9_\-]{8,128}", nonce or ""):
        raise InvalidSignature("invalid nonce format")

    msg = f"{timestamp}.{nonce}.".encode("utf-8") + (raw_body or b"")
    expected = hmac.new(used_secret.encode("utf-8"), msg, hashlib.sha512).hexdigest()
    if not hmac.compare_digest(expected.lower(), provided_signature.strip().lower()):
        raise InvalidSignature("signature mismatch")

    # Record the nonce only after the signature is verified so unauthenticated
    # callers can't pollute the replay-protection cache.
    ttl = float(skew) * 2.0
    if not _nonce_remember(nonce, ttl):
        raise InvalidSignature("nonce replay detected")


def sign_webhook_payload(raw_body: bytes, *, secret: Optional[str] = None) -> str:
    """Produce the lowercase hex HMAC-SHA512 signature for the outbound webhook."""
    used_secret = (secret if secret is not None else SETTINGS.backend_webhook_secret) or ""
    if not used_secret:
        return ""
    return hmac.new(used_secret.encode("utf-8"), raw_body or b"", hashlib.sha512).hexdigest().lower()


# ---------------------------------------------------------------------------
# terminal_id validation + path confinement
# ---------------------------------------------------------------------------
# Every backend RPC is keyed by ``terminal_id``. We use it directly as a
# directory name under ``mt_install_root`` and as a key in log-tail state, so
# letting through ``..`` or absolute paths would let a compromised backend or
# a bug elsewhere drop files anywhere on the host. Restrict to a safe charset
# and validate any constructed path resolves under the configured root.

_TERMINAL_ID_RE = re.compile(r"^[A-Za-z0-9_\-]{1,128}$")


def is_safe_terminal_id(terminal_id: str) -> bool:
    return bool(_TERMINAL_ID_RE.fullmatch(str(terminal_id or "")))


def validate_terminal_id(terminal_id: str) -> str:
    s = str(terminal_id or "").strip()
    if not is_safe_terminal_id(s):
        raise InvalidTerminalId("terminal_id must match [A-Za-z0-9_-]{1,128}")
    return s


def safe_join_under_root(root: str, *parts: str) -> str:
    """Join ``parts`` under ``root`` and assert the result stays inside it.

    Defends against path-traversal via crafted terminal_id, log-file names,
    or any other untrusted segment.
    """
    base = os.path.realpath(os.path.abspath(str(root or "")))
    cleaned = [str(p or "") for p in parts]
    joined = os.path.realpath(os.path.abspath(os.path.join(base, *cleaned)))
    # Ensure the resolved path is the root itself or a strict descendant.
    sep = os.sep
    if joined != base and not joined.startswith(base + sep):
        raise InvalidTerminalId("path escapes configured root")
    return joined
