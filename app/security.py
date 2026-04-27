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
import time
from typing import Optional

from .settings import SETTINGS


class InvalidSignature(Exception):
    pass


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

    msg = f"{timestamp}.{nonce}.".encode("utf-8") + (raw_body or b"")
    expected = hmac.new(used_secret.encode("utf-8"), msg, hashlib.sha512).hexdigest()
    if not hmac.compare_digest(expected.lower(), provided_signature.strip().lower()):
        raise InvalidSignature("signature mismatch")


def sign_webhook_payload(raw_body: bytes, *, secret: Optional[str] = None) -> str:
    """Produce the lowercase hex HMAC-SHA512 signature for the outbound webhook."""
    used_secret = (secret if secret is not None else SETTINGS.backend_webhook_secret) or ""
    if not used_secret:
        return ""
    return hmac.new(used_secret.encode("utf-8"), raw_body or b"", hashlib.sha512).hexdigest().lower()
