"""libsodium sealed-box decryption for broker credentials.

Design:
* The orchestrator owns a Curve25519 keypair. The public key is fetched by the
  desktop client (via the backend) and used to seal `{server, login, password}`
  with `nacl.public.SealedBox`. Only the orchestrator can decrypt — the
  backend stores the ciphertext as opaque bytes.
* If `FLAME_VPS_SEALEDBOX_PRIVKEY_B64` is configured we use it. Otherwise we
  load (or generate) a keypair file next to the SQLite state DB. This makes
  the dev experience zero-config while still letting prod inject a key from a
  secrets manager.
"""
from __future__ import annotations

import base64
import json
import logging
import os
import threading
from typing import Optional

from .settings import SETTINGS

_LOGGER = logging.getLogger("flame_vps.crypto")
_LOCK = threading.Lock()
_PRIVATE_KEY = None  # nacl.public.PrivateKey | None
_PUBLIC_KEY_B64: str = ""

try:  # PyNaCl is in requirements.txt; tolerate absence in dev environments.
    from nacl.public import PrivateKey, SealedBox  # type: ignore
    _NACL_AVAILABLE = True
except Exception:  # pragma: no cover
    PrivateKey = None  # type: ignore
    SealedBox = None  # type: ignore
    _NACL_AVAILABLE = False


def _keyfile_path() -> str:
    base = os.path.dirname(os.path.abspath(SETTINGS.state_db_path)) or "."
    return os.path.join(base, "flame_vps_sealedbox.key")


def _load_or_generate() -> None:
    global _PRIVATE_KEY, _PUBLIC_KEY_B64
    if not _NACL_AVAILABLE:
        _LOGGER.warning("PyNaCl not installed — sealed-box decryption disabled")
        return

    env_key = (SETTINGS.sealed_box_private_key_b64 or "").strip()
    if env_key:
        try:
            raw = base64.b64decode(env_key, validate=True)
            _PRIVATE_KEY = PrivateKey(raw)
            _PUBLIC_KEY_B64 = base64.b64encode(bytes(_PRIVATE_KEY.public_key)).decode("ascii")
            _LOGGER.info("Loaded sealed-box keypair from FLAME_VPS_SEALEDBOX_PRIVKEY_B64")
            return
        except Exception as exc:
            _LOGGER.error("FLAME_VPS_SEALEDBOX_PRIVKEY_B64 invalid (%s); falling back to keyfile", exc)

    path = _keyfile_path()
    try:
        if os.path.isfile(path):
            with open(path, "rb") as fh:
                raw = base64.b64decode(fh.read().strip(), validate=True)
            _PRIVATE_KEY = PrivateKey(raw)
        else:
            _PRIVATE_KEY = PrivateKey.generate()
            os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
            with open(path, "wb") as fh:
                fh.write(base64.b64encode(bytes(_PRIVATE_KEY.encode())))
            try:  # restrict perms (best-effort on Windows)
                os.chmod(path, 0o600)
            except Exception:
                pass
            _LOGGER.warning("Generated new sealed-box keypair at %s — paste public key into backend env FLAMEBOT_VPS_PUBKEY_B64", path)
        _PUBLIC_KEY_B64 = base64.b64encode(bytes(_PRIVATE_KEY.public_key)).decode("ascii")
    except Exception:
        _LOGGER.exception("Failed to initialize sealed-box keypair")
        _PRIVATE_KEY = None
        _PUBLIC_KEY_B64 = ""


def init() -> None:
    with _LOCK:
        if _PRIVATE_KEY is None:
            _load_or_generate()
            if _PUBLIC_KEY_B64:
                _LOGGER.info("flame-vps sealed-box public key (base64): %s", _PUBLIC_KEY_B64)


def public_key_b64() -> str:
    init()
    return _PUBLIC_KEY_B64


def decrypt_broker_payload(sealed: bytes) -> Optional[dict]:
    """Decrypt a sealed-box payload back into a dict {server, login, password}.

    Returns None if PyNaCl isn't available, the keypair isn't initialized, or
    decryption fails. Callers must not log the returned plaintext.
    """
    init()
    if not _NACL_AVAILABLE or _PRIVATE_KEY is None:
        return None
    try:
        box = SealedBox(_PRIVATE_KEY)
        plaintext = box.decrypt(sealed)
        obj = json.loads(plaintext.decode("utf-8"))
        if not isinstance(obj, dict):
            return None
        return obj
    except Exception:
        _LOGGER.warning("sealed-box decrypt failed (terminal credentials rejected)")
        return None
