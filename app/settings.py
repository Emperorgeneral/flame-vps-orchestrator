"""Runtime configuration loaded from environment variables."""
from __future__ import annotations

import os
from dataclasses import dataclass


def _env(name: str, default: str = "") -> str:
    return str(os.environ.get(name, default) or default).strip()


def _env_int(name: str, default: int, *, min_value: int = 1, max_value: int = 1_000_000) -> int:
    raw = _env(name, str(default))
    try:
        v = int(raw)
    except Exception:
        v = default
    return max(min_value, min(max_value, v))


@dataclass(frozen=True)
class Settings:
    # HTTP server
    host: str
    port: int

    # Auth: shared secret with backend for inbound RPCs.
    backend_rpc_secret: str
    rpc_max_skew_sec: int

    # Outbound webhook auth + target.
    backend_webhook_url: str
    backend_webhook_secret: str
    webhook_timeout_sec: int

    # State store (sqlite file by default — orchestrator is a single-host service).
    state_db_path: str

    # Provisioner roots.
    mt_install_root: str          # where portable MT trees live, one per terminal
    mt4_template_path: str        # source MT4 portable tree to copy from
    mt5_template_path: str        # source MT5 portable tree to copy from
    ea_bundle_root: str           # versioned EA artifacts (.ex4/.ex5/.set/.tpl)
    wine_bin_path: str            # preferred Wine executable on Linux/macOS

    # Worker pool.
    worker_pool_size: int

    # Capacity guard.
    max_terminals_total: int

    # Sealed-box decryption key (libsodium private key, base64). Stub-friendly: empty in dev.
    sealed_box_private_key_b64: str


def load_settings() -> Settings:
    return Settings(
        host=_env("FLAME_VPS_BIND_HOST", "0.0.0.0"),
        port=_env_int("FLAME_VPS_BIND_PORT", 8090, min_value=1, max_value=65535),

        backend_rpc_secret=_env("FLAME_VPS_BACKEND_RPC_SECRET", ""),
        rpc_max_skew_sec=_env_int("FLAME_VPS_RPC_MAX_SKEW_SEC", 300, min_value=30, max_value=3600),

        backend_webhook_url=_env("FLAME_VPS_BACKEND_WEBHOOK_URL", ""),
        backend_webhook_secret=_env("FLAME_VPS_BACKEND_WEBHOOK_SECRET", ""),
        webhook_timeout_sec=_env_int("FLAME_VPS_WEBHOOK_TIMEOUT_SEC", 10, min_value=2, max_value=60),

        state_db_path=_env("FLAME_VPS_STATE_DB", "flame_vps_state.sqlite3"),

        mt_install_root=_env("FLAME_VPS_MT_INSTALL_ROOT", r"C:\flame\terminals"),
        mt4_template_path=_env("FLAME_VPS_MT4_TEMPLATE", r"C:\flame\templates\mt4"),
        mt5_template_path=_env("FLAME_VPS_MT5_TEMPLATE", r"C:\flame\templates\mt5"),
        ea_bundle_root=_env("FLAME_VPS_EA_BUNDLE_ROOT", r"C:\flame\ea_bundles"),
        wine_bin_path=_env("FLAME_VPS_WINE_BIN", "/opt/wine-stable/bin/wine"),

        worker_pool_size=_env_int("FLAME_VPS_WORKER_POOL", 8, min_value=1, max_value=128),

        max_terminals_total=_env_int("FLAME_VPS_MAX_TERMINALS_TOTAL", 50, min_value=1, max_value=2000),

        sealed_box_private_key_b64=_env("FLAME_VPS_SEALEDBOX_PRIVKEY_B64", ""),
    )


SETTINGS = load_settings()
