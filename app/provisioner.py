"""Real MT4/MT5 provisioner + EA deployer (Phase 2.5).

Lifecycle:
* ``provision_terminal``  -> copy a portable MT tree from the configured
  template into ``<mt_install_root>/<terminal_id>``. No process is started
  yet (we don't have credentials).
* ``broker_login``        -> decrypt sealed creds and launch terminal.exe in
  portable mode with ``/login: /server: /password:``. Track the PID and
  start tailing the MT log.
* ``attach_ea``           -> resolve the EA artifact bundle (from
  ``ea_bundle_root``) for the given platform/account_type, copy the EA file
  into ``MQL{4,5}/Experts/`` and write a small ``FlameBotAuth.json`` so the
  EA knows which FlameBot user/license to report. Auto-attaching to a chart
  is delegated to the operator-prepared template tree (the template's profile
  already holds a chart that auto-loads ``FlameBot.ex{4,5}`` once the file
  exists).
* ``detach_ea``           -> remove the deployed EA artifact (chart objects
  remain; the EA simply fails to load on next launch and the user sees no
  trades placed).
* ``restart`` / ``stop``  -> kill the tracked process; ``restart`` relaunches
  with the most recently sealed credentials.
* ``destroy``             -> kill + ``shutil.rmtree``.

Everything degrades gracefully on non-Windows hosts: filesystem ops still run
(useful for tests) but ``subprocess.Popen`` of ``terminal.exe`` is skipped
with a warning instead of erroring out.
"""
from __future__ import annotations

import logging
import os
import shutil
import subprocess
import time
from dataclasses import dataclass
from typing import Optional, Tuple

from . import crypto, log_tail, process_manager, state
from .settings import SETTINGS

_LOGGER = logging.getLogger("flame_vps.provisioner")


@dataclass
class ProvisionResult:
    ok: bool
    message: str = ""


# ---------------------------------------------------------------------------
# Filesystem helpers
# ---------------------------------------------------------------------------

def _install_dir(terminal_id: str) -> str:
    return os.path.join(SETTINGS.mt_install_root, terminal_id)


def _template_dir(platform: str) -> str:
    return SETTINGS.mt5_template_path if (platform or "").lower() == "mt5" else SETTINGS.mt4_template_path


def _terminal_exe(install_dir: str, platform: str) -> str:
    """Resolve terminal[64].exe inside a portable install dir."""
    if (platform or "").lower() == "mt5":
        candidates = ["terminal64.exe", "terminal.exe"]
    else:
        candidates = ["terminal.exe"]
    for name in candidates:
        path = os.path.join(install_dir, name)
        if os.path.isfile(path):
            return path
    return os.path.join(install_dir, candidates[0])


def _copy_template_tree(src: str, dst: str) -> None:
    if not src or not os.path.isdir(src):
        raise FileNotFoundError(f"template not found: {src}")
    if os.path.exists(dst):
        # Re-provision: wipe and recopy. Sealed creds live in the orchestrator
        # state DB, not on disk, so we can safely nuke this tree.
        shutil.rmtree(dst, ignore_errors=True)
    shutil.copytree(src, dst, symlinks=False, ignore_dangling_symlinks=True)


def _safe_remove(path: str) -> None:
    try:
        if os.path.isfile(path):
            os.remove(path)
    except Exception:
        _LOGGER.warning("failed to remove %s", path, exc_info=False)


# ---------------------------------------------------------------------------
# Public lifecycle hooks (called by worker.py)
# ---------------------------------------------------------------------------

def provision_terminal(*, terminal_id: str, platform: str, account_type: str) -> ProvisionResult:
    src = _template_dir(platform)
    dst = _install_dir(terminal_id)
    try:
        _copy_template_tree(src, dst)
    except FileNotFoundError as exc:
        # In dev (no templates configured) keep the orchestrator usable.
        _LOGGER.warning("provision: template missing (%s); creating empty install dir", exc)
        os.makedirs(dst, exist_ok=True)
        return ProvisionResult(True, "provisioned (no template; dev mode)")
    except Exception as exc:
        _LOGGER.exception("provision failed terminal=%s", terminal_id)
        return ProvisionResult(False, f"provision failed: {exc}")
    _LOGGER.info("provisioned terminal=%s platform=%s root=%s", terminal_id, platform, dst)
    return ProvisionResult(True, f"provisioned {platform.upper()} at {dst}")


def broker_login(*, terminal_id: str, sealed_payload: bytes) -> ProvisionResult:
    if not sealed_payload:
        return ProvisionResult(False, "sealed payload missing")
    creds = crypto.decrypt_broker_payload(sealed_payload)
    if not isinstance(creds, dict):
        return ProvisionResult(False, "could not decrypt broker credentials")
    server = str(creds.get("server") or "").strip()
    login = str(creds.get("login") or "").strip()
    password = str(creds.get("password") or "")
    if not server or not login or not password:
        return ProvisionResult(False, "broker credentials incomplete")

    t = state.get_terminal(terminal_id)
    if t is None:
        return ProvisionResult(False, "terminal not found")
    install_dir = _install_dir(terminal_id)
    if not os.path.isdir(install_dir):
        return ProvisionResult(False, "install dir missing — re-provision required")

    # Make sure no stale process is running for this terminal.
    try:
        process_manager.stop(terminal_id)
    except Exception:
        pass

    exe = _terminal_exe(install_dir, t.platform)
    mt_args = [
        exe,
        "/portable",
        f"/login:{login}",
        f"/server:{server}",
        f"/password:{password}",
    ]

    if os.name == "nt":
        # Windows: launch directly with detached process flags.
        try:
            creationflags = subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP  # type: ignore[attr-defined]
        except Exception:
            creationflags = 0
        launch_args = mt_args
        launch_env = None
        launch_flags = creationflags
    else:
        # Linux / macOS: run under Wine. Each terminal gets its own WINEPREFIX
        # so Wine registries / settings don't bleed between terminals.
        wine_bin = shutil.which("wine")
        if not wine_bin:
            return ProvisionResult(False, "Wine is not installed on this host. Run: sudo apt install wine64")
        wineprefix = os.path.join(install_dir, ".wine")
        os.makedirs(wineprefix, exist_ok=True)
        launch_args = [wine_bin] + mt_args
        launch_env = os.environ.copy()
        launch_env["WINEPREFIX"] = wineprefix
        launch_env["WINEDEBUG"] = "-all"   # suppress Wine debug spam from stdout
        launch_env["WINEARCH"] = "win64"
        launch_flags = 0

    try:
        popen = subprocess.Popen(  # nosec B603 — args list, no shell
            launch_args,
            cwd=install_dir,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=launch_env,
            creationflags=launch_flags,
            close_fds=True,
        )
    except Exception as exc:
        _LOGGER.exception("Popen failed terminal=%s", terminal_id)
        return ProvisionResult(False, f"failed to launch terminal: {exc}")

    process_manager.register(terminal_id, popen, install_dir)
    try:
        log_tail.start(terminal_id, install_dir, t.platform)
    except Exception:
        _LOGGER.warning("log-tail failed to start for terminal=%s", terminal_id, exc_info=True)

    # Give MT a moment to boot before reporting success. The log-tail will
    # surface the actual "authorized on" / "login failed" lines as separate
    # webhook events the user can see.
    time.sleep(1.0)
    if popen.poll() is not None:
        return ProvisionResult(False, f"terminal exited immediately (code={popen.returncode})")
    return ProvisionResult(True, "broker login dispatched; check log for confirmation")


def _ea_artifact(platform: str, account_type: str) -> Tuple[Optional[str], str]:
    """Resolve (ea_source_path, target_filename) for the bundle.

    The bundle layout the operator prepares under ``ea_bundle_root`` is::

        ea_bundle_root/
            mt5/prop/FlameBot.ex5
            mt5/normal/FlameBot.ex5
            mt4/prop/FlameBot.ex4
            mt4/normal/FlameBot.ex4

    Falls back to a platform-only path if no per-account variant exists.
    """
    p = (platform or "").lower()
    a = (account_type or "normal").lower()
    ext = "ex5" if p == "mt5" else "ex4"
    target = f"FlameBot.{ext}"
    candidates = [
        os.path.join(SETTINGS.ea_bundle_root, p, a, target),
        os.path.join(SETTINGS.ea_bundle_root, p, target),
    ]
    for c in candidates:
        if os.path.isfile(c):
            return c, target
    return None, target


def attach_ea(*, terminal_id: str, account_type: str, ea_user_id: str, ea_license_key: str) -> ProvisionResult:
    t = state.get_terminal(terminal_id)
    if t is None:
        return ProvisionResult(False, "terminal not found")
    install_dir = _install_dir(terminal_id)
    if not os.path.isdir(install_dir):
        return ProvisionResult(False, "install dir missing — re-provision required")

    p = (t.platform or "").lower()
    src, target = _ea_artifact(p, account_type)
    experts_dir = os.path.join(install_dir, "MQL5" if p == "mt5" else "MQL4", "Experts")
    files_dir = os.path.join(install_dir, "MQL5" if p == "mt5" else "MQL4", "Files")
    os.makedirs(experts_dir, exist_ok=True)
    os.makedirs(files_dir, exist_ok=True)

    if src is None:
        # Don't fail hard — operator may not have published the bundle yet.
        # The orchestrator-prepared MT template can still ship a placeholder
        # EA. Surface a warning so the operator notices.
        _LOGGER.warning(
            "attach_ea: no EA artifact under %s for platform=%s account=%s",
            SETTINGS.ea_bundle_root, p, account_type,
        )
    else:
        try:
            shutil.copy2(src, os.path.join(experts_dir, target))
        except Exception as exc:
            return ProvisionResult(False, f"failed to deploy EA: {exc}")

    # Drop a small auth file the EA can read to know which FlameBot user/license
    # it should report to. The EA itself is responsible for picking this up.
    try:
        import json as _json
        auth_path = os.path.join(files_dir, "FlameBotAuth.json")
        with open(auth_path, "w", encoding="utf-8") as fh:
            _json.dump({
                "user_id": str(ea_user_id or ""),
                "license_key": str(ea_license_key or ""),
                "account_type": str(account_type or "normal").lower(),
                "issued_at": int(time.time()),
            }, fh)
    except Exception:
        _LOGGER.warning("attach_ea: failed to write FlameBotAuth.json", exc_info=True)

    return ProvisionResult(True, f"EA deployed for {p.upper()} ({account_type})")


def detach_ea(*, terminal_id: str) -> ProvisionResult:
    t = state.get_terminal(terminal_id)
    if t is None:
        return ProvisionResult(False, "terminal not found")
    install_dir = _install_dir(terminal_id)
    p = (t.platform or "").lower()
    ext = "ex5" if p == "mt5" else "ex4"
    experts_dir = os.path.join(install_dir, "MQL5" if p == "mt5" else "MQL4", "Experts")
    _safe_remove(os.path.join(experts_dir, f"FlameBot.{ext}"))
    return ProvisionResult(True, "EA artifact removed")


def restart_terminal(*, terminal_id: str) -> ProvisionResult:
    t = state.get_terminal(terminal_id)
    if t is None:
        return ProvisionResult(False, "terminal not found")
    try:
        process_manager.stop(terminal_id)
    except Exception:
        pass
    sealed = state.load_sealed_credentials(terminal_id)
    if not sealed:
        return ProvisionResult(True, "terminal stopped (no creds to relaunch)")
    return broker_login(terminal_id=terminal_id, sealed_payload=sealed)


def stop_terminal(*, terminal_id: str) -> ProvisionResult:
    try:
        process_manager.stop(terminal_id)
    except Exception:
        pass
    try:
        log_tail.stop_for(terminal_id)
    except Exception:
        pass
    return ProvisionResult(True, "terminal stopped")


def destroy_terminal(*, terminal_id: str) -> ProvisionResult:
    try:
        process_manager.stop(terminal_id)
    except Exception:
        pass
    try:
        log_tail.stop_for(terminal_id)
    except Exception:
        pass
    install_dir = _install_dir(terminal_id)
    try:
        if os.path.isdir(install_dir):
            shutil.rmtree(install_dir, ignore_errors=True)
    except Exception:
        _LOGGER.warning("destroy: rmtree failed terminal=%s", terminal_id, exc_info=True)
    return ProvisionResult(True, "terminal destroyed and tree wiped")
