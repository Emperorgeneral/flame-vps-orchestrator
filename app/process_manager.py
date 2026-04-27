"""In-memory map of terminal_id -> running MT process.

Single-host service, so a process-local dict is enough. We don't persist PIDs
across restarts — `provisioner` recovers by checking whether terminal.exe is
running for a given install dir, but for v1 a cold start treats everything as
not-running and the worker will re-launch on the next broker_login/restart.
"""
from __future__ import annotations

import logging
import os
import signal
import subprocess
import threading
import time
from dataclasses import dataclass
from typing import Dict, Optional

_LOGGER = logging.getLogger("flame_vps.process")

_LOCK = threading.RLock()


@dataclass
class TerminalProcess:
    terminal_id: str
    pid: int
    install_dir: str
    started_at: float


_PROCESSES: Dict[str, TerminalProcess] = {}


def register(terminal_id: str, popen: subprocess.Popen, install_dir: str) -> TerminalProcess:
    proc = TerminalProcess(
        terminal_id=terminal_id,
        pid=int(popen.pid),
        install_dir=install_dir,
        started_at=time.time(),
    )
    with _LOCK:
        _PROCESSES[terminal_id] = proc
    return proc


def get(terminal_id: str) -> Optional[TerminalProcess]:
    with _LOCK:
        return _PROCESSES.get(terminal_id)


def is_running(terminal_id: str) -> bool:
    with _LOCK:
        proc = _PROCESSES.get(terminal_id)
    if proc is None:
        return False
    return _pid_alive(proc.pid)


def stop(terminal_id: str, *, timeout_sec: float = 8.0) -> bool:
    """Best-effort terminate of a tracked terminal process."""
    with _LOCK:
        proc = _PROCESSES.pop(terminal_id, None)
    if proc is None:
        return False
    return _kill_pid(proc.pid, timeout_sec=timeout_sec)


def stop_all() -> None:
    with _LOCK:
        items = list(_PROCESSES.items())
        _PROCESSES.clear()
    for _tid, proc in items:
        try:
            _kill_pid(proc.pid, timeout_sec=4.0)
        except Exception:
            pass


def _pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    if os.name == "nt":
        # On Windows, check via tasklist filtered by PID.
        try:
            out = subprocess.run(
                ["tasklist", "/FI", f"PID eq {int(pid)}", "/FO", "CSV", "/NH"],
                capture_output=True, text=True, timeout=3.0,
            )
            return bool(out.stdout) and f'"{int(pid)}"' in out.stdout
        except Exception:
            return False
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def _kill_pid(pid: int, *, timeout_sec: float = 8.0) -> bool:
    if pid <= 0:
        return False
    try:
        if os.name == "nt":
            subprocess.run(
                ["taskkill", "/PID", str(int(pid)), "/T", "/F"],
                capture_output=True, timeout=max(2.0, float(timeout_sec)),
            )
        else:
            try:
                os.kill(pid, signal.SIGTERM)
            except OSError:
                return False
            deadline = time.time() + float(timeout_sec)
            while time.time() < deadline:
                if not _pid_alive(pid):
                    return True
                time.sleep(0.2)
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass
        return not _pid_alive(pid)
    except Exception:
        _LOGGER.exception("failed to kill pid=%s", pid)
        return False
