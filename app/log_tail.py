"""Best-effort tail of MT4/MT5 terminal logs -> webhook events.

MT terminals write daily log files into:
    MT4: <install_dir>/logs/YYYYMMDD.log
    MT5: <install_dir>/Logs/YYYYMMDD.log  (terminal log)
         <install_dir>/MQL5/Logs/YYYYMMDD.log  (Experts log)

We open the most recent log file per terminal, follow it, and forward INFO/
WARN/ERROR entries to the backend webhook. This gives the user feedback like
"login succeeded" / "EA attached" / "no symbol XAUUSD" without us having to
parse the whole MT protocol.
"""
from __future__ import annotations

import datetime
import logging
import os
import threading
import time
from typing import Dict

from . import state, webhook

_LOGGER = logging.getLogger("flame_vps.logtail")

_THREADS: Dict[str, threading.Thread] = {}
_STOP_FLAGS: Dict[str, threading.Event] = {}
_LOCK = threading.RLock()


def _candidate_log_paths(install_dir: str, platform: str) -> list[str]:
    today = datetime.datetime.now().strftime("%Y%m%d")
    yesterday = (datetime.datetime.now() - datetime.timedelta(days=1)).strftime("%Y%m%d")
    bases = []
    p = (platform or "").lower()
    if p == "mt5":
        bases = [
            os.path.join(install_dir, "Logs"),
            os.path.join(install_dir, "MQL5", "Logs"),
        ]
    else:  # mt4
        bases = [
            os.path.join(install_dir, "logs"),
            os.path.join(install_dir, "MQL4", "Logs"),
        ]
    paths: list[str] = []
    for base in bases:
        for name in (today, yesterday):
            paths.append(os.path.join(base, f"{name}.log"))
    return paths


def _classify(line: str) -> tuple[str, str]:
    """Return (event_type, severity) from a log line. Best-effort heuristics."""
    low = line.lower()
    if "login" in low and ("failed" in low or "invalid" in low):
        return ("broker_login_log", "error")
    if "authorized on" in low or "login succeed" in low or "login success" in low:
        return ("broker_login_log", "info")
    if "expert " in low and ("loaded successfully" in low or "started" in low):
        return ("ea_log", "info")
    if "expert " in low and ("removed" in low or "stopped" in low):
        return ("ea_log", "info")
    if "error" in low or "failed" in low:
        return ("mt_log", "warn")
    return ("mt_log", "info")


def _follow(install_dir: str, platform: str, terminal_id: str, stop: threading.Event) -> None:
    fh = None
    current_path = ""
    file_pos = 0
    while not stop.is_set():
        try:
            paths = _candidate_log_paths(install_dir, platform)
            best = None
            for p in paths:
                try:
                    if os.path.isfile(p):
                        if best is None or os.path.getmtime(p) > os.path.getmtime(best):
                            best = p
                except Exception:
                    continue
            if best != current_path:
                if fh is not None:
                    try:
                        fh.close()
                    except Exception:
                        pass
                    fh = None
                current_path = best or ""
                file_pos = 0
                if current_path:
                    try:
                        fh = open(current_path, "r", encoding="utf-8", errors="replace")
                        fh.seek(0, os.SEEK_END)
                        file_pos = fh.tell()
                    except Exception:
                        fh = None
            if fh is None:
                stop.wait(2.0)
                continue
            line = fh.readline()
            if not line:
                stop.wait(0.75)
                continue
            file_pos += len(line)
            event_type, severity = _classify(line)
            msg = line.strip()[:512]
            if not msg:
                continue
            try:
                state.record_event(terminal_id=terminal_id, event_type=event_type, severity=severity, message=msg)
            except Exception:
                pass
            try:
                webhook.push_status(
                    terminal_id=terminal_id,
                    event_type=event_type,
                    severity=severity,
                    message=msg,
                )
            except Exception:
                pass
        except Exception:
            _LOGGER.exception("log-tail loop error terminal=%s", terminal_id)
            stop.wait(2.0)
    if fh is not None:
        try:
            fh.close()
        except Exception:
            pass


def start(terminal_id: str, install_dir: str, platform: str) -> None:
    with _LOCK:
        if terminal_id in _THREADS and _THREADS[terminal_id].is_alive():
            return
        stop = threading.Event()
        _STOP_FLAGS[terminal_id] = stop
        th = threading.Thread(
            target=_follow,
            args=(install_dir, platform, terminal_id, stop),
            name=f"flame-vps-logtail-{terminal_id[:8]}",
            daemon=True,
        )
        _THREADS[terminal_id] = th
        th.start()


def stop_for(terminal_id: str) -> None:
    with _LOCK:
        ev = _STOP_FLAGS.pop(terminal_id, None)
        _THREADS.pop(terminal_id, None)
    if ev is not None:
        ev.set()


def stop_all() -> None:
    with _LOCK:
        for ev in _STOP_FLAGS.values():
            ev.set()
        _STOP_FLAGS.clear()
        _THREADS.clear()
