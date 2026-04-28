"""Background worker that drains the job queue and drives terminals through
their lifecycle.

Job kinds (must match what api.py enqueues):
    * provision     -> queued -> provisioning -> ready
    * broker_login  -> ready -> broker_login_pending -> broker_logged_in
    * attach_ea     -> broker_logged_in -> ea_attach_pending -> live
    * detach_ea     -> live -> broker_logged_in
    * restart       -> any -> provisioning -> ready (then prior steps re-issued)
    * stop          -> any -> stopped
    * destroy       -> wipe + delete
"""
from __future__ import annotations

import logging
import threading
import time
from typing import Optional

from . import provisioner, state
from .settings import SETTINGS
from .webhook import push_status

_LOGGER = logging.getLogger("flame_vps.worker")

_STOP = threading.Event()
_THREADS: list[threading.Thread] = []


def _transition(terminal_id: str, *, status: str, event_type: str, message: str, severity: str = "info", ea_attached: Optional[bool] = None) -> None:
    fields = {"status": status}
    if ea_attached is not None:
        fields["ea_attached"] = 1 if ea_attached else 0  # type: ignore[assignment]
    state.update_terminal_fields(terminal_id, **fields)
    state.record_event(terminal_id=terminal_id, event_type=event_type, severity=severity, message=message)
    push_status(
        terminal_id=terminal_id,
        status=status,
        event_type=event_type,
        message=message,
        severity=severity,
        ea_attached=ea_attached,
    )


def _handle_job(job: dict) -> None:
    terminal_id = job["terminal_id"]
    kind = job["kind"]
    payload = job.get("payload") or {}
    t = state.get_terminal(terminal_id)
    if t is None and kind != "destroy":
        state.finish_job(job["id"], ok=False, error="terminal not found")
        return

    try:
        job_ok = True
        job_error = ""

        if kind == "provision":
            _transition(terminal_id, status="provisioning", event_type="provisioning_started", message="MT terminal provisioning")
            res = provisioner.provision_terminal(
                terminal_id=terminal_id,
                platform=t.platform if t else str(payload.get("platform", "mt5")),
                account_type=t.account_type if t else str(payload.get("account_type", "normal")),
            )
            if res.ok:
                _transition(terminal_id, status="ready", event_type="terminal_ready", message=res.message)
            else:
                job_ok = False
                job_error = res.message
                _transition(terminal_id, status="failed", event_type="provision_failed", message=res.message, severity="error")

        elif kind == "broker_login":
            _transition(terminal_id, status="broker_login_pending", event_type="broker_login_started", message="Submitting broker credentials to MT")
            sealed = state.load_sealed_credentials(terminal_id) or b""
            res = provisioner.broker_login(terminal_id=terminal_id, sealed_payload=sealed)
            if res.ok:
                _transition(terminal_id, status="broker_logged_in", event_type="broker_logged_in", message=res.message)
            else:
                job_ok = False
                job_error = res.message
                _transition(terminal_id, status="failed", event_type="broker_login_failed", message=res.message, severity="error")

        elif kind == "attach_ea":
            _transition(terminal_id, status="ea_attach_pending", event_type="ea_attach_started", message="Deploying and attaching EA")
            res = provisioner.attach_ea(
                terminal_id=terminal_id,
                account_type=str(payload.get("account_type") or (t.account_type if t else "normal")),
                ea_user_id=str(payload.get("ea_user_id") or ""),
                ea_license_key=str(payload.get("ea_license_key") or ""),
            )
            if res.ok:
                _transition(terminal_id, status="live", event_type="ea_attached", message=res.message, ea_attached=True)
            else:
                job_ok = False
                job_error = res.message
                _transition(terminal_id, status="failed", event_type="ea_attach_failed", message=res.message, severity="error")

        elif kind == "detach_ea":
            res = provisioner.detach_ea(terminal_id=terminal_id)
            if not res.ok:
                job_ok = False
                job_error = res.message
            _transition(terminal_id, status="broker_logged_in", event_type="ea_detached", message=res.message, ea_attached=False)

        elif kind == "restart":
            res = provisioner.restart_terminal(terminal_id=terminal_id)
            if not res.ok:
                job_ok = False
                job_error = res.message
            _transition(terminal_id, status="ready" if res.ok else "failed",
                        event_type="terminal_restarted" if res.ok else "restart_failed",
                        message=res.message,
                        severity="info" if res.ok else "error")

        elif kind == "stop":
            res = provisioner.stop_terminal(terminal_id=terminal_id)
            if not res.ok:
                job_ok = False
                job_error = res.message
            _transition(terminal_id, status="stopped", event_type="terminal_stopped", message=res.message)

        elif kind == "destroy":
            provisioner.destroy_terminal(terminal_id=terminal_id)
            state.delete_terminal(terminal_id)
            push_status(terminal_id=terminal_id, status="stopped", event_type="terminal_destroyed",
                        message="Terminal removed and credentials wiped")

        else:
            state.finish_job(job["id"], ok=False, error=f"unknown kind {kind}")
            return

        state.finish_job(job["id"], ok=job_ok, error=job_error)
    except Exception as exc:
        _LOGGER.exception("job %s/%s failed", kind, terminal_id)
        state.record_event(terminal_id=terminal_id, event_type=f"{kind}_exception", severity="error", message=str(exc))
        push_status(terminal_id=terminal_id, status="failed", event_type=f"{kind}_exception",
                    message=str(exc), severity="error")
        state.finish_job(job["id"], ok=False, error=str(exc))


def _loop(worker_index: int) -> None:
    _LOGGER.info("worker %d started", worker_index)
    while not _STOP.is_set():
        job = state.claim_next_job()
        if job is None:
            time.sleep(0.25)
            continue
        _handle_job(job)


def start_workers() -> None:
    if _THREADS:
        return
    state.init()
    for i in range(int(SETTINGS.worker_pool_size)):
        th = threading.Thread(target=_loop, args=(i,), name=f"flame-vps-worker-{i}", daemon=True)
        th.start()
        _THREADS.append(th)


def stop_workers() -> None:
    _STOP.set()
