"""SQLite-backed terminal session store.

Single-host orchestrator -> sqlite is enough for v1. Schema mirrors the
backend's vps_terminals + vps_terminal_events but is independent (the backend
is the source of truth for billing/ownership; the orchestrator owns runtime
state).
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Dict, Iterator, List, Optional

from .settings import SETTINGS


_LOCK = threading.RLock()
_CONN: Optional[sqlite3.Connection] = None


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(SETTINGS.state_db_path, check_same_thread=False, isolation_level=None)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    conn.row_factory = sqlite3.Row
    return conn


def init() -> None:
    global _CONN
    with _LOCK:
        if _CONN is None:
            _CONN = _connect()
        _CONN.executescript(
            """
            CREATE TABLE IF NOT EXISTS terminals (
                terminal_id TEXT PRIMARY KEY,
                owner TEXT NOT NULL,
                platform TEXT NOT NULL,
                account_type TEXT NOT NULL,
                status TEXT NOT NULL,
                ea_attached INTEGER NOT NULL DEFAULT 0,
                ea_detached_manually INTEGER NOT NULL DEFAULT 0,
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sealed_credentials (
                terminal_id TEXT PRIMARY KEY,
                sealed_payload BLOB NOT NULL,
                updated_at REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS jobs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                terminal_id TEXT NOT NULL,
                kind TEXT NOT NULL,
                payload_json TEXT,
                status TEXT NOT NULL DEFAULT 'queued',
                attempts INTEGER NOT NULL DEFAULT 0,
                error TEXT,
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL
            );
            CREATE INDEX IF NOT EXISTS ix_jobs_status ON jobs(status, id);
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                terminal_id TEXT NOT NULL,
                event_type TEXT NOT NULL,
                severity TEXT NOT NULL DEFAULT 'info',
                message TEXT NOT NULL DEFAULT '',
                meta_json TEXT,
                created_at REAL NOT NULL
            );
            CREATE INDEX IF NOT EXISTS ix_events_terminal ON events(terminal_id, id);
            """
        )


def _now() -> float:
    return time.time()


@contextmanager
def _cur() -> Iterator[sqlite3.Cursor]:
    init()
    assert _CONN is not None
    with _LOCK:
        cur = _CONN.cursor()
        try:
            yield cur
        finally:
            cur.close()


# ---------------------------------------------------------------------------
# Terminals
# ---------------------------------------------------------------------------

@dataclass
class Terminal:
    terminal_id: str
    owner: str
    platform: str
    account_type: str
    status: str
    ea_attached: bool
    ea_detached_manually: bool
    created_at: float
    updated_at: float


def upsert_terminal(*, terminal_id: str, owner: str, platform: str, account_type: str, status: str = "queued") -> Terminal:
    now = _now()
    with _cur() as c:
        c.execute(
            """
            INSERT INTO terminals (terminal_id, owner, platform, account_type, status, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(terminal_id) DO UPDATE SET
                owner=excluded.owner,
                platform=excluded.platform,
                account_type=excluded.account_type,
                updated_at=excluded.updated_at
            """,
            (terminal_id, owner, platform, account_type, status, now, now),
        )
    return get_terminal(terminal_id)  # type: ignore[return-value]


def get_terminal(terminal_id: str) -> Optional[Terminal]:
    with _cur() as c:
        row = c.execute("SELECT * FROM terminals WHERE terminal_id=?", (terminal_id,)).fetchone()
    if row is None:
        return None
    return Terminal(
        terminal_id=row["terminal_id"],
        owner=row["owner"],
        platform=row["platform"],
        account_type=row["account_type"],
        status=row["status"],
        ea_attached=bool(row["ea_attached"]),
        ea_detached_manually=bool(row["ea_detached_manually"]),
        created_at=float(row["created_at"]),
        updated_at=float(row["updated_at"]),
    )


def update_terminal_fields(terminal_id: str, **fields: Any) -> None:
    if not fields:
        return
    fields["updated_at"] = _now()
    cols = ", ".join(f"{k}=?" for k in fields.keys())
    vals = list(fields.values()) + [terminal_id]
    with _cur() as c:
        c.execute(f"UPDATE terminals SET {cols} WHERE terminal_id=?", vals)


def delete_terminal(terminal_id: str) -> None:
    with _cur() as c:
        c.execute("DELETE FROM sealed_credentials WHERE terminal_id=?", (terminal_id,))
        c.execute("DELETE FROM jobs WHERE terminal_id=?", (terminal_id,))
        c.execute("DELETE FROM terminals WHERE terminal_id=?", (terminal_id,))


def count_terminals() -> int:
    with _cur() as c:
        row = c.execute("SELECT COUNT(*) AS n FROM terminals").fetchone()
    return int(row["n"]) if row else 0


# ---------------------------------------------------------------------------
# Sealed credentials
# ---------------------------------------------------------------------------

def store_sealed_credentials(terminal_id: str, sealed: bytes) -> None:
    with _cur() as c:
        c.execute(
            """
            INSERT INTO sealed_credentials (terminal_id, sealed_payload, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(terminal_id) DO UPDATE SET
                sealed_payload=excluded.sealed_payload,
                updated_at=excluded.updated_at
            """,
            (terminal_id, sqlite3.Binary(sealed), _now()),
        )


def load_sealed_credentials(terminal_id: str) -> Optional[bytes]:
    with _cur() as c:
        row = c.execute("SELECT sealed_payload FROM sealed_credentials WHERE terminal_id=?", (terminal_id,)).fetchone()
    return bytes(row["sealed_payload"]) if row else None


# ---------------------------------------------------------------------------
# Jobs
# ---------------------------------------------------------------------------

def enqueue_job(*, terminal_id: str, kind: str, payload: Optional[Dict[str, Any]] = None) -> int:
    now = _now()
    with _cur() as c:
        cur = c.execute(
            """
            INSERT INTO jobs (terminal_id, kind, payload_json, status, attempts, created_at, updated_at)
            VALUES (?, ?, ?, 'queued', 0, ?, ?)
            """,
            (terminal_id, kind, json.dumps(payload or {}, ensure_ascii=False), now, now),
        )
    return int(cur.lastrowid)


def claim_next_job() -> Optional[Dict[str, Any]]:
    with _cur() as c:
        row = c.execute(
            "SELECT * FROM jobs WHERE status='queued' ORDER BY id ASC LIMIT 1"
        ).fetchone()
        if row is None:
            return None
        c.execute(
            "UPDATE jobs SET status='running', attempts=attempts+1, updated_at=? WHERE id=? AND status='queued'",
            (_now(), int(row["id"])),
        )
    return {
        "id": int(row["id"]),
        "terminal_id": str(row["terminal_id"]),
        "kind": str(row["kind"]),
        "payload": json.loads(row["payload_json"] or "{}"),
        "attempts": int(row["attempts"]) + 1,
    }


def finish_job(job_id: int, *, ok: bool, error: Optional[str] = None) -> None:
    with _cur() as c:
        c.execute(
            "UPDATE jobs SET status=?, error=?, updated_at=? WHERE id=?",
            ("done" if ok else "failed", (error or "")[:1000], _now(), int(job_id)),
        )


# ---------------------------------------------------------------------------
# Events (kept locally for diagnostics; backend is the user-facing source)
# ---------------------------------------------------------------------------

def record_event(*, terminal_id: str, event_type: str, severity: str = "info", message: str = "", meta: Optional[Dict[str, Any]] = None) -> None:
    with _cur() as c:
        c.execute(
            """
            INSERT INTO events (terminal_id, event_type, severity, message, meta_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (terminal_id, event_type[:64], severity[:8], message[:4000], json.dumps(meta or {}, ensure_ascii=False), _now()),
        )


def list_events(terminal_id: str, *, since_id: int = 0, limit: int = 100) -> List[Dict[str, Any]]:
    with _cur() as c:
        rows = c.execute(
            "SELECT * FROM events WHERE terminal_id=? AND id>? ORDER BY id ASC LIMIT ?",
            (terminal_id, int(since_id), int(max(1, min(500, limit)))),
        ).fetchall()
    return [
        {
            "id": int(r["id"]),
            "event_type": r["event_type"],
            "severity": r["severity"],
            "message": r["message"],
            "meta": json.loads(r["meta_json"] or "{}"),
            "created_at": float(r["created_at"]),
        }
        for r in rows
    ]
