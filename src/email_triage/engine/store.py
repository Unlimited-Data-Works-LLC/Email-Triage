"""SQLite-backed persistence for flow state with revision-checked mutations.

Canonical connection pattern (#145.4)
─────────────────────────────────────
``FlowStore`` ALWAYS accepts an injected ``sqlite3.Connection`` —
the one owned by ``email_triage.web.db.init_db`` (held on
``app.state.db``). That single shared connection guarantees one
writer per process: WAL still serialises at the OS layer, but
sharing the in-process connection eliminates the stale-read /
expected_revision-regress window that two independent writers would
otherwise create against the same file.

Canonical caller pattern (web handler / orchestrator)::

    from email_triage.engine.store import FlowStore
    store = FlowStore(connection=request.app.state.db)

Legacy fallback (DEPRECATED)
─────────────────────────────
``FlowStore(db_path="/path/to/triage.db")`` — only the standalone
CLI / one-shot triage path still uses this form, because the CLI
runs without a web-app lifespan and therefore has no canonical
connection to inject. The legacy path opens its own connection
(with WAL + FK pragmas), emits a WARNING log naming this entry
point, and otherwise behaves identically. Do NOT introduce new
callers on the legacy path — pass in a connection from
``init_db`` instead.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from email_triage.engine.models import (
    Classification,
    FlowState,
    FlowStatus,
)
from email_triage.triage_logging import get_logger

log = get_logger("engine.store")


class RevisionConflict(Exception):
    """Raised when an update targets a stale revision."""

    def __init__(self, flow_id: str, expected: int, actual: int | None = None):
        self.flow_id = flow_id
        self.expected = expected
        self.actual = actual
        detail = f"expected {expected}"
        if actual is not None:
            detail += f", found {actual}"
        super().__init__(f"Revision conflict on flow {flow_id}: {detail}")


class FlowNotFound(Exception):
    def __init__(self, flow_id: str):
        self.flow_id = flow_id
        super().__init__(f"Flow not found: {flow_id}")


class DuplicateFlow(Exception):
    def __init__(self, provider: str, message_id: str):
        self.provider = provider
        self.message_id = message_id
        super().__init__(f"Flow already exists for {provider}:{message_id}")


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

_FLOWS_DDL = """\
CREATE TABLE IF NOT EXISTS flows (
    flow_id           TEXT PRIMARY KEY,
    message_id        TEXT NOT NULL,
    provider          TEXT NOT NULL,
    status            TEXT NOT NULL DEFAULT 'created',
    revision          INTEGER NOT NULL DEFAULT 0,
    classification_json TEXT,
    actions_completed_json TEXT NOT NULL DEFAULT '[]',
    actions_pending_json   TEXT NOT NULL DEFAULT '[]',
    state_bag_json    TEXT NOT NULL DEFAULT '{}',
    error             TEXT,
    created_at        TEXT NOT NULL,
    updated_at        TEXT NOT NULL,
    UNIQUE(provider, message_id)
);

CREATE INDEX IF NOT EXISTS idx_flows_status ON flows(status);
CREATE INDEX IF NOT EXISTS idx_flows_provider_message ON flows(provider, message_id);
"""


# ---------------------------------------------------------------------------
# Serialisation helpers
# ---------------------------------------------------------------------------

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_dt(s: str) -> datetime:
    return datetime.fromisoformat(s)


def _cls_to_json(cls: Classification | None) -> str | None:
    if cls is None:
        return None
    return json.dumps({
        "category": cls.category,
        "confidence": cls.confidence,
        "reason": cls.reason,
        "source": cls.source,
    })


def _cls_from_json(s: str | None) -> Classification | None:
    if s is None:
        return None
    d = json.loads(s)
    return Classification(**d)


def _safe_json_load_dict(
    raw: str | None, *, label: str, flow_id: str,
) -> tuple[dict, str | None]:
    """Parse a JSON-blob column, surviving corruption.

    PR 7 / C4. Plain ``json.loads`` on a corrupted ``state_bag_json``
    column raised JSONDecodeError out of ``_row_to_flow``, which
    bubbled all the way up and crashed the engine — leaving the
    operator with a flow that couldn't be loaded, retried, or
    fixed without a hand-edit of the row in SQLite.

    New behaviour: catch the parse error, log the raw blob for
    forensics (truncated to 256 chars), return ``({}, error_msg)``.
    The engine sees an empty dict and an error string; downstream
    can mark the flow ``FAILED`` with a clear reason instead of
    crashing the loop.
    """
    if raw is None or raw == "":
        return {}, None
    try:
        out = json.loads(raw)
        if not isinstance(out, dict):
            # JSON valid but wrong shape (e.g. ``"null"``). Treat as
            # corruption — every column we use this for is a JSON
            # object by contract.
            return {}, (
                f"{label}: expected object, got {type(out).__name__}"
            )
        return out, None
    except (json.JSONDecodeError, TypeError, ValueError) as exc:
        snippet = (raw[:256] if isinstance(raw, str) else str(raw)[:256])
        return {}, (
            f"{label}_corrupt: {type(exc).__name__}: {exc}; "
            f"raw_snippet={snippet!r}"
        )


def _row_to_flow(row: sqlite3.Row) -> FlowState:
    sb_raw = row["state_bag_json"]
    state_bag, sb_err = _safe_json_load_dict(
        sb_raw, label="state_bag", flow_id=row["flow_id"],
    )
    flow = FlowState(
        flow_id=row["flow_id"],
        message_id=row["message_id"],
        provider=row["provider"],
        status=FlowStatus(row["status"]),
        revision=row["revision"],
        classification=_cls_from_json(row["classification_json"]),
        actions_completed=json.loads(row["actions_completed_json"]),
        actions_pending=json.loads(row["actions_pending_json"]),
        state_bag=state_bag,
        error=row["error"],
        created_at=_parse_dt(row["created_at"]),
        updated_at=_parse_dt(row["updated_at"]),
    )
    if sb_err is not None:
        # Stash the corruption note on state_bag so the engine /
        # admin UI can detect-and-skip cleanly without re-parsing.
        flow.state_bag["__corruption__"] = sb_err
    return flow


# ---------------------------------------------------------------------------
# FlowStore
# ---------------------------------------------------------------------------

class FlowStore:
    """SQLite persistence layer for triage flows.

    All mutations use optimistic concurrency via a revision counter:
    ``UPDATE ... WHERE flow_id = ? AND revision = ?``
    If no row is affected the caller holds a stale copy.
    """

    def __init__(
        self,
        db_path: str | Path = ":memory:",
        *,
        connection: sqlite3.Connection | None = None,
    ):
        """Construct a ``FlowStore``.

        Preferred form (#145.4)::

            FlowStore(connection=app.state.db)

        The injected connection is the canonical web-app connection
        owned by ``email_triage.web.db.init_db``. ``FlowStore`` will
        use it directly — no second writer connection is opened,
        which eliminates the stale-read / expected_revision-regress
        window between two independent connections to the same file.

        Legacy fallback (DEPRECATED)::

            FlowStore("/path/to/triage.db")

        Used only by the standalone CLI / one-shot triage entry
        points that run without a web-app lifespan. A WARNING is
        logged on this path. The connection opened here is owned by
        ``FlowStore`` and ``close()`` will release it.

        Parameters
        ----------
        db_path:
            Path to the SQLite database. Used only when
            ``connection`` is None. Ignored otherwise.
        connection:
            An already-open ``sqlite3.Connection`` (typically the
            one from ``init_db``). When provided, ``FlowStore`` uses
            it directly and does NOT call ``sqlite3.connect``.
            ``close()`` does NOT close an injected connection — the
            caller (web-app lifespan) owns its lifecycle.
        """
        if connection is not None:
            # Canonical path — reuse the caller's connection.
            self._db_path = ""
            self._conn = connection
            self._owns_connection = False
        else:
            # Legacy fallback — open our own. Warn so this path is
            # visible in operator logs; new callers must not land
            # here against a web-app DB path.
            self._db_path = str(db_path)
            log.warning(
                "FlowStore opened its own SQLite connection — "
                "legacy CLI / one-shot path. New callers should "
                "inject the canonical web.db connection via "
                "FlowStore(connection=app.state.db). "
                "See engine/store.py module docstring (#145.4).",
                db_path=self._db_path,
            )
            self._conn = self._connect()
            self._owns_connection = True
        self._ensure_schema()

    def _connect(self) -> sqlite3.Connection:
        """Open a new SQLite connection (legacy fallback only).

        Called when no ``connection`` was injected — that's the
        standalone CLI / one-shot triage path. The canonical web-app
        path injects the connection from ``init_db`` and never
        reaches this method.
        """
        conn = sqlite3.connect(self._db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _ensure_schema(self) -> None:
        self._conn.executescript(_FLOWS_DDL)

    # -- create ---------------------------------------------------------------

    def create_flow(self, message_id: str, provider: str) -> FlowState:
        """Insert a new flow. Raises DuplicateFlow if (provider, message_id) exists."""
        flow_id = FlowState.new_id()
        now = _now_iso()
        try:
            self._conn.execute(
                """INSERT INTO flows
                   (flow_id, message_id, provider, status, revision, created_at, updated_at)
                   VALUES (?, ?, ?, ?, 0, ?, ?)""",
                (flow_id, message_id, provider, FlowStatus.CREATED.value, now, now),
            )
            self._conn.commit()
        except sqlite3.IntegrityError:
            raise DuplicateFlow(provider, message_id)

        return FlowState(
            flow_id=flow_id,
            message_id=message_id,
            provider=provider,
            status=FlowStatus.CREATED,
            revision=0,
            created_at=_parse_dt(now),
            updated_at=_parse_dt(now),
        )

    def get_or_create_flow(
        self, message_id: str, provider: str
    ) -> tuple[FlowState, bool]:
        """Idempotent create. Returns (flow, was_created)."""
        try:
            flow = self.create_flow(message_id, provider)
            return flow, True
        except DuplicateFlow:
            existing = self.find_flows(provider=provider, message_id=message_id)
            return existing[0], False

    # -- read -----------------------------------------------------------------

    def get_flow(self, flow_id: str) -> FlowState:
        """Load a flow by ID. Raises FlowNotFound."""
        row = self._conn.execute(
            "SELECT * FROM flows WHERE flow_id = ?", (flow_id,)
        ).fetchone()
        if row is None:
            raise FlowNotFound(flow_id)
        return _row_to_flow(row)

    def find_flows(
        self,
        status: FlowStatus | None = None,
        provider: str | None = None,
        message_id: str | None = None,
        limit: int = 100,
    ) -> list[FlowState]:
        """Query flows with optional filters."""
        clauses: list[str] = []
        params: list[Any] = []
        if status is not None:
            clauses.append("status = ?")
            params.append(status.value)
        if provider is not None:
            clauses.append("provider = ?")
            params.append(provider)
        if message_id is not None:
            clauses.append("message_id = ?")
            params.append(message_id)

        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        sql = f"SELECT * FROM flows{where} ORDER BY updated_at DESC LIMIT ?"
        params.append(limit)

        rows = self._conn.execute(sql, params).fetchall()
        return [_row_to_flow(r) for r in rows]

    # -- update ---------------------------------------------------------------

    def update_flow(
        self, flow: FlowState, expected_revision: int
    ) -> FlowState:
        """Persist changes with optimistic concurrency.

        Raises RevisionConflict if the stored revision doesn't match
        ``expected_revision``.  On success the returned flow has
        ``revision = expected_revision + 1``.
        """
        now = _now_iso()
        cur = self._conn.execute(
            """UPDATE flows SET
                   status = ?,
                   revision = revision + 1,
                   classification_json = ?,
                   actions_completed_json = ?,
                   actions_pending_json = ?,
                   state_bag_json = ?,
                   error = ?,
                   updated_at = ?
               WHERE flow_id = ? AND revision = ?""",
            (
                flow.status.value,
                _cls_to_json(flow.classification),
                json.dumps(flow.actions_completed),
                json.dumps(flow.actions_pending),
                json.dumps(flow.state_bag),
                flow.error,
                now,
                flow.flow_id,
                expected_revision,
            ),
        )
        self._conn.commit()

        if cur.rowcount == 0:
            # Was it not-found or a genuine conflict?
            try:
                current = self.get_flow(flow.flow_id)
                raise RevisionConflict(
                    flow.flow_id, expected_revision, current.revision
                )
            except FlowNotFound:
                raise FlowNotFound(flow.flow_id)

        flow.revision = expected_revision + 1
        flow.updated_at = _parse_dt(now)
        return flow

    # -- convenience ----------------------------------------------------------

    def count_by_status(self) -> dict[str, int]:
        """Return {status: count} for all flows."""
        rows = self._conn.execute(
            "SELECT status, COUNT(*) as cnt FROM flows GROUP BY status"
        ).fetchall()
        return {row["status"]: row["cnt"] for row in rows}

    def close(self) -> None:
        """Close the connection if owned by this ``FlowStore``.

        When ``connection`` was injected at construction, the caller
        owns the connection lifecycle (web-app lifespan) and we do
        NOT close it here — closing the canonical app connection
        underneath the web-app would orphan every other handler.
        """
        if self._owns_connection:
            self._conn.close()
