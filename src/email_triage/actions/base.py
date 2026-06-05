"""Abstract base class for triage actions.

Actions are the terminal step in the triage pipeline: once an email is
classified and routed, one or more actions execute against it.

Idempotency model (PR 6 / C2)
-----------------------------

Action outcomes are recorded under
``flow.state_bag["action_results"][action.name]``::

    {
        "idempotency_key": "<sha256 hex>",
        "external_id":     "<provider id or null>",
        "completed_at":    "<iso ts>",
    }

The key is ``sha256(flow_id || action.name || message_id)`` —
deterministic per (flow, action, message). On retry, an action's
``execute`` calls ``check_idempotent_already_done(...)`` first; if
the recorded key matches the current key, the action short-circuits
with a SKIPPED result instead of re-applying its mutation.

This protects against duplicate drafts (the painful case — Gmail
``users.messages.send`` happily creates a second draft on every
call), duplicate notify emails, etc. ``label`` is genuinely
idempotent at the provider level but still records for audit so
the same surface answers "did this run?" for every action.

Durable store
--------------------

The state_bag record above only survives a retry when the engine
persists the state_bag — which the ``FlowEngine`` path does, but the
watcher / runner / bulk ingestion paths do NOT (they build a
throwaway ``FlowState`` per action). So ``check_idempotent_already_done``
/ ``record_idempotent_done`` now ALSO write/read a durable table,
``action_idempotency`` (migration v34), keyed
``(account_id, rfc_message_id, action_name)``. When the flow's
state_bag carries a db connection + ``account_id`` and the message
has an RFC Message-ID, the durable table is authoritative and the
skip survives a retry-queue re-run or a container restart. Otherwise
the helpers fall back to the legacy per-flow state_bag record.
"""

from __future__ import annotations

import hashlib
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any

from email_triage.engine.models import (
    ActionOutput,
    ActionResult,
    Classification,
    EmailMessage,
    FlowState,
)
from email_triage.providers.base import EmailProvider


# ---------------------------------------------------------------------------
# Idempotency helpers (PR 6 / C2)
# ---------------------------------------------------------------------------

def _compute_idempotency_key(
    flow_id: str | int, action_name: str, message_id: str | None,
) -> str:
    """sha256(flow_id || action_name || message_id) — hex.

    Deterministic per (flow, action, message). A retry of the same
    flow re-issues the same key for each action, so the recorded
    state_bag entry matches and the action skips.
    """
    blob = (
        f"{flow_id}|{action_name}|{message_id or ''}"
    ).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def _message_rfc_id(message: EmailMessage) -> str:
    """The RFC 5322 Message-ID of ``message``, or '' when absent.

    The durable idempotency store keys on this rather than the
    provider message id: an IMAP UID is unique only within a mailbox,
    so a UID could collide across two mailboxes of the same account.
    The RFC Message-ID is globally unique.
    """
    try:
        from email_triage.mail_headers import get_rfc_message_id
        return get_rfc_message_id(getattr(message, "headers", {}) or {})
    except Exception:
        return ""


async def check_idempotent_already_done(
    flow: FlowState, message: EmailMessage, action_name: str,
) -> ActionOutput | None:
    """Return a SKIPPED ActionOutput if this action already ran for
    this message; else None.

    Call from the top of an Action.execute() that has external side
    effects.

     — when the flow's ``state_bag`` carries a db connection +
    ``account_id`` and the message has an RFC Message-ID, this consults
    the DURABLE ``action_idempotency`` table, so the skip survives a
    retry-queue re-run or a container restart. Without those (the
    FlowEngine path, or mail with no Message-ID) it falls back to the
    legacy per-flow ``state_bag`` record.

     — ``async def`` so the durable-path ``action_idempotency``
    read can hop to the threadpool via ``db_call``. Action.execute is
    invoked on the event-loop thread, so a bare ``db.execute`` here ran
    SQLite work on the loop and could race a concurrent ``db_call``
    worker on the one shared connection. Every caller awaits this.
    """
    bag = flow.state_bag or {}
    db = bag.get("db")
    account_id = bag.get("account_id")
    rfc_id = _message_rfc_id(message)
    if db is not None and account_id is not None and rfc_id:
        # Durable path.
        from email_triage.web.db_threadpool import db_call

        def _idempotency_row_lookup():
            return db.execute(
                "SELECT external_id, completed_at FROM action_idempotency "
                "WHERE account_id=? AND rfc_message_id=? AND action_name=?",
                (int(account_id), rfc_id, action_name),
            ).fetchone()

        try:
            row = await db_call(_idempotency_row_lookup)
        except Exception:
            # Table missing / DB error — fail safe: let the action run.
            return None
        if row is None:
            return None
        ext = row["external_id"] if hasattr(row, "keys") else row[0]
        done_at = row["completed_at"] if hasattr(row, "keys") else row[1]
        return ActionOutput(
            result=ActionResult.SKIPPED,
            data={
                "skipped_idempotent": True,
                "previous_run_at": done_at,
                "previous_external_id": ext,
            },
        )

    # Legacy fallback — per-flow state_bag (FlowEngine / no Message-ID).
    results = bag.get("action_results") or {}
    record = results.get(action_name)
    if not record:
        return None
    expected_key = _compute_idempotency_key(
        flow.flow_id, action_name, getattr(message, "message_id", None),
    )
    if record.get("idempotency_key") != expected_key:
        # Recorded entry was for a different flow/message — most
        # likely a state_bag from a renamed action or a manual
        # /flows/<id>/retry where the message_id changed. Treat as
        # not-done and let the action run.
        return None
    return ActionOutput(
        result=ActionResult.SKIPPED,
        data={
            "skipped_idempotent": True,
            "previous_run_at": record.get("completed_at"),
            "previous_external_id": record.get("external_id"),
        },
    )


async def record_idempotent_done(
    flow: FlowState,
    message: EmailMessage,
    action_name: str,
    *,
    external_id: str | None = None,
) -> None:
    """Record that ``action_name`` completed for this message so a
    later ``check_idempotent_already_done`` skips it.

     — durable when the ``state_bag`` carries db + ``account_id``
    and the message has an RFC Message-ID (writes the
    ``action_idempotency`` table); otherwise the legacy per-flow
    ``state_bag`` record (which the FlowEngine path persists via
    update_flow).

     — ``async def`` so the durable INSERT+commit hops to the
    threadpool via ``db_call``. Action.execute runs on the event-loop
    thread; the previous bare ``db.execute`` + ``db.commit()`` here
    ran on the loop AND took no write lock — it could both freeze the
    loop and race a concurrent ``db_call`` worker on the shared
    connection. Every caller awaits this.
    """
    bag = flow.state_bag or {}
    db = bag.get("db")
    account_id = bag.get("account_id")
    rfc_id = _message_rfc_id(message)
    now = datetime.now(timezone.utc).isoformat()
    if db is not None and account_id is not None and rfc_id:
        # Durable path.
        from email_triage.web.db_threadpool import db_call

        def _idempotency_upsert():
            db.execute(
                "INSERT INTO action_idempotency "
                "(account_id, rfc_message_id, action_name, external_id, "
                " completed_at) VALUES (?, ?, ?, ?, ?) "
                "ON CONFLICT(account_id, rfc_message_id, action_name) "
                "DO UPDATE SET external_id=excluded.external_id, "
                "  completed_at=excluded.completed_at",
                (int(account_id), rfc_id, action_name, external_id, now),
            )
            db.commit()

        try:
            await db_call(_idempotency_upsert)
            return
        except Exception:
            # Durable write failed — fall through to the state_bag
            # record so the in-flow retry path still skips.
            pass

    # Legacy fallback — per-flow state_bag.
    if flow.state_bag is None:
        flow.state_bag = {}
    results = flow.state_bag.setdefault("action_results", {})
    results[action_name] = {
        "idempotency_key": _compute_idempotency_key(
            flow.flow_id, action_name,
            getattr(message, "message_id", None),
        ),
        "external_id": external_id,
        "completed_at": now,
    }


def build_action_log_extras(
    flow: FlowState,
    message: EmailMessage,
    classification: Classification,
    provider: EmailProvider,
    /,
    **more: Any,
) -> dict[str, Any]:
    """Build a structured-log ``extra`` dict for action log lines.

    Replaces the per-action ``def _extras(**more)`` closure pattern
    repeated across ``label.py``, ``move.py`` (and inline shape in
    ``notify.py``, ``escalate.py``, ``draft_reply.py``). Single source
    of truth so the extras shape stays consistent across actions —
    operators triaging "did this flow run?" don't have to remember
    which action emits which fields.

    Field order intentional. Operators identify accounts by
    ``owner + account_name`` per ``feedback_no_account_id_alone.md``;
    the numeric ``account_id`` is included as a tiebreaker (when
    names collide across owners) but never alone. ``flow_id`` and
    ``message_id`` come first as the request-correlation key.

    PHI redaction. When ``message.hipaa`` is True (the message was
    fetched from a HIPAA-flagged account), ``sender`` and ``subject``
    are not surfaced to logs. ``account_id``, ``account_name``, and
    ``owner`` ARE surfaced regardless — those are workforce
    identifiers (per item ), not PHI even on HIPAA accounts; the
    HIPAA-mode log filter blocks them at sink-time only when
    ``hipaa.session_redact_account_chips`` is on, which is the
    operator's choice and not relevant to the action-emission shape.

    Caller-provided keyword args in ``more`` overlay the base dict
    last so an action that wants to append e.g. ``label`` /
    ``folder`` / ``draft_id`` can do so without colliding with
    the canonical fields.
    """
    extras: dict[str, Any] = {
        "flow_id": flow.flow_id,
        "message_id": message.message_id,
        "provider": provider.name,
        "category": classification.category,
    }
    sb = flow.state_bag or {}
    if sb.get("owner"):
        extras["owner"] = sb["owner"]
    if sb.get("account_name"):
        extras["account_name"] = sb["account_name"]
    if sb.get("account_id"):
        extras["account_id"] = sb["account_id"]
    if not getattr(message, "hipaa", False):
        if message.sender:
            extras["sender"] = message.sender
        if message.subject:
            extras["subject"] = message.subject[:80]
    extras.update(more)
    return extras


class Action(ABC):
    """Execute a single triage action against a classified email."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Short identifier for this action (e.g. 'notify', 'label')."""

    @abstractmethod
    async def execute(
        self,
        flow: FlowState,
        message: EmailMessage,
        classification: Classification,
        provider: EmailProvider,
        config: dict[str, Any] | None = None,
    ) -> ActionOutput:
        """Run the action and return the outcome.

        Parameters
        ----------
        flow:
            Current flow state (for flow_id, state_bag, etc.).
        message:
            The original email message.
        classification:
            The LLM/list classification result.
        provider:
            The email provider, for actions that need to interact with
            the mailbox (draft, label, archive).
        config:
            Optional action-specific configuration.

        Returns
        -------
        ActionOutput with result (COMPLETED/WAITING/FAILED/SKIPPED)
        and optional data/error.
        """
