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


def check_idempotent_already_done(
    flow: FlowState, message: EmailMessage, action_name: str,
) -> ActionOutput | None:
    """Return a SKIPPED ActionOutput if this action already ran for
    this (flow, message); else None.

    Call from the top of an Action.execute() that has external side
    effects. The ``message_id`` used for hashing is whichever the
    provider returns — Gmail thread IDs, IMAP UIDs, Office365
    message IDs all qualify, since we're hashing for equality, not
    cross-provider correlation.
    """
    bag = flow.state_bag or {}
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


def record_idempotent_done(
    flow: FlowState,
    message: EmailMessage,
    action_name: str,
    *,
    external_id: str | None = None,
) -> None:
    """Stamp the state_bag entry that ``check_idempotent_already_done``
    consumes on retry.

    Mutates ``flow.state_bag`` in place. The engine's update_flow
    after the action chain finishes persists state_bag back to
    the flows row.
    """
    if flow.state_bag is None:
        flow.state_bag = {}
    results = flow.state_bag.setdefault("action_results", {})
    results[action_name] = {
        "idempotency_key": _compute_idempotency_key(
            flow.flow_id, action_name,
            getattr(message, "message_id", None),
        ),
        "external_id": external_id,
        "completed_at": datetime.now(timezone.utc).isoformat(),
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
    identifiers (per item #11), not PHI even on HIPAA accounts; the
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
