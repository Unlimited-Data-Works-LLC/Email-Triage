""" — a FAILED action makes triage_single_message return status='e'.

Before the retry-subsystem rebuild, ``triage_single_message`` returned
``status='p'`` (processed) even when the action chain halted on a
``FAILED`` action: the message got dedup-stamped, the cursor advanced,
and it was never retried. The fix returns ``status='e'`` so the caller
enqueues a retry; idempotency makes the already-succeeded earlier
actions safe to re-run.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone

import pytest

from email_triage.actions.base import Action
from email_triage.actions.registry import ActionRegistry
from email_triage.engine.models import (
    ActionOutput, ActionResult, Classification, EmailMessage,
)
from email_triage.web.db import init_db
from email_triage.web.triage_one import TriageContext, triage_single_message


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------

class _FailingAction(Action):
    """An action that always returns FAILED."""

    @property
    def name(self) -> str:
        return "always_fails"

    async def execute(self, flow, message, classification, provider,
                      config=None) -> ActionOutput:
        return ActionOutput(result=ActionResult.FAILED, error="boom")


class _OkAction(Action):
    """An action that always COMPLETES — records that it ran."""

    def __init__(self):
        self.ran = 0

    @property
    def name(self) -> str:
        return "always_ok"

    async def execute(self, flow, message, classification, provider,
                      config=None) -> ActionOutput:
        self.ran += 1
        return ActionOutput(result=ActionResult.COMPLETED, data={})


class _FakeClassifier:
    def __init__(self, category="invoices"):
        self._category = category

    async def classify(self, message, categories, hints):
        return Classification(
            category=self._category, confidence=0.9, reason="t",
        )


@pytest.fixture
def conn() -> sqlite3.Connection:
    c = init_db(":memory:")
    yield c
    c.close()


@pytest.fixture
def account_id(conn: sqlite3.Connection) -> int:
    now = datetime.now(timezone.utc).isoformat()
    cur = conn.execute(
        "INSERT INTO users (email, name, role, created_at) "
        "VALUES ('op@x.com','Op','user',?)", (now,),
    )
    uid = int(cur.lastrowid)
    cur = conn.execute(
        "INSERT INTO email_accounts "
        "(user_id, name, provider_type, config_json, created_at, updated_at)"
        " VALUES (?,?,?,?,?,?)",
        (uid, "M", "imap", "{}", now, now),
    )
    conn.commit()
    return int(cur.lastrowid)


def _msg() -> EmailMessage:
    return EmailMessage(
        message_id="42", provider="imap",
        sender="alice@example.com", recipients=["op@x.com"],
        subject="invoice", body_text="body",
        date=datetime.now(timezone.utc),
        headers={"Message-ID": "<m42@example.com>"},
    )


def _ctx(conn, account_id, registry, routes) -> TriageContext:
    from email_triage.web.db import get_email_account
    acct = get_email_account(conn, account_id)
    return TriageContext(
        db=conn, config=None, secrets=None, acct=acct,
        classifier=_FakeClassifier(), provider=None,
        registry=registry, categories={},
        routes_by_cat=routes,
        durable_dedup=True,
        mark_triaged_on_success=True,
        set_keyword_on_success=False,
        fire_watches=False,
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_failed_action_yields_status_e(conn, account_id):
    """A route whose action FAILs → triage returns status='e'."""
    registry = ActionRegistry()
    registry.register(_FailingAction())
    routes = {"invoices": [{"action": "always_fails", "config": {}}]}

    res = await triage_single_message(
        _ctx(conn, account_id, registry, routes), _msg(), "42",
    )
    assert res.status == "e"
    assert "error" in res.entry


@pytest.mark.asyncio
async def test_failed_action_skips_dedup_stamp(conn, account_id):
    """On a FAILED action the message must NOT be dedup-stamped — a
    retry has to be able to re-process it."""
    from email_triage.web.db import is_triaged
    registry = ActionRegistry()
    registry.register(_FailingAction())
    routes = {"invoices": [{"action": "always_fails", "config": {}}]}

    await triage_single_message(
        _ctx(conn, account_id, registry, routes), _msg(), "42",
    )
    # rfc-id NOT stamped → a retry re-processes the message.
    assert is_triaged(conn, account_id, "<m42@example.com>") is False


@pytest.mark.asyncio
async def test_all_ok_actions_yield_status_p(conn, account_id):
    """A clean action chain still returns status='p' (processed)."""
    ok = _OkAction()
    registry = ActionRegistry()
    registry.register(ok)
    routes = {"invoices": [{"action": "always_ok", "config": {}}]}

    res = await triage_single_message(
        _ctx(conn, account_id, registry, routes), _msg(), "42",
    )
    assert res.status == "p"
    assert ok.ran == 1
