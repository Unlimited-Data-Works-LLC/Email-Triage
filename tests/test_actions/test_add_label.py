"""Tests for ``AddLabelAction`` — punch-list item #129 tail.

Covers the new route-action that attaches internal labels (via the
``message_labels`` junction table) and/or provider-native labels
(via ``provider.apply_label``) when a route fires.

Mirrors the test pattern in ``test_actions.py`` for ``LabelAction``
(close cousin — same provider API, different config shape) and the
HIPAA-gate pattern in ``test_idempotency.py``.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from unittest.mock import AsyncMock

import pytest

from email_triage.actions.add_label import AddLabelAction, _normalise_string_list
from email_triage.engine.models import (
    ActionResult,
    Classification,
    EmailMessage,
    FlowState,
    FlowStatus,
)


# ---------------------------------------------------------------------------
# Builders
# ---------------------------------------------------------------------------

def _make_flow(state_bag: dict | None = None) -> FlowState:
    return FlowState(
        flow_id="f-add-label-1",
        message_id="m-1",
        provider="imap",
        status=FlowStatus.ACTING,
        state_bag=state_bag if state_bag is not None else {},
    )


def _make_message(
    message_id: str = "m-1",
    *,
    hipaa: bool = False,
) -> EmailMessage:
    msg = EmailMessage(
        message_id=message_id,
        provider="imap",
        sender="alice@example.com",
        recipients=["bob@example.com"],
        subject="Receipt for order #42",
        body_text="Thanks for shopping.",
        date=datetime(2026, 5, 13, 14, 30, tzinfo=timezone.utc),
    )
    msg.hipaa = hipaa
    return msg


def _make_classification(category: str = "receipts") -> Classification:
    return Classification(
        category=category, confidence=0.9, reason="rule match",
    )


def _make_provider() -> AsyncMock:
    p = AsyncMock()
    p.name = "imap"
    return p


# ---------------------------------------------------------------------------
# In-memory DB fixture for the internal-label apply path
# ---------------------------------------------------------------------------

@pytest.fixture
def _db_with_labels(tmp_path):
    """Minimal SQLite DB carrying the labels + message_labels schema
    and one user + email_accounts row so the apply helper can be
    exercised without spinning up the full web app."""
    from email_triage.web.migrations import _v18_create_labels
    db = sqlite3.connect(":memory:")
    db.row_factory = sqlite3.Row
    # Tables referenced by the schema's foreign keys. Minimal stand-ins
    # for the v1 base schema's users + email_accounts tables.
    db.execute(
        "CREATE TABLE users ("
        "id INTEGER PRIMARY KEY, email TEXT, role TEXT)"
    )
    db.execute(
        "CREATE TABLE email_accounts ("
        "id INTEGER PRIMARY KEY, user_id INTEGER, name TEXT)"
    )
    db.execute("INSERT INTO users (id, email, role) VALUES (1, 'a@b', 'user')")
    db.execute(
        "INSERT INTO email_accounts (id, user_id, name) VALUES (42, 1, 'acct')"
    )
    # _v18_create_labels also column-guards list_rules.adds_labels —
    # stub the table to satisfy the PRAGMA + ALTER TABLE inside the
    # migration. No rows; we never exercise rule-driven applies here.
    db.execute(
        "CREATE TABLE list_rules ("
        "id INTEGER PRIMARY KEY, list_id INTEGER, rule_type TEXT, "
        "pattern TEXT)"
    )
    _v18_create_labels(db)
    # Seed two labels.
    now = datetime.now(timezone.utc).isoformat()
    db.execute(
        "INSERT INTO labels (slug, name, color, created_by_user_id, "
        "created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
        ("receipts", "Receipts", "#5b9", 1, now, now),
    )
    db.execute(
        "INSERT INTO labels (slug, name, color, created_by_user_id, "
        "created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
        ("tax-2026", "Tax 2026", "#fa0", 1, now, now),
    )
    db.commit()
    return db


# ---------------------------------------------------------------------------
# Empty / no-op
# ---------------------------------------------------------------------------

class TestAddLabelEmpty:
    async def test_no_config_skips(self):
        provider = _make_provider()
        action = AddLabelAction()
        out = await action.execute(
            _make_flow(), _make_message(), _make_classification(),
            provider, config=None,
        )
        assert out.result == ActionResult.SKIPPED
        provider.apply_label.assert_not_called()

    async def test_empty_lists_skip(self):
        provider = _make_provider()
        action = AddLabelAction()
        out = await action.execute(
            _make_flow(), _make_message(), _make_classification(),
            provider, config={"labels": [], "provider_labels": []},
        )
        assert out.result == ActionResult.SKIPPED
        provider.apply_label.assert_not_called()


# ---------------------------------------------------------------------------
# Provider-native labels
# ---------------------------------------------------------------------------

class TestAddLabelProviderNative:
    async def test_applies_all_provider_labels(self):
        provider = _make_provider()
        action = AddLabelAction()
        out = await action.execute(
            _make_flow(), _make_message(), _make_classification(),
            provider,
            config={"provider_labels": ["Receipts/2026", "Tax"]},
        )
        assert out.result == ActionResult.COMPLETED
        # Both labels were attempted on the provider.
        assert provider.apply_label.call_count == 2
        assert out.data["provider_applied"] == ["Receipts/2026", "Tax"]

    async def test_skips_remainder_when_provider_unsupported(self):
        provider = _make_provider()
        provider.apply_label.side_effect = NotImplementedError("no labels")
        action = AddLabelAction()
        out = await action.execute(
            _make_flow(), _make_message(), _make_classification(),
            provider,
            config={"provider_labels": ["a", "b", "c"]},
        )
        # First call raises NotImplementedError → skip remainder.
        # No internal labels configured, so the overall result is SKIPPED.
        assert out.result == ActionResult.SKIPPED
        assert provider.apply_label.call_count == 1
        # Every name ends up in provider_skipped because no apply succeeded.
        assert set(out.data["provider_skipped"]) == {"a", "b", "c"}

    async def test_provider_error_reported(self):
        provider = _make_provider()
        provider.apply_label.side_effect = RuntimeError("API 500")
        action = AddLabelAction()
        out = await action.execute(
            _make_flow(), _make_message(), _make_classification(),
            provider,
            config={"provider_labels": ["Receipts/2026"]},
        )
        assert out.result == ActionResult.FAILED
        # ``fmt_exc`` returns str(exc) when non-empty; the action wraps
        # it with the per-label site prefix so operators can attribute
        # the failure to a specific provider-native name.
        assert "API 500" in (out.error or "")
        assert "Receipts/2026" in (out.error or "")


# ---------------------------------------------------------------------------
# Internal labels
# ---------------------------------------------------------------------------

class TestAddLabelInternal:
    async def test_internal_labels_applied(self, _db_with_labels):
        provider = _make_provider()
        action = AddLabelAction()
        flow = _make_flow(state_bag={
            "db": _db_with_labels,
            "account_id": 42,
            "actor_user_id": 1,
        })
        out = await action.execute(
            flow, _make_message(message_id="m-X"),
            _make_classification(),
            provider,
            config={"labels": ["receipts", "tax-2026"]},
        )
        assert out.result == ActionResult.COMPLETED
        assert set(out.data["internal_applied"]) == {"receipts", "tax-2026"}
        # message_labels rows landed.
        rows = _db_with_labels.execute(
            "SELECT label_slug FROM message_labels WHERE message_id = ?",
            ("m-X",),
        ).fetchall()
        slugs = {r["label_slug"] for r in rows}
        assert slugs == {"receipts", "tax-2026"}
        # Provider not touched — no provider_labels configured.
        provider.apply_label.assert_not_called()

    async def test_internal_skips_silently_without_db(self):
        """CLI / engine path without web-DB plumbing — internal labels
        are skipped but the action still completes if provider labels
        applied. Mirrors the action docstring's note on portability."""
        provider = _make_provider()
        action = AddLabelAction()
        flow = _make_flow(state_bag={})  # no db, no account_id
        out = await action.execute(
            flow, _make_message(), _make_classification(),
            provider,
            config={
                "labels": ["receipts"],
                "provider_labels": ["Receipts/2026"],
            },
        )
        assert out.result == ActionResult.COMPLETED
        assert out.data["internal_applied"] == []
        assert out.data["provider_applied"] == ["Receipts/2026"]

    async def test_unknown_slug_dropped_silently(self, _db_with_labels):
        """Slugs not in the catalog are silently dropped at the DB
        helper layer. The action reports what it ATTEMPTED, so the
        catch is at the helper level — INSERT-OR-IGNORE behaviour."""
        provider = _make_provider()
        action = AddLabelAction()
        flow = _make_flow(state_bag={
            "db": _db_with_labels,
            "account_id": 42,
            "actor_user_id": 1,
        })
        out = await action.execute(
            flow, _make_message(message_id="m-Y"),
            _make_classification(),
            provider,
            config={"labels": ["receipts", "no-such-label"]},
        )
        assert out.result == ActionResult.COMPLETED
        # Action reports the attempt list (the helper filters silently).
        assert "receipts" in out.data["internal_applied"]
        rows = _db_with_labels.execute(
            "SELECT label_slug FROM message_labels WHERE message_id = ?",
            ("m-Y",),
        ).fetchall()
        assert {r["label_slug"] for r in rows} == {"receipts"}


# ---------------------------------------------------------------------------
# HIPAA gate — provider labels skipped, internal stays
# ---------------------------------------------------------------------------

class TestAddLabelHipaaGate:
    async def test_hipaa_skips_provider_keeps_internal(self, _db_with_labels):
        """The PROVIDER portion is skipped on HIPAA accounts (label
        names can leak subject hints upstream). INTERNAL labels still
        land — they live in the install DB only."""
        provider = _make_provider()
        action = AddLabelAction()
        flow = _make_flow(state_bag={
            "db": _db_with_labels,
            "account_id": 42,
            "actor_user_id": 1,
        })
        msg = _make_message(message_id="m-Z", hipaa=True)
        out = await action.execute(
            flow, msg, _make_classification(),
            provider,
            config={
                "labels": ["receipts"],
                "provider_labels": ["PHI-leak/PatientLabResults"],
            },
        )
        # Internal applied → overall COMPLETED.
        assert out.result == ActionResult.COMPLETED
        assert out.data["internal_applied"] == ["receipts"]
        assert out.data["provider_applied"] == []
        assert "PHI-leak/PatientLabResults" in out.data["provider_skipped"]
        # Provider.apply_label was never called.
        provider.apply_label.assert_not_called()

    async def test_hipaa_only_provider_labels_skips_overall(self):
        provider = _make_provider()
        action = AddLabelAction()
        msg = _make_message(hipaa=True)
        out = await action.execute(
            _make_flow(), msg, _make_classification(),
            provider,
            config={"provider_labels": ["PHI/leaky-label"]},
        )
        # Nothing applied (HIPAA gated provider; no internal).
        assert out.result == ActionResult.SKIPPED
        assert out.data["reason"] == "hipaa_mode"
        provider.apply_label.assert_not_called()


# ---------------------------------------------------------------------------
# Input normalisation
# ---------------------------------------------------------------------------

class TestNormaliseStringList:
    def test_list_input(self):
        out = _normalise_string_list(["a", "b", "a"], lower=False)
        assert out == ["a", "b"]

    def test_string_input_splits_on_comma(self):
        out = _normalise_string_list("a, b ,c", lower=False)
        assert out == ["a", "b", "c"]

    def test_lowercase_flag(self):
        out = _normalise_string_list(["Foo", "BAR"], lower=True)
        assert out == ["foo", "bar"]

    def test_none_returns_empty(self):
        assert _normalise_string_list(None, lower=False) == []

    def test_drops_blank_entries(self):
        assert _normalise_string_list(["a", "", "  ", "b"], lower=False) == ["a", "b"]


# ---------------------------------------------------------------------------
# Action registry — wired in all three sites
# ---------------------------------------------------------------------------

class TestAddLabelRegistered:
    def test_action_name(self):
        assert AddLabelAction().name == "add-label"

    def test_registered_in_cli_engine_builder(self):
        """The CLI's ``_build_engine`` must register the new action so
        a non-web caller can invoke an ``add-label``-bearing route."""
        # Source-grep is enough — full _build_engine instantiation
        # requires a YAML config + provider. The registration line is
        # the contract.
        from pathlib import Path
        src = (
            Path(__file__).parent.parent.parent
            / "src" / "email_triage" / "cli.py"
        ).read_text(encoding="utf-8")
        assert "AddLabelAction()" in src
        assert "from email_triage.actions.add_label import AddLabelAction" in src

    def test_registered_in_inline_triage_runner(self):
        from pathlib import Path
        src = (
            Path(__file__).parent.parent.parent
            / "src" / "email_triage" / "web" / "triage_runner.py"
        ).read_text(encoding="utf-8")
        assert "AddLabelAction()" in src

    def test_registered_in_bulk_triage_runner(self):
        from pathlib import Path
        src = (
            Path(__file__).parent.parent.parent
            / "src" / "email_triage" / "web" / "triage_runner_bulk.py"
        ).read_text(encoding="utf-8")
        assert "AddLabelAction()" in src
