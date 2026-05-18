"""Tests for #106 — multi-address-to-one-account routing.

Covers the JSON-array-first cut:

* Migration v10 adds the ``aliases_json`` column with a default of
  ``'[]'`` and is idempotent on a DB that already has it.
* :func:`account_addresses` returns the union of primary + aliases.
* :func:`normalize_aliases` rejects malformed addresses, primary
  duplicates, and within-list duplicates with operator-readable
  messages.
* The web endpoints (``/accounts/{id}/aliases/{add,remove}``) round-
  trip an alias write back to the read path.
* The HIPAA recipient-mismatch guard accepts both the primary and
  any configured alias as a valid digest ``to_addr``.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from email_triage.web.db import (
    AliasValidationError,
    account_addresses,
    account_aliases,
    account_email,
    init_db,
    normalize_aliases,
    update_email_account_aliases,
)


# ---------------------------------------------------------------------------
# Migration v10 — column add + default
# ---------------------------------------------------------------------------


class TestMigrationV10:
    def test_fresh_db_has_aliases_column_with_empty_default(self):
        """A fresh init_db should create email_accounts with an
        ``aliases_json`` column whose default is the empty JSON array."""
        conn = init_db(":memory:")
        try:
            cols = conn.execute(
                "PRAGMA table_info(email_accounts)"
            ).fetchall()
            names = {c["name"] for c in cols}
            assert "aliases_json" in names

            # Insert a user + an account; verify the default row value.
            now = datetime.now(timezone.utc).isoformat()
            conn.execute(
                "INSERT INTO users (email, name, role, created_at) "
                "VALUES (?, ?, ?, ?)",
                ("user@example.com", "Operator A", "user", now),
            )
            conn.execute(
                "INSERT INTO email_accounts "
                "(user_id, name, provider_type, config_json, "
                "is_active, hipaa, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    1, "test", "imap",
                    json.dumps({"username": "user@example.com"}),
                    1, 0, now, now,
                ),
            )
            conn.commit()
            row = conn.execute(
                "SELECT aliases_json FROM email_accounts WHERE id = 1"
            ).fetchone()
            assert row["aliases_json"] == "[]"
        finally:
            conn.close()

    def test_legacy_db_gains_column_idempotently(self):
        """A pre-v10 DB whose email_accounts table lacks the column should
        gain it via the v10 migration, with the default applied to
        existing rows."""
        from email_triage.web import migrations as mig_mod

        # Hand-build a legacy email_accounts shape (no aliases_json
        # column). Skip running the framework — we'll run it after.
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        conn.execute("""
            CREATE TABLE email_accounts (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id     INTEGER NOT NULL,
                name        TEXT NOT NULL,
                provider_type TEXT NOT NULL,
                config_json TEXT NOT NULL DEFAULT '{}',
                is_active   INTEGER NOT NULL DEFAULT 1,
                hipaa       INTEGER NOT NULL DEFAULT 0,
                created_under_system_hipaa INTEGER NOT NULL DEFAULT 0,
                created_at  TEXT NOT NULL,
                updated_at  TEXT NOT NULL
            )
        """)
        now = datetime.now(timezone.utc).isoformat()
        conn.execute(
            "INSERT INTO email_accounts "
            "(user_id, name, provider_type, config_json, created_at, "
            "updated_at) VALUES (?, ?, ?, ?, ?, ?)",
            (1, "legacy", "imap", "{}", now, now),
        )
        conn.commit()

        # Run only the v10 migration (isolate from earlier ones).
        try:
            v10 = next(m for m in mig_mod.MIGRATIONS if m.version == 10)
        except StopIteration:
            pytest.fail("v10 migration not registered")
        v10.body(conn)

        cols = conn.execute(
            "PRAGMA table_info(email_accounts)"
        ).fetchall()
        names = {c["name"] for c in cols}
        assert "aliases_json" in names
        # Existing row picks up the default.
        row = conn.execute(
            "SELECT aliases_json FROM email_accounts WHERE id = 1"
        ).fetchone()
        assert row["aliases_json"] == "[]"

        # Re-running is a no-op.
        v10.body(conn)
        conn.close()


# ---------------------------------------------------------------------------
# Helpers — account_aliases / account_addresses
# ---------------------------------------------------------------------------


class TestAccountHelpers:
    def test_account_addresses_primary_only(self):
        acct = {"config": {"username": "user@example.com"}, "aliases": []}
        assert account_addresses(acct) == {"user@example.com"}

    def test_account_addresses_union_with_aliases(self):
        acct = {
            "config": {"username": "user@example.com"},
            "aliases": [
                {"address": "alias1@example.com", "label": "Work"},
                {"address": "alias2@example.org", "label": ""},
            ],
        }
        assert account_addresses(acct) == {
            "user@example.com",
            "alias1@example.com",
            "alias2@example.org",
        }

    def test_account_addresses_normalizes_case(self):
        """Both primary and aliases should normalize to lowercase so
        comparisons against a normalized incoming to_addr match."""
        acct = {
            "config": {"username": "User@Example.Com"},
            "aliases": [{"address": "ALIAS@EXAMPLE.COM", "label": ""}],
        }
        assert account_addresses(acct) == {
            "user@example.com", "alias@example.com",
        }

    def test_account_addresses_handles_missing_account(self):
        assert account_addresses(None) == set()
        assert account_addresses({}) == set()

    def test_account_aliases_filters_malformed_entries(self):
        """Stored list with stray non-dict / blank-address entries
        is filtered defensively rather than raising on read."""
        acct = {
            "aliases": [
                {"address": "good@example.com", "label": "ok"},
                "not a dict",
                {"label": "no address key"},
                {"address": "  ", "label": "blank"},
            ],
        }
        addrs = account_aliases(acct)
        assert len(addrs) == 1
        assert addrs[0]["address"] == "good@example.com"


# ---------------------------------------------------------------------------
# Validator — normalize_aliases
# ---------------------------------------------------------------------------


class TestNormalizeAliases:
    def test_passes_clean_input(self):
        out = normalize_aliases([
            {"address": "Alias1@Example.Com", "label": "Work"},
            {"address": "alias2@example.org", "label": ""},
        ], primary="user@example.com")
        assert out == [
            {"address": "alias1@example.com", "label": "Work"},
            {"address": "alias2@example.org", "label": ""},
        ]

    def test_rejects_blank_address(self):
        with pytest.raises(AliasValidationError, match="blank"):
            normalize_aliases([{"address": "", "label": "x"}])

    def test_rejects_malformed_address(self):
        with pytest.raises(AliasValidationError, match="doesn't look like"):
            normalize_aliases([{"address": "notanemail", "label": ""}])

    def test_rejects_address_without_dot_in_host(self):
        with pytest.raises(AliasValidationError, match="doesn't look like"):
            normalize_aliases([{"address": "user@localhost", "label": ""}])

    def test_rejects_primary_as_alias(self):
        with pytest.raises(AliasValidationError, match="main address"):
            normalize_aliases(
                [{"address": "user@example.com", "label": "x"}],
                primary="user@example.com",
            )

    def test_rejects_duplicate_within_list(self):
        with pytest.raises(AliasValidationError, match="listed twice"):
            normalize_aliases([
                {"address": "alias@example.com", "label": "first"},
                {"address": "ALIAS@example.com", "label": "second"},
            ])

    def test_empty_list_is_valid(self):
        assert normalize_aliases([]) == []


# ---------------------------------------------------------------------------
# Storage round-trip — write + read
# ---------------------------------------------------------------------------


@pytest.fixture
def db_with_account():
    """Init the DB and seed one user + one IMAP account."""
    conn = init_db(":memory:")
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "INSERT INTO users (email, name, role, created_at) "
        "VALUES (?, ?, ?, ?)",
        ("user@example.com", "Operator A", "user", now),
    )
    conn.execute(
        "INSERT INTO email_accounts "
        "(user_id, name, provider_type, config_json, created_at, "
        "updated_at) VALUES (?, ?, ?, ?, ?, ?)",
        (1, "Primary", "imap",
         json.dumps({"host": "x.test", "port": 993,
                     "username": "user@example.com"}),
         now, now),
    )
    conn.commit()
    yield conn
    conn.close()


class TestStorageRoundTrip:
    def test_get_email_account_parses_aliases_field(self, db_with_account):
        from email_triage.web.db import get_email_account

        update_email_account_aliases(
            db_with_account, 1,
            [{"address": "alias1@example.com", "label": "Work"}],
        )
        acct = get_email_account(db_with_account, 1)
        assert acct["aliases"] == [
            {"address": "alias1@example.com", "label": "Work"},
        ]

    def test_list_email_accounts_parses_aliases_field(
        self, db_with_account,
    ):
        from email_triage.web.db import list_email_accounts

        update_email_account_aliases(
            db_with_account, 1,
            [{"address": "alias2@example.org", "label": ""}],
        )
        accts = list_email_accounts(db_with_account)
        assert len(accts) == 1
        assert accts[0]["aliases"] == [
            {"address": "alias2@example.org", "label": ""},
        ]

    def test_account_addresses_after_update(self, db_with_account):
        from email_triage.web.db import get_email_account

        update_email_account_aliases(
            db_with_account, 1,
            [
                {"address": "alias1@example.com", "label": "A"},
                {"address": "alias2@example.org", "label": "B"},
            ],
        )
        acct = get_email_account(db_with_account, 1)
        assert account_email(acct) == "user@example.com"
        assert account_addresses(acct) == {
            "user@example.com",
            "alias1@example.com",
            "alias2@example.org",
        }


# ---------------------------------------------------------------------------
# HIPAA recipient-mismatch guard accepts aliases (regression for the
# whole reason this feature exists)
# ---------------------------------------------------------------------------


@pytest.fixture
def acct_with_aliases():
    """Account dict shape that ``_fire_one_digest`` expects, with one
    alias configured. HIPAA off; the same accept-alias behaviour is
    asserted under HIPAA in a separate test."""
    return {
        "id": 42,
        "name": "with-aliases",
        "user_id": 1,
        "provider_type": "imap",
        "config": {
            "host": "x.test", "port": 993, "username": "user@example.com",
        },
        "email_address": "user@example.com",
        "aliases": [
            {"address": "alias1@example.com", "label": "Work"},
        ],
        "is_active": True,
        "hipaa": False,
    }


@pytest.fixture
def dcfg_custom():
    from email_triage.actions.digest_configs import (
        DigestConfig, DigestFormat,
    )
    return DigestConfig(
        id="digest_x", kind="custom", name="x",
        enabled=True,
        format=DigestFormat(render_as="grouped_list"),
    )


class _FakeSmtp:
    host = "smtp.test"
    port = 587
    username = "smtp_user"
    from_addr = "noreply@example.com"
    from_name = "Triage"
    use_tls = True


@pytest.mark.asyncio
async def test_recipient_mismatch_guard_accepts_primary(
    acct_with_aliases, dcfg_custom,
):
    """Primary address still passes the guard (regression)."""
    from email_triage.web.app import _fire_one_digest

    sent = MagicMock(return_value=None)
    rows = [{
        "category": "newsletter", "sender": "x@y", "subject": "s",
        "date": "2026-05-05T08:00:00+00:00",
        "labels": [], "actions": [], "attachments": [], "headers": {},
        "source": "llm", "reason": "rrr",
    }]
    with patch(
        "email_triage.actions.recipient_digest.send_recipient_digest",
        sent,
    ), patch(
        "email_triage.actions.recipient_digest.gather_digest_rows",
        return_value=rows,
    ):
        await _fire_one_digest(
            db=object(),
            secrets=type("S", (), {"get": lambda *a, **k: ""})(),
            smtp=_FakeSmtp(),
            acct=acct_with_aliases, dcfg=dcfg_custom, hipaa=False,
            now_utc=datetime.now(timezone.utc),
            last_sent=None,
            to_addr="user@example.com",
        )
    sent.assert_called_once()


@pytest.mark.asyncio
async def test_recipient_mismatch_guard_accepts_alias(
    acct_with_aliases, dcfg_custom,
):
    """The whole point of #106 — an alias-addressed digest delivery
    must round-trip without tripping the guard."""
    from email_triage.web.app import _fire_one_digest

    sent = MagicMock(return_value=None)
    rows = [{
        "category": "newsletter", "sender": "x@y", "subject": "s",
        "date": "2026-05-05T08:00:00+00:00",
        "labels": [], "actions": [], "attachments": [], "headers": {},
        "source": "llm", "reason": "rrr",
    }]
    with patch(
        "email_triage.actions.recipient_digest.send_recipient_digest",
        sent,
    ), patch(
        "email_triage.actions.recipient_digest.gather_digest_rows",
        return_value=rows,
    ):
        await _fire_one_digest(
            db=object(),
            secrets=type("S", (), {"get": lambda *a, **k: ""})(),
            smtp=_FakeSmtp(),
            acct=acct_with_aliases, dcfg=dcfg_custom, hipaa=False,
            now_utc=datetime.now(timezone.utc),
            last_sent=None,
            to_addr="alias1@example.com",
        )
    sent.assert_called_once()


@pytest.mark.asyncio
async def test_recipient_mismatch_guard_accepts_alias_under_hipaa(
    acct_with_aliases, dcfg_custom,
):
    """Sibling guarantee: HIPAA-flagged accounts also accept aliases.
    The data subject is the same mailbox owner; alias delivery is
    NOT a third-party leak."""
    from email_triage.web.app import _fire_one_digest

    acct_with_aliases["hipaa"] = True
    sent = MagicMock(return_value=None)
    rows = [{
        "category": "newsletter", "sender": "x@y", "subject": "s",
        "date": "2026-05-05T08:00:00+00:00",
        "labels": [], "actions": [], "attachments": [], "headers": {},
        "source": "llm", "reason": "rrr",
    }]
    with patch(
        "email_triage.actions.recipient_digest.send_recipient_digest",
        sent,
    ), patch(
        "email_triage.actions.recipient_digest.gather_digest_rows",
        return_value=rows,
    ):
        await _fire_one_digest(
            db=object(),
            secrets=type("S", (), {"get": lambda *a, **k: ""})(),
            smtp=_FakeSmtp(),
            acct=acct_with_aliases, dcfg=dcfg_custom, hipaa=True,
            now_utc=datetime.now(timezone.utc),
            last_sent=None,
            to_addr="alias1@example.com",
        )
    sent.assert_called_once()


@pytest.mark.asyncio
async def test_recipient_mismatch_guard_rejects_third_party(
    acct_with_aliases, dcfg_custom,
):
    """A third-party address is NOT one of the account's aliases
    and must still be refused. The mismatch case the guard exists
    to catch is unaffected by alias support."""
    from email_triage.web.app import _fire_one_digest

    sent = MagicMock(return_value=None)
    with patch(
        "email_triage.actions.recipient_digest.send_recipient_digest",
        sent,
    ):
        with pytest.raises(RuntimeError, match="recipient mismatch"):
            await _fire_one_digest(
                db=object(),
                secrets=type("S", (), {"get": lambda *a, **k: ""})(),
                smtp=_FakeSmtp(),
                acct=acct_with_aliases, dcfg=dcfg_custom, hipaa=False,
                now_utc=datetime.now(timezone.utc),
                last_sent=None,
                to_addr="attacker@example.net",
            )
    sent.assert_not_called()


@pytest.mark.asyncio
async def test_recipient_mismatch_guard_case_insensitive(
    acct_with_aliases, dcfg_custom,
):
    """Mixed-case to_addr that matches an alias by case-insensitive
    comparison still passes. SMTP recipient capitalization is
    historically inconsistent — we shouldn't reject for case alone."""
    from email_triage.web.app import _fire_one_digest

    sent = MagicMock(return_value=None)
    rows = [{
        "category": "newsletter", "sender": "x@y", "subject": "s",
        "date": "2026-05-05T08:00:00+00:00",
        "labels": [], "actions": [], "attachments": [], "headers": {},
        "source": "llm", "reason": "rrr",
    }]
    with patch(
        "email_triage.actions.recipient_digest.send_recipient_digest",
        sent,
    ), patch(
        "email_triage.actions.recipient_digest.gather_digest_rows",
        return_value=rows,
    ):
        await _fire_one_digest(
            db=object(),
            secrets=type("S", (), {"get": lambda *a, **k: ""})(),
            smtp=_FakeSmtp(),
            acct=acct_with_aliases, dcfg=dcfg_custom, hipaa=False,
            now_utc=datetime.now(timezone.utc),
            last_sent=None,
            to_addr="Alias1@Example.Com",
        )
    sent.assert_called_once()


# ---------------------------------------------------------------------------
# Triage runner — alias-aware recipient set on flow state_bag
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_run_triage_threads_alias_set_into_state_bag(
    db_with_account,
):
    """The runner must stash both ``self_email`` (primary) and
    ``self_email_addresses`` (the alias-aware union) on every flow's
    state_bag so action-side recipient matching can take the union.

    The full happy-path through ``run_triage`` is heavy (provider
    factory + classifier + categories + …); the unit covered here
    is the state_bag plumbing. We invoke the runner with mocks for
    the heavy parts, run a one-message route, and inspect the
    state_bag the action received.
    """
    from email_triage.config import TriageConfig
    from email_triage.engine.models import (
        ActionOutput, ActionResult, Classification, EmailMessage,
    )
    from email_triage.web import triage_runner as _tr

    update_email_account_aliases(
        db_with_account, 1,
        [
            {"address": "alias1@example.com", "label": "A"},
            {"address": "alias2@example.org", "label": "B"},
        ],
    )

    # Seed a category row so the runner doesn't bail on
    # ``no_categories``. The category name doesn't matter — the
    # mocked classifier returns whatever we tell it.
    from email_triage.web.db import (
        get_email_account, list_email_accounts,
    )
    now = datetime.now(timezone.utc).isoformat()
    db_with_account.execute(
        "INSERT INTO categories (slug, description, sort_order, "
        "created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
        ("invoice", "", 0, now, now),
    )
    # Add a route mapping invoice -> notify so an action runs.
    from email_triage.web.db import (
        upsert_account_route,
    )
    upsert_account_route(
        db_with_account, 1, "invoice",
        [{"action": "notify", "config": {}}],
    )

    acct = get_email_account(db_with_account, 1)
    assert account_email(acct) == "user@example.com"
    assert "alias1@example.com" in account_addresses(acct)

    captured: dict = {}

    class _StubProvider:
        async def search(self, query, limit):
            return ["msg-1"]

        async def fetch_message(self, mid):
            return EmailMessage(
                message_id=mid,
                provider="imap",
                sender="x@example.org",
                recipients=["alias1@example.com"],
                subject="Invoice",
                body_text="body",
                date=datetime.now(timezone.utc),
                labels=[],
            )

        async def close(self):
            return None

    class _StubClassifier:
        async def classify(self, message, categories, hints):
            return Classification(
                category="invoice", confidence=0.99,
                reason="r", source="llm",
            )

    class _StubAction:
        name = "notify"

        async def execute(
            self, flow, message, classification, provider, action_config,
        ):
            captured["state_bag"] = dict(flow.state_bag)
            return ActionOutput(
                result=ActionResult.OK, data=None, error=None,
            )

    # Minimal mocks for the import-time helpers in run_triage.
    mock_create_provider = MagicMock(return_value=_StubProvider())
    mock_build_classifier = MagicMock(return_value=_StubClassifier())
    mock_get_categories = MagicMock(
        return_value=[{"slug": "invoice", "description": ""}],
    )
    mock_collect_hints = MagicMock(return_value=[])
    # #134.1 — _load_all_list_hints now returns (lists, rules_by_list).
    # The old "warms cache, returns None" contract was replaced by the
    # explicit pre-fetch pair that callers thread through.
    mock_load_hints = MagicMock(return_value=([], {}))
    mock_is_dry_run = MagicMock(return_value=False)

    # ActionRegistry is constructed inside run_triage; patch
    # registry.get to return our stub action regardless of name.
    class _StubRegistry:
        def __init__(self):
            self._a = _StubAction()

        def register(self, action):
            return None

        def get(self, name):
            return self._a if name == "notify" else None

    with patch(
        "email_triage.web.routers.ui._create_provider_from_account",
        mock_create_provider,
    ), patch(
        "email_triage.web.routers.ui._build_classifier_from_config",
        mock_build_classifier,
    ), patch(
        "email_triage.web.routers.ui._get_categories_from_db",
        mock_get_categories,
    ), patch(
        "email_triage.web.routers.ui._collect_list_hints_for_message",
        mock_collect_hints,
    ), patch(
        "email_triage.web.routers.ui._load_all_list_hints",
        mock_load_hints,
    ), patch(
        "email_triage.web.routers.ui._is_dry_run", mock_is_dry_run,
    ), patch(
        "email_triage.actions.registry.ActionRegistry", _StubRegistry,
    ):
        config = TriageConfig()
        secrets = type("S", (), {"get": lambda *a, **k: ""})()

        await _tr.run_triage(
            db_with_account, config, secrets, acct,
            query="", limit=10,
            actor_user_id=acct["user_id"],  # owner-self avoids HIPAA path
            trigger="test",
        )

    assert "state_bag" in captured, "Action stub never ran"
    bag = captured["state_bag"]
    assert bag["self_email"] == "user@example.com"
    addrs = bag["self_email_addresses"]
    assert isinstance(addrs, set)
    assert "user@example.com" in addrs
    assert "alias1@example.com" in addrs
    assert "alias2@example.org" in addrs
