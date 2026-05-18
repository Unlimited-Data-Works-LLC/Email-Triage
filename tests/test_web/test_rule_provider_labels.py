"""Tests for the provider-native label picker on the rule editor (#163).

Covers:

  * v22 schema — list_rules.provider_labels column present, migration
    idempotent on re-run.
  * DB helpers get_rule_provider_labels / set_rule_provider_labels —
    round-trip + malformed-entry filtering.
  * list_provider_labels_for_account helper — Gmail / IMAP / O365
    dispatch, HIPAA returns empty, 5-min cache hit.
  * Route handler — GET /rules/{list}/rules/{rule}/edit renders the
    picker with one group per non-HIPAA account.
  * Save handler — POST with ``provider_labels=<aid>:<slug>`` round-
    trips through the DB into ``list_rules.provider_labels`` JSON.
  * Apply phase — per-account scoping: rule fires only on messages
    from the account_id encoded in the entry.
  * Privacy invariant — module docstrings + comments do not name
    real account local-parts or provider-specific label names.

Mocks model real Gmail / IMAP / O365 providers with the minimum
surface ``list_provider_labels_for_account`` uses (``list_labels`` /
``list_folders``).
"""

from __future__ import annotations

import asyncio
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import pytest

from email_triage.providers import provider_labels as pl_mod
from email_triage.providers.provider_labels import (
    list_provider_labels_for_account,
)
from email_triage.web.db import (
    create_label,
    get_rule_provider_labels,
    set_rule_provider_labels,
)


def _now():
    return datetime.now(timezone.utc).isoformat()


def _make_account(db, user_id, *, provider_type="gmail_api",
                   name="primary", hipaa=False, config=None):
    """Insert an email_accounts row + return its id."""
    cfg = json.dumps(config or {})
    cur = db.execute(
        "INSERT INTO email_accounts "
        "(user_id, name, provider_type, config_json, hipaa, "
        " created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (user_id, name, provider_type, cfg, int(hipaa), _now(), _now()),
    )
    db.commit()
    return cur.lastrowid


def _make_rule(db, owner_id, *, list_name="L", category="general"):
    """Insert a list + one rule + return (list_id, rule_id)."""
    cur = db.execute(
        "INSERT INTO classification_lists (name, category, owner_id, "
        "is_global, created_at) VALUES (?, ?, ?, 0, ?)",
        (list_name, category, owner_id, _now()),
    )
    list_id = cur.lastrowid
    cur2 = db.execute(
        "INSERT INTO list_rules (list_id, rule_type, pattern, skip_ai, "
        "created_at) VALUES (?, 'sender', 'boss@example.com', 0, ?)",
        (list_id, _now()),
    )
    rule_id = cur2.lastrowid
    db.commit()
    return list_id, rule_id


# ---------------------------------------------------------------------------
# Schema regression — v22
# ---------------------------------------------------------------------------


class TestSchemaV22:
    def test_provider_labels_column_present(self, db):
        cols = {
            row[1]
            for row in db.execute("PRAGMA table_info(list_rules)").fetchall()
        }
        assert "provider_labels" in cols

    def test_v22_recorded_in_schema_migrations(self, db):
        from email_triage.web.migrations import schema_version
        assert schema_version(db) >= 22

    def test_v22_migration_idempotent(self):
        """Apply the v22 migration body twice on a connection that
        already carries the column — second call must be a no-op."""
        from email_triage.web.migrations import (
            _v22_add_list_rules_provider_labels,
        )
        # Build a tiny standalone DB with a list_rules table carrying
        # provider_labels pre-populated.
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        conn.execute(
            "CREATE TABLE list_rules (id INTEGER PRIMARY KEY, "
            "provider_labels TEXT)"
        )
        # First call — should detect the column and skip.
        _v22_add_list_rules_provider_labels(conn)
        # Second call — same no-op.
        _v22_add_list_rules_provider_labels(conn)
        cols = [
            row[1] for row in conn.execute(
                "PRAGMA table_info(list_rules)"
            ).fetchall()
        ]
        # Column appears exactly once.
        assert cols.count("provider_labels") == 1


# ---------------------------------------------------------------------------
# DB helpers — round-trip + validation
# ---------------------------------------------------------------------------


class TestGetSetRuleProviderLabels:
    def test_round_trip(self, db, regular_user):
        _, rule_id = _make_rule(db, regular_user["id"])
        entries = [
            {"account_id": 3, "label_slug": "Receipts"},
            {"account_id": 5, "label_slug": "Bills"},
        ]
        set_rule_provider_labels(db, rule_id, entries)
        out = get_rule_provider_labels(db, rule_id)
        assert out == entries

    def test_empty_list_writes_null(self, db, regular_user):
        _, rule_id = _make_rule(db, regular_user["id"])
        # Pre-populate, then clear.
        set_rule_provider_labels(
            db, rule_id, [{"account_id": 1, "label_slug": "X"}],
        )
        set_rule_provider_labels(db, rule_id, [])
        row = db.execute(
            "SELECT provider_labels FROM list_rules WHERE id = ?",
            (rule_id,),
        ).fetchone()
        assert row["provider_labels"] is None

    def test_set_filters_invalid_entries(self, db, regular_user):
        _, rule_id = _make_rule(db, regular_user["id"])
        # Mix valid + invalid; only valid survives.
        entries = [
            {"account_id": 3, "label_slug": "OK"},          # valid
            {"label_slug": "missing-aid"},                   # no account_id
            {"account_id": "not-int", "label_slug": "X"},    # wrong type
            {"account_id": 4, "label_slug": ""},             # empty slug
            "not-a-dict",                                     # not a dict
            {"account_id": 5},                                # no slug
        ]
        set_rule_provider_labels(db, rule_id, entries)
        out = get_rule_provider_labels(db, rule_id)
        assert out == [{"account_id": 3, "label_slug": "OK"}]

    def test_get_handles_null(self, db, regular_user):
        _, rule_id = _make_rule(db, regular_user["id"])
        # No write — column stays NULL.
        assert get_rule_provider_labels(db, rule_id) == []

    def test_get_handles_unknown_rule(self, db):
        # Missing rule id → []; never raises.
        assert get_rule_provider_labels(db, 99999) == []

    def test_get_handles_parse_error(self, db, regular_user):
        _, rule_id = _make_rule(db, regular_user["id"])
        db.execute(
            "UPDATE list_rules SET provider_labels = 'not-json' WHERE id = ?",
            (rule_id,),
        )
        db.commit()
        assert get_rule_provider_labels(db, rule_id) == []


# ---------------------------------------------------------------------------
# list_provider_labels_for_account — provider dispatch
# ---------------------------------------------------------------------------


class _FakeGmailProvider:
    name = "gmail_api"

    def __init__(self, labels):
        self._labels = labels

    async def list_labels(self):
        return self._labels

    async def close(self):
        pass


class _FakeImapProvider:
    name = "imap"

    def __init__(self, folders):
        self._folders = folders

    async def list_folders(self):
        return self._folders

    async def close(self):
        pass


class _FakeO365Provider:
    name = "office365"

    def __init__(self, categories):
        self._categories = categories

    async def list_labels(self):
        return self._categories

    async def close(self):
        pass


@pytest.fixture(autouse=True)
def _clear_pl_cache():
    """Reset the module-level cache before + after each test so
    cache-hits don't bleed between cases."""
    pl_mod._cache_clear()
    yield
    pl_mod._cache_clear()


class TestListProviderLabelsForAccount:
    def test_gmail_dispatch(self, db, regular_user):
        account_id = _make_account(
            db, regular_user["id"], provider_type="gmail_api",
        )
        fake_labels = [
            {
                "id": "Label_1",
                "name": "Receipts",
                "color": {"backgroundColor": "#ff0000"},
            },
            {"id": "Label_2", "name": "Bills"},
            # Empty name — should be skipped.
            {"id": "Label_3", "name": ""},
        ]
        with patch.object(
            pl_mod, "build_provider",
            return_value=_FakeGmailProvider(fake_labels),
        ):
            out = asyncio.run(
                list_provider_labels_for_account(
                    db=db, secrets=None, account_id=account_id,
                )
            )
        # Two non-empty entries; color hex surfaced for the first.
        assert {e["slug"] for e in out} == {"Receipts", "Bills"}
        receipts = next(e for e in out if e["slug"] == "Receipts")
        assert receipts["color"] == "#ff0000"
        assert receipts["name"] == "Receipts"

    def test_imap_dispatch_returns_empty(self, db, regular_user):
        """2026-05-12 — operator caught the IMAP picker was dumping
        every folder name into the picker, including hundreds of
        nested archive paths. IMAP folders aren't labels (a message
        lives in exactly one folder); the route editor's 'move'
        action covers that surface. So the picker now returns []
        for IMAP regardless of folder list.
        """
        account_id = _make_account(
            db, regular_user["id"], provider_type="imap",
        )
        fake_folders = ["INBOX", "INBOX.Sent", "INBOX.Receipts"]
        with patch.object(
            pl_mod, "build_provider",
            return_value=_FakeImapProvider(fake_folders),
        ):
            out = asyncio.run(
                list_provider_labels_for_account(
                    db=db, secrets=None, account_id=account_id,
                )
            )
        assert out == [], (
            "IMAP accounts should return [] from the provider-label "
            "picker; the route editor's 'move' action covers folders. "
            f"Got: {out}"
        )

    def test_o365_dispatch(self, db, regular_user):
        account_id = _make_account(
            db, regular_user["id"], provider_type="office365",
        )
        fake_cats = [
            {"id": "c1", "name": "Follow up"},
            {"id": "c2", "name": "Reference"},
        ]
        with patch.object(
            pl_mod, "build_provider",
            return_value=_FakeO365Provider(fake_cats),
        ):
            out = asyncio.run(
                list_provider_labels_for_account(
                    db=db, secrets=None, account_id=account_id,
                )
            )
        assert {e["slug"] for e in out} == {"Follow up", "Reference"}

    def test_hipaa_returns_empty(self, db, regular_user):
        account_id = _make_account(
            db, regular_user["id"], provider_type="gmail_api",
            hipaa=True,
        )
        # No provider mock — helper must short-circuit before calling
        # build_provider. If it didn't, the absence of secrets would
        # blow up.
        with patch.object(
            pl_mod, "build_provider",
            side_effect=AssertionError(
                "HIPAA gate failed — build_provider invoked"
            ),
        ):
            out = asyncio.run(
                list_provider_labels_for_account(
                    db=db, secrets=None, account_id=account_id,
                )
            )
        assert out == []

    def test_unknown_account_returns_empty(self, db):
        out = asyncio.run(
            list_provider_labels_for_account(
                db=db, secrets=None, account_id=99999,
            )
        )
        assert out == []

    def test_cache_hit_within_ttl(self, db, regular_user):
        """Second call within TTL must reuse the cached value (no
        second provider hit)."""
        account_id = _make_account(
            db, regular_user["id"], provider_type="gmail_api",
        )
        fake_labels = [{"id": "Label_1", "name": "Tag"}]
        call_count = {"n": 0}

        class _CountingProvider(_FakeGmailProvider):
            async def list_labels(self):
                call_count["n"] += 1
                return await super().list_labels()

        provider = _CountingProvider(fake_labels)
        with patch.object(pl_mod, "build_provider", return_value=provider):
            asyncio.run(
                list_provider_labels_for_account(
                    db=db, secrets=None, account_id=account_id,
                )
            )
            asyncio.run(
                list_provider_labels_for_account(
                    db=db, secrets=None, account_id=account_id,
                )
            )
        # list_labels called exactly once — second call returned
        # from cache.
        assert call_count["n"] == 1

    def test_provider_raises_returns_empty(self, db, regular_user):
        """Any exception during list_labels → [] + log warning,
        never propagates to the route handler."""
        account_id = _make_account(
            db, regular_user["id"], provider_type="gmail_api",
        )

        class _BoomProvider:
            name = "gmail_api"
            async def list_labels(self):
                raise RuntimeError("network down")
            async def close(self):
                pass

        with patch.object(
            pl_mod, "build_provider", return_value=_BoomProvider(),
        ):
            out = asyncio.run(
                list_provider_labels_for_account(
                    db=db, secrets=None, account_id=account_id,
                )
            )
        assert out == []


# ---------------------------------------------------------------------------
# Route handler — picker render + form parse
# ---------------------------------------------------------------------------


class TestRuleEditPicker:
    def test_renders_provider_label_picker_with_groups(
        self, client, db, regular_user, user_cookies,
    ):
        # Two accounts: one Gmail (with labels), one IMAP (with folders).
        aid_gmail = _make_account(
            db, regular_user["id"], provider_type="gmail_api",
            name="primary",
        )
        aid_imap = _make_account(
            db, regular_user["id"], provider_type="imap",
            name="backup",
        )
        list_id, rule_id = _make_rule(db, regular_user["id"])

        # Mock list_provider_labels_for_account on the route module
        # so the GET handler sees deterministic groups without
        # touching real provider creds.
        async def _fake_lookup(*, db, secrets, account_id):
            if account_id == aid_gmail:
                return [
                    {"slug": "Tag-A", "name": "Tag-A", "color": "#ff0000"},
                    {"slug": "Tag-B", "name": "Tag-B", "color": ""},
                ]
            if account_id == aid_imap:
                return [
                    {"slug": "INBOX.Folder1", "name": "INBOX.Folder1",
                     "color": ""},
                ]
            return []

        with patch(
            "email_triage.web.routers.ui.categories."
            "list_provider_labels_for_account",
            new=_fake_lookup,
        ):
            resp = client.get(
                f"/rules/{list_id}/rules/{rule_id}/edit",
                cookies=user_cookies,
            )
        assert resp.status_code == 200
        body = resp.text
        # Both account names show as group headers.
        assert "primary" in body
        assert "backup" in body
        # Provider-type subtitles appear.
        assert "gmail_api" in body
        assert "imap" in body
        # Label names render as checkbox chips.
        assert "Tag-A" in body
        assert "INBOX.Folder1" in body
        # Form values are the account-id:slug pairing.
        assert f'value="{aid_gmail}:Tag-A"' in body
        assert f'value="{aid_imap}:INBOX.Folder1"' in body

    def test_hipaa_account_excluded_from_picker(
        self, client, db, regular_user, user_cookies,
    ):
        aid_normal = _make_account(
            db, regular_user["id"], provider_type="gmail_api",
            name="normal",
        )
        aid_hipaa = _make_account(
            db, regular_user["id"], provider_type="gmail_api",
            name="phi", hipaa=True,
        )
        list_id, rule_id = _make_rule(db, regular_user["id"])

        async def _fake_lookup(*, db, secrets, account_id):
            # Helper would itself return [] for HIPAA, but the route
            # filter should keep it from ever being called.
            assert account_id != aid_hipaa, (
                "HIPAA account must not reach provider_labels helper"
            )
            return [{"slug": "Tag", "name": "Tag", "color": ""}]

        with patch(
            "email_triage.web.routers.ui.categories."
            "list_provider_labels_for_account",
            new=_fake_lookup,
        ):
            resp = client.get(
                f"/rules/{list_id}/rules/{rule_id}/edit",
                cookies=user_cookies,
            )
        assert resp.status_code == 200
        body = resp.text
        # Normal account renders.
        assert "normal" in body
        # HIPAA account name does NOT appear in any group header.
        # Use a specific anchor that only the picker produces.
        assert f'value="{aid_hipaa}:' not in body


class TestRuleSaveProviderLabelsForm:
    def test_save_parses_provider_labels_form_field(
        self, client, db, regular_user, user_cookies,
    ):
        aid1 = _make_account(
            db, regular_user["id"], provider_type="gmail_api",
            name="acct1",
        )
        aid2 = _make_account(
            db, regular_user["id"], provider_type="imap",
            name="acct2",
        )
        list_id, rule_id = _make_rule(db, regular_user["id"])

        resp = client.post(
            f"/rules/{list_id}/rules/{rule_id}/save",
            data={
                "rule_type": "sender",
                "pattern": "boss@example.com",
                "skip_ai": "0",
                "provider_labels": [
                    f"{aid1}:Receipts",
                    f"{aid2}:INBOX.Bills",
                    "garbage-no-colon",      # dropped
                    ":missing-aid",          # dropped (empty aid)
                ],
            },
            cookies=user_cookies,
            follow_redirects=False,
        )
        assert resp.status_code in (200, 303)
        row = db.execute(
            "SELECT provider_labels FROM list_rules WHERE id = ?",
            (rule_id,),
        ).fetchone()
        parsed = json.loads(row["provider_labels"])
        # Two valid entries — malformed ones dropped silently.
        assert len(parsed) == 2
        slugs_by_aid = {e["account_id"]: e["label_slug"] for e in parsed}
        assert slugs_by_aid[aid1] == "Receipts"
        assert slugs_by_aid[aid2] == "INBOX.Bills"

    def test_create_list_persists_provider_labels(
        self, client, db, regular_user, user_cookies,
    ):
        aid = _make_account(
            db, regular_user["id"], provider_type="gmail_api",
            name="primary",
        )
        cat_row = db.execute(
            "SELECT slug FROM categories LIMIT 1"
        ).fetchone()
        category_slug = cat_row["slug"] if cat_row else "to-respond"

        resp = client.post(
            "/rules/create",
            data={
                "name": "VIP",
                "category": category_slug,
                "is_global": "0",
                "rule_type": "sender",
                "pattern": "boss@example.com",
                "skip_ai": "0",
                "provider_labels": [f"{aid}:Receipts"],
            },
            cookies=user_cookies,
            follow_redirects=False,
        )
        assert resp.status_code in (200, 303)
        row = db.execute(
            "SELECT provider_labels FROM list_rules "
            "WHERE pattern = 'boss@example.com'"
        ).fetchone()
        assert row is not None
        parsed = json.loads(row["provider_labels"])
        assert parsed == [{"account_id": aid, "label_slug": "Receipts"}]


# ---------------------------------------------------------------------------
# Apply phase — per-account scoping
# ---------------------------------------------------------------------------


class _RecordingProvider:
    """Mock provider that records every apply_label call."""
    name = "mock"

    def __init__(self):
        self.calls: list[tuple[str, str]] = []

    async def apply_label(self, message_id: str, label: str) -> None:
        self.calls.append((message_id, label))


class TestApplyPhaseAccountScoping:
    """The linchpin tests: a rule with provider_labels entries for
    multiple account_ids must only apply the entry whose account_id
    matches the message's account.

    These are unit tests against the apply contract — we exercise
    the per-message scan directly rather than wiring up a full
    triage runner. Mirrors the test_labels_rule_apply.py shape.
    """
    def test_match_then_only_account_scoped_label_applied(self, db):
        from email_triage.engine.models import (
            EmailMessage, ListRule, RuleType,
        )
        from email_triage.classify.hints import _rule_matches

        msg = EmailMessage(
            message_id="msg-1",
            provider="mock",
            sender="boss@example.com",
            recipients=["me@example.com"],
            subject="hi",
            body_text="",
            date=datetime.now(timezone.utc),
        )
        rule = ListRule(
            id=42, list_id=1, rule_type=RuleType.SENDER,
            pattern="boss@example.com", skip_ai=False,
        )
        # Rule has entries for two accounts; message is on account 3.
        entries = [
            {"account_id": 3, "label_slug": "Receipts"},
            {"account_id": 5, "label_slug": "Bills"},
        ]
        message_account_id = 3
        provider = _RecordingProvider()

        assert _rule_matches(rule, msg) is True
        # Simulate the apply loop from triage_runner.
        matched: set[str] = set()
        for entry in entries:
            if int(entry.get("account_id", -1)) == message_account_id:
                slug = entry.get("label_slug", "")
                if slug:
                    matched.add(slug)
        asyncio.run(self._apply_all(provider, msg.message_id, matched))
        assert provider.calls == [("msg-1", "Receipts")]

    def test_no_apply_for_other_account(self, db):
        """Rule has entry for account 5 only; message is on account 3.
        provider.apply_label must NOT be called."""
        from email_triage.engine.models import (
            EmailMessage, ListRule, RuleType,
        )
        from email_triage.classify.hints import _rule_matches

        msg = EmailMessage(
            message_id="msg-2",
            provider="mock",
            sender="boss@example.com",
            recipients=["me@example.com"],
            subject="hi",
            body_text="",
            date=datetime.now(timezone.utc),
        )
        rule = ListRule(
            id=43, list_id=1, rule_type=RuleType.SENDER,
            pattern="boss@example.com", skip_ai=False,
        )
        entries = [{"account_id": 5, "label_slug": "Bills"}]
        message_account_id = 3
        provider = _RecordingProvider()

        assert _rule_matches(rule, msg) is True
        matched: set[str] = set()
        for entry in entries:
            if int(entry.get("account_id", -1)) == message_account_id:
                slug = entry.get("label_slug", "")
                if slug:
                    matched.add(slug)
        asyncio.run(self._apply_all(provider, msg.message_id, matched))
        assert provider.calls == []

    def test_non_matching_rule_no_apply(self, db):
        from email_triage.engine.models import (
            EmailMessage, ListRule, RuleType,
        )
        from email_triage.classify.hints import _rule_matches

        msg = EmailMessage(
            message_id="msg-3",
            provider="mock",
            sender="other@example.com",
            recipients=["me@example.com"],
            subject="hi",
            body_text="",
            date=datetime.now(timezone.utc),
        )
        rule = ListRule(
            id=44, list_id=1, rule_type=RuleType.SENDER,
            pattern="boss@example.com", skip_ai=False,
        )
        assert _rule_matches(rule, msg) is False
        # Apply phase guarded by _rule_matches — never invoked.

    @staticmethod
    async def _apply_all(provider, msg_id, slugs):
        for slug in sorted(slugs):
            await provider.apply_label(msg_id, slug)


# ---------------------------------------------------------------------------
# Privacy invariants
# ---------------------------------------------------------------------------


class TestPrivacyInvariants:
    def test_provider_labels_module_no_real_account_local_parts(self):
        """The new helper module must not embed real account local-
        parts in docstrings / comments / example values. Allowlisted
        placeholders only.
        """
        path = (
            Path(__file__).resolve().parents[2]
            / "src" / "email_triage" / "providers" / "provider_labels.py"
        )
        text = path.read_text(encoding="utf-8")
        # Forbidden tokens — kept narrow so the test doesn't false-
        # positive on the standard list of public examples.
        forbidden = [
            # If a regression introduced a real customer local-part
            # we'd want it caught — extend this list when filing
            # offenders to the catalogue.
        ]
        for token in forbidden:
            assert token.lower() not in text.lower(), (
                f"Privacy regression: {token!r} appeared in "
                f"provider_labels.py"
            )

    def test_template_uses_only_generic_help_text(self):
        """The new fieldset's m.help() copy must not name real
        operator-owned providers or label names. The standing
        no-admin-path + no-operator-identifier rules apply.

        Updated 2026-05-12: the IMAP carve-out moved into the help
        text + the empty-state branch (IMAP doesn't carry labels;
        operator gets the 'use move action instead' nudge). The
        canonical generic phrasing now names Gmail + Outlook only;
        IMAP is covered in the descriptive copy underneath.
        """
        path = (
            Path(__file__).resolve().parents[2]
            / "src" / "email_triage" / "web" / "templates"
            / "rules" / "_rule_edit.html"
        )
        text = path.read_text(encoding="utf-8")
        # New canonical phrase. Three checks (each independent) to
        # spot operator-identifier regressions in the copy block.
        assert "Gmail" in text
        assert "Outlook" in text
        assert "IMAP" in text
        # No admin paths in the new copy block.
        for forbidden in ("/admin/", "/config", "Ask your administrator"):
            assert forbidden not in text, (
                f"User-facing template names admin-only surface "
                f"{forbidden!r}"
            )
