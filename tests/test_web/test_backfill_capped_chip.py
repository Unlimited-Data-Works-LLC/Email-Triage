""" — bounded-backfill saturation chip.

When a Gmail history-expired / O365 delta-resync recovery saturates the
bounded backfill cap, older mail in the gap may be un-triaged. Before
this fix that loss was silent. These tests cover the chip lifecycle
(mark → read → clear), the per-account delete-sweep catalog entry, the
dismiss route, and the SSOT cap constant.
"""

import json
from pathlib import Path

import pytest

from email_triage.web._backfill_chip import (
    BACKFILL_CAP,
    mark_backfill_capped,
    get_backfill_capped,
    clear_backfill_capped,
)
from email_triage.web import settings_keys as _S


def _make_account(db, user_id, *, name="Inbox"):
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    cur = db.execute(
        "INSERT INTO email_accounts "
        "(user_id, name, provider_type, config_json, is_active, "
        " created_at, updated_at) VALUES (?, ?, 'imap', ?, 1, ?, ?)",
        (user_id, name, json.dumps({"host": "h"}), now, now),
    )
    db.commit()
    return cur.lastrowid


class TestChipLifecycle:
    def test_mark_then_get_round_trip(self, db, regular_user):
        acct = _make_account(db, regular_user["id"])
        assert get_backfill_capped(db, acct) is None
        mark_backfill_capped(
            db, acct, kind="gmail_history", window="last 7 days",
            recovered=BACKFILL_CAP,
        )
        chip = get_backfill_capped(db, acct)
        assert chip is not None
        assert chip["kind"] == "gmail_history"
        assert chip["recovered"] == BACKFILL_CAP
        assert chip["cap"] == BACKFILL_CAP
        assert chip["window"] == "last 7 days"
        assert chip.get("at")

    def test_clear_removes_chip(self, db, regular_user):
        acct = _make_account(db, regular_user["id"])
        mark_backfill_capped(
            db, acct, kind="o365_resync", window="most recent",
            recovered=BACKFILL_CAP,
        )
        assert get_backfill_capped(db, acct) is not None
        clear_backfill_capped(db, acct)
        assert get_backfill_capped(db, acct) is None

    def test_clear_when_absent_is_noop(self, db, regular_user):
        acct = _make_account(db, regular_user["id"])
        # No chip set — clear must not raise / must stay None.
        clear_backfill_capped(db, acct)
        assert get_backfill_capped(db, acct) is None


class TestCatalogCleanup:
    def test_backfill_capped_in_account_key_catalog(self):
        """Account-delete sweep must clean up the chip, else a deleted
        account's chip key lingers."""
        prefixes = [p for (p, _exact) in _S._ACCOUNT_KEY_CATALOG]
        assert "backfill_capped:" in prefixes

    def test_account_settings_keys_includes_chip(self):
        keys = dict(_S.account_settings_keys(7))
        assert _S.backfill_capped(7) in keys  # "backfill_capped:7"


class TestDismissRoute:
    def test_dismiss_clears_chip(self, client, db, regular_user, user_cookies):
        acct = _make_account(db, regular_user["id"])
        mark_backfill_capped(
            db, acct, kind="gmail_history", window="last 7 days",
            recovered=BACKFILL_CAP,
        )
        assert get_backfill_capped(db, acct) is not None
        resp = client.post(
            f"/accounts/{acct}/backfill-capped/dismiss", cookies=user_cookies,
        )
        assert resp.status_code == 200
        assert get_backfill_capped(db, acct) is None

    def test_dismiss_writes_audit_row(
        self, client, db, regular_user, user_cookies,
    ):
        """ SME (S1) — dismissing the chip records a §164.312(b)
        access-log row so a known un-triage gap acknowledged by the
        operator leaves a trail instead of silently vanishing."""
        from email_triage.web.db import list_access_events
        acct = _make_account(db, regular_user["id"])
        mark_backfill_capped(
            db, acct, kind="gmail_history", window="last 7 days",
            recovered=BACKFILL_CAP,
        )
        client.post(
            f"/accounts/{acct}/backfill-capped/dismiss", cookies=user_cookies,
        )
        events = list_access_events(db, account_id=acct)
        assert any(
            "backfill_capped dismissed" in (e.get("detail") or "")
            for e in events
        ), "dismiss did not leave an audit trail"

    def test_dismiss_foreign_account_forbidden(
        self, client, db, regular_user, admin_user, user_cookies,
    ):
        """A user can't clear another owner's chip (IDOR guard via
        OwnedAccount)."""
        other = _make_account(db, admin_user["id"], name="NotMine")
        mark_backfill_capped(
            db, other, kind="o365_resync", window="most recent",
            recovered=BACKFILL_CAP,
        )
        resp = client.post(
            f"/accounts/{other}/backfill-capped/dismiss",
            cookies=user_cookies, follow_redirects=False,
        )
        assert resp.status_code in (403, 404)
        # Chip survives — the foreign dismiss was refused.
        assert get_backfill_capped(db, other) is not None


class TestCapIsSSOT:
    def test_resync_sites_use_backfill_cap_not_magic_200(self):
        """The three cursor-expiry recovery sites must import the shared
        BACKFILL_CAP, not hardcode 200 — so the cap can't drift."""
        root = Path(__file__).resolve().parent.parent.parent
        src = root / "src" / "email_triage" / "web"
        for fname in ("ingestion_push.py", "poll_ingestion.py"):
            text = (src / fname).read_text(encoding="utf-8")
            assert "limit=200" not in text, (
                f"{fname} still hardcodes limit=200 in a backfill site"
            )
            assert "BACKFILL_CAP" in text, (
                f"{fname} does not reference the shared BACKFILL_CAP"
            )
