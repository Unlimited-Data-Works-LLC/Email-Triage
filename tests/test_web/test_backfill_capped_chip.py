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
    probe_resync_walk,
)
from email_triage.web import settings_keys as _S


def _make_account(db, user_id, *, name="Inbox"):
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    cur = db.execute(
        "INSERT INTO email_accounts "
        "(user_id, name, provider_type, config_json, is_active, "
        " created_at, updated_at) VALUES (?, ?, 'imap', ?, 1, ?, ?)",
        (user_id, name, json.dumps({"host": "h.invalid"}), now, now),
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

    def test_scoped_clear_needs_a_full_walk_of_the_same_mailbox(
        self, db, regular_user,
    ):
        """Punch 854 — a scoped clear (a recovery path, not the operator)
        removes the chip only after a walk in FULL_WALK_KINDS, and only a
        chip raised by the same mailbox."""
        acct = _make_account(db, regular_user["id"])
        mark_backfill_capped(
            db, acct, kind="imap_uidvalidity", window="renumbered",
            recovered=0, source_mailbox="INBOX",
        )
        clear_backfill_capped(db, acct, source_mailbox="INBOX")
        assert get_backfill_capped(db, acct) is not None
        clear_backfill_capped(
            db, acct, source_mailbox="INBOX", walk_kind="gmail_history",
        )
        assert get_backfill_capped(db, acct) is not None
        clear_backfill_capped(
            db, acct, source_mailbox="Archive", walk_kind="o365_resync",
        )
        assert get_backfill_capped(db, acct) is not None
        clear_backfill_capped(
            db, acct, source_mailbox="INBOX", walk_kind="o365_resync",
        )
        assert get_backfill_capped(db, acct) is None

    def test_scoped_clear_keeps_a_legacy_chip(self, db, regular_user):
        """A chip stored with no source_mailbox (pre-N-211) is not proven
        to belong to any walk; only the operator's dismiss clears it. It
        used to fall to any scoped clear."""
        acct = _make_account(db, regular_user["id"])
        mark_backfill_capped(
            db, acct, kind="o365_resync", window="most recent",
            recovered=BACKFILL_CAP,
        )
        clear_backfill_capped(
            db, acct, source_mailbox="INBOX", walk_kind="o365_resync",
        )
        assert get_backfill_capped(db, acct) is not None
        clear_backfill_capped(db, acct, source_mailbox=None)
        assert get_backfill_capped(db, acct) is None

    def test_window_bounded_and_reseed_walks_are_not_full_walks(self):
        """A 7-day Gmail walk and a UIDVALIDITY reseed cannot cover an
        earlier gap; neither may join FULL_WALK_KINDS."""
        from email_triage.web._backfill_chip import FULL_WALK_KINDS
        assert "o365_resync" in FULL_WALK_KINDS
        assert "gmail_history" not in FULL_WALK_KINDS
        assert "imap_uidvalidity" not in FULL_WALK_KINDS

    def test_mark_from_another_mailbox_drops_the_mailbox(self, db, regular_user):
        """Punch 854 (DA MISSED-1) — one key per account. A second gap on a
        different mailbox must not relabel the first gap's chip, or a later
        scoped clear for the second mailbox would erase the first gap's
        notice. The merged chip names no mailbox and falls only to dismiss."""
        acct = _make_account(db, regular_user["id"])
        mark_backfill_capped(
            db, acct, kind="imap_uidvalidity", window="reseed",
            recovered=0, source_mailbox="Archive",
        )
        mark_backfill_capped(
            db, acct, kind="o365_resync", window="most recent",
            recovered=BACKFILL_CAP, source_mailbox="INBOX",
        )
        chip = get_backfill_capped(db, acct)
        assert chip is not None and "source_mailbox" not in chip
        clear_backfill_capped(
            db, acct, source_mailbox="INBOX", walk_kind="o365_resync",
        )
        assert get_backfill_capped(db, acct) is not None
        clear_backfill_capped(db, acct, source_mailbox=None)
        assert get_backfill_capped(db, acct) is None

    def test_repeat_mark_from_the_same_mailbox_keeps_the_mailbox(
        self, db, regular_user,
    ):
        acct = _make_account(db, regular_user["id"])
        for _ in range(2):
            mark_backfill_capped(
                db, acct, kind="o365_resync", window="most recent",
                recovered=BACKFILL_CAP, source_mailbox="INBOX",
            )
        assert get_backfill_capped(db, acct)["source_mailbox"] == "INBOX"

    def test_failed_mark_is_logged_not_dropped(
        self, db, regular_user, caplog, monkeypatch,
    ):
        """The chip is the only notice that mail was skipped. A write that
        fails must not abort the recovery, and must reach the log at ERROR."""
        import logging
        from email_triage.web import db as _db

        def _boom(*_a, **_k):
            raise RuntimeError("settings write refused")

        acct = _make_account(db, regular_user["id"])
        monkeypatch.setattr(_db, "set_setting", _boom)
        with caplog.at_level(
            logging.ERROR, logger="email_triage.web.backfill_chip",
        ):
            mark_backfill_capped(
                db, acct, kind="imap_uidvalidity", window="reseed",
                recovered=0, source_mailbox="INBOX",
            )
        hits = [r for r in caplog.records
                if r.levelno == logging.ERROR
                and "chip write FAILED" in r.getMessage()]
        assert hits, [r.getMessage() for r in caplog.records]


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
        details = [e.get("detail") or "" for e in events]
        dismissed = [d for d in details if "backfill_capped dismissed" in d]
        assert dismissed, "dismiss did not leave an audit trail"
        # Punch 854 (hipaa-sme N1): the row dates the acknowledged gap.
        assert "at=" in dismissed[0] and "at=?" not in dismissed[0]

    @pytest.mark.audit_failure_expected(match="backfill_capped_dismiss", count=1)
    def test_dismiss_keeps_the_chip_when_the_audit_write_fails(
        self, client, db, regular_user, user_cookies, monkeypatch,
    ):
        """Punch 854 (hipaa-sme S5, PD-8): for imap and gmail chips the
        dismiss is the only clear edge, so an unwitnessed dismiss would turn
        a known gap silent. No access_log row, no clear."""
        from email_triage.web import db as _db

        acct = _make_account(db, regular_user["id"])
        mark_backfill_capped(
            db, acct, kind="imap_uidvalidity", window="reseed",
            recovered=0, source_mailbox="INBOX",
        )

        def _boom(*_a, **_kw):
            raise RuntimeError("access_log unavailable")

        monkeypatch.setattr(_db, "record_access_event", _boom)
        resp = client.post(
            f"/accounts/{acct}/backfill-capped/dismiss", cookies=user_cookies,
        )
        assert resp.status_code == 503
        assert get_backfill_capped(db, acct) is not None

    @pytest.mark.audit_failure_expected(match="backfill_capped_dismiss", count=1)
    def test_htmx_dismiss_failure_swaps_an_inline_alert(
        self, client, db, regular_user, user_cookies, monkeypatch,
    ):
        """Punch 854 (DA S3): HTMX does not swap a 5xx, so an HTMX dismiss
        whose audit write fails gets a 200 whose body replaces the chip with
        an alert. The chip stays stored."""
        from email_triage.web import db as _db

        acct = _make_account(db, regular_user["id"])
        mark_backfill_capped(
            db, acct, kind="imap_uidvalidity", window="reseed",
            recovered=0, source_mailbox="INBOX",
        )

        def _boom(*_a, **_kw):
            raise RuntimeError("access_log unavailable")

        monkeypatch.setattr(_db, "record_access_event", _boom)
        resp = client.post(
            f"/accounts/{acct}/backfill-capped/dismiss",
            cookies=user_cookies, headers={"HX-Request": "true"},
        )
        assert resp.status_code == 200
        assert f'id="backfill-chip-{acct}"' in resp.text
        assert 'role="alert"' in resp.text
        assert get_backfill_capped(db, acct) is not None

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


class TestChipRender:
    """Punch 854 (DA S2): the chip now stays until dismissed, so its text
    follows its kind. A UIDVALIDITY reseed is not a capped recovery."""

    def test_imap_reseed_chip_says_folder_renumbered(
        self, client, db, regular_user, user_cookies,
    ):
        acct = _make_account(db, regular_user["id"])
        mark_backfill_capped(
            db, acct, kind="imap_uidvalidity", window="reseed",
            recovered=0, source_mailbox="INBOX",
        )
        resp = client.get("/accounts", cookies=user_cookies)
        assert resp.status_code == 200
        assert "Folder renumbered" in resp.text
        assert "capped at" not in resp.text
        assert "Sync recovery capped" not in resp.text

    def test_capped_recovery_chip_says_capped(
        self, client, db, regular_user, user_cookies,
    ):
        acct = _make_account(db, regular_user["id"])
        mark_backfill_capped(
            db, acct, kind="gmail_history", window="last 7 days",
            recovered=BACKFILL_CAP,
        )
        resp = client.get("/accounts", cookies=user_cookies)
        assert resp.status_code == 200
        assert "Sync recovery capped" in resp.text
        assert f"capped at {BACKFILL_CAP} messages" in resp.text
        assert "Folder renumbered" not in resp.text


class _PagedProvider:
    """A provider whose ``search_iter`` yields fixed pages, nextLink on all but
    the last, and records whether the walk was closed."""

    def __init__(self, pages):
        self.pages = pages
        self.calls = []
        self.closed = False

    def search_iter(self, query, *, batch_size=500, **_kw):
        self.calls.append((query, batch_size))
        return self._walk()

    async def _walk(self):
        try:
            for i, page in enumerate(self.pages):
                yield list(page), ("next" if i < len(self.pages) - 1 else None)
        finally:
            self.closed = True


class TestProbeResyncWalk:
    """Punch 854 (db-sme S1): the O365 full-walk proof follows nextLink."""

    @pytest.mark.asyncio
    async def test_short_pages_with_more_pending_saturate(self):
        provider = _PagedProvider([["a"] * 150, ["b"] * 51])
        ids, saturated = await probe_resync_walk(provider)
        assert saturated is True
        assert len(ids) == BACKFILL_CAP
        assert provider.calls == [("ALL", BACKFILL_CAP + 1)]
        assert provider.closed

    @pytest.mark.asyncio
    async def test_whole_mailbox_at_the_cap_is_not_saturated(self):
        provider = _PagedProvider([["a"] * 120, ["b"] * 80])
        ids, saturated = await probe_resync_walk(provider)
        assert saturated is False
        assert len(ids) == BACKFILL_CAP
        assert provider.closed

    @pytest.mark.asyncio
    async def test_stops_reading_once_saturated(self):
        provider = _PagedProvider([["a"] * 201, ["never"] * 5])
        ids, saturated = await probe_resync_walk(provider)
        assert saturated is True
        assert "never" not in ids
        assert provider.closed


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
