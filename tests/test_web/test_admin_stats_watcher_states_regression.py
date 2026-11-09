"""N-411 regression — /admin/stats "Watcher state" must render.

Bug (operator screenshot 2026-07-13 ~23:20 EDT, HEAD 66d69da8):
    The N-411 Drive-1 fold-in relocated `_admin_stats_snapshot` to
    hydrate ``watcher_states`` by folding over
    ``WatcherManager.account_states(db)``. The Gmail-API + O365 branch
    of that fold reads ``push_deliveries`` (the per-account count union
    for providers with no per-mailbox ``_mb_state``). But
    ``push_deliveries`` was fetched AFTER the fold, so the fold hit a
    ``NameError`` on every request — swallowed silently by a bare
    ``except Exception: pass`` — and ``watcher_states`` stayed empty.
    The template rendered "No watchers tracked" while watchers were
    healthy and actively processing mail.

Fix (this drive):
    (a) Relocate the ``push_deliveries`` fetch ABOVE the fold.
    (b) Replace the bare swallow with a structured ``_log.error(...,
        exc_info=e)`` so the next hydration bug of this class fails
        loud in the container log instead of silently rendering
        "No watchers tracked."

Why this pin exists (per ``feedback_test_the_view_not_just_machinery``):
    ``test_account_status_ssot_pin.py`` catches the ``all_statuses()``
    vs ``account_states(db)`` code-shape drift, but it CANNOT catch a
    ``NameError`` swallowed at runtime — the source parses, py_compile
    is green, unit tests that mock the fold-body pass. The only signal
    is the rendered view. This test exercises the ACTUAL route render
    and asserts ``watcher_states`` reaches the template with rows,
    matching the Prime Directive  "test the view, not just
    machinery" rule.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone


def _make_account_provider(db, user_id, *, name, provider_type, config=None):
    """Insert an email_accounts row with a specified provider_type
    (the shipped ``_make_account`` helper hardcodes ``imap``). Same
    columns, same is_active=1 default."""
    now = datetime.now(timezone.utc).isoformat()
    cursor = db.execute(
        "INSERT INTO email_accounts "
        "(user_id, name, provider_type, config_json, is_active, "
        " created_at, updated_at) "
        "VALUES (?, ?, ?, ?, 1, ?, ?)",
        (user_id, name, provider_type,
         json.dumps(config or {"host": "mail.test.invalid"}), now, now),
    )
    db.commit()
    return cursor.lastrowid


class _FakeWM:
    """Test fake — returns `account_states(db)` rows shaped like the
    real ``WatcherManager.account_states`` output (per its docstring,
    watcher.py:280-409). Includes IMAP + Gmail-API + O365 rows so the
    fold in ``_admin_stats_snapshot`` exercises both provider
    branches."""

    def __init__(self, states):
        self._states = states  # legacy IMAP `_mb_state` shape
        self._account_rows = []

    def set_account_rows(self, rows):
        self._account_rows = rows

    def all_statuses(self):
        return self._states

    def account_states(self, db):
        return list(self._account_rows)


def test_admin_stats_snapshot_hydrates_watcher_states(
    client, db, app, admin_user, admin_cookies,
):
    """Regression: rendered /admin/stats MUST show the Watcher-state
    rows, not the "No watchers tracked" empty state, when the watcher
    manager reports live accounts. Reproduces the operator-visible
    2026-07-13 bug (fold hit NameError on `push_deliveries`, swallowed
    silently, table rendered empty)."""
    aid_imap = _make_account_provider(
        db, admin_user["id"], name="IMAP Mailbox", provider_type="imap",
    )
    aid_gmail = _make_account_provider(
        db, admin_user["id"], name="Gmail Mailbox", provider_type="gmail_api",
    )
    aid_o365 = _make_account_provider(
        db, admin_user["id"], name="O365 Mailbox", provider_type="office365",
    )

    fake = _FakeWM({
        # IMAP `_mb_state` shape — one healthy folder
        aid_imap: {
            "status": "watching",
            "processed": 42,
            "errors": 0,
            "started_at": datetime.now(timezone.utc).isoformat(),
        },
    })
    fake.set_account_rows([
        {
            "account_id": aid_imap, "account_name": "IMAP Mailbox",
            "owner": admin_user["email"], "provider": "imap",
            "push": {"configured": True, "active": True, "detail": "1/1"},
            "poll": {"enrolled": False, "last_tick": None, "fresh": False},
            "mode": "push", "primary": "push", "alert": None,
        },
        {
            "account_id": aid_gmail, "account_name": "Gmail Mailbox",
            "owner": admin_user["email"], "provider": "gmail_api",
            "push": {"configured": True, "active": True, "detail": "watch"},
            "poll": {"enrolled": False, "last_tick": None, "fresh": False},
            "mode": "push", "primary": "push", "alert": None,
        },
        {
            "account_id": aid_o365, "account_name": "O365 Mailbox",
            "owner": admin_user["email"], "provider": "office365",
            "push": {"configured": True, "active": True, "detail": "sub"},
            "poll": {"enrolled": False, "last_tick": None, "fresh": False},
            "mode": "push", "primary": "push", "alert": None,
        },
    ])
    app.state.watcher_manager = fake

    resp = client.get("/admin/stats", cookies=admin_cookies)
    assert resp.status_code == 200, resp.text[:500]
    body = resp.text

    # The bug: this string appeared when `watcher_states` was empty.
    # Absence of the empty-state message is the primary regression
    # signal — presence would mean the fold NameError'd + got
    # swallowed again.
    assert "No watchers tracked" not in body, (
        "Watcher state table rendered the empty state while "
        "account_states() returned 3 rows — the N-411 fold-in has "
        "re-broken. Check container logs for "
        "'_admin_stats_snapshot: watcher_states hydration failed' "
        "(the structured swallow-replacement) to identify the "
        "current NameError / AttributeError / etc."
    )

    # Positive: every provider's account name must appear in the
    # rendered table. This confirms all three branches of the fold
    # (IMAP via `_mb_state` counters; Gmail-API + O365 via
    # `push_deliveries`) ran to completion.
    for name in ("IMAP Mailbox", "Gmail Mailbox", "O365 Mailbox"):
        assert name in body, (
            f"Rendered /admin/stats missing account name {name!r} — "
            f"the fold skipped its provider branch."
        )

    # N-411 anti-irony fold-in: the per-provider `count_window` label
    # ("lifetime" for IMAP, "14d" for Gmail/O365) surfaces the count-
    # semantics divergence. Presence in the rendered body confirms
    # both branches wrote it into the dict + the template rendered it.
    assert "lifetime" in body, "IMAP count_window='lifetime' missing"
    assert "14d" in body, "Gmail/O365 count_window='14d' missing"


def test_admin_stats_snapshot_survives_push_deliveries_fetch_failure(
    client, db, app, admin_user, admin_cookies, monkeypatch,
):
    """Defence-in-depth: even if ``get_push_deliveries_window`` raises,
    the watcher_states fold MUST still populate. The Drive-1 bug hid
    behind ``push_deliveries`` reference-before-assignment; the guard
    fix must not re-introduce the coupling — a fetch failure logs but
    keeps rendering."""
    aid_imap = _make_account_provider(
        db, admin_user["id"], name="IMAP Only", provider_type="imap",
    )
    fake = _FakeWM({aid_imap: {
        "status": "watching", "processed": 7, "errors": 0,
        "started_at": datetime.now(timezone.utc).isoformat(),
    }})
    fake.set_account_rows([{
        "account_id": aid_imap, "account_name": "IMAP Only",
        "owner": admin_user["email"], "provider": "imap",
        "push": {"configured": False, "active": False, "detail": ""},
        "poll": {"enrolled": False, "last_tick": None, "fresh": False},
        "mode": "none", "primary": "none", "alert": None,
    }])
    app.state.watcher_manager = fake

    def _boom(*a, **kw):
        raise RuntimeError("push_deliveries fetch simulated failure")

    monkeypatch.setattr(
        "email_triage.web.db.get_push_deliveries_window", _boom,
    )

    resp = client.get("/admin/stats", cookies=admin_cookies)
    assert resp.status_code == 200
    assert "No watchers tracked" not in resp.text
    assert "IMAP Only" in resp.text
