"""Bundle C — DB N+1 sweep regression coverage (#134, #145.6, #140.3).

Each test pins the post-fix query count to detect regressions. The
counter uses ``sqlite3.Connection.set_trace_callback`` — same idiom as
``test_secrets.py``'s rotation-order test. We trace every executed
statement (filtering out housekeeping like ``COMMIT`` / ``BEGIN``)
and assert the count is ≤ a small constant rather than scaling with
``n``.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from email_triage.engine.models import EmailMessage
from email_triage.web.db import (
    apply_ingestion_back_compat,
    create_email_account,
    disabled_user_ids,
    get_setting,
    init_db,
    is_user_disabled,
    latest_hipaa_boundaries_for_accounts,
    latest_hipaa_boundary,
    list_email_accounts,
    record_hipaa_boundary,
    seed_categories,
    set_setting,
)
from email_triage.web.routers.ui import (
    _collect_list_hints_for_message,
    _load_all_list_hints,
)
from email_triage.web import settings_keys as S


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _QueryCounter:
    """Trace SELECTs / DML on a sqlite3.Connection.

    Intentionally records ALL statements (even housekeeping ones).
    Tests filter by prefix when they want to compare specific shapes.
    """

    def __init__(self, conn):
        self.conn = conn
        self.statements: list[str] = []

    def __enter__(self):
        self.conn.set_trace_callback(
            lambda sql: self.statements.append(sql.strip())
        )
        return self

    def __exit__(self, exc_type, exc, tb):
        self.conn.set_trace_callback(None)

    def select_count(self, like: str | None = None) -> int:
        out = 0
        for sql in self.statements:
            up = sql.upper()
            if not up.startswith("SELECT"):
                continue
            if like is None or like.lower() in sql.lower():
                out += 1
        return out


def _make_db():
    """Spin up an in-memory SQLite DB with the test schema."""
    db = init_db(":memory:")
    seed_categories(db, {
        "work": "Work mail",
        "personal": "Personal mail",
        "newsletters": "Newsletters",
    })
    return db


def _make_user(db, email: str, *, disabled: bool = False) -> int:
    now = datetime.now(timezone.utc).isoformat()
    cur = db.execute(
        "INSERT INTO users (email, name, role, created_at, disabled) "
        "VALUES (?, ?, ?, ?, ?)",
        (email, email, "user", now, 1 if disabled else 0),
    )
    db.commit()
    return cur.lastrowid


def _make_lists_and_rules(db, *, n_lists: int, rules_per_list: int) -> None:
    """Seed n classification_lists each with rules_per_list list_rules."""
    now = datetime.now(timezone.utc).isoformat()
    for i in range(n_lists):
        cur = db.execute(
            "INSERT INTO classification_lists "
            "(name, category, owner_id, is_global, created_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (f"list-{i}", "newsletters", None, 1, now),
        )
        list_id = cur.lastrowid
        for j in range(rules_per_list):
            db.execute(
                "INSERT INTO list_rules "
                "(list_id, rule_type, pattern, skip_ai, created_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (list_id, "sender_domain", f"sender{i}-{j}.example", 0, now),
            )
    db.commit()


def _make_message() -> EmailMessage:
    return EmailMessage(
        message_id="t1",
        provider="imap",
        sender="alice@example.com",
        recipients=["me@example.com"],
        subject="hello",
        body_text="body",
        date=datetime.now(timezone.utc),
    )


# ---------------------------------------------------------------------------
# #134.1 — list-hint loader fanout (1 + N → 2)
# ---------------------------------------------------------------------------


def test_load_all_list_hints_uses_two_queries_regardless_of_list_count():
    db = _make_db()
    _make_lists_and_rules(db, n_lists=20, rules_per_list=3)

    with _QueryCounter(db) as qc:
        lists, rules_by_list = _load_all_list_hints(db)

    # Pre-fix: 1 (lists) + 20 (rules-per-list) = 21 SELECTs.
    # Post-fix: 1 (lists) + 1 (single rule SELECT bucketed in Python).
    assert qc.select_count() == 2, (
        f"Expected exactly 2 SELECTs (lists + rules); got {qc.statements}"
    )
    assert len(lists) == 20
    assert sum(len(rs) for rs in rules_by_list.values()) == 60


def test_collect_list_hints_with_preloaded_pair_issues_zero_queries():
    """In-loop call must hit zero DB once preloaded data is passed."""
    db = _make_db()
    _make_lists_and_rules(db, n_lists=5, rules_per_list=2)
    lists, rules_by_list = _load_all_list_hints(db)

    msg = _make_message()
    with _QueryCounter(db) as qc:
        # Simulate 100-message inline triage loop.
        for _ in range(100):
            _collect_list_hints_for_message(
                db, msg, lists=lists, rules_by_list=rules_by_list,
            )

    # Pre-fix: 100 messages × (1 + n_lists) = 600 queries.
    # Post-fix: 0 queries — pure in-memory matching.
    assert qc.select_count() == 0, (
        f"Pre-loaded pair should not query DB; got {qc.statements}"
    )


def test_collect_list_hints_falls_back_when_no_preload_passed():
    """Single-message path (e.g. /classify/test) still works without preload."""
    db = _make_db()
    _make_lists_and_rules(db, n_lists=3, rules_per_list=1)
    msg = _make_message()
    # Should not raise; legacy callers omit the kwargs.
    hints = _collect_list_hints_for_message(db, msg)
    assert isinstance(hints, list)


# ---------------------------------------------------------------------------
# #134.2 — apply_ingestion_back_compat fast-path
# ---------------------------------------------------------------------------


def test_apply_ingestion_back_compat_fast_path_skips_db_when_already_filled():
    """Migrated cfg with all three keys present → zero settings/gmail SELECTs."""
    db = _make_db()
    cfg = {
        "push_enabled": True,
        "poll_enabled": True,
        "poll_interval_minutes": 60,
    }
    with _QueryCounter(db) as qc:
        out = apply_ingestion_back_compat(db, account_id=42, provider_type="imap", cfg=cfg)
    assert qc.select_count() == 0, (
        f"Fast-path must not hit DB; got {qc.statements}"
    )
    assert out["push_enabled"] is True
    assert out["poll_enabled"] is True
    assert out["poll_interval_minutes"] == 60


def test_apply_ingestion_back_compat_legacy_imap_still_backfills_from_settings():
    """Legacy row missing push_enabled → reads watch:<id> setting."""
    db = _make_db()
    set_setting(db, S.watch(7), {"enabled": True})
    cfg = {}  # No push/poll keys at all; pure-legacy row.
    out = apply_ingestion_back_compat(db, account_id=7, provider_type="imap", cfg=cfg)
    assert out["push_enabled"] is True
    assert out["poll_enabled"] is True
    assert "poll_interval_minutes" in out


def test_apply_ingestion_back_compat_legacy_gmail_with_no_watch_row():
    """Legacy gmail row, no gmail_watches → defaults to push_enabled=True."""
    db = _make_db()
    cfg = {}
    out = apply_ingestion_back_compat(
        db, account_id=99, provider_type="gmail_api", cfg=cfg,
    )
    assert out["push_enabled"] is True


# ---------------------------------------------------------------------------
# #134.3 — latest_hipaa_boundary bulk variant
# ---------------------------------------------------------------------------


def test_latest_hipaa_boundaries_for_accounts_returns_same_data_one_query():
    db = _make_db()
    user_id = _make_user(db, "owner@test.com")
    aid_a = create_email_account(
        db, user_id, "A", "imap", {"username": "a@x"},
    )
    aid_b = create_email_account(
        db, user_id, "B", "imap", {"username": "b@x"},
    )
    # Two boundary events for A, one for B. Most-recent wins per scope.
    record_hipaa_boundary(db, f"account:{aid_a}", "on", actor_id=user_id)
    record_hipaa_boundary(db, f"account:{aid_a}", "off", actor_id=user_id)
    record_hipaa_boundary(db, f"account:{aid_b}", "on", actor_id=user_id)

    # Bulk variant reads everything in one round-trip.
    with _QueryCounter(db) as qc:
        result = latest_hipaa_boundaries_for_accounts(db)
    assert qc.select_count() == 1

    # Same data shape as per-account latest_hipaa_boundary().
    expected_a = latest_hipaa_boundary(db, f"account:{aid_a}")
    expected_b = latest_hipaa_boundary(db, f"account:{aid_b}")
    assert result[f"account:{aid_a}"]["direction"] == expected_a["direction"]
    assert result[f"account:{aid_b}"]["direction"] == expected_b["direction"]


# ---------------------------------------------------------------------------
# #134.4 — disabled_user_ids set-membership
# ---------------------------------------------------------------------------


def test_disabled_user_ids_one_query_per_loop_iteration():
    db = _make_db()
    enabled_uid = _make_user(db, "enabled@test.com", disabled=False)
    disabled_uid = _make_user(db, "disabled@test.com", disabled=True)

    with _QueryCounter(db) as qc:
        disabled = disabled_user_ids(db)
        # 100-account loop simulating the watcher-restore inner.
        results = []
        for _ in range(100):
            results.append(enabled_uid in disabled)
            results.append(disabled_uid in disabled)

    # Pre-fix: 200 SELECTs (one is_user_disabled per check).
    # Post-fix: 1 (one set fetch).
    assert qc.select_count() == 1
    assert disabled == {disabled_uid}
    assert all(r is False for r in results[::2])  # enabled checks
    assert all(r is True for r in results[1::2])  # disabled checks


def test_disabled_user_ids_matches_per_call_is_user_disabled():
    db = _make_db()
    a = _make_user(db, "a@t.com", disabled=False)
    b = _make_user(db, "b@t.com", disabled=True)
    c = _make_user(db, "c@t.com", disabled=True)
    bulk = disabled_user_ids(db)
    assert (a in bulk) == is_user_disabled(db, a)
    assert (b in bulk) == is_user_disabled(db, b)
    assert (c in bulk) == is_user_disabled(db, c)


# ---------------------------------------------------------------------------
# #145.6 — request-scoped list_email_accounts memo
# ---------------------------------------------------------------------------


def test_get_request_accounts_memoises_within_request_state():
    """Multiple calls on the same request reuse the cached result."""
    from types import SimpleNamespace

    from email_triage.web.app import get_request_accounts

    db = _make_db()
    user_id = _make_user(db, "u@t.com")
    create_email_account(db, user_id, "A", "imap", {"username": "a@x"})
    create_email_account(db, user_id, "B", "imap", {"username": "b@x"})

    # Build a minimal Request stand-in: needs .state and .app.state.db.
    state = SimpleNamespace()
    request = SimpleNamespace(
        state=state,
        app=SimpleNamespace(state=SimpleNamespace(db=db)),
    )

    with _QueryCounter(db) as qc:
        first = get_request_accounts(request)
        second = get_request_accounts(request)
        third = get_request_accounts(request, user_id=user_id)
        fourth = get_request_accounts(request, user_id=user_id)
        # Repeat with admin scope a fourth time to make sure that
        # cached path stays cached.
        fifth = get_request_accounts(request)

    # Cache identity holds within each key class.
    assert first is second is fifth
    assert third is fourth

    # list_email_accounts(user_id=None) issues 1 SELECT against
    # email_accounts; list_email_accounts(user_id=X) issues 2 (owner +
    # delegate JOIN). Pre-fix, second/fourth/fifth would each repeat their
    # query (5 calls × shape = 7 SELECTs total). Post-fix, exactly one
    # fetch per cache key — so 1 + 2 = 3 account-shaped SELECTs.
    n_account_selects = qc.select_count(like="FROM email_accounts ea")
    assert n_account_selects == 3, (
        f"Expected 3 account-list SELECTs (1 admin + 2 user); "
        f"got {n_account_selects}: {qc.statements}"
    )


# ---------------------------------------------------------------------------
# #140.3 — settings_keys registry
# ---------------------------------------------------------------------------


def test_settings_keys_round_trip_legacy_string_shape():
    """Existing rows under the old f-string key must still round-trip."""
    db = _make_db()
    # Write under the legacy string shape directly.
    set_setting(db, "watch:42", {"enabled": True})
    # Read via the new builder — must hit the same row.
    val = get_setting(db, S.watch(42))
    assert val == {"enabled": True}


def test_settings_keys_new_calls_match_old_f_string_shape():
    """Builders must produce the canonical <thing>:<id> string."""
    assert S.watch(7) == "watch:7"
    assert S.watch_hwm(7) == "watch_hwm:7"
    assert S.watch_hwm_mailbox(7, "INBOX") == "watch_hwm:7:mailbox:INBOX"
    assert S.calendar_enabled(7) == "calendar_enabled:7"
    assert S.digest(7) == "digest:7"
    assert S.digest_schedules(7) == "digest_schedules:7"
    assert S.auth_stale(7) == "auth_stale:7"
    assert S.gmail_oauth_flow(7) == "gmail_oauth_flow:7"
    assert S.poll_state(7) == "poll_state:7"
    assert S.openclaw_quiet(7) == "openclaw_quiet:7"
    assert S.style_profile(7) == "style_profile:7"
    assert S.rag_sent_index_enabled(7) == "rag_sent_index_enabled:7"
    assert S.office365_clientstate(7) == "office365_clientstate:7"
    # Per-user.
    assert S.meeting_prefs(3) == "meeting_prefs:3"
    assert S.escalation_sms(3) == "escalation_sms:3"
    assert S.last_routes_account_id(3) == "last_routes_account_id:3"
    # Documented legacy exceptions.
    assert S.account_state(7, "foo") == "account_state:7:foo"
    assert S.user_scoped(3, "bar") == "user:3:bar"


def test_delete_account_settings_sweeps_every_known_key():
    db = _make_db()
    aid = 5
    other = 50
    # Plant rows under the catalogued keys for aid + a different account.
    set_setting(db, S.watch(aid), {"enabled": True})
    set_setting(db, S.calendar_enabled(aid), {"enabled": True})
    set_setting(db, S.digest_schedules(aid), [{"x": 1}])
    set_setting(db, S.watch_hwm(aid), {"hwm": 1})
    set_setting(db, S.watch_hwm_mailbox(aid, "INBOX"), {"hwm": 9})
    # And a different account that must NOT be touched.
    set_setting(db, S.watch(other), {"enabled": True})
    set_setting(db, S.watch_hwm_mailbox(other, "INBOX"), {"hwm": 1})

    deleted = S.delete_account_settings(db, aid)
    assert deleted >= 5

    # All aid keys gone.
    assert get_setting(db, S.watch(aid)) is None
    assert get_setting(db, S.calendar_enabled(aid)) is None
    assert get_setting(db, S.digest_schedules(aid)) is None
    assert get_setting(db, S.watch_hwm(aid)) is None
    assert get_setting(db, S.watch_hwm_mailbox(aid, "INBOX")) is None

    # Other account untouched.
    assert get_setting(db, S.watch(other)) == {"enabled": True}
    assert get_setting(db, S.watch_hwm_mailbox(other, "INBOX")) == {"hwm": 1}


def test_delete_account_settings_anchors_colon_to_avoid_prefix_collision():
    """Account 1 delete must NOT touch account 10 / 11 / 100."""
    db = _make_db()
    set_setting(db, S.watch(1), {"a": 1})
    set_setting(db, S.watch(10), {"a": 10})
    set_setting(db, S.watch(100), {"a": 100})
    set_setting(db, S.watch_hwm(1), {"x": 1})
    set_setting(db, S.watch_hwm(10), {"x": 10})

    S.delete_account_settings(db, 1)

    assert get_setting(db, S.watch(1)) is None
    assert get_setting(db, S.watch(10)) == {"a": 10}
    assert get_setting(db, S.watch(100)) == {"a": 100}
    assert get_setting(db, S.watch_hwm(1)) is None
    assert get_setting(db, S.watch_hwm(10)) == {"x": 10}
