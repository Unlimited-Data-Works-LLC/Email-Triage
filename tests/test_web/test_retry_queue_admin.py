"""Tests for the admin /admin/retry-queue page.

R-A ships the migration + db helpers in parallel; this test
synthesises the expected R-A schema (v30) inside the fixture so
the page-level tests run against the table shape R-A is going to
deliver. When R-A's commit lands at cherry-pick, the
``_install_ra_schema`` helper here becomes a no-op (table already
exists in the right shape from the migration) and the same tests
still pass.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest


# ---------------------------------------------------------------------------
# Synthesised R-A schema. The real migration (v30) lands in R-A's worktree;
# these tests need the table shape NOW so the admin-page coverage runs.
# ---------------------------------------------------------------------------


def _install_ra_schema(db) -> None:
    """Originally a fixture to install a stub watcher_retry_queue
    schema before R-A's v30 migration shipped. After cherry-pick
    (2026-05-17) R-A's real v30 migration ships the table with
    its canonical column names (``attempt_count`` / ``last_error_class``
    / ``last_error_msg`` / ``first_seen_at`` / ``last_error_at``).
    Conftest's ``init_db`` fixture already applies v30, so this
    helper is a NO-OP today — left in place so the per-test
    ``_install_ra_schema(db)`` calls don't need surgical removal.
    Stub-helper installation also dropped: ``email_triage.web.db``
    exports the real helpers.
    """
    return

    # Install stub helpers on email_triage.web.db. Use
    # globals().setdefault so a real R-A implementation wins.
    from email_triage.web import db as _wdb

    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    def _enqueue_retry(
        conn, *, account_id, provider_type,
        mailbox=None, uid=None, uidvalidity=None,
        gmail_msg_id=None, o365_msg_id=None,
        error_class, error_msg,
    ) -> int:
        now = _now()
        cur = conn.execute(
            "INSERT INTO watcher_retry_queue ("
            " account_id, provider_type, mailbox, uid, uidvalidity, "
            " gmail_msg_id, o365_msg_id, error_class, error_msg, "
            " state, attempts, next_attempt_at, created_at, updated_at"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', 0, ?, ?, ?)",
            (
                int(account_id), str(provider_type),
                mailbox, uid, uidvalidity,
                gmail_msg_id, o365_msg_id,
                error_class, error_msg, now, now, now,
            ),
        )
        conn.commit()
        return int(cur.lastrowid)

    def _mark_retry_dead(conn, retry_id, *, reason):
        now = _now()
        conn.execute(
            "UPDATE watcher_retry_queue SET state = 'dead', "
            "dead_reason = ?, updated_at = ? WHERE id = ?",
            (str(reason), now, int(retry_id)),
        )
        conn.commit()

    def _mark_retry_done(conn, retry_id):
        now = _now()
        conn.execute(
            "UPDATE watcher_retry_queue SET state = 'done', "
            "updated_at = ? WHERE id = ?",
            (now, int(retry_id)),
        )
        conn.commit()

    def _get_retry(conn, retry_id):
        row = conn.execute(
            "SELECT * FROM watcher_retry_queue WHERE id = ?",
            (int(retry_id),),
        ).fetchone()
        return row

    def _list_retries_for_admin(conn, *, account_id=None, state=None, limit=200):
        sql = "SELECT * FROM watcher_retry_queue WHERE 1=1"
        args: list = []
        if account_id is not None:
            sql += " AND account_id = ?"
            args.append(int(account_id))
        if state is not None:
            sql += " AND state = ?"
            args.append(str(state))
        sql += " ORDER BY id DESC LIMIT ?"
        args.append(int(limit))
        return list(conn.execute(sql, args).fetchall())

    def _count_recent_deads(conn, *, account_id=None, since_hours=24):
        since = (
            datetime.now(timezone.utc) - timedelta(hours=int(since_hours))
        ).isoformat()
        if account_id is None:
            row = conn.execute(
                "SELECT COUNT(*) FROM watcher_retry_queue "
                "WHERE state = 'dead' AND updated_at >= ?",
                (since,),
            ).fetchone()
        else:
            row = conn.execute(
                "SELECT COUNT(*) FROM watcher_retry_queue "
                "WHERE state = 'dead' AND updated_at >= ? "
                "AND account_id = ?",
                (since, int(account_id)),
            ).fetchone()
        if row is None:
            return 0
        return int(row[0])

    def _list_due_retries(conn, *, limit=10):
        return list(conn.execute(
            "SELECT * FROM watcher_retry_queue "
            "WHERE state = 'pending' "
            "ORDER BY next_attempt_at ASC LIMIT ?",
            (int(limit),),
        ).fetchall())

    for name, fn in [
        ("enqueue_retry", _enqueue_retry),
        ("mark_retry_dead", _mark_retry_dead),
        ("mark_retry_done", _mark_retry_done),
        ("get_retry", _get_retry),
        ("list_retries_for_admin", _list_retries_for_admin),
        ("count_recent_deads", _count_recent_deads),
        ("list_due_retries", _list_due_retries),
    ]:
        if not hasattr(_wdb, name):
            setattr(_wdb, name, fn)


def _make_account(db, *, account_id=1, name="acct1", hipaa=False, user_id=None):
    now = datetime.now(timezone.utc).isoformat()
    if user_id is None:
        cur = db.execute(
            "INSERT INTO users (email, name, role, created_at) "
            "VALUES (?, ?, ?, ?)",
            (f"u{account_id}@test.com", f"User {account_id}", "user", now),
        )
        user_id = cur.lastrowid
    db.execute(
        "INSERT INTO email_accounts "
        "(id, user_id, name, provider_type, config_json, hipaa, "
        " created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (account_id, user_id, name, "imap", "{}", 1 if hipaa else 0, now, now),
    )
    db.commit()
    return account_id


def _seed_retry_row(
    db, *, account_id, state="pending", mailbox=None, uid=None,
    gmail_msg_id=None, o365_msg_id=None,
    error_class="ReadTimeout", error_msg="timed out",
    dead_reason=None, attempts=0, provider_type="imap",
    updated_hours_ago=0, failure_kind=None,
) -> int:
    """INSERT a row against the canonical v30 ``watcher_retry_queue``
    schema (R-A). Column-name aliases here translate the kwargs
    used by tests (kept stable so test bodies don't need rewrite)
    into R-A's column names — ``attempts`` → ``attempt_count``,
    ``error_class`` → ``last_error_class``, ``error_msg`` →
    ``last_error_msg``, ``updated_hours_ago`` → ``last_error_at``.
    ``next_attempt_at`` is required (NOT NULL) so it gets the same
    timestamp on insert; tests bump it explicitly via the
    ``retry-now`` route when they care about the value.
    """
    now = (
        datetime.now(timezone.utc) - timedelta(hours=updated_hours_ago)
    ).isoformat()
    resolved_at = now if state in ("dead", "done") else None
    cur = db.execute(
        "INSERT INTO watcher_retry_queue ("
        " account_id, provider_type, mailbox, uid, "
        " gmail_msg_id, o365_msg_id, "
        " last_error_class, last_error_msg, last_error_at, "
        " state, attempt_count, next_attempt_at, dead_reason, "
        " resolved_at, first_seen_at, created_at, failure_kind"
        ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            account_id, provider_type, mailbox,
            int(uid) if uid is not None else None,
            gmail_msg_id, o365_msg_id,
            error_class, error_msg, now,
            state, attempts, now, dead_reason,
            resolved_at, now, now, failure_kind,
        ),
    )
    db.commit()
    return int(cur.lastrowid)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestAdminRetryQueueIndex:
    def test_anonymous_redirects_to_login(self, client, db):
        _install_ra_schema(db)
        r = client.get("/admin/retry-queue", follow_redirects=False)
        assert r.status_code == 303

    def test_non_admin_forbidden(self, client, db, user_cookies):
        _install_ra_schema(db)
        r = client.get(
            "/admin/retry-queue", cookies=user_cookies,
            follow_redirects=False,
        )
        assert r.status_code == 403

    def test_admin_empty_renders(self, client, db, admin_cookies):
        _install_ra_schema(db)
        r = client.get(
            "/admin/retry-queue", cookies=admin_cookies,
            follow_redirects=False,
        )
        assert r.status_code == 200
        assert "Retry queue" in r.text
        # Empty-state copy fires when there are no rows.
        assert "Nothing in this view" in r.text

    def test_watch_delivery_failure_shows_plain_english_badge(
        self, client, db, admin_cookies,
    ):
        """#7: a watcher delivery failure renders a plain-
        English 'Delivery failure' flag (test the VIEW), not just the leaked
        WatchDeliveryFailed qualname this admin page's audience header says
        operators shouldn't have to read. failure_kind rides the row via
        SELECT *; the badge + qualname-suppression are template-only."""
        _make_account(db, account_id=1, name="Inbox A")
        _seed_retry_row(
            db, account_id=1, state="pending",
            failure_kind="watch_delivery_failure",
            error_class="WatchDeliveryFailed",
        )
        r = client.get("/admin/retry-queue", cookies=admin_cookies)
        assert r.status_code == 200
        body = r.text
        assert "Delivery failure" in body
        assert "WatchDeliveryFailed" not in body  # qualname suppressed

    def test_non_delivery_row_has_no_badge_and_keeps_error_class(
        self, client, db, admin_cookies,
    ):
        """A normal retry row (no delivery-failure kind) shows NO 'Delivery
        failure' badge and still surfaces its real error class."""
        _make_account(db, account_id=1, name="Inbox A")
        _seed_retry_row(
            db, account_id=1, state="pending",
            failure_kind=None, error_class="ReadTimeout",
        )
        r = client.get("/admin/retry-queue", cookies=admin_cookies)
        assert r.status_code == 200
        body = r.text
        assert "Delivery failure" not in body
        assert "ReadTimeout" in body

    def test_compound_edge_keeps_delivery_badge_no_qualname(
        self, client, db, admin_cookies,
    ):
        """#9 BEHAVIORAL (db-sme + DA impl-review must-fix/should-fix): the
        compound edge — a routed action errored (status=='e') AND a watch was
        undelivered on the SAME message — drives a real two-enqueue sequence
        (the  delivery-retry, then the generic status=='e' bump). Assert it
        yields ONE row that KEEPS failure_kind='watch_delivery_failure' past the
        generic NULL-kind bump (COALESCE-preserved), and the rendered row shows
        the 'Delivery failure' badge with NO raw RuntimeError qualname. This pins
        the load-bearing COALESCE + UPSERT-dedup + qualname-suppression that the
        structural #9 ordering pin cannot see (a COALESCE removal or a template
        regression would pass the ordering pin but fail HERE)."""
        from email_triage.web.watcher_retry import (
            enqueue_watch_delivery_retry,
            enqueue_watcher_retry,
        )
        _make_account(db, account_id=1, name="Inbox A")
        # (1) the moved  block enqueues the watch-delivery retry FIRST
        rid = enqueue_watch_delivery_retry(
            db, account_id=1, provider_type="imap",
            failed_count=2, total_count=3,
            mailbox="INBOX", uid=42, uidvalidity=1234567,
        )
        # (2) the status=='e' re-raise lands in the generic handler, which bumps
        #     the SAME addressing tuple with failure_kind=None
        rid2 = enqueue_watcher_retry(
            db, account_id=1, provider_type="imap",
            mailbox="INBOX", uid=42, uidvalidity=1234567,
            error=RuntimeError("triage error"), failure_kind=None,
        )
        assert rid2 == rid, "the generic bump must hit the SAME row (UPSERT dedup)"
        rows = db.execute(
            "SELECT failure_kind, last_error_class FROM watcher_retry_queue "
            "WHERE account_id=1"
        ).fetchall()
        assert len(rows) == 1, "compound edge must yield ONE physical row"
        assert rows[0]["failure_kind"] == "watch_delivery_failure", (
            "failure_kind must survive the generic NULL-kind bump (COALESCE)"
        )
        # the bump did refresh the class to the routed-action error…
        assert rows[0]["last_error_class"] == "RuntimeError"
        # …but the rendered row shows the badge and SUPPRESSES the raw qualname.
        r = client.get("/admin/retry-queue", cookies=admin_cookies)
        assert r.status_code == 200
        body = r.text
        assert "Delivery failure" in body
        assert "RuntimeError" not in body

    def test_count_retries_for_admin_matches_filter(self, db):
        """ — count helper mirrors list_retries_for_admin's state
        filter so the 'showing N of M' denominator is accurate."""
        from email_triage.web.db import count_retries_for_admin
        _install_ra_schema(db)
        _make_account(db, account_id=1, name="Inbox A")
        for _ in range(4):
            _seed_retry_row(db, account_id=1, state="pending")
        for _ in range(2):
            _seed_retry_row(db, account_id=1, state="dead")
        assert count_retries_for_admin(db, state="pending") == 4
        assert count_retries_for_admin(db, state="dead") == 2
        assert count_retries_for_admin(db) == 6  # no filter → all states

    def test_over_cap_renders_showing_n_of_m(
        self, client, db, admin_cookies, monkeypatch,
    ):
        """ — when the queue exceeds the page cap, the admin sees a
        'showing first N of M' banner instead of a complete-looking list.
        Cap is monkeypatched small so the test stays fast."""
        import email_triage.web.routers.ui.retry_queue as rq
        monkeypatch.setattr(rq, "_CAP_COMBINED", 2)
        _install_ra_schema(db)
        _make_account(db, account_id=1, name="Inbox A")
        for _ in range(5):                      # 5 pending > cap of 2
            _seed_retry_row(db, account_id=1, state="pending")
        r = client.get(
            "/admin/retry-queue", cookies=admin_cookies,
            follow_redirects=False,
        )
        assert r.status_code == 200
        # Banner names the cap (2) and the true total (5).
        assert "first" in r.text and "of 5" in r.text
        assert "not shown" in r.text

    def test_under_cap_no_banner(
        self, client, db, admin_cookies, monkeypatch,
    ):
        """Under the cap → no 'showing N of M' banner (don't cry wolf)."""
        import email_triage.web.routers.ui.retry_queue as rq
        monkeypatch.setattr(rq, "_CAP_COMBINED", 50)
        _install_ra_schema(db)
        _make_account(db, account_id=1, name="Inbox A")
        _seed_retry_row(db, account_id=1, state="pending")
        r = client.get(
            "/admin/retry-queue", cookies=admin_cookies,
            follow_redirects=False,
        )
        assert r.status_code == 200
        assert "not shown" not in r.text

    def test_single_state_pager_reaches_older(
        self, client, db, admin_cookies, monkeypatch,
    ):
        """ reachability — a single-state view pages via ?offset= so
        the full backlog past the cap is REACHABLE, not just counted.
        Cap monkeypatched small to stay fast."""
        import email_triage.web.routers.ui.retry_queue as rq
        monkeypatch.setattr(rq, "_CAP_SINGLE", 2)
        _install_ra_schema(db)
        _make_account(db, account_id=1, name="Inbox A")
        for _ in range(5):  # 5 dead > cap of 2
            _seed_retry_row(db, account_id=1, state="dead")
        # First page: pager + a reachable 'load older' link.
        r = client.get(
            "/admin/retry-queue?state=dead", cookies=admin_cookies,
            follow_redirects=False,
        )
        assert r.status_code == 200
        assert "of 5" in r.text
        assert "load older" in r.text
        assert "offset=2" in r.text
        # Older page: reachable, with a 'newer' link back.
        r2 = client.get(
            "/admin/retry-queue?state=dead&offset=4", cookies=admin_cookies,
            follow_redirects=False,
        )
        assert r2.status_code == 200
        assert "newer" in r2.text

    def test_admin_lists_pending_rows(self, client, db, admin_cookies):
        _install_ra_schema(db)
        _make_account(db, account_id=1, name="Inbox A")
        _seed_retry_row(
            db, account_id=1, state="pending",
            mailbox="INBOX", uid="42",
            error_class="httpx.ReadTimeout", error_msg="read timed out",
        )
        r = client.get(
            "/admin/retry-queue", cookies=admin_cookies,
            follow_redirects=False,
        )
        assert r.status_code == 200
        assert "Inbox A" in r.text
        # Qualname stripped — "ReadTimeout" not "httpx.ReadTimeout"
        # in the rendered short class label (the full msg still
        # appears in the muted sub-text).
        assert "ReadTimeout" in r.text
        # Plain-English state chip.
        assert "Waiting to retry" in r.text

    def test_state_filter_dead(self, client, db, admin_cookies):
        _install_ra_schema(db)
        _make_account(db, account_id=1, name="Inbox A")
        _seed_retry_row(db, account_id=1, state="pending", uid="11")
        _seed_retry_row(
            db, account_id=1, state="dead", uid="22",
            dead_reason="auth_revoked",
        )
        r = client.get(
            "/admin/retry-queue?state=dead", cookies=admin_cookies,
        )
        assert r.status_code == 200
        # Only the dead row's "Account needs re-authentication" copy
        # appears in dead-only view.
        assert "Account needs re-authentication" in r.text

    def test_hipaa_mailbox_redacted(self, client, db, admin_cookies):
        _install_ra_schema(db)
        _make_account(db, account_id=2, name="Patients", hipaa=True)
        _seed_retry_row(
            db, account_id=2, state="pending",
            mailbox="INBOX/Patients-2026", uid="7",
        )
        r = client.get(
            "/admin/retry-queue", cookies=admin_cookies,
        )
        assert r.status_code == 200
        # Mailbox cell is suppressed.
        assert "(redacted)" in r.text
        assert "INBOX/Patients-2026" not in r.text


class TestAdminRetryQueueActions:
    def test_retry_now_bumps_next_attempt(self, client, db, admin_cookies):
        _install_ra_schema(db)
        _make_account(db, account_id=1)
        # Seed with a far-future next_attempt_at so we can detect
        # the bump easily.
        future = (
            datetime.now(timezone.utc) + timedelta(hours=24)
        ).isoformat()
        # Use the shared _seed_retry_row helper rather than reinventing
        # the INSERT — keeps R-A's canonical column names in one place.
        retry_id = _seed_retry_row(
            db, account_id=1, state="pending", mailbox="INBOX", uid="1",
            error_class="ReadTimeout", error_msg="", attempts=1,
        )
        # Bump next_attempt_at to the far future so the route's
        # bump-to-now is observable.
        db.execute(
            "UPDATE watcher_retry_queue SET next_attempt_at = ? "
            "WHERE id = ?",
            (future, retry_id),
        )
        db.commit()

        r = client.post(
            f"/admin/retry-queue/{retry_id}/retry-now",
            cookies=admin_cookies,
            follow_redirects=False,
        )
        assert r.status_code == 303

        new_next = db.execute(
            "SELECT next_attempt_at FROM watcher_retry_queue WHERE id = ?",
            (retry_id,),
        ).fetchone()[0]
        # Bumped to ~now (well before the original 24h-future ts).
        assert new_next < future

    def test_abandon_marks_dead(self, client, db, admin_cookies):
        _install_ra_schema(db)
        _make_account(db, account_id=1)
        retry_id = _seed_retry_row(db, account_id=1, state="pending")

        r = client.post(
            f"/admin/retry-queue/{retry_id}/abandon",
            cookies=admin_cookies,
            follow_redirects=False,
        )
        assert r.status_code == 303

        row = db.execute(
            "SELECT state, dead_reason FROM watcher_retry_queue WHERE id = ?",
            (retry_id,),
        ).fetchone()
        assert row[0] == "dead"
        assert row[1] == "operator_abandoned"

    def test_retry_now_404_unknown_id(self, client, db, admin_cookies):
        _install_ra_schema(db)
        r = client.post(
            "/admin/retry-queue/9999/retry-now",
            cookies=admin_cookies,
            follow_redirects=False,
        )
        assert r.status_code == 404

    def test_abandon_404_unknown_id(self, client, db, admin_cookies):
        _install_ra_schema(db)
        r = client.post(
            "/admin/retry-queue/9999/abandon",
            cookies=admin_cookies,
            follow_redirects=False,
        )
        assert r.status_code == 404

    def test_actions_emit_audit_rows(self, client, db, admin_cookies):
        _install_ra_schema(db)
        _make_account(db, account_id=1)
        retry_id = _seed_retry_row(db, account_id=1, state="pending")

        before = db.execute(
            "SELECT COUNT(*) FROM access_log "
            "WHERE route LIKE '/admin/retry-queue%'"
        ).fetchone()[0]

        client.post(
            f"/admin/retry-queue/{retry_id}/retry-now",
            cookies=admin_cookies, follow_redirects=False,
        )
        client.post(
            f"/admin/retry-queue/{retry_id}/abandon",
            cookies=admin_cookies, follow_redirects=False,
        )
        # GET also audits.
        client.get(
            "/admin/retry-queue", cookies=admin_cookies,
        )

        after = db.execute(
            "SELECT COUNT(*) FROM access_log "
            "WHERE route LIKE '/admin/retry-queue%'"
        ).fetchone()[0]
        assert after - before >= 3

    def test_non_admin_cannot_post_actions(self, client, db, user_cookies):
        _install_ra_schema(db)
        _make_account(db, account_id=1)
        retry_id = _seed_retry_row(db, account_id=1)
        r = client.post(
            f"/admin/retry-queue/{retry_id}/retry-now",
            cookies=user_cookies, follow_redirects=False,
        )
        assert r.status_code == 403
        r = client.post(
            f"/admin/retry-queue/{retry_id}/abandon",
            cookies=user_cookies, follow_redirects=False,
        )
        assert r.status_code == 403


class TestRetryQueueCSRFEnforcement:
    """When the install has CSRF enforcement on, POSTs without a
    token are rejected before reaching the handler."""

    def test_post_without_csrf_rejected(self, raw_client, db, admin_cookies, app):
        _install_ra_schema(db)
        _make_account(db, account_id=1)
        retry_id = _seed_retry_row(db, account_id=1)
        # Flip the install to enforce.
        app.state.csrf_enforce = True
        try:
            r = raw_client.post(
                f"/admin/retry-queue/{retry_id}/abandon",
                cookies=admin_cookies, follow_redirects=False,
            )
            # CSRF middleware bounces us before the handler runs.
            # Different installs return 400 or 403 depending on
            # middleware shape — either is acceptable, as long as
            # the state didn't change.
            assert r.status_code in (400, 403)
            row = db.execute(
                "SELECT state FROM watcher_retry_queue WHERE id = ?",
                (retry_id,),
            ).fetchone()
            assert row[0] == "pending"
        finally:
            app.state.csrf_enforce = False
