"""Tests for the admin /admin/retry-queue page (#175 R-B).

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
    updated_hours_ago=0,
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
        " resolved_at, first_seen_at, created_at"
        ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            account_id, provider_type, mailbox,
            int(uid) if uid is not None else None,
            gmail_msg_id, o365_msg_id,
            error_class, error_msg, now,
            state, attempts, now, dead_reason,
            resolved_at, now, now,
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

    def test_post_without_csrf_rejected(self, client, db, admin_cookies, app):
        _install_ra_schema(db)
        _make_account(db, account_id=1)
        retry_id = _seed_retry_row(db, account_id=1)
        # Flip the install to enforce.
        app.state.csrf_enforce = True
        try:
            r = client.post(
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
