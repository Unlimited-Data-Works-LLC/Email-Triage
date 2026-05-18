"""Tests for the ``/logs`` admin viewer and the account-resolution helper
that keeps ``account_id`` log extras human-readable.

Audit item #11: log lines referencing ``account_id=N`` were opaque
without cross-referencing ``/accounts``. The emit side now splats a
small helper so every log gets ``account_name`` too; the render side
resolves the numeric id to a link pill via an ``accounts_by_id`` dict
built once per ``/logs`` request.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone


def _make_account(db, user_id, *, name="Ops Mailbox"):
    now = datetime.now(timezone.utc).isoformat()
    cursor = db.execute(
        "INSERT INTO email_accounts "
        "(user_id, name, provider_type, config_json, is_active, "
        " created_at, updated_at) "
        "VALUES (?, ?, ?, ?, 1, ?, ?)",
        (user_id, name, "imap",
         json.dumps({"host": "mail.test.com"}), now, now),
    )
    db.commit()
    return cursor.lastrowid


class TestAcctLogExtras:
    """``_acct_log_extras`` is the one helper every ``account_id=`` log
    call in ``app.py`` now splats into its extras. It must always
    emit both keys so the log viewer can pair them."""

    def test_log_extras_include_account_name_via_helper(self):
        from email_triage.web.app import _acct_log_extras
        extras = _acct_log_extras({"id": 5, "name": "Clinic Inbox"})
        assert extras == {"account_id": 5, "account_name": "Clinic Inbox"}

    def test_log_extras_tolerate_missing_name(self):
        """Defensive: if ``acct`` somehow lacks ``name`` we should still
        emit an empty string rather than KeyError'ing the log call."""
        from email_triage.web.app import _acct_log_extras
        extras = _acct_log_extras({"id": 7})
        assert extras == {"account_id": 7, "account_name": ""}


class TestLogsPageAccountChip:
    """Render-side: the admin ``/logs`` viewer resolves the
    ``account_id`` extra into a ``Name (#id)`` chip that links to the
    account listing."""

    def _insert_log(self, db, *, account_id: int, account_name: str):
        now = datetime.now(timezone.utc).isoformat()
        db.execute(
            "INSERT INTO log_entries "
            "(ts, level, logger, message, extra_json, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (now, "INFO", "web.app", "Watcher triaged message",
             json.dumps({
                 "account_id": account_id,
                 "account_name": account_name,
                 "uid": "42",
             }),
             now),
        )
        db.commit()

    def test_logs_page_renders_account_name_chip(
        self, client, db, admin_cookies, admin_user,
    ):
        acct_id = _make_account(db, admin_user["id"], name="Clinic Inbox")
        self._insert_log(db, account_id=acct_id, account_name="Clinic Inbox")

        resp = client.get("/logs", cookies=admin_cookies)
        assert resp.status_code == 200
        body = resp.text
        # Chip shows the resolved name AND the numeric id in parens,
        # wrapped in a link to /accounts.
        assert "Clinic Inbox" in body
        assert f"(#{acct_id})" in body
        assert 'href="/accounts"' in body
        # The duplicate ``account_name=...`` line should be suppressed
        # by the template (the chip already conveys it).
        assert "account_name=Clinic Inbox" not in body

    def test_logs_page_falls_back_when_account_deleted(
        self, client, db, admin_cookies, admin_user,
    ):
        """If the account has been deleted since the log was emitted,
        the template should fall back to the plain ``account_id=N``
        form — no KeyError, no empty chip."""
        self._insert_log(db, account_id=9999, account_name="Ghost")
        resp = client.get("/logs", cookies=admin_cookies)
        assert resp.status_code == 200
        assert "account_id=9999" in resp.text

    def test_logs_page_requires_admin(
        self, client, db, user_cookies, regular_user,
    ):
        resp = client.get("/logs", cookies=user_cookies)
        assert resp.status_code == 403


class TestLogsSearch:
    """Free-text search on /logs — matches message + logger + extras
    so operators can correlate on flow_id, sender, account_name, uid,
    or any text threaded into log extras."""

    def _seed(self, db, *, message: str, extra: dict | None = None,
              level: str = "ERROR", logger: str = "email_triage.actions.label"):
        now = datetime.now(timezone.utc).isoformat()
        db.execute(
            "INSERT INTO log_entries "
            "(ts, level, logger, message, extra_json, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (now, level, logger, message, json.dumps(extra or {}), now),
        )
        db.commit()

    def test_search_by_flow_id_narrows_results(
        self, client, db, admin_cookies,
    ):
        self._seed(db, message="Failed to apply label",
                   extra={"flow_id": "22ecbc6a-a3bd-4ca0-b453-349f2eedc46b"})
        self._seed(db, message="Watcher triaged message",
                   extra={"flow_id": "00000000-deaf-beef-0000-000000000000"},
                   level="INFO", logger="email_triage.web.app")

        resp = client.get(
            "/logs?q=22ecbc6a-a3bd", cookies=admin_cookies,
        )
        assert resp.status_code == 200
        assert "Failed to apply label" in resp.text
        assert "Watcher triaged message" not in resp.text

    def test_search_matches_sender_in_extras(
        self, client, db, admin_cookies,
    ):
        self._seed(db, message="Label applied",
                   extra={"sender": "shipment-tracking@amazon.com"},
                   level="INFO")
        self._seed(db, message="Label applied",
                   extra={"sender": "boss@company.com"},
                   level="INFO")

        resp = client.get("/logs?q=amazon", cookies=admin_cookies)
        assert resp.status_code == 200
        assert "amazon.com" in resp.text
        assert "boss@company.com" not in resp.text

    def test_search_case_insensitive(
        self, client, db, admin_cookies,
    ):
        self._seed(db, message="Failed to apply label",
                   extra={"sender": "SHIPMENT-TRACKING@AMAZON.COM"})
        resp = client.get("/logs?q=amazon", cookies=admin_cookies)
        assert resp.status_code == 200
        assert "AMAZON.COM" in resp.text

    def test_search_empty_returns_all(
        self, client, db, admin_cookies,
    ):
        self._seed(db, message="Label applied", level="INFO")
        resp = client.get("/logs?q=", cookies=admin_cookies)
        assert resp.status_code == 200
        assert "Label applied" in resp.text

    def test_search_combines_with_level_filter(
        self, client, db, admin_cookies,
    ):
        self._seed(db, message="ERR: notifications",
                   extra={"sender": "amazon.com"}, level="ERROR")
        self._seed(db, message="INFO: amazon delivery",
                   extra={"sender": "amazon.com"}, level="INFO",
                   logger="email_triage.web.app")
        resp = client.get(
            "/logs?level=ERROR&q=amazon", cookies=admin_cookies,
        )
        assert resp.status_code == 200
        assert "ERR: notifications" in resp.text
        assert "INFO: amazon delivery" not in resp.text

    def test_search_box_rendered_with_current_query(
        self, client, db, admin_cookies,
    ):
        resp = client.get("/logs?q=flow-abc", cookies=admin_cookies)
        assert resp.status_code == 200
        # Input echoes the query so the operator sees what's active.
        assert 'value="flow-abc"' in resp.text
        assert 'placeholder="search flow_id' in resp.text


class TestLogsDensityImprovements:
    """Item #10 — /logs information-density pass. These regressions pin
    the six template improvements so a future refactor can't silently
    drop them."""

    def _insert_log(
        self, db, *, level="INFO", extra: dict | None = None,
        message: str = "hello",
    ):
        now = datetime.now(timezone.utc).isoformat()
        db.execute(
            "INSERT INTO log_entries "
            "(ts, level, logger, message, extra_json, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (now, level, "web.app", message,
             json.dumps(extra or {}), now),
        )
        db.commit()

    # 10.2 — severity-default-open -----------------------------------

    def test_logs_error_rows_open_by_default(
        self, client, db, admin_cookies, admin_user,
    ):
        self._insert_log(db, level="ERROR", extra={"error": "boom"})
        resp = client.get("/logs", cookies=admin_cookies)
        assert resp.status_code == 200
        body = resp.text
        # The ERROR row's <details> block must render with the ``open``
        # attribute so the extras are visible without a click.
        assert "log-row-extras" in body
        assert 'class="log-row-extras" open' in body

    def test_logs_warning_rows_open_by_default(
        self, client, db, admin_cookies, admin_user,
    ):
        self._insert_log(db, level="WARNING", extra={"uid": "42"})
        resp = client.get("/logs", cookies=admin_cookies)
        assert resp.status_code == 200
        assert 'class="log-row-extras" open' in resp.text

    def test_logs_info_rows_closed_by_default(
        self, client, db, admin_cookies, admin_user,
    ):
        self._insert_log(db, level="INFO", extra={"uid": "42"})
        resp = client.get("/logs", cookies=admin_cookies)
        assert resp.status_code == 200
        body = resp.text
        # INFO rows still render the <details> block but NOT open —
        # expand-all is the user's override.
        assert "log-row-extras" in body
        assert 'class="log-row-extras" open' not in body

    # 10.3 — inline priority pills -----------------------------------

    def test_logs_priority_pills_rendered_for_account_id(
        self, client, db, admin_cookies, admin_user,
    ):
        acct_id = _make_account(db, admin_user["id"], name="Clinic Inbox")
        self._insert_log(
            db, level="INFO",
            extra={"account_id": acct_id, "uid": "42"},
        )
        resp = client.get("/logs", cookies=admin_cookies)
        assert resp.status_code == 200
        body = resp.text
        # A pill with the resolved account name appears inline with the
        # message, not just inside the <details> block.
        assert "log-pill" in body
        assert "Clinic Inbox" in body
        assert f"(#{acct_id})" in body

    def test_logs_priority_pills_capped_at_three(
        self, client, db, admin_cookies, admin_user,
    ):
        # Five priority-eligible fields — template must only render 3.
        self._insert_log(
            db, level="INFO",
            extra={
                "account_id": 9999,   # no matching account -> skipped
                "error": "boom",
                "message_id": "<abc@x>",
                "run_id": "r1",
                "elapsed_secs": 1.5,
                "extra_field": "ignored",
            },
        )
        resp = client.get("/logs", cookies=admin_cookies)
        assert resp.status_code == 200
        body = resp.text
        # Only 3 inline pills rendered. Walk the message cell by locating
        # the pill class — count occurrences of the standalone pill
        # wrappers (``log-pill`` appears once per rendered pill wrapper
        # element; the details <pre> block does NOT use this class).
        # Both the ``log-pill`` and ``log-pill-error`` variants count.
        #
        # Excluding the ``log-pill-key`` span inside each pill, the
        # outer pill element always has ``class="log-pill"`` or
        # ``class="log-pill log-pill-error"`` as its substring.
        outer_pill_count = body.count('class="log-pill"') + body.count('class="log-pill log-pill-error"')
        assert outer_pill_count == 3, (
            f"expected exactly 3 inline pills, got {outer_pill_count}"
        )

    # 10.6 — sticky header -------------------------------------------

    def test_logs_sticky_header_class_present(
        self, client, db, admin_cookies, admin_user,
    ):
        self._insert_log(db)
        resp = client.get("/logs", cookies=admin_cookies)
        assert resp.status_code == 200
        body = resp.text
        # Either the sticky CSS rule or the class selector must be
        # shipped to the client — we assert the CSS rule is present.
        assert "position: sticky" in body
        assert "logs-table" in body

    # 10.1 — expand-all toggle ---------------------------------------

    def test_logs_expand_all_button_present(
        self, client, db, admin_cookies, admin_user,
    ):
        self._insert_log(db)
        resp = client.get("/logs", cookies=admin_cookies)
        assert resp.status_code == 200
        body = resp.text
        assert 'id="logs-expand-all"' in body
        # The localStorage-backed persistence key is part of the
        # contract so the preference survives navigation.
        assert "logs.expandAll" in body

    # 10.5 — level-coloured filter buttons ---------------------------

    def test_logs_filter_buttons_have_level_class(
        self, client, db, admin_cookies, admin_user,
    ):
        self._insert_log(db)
        resp = client.get("/logs", cookies=admin_cookies)
        assert resp.status_code == 200
        body = resp.text
        # Each filter button must carry a level-specific class so the
        # stylesheet can colour them distinctly.
        for lv in ("ERROR", "WARNING", "INFO", "DEBUG"):
            assert f"level-{lv}" in body


# ---------------------------------------------------------------------------
# Legacy-row render-time unpack — pre-ec06f21 shape
# ---------------------------------------------------------------------------

class TestLegacyExtraUnpack:
    """Rows emitted before the ec06f21 SQLite-emit fix landed with
    shape ``{"_extra": "<stringified Python repr of caller dict>"}``.
    The /logs page's pill renderer + Details column can't see the
    inner keys without an unpack. Backfilling the rows would invalidate
    the audit hash chain (#131); the render-time unpack in
    ``list_log_entries`` leaves storage intact + shows the operator-
    actionable fields on the page."""

    def _insert_legacy(
        self, db, message="Watcher: message triage error",
        legacy_payload="{'account': 'acct1', 'uid': '42', "
                       "'error': 'All connection attempts failed'}",
    ):
        from datetime import datetime, timezone
        ts = datetime.now(timezone.utc).isoformat()
        # Wrap the stringified repr in a JSON object — that's the
        # exact broken shape pre-ec06f21 emit produced.
        import json as _json
        extra_json = _json.dumps({"_extra": legacy_payload})
        db.execute(
            "INSERT INTO log_entries "
            "(ts, level, logger, message, extra_json, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (ts, "ERROR", "email_triage.web.app", message,
             extra_json, ts),
        )
        db.commit()

    def test_legacy_extra_unpacked_into_top_level_keys(self, db):
        from email_triage.web.db import list_log_entries
        self._insert_legacy(db)
        rows = list_log_entries(db, limit=1)
        assert rows
        extra = rows[0]["extra"]
        # Inner keys hoisted to top-level. _extra wrapper gone.
        assert extra.get("account") == "acct1"
        assert extra.get("uid") == "42"
        assert extra.get("error") == "All connection attempts failed"
        assert "_extra" not in extra

    def test_legacy_unpack_falls_through_on_malformed_payload(self, db):
        from email_triage.web.db import list_log_entries
        # Garbage that doesn't parse as a Python literal.
        self._insert_legacy(db, legacy_payload="this is not a dict")
        rows = list_log_entries(db, limit=1)
        assert rows
        # Original shape preserved when ast.literal_eval can't parse.
        # Operator can still see SOMETHING even if pills don't render.
        assert "_extra" in rows[0]["extra"]

    def test_post_fix_emit_shape_passes_through_unchanged(self, db):
        """Rows emitted POST-ec06f21 already have keys at top-level.
        The legacy-unpack path must NOT touch them (no double-unpack)."""
        from datetime import datetime, timezone
        from email_triage.web.db import list_log_entries
        import json as _json
        ts = datetime.now(timezone.utc).isoformat()
        # Post-fix shape: keys directly at top-level.
        extra_json = _json.dumps({
            "account": "acct2",
            "uid": "99",
            "error": "boom",
        })
        db.execute(
            "INSERT INTO log_entries "
            "(ts, level, logger, message, extra_json, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (ts, "ERROR", "email_triage.web.app", "post-fix entry",
             extra_json, ts),
        )
        db.commit()
        rows = list_log_entries(db, limit=1)
        assert rows
        extra = rows[0]["extra"]
        assert extra == {
            "account": "acct2", "uid": "99", "error": "boom",
        }
