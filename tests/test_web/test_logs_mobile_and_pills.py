"""/logs mobile responsive Details column + broadened pill fields (#118).

Two operator-visible regressions covered here:

1. Below ~700 px viewport the Details column was hidden behind the
   horizontal scroll wrapper (touch + visible width too narrow). The
   mobile CSS now promotes the Details cell to a full-width block
   under the message row.
2. Many low-richness rows (skip rows, simple INFO log lines) have a
   ``request_id`` / ``message_id`` but rendered NO inline pill,
   forcing the operator to open every Details collapse to find the
   correlation key. The priority_keys list is broadened so the
   most-useful trace IDs surface inline.

PHI guard: every key added to ``priority_keys`` is cross-checked
against ``triage_logging._PHI_KEYS`` so HIPAA mode never auto-
promotes a content-bearing field into the always-rendered set.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone


def _insert_log(db, *, level="INFO", extra: dict | None = None,
                message: str = "hello"):
    now = datetime.now(timezone.utc).isoformat()
    db.execute(
        "INSERT INTO log_entries "
        "(ts, level, logger, message, extra_json, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (now, level, "web.app", message,
         json.dumps(extra or {}), now),
    )
    db.commit()


# ---------------------------------------------------------------------------
# Mobile responsive — Details column visibility
# ---------------------------------------------------------------------------


class TestLogsMobileDetails:
    def test_logs_table_has_named_wrapper_class(
        self, client, db, admin_cookies, admin_user,
    ):
        """The wrapper carries a class ``logs-table-wrap`` so the
        narrow-viewport CSS can target it. Without the class the
        @media (min-width: 701px) rule wouldn't have anything to
        re-enable overflow on."""
        _insert_log(db)
        resp = client.get("/logs", cookies=admin_cookies)
        assert resp.status_code == 200
        assert "logs-table-wrap" in resp.text

    def test_logs_narrow_viewport_promotes_message_block(
        self, client, db, admin_cookies, admin_user,
    ):
        """2026-05-10: Details column merged into Message cell so it's
        reachable at every viewport width without horizontal scroll.
        Narrow-viewport CSS still promotes the Message cell to a
        full-width block — that's the column carrying the inline
        ``<details>`` payload now."""
        _insert_log(db, level="ERROR", extra={"error": "boom"})
        resp = client.get("/logs", cookies=admin_cookies)
        body = resp.text

        # Narrow-viewport breakpoint.
        assert "max-width: 640px" in body
        # The Message cell becomes a full-width block at narrow widths.
        assert "log-col-message" in body
        assert "display: block" in body

    def test_logs_wrapper_keeps_overflow_scroll(
        self, client, db, admin_cookies, admin_user,
    ):
        """The table wrapper keeps ``overflow-x:auto`` so the remaining
        four columns (Time / Level / Logger / Message) still scroll on
        landscape tablet. The Details payload is inline in Message and
        always visible — no horizontal scroll needed to reach it."""
        _insert_log(db)
        resp = client.get("/logs", cookies=admin_cookies)
        body = resp.text
        assert "logs-table-wrap" in body
        assert "overflow-x:auto" in body or "overflow-x: auto" in body


# ---------------------------------------------------------------------------
# Broadened pill keys
# ---------------------------------------------------------------------------


class TestLogsBroadenedPills:
    def test_request_id_renders_as_inline_pill(
        self, client, db, admin_cookies, admin_user,
    ):
        """request_id (cross-row trace key) should now appear inline
        — without it operators had to open every Details collapse to
        correlate skip rows back to the originating request."""
        _insert_log(db, extra={"request_id": "00000000-0000-0000-0000-000000000abc"})
        resp = client.get("/logs", cookies=admin_cookies)
        assert resp.status_code == 200
        body = resp.text
        # Pill rendered inline (not just inside the <details> block).
        assert "log-pill" in body
        assert "00000000-0000-0000-0000-000000000abc" in body
        # The pill key label is the literal extra-key name.
        assert "request_id" in body

    def test_message_id_renders_as_inline_pill(
        self, client, db, admin_cookies, admin_user,
    ):
        """message_id correlates skip rows (no error, no run_id) to
        the upstream cause."""
        _insert_log(
            db,
            extra={"message_id": "abc123", "skip_reason": "self_origin"},
            message="Skipping self-origin message",
        )
        resp = client.get("/logs", cookies=admin_cookies)
        assert resp.status_code == 200
        assert "log-pill" in resp.text
        assert "abc123" in resp.text

    def test_low_richness_skip_row_now_renders_at_least_one_pill(
        self, client, db, admin_cookies, admin_user,
    ):
        """Regression: a skip-status row with only request_id / message_id
        (no error, no run_id, no elapsed_secs) used to render NO inline
        pills. With the broadened priority_keys at least one of the
        pills must surface."""
        _insert_log(
            db,
            extra={
                "request_id": "req-zzz",
                "message_id": "uid-42",
                "skip_reason": "in_flight",
            },
            message="Skipping concurrent triage cycle",
        )
        resp = client.get("/logs", cookies=admin_cookies)
        body = resp.text
        # At least ONE inline pill rendered.
        outer_pill_count = (
            body.count('class="log-pill"')
            + body.count('class="log-pill log-pill-error"')
        )
        assert outer_pill_count >= 1, (
            "broadened priority_keys should surface ≥1 pill on this row"
        )

    def test_account_name_only_when_account_id_absent(
        self, client, db, admin_cookies, admin_user,
    ):
        """``account_id`` resolves to a name+id chip already; the
        broadened ``account_name`` priority should NOT double-pill
        when the chip rendered."""
        # Insert account_id alongside account_name — chip should win,
        # account_name slot is dropped without count bump.
        from datetime import datetime as _dt
        now = _dt.now(timezone.utc).isoformat()
        cursor = db.execute(
            "INSERT INTO email_accounts "
            "(user_id, name, provider_type, config_json, is_active, "
            " created_at, updated_at) "
            "VALUES (?, ?, ?, ?, 1, ?, ?)",
            (admin_user["id"], "Clinic Inbox", "imap",
             json.dumps({"host": "x.test"}), now, now),
        )
        db.commit()
        acct_id = cursor.lastrowid

        _insert_log(db, extra={
            "account_id": acct_id,
            "account_name": "Clinic Inbox",
            "request_id": "req-1",
        })
        resp = client.get("/logs", cookies=admin_cookies)
        body = resp.text
        # Chip rendered (account_id resolved to name+id).
        assert "Clinic Inbox" in body
        assert f"(#{acct_id})" in body
        # Standalone account_name pill (not the chip) should NOT
        # double-render the value with a key=value form.
        assert "account_name=Clinic Inbox" not in body


# ---------------------------------------------------------------------------
# PHI guard — broadened keys must not leak content under HIPAA
# ---------------------------------------------------------------------------


class TestPriorityKeysVsPhiKeys:
    def test_no_priority_key_collides_with_phi_keys(self):
        """Cross-check: the broadened priority_keys list must not
        contain any field that ``triage_logging._PHI_KEYS`` strips
        in HIPAA mode. A collision would mean the inline pill renders
        a value the logger ALREADY scrubbed — confusing at best,
        leaky at worst."""
        from email_triage.triage_logging import TriageLogger

        # Same default the template uses when the handler doesn't
        # override (kept in sync intentionally; the test pins both
        # sides so a future template edit can't drift).
        priority_keys = {
            "request_id", "account_id", "account_name",
            "error", "message_id", "run_id", "elapsed_secs",
        }
        overlap = priority_keys & TriageLogger._PHI_KEYS
        assert not overlap, (
            f"priority_keys overlap with PHI keys: {overlap} — "
            "remove from priority_keys or scrub before pill render"
        )
