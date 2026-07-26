"""Tests for the ``retry_queue`` field on /health/detail.

Installs the real v30 ``watcher_retry_queue`` schema (see
``migrations.py`` ``_v30_create_watcher_retry_queue``) so the
health-field tests run against the table the production code
actually queries. : the dead-in-24h window filters on
``resolved_at`` — the column set on the dead transition — not the
non-existent ``updated_at`` an earlier synthetic-schema guess used.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone


def _install_ra_schema(db) -> None:
    """Drop any prior shape + install the real v30 schema. Idempotent."""
    try:
        db.execute("DROP TABLE IF EXISTS watcher_retry_queue")
    except Exception:
        pass
    db.execute(
        """
        CREATE TABLE watcher_retry_queue (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            account_id INTEGER NOT NULL,
            provider_type TEXT NOT NULL,
            mailbox TEXT,
            uid INTEGER,
            uidvalidity INTEGER,
            gmail_msg_id TEXT,
            o365_msg_id TEXT,
            state TEXT NOT NULL DEFAULT 'pending',
            attempt_count INTEGER NOT NULL DEFAULT 0,
            first_seen_at TEXT NOT NULL DEFAULT (datetime('now')),
            next_attempt_at TEXT NOT NULL,
            last_error_class TEXT,
            last_error_msg TEXT,
            last_error_at TEXT,
            resolved_at TEXT,
            dead_reason TEXT,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        )
        """
    )
    db.commit()


def _seed(
    db, *, state, dead_reason=None, created_hours_ago=0,
    updated_hours_ago=0,
):
    """Insert one retry row.

    ``updated_hours_ago`` sets ``resolved_at`` — the timestamp the
    dead/done transition stamps, and the column the 24h dead-window
    query filters on.
    """
    created = (
        datetime.now(timezone.utc) - timedelta(hours=created_hours_ago)
    ).isoformat()
    resolved = (
        datetime.now(timezone.utc) - timedelta(hours=updated_hours_ago)
    ).isoformat()
    # ``resolved_at`` is only set once a row leaves the pending state.
    resolved_at = resolved if state in ("dead", "done") else None
    db.execute(
        "INSERT INTO watcher_retry_queue ("
        " account_id, provider_type, last_error_class, last_error_msg, "
        " state, attempt_count, next_attempt_at, dead_reason, "
        " created_at, resolved_at"
        ") VALUES (1, 'imap', 'ReadTimeout', '', ?, 0, ?, ?, ?, ?)",
        (state, resolved, dead_reason, created, resolved_at),
    )
    db.commit()


class TestHealthDetailRetryQueueBlock:
    def test_empty_db_renders_zero_block(self, client, db, admin_cookies):
        _install_ra_schema(db)
        r = client.get(
            "/health/detail", cookies=admin_cookies,
        )
        assert r.status_code == 200
        body = r.json()
        assert "retry_queue" in body
        rq = body["retry_queue"]
        assert rq["pending"] == 0
        assert rq["dead_24h"] == 0
        assert rq["oldest_pending_age_sec"] is None
        # All canonical reason keys present even with no rows.
        bd = rq["dead_breakdown_24h"]
        assert bd["max_attempts_exceeded"] == 0
        assert bd["auth_revoked"] == 0
        assert bd["uidvalidity_changed"] == 0
        assert bd["message_gone"] == 0
        assert bd["operator_abandoned"] == 0

    def test_pending_and_dead_counts(self, client, db, admin_cookies):
        _install_ra_schema(db)
        _seed(db, state="pending", created_hours_ago=2)
        _seed(db, state="pending", created_hours_ago=4)
        _seed(db, state="dead", dead_reason="auth_revoked", updated_hours_ago=3)
        _seed(db, state="dead", dead_reason="max_attempts_exceeded", updated_hours_ago=10)
        # An older dead row (40h ago) — outside the 24h window, must
        # NOT count toward dead_24h.
        _seed(db, state="dead", dead_reason="operator_abandoned", updated_hours_ago=40)

        r = client.get("/health/detail", cookies=admin_cookies)
        body = r.json()
        rq = body["retry_queue"]
        assert rq["pending"] == 2
        assert rq["dead_24h"] == 2  # the 40h dead one is excluded
        bd = rq["dead_breakdown_24h"]
        assert bd["auth_revoked"] == 1
        assert bd["max_attempts_exceeded"] == 1
        assert bd["operator_abandoned"] == 0  # excluded by 24h window

    def test_oldest_pending_age_computed(self, client, db, admin_cookies):
        _install_ra_schema(db)
        _seed(db, state="pending", created_hours_ago=5)
        _seed(db, state="pending", created_hours_ago=1)
        # Dead rows must not influence oldest_pending_age.
        _seed(
            db, state="dead", dead_reason="auth_revoked",
            created_hours_ago=10,
        )

        r = client.get("/health/detail", cookies=admin_cookies)
        rq = r.json()["retry_queue"]
        # Oldest of the two pending rows is ~5h ago = 18000s. Allow
        # a generous window for time skew.
        assert rq["oldest_pending_age_sec"] is not None
        assert 4 * 3600 < rq["oldest_pending_age_sec"] < 6 * 3600

    def test_missing_table_returns_sentinel(self, client, db, admin_cookies):
        # Drop the table entirely — pre-migration install.
        db.execute("DROP TABLE IF EXISTS watcher_retry_queue")
        db.commit()
        r = client.get("/health/detail", cookies=admin_cookies)
        # The endpoint must still return 200 — retry_queue is one
        # failure-safe block among many.
        assert r.status_code == 200
        rq = r.json()["retry_queue"]
        assert rq.get("state") == "unknown"
        assert "error" in rq


class TestRetryDeadDegradePolicy:
    """Only GENUINE-FAULT dead retries degrade /health. ``message_gone`` (the
    email was deleted/expunged before triage) and ``operator_abandoned`` (a
    deliberate human action) are benign — they must NOT flip /health to degraded
    (a the monitoring system CRITICAL). ``max_attempts_exceeded`` / ``auth_revoked`` /
    ``uidvalidity_changed`` still degrade. The benign rows stay VISIBLE in
    ``dead_breakdown_24h``. Regression for the 2026-06-13 false-alarm CRITICAL
    caused by one ``message_gone`` dead-letter (a deleted GitHub email)."""

    def test_message_gone_only_does_not_degrade(self, client, db, admin_cookies):
        _install_ra_schema(db)
        _seed(db, state="dead", dead_reason="message_gone", updated_hours_ago=1)
        resp = client.get("/health")  # minimal status endpoint (503-on-degraded)
        assert resp.status_code == 200, resp.json()
        assert resp.json()["status"] == "ok"
        # ...but the dead row is still VISIBLE in the detail breakdown.
        rq = client.get(
            "/health/detail", cookies=admin_cookies,
        ).json()["retry_queue"]
        assert rq["dead_breakdown_24h"]["message_gone"] == 1

    def test_operator_abandoned_only_does_not_degrade(self, client, db, admin_cookies):
        _install_ra_schema(db)
        _seed(db, state="dead", dead_reason="operator_abandoned", updated_hours_ago=1)
        assert client.get("/health").status_code == 200

    def test_max_attempts_exceeded_spike_degrades(self, client, db, admin_cookies):
        """N-372 (2026-07-05) — a SPIKE of ``max_attempts_exceeded`` (>= the
        per-reason threshold in 24h) DOES degrade: systemic classify/action
        failure worth alerting on."""
        from email_triage.web.routers.health import (
            _MAX_ATTEMPTS_EXCEEDED_DEGRADE_THRESHOLD,
        )
        _install_ra_schema(db)
        for _ in range(_MAX_ATTEMPTS_EXCEEDED_DEGRADE_THRESHOLD):
            _seed(
                db, state="dead", dead_reason="max_attempts_exceeded",
                updated_hours_ago=1,
            )
        resp = client.get("/health")
        assert resp.status_code == 503
        assert resp.json()["status"] == "degraded"

    def test_max_attempts_exceeded_below_threshold_does_not_degrade(
        self, client, db, admin_cookies,
    ):
        """N-372 (2026-07-05) — a single stuck message (transient LLM parse
        edge, model burp) must NOT flip /health for 24h. This is the exact
        pre-N-372 regression the threshold was raised to fix (2026-07-05
        FedEx-notification incident, retry-queue row 276)."""
        from email_triage.web.routers.health import (
            _MAX_ATTEMPTS_EXCEEDED_DEGRADE_THRESHOLD,
        )
        assert _MAX_ATTEMPTS_EXCEEDED_DEGRADE_THRESHOLD > 1, (
            "Threshold must exceed 1 or this test is vacuous"
        )
        _install_ra_schema(db)
        for _ in range(_MAX_ATTEMPTS_EXCEEDED_DEGRADE_THRESHOLD - 1):
            _seed(
                db, state="dead", dead_reason="max_attempts_exceeded",
                updated_hours_ago=1,
            )
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"

    def test_uidvalidity_changed_still_degrades(self, client, db, admin_cookies):
        _install_ra_schema(db)
        _seed(db, state="dead", dead_reason="uidvalidity_changed", updated_hours_ago=1)
        assert client.get("/health").status_code == 503

    def test_benign_plus_genuine_degrades_on_the_genuine(self, client, db, admin_cookies):
        _install_ra_schema(db)
        _seed(db, state="dead", dead_reason="message_gone", updated_hours_ago=1)
        _seed(db, state="dead", dead_reason="auth_revoked", updated_hours_ago=1)
        assert client.get("/health").status_code == 503

    def test_message_gone_spike_degrades(self, client, db, admin_cookies):
        """A SPIKE of message_gone (>= the threshold in 24h) DOES degrade — a
        systematic fetch degradation mis-tombstoning real mail (the AMBIGUOUS
        empty-fetch case the verified split keeps watching) must alert."""
        from email_triage.web.routers.health import (
            _MESSAGE_GONE_DEGRADE_THRESHOLD,
        )
        _install_ra_schema(db)
        for _ in range(_MESSAGE_GONE_DEGRADE_THRESHOLD):
            _seed(db, state="dead", dead_reason="message_gone", updated_hours_ago=1)
        resp = client.get("/health")
        assert resp.status_code == 503
        assert resp.json()["status"] == "degraded"

    def test_message_gone_below_threshold_does_not_degrade(
        self, client, db, admin_cookies,
    ):
        """Below the (raised) threshold, message_gone is benign — ordinary
        expunge-race churn must not flip /health."""
        from email_triage.web.routers.health import (
            _MESSAGE_GONE_DEGRADE_THRESHOLD,
        )
        _install_ra_schema(db)
        for _ in range(_MESSAGE_GONE_DEGRADE_THRESHOLD - 1):
            _seed(db, state="dead", dead_reason="message_gone", updated_hours_ago=1)
        resp = client.get("/health")
        assert resp.status_code == 200, resp.json()
        assert resp.json()["status"] == "ok"

    def test_message_expunged_never_degrades(self, client, db, admin_cookies):
        """2026-06-19 verified split: a CONFIRMED-absent expunge (provider 404
        or UID-SEARCH-confirmed gone) is the benign ``message_expunged`` reason
        and NEVER degrades, even far above the message_gone threshold."""
        from email_triage.web.routers.health import (
            _MESSAGE_GONE_DEGRADE_THRESHOLD,
        )
        _install_ra_schema(db)
        for _ in range(_MESSAGE_GONE_DEGRADE_THRESHOLD * 3):
            _seed(
                db, state="dead", dead_reason="message_expunged",
                updated_hours_ago=1,
            )
        resp = client.get("/health")
        assert resp.status_code == 200, resp.json()
        assert resp.json()["status"] == "ok"


class TestHealthDetailOpsToken:
    """Container-internal ops access to /health/detail. The bypass is LAYERED
    (see _ops_token_authorized): loopback-origin AND a >= 16-char
    ET_HEALTH_OPS_TOKEN AND a constant-time X-Ops-Token match. The published LAN
    port (non-loopback origin) can NEVER use the token; a blank/weak/unset token
    disables the bypass (admin-session-only, unchanged)."""

    _TOK = "x" * 16  # == _OPS_TOKEN_MIN_LEN

    def test_helper_loopback_strong_token_match_authorizes(self):
        from email_triage.web.routers.health import _ops_token_authorized
        assert _ops_token_authorized(
            client_host="127.0.0.1", presented=self._TOK, env_token=self._TOK,
        ) is True
        assert _ops_token_authorized(  # IPv6 loopback
            client_host="::1", presented=self._TOK, env_token=self._TOK,
        ) is True

    def test_helper_non_loopback_denied_even_with_correct_token(self):
        """The DA must-fix: a CORRECT token from a non-loopback origin (the
        container gateway ip a published-port request arrives with) must NOT
        authorize — the LAN can't use the token even if it leaks."""
        from email_triage.web.routers.health import _ops_token_authorized
        for host in ("10.88.0.1", "10.95.1.8", "192.168.1.5", "", "testclient"):
            assert _ops_token_authorized(
                client_host=host, presented=self._TOK, env_token=self._TOK,
            ) is False, host

    def test_helper_weak_or_blank_token_disables_bypass(self):
        from email_triage.web.routers.health import _ops_token_authorized
        assert _ops_token_authorized(
            client_host="127.0.0.1", presented="short", env_token="short",
        ) is False
        assert _ops_token_authorized(
            client_host="127.0.0.1", presented="", env_token="",
        ) is False
        assert _ops_token_authorized(
            client_host="127.0.0.1", presented="   ", env_token="   ",
        ) is False

    def test_helper_wrong_token_denied(self):
        from email_triage.web.routers.health import _ops_token_authorized
        assert _ops_token_authorized(
            client_host="127.0.0.1", presented="y" * 16, env_token=self._TOK,
        ) is False

    def test_lan_token_request_is_denied_303(self, client, db, monkeypatch):
        """End-to-end: the TestClient reports a NON-loopback host, so even a
        VALID token is denied → admin gate (303). Proves the published port
        cannot use the token."""
        monkeypatch.setenv("ET_HEALTH_OPS_TOKEN", self._TOK)
        r = client.get(
            "/health/detail", headers={"X-Ops-Token": self._TOK},
            follow_redirects=False,
        )
        assert r.status_code == 303

    def test_unset_env_disables_bypass_303(self, client, db, monkeypatch):
        monkeypatch.delenv("ET_HEALTH_OPS_TOKEN", raising=False)
        r = client.get(
            "/health/detail", headers={"X-Ops-Token": "anything"},
            follow_redirects=False,
        )
        assert r.status_code == 303


def _walk_json(obj):
    """Yield (last_key, value) for every node in a nested JSON structure."""
    stack = [("", obj)]
    while stack:
        key, node = stack.pop()
        if isinstance(node, dict):
            for k, v in node.items():
                stack.append((str(k), v))
        elif isinstance(node, (list, tuple)):
            for v in node:
                stack.append((key, v))
        else:
            yield key, node


class TestHealthDetailBodyIsPhiFree:
    """hipaa-sme C1 pin: the /health/detail body (now reachable by a non-session
    ops token) must carry NO PHI/PII identity field. A future field that adds an
    owner name / email / subject / message content turns the ops-token path into
    a PHI surface — fail HERE before that ships. Keyed on the body schema, not a
    count. (Denylist terms chosen to not collide with config TASK NAMES like
    'recipient-digest-sender'; the '@' value check is the email/PII catch-all.)"""

    _DENY_KEY_SUBSTR = (
        "owner", "subject", "from_addr", "to_addr", "display_name",
        "snippet", "preview", "msg_body",
    )

    def test_health_detail_body_is_phi_free(self, client, db, admin_cookies):
        _install_ra_schema(db)
        body = client.get("/health/detail", cookies=admin_cookies).json()
        for key, val in _walk_json(body):
            klow = key.lower()
            assert not any(s in klow for s in self._DENY_KEY_SUBSTR), (
                f"identity-bearing key in /health/detail body: {key!r}"
            )
            if isinstance(val, str):
                assert "@" not in val, (
                    f"possible email address in /health/detail at {key!r}: {val!r}"
                )
