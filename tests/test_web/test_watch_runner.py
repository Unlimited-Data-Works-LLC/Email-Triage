"""Tests for the watch fire pipeline.

Covers:
* fire_one_watch executes escalate via the SMTP path (mocked)
* fire_one_watch posts to the webhook with HMAC signature header
* HMAC signature verifies against the per-watch secret
* HIPAA mode redacts payload + audit row records the posture
* fire_watches_for_message excludes HIPAA accounts from all-scope
* Audit row is written on every fire (success + failure)

httpx is mocked via ``unittest.mock.patch("httpx.AsyncClient")`` to
match the project-wide pattern in ``test_events.py`` — no extra test
deps (e.g. respx) are needed.
"""

from __future__ import annotations
from _db_tracking import track

import asyncio
import hashlib
import hmac
import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from email_triage.config import TriageConfig
from email_triage.web import email_watches as W
from email_triage.web.db import init_db
from email_triage.web.watch_runner import (
    fire_one_watch,
    fire_watches_for_message,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


class _Secrets:
    def __init__(self, store=None):
        self._d = dict(store or {})

    def get(self, key):
        return self._d.get(key)

    def set(self, key, value):
        self._d[key] = value

    def list_keys(self):
        return list(self._d)


def _patched_httpx(captured: dict, status: int = 200):
    """Return a context-manager that patches httpx.AsyncClient.

    Every POST captures (url, content, headers) into ``captured`` and
    returns a MagicMock response with the given status_code. Mirrors
    the shape used in test_events.py.
    """
    response = MagicMock()
    response.status_code = status

    async def capture_post(url, content=None, headers=None, **kwargs):
        captured["url"] = url
        captured["body"] = content
        captured["headers"] = dict(headers or {})
        return response

    @MagicMock
    def patched():
        pass

    mock_client = AsyncMock()
    mock_client.post = capture_post
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    return patch("httpx.AsyncClient", return_value=mock_client)


@pytest.fixture(autouse=True)
def _reset_module_webhook_client():
    """Reset the module-level long-lived httpx client between tests.

     introduced a per-process ``LazyHttpClient`` for webhook
    fan-out. Test mocks of ``httpx.AsyncClient`` only intercept
    construction; once the module has cached a (mocked) client from
    test N, test N+1's patch never fires. Forcing the cache empty
    between tests restores per-test isolation.
    """
    from email_triage.web import watch_runner
    yield
    # -d: _WEBHOOK_CLIENT is now a lazy None-initialised singleton
    # rebuilt by _get_webhook_client() on next use, so nuking the
    # module ref restores per-test httpx patch interception.
    watch_runner._WEBHOOK_CLIENT = None


@pytest.fixture
def db():
    conn = track(init_db(":memory:"))
    yield conn
    conn.close()


@pytest.fixture
def acct(db):
    """Insert a non-HIPAA account row + return the dict."""
    now = datetime.now(timezone.utc).isoformat()
    db.execute(
        "INSERT INTO users (email, name, role, created_at) "
        "VALUES (?, ?, ?, ?)",
        ("user@example.com", "Operator A", "user", now),
    )
    user_id = db.execute(
        "SELECT id FROM users WHERE email='user@example.com'"
    ).fetchone()["id"]
    db.execute(
        "INSERT INTO email_accounts "
        "(id, user_id, name, provider_type, config_json, hipaa, "
        "created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (
            1, user_id, "acct1", "imap",
            json.dumps({
                "host": "mail.example.com",
                "username": "u@example.com",
                "notify_email": "ops@example.com",
            }),
            0, now, now,
        ),
    )
    db.commit()
    return {
        "id": 1, "user_id": user_id, "name": "acct1",
        "provider_type": "imap", "hipaa": False,
        "config": {"notify_email": "ops@example.com"},
    }


@pytest.fixture
def hipaa_acct(db):
    """Insert a HIPAA-flagged account row + return the dict."""
    now = datetime.now(timezone.utc).isoformat()
    db.execute(
        "INSERT INTO users (email, name, role, created_at) "
        "VALUES (?, ?, ?, ?)",
        ("admin@example.com", "Operator B", "admin", now),
    )
    user_id = db.execute(
        "SELECT id FROM users WHERE email='admin@example.com'"
    ).fetchone()["id"]
    db.execute(
        "INSERT INTO email_accounts "
        "(id, user_id, name, provider_type, config_json, hipaa, "
        "created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (
            2, user_id, "phi-acct", "imap",
            json.dumps({"host": "mail.example.com",
                        "username": "u2@example.com"}),
            1, now, now,
        ),
    )
    db.commit()
    return {
        "id": 2, "user_id": user_id, "name": "phi-acct",
        "provider_type": "imap", "hipaa": True,
        "config": {},
    }


@pytest.fixture
def config():
    """A TriageConfig with a configured SMTP relay."""
    cfg = TriageConfig()
    cfg.smtp.host = "smtp.example.com"
    cfg.smtp.port = 587
    cfg.smtp.username = "u@example.com"
    cfg.smtp.from_addr = "noreply@example.com"
    cfg.smtp.from_name = "Email Triage"
    cfg.smtp.use_tls = True
    return cfg


# ---------------------------------------------------------------------------
# Escalate
# ---------------------------------------------------------------------------


class TestEscalate:
    @pytest.mark.asyncio
    async def test_escalate_calls_smtp_with_alert_text(
        self, db, acct, config,
    ):
        secrets = _Secrets({"SMTP_PASSWORD": "x"})
        w = W.upsert_watch(db, W.EmailWatch(
            name="boss",
            account_id=1,
            filter=W.WatchFilter(from_addr="boss@"),
            actions=W.WatchActions(
                escalate=W.EscalateAction(
                    enabled=True, notify_email="ops@example.com",
                ),
            ),
        ))
        with patch(
            "email_triage.web.smtp_send.send_simple_smtp_email",
        ) as send:
            res = await fire_one_watch(
                db=db, config=config, secrets=secrets,
                watch=w, account=acct,
                sender="boss@example.com",
                subject="Quarterly review",
                category="action-required",
                message_id="m1",
            )
            assert send.called
            kwargs = send.call_args.kwargs
            assert kwargs["to_addr"] == "ops@example.com"
            assert "URGENT" in kwargs["subject"]
            assert "Quarterly review" in kwargs["subject"]
            assert res["escalate"]["ok"] is True

    @pytest.mark.asyncio
    async def test_escalate_falls_back_to_account_notify_email(
        self, db, acct, config,
    ):
        secrets = _Secrets({"SMTP_PASSWORD": "x"})
        w = W.upsert_watch(db, W.EmailWatch(
            name="boss",
            account_id=1,
            filter=W.WatchFilter(from_addr="boss@"),
            actions=W.WatchActions(
                escalate=W.EscalateAction(enabled=True, notify_email=""),
            ),
        ))
        with patch(
            "email_triage.web.smtp_send.send_simple_smtp_email",
        ) as send:
            await fire_one_watch(
                db=db, config=config, secrets=secrets,
                watch=w, account=acct,
                sender="boss@example.com",
                subject="x", category="t", message_id="m1",
            )
            assert send.call_args.kwargs["to_addr"] == "ops@example.com"

    @pytest.mark.asyncio
    async def test_escalate_skipped_when_smtp_unconfigured(
        self, db, acct,
    ):
        cfg = TriageConfig()  # no smtp.host -> skipped
        secrets = _Secrets()
        w = W.upsert_watch(db, W.EmailWatch(
            name="boss",
            account_id=1,
            filter=W.WatchFilter(from_addr="boss@"),
            actions=W.WatchActions(
                escalate=W.EscalateAction(
                    enabled=True, notify_email="ops@example.com",
                ),
            ),
        ))
        res = await fire_one_watch(
            db=db, config=cfg, secrets=secrets,
            watch=w, account=acct,
            sender="boss@example.com",
            subject="x", category="t", message_id="m1",
        )
        assert res["escalate"]["ok"] is False
        assert "smtp" in res["escalate"]["error"].lower()


# ---------------------------------------------------------------------------
# Webhook + HMAC
# ---------------------------------------------------------------------------


class TestWebhook:
    @pytest.mark.asyncio
    async def test_webhook_posts_with_hmac_signature(
        self, db, acct, config,
    ):
        secrets = _Secrets({"SMTP_PASSWORD": ""})
        w = W.upsert_watch(db, W.EmailWatch(
            name="invoice-hook",
            account_id=1,
            filter=W.WatchFilter(subject_contains="invoice"),
            actions=W.WatchActions(
                webhook=W.WebhookAction(
                    enabled=True,
                    url="http://192.168.1.10:9000/hook",
                ),
            ),
        ))
        secret = "test-secret-12345"
        secrets.set(W.hmac_secret_key(w.watch_id), secret)

        captured: dict = {}
        with _patched_httpx(captured, status=200):
            res = await fire_one_watch(
                db=db, config=config, secrets=secrets,
                watch=w, account=acct,
                sender="acme@vendor.test",
                subject="Invoice ",
                category="action-required",
                message_id="m1",
            )

        assert res["webhook"]["ok"] is True
        assert captured["url"] == "http://192.168.1.10:9000/hook"
        sig = captured["headers"].get("X-Signature-256", "")
        assert sig.startswith("sha256=")
        recv_sig = sig[len("sha256="):]
        expected = hmac.new(
            secret.encode("utf-8"),
            captured["body"],
            hashlib.sha256,
        ).hexdigest()
        assert hmac.compare_digest(recv_sig, expected)

        body_dict = json.loads(captured["body"])
        assert body_dict["event"] == "watch.fired"
        assert body_dict["watch_id"] == w.watch_id
        assert body_dict["subject"] == "Invoice "
        assert body_dict["redaction"] == "standard"
        assert "body" not in body_dict
        assert "body_text" not in body_dict

    @pytest.mark.asyncio
    async def test_webhook_hipaa_payload_redacted(
        self, db, hipaa_acct, config,
    ):
        secrets = _Secrets()
        w = W.upsert_watch(db, W.EmailWatch(
            name="phi-hook",
            account_id=2,
            filter=W.WatchFilter(from_domain="example.com"),
            actions=W.WatchActions(
                webhook=W.WebhookAction(
                    enabled=True,
                    url="http://192.168.1.10:9000/phi",
                ),
            ),
        ))
        secrets.set(W.hmac_secret_key(w.watch_id), "phi-secret")

        captured: dict = {}
        with _patched_httpx(captured, status=200):
            await fire_one_watch(
                db=db, config=config, secrets=secrets,
                watch=w, account=hipaa_acct,
                sender="Dr. Operator A <a@example.com>",
                subject="patient details",
                body_text="full PHI body",
                category="action-required",
                message_id="m1",
            )
        body = json.loads(captured["body"])
        assert body["redaction"] == "hipaa_redacted"
        assert body["subject"] == "[redacted]"
        assert "patient" not in body["sender"].lower()
        assert "body" not in body
        assert "body_text" not in body


# ---------------------------------------------------------------------------
# Audit + scope
# ---------------------------------------------------------------------------


class TestAuditAndScope:
    @pytest.mark.asyncio
    async def test_audit_row_written_on_fire(
        self, db, acct, config,
    ):
        secrets = _Secrets()
        w = W.upsert_watch(db, W.EmailWatch(
            name="any",
            account_id=1,
            filter=W.WatchFilter(keyword="ping"),
            actions=W.WatchActions(
                webhook=W.WebhookAction(
                    enabled=True, url="http://192.168.1.10:9000/h",
                ),
            ),
        ))
        secrets.set(W.hmac_secret_key(w.watch_id), "s")
        captured: dict = {}
        with _patched_httpx(captured, status=200):
            await fire_one_watch(
                db=db, config=config, secrets=secrets,
                watch=w, account=acct,
                sender="x@y.test", subject="ping me", category="t",
                message_id="m42",
            )
        rows = db.execute(
            "SELECT outcome, account_id, message_id, detail "
            "FROM access_log WHERE outcome = 'watch_fired'"
        ).fetchall()
        assert len(rows) == 1
        assert rows[0]["account_id"] == 1
        assert rows[0]["message_id"] == "m42"
        d = json.loads(rows[0]["detail"])
        assert d["watch_id"] == w.watch_id
        assert d["webhook"] is True

    @pytest.mark.asyncio
    async def test_hipaa_account_excluded_from_all_scope(
        self, db, hipaa_acct, config,
    ):
        secrets = _Secrets()
        w = W.upsert_watch(db, W.EmailWatch(
            name="catch-all",
            account_id=None,
            filter=W.WatchFilter(keyword="anything"),
            actions=W.WatchActions(
                webhook=W.WebhookAction(
                    enabled=True, url="http://192.168.1.10:9000/h",
                ),
            ),
        ))
        secrets.set(W.hmac_secret_key(w.watch_id), "s")
        results = await fire_watches_for_message(
            db=db, config=config, secrets=secrets,
            account=hipaa_acct,
            sender="x@y.test", subject="anything",
            category="t", message_id="m1",
        )
        assert results == []

    @pytest.mark.asyncio
    async def test_per_account_watch_fires_on_hipaa_account(
        self, db, hipaa_acct, config,
    ):
        secrets = _Secrets()
        w = W.upsert_watch(db, W.EmailWatch(
            name="phi-targeted",
            account_id=2,
            filter=W.WatchFilter(keyword="ok"),
            actions=W.WatchActions(
                webhook=W.WebhookAction(
                    enabled=True, url="http://192.168.1.10:9000/h",
                ),
            ),
        ))
        secrets.set(W.hmac_secret_key(w.watch_id), "s")
        captured: dict = {}
        with _patched_httpx(captured, status=200):
            results = await fire_watches_for_message(
                db=db, config=config, secrets=secrets,
                account=hipaa_acct,
                sender="x@example.com",
                subject="ok please ping",
                category="t",
                message_id="phi-m1",
            )
        assert len(results) == 1
        assert results[0]["redaction"] == "hipaa_redacted"
        rows = db.execute(
            "SELECT detail FROM access_log WHERE outcome = 'watch_fired'"
        ).fetchall()
        assert len(rows) == 1
        d = json.loads(rows[0]["detail"])
        assert d["redaction"] == "hipaa_redacted"


# ---------------------------------------------------------------------------
# Watch-fire idempotency
# ---------------------------------------------------------------------------


class TestWatchFireIdempotency:
    """ — ``fire_watches_for_message`` is idempotent per
    ``(account_id, rfc_message_id, watch_id)``;  hardens it.

    The retry drainer (``_recover_one_retry_row``) was reverted to
    ``fire_watches=True`` so an escalation watch on mail that arrived
    during an LLM outage actually fires (the  retry worker is the
    first attempt that reaches the watch stage — ``classify`` raised
    before it on the original attempt). The idempotency guard makes
    the restored re-fire safe: a second drainer pass does not re-send
    the pager/SMS escalation.

     fixed three bugs in the original  design:
      * Bug 1 — a fire whose SMTP send FAILED was still recorded as
        fired → permanently dropped pager/SMS. Fix: the durable table
        records ONLY a delivered fire; a failed fire leaves no row and
        stays retryable.
      * Bug 2 — the key used the provider message id (an IMAP
        mailbox-scoped UID). Fix: key on the RFC 5322 Message-ID.
      * Bug 3 — check-then-record TOCTOU window. Fix: the
        check -> fire -> record sequence runs under a per-(account,
        idempotency_key, watch) asyncio.Lock so concurrent runs cannot
        both fire. Because the table records only SUCCESSFUL fires,
        the second runner re-checks after the first and skips only if
        the first actually delivered — a first-runner failure leaves
        no row and the second correctly re-fires (no dropped pager).
    """

    @pytest.mark.asyncio
    async def test_watch_fires_once(self, db, acct, config):
        """A single drainer/ingest pass fires the watch exactly once."""
        secrets = _Secrets({"SMTP_PASSWORD": "x"})
        W.upsert_watch(db, W.EmailWatch(
            name="boss",
            account_id=1,
            filter=W.WatchFilter(from_addr="boss@"),
            actions=W.WatchActions(
                escalate=W.EscalateAction(
                    enabled=True, notify_email="ops@example.com",
                ),
            ),
        ))
        with patch(
            "email_triage.web.smtp_send.send_simple_smtp_email",
        ) as send:
            results = await fire_watches_for_message(
                db=db, config=config, secrets=secrets,
                account=acct,
                sender="boss@example.com", subject="review",
                category="action-required", message_id="m-once",
            )
        assert send.call_count == 1
        assert len(results) == 1
        assert not results[0].get("skipped_idempotent")
        # The fire was recorded in the durable table. With no explicit
        # idempotency_key the provider message_id is the fallback key.
        row = db.execute(
            "SELECT 1 FROM watch_fire_idempotency "
            "WHERE account_id=1 AND rfc_message_id='m-once'"
        ).fetchone()
        assert row is not None

    @pytest.mark.asyncio
    async def test_second_drainer_run_does_not_refire(
        self, db, acct, config,
    ):
        """A second ``fire_watches_for_message`` call for the SAME
        (account, message) does NOT re-fire the watch — no duplicate
        pager/SMS escalation when the retry drainer re-runs.
        """
        secrets = _Secrets({"SMTP_PASSWORD": "x"})
        W.upsert_watch(db, W.EmailWatch(
            name="boss",
            account_id=1,
            filter=W.WatchFilter(from_addr="boss@"),
            actions=W.WatchActions(
                escalate=W.EscalateAction(
                    enabled=True, notify_email="ops@example.com",
                ),
            ),
        ))
        with patch(
            "email_triage.web.smtp_send.send_simple_smtp_email",
        ) as send:
            # Pass 1 — original ingestion (or first drainer pass).
            first = await fire_watches_for_message(
                db=db, config=config, secrets=secrets,
                account=acct,
                sender="boss@example.com", subject="review",
                category="action-required", message_id="m-dup",
            )
            # Pass 2 — retry drainer re-runs the same row.
            second = await fire_watches_for_message(
                db=db, config=config, secrets=secrets,
                account=acct,
                sender="boss@example.com", subject="review",
                category="action-required", message_id="m-dup",
            )
        # SMTP escalation sent exactly once across both passes.
        assert send.call_count == 1
        assert len(first) == 1 and not first[0].get("skipped_idempotent")
        # The re-run still reports a result row, flagged idempotent.
        assert len(second) == 1
        assert second[0]["skipped_idempotent"] is True
        assert second[0]["escalate"] is None
        # Exactly one durable idempotency row.
        n = db.execute(
            "SELECT COUNT(*) FROM watch_fire_idempotency "
            "WHERE account_id=1 AND rfc_message_id='m-dup'"
        ).fetchone()[0]
        assert n == 1

    @pytest.mark.asyncio
    async def test_llm_down_retry_fires_the_watch(
        self, db, acct, config,
    ):
        """The  silent-drop bug is gone.

        Models the LLM-down retry path: ``classify`` raised on the
        original ingestion attempt BEFORE the watch stage, so the
        watch never fired and no idempotency row exists. The 
        retry worker drains the row and calls
        ``fire_watches_for_message`` (``fire_watches=True`` again,
        post-#243). The watch MUST fire — an escalation on mail that
        arrived during an LLM outage is not silently dropped.
        """
        secrets = _Secrets({"SMTP_PASSWORD": "x"})
        W.upsert_watch(db, W.EmailWatch(
            name="pager",
            account_id=1,
            filter=W.WatchFilter(from_addr="boss@"),
            actions=W.WatchActions(
                escalate=W.EscalateAction(
                    enabled=True, notify_email="ops@example.com",
                ),
            ),
        ))
        # Precondition: no prior fire recorded for this message — the
        # original attempt never reached the watch stage.
        pre = db.execute(
            "SELECT COUNT(*) FROM watch_fire_idempotency "
            "WHERE account_id=1 AND rfc_message_id='m-llm-down'"
        ).fetchone()[0]
        assert pre == 0
        with patch(
            "email_triage.web.smtp_send.send_simple_smtp_email",
        ) as send:
            # The retry drainer re-runs the message — the FIRST time
            # watches reach this message.
            results = await fire_watches_for_message(
                db=db, config=config, secrets=secrets,
                account=acct,
                sender="boss@example.com", subject="urgent",
                category="action-required", message_id="m-llm-down",
            )
        # The escalation fired — not silently dropped.
        assert send.call_count == 1
        assert len(results) == 1
        assert not results[0].get("skipped_idempotent")
        assert results[0]["escalate"]["ok"] is True

    # --  Bug 1 — only a DELIVERED fire is recorded ---------------

    @pytest.mark.asyncio
    async def test_failed_escalation_not_recorded_so_retry_refires(
        self, db, acct, config,
    ):
        """ Bug 1 — a watch whose escalation SMTP send FAILED is
        NOT recorded in the durable table; the retry drainer re-fires it.

        Pre-#250 the record was written unconditionally after the fire,
        so a failed pager/SMS was recorded as fired and skipped forever
        on retry. Under Option 4 the table records only a DELIVERED
        fire — a failure leaves no row, so a retry re-fires.
        """
        secrets = _Secrets({"SMTP_PASSWORD": "x"})
        W.upsert_watch(db, W.EmailWatch(
            name="pager",
            account_id=1,
            filter=W.WatchFilter(from_addr="boss@"),
            actions=W.WatchActions(
                escalate=W.EscalateAction(
                    enabled=True, notify_email="ops@example.com",
                ),
            ),
        ))
        # Pass 1 — the SMTP relay is down; send raises.
        with patch(
            "email_triage.web.smtp_send.send_simple_smtp_email",
            side_effect=OSError("connection refused"),
        ) as send_fail:
            first = await fire_watches_for_message(
                db=db, config=config, secrets=secrets,
                account=acct,
                sender="boss@example.com", subject="urgent",
                category="action-required", message_id="m-fail",
            )
        assert send_fail.call_count == 1
        assert len(first) == 1
        assert first[0]["escalate"]["ok"] is False
        # The failed fire was NOT recorded — no idempotency row.
        n = db.execute(
            "SELECT COUNT(*) FROM watch_fire_idempotency "
            "WHERE account_id=1 AND rfc_message_id='m-fail'"
        ).fetchone()[0]
        assert n == 0, "a failed fire must not be recorded as delivered"

        # Pass 2 — the retry drainer re-runs; SMTP is back. The watch
        # MUST fire again (it was never successfully delivered).
        with patch(
            "email_triage.web.smtp_send.send_simple_smtp_email",
        ) as send_ok:
            second = await fire_watches_for_message(
                db=db, config=config, secrets=secrets,
                account=acct,
                sender="boss@example.com", subject="urgent",
                category="action-required", message_id="m-fail",
            )
        assert send_ok.call_count == 1, "retry must re-fire a failed escalation"
        assert len(second) == 1
        assert not second[0].get("skipped_idempotent")
        assert second[0]["escalate"]["ok"] is True
        # Now — and only now — a durable record survives.
        n = db.execute(
            "SELECT COUNT(*) FROM watch_fire_idempotency "
            "WHERE account_id=1 AND rfc_message_id='m-fail'"
        ).fetchone()[0]
        assert n == 1

    @pytest.mark.asyncio
    async def test_skipped_escalation_is_recorded(
        self, db, acct, config,
    ):
        """ Bug 1 boundary — a CONFIG-skipped escalate (no SMTP
        relay configured) is NOT a delivery failure: it counts as
        delivered and IS recorded, because a re-fire would skip
        identically until the operator fixes the config.
        """
        secrets = _Secrets({"SMTP_PASSWORD": "x"})
        # config_no_smtp: a TriageConfig with no SMTP host.
        cfg = TriageConfig()  # smtp.host is empty by default.
        W.upsert_watch(db, W.EmailWatch(
            name="pager",
            account_id=1,
            filter=W.WatchFilter(from_addr="boss@"),
            actions=W.WatchActions(
                escalate=W.EscalateAction(
                    enabled=True, notify_email="ops@example.com",
                ),
            ),
        ))
        with patch(
            "email_triage.web.smtp_send.send_simple_smtp_email",
        ) as send:
            results = await fire_watches_for_message(
                db=db, config=cfg, secrets=secrets,
                account=acct,
                sender="boss@example.com", subject="urgent",
                category="action-required", message_id="m-skip",
            )
        # SMTP was never even attempted — no relay configured.
        assert send.call_count == 0
        assert len(results) == 1
        assert results[0]["escalate"]["ok"] is False
        assert results[0]["escalate"]["mode"] == "skipped"
        # A config skip IS recorded — it is not a delivery failure;
        # a retry would skip identically, so re-firing is pointless.
        n = db.execute(
            "SELECT COUNT(*) FROM watch_fire_idempotency "
            "WHERE account_id=1 AND rfc_message_id='m-skip'"
        ).fetchone()[0]
        assert n == 1

    @pytest.mark.asyncio
    async def test_failed_webhook_not_recorded(
        self, db, acct, config,
    ):
        """ Bug 1 — a watch whose webhook POST failed is NOT
        recorded, so a retry re-delivers it.
        """
        secrets = _Secrets()
        w = W.upsert_watch(db, W.EmailWatch(
            name="hook",
            account_id=1,
            filter=W.WatchFilter(from_addr="boss@"),
            actions=W.WatchActions(
                webhook=W.WebhookAction(
                    enabled=True, url="http://192.168.1.10:9000/h",
                ),
            ),
        ))
        secrets.set(W.hmac_secret_key(w.watch_id), "s")
        captured: dict = {}
        # Webhook receiver returns 500 → ok=False.
        with _patched_httpx(captured, status=500):
            results = await fire_watches_for_message(
                db=db, config=config, secrets=secrets,
                account=acct,
                sender="boss@example.com", subject="urgent",
                category="action-required", message_id="m-hook-fail",
            )
        assert len(results) == 1
        assert results[0]["webhook"]["ok"] is False
        # The failed webhook was NOT recorded — a retry is allowed.
        n = db.execute(
            "SELECT COUNT(*) FROM watch_fire_idempotency "
            "WHERE account_id=1 AND rfc_message_id='m-hook-fail'"
        ).fetchone()[0]
        assert n == 0

    # --  Bug 2 — key on the RFC 5322 Message-ID ------------------

    @pytest.mark.asyncio
    async def test_idempotency_keyed_on_rfc_message_id(
        self, db, acct, config,
    ):
        """ Bug 2 — the idempotency claim is keyed on the supplied
        ``idempotency_key`` (the RFC 5322 Message-ID), independent of
        the provider ``message_id``.

        Two passes with the SAME RFC Message-ID but DIFFERENT provider
        ids (e.g. the message COPY'd to another folder gets a new IMAP
        UID) must still be deduplicated — only one escalation fires.
        """
        secrets = _Secrets({"SMTP_PASSWORD": "x"})
        W.upsert_watch(db, W.EmailWatch(
            name="boss",
            account_id=1,
            filter=W.WatchFilter(from_addr="boss@"),
            actions=W.WatchActions(
                escalate=W.EscalateAction(
                    enabled=True, notify_email="ops@example.com",
                ),
            ),
        ))
        with patch(
            "email_triage.web.smtp_send.send_simple_smtp_email",
        ) as send:
            # Pass 1 — provider UID 100, RFC id "<abc@host>".
            first = await fire_watches_for_message(
                db=db, config=config, secrets=secrets,
                account=acct,
                sender="boss@example.com", subject="review",
                category="action-required",
                message_id="100", idempotency_key="<abc@host>",
            )
            # Pass 2 — SAME mail, different provider UID 7777 (a new
            # folder / a UIDVALIDITY rollover) but the SAME RFC id.
            second = await fire_watches_for_message(
                db=db, config=config, secrets=secrets,
                account=acct,
                sender="boss@example.com", subject="review",
                category="action-required",
                message_id="7777", idempotency_key="<abc@host>",
            )
        # Deduplicated on the RFC id — exactly one escalation.
        assert send.call_count == 1
        assert not first[0].get("skipped_idempotent")
        assert second[0]["skipped_idempotent"] is True
        # The durable row is keyed on the RFC id, not the UID.
        row = db.execute(
            "SELECT rfc_message_id FROM watch_fire_idempotency "
            "WHERE account_id=1"
        ).fetchone()
        assert row["rfc_message_id"] == "<abc@host>"
        n = db.execute(
            "SELECT COUNT(*) FROM watch_fire_idempotency WHERE account_id=1"
        ).fetchone()[0]
        assert n == 1

    @pytest.mark.asyncio
    async def test_same_provider_uid_different_rfc_id_both_fire(
        self, db, acct, config,
    ):
        """ Bug 2 — the collision the old key suffered: two
        DIFFERENT messages sharing one provider UID value (the IMAP
        UID 42 recurs in another folder, or after a UIDVALIDITY
        rollover) must each fire their own escalation.

        Under the pre-#250 ``(account, provider_message_id, watch)``
        key the second message would be wrongly suppressed.
        """
        secrets = _Secrets({"SMTP_PASSWORD": "x"})
        W.upsert_watch(db, W.EmailWatch(
            name="boss",
            account_id=1,
            filter=W.WatchFilter(from_addr="boss@"),
            actions=W.WatchActions(
                escalate=W.EscalateAction(
                    enabled=True, notify_email="ops@example.com",
                ),
            ),
        ))
        with patch(
            "email_triage.web.smtp_send.send_simple_smtp_email",
        ) as send:
            # Message A — provider UID 42, RFC id "<a@host>".
            a = await fire_watches_for_message(
                db=db, config=config, secrets=secrets,
                account=acct,
                sender="boss@example.com", subject="review A",
                category="action-required",
                message_id="42", idempotency_key="<a@host>",
            )
            # Message B — a DIFFERENT mail that also has provider UID
            # 42 (different folder / epoch) but its own RFC id.
            b = await fire_watches_for_message(
                db=db, config=config, secrets=secrets,
                account=acct,
                sender="boss@example.com", subject="review B",
                category="action-required",
                message_id="42", idempotency_key="<b@host>",
            )
        # Both fired — no false suppression from the UID collision.
        assert send.call_count == 2
        assert not a[0].get("skipped_idempotent")
        assert not b[0].get("skipped_idempotent")
        n = db.execute(
            "SELECT COUNT(*) FROM watch_fire_idempotency WHERE account_id=1"
        ).fetchone()[0]
        assert n == 2

    @pytest.mark.asyncio
    async def test_missing_rfc_id_falls_back_to_provider_id(
        self, db, acct, config,
    ):
        """ Bug 2 boundary — a message with no RFC Message-ID
        header (empty ``idempotency_key``) falls back to the provider
        ``message_id`` for the key. Still deduplicates within that
        fallback — no worse than the pre-#250 behaviour.
        """
        secrets = _Secrets({"SMTP_PASSWORD": "x"})
        W.upsert_watch(db, W.EmailWatch(
            name="boss",
            account_id=1,
            filter=W.WatchFilter(from_addr="boss@"),
            actions=W.WatchActions(
                escalate=W.EscalateAction(
                    enabled=True, notify_email="ops@example.com",
                ),
            ),
        ))
        with patch(
            "email_triage.web.smtp_send.send_simple_smtp_email",
        ) as send:
            first = await fire_watches_for_message(
                db=db, config=config, secrets=secrets,
                account=acct,
                sender="boss@example.com", subject="review",
                category="action-required",
                message_id="prov-9", idempotency_key="",
            )
            second = await fire_watches_for_message(
                db=db, config=config, secrets=secrets,
                account=acct,
                sender="boss@example.com", subject="review",
                category="action-required",
                message_id="prov-9", idempotency_key="",
            )
        assert send.call_count == 1
        assert not first[0].get("skipped_idempotent")
        assert second[0]["skipped_idempotent"] is True
        # The fallback key is the provider id.
        row = db.execute(
            "SELECT rfc_message_id FROM watch_fire_idempotency "
            "WHERE account_id=1"
        ).fetchone()
        assert row["rfc_message_id"] == "prov-9"

    # --  Bug 3 — per-key lock serialises check->fire->record -----

    @pytest.mark.asyncio
    async def test_concurrent_fires_escalate_exactly_once(
        self, db, acct, config,
    ):
        """ Bug 3 — two concurrent ``fire_watches_for_message``
        calls for the SAME message race; the per-(account, rfc_id,
        watch) asyncio.Lock serialises check -> fire -> record so
        exactly ONE escalation goes out, never a duplicate pager/SMS.

        Pre-#250 the check (``SELECT``) and the record (``INSERT``)
        were two separate lock acquisitions with an ``await`` between
        them — both racers could pass the check and both fire.
        """
        secrets = _Secrets({"SMTP_PASSWORD": "x"})
        W.upsert_watch(db, W.EmailWatch(
            name="pager",
            account_id=1,
            filter=W.WatchFilter(from_addr="boss@"),
            actions=W.WatchActions(
                escalate=W.EscalateAction(
                    enabled=True, notify_email="ops@example.com",
                ),
            ),
        ))
        send_calls = 0

        def _slow_send(*args, **kwargs):
            nonlocal send_calls
            send_calls += 1

        async def _one():
            return await fire_watches_for_message(
                db=db, config=config, secrets=secrets,
                account=acct,
                sender="boss@example.com", subject="urgent",
                category="action-required",
                message_id="200", idempotency_key="<race@host>",
            )

        # ONE patch around the whole gather — see the no-drop test
        # below for why per-coroutine patches are unsafe here.
        with patch(
            "email_triage.web.smtp_send.send_simple_smtp_email",
            side_effect=_slow_send,
        ):
            results = await asyncio.gather(_one(), _one())
        # Exactly one escalation across both concurrent runs.
        assert send_calls == 1
        fired = [r for pair in results for r in pair
                 if not r.get("skipped_idempotent")]
        skipped = [r for pair in results for r in pair
                   if r.get("skipped_idempotent")]
        assert len(fired) == 1
        assert len(skipped) == 1
        # Exactly one durable success row.
        n = db.execute(
            "SELECT COUNT(*) FROM watch_fire_idempotency WHERE account_id=1"
        ).fetchone()[0]
        assert n == 1

    @pytest.mark.asyncio
    async def test_concurrent_first_fire_fails_second_refires_no_drop(
        self, db, acct, config,
    ):
        """ Bug 3 — the no-DROP property under concurrency.

        Two concurrent ``fire_watches_for_message`` calls for the SAME
        message. The runner that wins the per-key lock fires FIRST and
        its escalation FAILS (SMTP down). Because the durable table
        records only DELIVERED fires, the loser — which waited on the
        lock — re-checks, finds NO success row, and RE-FIRES.

        This is the property the earlier claim-before-fire design broke:
        there the loser saw the winner's claim and skipped, the winner
        then failed and released, and the watch fired zero times — a
        permanently dropped pager on the live path. Option 4 keeps the
        escalation alive: a first-runner failure never makes the second
        runner skip.
        """
        secrets = _Secrets({"SMTP_PASSWORD": "x"})
        W.upsert_watch(db, W.EmailWatch(
            name="pager",
            account_id=1,
            filter=W.WatchFilter(from_addr="boss@"),
            actions=W.WatchActions(
                escalate=W.EscalateAction(
                    enabled=True, notify_email="ops@example.com",
                ),
            ),
        ))
        # The first SMTP send raises (relay momentarily down); every
        # later send succeeds. The per-key lock serialises the two
        # runners, so "first send" == the lock winner's fire. ONE patch
        # wraps the whole gather — nesting a patch per coroutine would
        # let the first coroutine's patch-exit restore the real SMTP
        # function while the second is still running.
        send_attempts = 0

        def _first_fails(*args, **kwargs):
            nonlocal send_attempts
            send_attempts += 1
            if send_attempts == 1:
                raise OSError("connection refused")

        async def _one():
            return await fire_watches_for_message(
                db=db, config=config, secrets=secrets,
                account=acct,
                sender="boss@example.com", subject="urgent",
                category="action-required",
                message_id="300", idempotency_key="<nodrop@host>",
            )

        with patch(
            "email_triage.web.smtp_send.send_simple_smtp_email",
            side_effect=_first_fails,
        ):
            results = await asyncio.gather(_one(), _one())
        # Two send attempts: the winner failed, the loser re-fired and
        # succeeded — the escalation was NOT dropped.
        assert send_attempts == 2
        all_results = [r for pair in results for r in pair]
        # Neither run reports skipped_idempotent: the winner fired (and
        # failed), the loser re-fired (because no success was recorded).
        skipped = [r for r in all_results if r.get("skipped_idempotent")]
        assert skipped == [], "a failed first fire must not make the second skip"
        # Exactly one DELIVERED fire is recorded (the loser's success).
        oks = [r for r in all_results
               if (r.get("escalate") or {}).get("ok")]
        assert len(oks) == 1
        n = db.execute(
            "SELECT COUNT(*) FROM watch_fire_idempotency WHERE account_id=1"
        ).fetchone()[0]
        assert n == 1

    @pytest.mark.asyncio
    async def test_per_key_lock_proven_contended(
        self, db, acct, config,
    ):
        """ Bug 3 — PROVE the per-key lock is genuinely contended,
        not merely that two gathered coroutines happen to serialise.

        ``pattern_barrier_concurrency_test.md`` warns against relying on
        incidental ordering. Here the coroutine concurrency is on ONE
        event loop, so the asyncio-correct rendezvous is an
        ``asyncio.Event`` (a blocking ``threading.Barrier`` would
        deadlock the single loop thread). The test:

          1. patches ``fire_one_watch`` so the lock WINNER, once inside
             the per-key critical section, signals ``winner_inside`` and
             then parks on ``release_winner``;
          2. starts both runners; waits for ``winner_inside``;
          3. asserts — while the winner is parked mid-critical-section —
             that the per-key lock IS locked and HAS exactly one waiter
             (the loser, provably blocked in ``async with lock``);
          4. releases the winner; both finish; asserts exactly one
             delivered fire + one durable row + one idempotent skip.

        Step 3 is the proof: the loser reached the lock and blocked
        while the winner held it — genuine contention, not luck.
        """
        from email_triage.web import watch_runner as WR

        secrets = _Secrets({"SMTP_PASSWORD": "x"})
        watch = W.upsert_watch(db, W.EmailWatch(
            name="pager",
            account_id=1,
            filter=W.WatchFilter(from_addr="boss@"),
            actions=W.WatchActions(
                escalate=W.EscalateAction(
                    enabled=True, notify_email="ops@example.com",
                ),
            ),
        ))
        # The per-key lock is keyed (account_id, idempotency_key,
        # watch_id) — capture the real watch_id assigned by upsert.
        lock_key = (acct["id"], "<contend@host>", watch.watch_id)

        winner_inside = asyncio.Event()
        release_winner = asyncio.Event()
        fire_calls = 0
        real_fire_one_watch = WR.fire_one_watch

        async def _gated_fire_one_watch(**kwargs):
            # Runs INSIDE the per-key lock's critical section. The first
            # caller is the lock winner: signal + park so the test can
            # inspect the lock while it is held.
            nonlocal fire_calls
            fire_calls += 1
            if fire_calls == 1:
                winner_inside.set()
                await release_winner.wait()
            return await real_fire_one_watch(**kwargs)

        async def _one():
            return await fire_watches_for_message(
                db=db, config=config, secrets=secrets,
                account=acct,
                sender="boss@example.com", subject="urgent",
                category="action-required",
                message_id="400", idempotency_key="<contend@host>",
            )

        with patch(
            "email_triage.web.smtp_send.send_simple_smtp_email",
        ):
            with patch.object(
                WR, "fire_one_watch", side_effect=_gated_fire_one_watch,
            ):
                task_a = asyncio.create_task(_one())
                task_b = asyncio.create_task(_one())
                # Wait until the winner is parked inside the critical
                # section. Bounded so a regression cannot hang the suite.
                await asyncio.wait_for(winner_inside.wait(), timeout=5.0)

                # PROOF OF CONTENTION: the per-key lock is held by the
                # winner, and the loser is blocked waiting on it.
                lock = WR._watch_fire_locks.get(lock_key)
                assert lock is not None
                assert lock.locked(), "winner must hold the per-key lock"
                # Wait for the loser to reach `async with lock` and
                # populate the asyncio.Lock internal `_waiters` deque.
                # A single sleep(0) is one scheduler tick — not enough
                # under CI runner load. Mirror the winner-side event
                # barrier idiom with a bounded poll on the state we
                # are about to assert. Root-cause-scope-adjacent to
                # the refcount barrier fix below.
                async def _loser_at_waiters():
                    while not getattr(lock, "_waiters", None):
                        await asyncio.sleep(0)
                await asyncio.wait_for(_loser_at_waiters(), timeout=5.0)
                waiters = getattr(lock, "_waiters", None)
                assert waiters, (
                    "the loser must be blocked waiting on the per-key "
                    "lock — proves genuine contention"
                )

                # Release the winner; both runners finish.
                release_winner.set()
                results = await asyncio.gather(task_a, task_b)

        all_results = [r for pair in results for r in pair]
        fired = [r for r in all_results
                 if not r.get("skipped_idempotent")]
        skipped = [r for r in all_results
                   if r.get("skipped_idempotent")]
        # Exactly one fired, one skipped — the lock serialised them.
        assert len(fired) == 1
        assert len(skipped) == 1
        assert (fired[0].get("escalate") or {}).get("ok") is True
        n = db.execute(
            "SELECT COUNT(*) FROM watch_fire_idempotency WHERE account_id=1"
        ).fetchone()[0]
        assert n == 1
        # The lock entry is pruned once both runners are done (idle).
        assert lock_key not in WR._watch_fire_locks

    @pytest.mark.asyncio
    async def test_lock_registry_refcounted_prune(
        self, db, acct, config,
    ):
        """ Bug 3 — the per-key lock registry is REFCOUNTED.

        db-sme's Option-4 re-review flagged that inferring lock
        idleness from ``asyncio.Lock._waiters`` has a scheduler-race
        window (``release()`` empties ``_waiters`` before the woken
        waiter actually holds the lock — a prune in that window splits
        the key across two lock objects → duplicate pager). The fix is
        a refcount: every ``_get_watch_fire_lock`` increments, every
        ``_release_watch_fire_lock`` decrements, prune only at 0.

        This test pins the refcount lifecycle: while a fire is in
        flight the key has a lock entry AND a positive refcount; once
        every runner has released, BOTH dicts drop the key.
        """
        from email_triage.web import watch_runner as WR

        secrets = _Secrets({"SMTP_PASSWORD": "x"})
        watch = W.upsert_watch(db, W.EmailWatch(
            name="pager",
            account_id=1,
            filter=W.WatchFilter(from_addr="boss@"),
            actions=W.WatchActions(
                escalate=W.EscalateAction(
                    enabled=True, notify_email="ops@example.com",
                ),
            ),
        ))
        key = (acct["id"], "<refcount@host>", watch.watch_id)

        winner_inside = asyncio.Event()
        release_winner = asyncio.Event()
        fire_calls = 0
        real_fire_one_watch = WR.fire_one_watch

        async def _gated_fire_one_watch(**kwargs):
            nonlocal fire_calls
            fire_calls += 1
            if fire_calls == 1:
                winner_inside.set()
                await release_winner.wait()
            return await real_fire_one_watch(**kwargs)

        async def _one():
            return await fire_watches_for_message(
                db=db, config=config, secrets=secrets,
                account=acct,
                sender="boss@example.com", subject="urgent",
                category="action-required",
                message_id="500", idempotency_key="<refcount@host>",
            )

        # Precondition: registry clean.
        assert key not in WR._watch_fire_locks
        assert key not in WR._watch_fire_refcount

        with patch("email_triage.web.smtp_send.send_simple_smtp_email"):
            with patch.object(
                WR, "fire_one_watch", side_effect=_gated_fire_one_watch,
            ):
                task_a = asyncio.create_task(_one())
                task_b = asyncio.create_task(_one())
                await asyncio.wait_for(winner_inside.wait(), timeout=5.0)

                # Wait for the loser to hit refcount++ inside
                # _get_watch_fire_lock. A single asyncio.sleep(0)
                # isn't enough under CI runner load (one scheduler
                # tick may not schedule the loser far enough); mirror
                # the winner-side event barrier idiom with a bounded
                # poll on the state we're about to assert.
                async def _loser_at_refcount():
                    while WR._watch_fire_refcount.get(key) != 2:
                        await asyncio.sleep(0)
                await asyncio.wait_for(_loser_at_refcount(), timeout=5.0)

                # MID-FLIGHT: both runners are in the get/release span
                # (winner holds, loser waits) — refcount must be 2 and
                # the lock entry must be present.
                assert key in WR._watch_fire_locks
                assert WR._watch_fire_refcount.get(key) == 2

                release_winner.set()
                await asyncio.gather(task_a, task_b)

        # POST: every runner released — both dicts drop the key.
        assert key not in WR._watch_fire_locks
        assert key not in WR._watch_fire_refcount


# ---------------------------------------------------------------------------
# fire_triage_completed wiring
# ---------------------------------------------------------------------------


class TestTriageCompletedEmitter:
    """Defensive coverage for the existing  emitter — the receiver
    side ships on OpenClaw later. Verify the gate ordering + payload
    shape so future refactors don't accidentally start sending PHI.
    """

    @pytest.mark.asyncio
    async def test_hipaa_account_skips_emit(self, db, hipaa_acct, config):
        from email_triage.web.events import (
            EventDispatcher, fire_triage_completed,
        )
        from email_triage.config import WebhookTarget
        dispatcher = EventDispatcher(
            targets=[WebhookTarget(
                url="http://127.0.0.1:9999/h",
                events=["triage.completed"],
            )],
        )
        run = {
            "run_id": "r1", "query": "is:unread",
            "total_messages": 0, "results": [], "errors": [],
            "elapsed_secs": 0.1,
        }
        attempted = await fire_triage_completed(
            dispatcher, db, config, hipaa_acct, run,
        )
        assert attempted is False

    @pytest.mark.asyncio
    async def test_non_hipaa_account_fires(self, db, acct, config):
        from email_triage.web.events import (
            EventDispatcher, fire_triage_completed,
        )
        from email_triage.config import WebhookTarget

        dispatcher = EventDispatcher(
            targets=[WebhookTarget(
                url="http://192.168.1.10:9999/h",
                events=["triage.completed"],
            )],
        )
        run = {
            "run_id": "r1", "query": "is:unread",
            "total_messages": 0, "results": [], "errors": [],
            "elapsed_secs": 0.1,
        }
        captured: dict = {}
        with _patched_httpx(captured, status=200):
            attempted = await fire_triage_completed(
                dispatcher, db, config, acct, run,
            )
        assert attempted is True


# ---------------------------------------------------------------------------
#  — auto-retire seam (proves the runner actually CALLS maybe_auto_retire,
# and that retire is GROUP-grained, not per-account-row)
# ---------------------------------------------------------------------------


class TestAutoRetireSeam:
    """ — the auto-retire seam in ``fire_watches_for_message``.

    Guards two things the model-only tests can't:
      * the runner ACTUALLY invokes ``maybe_auto_retire_watch`` on a delivered
        fire (the ``incident_2026-06-11_topic_digest_dead_in_prod`` shape — a
        green model test over a dead seam proves nothing);
      * retire is GROUP-grained: a watch spanning N accounts retires at N TOTAL
        matches and retires the WHOLE group atomically (the devils-advocate
        must-fix — per-row counting would mean "N per account" + fragment the
        group on delete).
    """

    def _add_account(self, db, acct_id, user_id):
        now = datetime.now(timezone.utc).isoformat()
        db.execute(
            "INSERT INTO email_accounts "
            "(id, user_id, name, provider_type, config_json, hipaa, "
            "created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (acct_id, user_id, f"acct{acct_id}", "imap",
             json.dumps({"notify_email": "ops@example.com"}), 0, now, now),
        )
        db.commit()
        return {"id": acct_id, "user_id": user_id, "name": f"acct{acct_id}",
                "provider_type": "imap", "hipaa": False,
                "config": {"notify_email": "ops@example.com"}}

    @pytest.mark.asyncio
    async def test_runner_invokes_auto_retire_and_disables(
        self, db, acct, config,
    ):
        """A single-account watch with ``after_n=2`` is disabled by the runner
        on the 2nd delivered fire — and the result row is stamped."""
        secrets = _Secrets({"SMTP_PASSWORD": "x"})
        w = W.upsert_watch(db, W.EmailWatch(
            name="retire-me", account_id=1,
            filter=W.WatchFilter(from_addr="boss@"),
            actions=W.WatchActions(
                escalate=W.EscalateAction(
                    enabled=True, notify_email="ops@example.com"),
                auto_retire=W.AutoRetireAction(after_n=2, action="disable"),
            ),
        ))
        with patch("email_triage.web.smtp_send.send_simple_smtp_email"):
            r1 = await fire_watches_for_message(
                db=db, config=config, secrets=secrets, account=acct,
                sender="boss@example.com", subject="s", category="c",
                message_id="m1")
            # 1 < 2 -> not retired yet.
            assert not r1[0].get("auto_retired")
            assert W.get_watch(db, w.watch_id).enabled is True
            r2 = await fire_watches_for_message(
                db=db, config=config, secrets=secrets, account=acct,
                sender="boss@example.com", subject="s", category="c",
                message_id="m2")
        assert r2[0]["auto_retired"] == "disabled"
        got = W.get_watch(db, w.watch_id)
        assert got is not None and got.enabled is False  # reversible

    @pytest.mark.asyncio
    async def test_group_retires_at_total_not_per_account(
        self, db, acct, config,
    ):
        """A 2-account watch group with ``after_n=2`` retires at 2 TOTAL (one
        match on each account), disabling BOTH rows — not 2-per-account."""
        secrets = _Secrets({"SMTP_PASSWORD": "x"})
        acct2 = self._add_account(db, 2, acct["user_id"])
        gid = "grp-disable"
        ar = W.WatchActions(
            escalate=W.EscalateAction(
                enabled=True, notify_email="ops@example.com"),
            auto_retire=W.AutoRetireAction(after_n=2, action="disable"),
        )
        w1 = W.upsert_watch(db, W.EmailWatch(
            name="g", account_id=1, watch_group_id=gid,
            filter=W.WatchFilter(from_addr="boss@"), actions=ar))
        w2 = W.upsert_watch(db, W.EmailWatch(
            name="g", account_id=2, watch_group_id=gid,
            filter=W.WatchFilter(from_addr="boss@"), actions=ar))
        with patch("email_triage.web.smtp_send.send_simple_smtp_email"):
            # 1 match on account 1 -> group total 1 < 2, nothing retired.
            await fire_watches_for_message(
                db=db, config=config, secrets=secrets, account=acct,
                sender="boss@example.com", subject="s", category="c",
                message_id="a1")
            assert W.get_watch(db, w1.watch_id).enabled is True
            assert W.get_watch(db, w2.watch_id).enabled is True
            # 1 match on account 2 -> group total 2 >= 2, retire the GROUP.
            r = await fire_watches_for_message(
                db=db, config=config, secrets=secrets, account=acct2,
                sender="boss@example.com", subject="s", category="c",
                message_id="b1")
        assert r[0]["auto_retired"] == "disabled"
        # BOTH rows disabled — atomic group retire, not just account 2's.
        assert W.get_watch(db, w1.watch_id).enabled is False
        assert W.get_watch(db, w2.watch_id).enabled is False

    @pytest.mark.asyncio
    async def test_group_delete_removes_all_rows(self, db, acct, config):
        """``action="delete"`` at the group threshold removes EVERY row in the
        group (not just the firing account's), and purges the group's fire log."""
        secrets = _Secrets({"SMTP_PASSWORD": "x"})
        acct2 = self._add_account(db, 2, acct["user_id"])
        gid = "grp-delete"
        ar = W.WatchActions(
            escalate=W.EscalateAction(
                enabled=True, notify_email="ops@example.com"),
            auto_retire=W.AutoRetireAction(after_n=2, action="delete"),
        )
        w1 = W.upsert_watch(db, W.EmailWatch(
            name="g", account_id=1, watch_group_id=gid,
            filter=W.WatchFilter(from_addr="boss@"), actions=ar))
        w2 = W.upsert_watch(db, W.EmailWatch(
            name="g", account_id=2, watch_group_id=gid,
            filter=W.WatchFilter(from_addr="boss@"), actions=ar))
        with patch("email_triage.web.smtp_send.send_simple_smtp_email"):
            await fire_watches_for_message(
                db=db, config=config, secrets=secrets, account=acct,
                sender="boss@example.com", subject="s", category="c",
                message_id="a1")
            r = await fire_watches_for_message(
                db=db, config=config, secrets=secrets, account=acct2,
                sender="boss@example.com", subject="s", category="c",
                message_id="b1")
        assert r[0]["auto_retired"] == "deleted"
        # Whole group gone — no fragmentation.
        assert W.get_watch(db, w1.watch_id) is None
        assert W.get_watch(db, w2.watch_id) is None
        # The group's now-dead idempotency rows were purged.
        remaining = db.execute(
            "SELECT COUNT(*) FROM watch_fire_idempotency "
            "WHERE watch_id IN (?, ?)", (w1.watch_id, w2.watch_id),
        ).fetchone()[0]
        assert remaining == 0
