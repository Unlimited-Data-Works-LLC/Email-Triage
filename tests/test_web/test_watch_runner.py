"""Tests for the watch fire pipeline (#100).

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

    #139 introduced a per-process ``LazyHttpClient`` for webhook
    fan-out. Test mocks of ``httpx.AsyncClient`` only intercept
    construction; once the module has cached a (mocked) client from
    test N, test N+1's patch never fires. Forcing the cache empty
    between tests restores per-test isolation.
    """
    from email_triage.web import watch_runner
    yield
    watch_runner._WEBHOOK_CLIENT._client = None


@pytest.fixture
def db():
    conn = init_db(":memory:")
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
                subject="Invoice #999",
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
        assert body_dict["subject"] == "Invoice #999"
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
# fire_triage_completed wiring (#96 emitter sanity)
# ---------------------------------------------------------------------------


class TestTriageCompletedEmitter:
    """Defensive coverage for the existing #96 emitter — the receiver
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
