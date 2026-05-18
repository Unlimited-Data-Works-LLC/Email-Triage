"""HIPAA PHI-redaction regression tests for persisted triage output.

Guards two persistence paths that were leaking the classifier's
free-form natural-language output into SQLite rows or HTML responses:

* ``triage_runs.results_json`` — each per-message entry's ``reason``
  field, set in ``email_triage.web.triage_runner.run_triage``.
* Discover scan ``raw_results`` — each entry's ``raw_description``
  field, set in ``email_triage.web.routers.ui.discover_run``.

Both were scrubbed from in-flight logs by ``TriageLogger._PHI_KEYS``
but persisted verbatim prior to this change — so an auditor reading
``triage_runs`` could still see subjects echoed inside the reason.

``is_account_hipaa`` already composes per-account + system HIPAA
(most-restrictive wins — see ``email_triage.triage_logging``), so we
cover both activation paths.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from email_triage.engine.models import Classification, EmailMessage


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_account(db, user_id, *, hipaa, account_id=1):
    now = datetime.now(timezone.utc).isoformat()
    db.execute(
        "INSERT OR REPLACE INTO email_accounts "
        "(id, user_id, name, provider_type, config_json, hipaa, is_active, "
        " created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?)",
        (
            account_id, user_id, "Test IMAP", "imap",
            json.dumps({"host": "mail.test.com", "username": "u@t.com"}),
            1 if hipaa else 0, now, now,
        ),
    )
    db.commit()
    return account_id


def _fake_message(mid="m-1"):
    return EmailMessage(
        message_id=mid,
        provider="imap",
        sender="sender@example.com",
        recipients=["me@example.com"],
        subject="Appointment reminder for Jane Doe",
        body_text="Your next visit is on Monday.",
        date=datetime.now(timezone.utc),
    )


# Reason / description strings that look like PHI. If these leak into
# persisted storage, the exact bug we regress against has returned.
PHI_REASON = "Patient Jane Doe has an upcoming appointment for test results"
PHI_DESCRIPTION = "Clinical note summarising patient Jane Doe's vitals"


class _FakeProvider:
    """Plain class so ``hasattr(provider, "peek_recent_uids")`` returns False
    (MagicMock auto-creates attributes, which would force discover_run's
    ``can_peek`` branch on)."""

    def __init__(self, message=None):
        self._message = message or _fake_message("m-1")
        self.list_folders = AsyncMock(return_value=["INBOX"])
        self.search = AsyncMock(return_value=["m-1"])
        self.fetch_message = AsyncMock(return_value=self._message)
        self.close = AsyncMock()


# ---------------------------------------------------------------------------
# triage_runner: classifier `reason` redaction
# ---------------------------------------------------------------------------


class TestTriageReasonRedaction:
    """``entry["reason"]`` must be ``[redacted]`` when HIPAA is effective."""

    async def _run(self, app, db, acct_id, *, reason):
        from email_triage.web.triage_runner import run_triage

        acct_row = db.execute(
            "SELECT * FROM email_accounts WHERE id = ?", (acct_id,),
        ).fetchone()
        acct = dict(acct_row)
        acct["config"] = json.loads(acct_row["config_json"])

        fake_provider = _FakeProvider()

        fake_classifier = MagicMock()
        fake_classifier.classify = AsyncMock(return_value=Classification(
            category="action-required", confidence=0.9, reason=reason,
        ))

        with patch(
            "email_triage.web.routers.ui._create_provider_from_account",
            return_value=fake_provider,
        ), patch(
            "email_triage.web.routers.ui._build_classifier_from_config",
            return_value=fake_classifier,
        ):
            return await run_triage(
                db, app.state.config, app.state.secrets, acct,
                query="ALL", limit=5, actor_user_id=None, trigger="test",
            )

    async def test_reason_stripped_on_hipaa_account(self, app, db, admin_user):
        acct_id = _make_account(db, admin_user["id"], hipaa=True)
        result = await self._run(app, db, acct_id, reason=PHI_REASON)
        assert len(result["results"]) == 1
        entry = result["results"][0]
        assert entry["reason"] == "[redacted]"
        row = db.execute(
            "SELECT results_json FROM triage_runs ORDER BY id DESC LIMIT 1"
        ).fetchone()
        assert row is not None
        assert PHI_REASON not in row["results_json"]

    async def test_reason_stripped_when_system_hipaa_on(self, app, db, admin_user):
        """Per-account flag OFF — system HIPAA mode alone must trigger
        the redaction. ``is_account_hipaa`` composes both."""
        acct_id = _make_account(db, admin_user["id"], hipaa=False)

        import email_triage.triage_logging as tlog
        saved = tlog._hipaa_mode
        tlog._hipaa_mode = True
        try:
            result = await self._run(app, db, acct_id, reason=PHI_REASON)
        finally:
            tlog._hipaa_mode = saved

        entry = result["results"][0]
        assert entry["reason"] == "[redacted]"
        row = db.execute(
            "SELECT results_json FROM triage_runs ORDER BY id DESC LIMIT 1"
        ).fetchone()
        assert PHI_REASON not in row["results_json"]

    async def test_reason_preserved_when_no_hipaa(self, app, db, admin_user):
        """Regression sanity: the gate doesn't over-redact in the common
        non-HIPAA case."""
        acct_id = _make_account(db, admin_user["id"], hipaa=False)
        result = await self._run(app, db, acct_id, reason=PHI_REASON)
        entry = result["results"][0]
        assert entry["reason"] == PHI_REASON


# ---------------------------------------------------------------------------
# discover_run: classifier `raw_description` redaction
# ---------------------------------------------------------------------------


class TestDiscoverRawDescriptionRedaction:
    """``raw_results[i]["raw_description"]`` must be ``[redacted]``
    when HIPAA is effective for the scanned account."""

    def _post(self, client, admin_cookies, acct_id):
        return client.post(
            "/triage/discover/run",
            data={
                "account_id": str(acct_id),
                "limit": "5",
                "query": "ALL",
                "scan_scope": "inbox",
            },
            cookies=admin_cookies,
        )

    def _build_patches(self, fake_provider, description):
        classifier_text = json.dumps({
            "category": "medical", "description": description,
        })
        fake_classifier = MagicMock()
        fake_classifier.complete = AsyncMock(return_value=classifier_text)
        return [
            patch(
                "email_triage.web.routers.ui._create_provider_from_account",
                return_value=fake_provider,
            ),
            patch(
                "email_triage.web.routers.ui._build_classifier_from_config",
                return_value=fake_classifier,
            ),
        ]

    def test_raw_description_stripped_on_hipaa_account(
        self, client, db, admin_cookies, admin_user,
    ):
        acct_id = _make_account(db, admin_user["id"], hipaa=True)
        fake_provider = _FakeProvider()

        patches = self._build_patches(fake_provider, PHI_DESCRIPTION)
        for p in patches:
            p.start()
        try:
            resp = self._post(client, admin_cookies, acct_id)
        finally:
            for p in patches:
                p.stop()

        assert resp.status_code == 200
        assert PHI_DESCRIPTION not in resp.text
        assert "[redacted]" in resp.text

    def test_raw_description_stripped_when_system_hipaa_on(
        self, client, db, admin_cookies, admin_user,
    ):
        acct_id = _make_account(db, admin_user["id"], hipaa=False)
        fake_provider = _FakeProvider()

        import email_triage.triage_logging as tlog
        saved = tlog._hipaa_mode
        tlog._hipaa_mode = True
        patches = self._build_patches(fake_provider, PHI_DESCRIPTION)
        for p in patches:
            p.start()
        try:
            resp = self._post(client, admin_cookies, acct_id)
        finally:
            for p in patches:
                p.stop()
            tlog._hipaa_mode = saved

        assert resp.status_code == 200
        assert PHI_DESCRIPTION not in resp.text

    def test_raw_description_preserved_when_no_hipaa(
        self, client, db, admin_cookies, admin_user,
    ):
        """Regression sanity: the description is retained in the common
        non-HIPAA case."""
        acct_id = _make_account(db, admin_user["id"], hipaa=False)
        fake_provider = _FakeProvider()
        plain = "Weekly newsletter summary"

        patches = self._build_patches(fake_provider, plain)
        for p in patches:
            p.start()
        try:
            resp = self._post(client, admin_cookies, acct_id)
        finally:
            for p in patches:
                p.stop()

        assert resp.status_code == 200
        assert plain in resp.text
