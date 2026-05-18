"""#161 item 2 — per-account "Auto-scan on schedule" toggle.

Covers:

  * GET /profile/style-data renders the checkbox in both empty + populated
    branches with the HIPAA-aware default (non-HIPAA → checked; HIPAA →
    unchecked + disabled).
  * POST /profile/style-data/toggle-auto-scan persists the flag.
  * HIPAA without M-1+M-2 opt-in silently refuses the write.
  * The background ``_run_sent_mail_capture_sweep`` skips accounts with
    auto_scan_enabled=False (counted under ``skipped_auto_scan_off``).
"""

from __future__ import annotations

import asyncio
import types

import pytest

from email_triage.web.db import (
    create_email_account,
    is_auto_scan_enabled_for_account,
    set_auto_scan_enabled_for_account,
    set_account_hipaa,
    set_rag_sent_index_enabled,
    set_style_knobs_hipaa_allow,
    get_email_account,
)


def _make_acct(db, owner_id: int, name: str = "Acct") -> int:
    return create_email_account(
        db, owner_id, name, "imap", {"host": "mail.example.com"},
    )


class TestToggleRender:
    def test_non_hipaa_account_renders_auto_scan_checked(
        self, client, user_cookies, db, regular_user,
    ):
        _make_acct(db, regular_user["id"], "Personal")
        resp = client.get(
            "/profile/style-data", cookies=user_cookies,
        )
        assert resp.status_code == 200
        assert 'name="auto_scan_enabled"' in resp.text
        assert "Auto-scan on schedule" in resp.text

    def test_hipaa_without_optin_renders_disabled(
        self, client, user_cookies, db, regular_user,
    ):
        a = _make_acct(db, regular_user["id"], "MedAcct")
        set_account_hipaa(db, a, True, actor_id=regular_user["id"])
        resp = client.get(
            "/profile/style-data", cookies=user_cookies,
        )
        assert resp.status_code == 200
        # Auto-scan checkbox renders with the disabled attribute.
        assert 'name="auto_scan_enabled"' in resp.text


class TestToggleSave:
    def test_non_hipaa_save_persists(
        self, client, user_cookies, db, regular_user,
    ):
        a = _make_acct(db, regular_user["id"], "Personal")
        # Default for non-HIPAA = True.
        assert is_auto_scan_enabled_for_account(
            get_email_account(db, a),
        ) is True

        # Submit unchecked → flip off.
        resp = client.post(
            f"/profile/style-data/toggle-auto-scan?account_id={a}",
            data={"auto_scan_submitted": "1"},
            cookies=user_cookies,
        )
        assert resp.status_code in (200, 303)
        assert is_auto_scan_enabled_for_account(
            get_email_account(db, a),
        ) is False

        # Submit checked → flip back on.
        resp2 = client.post(
            f"/profile/style-data/toggle-auto-scan?account_id={a}",
            data={
                "auto_scan_submitted": "1",
                "auto_scan_enabled": "1",
            },
            cookies=user_cookies,
        )
        assert resp2.status_code in (200, 303)
        assert is_auto_scan_enabled_for_account(
            get_email_account(db, a),
        ) is True

    def test_hipaa_without_optin_refused(
        self, client, user_cookies, db, regular_user,
    ):
        a = _make_acct(db, regular_user["id"], "MedAcct")
        set_account_hipaa(db, a, True, actor_id=regular_user["id"])

        # Try to turn it ON.
        resp = client.post(
            f"/profile/style-data/toggle-auto-scan?account_id={a}",
            data={
                "auto_scan_submitted": "1",
                "auto_scan_enabled": "1",
            },
            cookies=user_cookies,
        )
        assert resp.status_code in (200, 303)
        # HIPAA + no opt-in default is OFF; still OFF after refused save.
        assert is_auto_scan_enabled_for_account(
            get_email_account(db, a),
        ) is False


class TestDefaultsHelper:
    def test_non_hipaa_defaults_on(self):
        assert is_auto_scan_enabled_for_account(
            {"hipaa": False, "config": {}},
        ) is True

    def test_hipaa_defaults_off(self):
        assert is_auto_scan_enabled_for_account(
            {"hipaa": True, "config": {}},
        ) is False

    def test_explicit_key_overrides_hipaa_default(self):
        assert is_auto_scan_enabled_for_account(
            {"hipaa": True, "config": {"auto_scan_enabled": True}},
        ) is True
        assert is_auto_scan_enabled_for_account(
            {"hipaa": False, "config": {"auto_scan_enabled": False}},
        ) is False


@pytest.mark.asyncio
async def test_capture_loop_skips_when_auto_scan_off(
    app, db, regular_user,
):
    """Background ``_run_sent_mail_capture_sweep`` honours the toggle.

    Create two non-HIPAA accounts: one with auto_scan_enabled=True (the
    default), one explicitly OFF. The sweep should consider both but
    skip the OFF one with skipped_auto_scan_off=1.
    """
    a_on = _make_acct(db, regular_user["id"], "On")
    a_off = _make_acct(db, regular_user["id"], "Off")
    set_auto_scan_enabled_for_account(db, a_off, False)
    # Opt both into RAG so they'd both run if not for the toggle.
    set_rag_sent_index_enabled(db, a_on, enabled=True)
    set_rag_sent_index_enabled(db, a_off, enabled=True)

    # Master toggle implicitly on (default). Wire a no-op embedding
    # backend so the no-backend branch doesn't fire.
    app.state.embedding_backend = object()
    app.state.embedding_model = "test-model"
    app.state.sqlite_vec_available = False

    # Stub _create_provider_from_account so the sweep never tries a
    # real connection — we only care about the gating counters.
    from email_triage.web.routers import ui as _ui

    class _StubProv:
        async def close(self):
            pass

    def _fake_create(acct, secrets):
        return _StubProv()

    orig = _ui._create_provider_from_account
    _ui._create_provider_from_account = _fake_create  # type: ignore[assignment]
    try:
        # Patch SentMailIndex + SentMailCaptureLoop so they don't
        # do real work; we only care about the per-account skip.
        from email_triage.actions import sent_mail_capture, sent_mail_index

        class _NoopLoop:
            def __init__(self, *a, **kw):
                pass
            async def scan_recent(self, *, limit):
                return 0

        class _NoopIndex:
            def __init__(self, *a, **kw):
                pass

        orig_loop = sent_mail_capture.SentMailCaptureLoop
        orig_index = sent_mail_index.SentMailIndex
        sent_mail_capture.SentMailCaptureLoop = _NoopLoop  # type: ignore[assignment]
        sent_mail_index.SentMailIndex = _NoopIndex  # type: ignore[assignment]
        try:
            from email_triage.web.app import _run_sent_mail_capture_sweep
            counters = await _run_sent_mail_capture_sweep(app)
        finally:
            sent_mail_capture.SentMailCaptureLoop = orig_loop
            sent_mail_index.SentMailIndex = orig_index
    finally:
        _ui._create_provider_from_account = orig  # type: ignore[assignment]

    assert counters["considered"] == 2
    assert counters["skipped_auto_scan_off"] == 1
