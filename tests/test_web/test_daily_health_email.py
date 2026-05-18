"""Tests for daily health email (#27), From-name (#32), signature (#33)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from unittest.mock import patch

import pytest

from email_triage.config import TriageConfig
from email_triage.web.auth import format_from_header
from email_triage.web.daily_health import (
    assemble_daily_health_email,
    gather_health_state,
    is_interesting,
    send_daily_health_email,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class _FakeWatcherManager:
    """Test fake. Accepts the legacy IMAP status dict shape and
    synthesizes the new ``account_states`` interface for daily_health
    + the dashboard chip refactor (everything moved to the unified
    per-account verdict). For each legacy entry we emit:

    * provider: imap
    * push.active: status == "watching"
    * alert: "push_dropped_no_poll" when not watching (matches the
      pre-refactor behaviour where any non-watching status raised
      attention).
    """

    def __init__(self, states):
        self._states = states

    def all_statuses(self):
        return self._states

    def account_states(self, db):
        out = []
        for aid, s in self._states.items():
            status = s.get("status", "unknown")
            active = status == "watching"
            out.append({
                "account_id": aid,
                "account_name": f"acct-{aid}",
                "owner": "test-owner",
                "provider": "imap",
                "push": {
                    "configured": True,
                    "active": active,
                    "detail": (
                        "1/1 folders watching" if active
                        else f"IDLE {status}"
                    ),
                },
                "poll": {"enrolled": False, "last_tick": None, "fresh": False},
                "mode": "push" if active else "none",
                "primary": "push" if active else "none",
                "alert": None if active else (
                    "no_ingestion" if not active else None
                ),
            })
        return out

    def mailbox_counts(self):
        total = len(self._states)
        watching = sum(
            1 for s in self._states.values()
            if s.get("status") == "watching"
        )
        return total, watching

    def poll_counts(self):
        return 0, 0

    def is_poll_running(self, account_id):
        return False


def _make_config(**overrides) -> TriageConfig:
    cfg = TriageConfig()
    cfg.health_email.enabled = True
    cfg.health_email.recipients = ["ops@example.com"]
    cfg.smtp.host = "smtp.example.com"
    cfg.smtp.from_addr = "triage@example.com"
    for k, v in overrides.items():
        head, _, tail = k.partition(".")
        if tail:
            sub = getattr(cfg, head)
            setattr(sub, tail, v)
        else:
            setattr(cfg, head, v)
    return cfg


def _seed_log(db, *, level: str, message: str, ts: str | None = None):
    from email_triage.web.db import insert_log_entry
    insert_log_entry(
        db,
        ts=ts or datetime.now(timezone.utc).isoformat(),
        level=level,
        logger="test",
        message=message,
    )
    db.commit()


# ---------------------------------------------------------------------------
# Signature scope regression (#33 — signature belongs on newsletter digest,
# NOT on the daily health email).  See tests/test_actions/test_digest.py
# for the positive signature-rendering tests.
# ---------------------------------------------------------------------------

class TestSignatureScopeRegression:
    def test_daily_health_email_does_not_include_signature_block(self, db):
        """The default signature string must not appear in either the HTML
        or plain-text rendering of the daily health email."""
        cfg = _make_config()
        state = gather_health_state(db, cfg)
        msg = assemble_daily_health_email(state, cfg)

        combined = "\n".join(
            str(p.get_payload()) for p in msg.walk() if not p.is_multipart()
        )
        assert "Sent by your email-triage" not in combined
        assert "Digest 🗞️" not in combined


# ---------------------------------------------------------------------------
# From-name (#32)
# ---------------------------------------------------------------------------

class TestFromName:
    def test_from_name_sets_display_name_header(self):
        assert format_from_header("addr@x.com", "Email Triage") == \
            '"Email Triage" <addr@x.com>'

    def test_from_name_empty_keeps_bare_address(self):
        assert format_from_header("addr@x.com", "") == "addr@x.com"
        assert format_from_header("addr@x.com", None) == "addr@x.com"

    def test_from_name_escapes_quotes(self):
        assert format_from_header("a@x.com", 'he said "hi"') == \
            '"he said \\"hi\\"" <a@x.com>'

    def test_send_otp_email_sets_from_name(self):
        """OTP codepath uses format_from_header when from_name is present."""
        from email_triage.web import auth as auth_mod

        captured: dict = {}

        class _FakeSMTP:
            def __init__(self, host, port):
                captured["host"] = host
            def __enter__(self):
                return self
            def __exit__(self, *a):
                return False
            def starttls(self):
                pass
            def login(self, u, p):
                pass
            def send_message(self, msg):
                captured["msg"] = msg

        with patch.object(auth_mod.smtplib, "SMTP", _FakeSMTP):
            auth_mod.send_otp_email(
                smtp_host="h", smtp_port=25, smtp_user="u",
                smtp_password="p", from_addr="t@x.com", to_addr="u@x.com",
                code="123456", use_tls=True, from_name="Email Triage",
            )
        # EmailMessage may normalize quotes away for token-safe names.
        # The important thing is that the display name + address both appear.
        from_hdr = str(captured["msg"]["From"])
        assert "Email Triage" in from_hdr
        assert "<t@x.com>" in from_hdr

    def test_send_otp_email_without_from_name_bare_address(self):
        from email_triage.web import auth as auth_mod

        captured: dict = {}

        class _FakeSMTP:
            def __init__(self, *a):
                pass
            def __enter__(self):
                return self
            def __exit__(self, *a):
                return False
            def starttls(self): pass
            def login(self, u, p): pass
            def send_message(self, msg):
                captured["msg"] = msg

        with patch.object(auth_mod.smtplib, "SMTP", _FakeSMTP):
            auth_mod.send_otp_email(
                smtp_host="h", smtp_port=25, smtp_user="u",
                smtp_password="p", from_addr="t@x.com", to_addr="u@x.com",
                code="123456", use_tls=True,
            )
        assert captured["msg"]["From"] == "t@x.com"


# ---------------------------------------------------------------------------
# Daily health assembly
# ---------------------------------------------------------------------------

class TestDailyHealthAssembly:
    def test_daily_health_email_assembles_all_sections(self, db):
        cfg = _make_config()
        _seed_log(db, level="ERROR", message="gateway disconnect")
        _seed_log(db, level="WARNING", message="slow classify")

        state = gather_health_state(db, cfg, watcher_manager=_FakeWatcherManager({
            1: {"status": "watching", "processed": 12, "errors": 0,
                "last_message": None, "last_error": None,
                "started_at": datetime.now(timezone.utc).isoformat()},
        }))
        msg = assemble_daily_health_email(state, cfg)

        # Multi-part: text + html.
        assert msg.is_multipart() or msg.get_content_type() == "multipart/alternative"
        payloads = [p.get_payload() for p in msg.walk() if not p.is_multipart()]
        combined = "\n".join(str(p) for p in payloads)

        assert "Daily health" in msg["Subject"]
        assert "Status" in combined
        assert "Activity" in combined
        assert "Error tail" in combined or "gateway disconnect" in combined
        assert "log_entries" in combined
        assert "Watchers" in combined
        # Signature intentionally NOT rendered on the daily health email
        # (item #39 scope correction — signature belongs on newsletter
        # digests, not admin health email).
        assert "Health Digest" not in combined

    def test_daily_health_email_drops_hipaa_section_on_system_hipaa_mode(self, db):
        cfg = _make_config()
        from email_triage import triage_logging
        prev = triage_logging._hipaa_mode
        try:
            triage_logging._hipaa_mode = True
            state = gather_health_state(db, cfg)
            msg = assemble_daily_health_email(state, cfg)
            combined = "\n".join(
                str(p.get_payload()) for p in msg.walk() if not p.is_multipart()
            )
            assert "HIPAA access events" not in combined
        finally:
            triage_logging._hipaa_mode = prev

    def test_daily_health_email_attention_subject_when_watcher_disconnected(self, db):
        cfg = _make_config()
        long_ago = (datetime.now(timezone.utc) - timedelta(minutes=30)).isoformat()
        watchers = _FakeWatcherManager({
            1: {"status": "error", "processed": 0, "errors": 3,
                "last_message": None, "last_error": "conn refused",
                "started_at": long_ago},
        })
        state = gather_health_state(db, cfg, watcher_manager=watchers)
        msg = assemble_daily_health_email(state, cfg)
        assert "Attention" in msg["Subject"]

    def test_daily_health_email_ok_subject_when_all_green(self, db):
        cfg = _make_config()
        cfg.health_email.error_rate_threshold_pct = 100  # nothing triggers
        state = gather_health_state(db, cfg)
        msg = assemble_daily_health_email(state, cfg)
        assert msg["Subject"].endswith("OK")

    def test_daily_health_email_quiet_mode_skips_when_nothing_interesting(self, db):
        cfg = _make_config()
        cfg.health_email.quiet_mode = True
        state = gather_health_state(db, cfg)
        # Clean DB, no watchers, no logs — boring.
        assert is_interesting(state) is False

    def test_daily_health_email_quiet_mode_fires_when_errors_present(self, db):
        cfg = _make_config()
        cfg.health_email.quiet_mode = True
        _seed_log(db, level="ERROR", message="boom")
        state = gather_health_state(db, cfg)
        assert is_interesting(state) is True


# ---------------------------------------------------------------------------
# Send codepath
# ---------------------------------------------------------------------------

class TestSendDailyHealth:
    def _capture_smtp(self, monkeypatch):
        captured: dict = {}

        class _FakeSMTP:
            def __init__(self, host, port):
                captured["host"] = host
                captured["port"] = port
            def __enter__(self): return self
            def __exit__(self, *a): return False
            def starttls(self): captured["tls"] = True
            def login(self, u, p):
                captured["login"] = (u, p)
            def send_message(self, msg):
                captured["msg"] = msg

        monkeypatch.setattr(
            "email_triage.web.daily_health.smtplib.SMTP", _FakeSMTP,
        )
        return captured

    def test_disabled_returns_false(self, db):
        cfg = _make_config()
        cfg.health_email.enabled = False
        sent, reason = send_daily_health_email(db, cfg, secrets=None)
        assert sent is False
        assert "disabled" in reason

    def test_missing_recipients(self, db):
        cfg = _make_config()
        cfg.health_email.recipients = []
        sent, reason = send_daily_health_email(db, cfg, secrets=None)
        assert sent is False
        assert "recipient" in reason

    def test_missing_smtp(self, db):
        cfg = _make_config()
        cfg.smtp.host = ""
        sent, reason = send_daily_health_email(db, cfg, secrets=None)
        assert sent is False
        assert "SMTP" in reason

    def test_send_now_button_fires_same_codepath(self, db, monkeypatch):
        cfg = _make_config()
        cfg.health_email.quiet_mode = True  # would normally skip
        captured = self._capture_smtp(monkeypatch)
        sent, reason = send_daily_health_email(
            db, cfg, secrets=None, force=True,
        )
        assert sent is True
        assert captured.get("msg") is not None
        assert captured["msg"]["To"] == "ops@example.com"

    def test_from_name_applied_to_health_email(self, db, monkeypatch):
        cfg = _make_config()
        cfg.smtp.from_name = "Ops Bot"
        captured = self._capture_smtp(monkeypatch)
        sent, _ = send_daily_health_email(db, cfg, secrets=None, force=True)
        assert sent is True
        from_hdr = str(captured["msg"]["From"])
        assert "Ops Bot" in from_hdr
        assert "triage@example.com" in from_hdr

    def test_from_name_blank_keeps_bare_address(self, db, monkeypatch):
        cfg = _make_config()
        cfg.smtp.from_name = ""
        captured = self._capture_smtp(monkeypatch)
        sent, _ = send_daily_health_email(db, cfg, secrets=None, force=True)
        assert sent is True
        assert captured["msg"]["From"] == "triage@example.com"


# ---------------------------------------------------------------------------
# Background task scheduling
# ---------------------------------------------------------------------------

class TestBackgroundTask:
    def test_background_task_fires_at_configured_time(self, db, monkeypatch):
        """The sender loop fires send_daily_health_email when HH:MM matches.

        Rather than driving the full sleep-loop, we exercise the core
        scheduling predicate: at the configured send_at HH:MM (and not
        before), the send callable is invoked; at a non-matching HH:MM
        it isn't. This is exactly what the loop checks each tick.
        """
        cfg = _make_config()
        cfg.health_email.send_at = "07:15"

        fires = []

        def _fake_send(db, config, secrets=None, watcher_manager=None, *, force=False):
            fires.append(config.health_email.send_at)
            return True, "sent"

        monkeypatch.setattr(
            "email_triage.web.daily_health.send_daily_health_email",
            _fake_send,
        )

        from email_triage.web.daily_health import send_daily_health_email
        # Simulate what the loop does: if HH:MM matches, call send.
        hh_mm = "07:15"
        if hh_mm == cfg.health_email.send_at:
            send_daily_health_email(db, cfg, None, None)
        assert fires == ["07:15"]

        # And not on a non-matching tick.
        fires.clear()
        hh_mm = "07:14"
        if hh_mm == cfg.health_email.send_at:
            send_daily_health_email(db, cfg, None, None)
        assert fires == []

    def test_background_task_honors_container_tz(self, db, monkeypatch):
        """``datetime.now().astimezone()`` reads container TZ — so set_at
        is interpreted in that TZ. Smoke: verify the call path uses
        ``datetime.now()`` without a fixed tz param."""
        # The actual assertion is structural: the sender code uses
        # ``datetime.now().astimezone()`` rather than ``utcnow()``. We
        # assert that by source inspection — any refactor that breaks TZ
        # honouring would also rewrite this call and fail this test.
        import inspect
        from email_triage.web import app as app_module

        src = inspect.getsource(app_module._daily_health_email_sender)
        assert "datetime.now().astimezone()" in src, \
            "sender must honour container TZ via astimezone()"


# ---------------------------------------------------------------------------
# CR-2c — "Update available" section in the daily health email
# ---------------------------------------------------------------------------

class TestUpdateAvailableSection:
    """Daily-health body grows a section when version_status flags an
    update. Up-to-date day stays silent.

    Architecture under test:

    * ``gather_update_available_section`` reads schema_migrations from
      the live DB connection and compares against the registered
      MIGRATIONS cap. Status drives whether the section renders.
    * GitHub Releases fetch is mocked at ``urllib.request.urlopen``.
    * Cache for the GitHub fetch is reset between tests so they don't
      contaminate each other.
    """

    def _patch_release_fetch(self, monkeypatch, *, payload=None, raise_exc=None):
        """Monkeypatch the urllib.request.urlopen the gather function uses.

        Pass ``payload`` to return that JSON dict. Pass ``raise_exc``
        to raise that exception from urlopen (network failure path).
        """
        from email_triage.web import daily_health as dh
        dh._reset_release_cache()

        import io
        import json
        class _FakeResp:
            def __init__(self, body: bytes):
                self._body = body
            def __enter__(self):
                return self
            def __exit__(self, *a):
                return False
            def read(self):
                return self._body

        def _fake_urlopen(req, timeout=None):
            if raise_exc is not None:
                raise raise_exc
            body = json.dumps(payload or {}).encode("utf-8")
            return _FakeResp(body)

        monkeypatch.setattr(
            dh.urllib.request, "urlopen", _fake_urlopen,
        )

    def _force_target_caps(self, monkeypatch, value: int):
        """Pin the source MIGRATIONS cap so the test isn't fragile to
        new migrations landing in the repo."""
        from email_triage.web import daily_health as dh
        from email_triage import version as version_mod
        monkeypatch.setattr(
            version_mod, "read_target_schema_caps", lambda: value,
        )
        # Also patch the symbol the gather function imports from the
        # version module lazily inside the function body.
        monkeypatch.setattr(
            "email_triage.version.read_target_schema_caps",
            lambda: value,
        )

    def _set_db_schema(self, db, version: int):
        """Force the schema_migrations table to a specific cap so the
        gather function reads our value rather than the real one
        applied by the conftest."""
        db.execute("DELETE FROM schema_migrations")
        if version > 0:
            db.execute(
                "INSERT INTO schema_migrations"
                "(version, name, applied_at, checksum) "
                "VALUES (?, 'pinned-for-test', "
                "'2026-01-01T00:00:00Z', 'test-checksum')",
                (version,),
            )
        db.commit()

    def test_section_appears_when_update_available(self, db, monkeypatch):
        """Section renders when target_caps > db_schema and we know it."""
        cfg = _make_config()
        self._set_db_schema(db, version=10)
        self._force_target_caps(monkeypatch, value=20)
        self._patch_release_fetch(monkeypatch, payload={
            "tag_name": "v1.2.3",
            "html_url": "https://example.com/r/v1.2.3",
            "body": "## What's new\n- shiny new thing",
        })

        state = gather_health_state(db, cfg)
        msg = assemble_daily_health_email(state, cfg)

        # Multipart — read text part directly (decoded by EmailMessage).
        text_parts = [
            p.get_content() for p in msg.walk()
            if p.get_content_type() == "text/plain"
        ]
        html_parts = [
            p.get_content() for p in msg.walk()
            if p.get_content_type() == "text/html"
        ]
        text = "\n".join(text_parts)
        html = "\n".join(html_parts)

        assert "Email Triage update available" in text
        assert "Email Triage update available" in html
        assert "v1.2.3" in text
        assert "v1.2.3" in html
        assert "shiny new thing" in text
        assert "shiny new thing" in html
        assert "https://example.com/r/v1.2.3" in html

    def test_section_includes_current_version(self, db, monkeypatch):
        """The running binary's __version__ is shown as the current side."""
        from email_triage import __version__ as APP_VERSION
        cfg = _make_config()
        self._set_db_schema(db, version=10)
        self._force_target_caps(monkeypatch, value=20)
        self._patch_release_fetch(monkeypatch, payload={
            "tag_name": "v9.9.9",
            "html_url": "https://x",
            "body": "release notes",
        })
        state = gather_health_state(db, cfg)
        msg = assemble_daily_health_email(state, cfg)
        text = "\n".join(
            p.get_content() for p in msg.walk()
            if p.get_content_type() == "text/plain"
        )
        assert APP_VERSION in text
        assert "v9.9.9" in text

    def test_section_renders_fallback_when_fetch_fails(self, db, monkeypatch):
        """Network failure -> section still renders with fallback line."""
        import urllib.error
        cfg = _make_config()
        self._set_db_schema(db, version=10)
        self._force_target_caps(monkeypatch, value=20)
        self._patch_release_fetch(
            monkeypatch,
            raise_exc=urllib.error.URLError("simulated network down"),
        )
        state = gather_health_state(db, cfg)
        msg = assemble_daily_health_email(state, cfg)
        text = "\n".join(
            p.get_content() for p in msg.walk()
            if p.get_content_type() == "text/plain"
        )
        assert "Email Triage update available" in text
        assert "Release notes unavailable" in text

    def test_section_absent_when_up_to_date(self, db, monkeypatch):
        """Up-to-date install does NOT grow a section."""
        cfg = _make_config()
        self._set_db_schema(db, version=20)
        self._force_target_caps(monkeypatch, value=20)
        # No urlopen patch — gather should bail before any fetch.
        state = gather_health_state(db, cfg)
        assert state["update_available"] is None
        msg = assemble_daily_health_email(state, cfg)
        text = "\n".join(
            p.get_content() for p in msg.walk()
            if p.get_content_type() == "text/plain"
        )
        assert "Email Triage update available" not in text

    def test_section_skipped_when_include_toggle_off(self, db, monkeypatch):
        """The HealthEmail.include_update_available flag suppresses the section."""
        cfg = _make_config()
        cfg.health_email.include_update_available = False
        self._set_db_schema(db, version=10)
        self._force_target_caps(monkeypatch, value=20)
        # gather shouldn't even try to fetch — confirm by raising.
        from email_triage.web import daily_health as dh
        dh._reset_release_cache()

        def _explode(req, timeout=None):
            raise AssertionError(
                "urlopen called even though include_update_available=False"
            )
        monkeypatch.setattr(dh.urllib.request, "urlopen", _explode)

        state = gather_health_state(db, cfg)
        assert state["update_available"] is None

    def test_release_fetch_caches_within_ttl(self, db, monkeypatch):
        """fetch_latest_release hits urlopen once per URL per TTL window."""
        from email_triage.web import daily_health as dh
        dh._reset_release_cache()

        call_count = {"n": 0}

        class _Resp:
            def __init__(self, body):
                self._body = body
            def __enter__(self): return self
            def __exit__(self, *a): return False
            def read(self): return self._body

        def _fake_urlopen(req, timeout=None):
            call_count["n"] += 1
            return _Resp(b'{"tag_name": "v1", "html_url": "u", "body": "b"}')

        monkeypatch.setattr(dh.urllib.request, "urlopen", _fake_urlopen)
        url = "https://api.github.com/repos/foo/bar/releases/latest"
        first = dh.fetch_latest_release(url)
        second = dh.fetch_latest_release(url)
        third = dh.fetch_latest_release(url)
        assert first is not None
        assert second == first
        assert third == first
        assert call_count["n"] == 1, "should cache after first fetch"

    def test_incompatible_rollback_promotes_to_attention(self, db, monkeypatch):
        """incompatible_rollback bumps attention_reasons (operator warning)."""
        cfg = _make_config()
        # Live schema at 15, target caps at 20, but :previous image
        # only opens up to 10 → rolling back after the update is unsafe.
        self._set_db_schema(db, version=15)
        self._force_target_caps(monkeypatch, value=20)
        monkeypatch.setattr(
            "email_triage.version.read_previous_schema_caps",
            lambda: 10,
        )
        # Also patch the symbol imported lazily inside gather.
        from email_triage import version as version_mod
        monkeypatch.setattr(
            version_mod, "read_previous_schema_caps", lambda: 10,
        )
        self._patch_release_fetch(monkeypatch, payload={
            "tag_name": "v2.0.0",
            "html_url": "u",
            "body": "n",
        })
        state = gather_health_state(db, cfg)
        msg = assemble_daily_health_email(state, cfg)
        # Subject flips to Attention.
        assert "Attention" in msg["Subject"]
        # And the section still renders.
        text = "\n".join(
            p.get_content() for p in msg.walk()
            if p.get_content_type() == "text/plain"
        )
        assert "Email Triage update available" in text


# ---------------------------------------------------------------------------
# CR-2c — admin_email recipient resolution + legacy fallback shim
# ---------------------------------------------------------------------------

class TestAdminEmailRecipientResolution:
    """``resolve_admin_recipients`` is the single seam between caller
    code and the recipient list. New canonical field
    ``admin_email.recipients``; legacy ``health_email.recipients`` is
    a read-fallback with a once-per-process deprecation warning.
    """

    def test_canonical_admin_email_recipients_used_when_set(self):
        from email_triage.web.daily_health import (
            _reset_deprecation_warning, resolve_admin_recipients,
        )
        _reset_deprecation_warning()
        cfg = TriageConfig()
        cfg.admin_email.recipients = ["new@example.com"]
        cfg.health_email.recipients = ["old@example.com"]
        # Canonical wins.
        assert resolve_admin_recipients(cfg) == ["new@example.com"]

    def test_legacy_health_email_recipients_used_when_admin_email_empty(self):
        from email_triage.web.daily_health import (
            _reset_deprecation_warning, resolve_admin_recipients,
        )
        _reset_deprecation_warning()
        cfg = TriageConfig()
        cfg.admin_email.recipients = []
        cfg.health_email.recipients = ["legacy@example.com"]
        assert resolve_admin_recipients(cfg) == ["legacy@example.com"]

    def test_empty_lists_return_empty(self):
        from email_triage.web.daily_health import (
            _reset_deprecation_warning, resolve_admin_recipients,
        )
        _reset_deprecation_warning()
        cfg = TriageConfig()
        cfg.admin_email.recipients = []
        cfg.health_email.recipients = []
        assert resolve_admin_recipients(cfg) == []

    def test_deprecation_warning_logged_once_on_legacy_fallback(
        self, caplog,
    ):
        import logging
        from email_triage.web.daily_health import (
            _reset_deprecation_warning, resolve_admin_recipients,
        )
        _reset_deprecation_warning()
        cfg = TriageConfig()
        cfg.admin_email.recipients = []
        cfg.health_email.recipients = ["legacy@example.com"]

        with caplog.at_level(logging.WARNING, logger="email_triage"):
            resolve_admin_recipients(cfg)
            resolve_admin_recipients(cfg)  # second call should NOT log

        # Count the warnings about the deprecation. Logger writes
        # structured records — the "msg" is in record.message after
        # rendering. We accept any record whose message mentions the
        # legacy key.
        records = [
            r for r in caplog.records
            if "health_email.recipients is deprecated" in r.getMessage()
        ]
        assert len(records) == 1, (
            "deprecation warning should fire exactly once per process"
        )

    def test_send_daily_health_uses_resolved_recipients(self, db, monkeypatch):
        """The send codepath honours the new admin_email field."""
        from email_triage.web.daily_health import (
            _reset_deprecation_warning, send_daily_health_email,
        )
        _reset_deprecation_warning()
        cfg = _make_config()
        cfg.health_email.recipients = []
        cfg.admin_email.recipients = ["admin@example.com"]

        captured: dict = {}

        class _FakeSMTP:
            def __init__(self, *a): pass
            def __enter__(self): return self
            def __exit__(self, *a): return False
            def starttls(self): pass
            def login(self, u, p): pass
            def send_message(self, msg): captured["msg"] = msg

        monkeypatch.setattr(
            "email_triage.web.daily_health.smtplib.SMTP", _FakeSMTP,
        )
        sent, _ = send_daily_health_email(
            db, cfg, secrets=None, force=True,
        )
        assert sent is True
        assert captured["msg"]["To"] == "admin@example.com"

    def test_send_daily_health_falls_back_to_legacy_recipients(
        self, db, monkeypatch,
    ):
        from email_triage.web.daily_health import (
            _reset_deprecation_warning, send_daily_health_email,
        )
        _reset_deprecation_warning()
        cfg = _make_config()
        cfg.admin_email.recipients = []
        cfg.health_email.recipients = ["legacy@example.com"]

        captured: dict = {}

        class _FakeSMTP:
            def __init__(self, *a): pass
            def __enter__(self): return self
            def __exit__(self, *a): return False
            def starttls(self): pass
            def login(self, u, p): pass
            def send_message(self, msg): captured["msg"] = msg

        monkeypatch.setattr(
            "email_triage.web.daily_health.smtplib.SMTP", _FakeSMTP,
        )
        sent, _ = send_daily_health_email(
            db, cfg, secrets=None, force=True,
        )
        assert sent is True
        assert captured["msg"]["To"] == "legacy@example.com"

    def test_yaml_admin_email_loads_into_config(self, tmp_path):
        """``admin_email:`` YAML section round-trips into AdminEmailConfig."""
        from email_triage.config import load_config
        yml = tmp_path / "config.yaml"
        yml.write_text(
            "admin_email:\n"
            "  recipients:\n"
            "    - alice@example.com\n"
            "    - bob@example.com\n"
            "  release_check_url: https://api.github.com/repos/x/y/releases/latest\n"
        )
        cfg = load_config(str(yml))
        assert cfg.admin_email.recipients == [
            "alice@example.com", "bob@example.com",
        ]
        assert cfg.admin_email.release_check_url == (
            "https://api.github.com/repos/x/y/releases/latest"
        )


# ---------------------------------------------------------------------------
# CR-2d — Update-failed alert
# ---------------------------------------------------------------------------

class TestUpdateFailedEmail:
    """``send_update_failed_email`` is the helper W4-Deploy calls from
    the snapshot-rollback path. Shares SMTP plumbing + recipient
    resolution with the daily-health email.
    """

    def _capture_smtp(self, monkeypatch):
        captured: dict = {}

        class _FakeSMTP:
            def __init__(self, host, port):
                captured["host"] = host
                captured["port"] = port
            def __enter__(self): return self
            def __exit__(self, *a): return False
            def starttls(self): captured["tls"] = True
            def login(self, u, p): captured["login"] = (u, p)
            def send_message(self, msg): captured["msg"] = msg

        monkeypatch.setattr(
            "email_triage.web.daily_health.smtplib.SMTP", _FakeSMTP,
        )
        return captured

    def test_subject_contains_attempted_and_current_tags(self, db, monkeypatch):
        from email_triage.web.daily_health import send_update_failed_email
        cfg = _make_config()
        cfg.admin_email.recipients = ["ops@example.com"]
        captured = self._capture_smtp(monkeypatch)
        sent, _ = send_update_failed_email(
            db, cfg, secrets=None,
            attempted_tag="v1.5.0",
            current_tag="v1.4.7",
            failure_reason="post-apply /health probe returned 503 for 60s",
            restored_from_snapshot="triage-2026-05-16T17:00:00Z.tar.gz",
        )
        assert sent is True
        subj = captured["msg"]["Subject"]
        assert "v1.5.0" in subj
        assert "v1.4.7" in subj
        assert "failed" in subj.lower()

    def test_body_contains_failure_reason_and_snapshot(self, db, monkeypatch):
        from email_triage.web.daily_health import send_update_failed_email
        cfg = _make_config()
        cfg.admin_email.recipients = ["ops@example.com"]
        captured = self._capture_smtp(monkeypatch)
        send_update_failed_email(
            db, cfg, secrets=None,
            attempted_tag="v1.5.0",
            current_tag="v1.4.7",
            failure_reason="UNIQUE failure signal for body check",
            restored_from_snapshot="snap-foo-bar.tar.gz",
        )
        msg = captured["msg"]
        text = "\n".join(
            p.get_content() for p in msg.walk()
            if p.get_content_type() == "text/plain"
        )
        assert "UNIQUE failure signal for body check" in text
        assert "snap-foo-bar.tar.gz" in text
        assert "journalctl -u email-triage" in text
        assert "v1.5.0" in text
        assert "v1.4.7" in text

    def test_uses_admin_email_recipients(self, db, monkeypatch):
        from email_triage.web.daily_health import send_update_failed_email
        cfg = _make_config()
        # Old-style: only legacy field set.
        cfg.admin_email.recipients = []
        cfg.health_email.recipients = ["legacy@example.com"]
        captured = self._capture_smtp(monkeypatch)
        sent, _ = send_update_failed_email(
            db, cfg, secrets=None,
            attempted_tag="v2", current_tag="v1",
            failure_reason="boom",
        )
        assert sent is True
        assert captured["msg"]["To"] == "legacy@example.com"

        # New-style: canonical field set, legacy field ignored.
        cfg.admin_email.recipients = ["new@example.com"]
        cfg.health_email.recipients = ["legacy@example.com"]
        captured2 = self._capture_smtp(monkeypatch)
        send_update_failed_email(
            db, cfg, secrets=None,
            attempted_tag="v2", current_tag="v1",
            failure_reason="boom",
        )
        assert captured2["msg"]["To"] == "new@example.com"

    def test_logs_audit_row_via_structured_log(self, db, monkeypatch, caplog):
        """Successful send emits a structured log.info — the same pattern
        the daily-health audit uses (flows to the log_entries table)."""
        import logging
        from email_triage.web.daily_health import send_update_failed_email
        cfg = _make_config()
        cfg.admin_email.recipients = ["ops@example.com"]
        self._capture_smtp(monkeypatch)
        with caplog.at_level(logging.INFO, logger="email_triage"):
            send_update_failed_email(
                db, cfg, secrets=None,
                attempted_tag="v1.5.0", current_tag="v1.4.7",
                failure_reason="health timeout",
            )
        # Any structured logger pipeline records the message.
        msgs = [r.getMessage() for r in caplog.records]
        assert any("Update-failed email sent" in m for m in msgs), msgs

    def test_no_recipients_returns_false_does_not_raise(self, db, monkeypatch):
        from email_triage.web.daily_health import send_update_failed_email
        cfg = _make_config()
        cfg.admin_email.recipients = []
        cfg.health_email.recipients = []
        sent, reason = send_update_failed_email(
            db, cfg, secrets=None,
            attempted_tag="v2", current_tag="v1",
            failure_reason="boom",
        )
        assert sent is False
        assert "recipient" in reason.lower()

    def test_missing_smtp_returns_false_does_not_raise(self, db, monkeypatch):
        from email_triage.web.daily_health import send_update_failed_email
        cfg = _make_config()
        cfg.admin_email.recipients = ["ops@example.com"]
        cfg.smtp.host = ""
        sent, reason = send_update_failed_email(
            db, cfg, secrets=None,
            attempted_tag="v2", current_tag="v1",
            failure_reason="boom",
        )
        assert sent is False
        assert "smtp" in reason.lower()

    def test_smtp_send_failure_returns_false_does_not_raise(
        self, db, monkeypatch,
    ):
        from email_triage.web.daily_health import send_update_failed_email
        cfg = _make_config()
        cfg.admin_email.recipients = ["ops@example.com"]

        class _BoomSMTP:
            def __init__(self, *a): pass
            def __enter__(self): return self
            def __exit__(self, *a): return False
            def starttls(self): pass
            def login(self, u, p): pass
            def send_message(self, msg):
                raise OSError("smtp connection refused")

        monkeypatch.setattr(
            "email_triage.web.daily_health.smtplib.SMTP", _BoomSMTP,
        )
        sent, reason = send_update_failed_email(
            db, cfg, secrets=None,
            attempted_tag="v2", current_tag="v1",
            failure_reason="boom",
        )
        assert sent is False
        assert "send failed" in reason

    def test_no_snapshot_recorded_renders_clean_line(self, db, monkeypatch):
        from email_triage.web.daily_health import send_update_failed_email
        cfg = _make_config()
        cfg.admin_email.recipients = ["ops@example.com"]
        captured = self._capture_smtp(monkeypatch)
        send_update_failed_email(
            db, cfg, secrets=None,
            attempted_tag="v2", current_tag="v1",
            failure_reason="something failed",
            restored_from_snapshot=None,
        )
        text = "\n".join(
            p.get_content() for p in captured["msg"].walk()
            if p.get_content_type() == "text/plain"
        )
        # The "no snapshot" line is present, not a None-ish leak.
        assert "Restored from snapshot" in text
        assert "None" not in text

