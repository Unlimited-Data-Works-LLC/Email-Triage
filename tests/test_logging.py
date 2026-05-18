"""Tests for PHI-safe structured logging."""

import json
import logging

import pytest

from email_triage.config import LoggingConfig
from email_triage.triage_logging import (
    TriageLogger,
    get_logger,
    is_hipaa_mode,
    setup_logging,
)


class TestHipaaMode:
    def test_default_is_not_hipaa(self):
        setup_logging(LoggingConfig(hipaa=False))
        assert is_hipaa_mode() is False

    def test_hipaa_mode_enables(self):
        setup_logging(LoggingConfig(hipaa=True))
        assert is_hipaa_mode() is True
        # Reset for other tests
        setup_logging(LoggingConfig(hipaa=False))


class TestAccountHipaaResolution:
    """is_account_hipaa resolves the effective state for a given account."""

    def _reset(self):
        from email_triage import triage_logging
        triage_logging._hipaa_mode = False

    def test_both_off(self):
        self._reset()
        from email_triage.triage_logging import is_account_hipaa
        acct = {"id": 1, "hipaa": 0, "created_under_system_hipaa": 0}
        assert is_account_hipaa(acct) is False

    def test_account_flag_on(self):
        self._reset()
        from email_triage.triage_logging import is_account_hipaa
        acct = {"id": 1, "hipaa": 1, "created_under_system_hipaa": 0}
        assert is_account_hipaa(acct) is True

    def test_system_flag_forces_on(self):
        self._reset()
        from email_triage import triage_logging
        from email_triage.triage_logging import is_account_hipaa
        triage_logging._hipaa_mode = True
        try:
            acct = {"id": 1, "hipaa": 0, "created_under_system_hipaa": 0}
            assert is_account_hipaa(acct) is True
        finally:
            self._reset()

    def test_missing_column_treated_as_off(self):
        self._reset()
        from email_triage.triage_logging import is_account_hipaa
        assert is_account_hipaa({"id": 1}) is False

    def test_none_account_returns_system_flag(self):
        self._reset()
        from email_triage.triage_logging import is_account_hipaa
        assert is_account_hipaa(None) is False
        from email_triage import triage_logging
        triage_logging._hipaa_mode = True
        try:
            assert is_account_hipaa(None) is True
        finally:
            self._reset()


class TestAccountHipaaLocked:
    """is_account_hipaa_locked: account can't be unflagged while system HIPAA is on
    AND it was created under system HIPAA."""

    def _reset(self):
        from email_triage import triage_logging
        triage_logging._hipaa_mode = False

    def test_not_locked_when_system_off(self):
        self._reset()
        from email_triage.triage_logging import is_account_hipaa_locked
        acct = {"id": 1, "hipaa": 1, "created_under_system_hipaa": 1}
        assert is_account_hipaa_locked(acct) is False

    def test_locked_when_system_on_and_created_under(self):
        self._reset()
        from email_triage import triage_logging
        from email_triage.triage_logging import is_account_hipaa_locked
        triage_logging._hipaa_mode = True
        try:
            acct = {"id": 1, "hipaa": 1, "created_under_system_hipaa": 1}
            assert is_account_hipaa_locked(acct) is True
        finally:
            self._reset()

    def test_not_locked_if_not_created_under_system(self):
        self._reset()
        from email_triage import triage_logging
        from email_triage.triage_logging import is_account_hipaa_locked
        triage_logging._hipaa_mode = True
        try:
            acct = {"id": 1, "hipaa": 1, "created_under_system_hipaa": 0}
            assert is_account_hipaa_locked(acct) is False
        finally:
            self._reset()


class TestTriageLoggerSanitisation:
    def test_standard_mode_passes_phi(self):
        setup_logging(LoggingConfig(hipaa=False))
        logger = get_logger("test")
        # In standard mode, _sanitise should pass through all keys.
        result = logger._sanitise({
            "sender": "alice@example.com",
            "subject": "Patient lab results",
            "flow_id": "f-123",
        })
        assert "sender" in result
        assert "subject" in result
        assert "flow_id" in result

    def test_hipaa_mode_strips_phi(self):
        setup_logging(LoggingConfig(hipaa=True))
        logger = get_logger("test")
        result = logger._sanitise({
            "sender": "alice@example.com",
            "subject": "Patient lab results",
            "reason": "Contains patient name",
            "flow_id": "f-123",
            "category": "to-respond",
        })
        assert "sender" not in result
        assert "subject" not in result
        assert "reason" not in result
        assert result["flow_id"] == "f-123"
        assert result["category"] == "to-respond"
        # Reset
        setup_logging(LoggingConfig(hipaa=False))

    def test_hipaa_strips_all_phi_keys(self):
        setup_logging(LoggingConfig(hipaa=True))
        logger = get_logger("test")
        phi_keys = {
            "sender": "x", "senders": "x", "recipients": "x",
            "subject": "x", "body": "x", "body_text": "x",
            "attachment": "x", "attachments": "x", "reason": "x",
            "classification_reason": "x", "headers": "x",
        }
        safe_keys = {"flow_id": "f-1", "status": "classified", "category": "fyi"}
        combined = {**phi_keys, **safe_keys}
        result = logger._sanitise(combined)
        for key in phi_keys:
            assert key not in result
        for key in safe_keys:
            assert key in result
        # Reset
        setup_logging(LoggingConfig(hipaa=False))


class TestLogOutput:
    def test_json_format(self, capfd):
        setup_logging(LoggingConfig(format="json", level="INFO", hipaa=False))
        logger = get_logger("test.json")
        logger.info("test message", flow_id="f-1")
        captured = capfd.readouterr()
        # JSON goes to stderr
        line = captured.err.strip().split("\n")[-1]
        data = json.loads(line)
        assert data["msg"] == "test message"
        assert data["flow_id"] == "f-1"
        assert "ts" in data

    def test_text_format(self, capfd):
        setup_logging(LoggingConfig(format="text", level="INFO", hipaa=False))
        logger = get_logger("test.text")
        logger.info("hello world", category="invoices")
        captured = capfd.readouterr()
        assert "hello world" in captured.err
        assert "category=invoices" in captured.err


class TestLocalTzFormatting:
    """Timestamps honour the local timezone (container TZ env var),
    not a hard-coded UTC. Deployments in America/Detroit should
    render EDT/EST times, not +00:00."""

    def test_text_formatter_honors_local_tz(self, monkeypatch):
        """Regression: _TextFormatter used ``datetime.now(timezone.utc)``
        so every line read as UTC regardless of container TZ. After
        the fix it uses ``datetime.now().astimezone()`` which picks up
        whatever the process TZ resolves to."""
        import logging as _logging
        import time as _time
        from email_triage.triage_logging import _TextFormatter

        # Force the process TZ. time.tzset() is POSIX-only; on Windows
        # we fall back to a manual offset check via astimezone().
        monkeypatch.setenv("TZ", "America/Detroit")
        if hasattr(_time, "tzset"):
            _time.tzset()

        formatter = _TextFormatter()
        record = _logging.LogRecord(
            name="x", level=_logging.INFO, pathname=__file__, lineno=1,
            msg="hi", args=(), exc_info=None,
        )
        line = formatter.format(record)

        if hasattr(_time, "tzset"):
            # POSIX: TZ env var is honoured, timestamp includes the
            # abbreviated zone name (EDT/EST) via %Z.
            assert ("EDT" in line) or ("EST" in line), (
                f"expected EDT/EST in log line, got: {line!r}"
            )
        else:
            # Windows: TZ env var isn't picked up the same way, but
            # the format string now ends with %Z — so the line should
            # at minimum not render as literal UTC, and should contain
            # some trailing zone/offset token. We assert the formatter
            # uses astimezone() (local) rather than a fixed UTC by
            # checking the trailing token isn't empty.
            parts = line.split()
            # parts: [date, time, zone, LEVEL, logger, msg...]
            assert len(parts) >= 3
            # The zone slot must be populated (non-empty) after %Z.
            assert parts[2].strip() != ""

    def test_json_formatter_honors_local_tz(self, monkeypatch):
        """_JsonFormatter likewise uses astimezone() — the ``ts``
        field must not be fixed UTC."""
        import json as _json
        import logging as _logging
        import time as _time
        from email_triage.triage_logging import _JsonFormatter

        monkeypatch.setenv("TZ", "America/Detroit")
        if hasattr(_time, "tzset"):
            _time.tzset()

        formatter = _JsonFormatter()
        record = _logging.LogRecord(
            name="x", level=_logging.INFO, pathname=__file__, lineno=1,
            msg="hi", args=(), exc_info=None,
        )
        data = _json.loads(formatter.format(record))

        if hasattr(_time, "tzset"):
            # America/Detroit is either -05:00 (EST) or -04:00 (EDT).
            # Never +00:00.
            assert "-04:00" in data["ts"] or "-05:00" in data["ts"], (
                f"expected -04:00/-05:00 in ts, got: {data['ts']!r}"
            )
        else:
            # Windows: at minimum the ts must carry some offset.
            assert data["ts"].endswith("Z") is False  # not bare UTC 'Z'
            # ISO 8601 with +HH:MM or -HH:MM offset at the end.
            assert data["ts"][-6] in ("+", "-") or data["ts"][-5] in ("+", "-")
