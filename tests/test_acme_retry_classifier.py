"""Tests for ACME retry classification + backoff curves (#77)."""

import pytest


from email_triage.web.acme_renewer import (
    _classify_acme_error,
    _retry_delay_secs,
)


# ---------------------------------------------------------------------------
# Backoff curves
# ---------------------------------------------------------------------------

class TestRetryDelaySecs:
    def test_fixed_returns_configured(self):
        for attempt in range(1, 6):
            assert _retry_delay_secs(
                attempt=attempt, backoff="fixed", configured_secs=60,
            ) == 60

    def test_exponential_first_retries_fast(self):
        assert _retry_delay_secs(
            attempt=1, backoff="exponential", configured_secs=600,
        ) == 15
        assert _retry_delay_secs(
            attempt=2, backoff="exponential", configured_secs=600,
        ) == 30
        assert _retry_delay_secs(
            attempt=3, backoff="exponential", configured_secs=600,
        ) == 60

    def test_exponential_capped_at_configured(self):
        # Configured 60s; sequence wants 120 by attempt 4 -> capped at 60.
        assert _retry_delay_secs(
            attempt=4, backoff="exponential", configured_secs=60,
        ) == 60

    def test_fibonacci_curve(self):
        # 15, 30, 45, 75, 120
        assert _retry_delay_secs(
            attempt=1, backoff="fibonacci", configured_secs=600,
        ) == 15
        assert _retry_delay_secs(
            attempt=2, backoff="fibonacci", configured_secs=600,
        ) == 30
        assert _retry_delay_secs(
            attempt=3, backoff="fibonacci", configured_secs=600,
        ) == 45
        assert _retry_delay_secs(
            attempt=4, backoff="fibonacci", configured_secs=600,
        ) == 75

    def test_unknown_backoff_falls_back_to_exponential(self):
        assert _retry_delay_secs(
            attempt=1, backoff="bogus", configured_secs=600,
        ) == 15

    def test_attempt_clamped_to_sequence_length(self):
        # Attempt 100 returns the last entry of the sequence (capped
        # at configured_secs). Doesn't IndexError.
        delay = _retry_delay_secs(
            attempt=100, backoff="exponential", configured_secs=600,
        )
        assert delay == 600


# ---------------------------------------------------------------------------
# Error classifier
# ---------------------------------------------------------------------------

class _FakeAcmeError(Exception):
    """Stand-in for acme.messages.Error -- carries a .typ attribute."""
    def __init__(self, typ: str, detail: str = ""):
        super().__init__(detail or typ)
        self.typ = typ


class _FakeChallenge:
    def __init__(self, typ: str | None = None):
        self.error = _FakeAcmeError(typ) if typ else None


class _FakeAuthzBody:
    def __init__(self, challenges):
        self.challenges = challenges


class _FakeAuthzr:
    def __init__(self, challenges):
        self.body = _FakeAuthzBody(challenges)


class _FakeValidationError(Exception):
    """Stand-in for acme.errors.ValidationError -- carries
    .failed_authzrs."""
    def __init__(self, failed_authzrs):
        super().__init__("validation failed")
        self.failed_authzrs = failed_authzrs


class TestClassifyAcmeError:
    def _run_with_fake_acme(self, exc, typ_class=None, monkeypatch=None):
        """Run _classify_acme_error with a monkeypatched acme.messages
        so the isinstance check on the real Error type works against
        our fake."""
        import sys
        import types
        fake_messages = types.ModuleType("acme.messages")
        fake_messages.Error = typ_class or _FakeAcmeError
        fake_acme = types.ModuleType("acme")
        fake_acme.messages = fake_messages
        # If the real `acme` is already imported (likely), keep it but
        # override the messages attribute so isinstance check matches
        # _FakeAcmeError instances. Cleaner approach: monkeypatch.setitem.
        if monkeypatch:
            monkeypatch.setitem(
                sys.modules, "acme.messages", fake_messages,
            )
        return _classify_acme_error(exc)

    def test_caa_is_permanent(self, monkeypatch):
        err = _FakeAcmeError("urn:ietf:params:acme:error:caa")
        kind, typ = self._run_with_fake_acme(
            err, typ_class=_FakeAcmeError, monkeypatch=monkeypatch,
        )
        assert kind == "permanent"
        assert typ == "urn:ietf:params:acme:error:caa"

    def test_rate_limited_is_rate_limited(self, monkeypatch):
        err = _FakeAcmeError("urn:ietf:params:acme:error:rateLimited")
        kind, typ = self._run_with_fake_acme(
            err, typ_class=_FakeAcmeError, monkeypatch=monkeypatch,
        )
        assert kind == "rate_limited"
        assert typ == "urn:ietf:params:acme:error:rateLimited"

    def test_unknown_typ_is_transient(self, monkeypatch):
        err = _FakeAcmeError("urn:ietf:params:acme:error:dns")
        kind, _ = self._run_with_fake_acme(
            err, typ_class=_FakeAcmeError, monkeypatch=monkeypatch,
        )
        assert kind == "transient"

    def test_validation_error_with_caa_subError_is_permanent(
        self, monkeypatch,
    ):
        ve = _FakeValidationError([
            _FakeAuthzr([_FakeChallenge(
                "urn:ietf:params:acme:error:caa",
            )]),
        ])
        kind, typ = self._run_with_fake_acme(
            ve, typ_class=_FakeAcmeError, monkeypatch=monkeypatch,
        )
        assert kind == "permanent"
        assert typ == "urn:ietf:params:acme:error:caa"

    def test_rate_limit_takes_precedence_over_permanent(
        self, monkeypatch,
    ):
        """When both rate-limit + permanent appear in sub-errors,
        rate-limit wins (it's the more actionable signal -- the
        operator needs to wait, not fix CAA)."""
        ve = _FakeValidationError([
            _FakeAuthzr([_FakeChallenge(
                "urn:ietf:params:acme:error:caa",
            )]),
            _FakeAuthzr([_FakeChallenge(
                "urn:ietf:params:acme:error:rateLimited",
            )]),
        ])
        kind, _ = self._run_with_fake_acme(
            ve, typ_class=_FakeAcmeError, monkeypatch=monkeypatch,
        )
        assert kind == "rate_limited"

    def test_no_typ_is_transient(self, monkeypatch):
        kind, typ = self._run_with_fake_acme(
            Exception("bare network failure"),
            typ_class=_FakeAcmeError, monkeypatch=monkeypatch,
        )
        assert kind == "transient"
        assert typ is None
