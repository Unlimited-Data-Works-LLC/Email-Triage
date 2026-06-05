"""Shared test fixtures."""

from datetime import datetime, timezone

import pytest

import email_triage.triage_logging as _triage_logging
from email_triage.engine.models import (
    Classification,
    EmailMessage,
    FlowState,
    FlowStatus,
)
from email_triage.engine.store import FlowStore


@pytest.fixture(autouse=True)
def _provision_audit_chain_hmac_key_for_tests():
    """Autouse fixture — install a deterministic HMAC key + clear after each test.

    H-02a (Cycle 6, 2026-05-23) made the audit-chain hash D1-fail-closed
    per hipaa-sme-2 + DA-3 regulatory verdict: ``compute_log_row_hash``
    raises ``RuntimeError`` if no HMAC key is provisioned. Real
    deployments wire the registry via
    :func:`email_triage.secrets.wire_audit_chain_hmac_keys` at lifespan
    startup (web/app.py + CLI bootstrap), but every test that touches
    log_entries would otherwise need to opt-in explicitly.

    Per the consolidated H-02a verdict's "MITIGATION for test-infra
    cost" point: include an explicit test helper rather than letting
    the primitive fall back to SHA-256. This fixture is that explicit
    helper, applied autouse so existing test suites stay green without
    surgery on every fixture.

    Tests that need to verify the D1 fail-closed behavior itself
    (e.g., ``TestH02aFailClosed`` in test_log_chain.py) call
    ``_clear_hmac_keys_for_test()`` inside the test body and then
    expect a RuntimeError. The autouse fixture re-clears after every
    test so the next test sees a clean registry baseline.

    The 32-byte deterministic key is NOT used in production —
    real deployments derive their key via HKDF over a per-install
    random Fernet master. Determinism here is only for test isolation
    (two tests running back-to-back see the same chain key and could
    in principle assert on row-hash bytes if useful).
    """
    from email_triage.db.audit import (
        _clear_hmac_keys_for_test,
        _set_hmac_key_for_test,
    )
    # 32 bytes of "for-testing-only" — repeated label keeps the test
    # key easily identifiable in dumps if anyone greps for it.
    _TEST_HMAC_KEY = b"H-02a-test-key-32-bytes-32bytes!"
    assert len(_TEST_HMAC_KEY) == 32
    _set_hmac_key_for_test(_TEST_HMAC_KEY, version=0)
    try:
        yield
    finally:
        _clear_hmac_keys_for_test()


@pytest.fixture(autouse=True)
def _restore_hipaa_mode_around_each_test():
    """Autouse function-scope snapshot+restore of ``triage_logging._hipaa_mode``.

    Bundle E5  — channel-2 contamination closure. ``_hipaa_mode`` is a
    module-global mutated by tests that call
    ``setup_logging(LoggingConfig(hipaa=...))``, by tests that assign the
    attribute directly, and by handlers routed through
    ``_apply_runtime_settings`` with ``allow_hipaa_change=True``. Without
    a per-test save/restore, a test that mutates this leaks the value
    into the next test's baseline; the  caller-intent gate at
    ``web/routers/ui/_shared.py:5472`` SURFACES the leak by raising on
    a cross-test flip.

    Complementary to the ``setup_method`` hooks at
    ``tests/test_actions/test_actions.py:71`` (``TestNotifyAction``) and
    ``:274`` (``TestEscalateAction``): those guard against OUTSIDE
    contamination entering this class's tests; this fixture guards
    against INSIDE contamination leaking out. Both are needed.

    Mirrors the precedent at ``tests/test_web/conftest.py:56-81``
    (``_reset_app_state``, ``_drain_audit_writes_after_test``) — same
    shape: autouse function-scope snapshot+restore for module-global
    cleanup.
    """
    prior = _triage_logging._hipaa_mode
    try:
        yield
    finally:
        _triage_logging._hipaa_mode = prior


@pytest.fixture
def memory_store() -> FlowStore:
    """FlowStore backed by in-memory SQLite."""
    return FlowStore(":memory:")


@pytest.fixture
def sample_email() -> EmailMessage:
    return EmailMessage(
        message_id="msg-001",
        provider="gmail_api",
        sender="alice@example.com",
        recipients=["bob@example.com"],
        subject="Q3 budget review",
        body_text="Please review the attached budget spreadsheet.",
        date=datetime(2026, 4, 14, 10, 30, tzinfo=timezone.utc),
        labels=["INBOX"],
    )


@pytest.fixture
def sample_classification() -> Classification:
    return Classification(
        category="action-required",
        confidence=0.92,
        reason="Email requests a review action with deadline context.",
    )
