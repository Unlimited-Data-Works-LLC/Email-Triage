"""the backlog  REDESIGNED v3 Part 0 — the canonical N-151 SOFT-gate
predicate lives in ``providers._msal_cache_crypto``.  This test pins the
3-arm contract that ``n151_soft_gate_active`` + ``n151_soft_gate_reason``
must always answer with one probe of ``_get_master_key``:

  1. ``available``               — probe returns a key → active=False,
                                    reason="available".
  2. ``unavailable-typed-error`` — probe raises a class in
                                    ``_N151_UNAVAIL_TYPES`` → active=True,
                                    reason="unavailable".
  3. ``unavailable-other``       — probe raises an unexpected class →
                                    active=True (fail-CLOSED per
                                    Prime Directive #8), reason=
                                    "probe_error".

The predicate is the SSOT the  pattern-alert circuit-breaker + the
existing ``msal_master_key_status`` health block both probe — the reason
enum MUST stay coherent with ``_MSAL_MASTER_KEY_REASON_ENUM`` in
``web/routers/health.py:1232``.
"""
from __future__ import annotations

import pytest

from email_triage.providers import _msal_cache_crypto as mkc


@pytest.fixture(autouse=True)
def _reset_master_key_cache():
    """Clear the lru_cache before + after each arm so a prior arm's
    successful call can't leak a cached key into the next arm's probe."""
    mkc._reset_master_key_cache_for_tests()
    yield
    mkc._reset_master_key_cache_for_tests()


# ---------------------------------------------------------------------------
# Arm 1 — available
# ---------------------------------------------------------------------------

def test_n151_soft_gate_available(monkeypatch: pytest.MonkeyPatch) -> None:
    """A successful ``_get_master_key`` probe → gate NOT active +
    reason == "available"."""
    # A Fernet-shaped 32-byte urlsafe-b64 key stand-in; the predicate
    # only checks that the call RETURNS (doesn't inspect the bytes).
    monkeypatch.setattr(
        mkc, "_get_master_key",
        lambda: b"Ci-K1KJk-1-fernet-master-key-for-test=",
    )

    assert mkc.n151_soft_gate_active() is False
    assert mkc.n151_soft_gate_reason() == "available"


# ---------------------------------------------------------------------------
# Arm 2 — unavailable, typed (matches _N151_UNAVAIL_TYPES)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "exc_factory",
    [
        # Each class in the SSOT partition — the reason MUST be "unavailable"
        # for every one.  Uses the exact class NAMES the SSOT partitions
        # against (``FileNotFoundError`` / ``KeyError`` are builtins;
        # ``OperationalError`` is imported from sqlite3; the two custom
        # classes are inline stand-ins so this test doesn't depend on the
        # secrets-backend module tree, matching the class-name-string
        # partition design).
        pytest.param(
            lambda: FileNotFoundError("bootstrap master key path missing"),
            id="FileNotFoundError",
        ),
        pytest.param(
            lambda: KeyError("secrets.master_key_name"),
            id="KeyError",
        ),
        pytest.param(
            lambda: __import__("sqlite3").OperationalError("database is locked"),
            id="sqlite3.OperationalError",
        ),
        pytest.param(
            lambda: type("SecretsBackendError", (Exception,), {})(
                "backend unreachable",
            ),
            id="SecretsBackendError",
        ),
        pytest.param(
            lambda: type("BootstrapMasterKeyMissing", (Exception,), {})(
                "no bootstrap key configured",
            ),
            id="BootstrapMasterKeyMissing",
        ),
    ],
)
def test_n151_soft_gate_unavailable_typed(
    monkeypatch: pytest.MonkeyPatch, exc_factory,
) -> None:
    """Any ``_N151_UNAVAIL_TYPES`` class → gate ACTIVE + reason ==
    "unavailable"."""
    def _raise() -> bytes:
        raise exc_factory()
    monkeypatch.setattr(mkc, "_get_master_key", _raise)

    assert mkc.n151_soft_gate_active() is True
    assert mkc.n151_soft_gate_reason() == "unavailable"


# ---------------------------------------------------------------------------
# Arm 3 — unavailable, other (outside the SSOT partition)
# ---------------------------------------------------------------------------

def test_n151_soft_gate_unavailable_other(monkeypatch: pytest.MonkeyPatch) -> None:
    """An unexpected exception class (not in ``_N151_UNAVAIL_TYPES``) still
    flips the gate ACTIVE (fail-CLOSED per PD #8) but with reason ==
    "probe_error" so the monitoring system / the health block can partition transient
    vs. persistent at the same alert-severity slug."""
    def _raise() -> bytes:
        # RuntimeError is deliberately NOT in _N151_UNAVAIL_TYPES.
        raise RuntimeError("secrets driver died mid-read — unexpected shape")
    monkeypatch.setattr(mkc, "_get_master_key", _raise)

    assert mkc.n151_soft_gate_active() is True
    assert mkc.n151_soft_gate_reason() == "probe_error"


# ---------------------------------------------------------------------------
# Coherence with health.py enum
# ---------------------------------------------------------------------------

def test_n151_soft_gate_reason_enum_is_subset_of_health_enum() -> None:
    """The predicate's reachable reasons must be a subset of the health
    block's ``_MSAL_MASTER_KEY_REASON_ENUM`` (the SSOT owner).  This is
    the coherence pin — if the health enum shrinks in a future landing
    without a matching predicate update, this test surfaces the drift."""
    from email_triage.web.routers.health import _MSAL_MASTER_KEY_REASON_ENUM
    reachable_from_predicate = {"available", "unavailable", "probe_error"}
    assert reachable_from_predicate.issubset(_MSAL_MASTER_KEY_REASON_ENUM)


# ---------------------------------------------------------------------------
# DB-SME F1 — atomic single-probe accessor n151_soft_gate_state
# ---------------------------------------------------------------------------

def test_n151_soft_gate_state_atomic(monkeypatch: pytest.MonkeyPatch) -> None:
    """``n151_soft_gate_state()`` returns a coherent ``(active, reason)``
    tuple from ONE probe of ``_get_master_key`` — the SSOT accessor
    callers use to avoid dual-call torn reads on transitions."""
    monkeypatch.setattr(
        mkc, "_get_master_key",
        lambda: b"Ci-K1KJk-1-fernet-master-key-for-test=",
    )

    state = mkc.n151_soft_gate_state()
    assert state == (False, "available")
    # Coherence with the legacy singletons on the SAME (steady) monkeypatch:
    assert state[0] is mkc.n151_soft_gate_active()
    assert state[1] == mkc.n151_soft_gate_reason()


@pytest.mark.parametrize(
    "exc_factory,expected_reason",
    [
        pytest.param(
            lambda: FileNotFoundError("bootstrap master key path missing"),
            "unavailable",
            id="FileNotFoundError-unavailable",
        ),
        pytest.param(
            lambda: KeyError("secrets.master_key_name"),
            "unavailable",
            id="KeyError-unavailable",
        ),
        pytest.param(
            lambda: __import__("sqlite3").OperationalError("database is locked"),
            "unavailable",
            id="OperationalError-unavailable",
        ),
        pytest.param(
            lambda: type("SecretsBackendError", (Exception,), {})(
                "backend unreachable",
            ),
            "unavailable",
            id="SecretsBackendError-unavailable",
        ),
        pytest.param(
            lambda: type("BootstrapMasterKeyMissing", (Exception,), {})(
                "no bootstrap key configured",
            ),
            "unavailable",
            id="BootstrapMasterKeyMissing-unavailable",
        ),
    ],
)
def test_n151_soft_gate_state_coherent_across_unavail_types(
    monkeypatch: pytest.MonkeyPatch, exc_factory, expected_reason,
) -> None:
    """``n151_soft_gate_state()`` returns a coherent (active=True,
    reason="unavailable") tuple for EVERY class in ``_N151_UNAVAIL_TYPES``
    — the atomic accessor must partition identically to the dual-call
    accessors across the full SSOT class set."""
    def _raise() -> bytes:
        raise exc_factory()
    monkeypatch.setattr(mkc, "_get_master_key", _raise)

    active, reason = mkc.n151_soft_gate_state()
    assert active is True
    assert reason == expected_reason
    # And the atomic tuple matches the legacy singletons on the SAME
    # (steady) monkeypatch — the coherence contract.
    assert active is mkc.n151_soft_gate_active()
    assert reason == mkc.n151_soft_gate_reason()


def test_n151_soft_gate_state_probe_error_tail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An unexpected exception class (outside ``_N151_UNAVAIL_TYPES``)
    still fail-CLOSES the atomic accessor to (True, "probe_error"),
    matching the dual-call behaviour."""
    def _raise() -> bytes:
        raise RuntimeError("secrets driver died mid-read — unexpected shape")
    monkeypatch.setattr(mkc, "_get_master_key", _raise)

    state = mkc.n151_soft_gate_state()
    assert state == (True, "probe_error")
