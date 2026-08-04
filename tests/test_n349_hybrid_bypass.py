"""N-349 hybrid mode — `get_or_mint_secret` bypass_check + bypass_clear semantics.

Operator directive 2026-07-05: fail-CLOSED default + CLI-only one-shot
bypass. Env-flag DELIBERATELY not supported. This test covers the SSOT
contract; the CLI verb + DB helpers are tested separately.
"""
from __future__ import annotations

import pytest

from email_triage.secrets import (
    SecretsDecryptError,
    SecretsProvider,
    get_or_mint_secret,
)


class _FakeProvider(SecretsProvider):
    """Minimal SecretsProvider for unit tests. Configurable read behaviour."""

    def __init__(self, *, read_raises: bool = False, read_returns=None):
        self._read_raises = read_raises
        self._read_returns = read_returns
        self.set_calls: list[tuple[str, str]] = []

    def get(self, key: str) -> str | None:
        if self._read_raises:
            raise SecretsDecryptError(key)
        return self._read_returns

    def set(self, key: str, value: str) -> None:
        self.set_calls.append((key, value))

    # Unused abstract methods (SecretsProvider ABC has these).
    def require(self, key: str) -> str:
        v = self.get(key)
        if v is None:
            from email_triage.secrets import SecretNotFound
            raise SecretNotFound(key)
        return v

    def list_keys(self) -> list[str]:
        return []

    def delete(self, key: str) -> None:
        pass


def test_bypass_none_is_fail_closed_on_decrypt_error():
    """No bypass_check → SecretsDecryptError propagates (default)."""
    p = _FakeProvider(read_raises=True)
    with pytest.raises(SecretsDecryptError):
        get_or_mint_secret(p, "watch_hmac:1", lambda: "MINTED")
    assert p.set_calls == [], "must not mint when fail-closed fires"


def test_bypass_returns_false_is_fail_closed():
    """bypass_check returns False → still fail-closed."""
    p = _FakeProvider(read_raises=True)
    calls = {"check": 0, "clear": 0}

    def check() -> bool:
        calls["check"] += 1
        return False

    def clear() -> None:
        calls["clear"] += 1

    with pytest.raises(SecretsDecryptError):
        get_or_mint_secret(
            p, "watch_hmac:1", lambda: "MINTED",
            bypass_check=check,
            bypass_clear=clear,
        )
    assert calls["check"] == 1, "bypass_check called exactly once"
    assert calls["clear"] == 0, "bypass_clear NOT called on fail-closed"
    assert p.set_calls == [], "no mint on fail-closed"


def test_bypass_returns_true_consumes_and_mints():
    """bypass_check returns True → mint + call bypass_clear + return."""
    p = _FakeProvider(read_raises=True)
    calls = {"check": 0, "clear": 0, "mint": 0}

    def check() -> bool:
        calls["check"] += 1
        return True

    def clear() -> None:
        calls["clear"] += 1

    def mint_fn() -> str:
        calls["mint"] += 1
        return "MINTED_FRESH"

    result = get_or_mint_secret(
        p, "watch_hmac:1", mint_fn,
        bypass_check=check,
        bypass_clear=clear,
    )
    assert result == "MINTED_FRESH"
    assert calls["check"] == 1
    assert calls["clear"] == 1, "bypass_clear consumed exactly once"
    assert calls["mint"] == 1, "mint_fn called exactly once"
    assert p.set_calls == [("watch_hmac:1", "MINTED_FRESH")], "must persist the mint"


def test_bypass_not_called_on_readable_secret():
    """Existing secret present → bypass_check MUST NOT fire."""
    p = _FakeProvider(read_raises=False, read_returns="EXISTING")
    calls = {"check": 0, "clear": 0, "mint": 0}

    def check() -> bool:
        calls["check"] += 1
        return True  # would activate bypass, but shouldn't be called

    def clear() -> None:
        calls["clear"] += 1

    def mint_fn() -> str:
        calls["mint"] += 1
        return "SHOULD_NOT_MINT"

    result = get_or_mint_secret(
        p, "watch_hmac:1", mint_fn,
        bypass_check=check,
        bypass_clear=clear,
    )
    assert result == "EXISTING"
    assert calls == {"check": 0, "clear": 0, "mint": 0}
    assert p.set_calls == []


def test_bypass_not_called_on_absent_secret():
    """Absent secret (None) → straight mint path, bypass_check MUST NOT fire."""
    p = _FakeProvider(read_raises=False, read_returns=None)
    calls = {"check": 0, "clear": 0, "mint": 0}

    def check() -> bool:
        calls["check"] += 1
        return False

    def clear() -> None:
        calls["clear"] += 1

    def mint_fn() -> str:
        calls["mint"] += 1
        return "MINTED_ABSENT"

    result = get_or_mint_secret(
        p, "watch_hmac:1", mint_fn,
        bypass_check=check,
        bypass_clear=clear,
    )
    assert result == "MINTED_ABSENT"
    assert calls["check"] == 0, "bypass_check must NOT fire on absent (not decrypt error)"
    assert calls["clear"] == 0
    assert calls["mint"] == 1
    assert p.set_calls == [("watch_hmac:1", "MINTED_ABSENT")]


def test_bypass_clear_none_is_tolerated():
    """bypass_check=True + bypass_clear=None → still mints (clear is optional)."""
    p = _FakeProvider(read_raises=True)

    result = get_or_mint_secret(
        p, "watch_hmac:1", lambda: "MINTED",
        bypass_check=lambda: True,
        bypass_clear=None,  # explicit None
    )
    assert result == "MINTED"
    assert p.set_calls == [("watch_hmac:1", "MINTED")]


def test_bypass_mint_failure_preserves_flag():
    """SME panel 2026-07-05 F1 — mint_fn raising must NOT consume the
    flag (PD  set/clear symmetry). Reorder invariant: clear runs LAST
    so a mint failure leaves the operator's one-shot flag armed for the
    next attempt."""
    p = _FakeProvider(read_raises=True)
    calls = {"check": 0, "clear": 0, "mint": 0}

    def check() -> bool:
        calls["check"] += 1
        return True

    def clear() -> None:
        calls["clear"] += 1

    def mint_fn() -> str:
        calls["mint"] += 1
        raise RuntimeError("mint provider transiently down")

    with pytest.raises(RuntimeError, match="mint provider transiently down"):
        get_or_mint_secret(
            p, "watch_hmac:1", mint_fn,
            bypass_check=check,
            bypass_clear=clear,
        )
    assert calls["check"] == 1
    assert calls["mint"] == 1
    assert calls["clear"] == 0, "bypass_clear MUST NOT fire on mint failure"
    assert p.set_calls == [], "no partial mint persisted"


def test_bypass_set_failure_preserves_flag():
    """SME panel 2026-07-05 F1 — secrets.set() failure (read-only backend,
    quota, disk error) must NOT consume the flag either. Reorder invariant
    covers both mint AND set failure surfaces."""

    class _SetFailsProvider(_FakeProvider):
        def set(self, key: str, value: str) -> None:
            raise OSError("read-only backend")

    p = _SetFailsProvider(read_raises=True)
    calls = {"check": 0, "clear": 0, "mint": 0}

    def check() -> bool:
        calls["check"] += 1
        return True

    def clear() -> None:
        calls["clear"] += 1

    def mint_fn() -> str:
        calls["mint"] += 1
        return "WOULD_MINT"

    with pytest.raises(OSError, match="read-only backend"):
        get_or_mint_secret(
            p, "watch_hmac:1", mint_fn,
            bypass_check=check,
            bypass_clear=clear,
        )
    assert calls["mint"] == 1
    assert calls["clear"] == 0, "bypass_clear MUST NOT fire on secrets.set failure"
