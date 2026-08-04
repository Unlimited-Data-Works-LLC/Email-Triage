"""N-314 R30 unit tests — tranche  batch B fix-forwards.

Two DA + HIPAA-SME panel recommendations landed together:

**Part 1 — `is_admin` fail-closed on falsy user (N-222c tranche 
batch B recommendation)**. Both SMEs (post-hoc VERIFIED) called
`is_admin(user)` STRICTER-fail-closed than the pre-migration
`user.get("role") == "admin"` branch. Assert the invariants
explicitly so a future contributor doesn't silently open the gate:
None user, empty dict, missing role key, non-str role, empty-str
role — all False. Only `role == "admin"` (case-sensitive, exact) is
True. §164.312(a)(1) access control.

**Part 2 — `_apply_standard_pragmas` execution order (N-214/N-214b
tranche  batch B recommendation)**. DA + HIPAA-SME both called
that the SQLCipher `PRAGMA key = "..."` MUST fire FIRST on the
encrypted connection; the SSOT helper runs AFTER. This test uses a
mock conn to assert that the helper emits exactly the 4 PRAGMAs the
SSOT owns (`journal_mode=WAL`, `busy_timeout=30000`,
`foreign_keys=ON`, `wal_autocheckpoint=0`) in a stable order — pins
ORDER, not just presence, per DA's specific ask.
§164.312(a)(2)(iv) encryption equivalent-measure.

2026-07-19 N-432 walresetbug drive fold: added
`PRAGMA wal_autocheckpoint = 0` (SQLite < 3.51.3 exposure P0).
Count expectation moved 3 → 4; order pin (journal_mode before
foreign_keys) preserved; wal_autocheckpoint MUST land AFTER
foreign_keys so the WAL journal is already the active mode when
auto-checkpoint is disabled.
"""
from __future__ import annotations

import pytest

# ----- Part 1: is_admin fail-closed -----------------------------------------


def test_is_admin_none_user_fails_closed():
    from email_triage.web.dependencies import is_admin
    assert is_admin(None) is False, (
        "N-314 R30: is_admin(None) MUST fail closed."
    )


def test_is_admin_empty_dict_fails_closed():
    from email_triage.web.dependencies import is_admin
    assert is_admin({}) is False


def test_is_admin_missing_role_key_fails_closed():
    from email_triage.web.dependencies import is_admin
    assert is_admin({"id": 1, "email": "a@b"}) is False


def test_is_admin_non_str_role_fails_closed():
    from email_triage.web.dependencies import is_admin
    assert is_admin({"role": None}) is False
    assert is_admin({"role": 0}) is False
    assert is_admin({"role": True}) is False, (
        "N-314 R30: role must be `isinstance(str)`; a truthy non-str "
        "MUST fail closed."
    )
    assert is_admin({"role": ["admin"]}) is False


def test_is_admin_empty_str_role_fails_closed():
    from email_triage.web.dependencies import is_admin
    assert is_admin({"role": ""}) is False


def test_is_admin_case_variant_fails_closed():
    from email_triage.web.dependencies import is_admin
    # Case-sensitive per commit body.
    assert is_admin({"role": "Admin"}) is False
    assert is_admin({"role": "ADMIN"}) is False
    assert is_admin({"role": "admin "}) is False, (
        "N-314 R30: trailing whitespace MUST fail closed (no strip)."
    )


def test_is_admin_exact_admin_returns_true():
    from email_triage.web.dependencies import is_admin
    assert is_admin({"role": "admin"}) is True


# ----- Part 2: _apply_standard_pragmas ORDER --------------------------------


def test_apply_standard_pragmas_execution_order():
    """DA + HIPAA-SME panel recommendation: pin the ORDER of the 3
    PRAGMAs the SSOT owns. A refactor that reorders them (e.g. moves
    `foreign_keys=ON` before `journal_mode=WAL`) could subtly break
    the plaintext-vs-encrypted contract; asserting order prevents
    that silent drift.
    """
    from email_triage.db._engine import _apply_standard_pragmas

    executed: list[str] = []

    class MockConn:
        def execute(self, sql: str, *args, **kwargs) -> "MockConn":
            executed.append(sql)
            return self

    _apply_standard_pragmas(MockConn())

    assert len(executed) == 4, (
        f"N-314 R30: _apply_standard_pragmas MUST emit exactly 4 "
        f"PRAGMAs (journal_mode, busy_timeout, foreign_keys, "
        f"wal_autocheckpoint per N-432 walresetbug P0); "
        f"got {len(executed)}: {executed}"
    )
    joined = " | ".join(executed).lower()
    # Assert all four PRAGMAs present (any spellings, e.g.
    # `journal_mode = wal` vs `journal_mode=WAL`, whitespace-agnostic).
    assert "journal_mode" in joined
    assert "busy_timeout" in joined
    assert "foreign_keys" in joined
    assert "wal_autocheckpoint" in joined, (
        "N-314 R30 + N-432 walresetbug P0: `PRAGMA wal_autocheckpoint = 0` "
        "MUST fire in the SSOT. Removing it re-exposes the WAL-checkpoint "
        "race on SQLite < 3.51.3."
    )

    # Order: journal_mode SHOULD land before foreign_keys so a
    # migration that toggles foreign_keys during its own body has a
    # stable WAL journal to write into first.
    j_idx = next(
        i for i, sql in enumerate(executed)
        if "journal_mode" in sql.lower()
    )
    f_idx = next(
        i for i, sql in enumerate(executed)
        if "foreign_keys" in sql.lower()
    )
    w_idx = next(
        i for i, sql in enumerate(executed)
        if "wal_autocheckpoint" in sql.lower()
    )
    assert j_idx < f_idx, (
        "N-314 R30: journal_mode PRAGMA MUST land before foreign_keys "
        f"so migrations have a stable WAL journal; got order {executed}"
    )
    assert f_idx < w_idx, (
        "N-432 walresetbug P0: `wal_autocheckpoint = 0` MUST land AFTER "
        "the WAL journal + foreign_keys pragmas so the WAL journal is "
        f"active when auto-checkpoint is disabled; got order {executed}"
    )
