"""N-354 R31 — per-account artifact dispose failure-isolation.

Trust-repair fix-forward per PHASE2 tranche  DA + the backlog  (TASK ).

Two residual defects the original N-310 shape left open:
  (a) `p = builder(account_id)` was OUTSIDE the try/except — a raising
      builder skipped every sibling disposal + propagated an unwrapped
      exception.
  (b) `errors[1:]` were silently DROPPED from the raised OSError message —
      only the first error's path + type survived.

These teeth prove both are closed at HEAD.
"""
from __future__ import annotations

import logging
from pathlib import Path

import pytest

from email_triage.providers import _ondisk_artifacts as mod


class _FakePath:
    def __init__(self, name: str, exists_returns: bool = True,
                 unlink_raises: Exception | None = None):
        self._name = name
        self._exists = exists_returns
        self._unlink_raises = unlink_raises

    def exists(self) -> bool:
        return self._exists

    def unlink(self, missing_ok: bool = False) -> None:
        if self._unlink_raises is not None:
            raise self._unlink_raises

    def __str__(self) -> str:
        return f"/fake/{self._name}"


def _install_builders(monkeypatch, builders):
    monkeypatch.setattr(mod, "_BUILDERS", list(builders))


def test_a_raising_builder_isolation_call_tracker(monkeypatch):
    """Same as above but with explicit call counting to prove BOTH ok
    builders' `.unlink()` fired despite the bad builder in the middle."""
    calls: list[str] = []

    class _TrackedPath(_FakePath):
        def __init__(self, name: str):
            super().__init__(name, exists_returns=True)
            self._name = name

        def unlink(self, missing_ok: bool = False) -> None:
            calls.append(self._name)

    p_a = _TrackedPath("a.cache")
    p_b = _TrackedPath("b.cache")

    _install_builders(
        monkeypatch,
        [
            lambda aid: p_a,
            lambda aid: (_ for _ in ()).throw(RuntimeError("broken")),
            lambda aid: p_b,
        ],
    )

    with pytest.raises(OSError, match=r"builder failed|3 of 3|1 of 3"):
        mod.dispose_all_per_account_artifacts(account_id=99)

    assert "a.cache" in calls, "N-354 fix (a) failed: pre-bad-builder unlink skipped"
    assert "b.cache" in calls, "N-354 fix (a) failed: post-bad-builder unlink skipped"


def test_b_extra_errors_logged_not_silently_dropped(monkeypatch, caplog):
    """N-354 fix (b): with 3+ failing dispose paths, only the FIRST is
    surfaced in the raised OSError message — the remaining errors' paths
    + types MUST be logged at WARNING so the partial-dispose incident
    has full forensic detail."""
    p_a = _FakePath("a.cache", unlink_raises=OSError("permission denied a"))
    p_b = _FakePath("b.cache", unlink_raises=OSError("permission denied b"))
    p_c = _FakePath("c.cache", unlink_raises=OSError("permission denied c"))

    _install_builders(
        monkeypatch,
        [lambda aid: p_a, lambda aid: p_b, lambda aid: p_c],
    )

    caplog.set_level(logging.WARNING, logger="email_triage.email_triage.providers._ondisk_artifacts")

    with pytest.raises(OSError) as ei:
        mod.dispose_all_per_account_artifacts(account_id=123)

    raised_msg = str(ei.value)
    assert "3 of 3" in raised_msg, f"raised msg should reference 3-of-3: {raised_msg}"

    # `caplog` captures the messages the WARNING logger emits. The two
    # extra errors (b + c) MUST appear in the log records.
    joined = " ".join(rec.getMessage() for rec in caplog.records)
    # The warning message itself is fixed; the artifact_path + error_msg
    # ride the structured extras. caplog captures the record attrs
    # (thanks to the TriageLogger `record.__dict__` promotion), so grep
    # for the paths in the record objects' __dict__.
    all_extras: list[str] = []
    for rec in caplog.records:
        for key in ("artifact_path", "error_msg", "error_type"):
            val = getattr(rec, key, None)
            if val is not None:
                all_extras.append(str(val))
    all_extras_joined = " | ".join(all_extras)
    assert "b.cache" in all_extras_joined or "/fake/b.cache" in all_extras_joined, (
        f"N-354 fix (b) failed: extra error for b.cache not logged; got {all_extras_joined!r}"
    )
    assert "c.cache" in all_extras_joined or "/fake/c.cache" in all_extras_joined, (
        f"N-354 fix (b) failed: extra error for c.cache not logged; got {all_extras_joined!r}"
    )


def test_zero_errors_returns_deleted_count(monkeypatch):
    """Happy path — every builder returns a disposable path; no raise."""
    p_a = _FakePath("a.cache")
    p_b = _FakePath("b.cache")

    _install_builders(monkeypatch, [lambda aid: p_a, lambda aid: p_b])

    deleted = mod.dispose_all_per_account_artifacts(account_id=1)
    assert deleted == 2, "N-354 must not break the happy path"


def test_single_oserror_re_raised_typed(monkeypatch):
    """Single OSError must be re-raised as-is (typed), preserving the
    fail-CLOSED contract callers rely on."""
    err = PermissionError("locked")
    p_a = _FakePath("a.cache", unlink_raises=err)

    _install_builders(monkeypatch, [lambda aid: p_a])

    with pytest.raises(PermissionError) as ei:
        mod.dispose_all_per_account_artifacts(account_id=1)
    assert ei.value is err, "single-OSError case must re-raise the exact exception"
