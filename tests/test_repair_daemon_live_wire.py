"""test_repair_daemon_live_wire.py — pin the Component B `--live` wire (2026-07-02).

Regression: `commit_and_pr` used to be a scaffold that only printed the intended
commit message. This commit wires a real live path behind `--live` — this pin
ensures:
  1. The `commit_and_pr` signature carries the `live: bool = False` kwarg.
  2. The CLI exposes a `--live` flag.
  3. `_extract_root_cause` parses `DONE: <root_cause>` correctly.
  4. Without `--live` set, `commit_and_pr` returns without touching git (safe
     scaffold — a cwd git status is unchanged after the call).
"""
from __future__ import annotations

import inspect
import subprocess
import sys
from pathlib import Path

import pytest

_SCRIPTS_DIR = Path(__file__).resolve().parents[1] / "scripts"


@pytest.fixture(scope="module")
def daemon():
    sys.path.insert(0, str(_SCRIPTS_DIR))
    try:
        import test_repair_daemon as trd  # type: ignore
    finally:
        # Keep on path for other tests but do not leak beyond module.
        pass
    return trd


def test_commit_and_pr_signature_has_live_kwarg(daemon):
    sig = inspect.signature(daemon.commit_and_pr)
    assert "live" in sig.parameters, (
        f"commit_and_pr must accept `live` kwarg; got {list(sig.parameters)}"
    )
    p = sig.parameters["live"]
    assert p.default is False, "live must default to False (safe scaffold)"


def test_cli_exposes_live_flag():
    r = subprocess.run(
        [sys.executable, str(_SCRIPTS_DIR / "test_repair_daemon.py"), "--help"],
        capture_output=True, text=True, timeout=20,
    )
    assert r.returncode == 0, f"--help failed: {r.stderr[:300]}"
    assert "--live" in r.stdout, f"--live flag missing from CLI:\n{r.stdout}"
    # Safety: --live's help text must state the operator-opt-in framing.
    assert "OPT-IN" in r.stdout or "opt-in" in r.stdout, (
        "--live help text must document operator-opt-in framing"
    )


@pytest.mark.parametrize("stdout,expected", [
    ("foo\nDONE: fixture-drift after v45\nqux", "fixture-drift after v45"),
    ("no marker here", ""),
    ("DONE:   whitespace stripped   ", "whitespace stripped"),
    ("multiple:\nDONE: first\nDONE: second", "first"),
])
def test_extract_root_cause(daemon, stdout, expected):
    assert daemon._extract_root_cause(stdout) == expected


def test_commit_and_pr_without_live_is_noop(daemon, tmp_path, capsys, monkeypatch):
    """Without --live, commit_and_pr must NOT run any git subprocess. Guard by
    patching `_run` to raise if called."""
    calls = []

    def _fake_run(*a, **kw):
        calls.append(a)
        raise AssertionError(f"_run must not be called in scaffold mode: {a}")

    monkeypatch.setattr(daemon, "_run", _fake_run)

    ok, detail = daemon.commit_and_pr(
        worktree=tmp_path,
        new_branch="repair/test",
        test_id="tests/test_x.py::test_y",
        root_cause="test fixture drift",
        base_branch="feat/v0.2.0",
        live=False,
    )
    assert ok is True
    assert calls == [], f"scaffold mode invoked _run: {calls}"
    assert "scaffold" in detail.lower() or "--live not set" in detail
