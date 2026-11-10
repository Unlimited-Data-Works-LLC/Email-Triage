"""feature-add-e2e-gate: the first push of a new branch must resolve a usable diff base.

GitHub sends ``github.event.before`` as the all-zeros null object id on the first push of a
new branch. ``tests.yml`` passes it straight through as ``E2E_GATE_BASE`` (a 40-zero string is
truthy, so the workflow's ``||`` fallback never fires), and ``git diff 000..HEAD`` is an invalid
range, so the gate exited 2 on every new branch (punch 517, run 36001455039).

Two arms, against the real repository:
* the RAW null id is proven to break the diff this gate runs — the failure is real here;
* the resolver turns the null id into a base the same diff accepts.
"""

from __future__ import annotations

import importlib.util
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
_SCRIPT = REPO_ROOT / "scripts" / "workflows" / "feature-add-e2e-gate.py"

_spec = importlib.util.spec_from_file_location("feature_add_e2e_gate", _SCRIPT)
gate = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gate)

NULL_SHA1 = "0" * 40
NULL_SHA256 = "0" * 64


def _diff_rc(base: str) -> int:
    """Return code of the same ``git diff --name-status <base>..HEAD`` the gate runs."""
    return subprocess.run(
        ["git", "diff", "--name-status", f"{base}..HEAD"],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        check=False,
    ).returncode


def _unset_base(monkeypatch: pytest.MonkeyPatch) -> str:
    monkeypatch.delenv("E2E_GATE_BASE", raising=False)
    return gate._default_base()


def test_raw_null_oid_breaks_the_gate_diff() -> None:
    """Red arm: the value GitHub sends is not a usable base in this repository."""
    assert _diff_rc(NULL_SHA1) != 0


@pytest.mark.parametrize("null", [NULL_SHA1, NULL_SHA256, " " + NULL_SHA1 + "\n"])
def test_null_oid_resolves_like_unset(monkeypatch: pytest.MonkeyPatch, null: str) -> None:
    """Green arm: an all-zeros base falls through the same chain as no base at all."""
    expected = _unset_base(monkeypatch)
    monkeypatch.setenv("E2E_GATE_BASE", null)
    got = gate._default_base()
    assert got == expected
    assert set(got) != {"0"}
    assert _diff_rc(got) == 0


def test_empty_base_resolves_like_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    expected = _unset_base(monkeypatch)
    monkeypatch.setenv("E2E_GATE_BASE", "   ")
    assert gate._default_base() == expected


def test_real_base_passes_through_unchanged(monkeypatch: pytest.MonkeyPatch) -> None:
    """Only the null id is special: a real sha (a normal push's ``before``) is used as given.

    Uses HEAD, not HEAD~1: the unit job checks out shallow (fetch-depth 1), where HEAD~1 does not
    exist (a2b2d912 went red in CI on exactly that while passing on a full local clone).
    """
    head_parent = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    monkeypatch.setenv("E2E_GATE_BASE", head_parent)
    assert gate._default_base() == head_parent


def test_unresolvable_non_null_base_is_not_rescued(monkeypatch: pytest.MonkeyPatch) -> None:
    """A non-null ref that does not resolve still reaches the diff as given, so the gate keeps
    failing CLOSED (exit 2) on it; the fallback is reserved for the documented null id."""
    bogus = "deadbeef" * 5
    monkeypatch.setenv("E2E_GATE_BASE", bogus)
    assert gate._default_base() == bogus
    assert _diff_rc(bogus) != 0

# 2026-10-09: the skip trailer is read from the trailer block only. A raw-body substring
# match made any range holding a commit that documents the flag fail open.

def _repo_with_commit(tmp_path: Path, message: str) -> Path:
    def g(*a: str) -> None:
        subprocess.run(["git", *a], cwd=str(tmp_path), check=True, capture_output=True, text=True)
    g("init", "-q")
    g("config", "user.email", "t@example.invalid")
    g("config", "user.name", "t")
    (tmp_path / "a.txt").write_text("a", encoding="utf-8")
    g("add", "a.txt")
    g("commit", "-q", "-m", "base")
    (tmp_path / "b.txt").write_text("b", encoding="utf-8")
    g("add", "b.txt")
    g("commit", "-q", "-m", message)
    return tmp_path


def test_a_body_that_mentions_the_skip_token_does_not_skip(tmp_path: Path) -> None:
    msg = (
        "docs: the deploy flag\n\n"
        "Use --skip-ref-guard OPERATOR-APPROVED-SKIP:<reason>, which still runs both.\n\n"
        "SME-Reviewed: GO (panel)\n"
    )
    repo = _repo_with_commit(tmp_path, msg)
    assert gate._commit_range_has_skip_trailer("HEAD~1", cwd=repo) is None


def test_a_real_skip_trailer_still_skips(tmp_path: Path) -> None:
    repo = _repo_with_commit(tmp_path, "add widget\n\nOPERATOR-APPROVED-SKIP: dev-tools scratchpad demo\n")
    assert gate._commit_range_has_skip_trailer("HEAD~1", cwd=repo) == "dev-tools scratchpad demo"
