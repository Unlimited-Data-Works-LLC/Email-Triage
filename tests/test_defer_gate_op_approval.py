"""Integration tests for scripts/hooks/defer_gate.py `main()` — the
signed-nonce gate on Edit/Write.

Verifies:
* A defer-shape Edit with NO signed nonce is DENIED (exit 2).
* The same Edit WITH a valid signed nonce ALLOWS (exit 0).
* A non-defer Edit (adding a `closed` row) ALLOWS regardless of nonce.
* An Edit on an unrelated path (e.g. `src/foo.py`) ALLOWS (out of scope).
* A Write of a new `docs/defers/DEFER-*.md` file is DENIED without a nonce.
* Malformed JSON ALLOWS (fail-open on infra error).

Anchors:
* design_defer_gate_yubikey_only_2026-07-12
* feedback_dont_over_defer recurrence #8
"""
from __future__ import annotations

import io
import json
import sys
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO / "scripts" / "hooks"))

import defer_gate  # noqa: E402
import _defer_da  # noqa: E402


_HEADER = "| ID | Description | Status | Notes |\n"
_SEP = "|----|-------------|--------|-------|\n"


def _make_payload(*, tool_name: str, file_path: str, old_string: str = "",
                  new_string: str = "", content: str = "") -> str:
    if tool_name == "Write":
        tool_input = {"file_path": file_path, "content": content}
    else:
        tool_input = {"file_path": file_path,
                      "old_string": old_string, "new_string": new_string}
    return json.dumps({
        "tool_name": tool_name,
        "tool_input": tool_input,
        "cwd": str(_REPO),
    })


def _run_main(payload: str, monkeypatch, *, approved: bool,
              head_file: str | None,
              baseline_or_earlier: bool = False,
              worktree_file: str | None = None,
              da_approved: bool = True) -> int:
    """Invoke defer_gate.main() with monkeypatched git/op-approval.

    ``worktree_file`` controls the .gitignored fallback: when HEAD lacks the
    file, the gate reads the working-tree copy. Tests can pass a distinct
    value to exercise the fallback path, or leave it None to inherit
    ``head_file`` (the pre-2nd-commit default behavior).

    ``da_approved`` stubs ``_defer_da.da_cosign`` — v2 (2026-07-13, per
    ``design_defer_gate_v2_1and3_da_cosign_signal_2026-07-13``) requires
    BOTH a YubiKey nonce AND a devils-advocate co-sign to allow a defer.
    Defaults to True so pre-v2 tests keep exercising the nonce path in
    isolation; set False to cover the DA-refuse arm."""
    baseline = worktree_file if worktree_file is not None else head_file
    monkeypatch.setattr(defer_gate, "_op_approved", lambda cwd: approved)
    monkeypatch.setattr(
        _defer_da, "da_cosign",
        lambda kind, details, before, after: (da_approved, "test-stub"),
    )
    monkeypatch.setattr(defer_gate, "_file_at_head", lambda p, cwd: head_file)
    monkeypatch.setattr(defer_gate, "_file_current_baseline",
                        lambda p, cwd: baseline)
    monkeypatch.setattr(defer_gate, "_is_baseline_or_earlier",
                        lambda cwd: baseline_or_earlier)
    monkeypatch.setattr(defer_gate, "_head_sha_short", lambda cwd: "abc1234")
    monkeypatch.setattr(defer_gate, "_rel_from_cwd",
                        lambda p, cwd: Path(p).as_posix())
    monkeypatch.setattr(sys, "stdin", io.StringIO(payload))
    with pytest.raises(SystemExit) as exc:
        defer_gate.main()
    return int(exc.value.code or 0)


def test_edit_adds_open_row_without_nonce_is_denied(monkeypatch):
    head = _HEADER + _SEP + "| N-100 | old | closed | . |\n"
    old = "| N-100 | old | closed | . |\n"
    new = (
        "| N-100 | old | closed | . |\n"
        "| N-200 | NEW | open | . |\n"
    )
    payload = _make_payload(
        tool_name="Edit", file_path="the backlog",
        old_string=old, new_string=new,
    )
    rc = _run_main(payload, monkeypatch, approved=False, head_file=head)
    assert rc == 2


def test_edit_adds_open_row_with_nonce_allowed(monkeypatch):
    head = _HEADER + _SEP + "| N-100 | old | closed | . |\n"
    old = "| N-100 | old | closed | . |\n"
    new = (
        "| N-100 | old | closed | . |\n"
        "| N-200 | NEW | open | . |\n"
    )
    payload = _make_payload(
        tool_name="Edit", file_path="the backlog",
        old_string=old, new_string=new,
    )
    rc = _run_main(payload, monkeypatch, approved=True, head_file=head)
    assert rc == 0


def test_edit_adds_closed_row_allowed_regardless_of_nonce(monkeypatch):
    head = _HEADER + _SEP + "| N-100 | old | open | . |\n"
    old = "| N-100 | old | open | . |\n"
    new = (
        "| N-100 | old | open | . |\n"
        "| N-200 | done | closed | . |\n"
    )
    payload = _make_payload(
        tool_name="Edit", file_path="the backlog",
        old_string=old, new_string=new,
    )
    rc = _run_main(payload, monkeypatch, approved=False, head_file=head)
    assert rc == 0


def test_edit_closing_open_row_allowed_without_nonce(monkeypatch):
    head = _HEADER + _SEP + "| N-100 | old | open | . |\n"
    old = "| N-100 | old | open | . |\n"
    new = "| N-100 | old | closed | . |\n"
    payload = _make_payload(
        tool_name="Edit", file_path="the backlog",
        old_string=old, new_string=new,
    )
    rc = _run_main(payload, monkeypatch, approved=False, head_file=head)
    assert rc == 0


def test_edit_reopening_closed_row_without_nonce_is_denied(monkeypatch):
    head = _HEADER + _SEP + "| N-100 | old | closed | . |\n"
    old = "| N-100 | old | closed | . |\n"
    new = "| N-100 | old | open | . |\n"
    payload = _make_payload(
        tool_name="Edit", file_path="the backlog",
        old_string=old, new_string=new,
    )
    rc = _run_main(payload, monkeypatch, approved=False, head_file=head)
    assert rc == 2


def test_edit_unrelated_path_out_of_scope(monkeypatch):
    payload = _make_payload(
        tool_name="Edit", file_path="src/email_triage/config.py",
        old_string="foo", new_string="bar",
    )
    rc = _run_main(payload, monkeypatch, approved=False, head_file="foo")
    assert rc == 0


def test_write_new_defer_file_without_nonce_is_denied(monkeypatch):
    payload = _make_payload(
        tool_name="Write",
        file_path="docs/defers/DEFER-2026-07-12-example.md",
        content="# DEFER 2026-07-12 example\n\n## Item\nSomething\n",
    )
    rc = _run_main(payload, monkeypatch, approved=False, head_file=None)
    assert rc == 2


def test_write_new_defer_file_with_nonce_allowed(monkeypatch):
    payload = _make_payload(
        tool_name="Write",
        file_path="docs/defers/DEFER-2026-07-12-example.md",
        content="# DEFER\n\n## Item\n...\n",
    )
    rc = _run_main(payload, monkeypatch, approved=True, head_file=None)
    assert rc == 0


def test_write_new_defer_file_da_refuse_is_denied(monkeypatch):
    # v2 contract: even with a valid YubiKey nonce, a DA-refuse denies.
    payload = _make_payload(
        tool_name="Write",
        file_path="docs/defers/DEFER-2026-07-12-example.md",
        content="# DEFER\n\n## Item\n...\n",
    )
    rc = _run_main(payload, monkeypatch, approved=True, head_file=None,
                   da_approved=False)
    assert rc == 2


def test_edit_open_row_da_refuse_is_denied(monkeypatch):
    head = _HEADER + _SEP + "| N-100 | old | closed | . |\n"
    old = "| N-100 | old | closed | . |\n"
    new = (
        "| N-100 | old | closed | . |\n"
        "| N-200 | NEW | open | . |\n"
    )
    payload = _make_payload(
        tool_name="Edit", file_path="the backlog",
        old_string=old, new_string=new,
    )
    rc = _run_main(payload, monkeypatch, approved=True, head_file=head,
                   da_approved=False)
    assert rc == 2


def test_write_existing_defer_file_allowed(monkeypatch):
    # Editing an existing defer artifact is not itself a defer event.
    payload = _make_payload(
        tool_name="Write",
        file_path="docs/defers/DEFER-2026-07-01-example.md",
        content="# updated body\n",
    )
    rc = _run_main(payload, monkeypatch, approved=False,
                   head_file="# preexisting body\n")
    assert rc == 0


def test_grandfathered_at_baseline_allows_without_nonce(monkeypatch):
    # If HEAD is at or before the baseline, the gate has effectively not
    # landed from the repo's POV — allow so the very commit that installs
    # the gate can land its own settings wiring.
    head = _HEADER + _SEP + "| N-100 | old | closed | . |\n"
    old = "| N-100 | old | closed | . |\n"
    new = (
        "| N-100 | old | closed | . |\n"
        "| N-200 | NEW | open | . |\n"
    )
    payload = _make_payload(
        tool_name="Edit", file_path="the backlog",
        old_string=old, new_string=new,
    )
    rc = _run_main(payload, monkeypatch, approved=False, head_file=head,
                   baseline_or_earlier=True)
    assert rc == 0


def test_non_edit_write_tool_allowed(monkeypatch):
    payload = json.dumps({
        "tool_name": "Bash",
        "tool_input": {"command": "git status"},
        "cwd": str(_REPO),
    })
    rc = _run_main(payload, monkeypatch, approved=False, head_file=None)
    assert rc == 0


def test_malformed_json_fails_open(monkeypatch):
    monkeypatch.setattr(sys, "stdin", io.StringIO("this is not json"))
    with pytest.raises(SystemExit) as exc:
        defer_gate.main()
    assert int(exc.value.code or 0) == 0


def test_gitignored_punch_list_uses_worktree_baseline(monkeypatch):
    # Regression: the backlog is .gitignored on this repo, so `git show
    # HEAD:the backlog` returns None. Without the worktree fallback the
    # gate would treat every existing open row as NEW and DENY every Edit.
    # With the fallback, only the CHANGE relative to the worktree baseline
    # matters — closing an existing open row (open -> closed) is allowed
    # even under no nonce.
    worktree = _HEADER + _SEP + (
        "| N-100 | pre-existing | open | . |\n"
        "| N-200 | pre-existing | open | . |\n"
    )
    old = "| N-100 | pre-existing | open | . |\n"
    new = "| N-100 | pre-existing | closed | . |\n"
    payload = _make_payload(
        tool_name="Edit", file_path="the backlog",
        old_string=old, new_string=new,
    )
    # HEAD returns None (.gitignored); worktree returns the actual file.
    rc = _run_main(payload, monkeypatch, approved=False, head_file=None,
                   worktree_file=worktree)
    assert rc == 0


def test_gitignored_punch_list_new_open_row_still_denied(monkeypatch):
    # The .gitignored fallback must NOT let NEW open rows through — only
    # differences vs the working-tree baseline should be evaluated.
    worktree = _HEADER + _SEP + "| N-100 | existing | open | . |\n"
    old = "| N-100 | existing | open | . |\n"
    new = (
        "| N-100 | existing | open | . |\n"
        "| N-999 | NEW ADDITION | open | . |\n"
    )
    payload = _make_payload(
        tool_name="Edit", file_path="the backlog",
        old_string=old, new_string=new,
    )
    rc = _run_main(payload, monkeypatch, approved=False, head_file=None,
                   worktree_file=worktree)
    assert rc == 2


def test_deny_message_names_target_and_nonce_command(monkeypatch, capsys):
    head = _HEADER + _SEP + "| N-100 | old | closed | . |\n"
    old = "| N-100 | old | closed | . |\n"
    new = (
        "| N-100 | old | closed | . |\n"
        "| N-200 | NEW | open | . |\n"
    )
    payload = _make_payload(
        tool_name="Edit", file_path="the backlog",
        old_string=old, new_string=new,
    )
    _run_main(payload, monkeypatch, approved=False, head_file=head)
    captured = capsys.readouterr()
    combined = captured.out + captured.err
    assert "N-200" in combined
    assert "op-approve.ps1 defer-file" in combined
    assert "abc1234" in combined  # the sha short
