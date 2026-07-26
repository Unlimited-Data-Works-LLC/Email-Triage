"""Regression tests for Layers A + B + F of the defer-gate widening
(N-408, 2026-07-12).

Anchors:
* design: `design_defer_gate_yubikey_only_2026-07-12` (parent gate) +
  DA verdict 2026-07-12 (widening design).
* feedback: `feedback_dont_over_defer` recurrence #8.

Covers:
* Layer A — `task_defer_gate.py`: TaskCreate/TaskUpdate defer-shape
  detection + governance bypass + nonce path + non-Task tool passthrough.
* Layer B — `todo_marker_gate.py`: Edit/Write source-file TODO/FIXME/
  DEFER/XXX marker detection + fixture-path exclusion + line-set delta
  (not substring) + docstring accepted + nonce path.
* Layer F — `devils_advocate_gate.py`: risk-surface commit + fresh
  marker with matching HEAD sha + stale-marker rejection (HEAD-sha
  embedding closes the stale-marker attack per DA verdict).
"""
from __future__ import annotations

import io
import json
import os
import sys
import tempfile
import time
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO / "scripts" / "hooks"))

import task_defer_gate  # noqa: E402
import todo_marker_gate  # noqa: E402
import devils_advocate_gate  # noqa: E402


# ---------------------------------------------------------------------------
# Layer A — task_defer_gate
# ---------------------------------------------------------------------------

def _run_task(payload: str, monkeypatch, *, approved: bool) -> int:
    monkeypatch.setattr(task_defer_gate, "_op_approved", lambda: approved)
    monkeypatch.setattr(sys, "stdin", io.StringIO(payload))
    with pytest.raises(SystemExit) as exc:
        task_defer_gate.main()
    return int(exc.value.code or 0)


def test_task_defer_with_id_without_nonce_denied(monkeypatch):
    payload = json.dumps({
        "tool_name": "TaskCreate",
        "tool_input": {
            "subject": "Defer  to next drive",
            "description": "Do this later.",
        },
    })
    assert _run_task(payload, monkeypatch, approved=False) == 2


def test_task_defer_with_id_with_nonce_allowed(monkeypatch):
    payload = json.dumps({
        "tool_name": "TaskCreate",
        "tool_input": {
            "subject": "Defer  to next drive",
            "description": "Do this later.",
        },
    })
    assert _run_task(payload, monkeypatch, approved=True) == 0


def test_task_defer_language_without_id_allowed(monkeypatch):
    # No ID shape → not a defer per Layer A specificity gate.
    payload = json.dumps({
        "tool_name": "TaskCreate",
        "tool_input": {
            "subject": "Make coffee later",
            "description": "Not a code defer.",
        },
    })
    assert _run_task(payload, monkeypatch, approved=False) == 0


def test_task_non_defer_allowed(monkeypatch):
    payload = json.dumps({
        "tool_name": "TaskCreate",
        "tool_input": {
            "subject": "Wire N-407 defer-gate in settings.json",
            "description": "Normal work.",
        },
    })
    assert _run_task(payload, monkeypatch, approved=False) == 0


def test_task_governance_bypass_allows_meta_work(monkeypatch):
    # DA-narrowed: talking about the defer-gate itself is meta-work, not a defer.
    payload = json.dumps({
        "tool_name": "TaskCreate",
        "tool_input": {
            "subject": "Defer  later — widen defer-gate to task-list",
            "description": "N-408 governance.",
        },
    })
    assert _run_task(payload, monkeypatch, approved=False) == 0


def test_task_non_taskcreate_tool_allowed(monkeypatch):
    payload = json.dumps({
        "tool_name": "Bash",
        "tool_input": {"command": "git status"},
    })
    assert _run_task(payload, monkeypatch, approved=False) == 0


def test_task_delete_with_defer_language_denied(monkeypatch):
    payload = json.dumps({
        "tool_name": "TaskUpdate",
        "tool_input": {
            "status": "deleted",
            "description": "Deferring  to next session.",
        },
    })
    assert _run_task(payload, monkeypatch, approved=False) == 2


# ---------------------------------------------------------------------------
# Layer B — todo_marker_gate
# ---------------------------------------------------------------------------

def _run_todo(payload: str, monkeypatch, *, approved: bool,
              head_file: str = "",
              baseline_or_earlier: bool = False) -> int:
    monkeypatch.setattr(todo_marker_gate, "_op_approved", lambda cwd: approved)
    monkeypatch.setattr(todo_marker_gate, "_file_at_head",
                        lambda p, cwd: head_file)
    monkeypatch.setattr(todo_marker_gate, "_is_baseline_or_earlier",
                        lambda cwd: baseline_or_earlier)
    monkeypatch.setattr(todo_marker_gate, "_rel_from_cwd",
                        lambda p, cwd: Path(p).as_posix())
    monkeypatch.setattr(todo_marker_gate, "_git",
                        lambda args, cwd: "abc1234\n")
    monkeypatch.setattr(sys, "stdin", io.StringIO(payload))
    with pytest.raises(SystemExit) as exc:
        todo_marker_gate.main()
    return int(exc.value.code or 0)


def test_todo_added_in_src_without_nonce_denied(monkeypatch):
    payload = json.dumps({
        "tool_name": "Edit",
        "tool_input": {
            "file_path": "src/email_triage/foo.py",
            "old_string": "def bar():\n    pass\n",
            "new_string": "def bar():\n    # TODO defer next drive\n    pass\n",
        },
    })
    assert _run_todo(payload, monkeypatch, approved=False,
                     head_file="def bar():\n    pass\n") == 2


def test_todo_added_in_src_with_nonce_allowed(monkeypatch):
    payload = json.dumps({
        "tool_name": "Edit",
        "tool_input": {
            "file_path": "src/email_triage/foo.py",
            "old_string": "def bar():\n    pass\n",
            "new_string": "def bar():\n    # TODO next\n    pass\n",
        },
    })
    assert _run_todo(payload, monkeypatch, approved=True,
                     head_file="def bar():\n    pass\n") == 0


def test_todo_preexisting_untouched_allowed(monkeypatch):
    # Editing an unrelated line while a TODO already exists → line-set
    # delta empty on the TODO line → not flagged.
    head = "# TODO existing\ndef bar():\n    x = 1\n"
    payload = json.dumps({
        "tool_name": "Edit",
        "tool_input": {
            "file_path": "src/email_triage/foo.py",
            "old_string": "    x = 1\n",
            "new_string": "    x = 2\n",
        },
    })
    assert _run_todo(payload, monkeypatch, approved=False,
                     head_file=head) == 0


def test_todo_in_docstring_allowed(monkeypatch):
    # DA-narrowed: docstring `"""TODO x"""` is not a code-defer marker.
    payload = json.dumps({
        "tool_name": "Edit",
        "tool_input": {
            "file_path": "src/email_triage/foo.py",
            "old_string": "def bar():\n    pass\n",
            "new_string": "def bar():\n    \"\"\"TODO: doc will be written\"\"\"\n    pass\n",
        },
    })
    assert _run_todo(payload, monkeypatch, approved=False,
                     head_file="def bar():\n    pass\n") == 0


def test_todo_in_fixtures_excluded(monkeypatch):
    payload = json.dumps({
        "tool_name": "Edit",
        "tool_input": {
            "file_path": "tests/fixtures/data_gen.py",
            "old_string": "pass\n",
            "new_string": "# TODO extend fixture\npass\n",
        },
    })
    assert _run_todo(payload, monkeypatch, approved=False,
                     head_file="pass\n") == 0


def test_todo_non_source_path_allowed(monkeypatch):
    payload = json.dumps({
        "tool_name": "Edit",
        "tool_input": {
            "file_path": "internal documentation",
            "old_string": "hello\n",
            "new_string": "# TODO write more\nhello\n",
        },
    })
    assert _run_todo(payload, monkeypatch, approved=False,
                     head_file="hello\n") == 0


def test_todo_baseline_or_earlier_allowed(monkeypatch):
    # Grandfather: this commit itself installs the gate, so it allows
    # its own settings-wiring/etc.
    payload = json.dumps({
        "tool_name": "Edit",
        "tool_input": {
            "file_path": "src/email_triage/foo.py",
            "old_string": "pass\n",
            "new_string": "# TODO\npass\n",
        },
    })
    assert _run_todo(payload, monkeypatch, approved=False,
                     head_file="pass\n",
                     baseline_or_earlier=True) == 0


# ---------------------------------------------------------------------------
# Layer F — devils_advocate_gate
# ---------------------------------------------------------------------------

def _run_da(payload: str, monkeypatch, *, approved: bool,
            touches_risk: bool = True,
            baseline_or_earlier: bool = False,
            marker: Path | None = None,
            head_sha: str = "deadbeefcafe0000000000000000000000000000") -> int:
    monkeypatch.setattr(devils_advocate_gate, "_op_approved",
                        lambda cwd: approved)
    monkeypatch.setattr(devils_advocate_gate, "_is_baseline_or_earlier",
                        lambda cwd: baseline_or_earlier)
    monkeypatch.setattr(devils_advocate_gate,
                        "_commit_touches_risk_surface",
                        lambda cmd, cwd: touches_risk)
    monkeypatch.setattr(devils_advocate_gate, "_head_sha",
                        lambda cwd: head_sha)
    monkeypatch.setattr(devils_advocate_gate, "_git",
                        lambda args, cwd: head_sha[:7] + "\n")
    if marker is None:
        monkeypatch.setattr(devils_advocate_gate, "_find_fresh_marker",
                            lambda cwd, sha, now=None: None)
    else:
        monkeypatch.setattr(devils_advocate_gate, "_find_fresh_marker",
                            lambda cwd, sha, now=None: marker)
    monkeypatch.setattr(sys, "stdin", io.StringIO(payload))
    with pytest.raises(SystemExit) as exc:
        devils_advocate_gate.main()
    return int(exc.value.code or 0)


def _commit_payload() -> str:
    return json.dumps({
        "tool_name": "Bash",
        "tool_input": {"command": "git commit -m 'x'"},
    })


def test_da_risk_surface_no_marker_no_nonce_denied(monkeypatch):
    assert _run_da(_commit_payload(), monkeypatch, approved=False) == 2


def test_da_risk_surface_no_marker_with_nonce_allowed(monkeypatch):
    assert _run_da(_commit_payload(), monkeypatch, approved=True) == 0


def test_da_risk_surface_with_fresh_marker_allowed(monkeypatch, tmp_path):
    # Fresh marker present + sha match → allow.
    m = tmp_path / "fresh.marker"
    m.write_text("deadbeefcafe0000000000000000000000000000\n", encoding="utf-8")
    assert _run_da(_commit_payload(), monkeypatch, approved=False,
                   marker=m) == 0


def test_da_non_risk_surface_allowed(monkeypatch):
    assert _run_da(_commit_payload(), monkeypatch, approved=False,
                   touches_risk=False) == 0


def test_da_baseline_or_earlier_allowed(monkeypatch):
    assert _run_da(_commit_payload(), monkeypatch, approved=False,
                   baseline_or_earlier=True) == 0


def test_da_non_commit_bash_allowed(monkeypatch):
    payload = json.dumps({
        "tool_name": "Bash",
        "tool_input": {"command": "git status"},
    })
    assert _run_da(payload, monkeypatch, approved=False) == 0


def test_da_find_fresh_marker_rejects_stale_sha(tmp_path):
    # Direct test of the marker-finder: mtime fresh but wrong sha → None.
    m = tmp_path / ".the AI assistant" / "da-invocations"
    m.mkdir(parents=True)
    stale = m / "stale.marker"
    stale.write_text("wrongsha\n", encoding="utf-8")
    got = devils_advocate_gate._find_fresh_marker(
        str(tmp_path), "deadbeef0000000000000000000000000000dead"
    )
    assert got is None


def test_da_find_fresh_marker_rejects_stale_mtime(tmp_path):
    # Correct sha but mtime older than FRESH_WINDOW_SEC → None.
    m = tmp_path / ".the AI assistant" / "da-invocations"
    m.mkdir(parents=True)
    old = m / "old.marker"
    old.write_text("deadbeef\n", encoding="utf-8")
    old_ts = time.time() - (devils_advocate_gate.FRESH_WINDOW_SEC + 60)
    os.utime(old, (old_ts, old_ts))
    got = devils_advocate_gate._find_fresh_marker(
        str(tmp_path), "deadbeef0000000000000000000000000000dead"
    )
    assert got is None


def test_da_find_fresh_marker_accepts_fresh_sha_match(tmp_path):
    m = tmp_path / ".the AI assistant" / "da-invocations"
    m.mkdir(parents=True)
    good = m / "good.marker"
    good.write_text(
        "deadbeef0000000000000000000000000000dead\nagentId=abc\n",
        encoding="utf-8",
    )
    got = devils_advocate_gate._find_fresh_marker(
        str(tmp_path), "deadbeef0000000000000000000000000000dead"
    )
    assert got is not None
    assert got.name == "good.marker"
