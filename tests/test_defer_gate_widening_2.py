"""Regression tests for N-409 defer-gate widening drive 2:
Layer C-alt (task_state_tracker + stop_completeness_ratchet) and
Layer E redesign (owner_attribution_gate).

Anchors:
* design: N-408 register row + DA verdict 2026-07-12
* feedback: `feedback_dont_over_defer` recurrence #8/#9 (this drive
  itself IS #9 — Alex called the irony of me deferring the anti-defer
  work).

Covers:
* task_state_tracker — records pending IDs per PostToolUse event,
  rolling window trimmed to MAX_HISTORY, JSON-safe writes.
* stop_completeness_ratchet — refuses Stop when pending count
  monotonically increases across the last WINDOW snapshots; nonce
  bypass; grandfather (short history) allow.
* owner_attribution_gate — trigger phrase + no Operator-Input trailer
  → DENY; trigger phrase + Operator-Input trailer → ALLOW; no trigger
  → ALLOW; nonce → ALLOW.
"""
from __future__ import annotations

import io
import json
import sys
import time
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO / "scripts" / "hooks"))

import task_state_tracker  # noqa: E402
import stop_completeness_ratchet as ratchet  # noqa: E402
import owner_attribution_gate as owner_gate  # noqa: E402


# ---------------------------------------------------------------------------
# task_state_tracker
# ---------------------------------------------------------------------------

def test_tracker_records_pending_ids_from_tool_output(tmp_path, monkeypatch):
    payload = {
        "tool_name": "TodoWrite",
        "cwd": str(tmp_path),
        "tool_input": {
            "todos": [
                {"id": "T1", "text": "one", "status": "pending"},
                {"id": "T2", "text": "two", "status": "in_progress"},
                {"id": "T3", "text": "three", "status": "pending"},
            ],
        },
        "tool_output": "",
    }
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(payload)))
    task_state_tracker.main()
    state_file = tmp_path / task_state_tracker.STATE_REL
    assert state_file.exists()
    data = json.loads(state_file.read_text(encoding="utf-8"))
    hist = data.get("history") or []
    assert len(hist) == 1
    assert set(hist[0]["pending_ids"]) == {"T1", "T3"}
    assert hist[0]["pending_count"] == 2


def test_tracker_rolling_window_trims(tmp_path, monkeypatch):
    for i in range(task_state_tracker.MAX_HISTORY + 5):
        payload = {
            "tool_name": "TaskCreate",
            "cwd": str(tmp_path),
            "tool_input": {
                "todos": [{"id": f"T{i}", "status": "pending"}],
            },
        }
        monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(payload)))
        task_state_tracker.main()
    data = json.loads((tmp_path / task_state_tracker.STATE_REL).read_text(encoding="utf-8"))
    assert len(data["history"]) == task_state_tracker.MAX_HISTORY


def test_tracker_ignores_non_task_tool(tmp_path, monkeypatch):
    payload = {"tool_name": "Bash", "cwd": str(tmp_path)}
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(payload)))
    task_state_tracker.main()
    assert not (tmp_path / task_state_tracker.STATE_REL).exists()


# ---------------------------------------------------------------------------
# stop_completeness_ratchet
# ---------------------------------------------------------------------------

def _seed_history(tmp_path: Path, counts: list[int]) -> None:
    hist = [
        {"ts": int(time.time()) - (len(counts) - i) * 60,
         "tool": "TodoWrite",
         "pending_ids": [f"T{i}"] * n,
         "pending_count": n}
        for i, n in enumerate(counts)
    ]
    p = tmp_path / task_state_tracker.STATE_REL
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps({"history": hist}), encoding="utf-8")


def _run_ratchet(tmp_path: Path, monkeypatch, *, approved: bool) -> int:
    monkeypatch.setattr(ratchet, "_op_approved", lambda: approved)
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps({"cwd": str(tmp_path)})))
    with pytest.raises(SystemExit) as exc:
        ratchet.main()
    return int(exc.value.code or 0)


def test_ratchet_short_history_allows_stop(tmp_path, monkeypatch):
    _seed_history(tmp_path, [3])
    assert _run_ratchet(tmp_path, monkeypatch, approved=False) == 0


def test_ratchet_monotonic_increase_blocks_stop(tmp_path, monkeypatch):
    _seed_history(tmp_path, [2, 3, 5, 7])
    assert _run_ratchet(tmp_path, monkeypatch, approved=False) == 2


def test_ratchet_any_decrease_allows_stop(tmp_path, monkeypatch):
    _seed_history(tmp_path, [2, 3, 2, 4])
    assert _run_ratchet(tmp_path, monkeypatch, approved=False) == 0


def test_ratchet_flat_history_allows_stop(tmp_path, monkeypatch):
    _seed_history(tmp_path, [3, 3, 3, 3])
    assert _run_ratchet(tmp_path, monkeypatch, approved=False) == 0


def test_ratchet_nonce_bypass_allows_stop(tmp_path, monkeypatch):
    _seed_history(tmp_path, [1, 2, 3, 4])
    assert _run_ratchet(tmp_path, monkeypatch, approved=True) == 0


def test_ratchet_missing_state_file_allows(tmp_path, monkeypatch):
    # No state file at all — session just started; allow Stop.
    assert _run_ratchet(tmp_path, monkeypatch, approved=False) == 0


# ---------------------------------------------------------------------------
# owner_attribution_gate
# ---------------------------------------------------------------------------

def _run_owner(cmd: str, monkeypatch, *, approved: bool,
               msg_body: str = "") -> int:
    monkeypatch.setattr(owner_gate, "_op_approved", lambda cwd: approved)
    monkeypatch.setattr(
        owner_gate, "_commit_message_from_command",
        lambda command, cwd: msg_body,
    )
    monkeypatch.setattr(owner_gate, "_git", lambda args, cwd: "abc1234\n")
    payload = json.dumps({
        "tool_name": "Bash",
        "tool_input": {"command": cmd},
    })
    monkeypatch.setattr(sys, "stdin", io.StringIO(payload))
    with pytest.raises(SystemExit) as exc:
        owner_gate.main()
    return int(exc.value.code or 0)


def test_owner_attribution_no_trigger_allowed(monkeypatch):
    body = "fix(N-407): defer-gate bug\n\nRoutine fix."
    assert _run_owner("git commit -m 'x'", monkeypatch, approved=False,
                      msg_body=body) == 0


def test_owner_attribution_per_operator_without_trailer_denied(monkeypatch):
    body = "chore: park  per operator direction\n\nDeferring.\n"
    assert _run_owner("git commit -m 'x'", monkeypatch, approved=False,
                      msg_body=body) == 2


def test_owner_attribution_with_operator_input_trailer_allowed(monkeypatch):
    body = (
        "chore: park  per operator direction\n\nDeferring.\n\n"
        "Operator-Input: park  to next cycle\n"
    )
    assert _run_owner("git commit -m 'x'", monkeypatch, approved=False,
                      msg_body=body) == 0


def test_owner_attribution_craig_said_denied(monkeypatch):
    body = "feat: X\n\nAlex said skip Y this drive.\n"
    assert _run_owner("git commit -m 'x'", monkeypatch, approved=False,
                      msg_body=body) == 2


def test_owner_attribution_nonce_bypass_allows(monkeypatch):
    body = "chore: skip per operator without trailer\n"
    assert _run_owner("git commit -m 'x'", monkeypatch, approved=True,
                      msg_body=body) == 0


def test_owner_attribution_non_commit_bash_allowed(monkeypatch):
    body = "n/a"
    assert _run_owner("git status", monkeypatch, approved=False,
                      msg_body=body) == 0
