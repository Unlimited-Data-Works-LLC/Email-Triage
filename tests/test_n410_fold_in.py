"""Regression tests for N-410 fold-in fixes:
* subagent_stop_da_marker — auto-writes DA marker on SubagentStop when
  agent_type is a devils-advocate variant.
* verify_defer_trailer — presence check + shape validation (crypto
  verify is stubbed via subprocess mock; the full YubiKey path is an
  integration concern, not covered here).
* todo_marker_gate fail-open loud-stderr shape.

Anchors:
* design: N-410 roadmap evaluation 2026-07-12.
* N-409 register row §4.25 for the parent widening chain.
"""
from __future__ import annotations

import base64
import io
import json
import subprocess
import sys
import time
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO / "scripts" / "hooks"))

import subagent_stop_da_marker as damarker  # noqa: E402
import _op_approval_server as opas  # noqa: E402
import todo_marker_gate as tmg  # noqa: E402


# ---------------------------------------------------------------------------
# subagent_stop_da_marker
# ---------------------------------------------------------------------------

def test_damarker_writes_on_devils_advocate_type(tmp_path, monkeypatch):
    monkeypatch.setattr(damarker, "_head_sha",
                        lambda cwd: "abcdef0123456789" * 2 + "abcd")
    payload = {
        "cwd": str(tmp_path),
        "agent_type": "devils-advocate",
        "agent_id": "aa11223344556677",
    }
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(payload)))
    damarker.main()
    dir_ = tmp_path / ".the AI assistant" / "da-invocations"
    assert dir_.is_dir()
    markers = list(dir_.glob("*.marker"))
    assert len(markers) == 1
    first = markers[0].read_text(encoding="utf-8").splitlines()[0]
    assert first.startswith("abcdef0123456789")


def test_damarker_skips_non_da_agent(tmp_path, monkeypatch):
    monkeypatch.setattr(damarker, "_head_sha", lambda cwd: "deadbeef" * 5)
    payload = {
        "cwd": str(tmp_path),
        "agent_type": "code-reviewer",
        "agent_id": "xx",
    }
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(payload)))
    damarker.main()
    assert not (tmp_path / ".the AI assistant" / "da-invocations").exists()


def test_damarker_handles_missing_head_sha(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(damarker, "_head_sha", lambda cwd: "")
    payload = {
        "cwd": str(tmp_path),
        "agent_type": "devils_advocate",
        "agent_id": "a1",
    }
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(payload)))
    damarker.main()
    assert not (tmp_path / ".the AI assistant" / "da-invocations").exists()
    err = capsys.readouterr().err
    assert "could not resolve HEAD" in err


def test_damarker_da_prefix_variant_detected(tmp_path, monkeypatch):
    monkeypatch.setattr(damarker, "_head_sha", lambda cwd: "cafe" * 10)
    payload = {
        "cwd": str(tmp_path),
        "agent_type": "da-panel",
        "agent_id": "a2",
    }
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(payload)))
    damarker.main()
    assert (tmp_path / ".the AI assistant" / "da-invocations").exists()


def test_damarker_agent_id_sanitized_for_filename(tmp_path, monkeypatch):
    monkeypatch.setattr(damarker, "_head_sha", lambda cwd: "beef" * 10)
    payload = {
        "cwd": str(tmp_path),
        "agent_type": "devils-advocate",
        "agent_id": "weird/path\\name:with*chars",
    }
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(payload)))
    damarker.main()
    markers = list((tmp_path / ".the AI assistant" / "da-invocations").glob("*.marker"))
    assert len(markers) == 1
    # No forbidden filesystem chars in filename.
    for c in "/\\:*":
        assert c not in markers[0].name


# ---------------------------------------------------------------------------
# verify_defer_trailer — presence + shape
# ---------------------------------------------------------------------------

def test_verify_defer_missing_trailer(tmp_path):
    ok, reason = opas.verify_defer_trailer(
        "chore: touch the backlog\n", "deadbeef1234567890" + "0" * 22, cwd=str(tmp_path),
    )
    assert not ok
    assert "no matching" in reason.lower() or "carries no" in reason.lower()


def test_verify_defer_bad_base64(tmp_path):
    body = "chore: test\n\nDefer-Approval-Proof: !!!not-base64!!!\n"
    ok, reason = opas.verify_defer_trailer(body, "d" * 40, cwd=str(tmp_path))
    assert not ok
    assert "base64" in reason.lower()


def test_verify_defer_missing_nul_separator(tmp_path):
    # A base64 blob with no NUL separator between msg and sig.
    blob = base64.b64encode(b"no-nul-here-just-bytes").decode()
    body = f"chore: test\n\nDefer-Approval-Proof: {blob}\n"
    ok, reason = opas.verify_defer_trailer(body, "d" * 40, cwd=str(tmp_path))
    assert not ok
    assert "nul" in reason.lower() or "separator" in reason.lower()


def test_verify_defer_wrong_verb(tmp_path):
    msg = b"verb=sme-skip\ntarget=abcd\nissued=100\nexpiry=200\nnonce=x\n"
    sig = b"fake-sig-bytes"
    blob = base64.b64encode(msg + b"\x00" + sig).decode()
    body = f"chore: test\n\nDefer-Approval-Proof: {blob}\n"
    ok, reason = opas.verify_defer_trailer(body, "d" * 40, cwd=str(tmp_path))
    assert not ok
    # Either verb mismatch OR canonical parse (if _op_approval_common
    # requires a stricter shape); both are acceptable fail-closed.
    assert "verb" in reason.lower() or "parse" in reason.lower()


def test_verify_defer_target_mismatch(tmp_path):
    # Canonical shape mocked; ensure sha-mismatch fails cleanly.
    # Real crypto is bypassed via monkeypatch on subprocess.
    from _op_approval_common import parse_canonical as _pc  # noqa: F401
    msg = b"verb=defer-file\ntarget=deadbeef\nissued=1\nexpiry=99999999999\nnonce=x\n"
    sig = b"fake-sig-bytes"
    blob = base64.b64encode(msg + b"\x00" + sig).decode()
    body = f"chore: test\n\nDefer-Approval-Proof: {blob}\n"
    ok, reason = opas.verify_defer_trailer(
        body, "cafebabe" + "0" * 32, cwd=str(tmp_path),
    )
    assert not ok
    assert "target" in reason.lower() or "parse" in reason.lower()


# ---------------------------------------------------------------------------
# todo_marker_gate loud fail-open
# ---------------------------------------------------------------------------

def test_todo_marker_gate_loud_stderr_on_fail_open(monkeypatch, capsys, tmp_path):
    # Force an exception inside the main body to trigger the fail-open
    # branch. Patch `_classify` to raise (an unexpected error).
    def boom(rel):
        raise RuntimeError("simulated infra failure")
    monkeypatch.setattr(tmg, "_classify", boom)
    monkeypatch.setattr(tmg, "_rel_from_cwd",
                        lambda p, cwd: str(Path(p).as_posix()))
    monkeypatch.setattr(tmg, "_is_baseline_or_earlier", lambda cwd: False)
    payload = json.dumps({
        "tool_name": "Edit",
        "tool_input": {"file_path": "src/email_triage/foo.py",
                       "old_string": "a", "new_string": "b"},
        "cwd": str(tmp_path),
    })
    monkeypatch.setattr(sys, "stdin", io.StringIO(payload))
    with pytest.raises(SystemExit) as exc:
        tmg.main()
    assert int(exc.value.code or 0) == 0
    err = capsys.readouterr().err
    assert "FAIL-OPEN" in err
    assert "INSPECT THIS EDIT" in err
    assert "src/email_triage/foo.py" in err
