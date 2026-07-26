"""Sanity tests for the CVE-inject SessionStart hook.

The hook is a small wrapper around one SSH call — the tests cover the
three surfaces the hook actually owns:

  * ``_format_row`` — matches the spec §4.7 sample verbatim on fields.
  * ``_filter``     — drops LOW/MED, unreachable, adopted; caps at 3.
  * ``main``        — happy path prints, error paths fail-open, off
                       marker short-circuits before the SSH call.

``subprocess.run`` is patched in ``main`` tests so no real SSH is
attempted — the CI/dev harness has no ``the gateway host`` route.
"""
from __future__ import annotations

import importlib.util
import json
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

HOOK_PATH = (
    Path(__file__).resolve().parents[2] / ".the AI assistant" / "hooks" / "cve-inject.py"
)


def _load_hook():
    """Load the hook as a module (its filename has a hyphen, so no direct import)."""
    spec = importlib.util.spec_from_file_location("cve_inject", HOOK_PATH)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


hook = _load_hook()


def _row(**overrides):
    base = {
        "id": "GHSA-vvqm-mxpv-jvvw",
        "severity": "HIGH",
        "package": "pyasn1",
        "affected": "<0.6.2",
        "fixed": "0.6.2",
        "class": "A",
        "auto_bumpable": True,
        "reachable": True,
        "adopted": False,
        "reachable_at": [
            {
                "file": "src/email_triage/webauthn/rp.py",
                "line": 88,
                "symbol": "pyasn1.codec.der.decoder.decode",
                "callchain": [
                    "email_triage.web.app:register_start",
                    "email_triage.webauthn.rp:_verify_attestation",
                    "pyasn1.codec.der.decoder:decode",
                ],
            }
        ],
    }
    base.update(overrides)
    return base


# --- formatter ------------------------------------------------------


def test_format_row_matches_spec_sample():
    out = hook._format_row(_row())
    assert "HIGH pyasn1 <0.6.2 → 0.6.2" in out
    assert "reachable at src/email_triage/webauthn/rp.py:88" in out
    # callchain rendered as bare function names joined by →
    assert "via register_start → _verify_attestation → decode" in out
    assert "Class A auto-bumpable · GHSA-vvqm-mxpv-jvvw" in out


def test_format_row_no_callchain_skips_via_line():
    row = _row()
    row["reachable_at"][0]["callchain"] = []
    out = hook._format_row(row)
    assert "via " not in out
    # first + class line still present
    assert "HIGH pyasn1" in out
    assert "Class A auto-bumpable" in out


def test_format_row_marks_manual_when_not_auto_bumpable():
    out = hook._format_row(_row(auto_bumpable=False, **{"class": "C"}))
    assert "Class C manual" in out


# --- filter ---------------------------------------------------------


def test_filter_drops_low_severity_unreachable_and_adopted():
    rows = [
        _row(severity="LOW", id="drop-low"),
        _row(severity="MEDIUM", id="drop-med"),
        _row(reachable=False, id="drop-unreachable"),
        _row(adopted=True, id="drop-adopted"),
        _row(id="keep-me"),
    ]
    kept = hook._filter(rows)
    assert [r["id"] for r in kept] == ["keep-me"]


def test_filter_keeps_critical():
    kept = hook._filter([_row(severity="CRITICAL", id="crit")])
    assert len(kept) == 1


def test_filter_caps_at_three():
    rows = [_row(id=f"cve-{i}") for i in range(10)]
    assert len(hook._filter(rows)) == 3


def test_filter_ignores_non_dict_entries():
    kept = hook._filter([None, "junk", 42, _row(id="keep")])
    assert [r["id"] for r in kept] == ["keep"]


# --- SSH parse path -------------------------------------------------


def _fake_proc(payload, returncode=0):
    return MagicMock(
        returncode=returncode,
        stdout=json.dumps(payload).encode("utf-8"),
        stderr=b"",
    )


def test_ssh_happy_path_prints_header_and_row(capsys):
    with patch.object(hook.subprocess, "run", return_value=_fake_proc({"queue": [_row()]})):
        rc = hook.main()
    out = capsys.readouterr().out
    assert rc == 0
    assert "CVE queue top (via cve-arc):" in out
    assert "HIGH pyasn1 <0.6.2" in out


def test_ssh_empty_queue_prints_nothing(capsys):
    with patch.object(hook.subprocess, "run", return_value=_fake_proc({"queue": []})):
        rc = hook.main()
    assert rc == 0
    assert capsys.readouterr().out == ""


def test_ssh_timeout_is_fail_open(capsys):
    with patch.object(
        hook.subprocess,
        "run",
        side_effect=subprocess.TimeoutExpired(cmd="ssh", timeout=5),
    ):
        rc = hook.main()
    assert rc == 0
    assert capsys.readouterr().out == ""


def test_ssh_nonzero_returncode_is_fail_open(capsys):
    fake = MagicMock(returncode=255, stdout=b"", stderr=b"host unreachable")
    with patch.object(hook.subprocess, "run", return_value=fake):
        rc = hook.main()
    assert rc == 0
    assert capsys.readouterr().out == ""


def test_bad_json_is_fail_open(capsys):
    fake = MagicMock(returncode=0, stdout=b"not-json", stderr=b"")
    with patch.object(hook.subprocess, "run", return_value=fake):
        rc = hook.main()
    assert rc == 0
    assert capsys.readouterr().out == ""


def test_missing_queue_key_is_fail_open(capsys):
    with patch.object(hook.subprocess, "run", return_value=_fake_proc({"other": []})):
        rc = hook.main()
    assert rc == 0
    assert capsys.readouterr().out == ""


def test_off_marker_short_circuits_before_ssh(tmp_path, monkeypatch, capsys):
    marker = tmp_path / "cve-inject.off"
    marker.write_text("")
    monkeypatch.setattr(hook, "OFF_MARKER", marker)
    with patch.object(hook.subprocess, "run") as run_mock:
        rc = hook.main()
    assert rc == 0
    assert capsys.readouterr().out == ""
    run_mock.assert_not_called()
