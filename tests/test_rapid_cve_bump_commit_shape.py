"""Pin per rapid-cve-notification-arc-design.md §7.2.

Locks the byte-exact commit-message template emitted by
`scripts/rapid-cve-bump.py`, the Class-B/C stop-before-commit
behavior, dry-run non-commit invariant, and the HIPAA-anchor
`requires_panel_before_push: true` + no-auto-push invariant.

Fail-closed: any drift in the template shape breaks this pin
immediately (no fuzzy matching).
"""
from __future__ import annotations

import importlib.util
import subprocess
from pathlib import Path
from unittest import mock

import pytest

_SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "rapid-cve-bump.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("rapid_cve_bump", str(_SCRIPT))
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


rcb = _load_module()


# --- canned enriched rows (§4.2 shape) --------------------------------------

_BASE_CALLCHAIN = [
    "email_triage.web.app:register_start",
    "email_triage.webauthn.rp:_verify_attestation",
    "pyasn1.codec.der.decoder:decode",
]

CLASS_A_ROW = {
    "id": "GHSA-vvqm-mxpv-jvvw",
    "cve": "CVE-2026-59885",
    "package": "pyasn1",
    "installed_version": "0.6.1",
    "fixed": "0.6.2",
    "url": "https://github.com/advisories/GHSA-vvqm-mxpv-jvvw",
    "hash": "0a3b884e1234deadbeef5678",
    "class": "A",
    "hipaa_anchor": None,
    "reachable_at": [
        {
            "file": "src/email_triage/webauthn/rp.py",
            "line": 88,
            "callchain": list(_BASE_CALLCHAIN),
        }
    ],
}

CLASS_B_ROW = {**CLASS_A_ROW, "class": "B", "hash": "b1b1b1b1b1b1b1b1b1b1b1b1"}

CLASS_A_HIPAA_ROW = {
    **CLASS_A_ROW,
    "hipaa_anchor": "§164.312(e)(1)",
    "hash": "aabb0000cceeff112233ccdd",
}


# --- expected byte-exact templates ------------------------------------------

EXPECTED_CLASS_A = (
    "fix(deps): bump pyasn1 0.6.1 -> 0.6.2 (Class-A auto-adopt CVE CVE-2026-59885)\n"
    "\n"
    "Advisory: https://github.com/advisories/GHSA-vvqm-mxpv-jvvw\n"
    "Reach: src/email_triage/webauthn/rp.py:88 via "
    "email_triage.web.app:register_start -> "
    "email_triage.webauthn.rp:_verify_attestation -> "
    "pyasn1.codec.der.decoder:decode\n"
    "HIPAA-anchor: n/a\n"
    "\n"
    "SME-Reviewed: PENDING-BATCH-0a3b884e1234\n"
    "Class-A auto-bump: yes\n"
    "auto-adopt-tool: scripts/rapid-cve-bump.py v1\n"
)

EXPECTED_CLASS_A_HIPAA = (
    "fix(deps): bump pyasn1 0.6.1 -> 0.6.2 (Class-A auto-adopt CVE CVE-2026-59885)\n"
    "\n"
    "Advisory: https://github.com/advisories/GHSA-vvqm-mxpv-jvvw\n"
    "Reach: src/email_triage/webauthn/rp.py:88 via "
    "email_triage.web.app:register_start -> "
    "email_triage.webauthn.rp:_verify_attestation -> "
    "pyasn1.codec.der.decoder:decode\n"
    "HIPAA-anchor: §164.312(e)(1)\n"
    "\n"
    "SME-Reviewed: PENDING-BATCH-aabb0000ccee\n"
    "Class-A auto-bump: yes\n"
    "auto-adopt-tool: scripts/rapid-cve-bump.py v1\n"
    "requires_panel_before_push: true\n"
)


# --- template shape pins ----------------------------------------------------


def test_commit_message_class_a_shape_byte_exact():
    assert rcb.compose_commit_message(CLASS_A_ROW) == EXPECTED_CLASS_A


def test_commit_message_class_b_shape_byte_exact():
    """Class-B row composes the SAME template (spec: 'drafts the same')."""
    # Only hash differs → PENDING-BATCH suffix differs; the rest is identical shape.
    msg = rcb.compose_commit_message(CLASS_B_ROW)
    assert msg.startswith(
        "fix(deps): bump pyasn1 0.6.1 -> 0.6.2 (Class-A auto-adopt CVE CVE-2026-59885)\n"
    )
    assert "SME-Reviewed: PENDING-BATCH-b1b1b1b1b1b1\n" in msg
    assert "Class-A auto-bump: yes\n" in msg
    assert "requires_panel_before_push:" not in msg


def test_commit_message_hipaa_adds_pending_batch_and_requires_panel_trailer():
    msg = rcb.compose_commit_message(CLASS_A_HIPAA_ROW)
    assert msg == EXPECTED_CLASS_A_HIPAA
    # Belt & braces — both mandatory trailers present verbatim.
    assert "SME-Reviewed: PENDING-BATCH-aabb0000ccee\n" in msg
    assert "requires_panel_before_push: true\n" in msg


# --- flow behavior pins -----------------------------------------------------


def test_class_b_flow_stops_before_commit_and_prints_instructions(capsys):
    """Class-B: no bump, no test, no pin sweep, no commit. Instructions surface."""
    with mock.patch.object(rcb, "fetch_enriched_row", return_value=CLASS_B_ROW), \
         mock.patch.object(rcb, "bump_lock") as bump, \
         mock.patch.object(rcb, "run_verified_test") as vtest, \
         mock.patch.object(rcb, "run_ratchet_sweep") as sweep, \
         mock.patch.object(rcb, "git_commit") as gcommit:
        rc = rcb.main(["--hash", CLASS_B_ROW["hash"]])

    assert rc == 0
    bump.assert_not_called()
    vtest.assert_not_called()
    sweep.assert_not_called()
    gcommit.assert_not_called()

    out = capsys.readouterr().out
    assert "class=B" in out
    assert "SME panel" in out
    assert "Drafted commit template" in out


def test_dry_run_does_not_invoke_git_commit(capsys):
    """--dry-run: steps run with dry_run=True; git_commit NEVER fires."""
    # `check_already_patched` is a defense-in-depth gate BEFORE bump_lock; a
    # canned needs-bump return keeps the flow pinned in this template test.
    # The guard itself is covered by test_rapid_cve_bump_already_patched_guard.
    with mock.patch.object(rcb, "fetch_enriched_row", return_value=CLASS_A_ROW), \
         mock.patch.object(rcb, "check_already_patched", return_value=(False, "0.6.1")), \
         mock.patch.object(rcb, "bump_lock") as bump, \
         mock.patch.object(rcb, "run_verified_test") as vtest, \
         mock.patch.object(rcb, "run_ratchet_sweep") as sweep, \
         mock.patch.object(rcb, "git_commit") as gcommit:
        rc = rcb.main(["--hash", CLASS_A_ROW["hash"], "--dry-run"])

    assert rc == 0
    gcommit.assert_not_called()
    bump.assert_called_once_with(CLASS_A_ROW, True)
    vtest.assert_called_once_with(True)
    sweep.assert_called_once_with(True)

    out = capsys.readouterr().out
    assert "[dry-run] would commit with message:" in out
    # The dry-run preview reproduces the byte-exact template.
    assert EXPECTED_CLASS_A in out


def test_dry_run_subprocess_layer_never_calls_git_commit():
    """Backstop: even at the subprocess layer no `git commit` is issued."""
    seen: list[list[str]] = []

    def fake_run(cmd, *args, **kwargs):
        # Record and short-circuit to a success shape.
        seen.append(list(cmd) if isinstance(cmd, (list, tuple)) else [str(cmd)])
        return subprocess.CompletedProcess(cmd, 0, stdout="{}", stderr="")

    with mock.patch.object(rcb, "fetch_enriched_row", return_value=CLASS_A_ROW), \
         mock.patch.object(rcb, "check_already_patched", return_value=(False, "0.6.1")), \
         mock.patch.object(rcb, "bump_lock"), \
         mock.patch.object(rcb, "run_verified_test"), \
         mock.patch.object(rcb, "run_ratchet_sweep"), \
         mock.patch.object(rcb.subprocess, "run", side_effect=fake_run):
        rc = rcb.main(["--hash", CLASS_A_ROW["hash"], "--dry-run"])

    assert rc == 0
    for cmd in seen:
        joined = " ".join(str(c) for c in cmd)
        assert not (joined.startswith("git ") and "commit" in joined), (
            f"unexpected git-commit subprocess call in dry-run: {cmd}"
        )


def test_hipaa_anchor_path_commits_but_never_auto_pushes(capsys):
    """HIPAA-lit Class-A: commit fires; NO auto-push; WARNING + trailer surface."""
    with mock.patch.object(rcb, "fetch_enriched_row", return_value=CLASS_A_HIPAA_ROW), \
         mock.patch.object(rcb, "check_already_patched", return_value=(False, "0.6.1")), \
         mock.patch.object(rcb, "bump_lock"), \
         mock.patch.object(rcb, "run_verified_test"), \
         mock.patch.object(rcb, "run_ratchet_sweep"), \
         mock.patch.object(rcb, "git_commit") as gcommit, \
         mock.patch.object(rcb, "_current_branch", return_value="feat/v0.2.0"):
        rc = rcb.main(["--hash", CLASS_A_HIPAA_ROW["hash"]])

    assert rc == 0
    gcommit.assert_called_once()
    passed_msg = gcommit.call_args.args[0]
    assert "SME-Reviewed: PENDING-BATCH-aabb0000ccee\n" in passed_msg
    assert "requires_panel_before_push: true\n" in passed_msg

    out = capsys.readouterr().out
    # Push command PRINTED (verb-gated recipe), but never invoked.
    assert "git push origin feat/v0.2.0" in out
    assert "WARNING" in out
    assert "SME panel verdict" in out
    assert "requires_panel_before_push" in out


def test_hipaa_path_never_invokes_push_at_subprocess_layer():
    """Backstop: no `git push` ever hits the subprocess layer on HIPAA path."""
    seen: list[list[str]] = []

    def fake_run(cmd, *args, **kwargs):
        seen.append(list(cmd) if isinstance(cmd, (list, tuple)) else [str(cmd)])
        return subprocess.CompletedProcess(cmd, 0, stdout="{}", stderr="")

    with mock.patch.object(rcb, "fetch_enriched_row", return_value=CLASS_A_HIPAA_ROW), \
         mock.patch.object(rcb, "check_already_patched", return_value=(False, "0.6.1")), \
         mock.patch.object(rcb, "bump_lock"), \
         mock.patch.object(rcb, "run_verified_test"), \
         mock.patch.object(rcb, "run_ratchet_sweep"), \
         mock.patch.object(rcb, "git_commit"), \
         mock.patch.object(rcb.subprocess, "run", side_effect=fake_run):
        rc = rcb.main(["--hash", CLASS_A_HIPAA_ROW["hash"]])

    assert rc == 0
    for cmd in seen:
        joined = " ".join(str(c) for c in cmd)
        assert "push" not in joined, f"unexpected git-push subprocess call: {cmd}"


def test_class_override_can_force_class_a_flow():
    """--class=A on a Class-B row lets an operator force the Class-A path."""
    row_b = {**CLASS_B_ROW}
    with mock.patch.object(rcb, "fetch_enriched_row", return_value=row_b), \
         mock.patch.object(rcb, "check_already_patched", return_value=(False, "0.6.1")), \
         mock.patch.object(rcb, "bump_lock") as bump, \
         mock.patch.object(rcb, "run_verified_test"), \
         mock.patch.object(rcb, "run_ratchet_sweep"), \
         mock.patch.object(rcb, "git_commit") as gcommit, \
         mock.patch.object(rcb, "_current_branch", return_value="feat/v0.2.0"):
        rc = rcb.main(["--hash", row_b["hash"], "--class=A"])

    assert rc == 0
    bump.assert_called_once()
    gcommit.assert_called_once()
