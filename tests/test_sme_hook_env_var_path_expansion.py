"""the backlog  (2026-07-12): env-var / ~ expansion in the `-F <path>`
shape of the SME + evidence-bound-claim hook extractors.

Ground truth: during the N-390 drive (2026-07-12), a commit via
`git commit -F $HOME/AppData/Local/Temp/.../msg.txt` was DENIED by the SME
gate because `_commit_message_from_command` opened the literal string
`$HOME/AppData/...` (no expansion), got OSError, returned None, and the
gate then read the message as empty and DENIED-on-no-trailer. Same class
bug lives in `evidence_bound_claim_gate._extract_msg_from_command` (both
extractors accept `-F <path>` — both must expand vars + ~).

The fix wraps the path in `os.path.expanduser(os.path.expandvars(...))`
BEFORE the file open. This test pins that a `$HOME`/`~` path now
resolves and the message body is read back correctly.

feedback_root_cause_scope — fix both sites same commit; the sibling
site is a separate assertion below, not a separate test file.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest


_HOOKS_DIR = Path(__file__).parent.parent / "scripts" / "hooks"


@pytest.fixture(autouse=True)
def _hook_import_path(monkeypatch):
    monkeypatch.syspath_prepend(str(_HOOKS_DIR))


def _load_sme_extractor():
    if "sme_review_gate" in sys.modules:
        del sys.modules["sme_review_gate"]
    import sme_review_gate as _mod
    return _mod._commit_message_from_command


def _load_evidence_extractor():
    if "evidence_bound_claim_gate" in sys.modules:
        del sys.modules["evidence_bound_claim_gate"]
    import evidence_bound_claim_gate as _mod
    return _mod._extract_msg_from_command


def test_sme_gate_dashF_dollar_home_expands(tmp_path, monkeypatch):
    """`sme_review_gate._commit_message_from_command` resolves $HOME in -F."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    body = "subject line\n\nSME-Reviewed: GO (test, 2026-07-12)\n"
    msg = tmp_path / "commit-msg.txt"
    msg.write_text(body, encoding="utf-8")

    extract = _load_sme_extractor()
    got = extract("git commit -F $HOME/commit-msg.txt", cwd=str(tmp_path))
    assert got == body


def test_sme_gate_dashF_tilde_expands(tmp_path, monkeypatch):
    """`sme_review_gate._commit_message_from_command` resolves ~ in -F."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    body = "subject\n\nSME-Reviewed: GO (test, 2026-07-12)\n"
    msg = tmp_path / "commit-msg.txt"
    msg.write_text(body, encoding="utf-8")

    extract = _load_sme_extractor()
    got = extract("git commit -F ~/commit-msg.txt", cwd=str(tmp_path))
    assert got == body


def test_sme_gate_dashF_literal_path_still_works(tmp_path):
    """Regression — a literal path with no vars still reads correctly."""
    body = "subject\n\nSME-Reviewed: GO (test, 2026-07-12)\n"
    msg = tmp_path / "commit-msg.txt"
    msg.write_text(body, encoding="utf-8")

    extract = _load_sme_extractor()
    got = extract(f"git commit -F {msg}", cwd=str(tmp_path))
    assert got == body


def test_evidence_gate_dashF_dollar_home_expands(tmp_path, monkeypatch):
    """`evidence_bound_claim_gate._extract_msg_from_command` resolves $HOME."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    body = "subject with the claim: 3/3 green\n"
    msg = tmp_path / "commit-msg.txt"
    msg.write_text(body, encoding="utf-8")

    extract = _load_evidence_extractor()
    got = extract("git commit -F $HOME/commit-msg.txt")
    assert got == body


def test_evidence_gate_dashF_tilde_expands(tmp_path, monkeypatch):
    """`evidence_bound_claim_gate._extract_msg_from_command` resolves ~."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    body = "subject with the claim: verified\n"
    msg = tmp_path / "commit-msg.txt"
    msg.write_text(body, encoding="utf-8")

    extract = _load_evidence_extractor()
    got = extract("git commit -F ~/commit-msg.txt")
    assert got == body


def test_evidence_gate_dashF_literal_path_still_works(tmp_path):
    """Regression — literal path with no vars still reads correctly."""
    body = "subject with the claim: all pass\n"
    msg = tmp_path / "commit-msg.txt"
    msg.write_text(body, encoding="utf-8")

    extract = _load_evidence_extractor()
    got = extract(f"git commit -F {msg}")
    assert got == body
