"""N-381 R32 test — `evidence_bound_claim_gate._extract_msg_from_command`
covers -F <path> / --file= / --message= (2026-07-09).

the backlog  (Phase-4 ci_hooks MED, workflow wf_1dcde854):
`scripts/hooks/evidence_bound_claim_gate.py::_extract_msg_from_command`
originally handled only ``-F -`` heredoc + ``-m "..."`` inline shapes.
`deploy.sh` and this repo's commit tooling frequently use a HEREDOC →
tempfile → ``-F <path>`` path, which silently bypassed the verify-
before-claim binding.

The widen adds support for:
  * ``-F <path>`` / ``-F<path>``
  * ``--file=<path>`` / ``--file <path>``
  * ``--message=<inline>`` / ``--message <inline>``

Best-effort file reads: an unreadable ``<path>`` returns empty string
(matches the pre-N-381 behaviour of an unrecognized command shape).
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest


_HOOKS_DIR = Path(__file__).parent.parent / "scripts" / "hooks"


@pytest.fixture(autouse=True)
def _hook_import_path(monkeypatch):
    """Add ``scripts/hooks`` to sys.path so we can import the hook
    module by name (it lives outside the ``email_triage`` package)."""
    monkeypatch.syspath_prepend(str(_HOOKS_DIR))


def _load_extractor():
    """Load the extractor freshly per test (defensive against sys.modules
    caching across the harness)."""
    if "evidence_bound_claim_gate" in sys.modules:
        del sys.modules["evidence_bound_claim_gate"]
    import evidence_bound_claim_gate as _mod
    return _mod._extract_msg_from_command


def test_extractor_heredoc_dashF_stdin(tmp_path):
    """Pre-N-381 shape: ``-F - <<HEREDOC ... HEREDOC``."""
    extract = _load_extractor()
    cmd = "git commit -F - <<EOF\nheredoc-body-line-1\nEOF"
    assert extract(cmd) == "heredoc-body-line-1"


def test_extractor_dashm_double_quoted():
    """Pre-N-381 shape: ``-m "..."``."""
    extract = _load_extractor()
    assert extract('git commit -m "inline double"') == "inline double"


def test_extractor_dashm_single_quoted():
    """Pre-N-381 shape: ``-m '...'``."""
    extract = _load_extractor()
    assert extract("git commit -m 'inline single'") == "inline single"


def test_extractor_dashF_file_path(tmp_path):
    """N-381 add: ``-F <path>`` reads the file."""
    extract = _load_extractor()
    f = tmp_path / "msg.txt"
    f.write_text("dashF file body", encoding="utf-8")
    assert extract(f"git commit -F {f}") == "dashF file body"


def test_extractor_dashfile_equals_path(tmp_path):
    """N-381 add: ``--file=<path>`` reads the file."""
    extract = _load_extractor()
    f = tmp_path / "msg2.txt"
    f.write_text("dashfile equals body", encoding="utf-8")
    assert extract(f"git commit --file={f}") == "dashfile equals body"


def test_extractor_dashfile_space_path(tmp_path):
    """N-381 add: ``--file <path>`` reads the file."""
    extract = _load_extractor()
    f = tmp_path / "msg3.txt"
    f.write_text("dashfile space body", encoding="utf-8")
    assert extract(f"git commit --file {f}") == "dashfile space body"


def test_extractor_dashmessage_equals():
    """N-381 add: ``--message="..."`` inline."""
    extract = _load_extractor()
    assert extract('git commit --message="msg equals"') == "msg equals"


def test_extractor_dashmessage_space():
    """N-381 add: ``--message '...'`` inline."""
    extract = _load_extractor()
    assert extract("git commit --message 'msg space'") == "msg space"


def test_extractor_unreadable_path_returns_empty(tmp_path):
    """Best-effort: an unreadable path returns "" (not raise) so the
    verify-before-claim gate defers to whatever trailer was in the
    actual commit-message downstream, matching pre-N-381 fail-open
    behaviour at the hook boundary."""
    extract = _load_extractor()
    missing = tmp_path / "does-not-exist.txt"
    assert extract(f"git commit -F {missing}") == ""


def test_extractor_unknown_shape_returns_empty():
    """Unrecognized command shape → empty string (matches pre-N-381)."""
    extract = _load_extractor()
    assert extract("git commit --nonsense-arg foo") == ""


def test_extractor_heredoc_takes_precedence_over_dashF_path(tmp_path):
    """A `-F - <<HEREDOC` shape MUST parse as heredoc, not chase a
    later `-F <path>` if one happened to appear.  The heredoc branch
    is (1), file-path branch skips ``-F -``.
    """
    extract = _load_extractor()
    cmd = "git commit -F - <<EOF\nheredoc-wins\nEOF"
    assert extract(cmd) == "heredoc-wins"


def test_extractor_dashF_double_quoted_path_with_spaces(tmp_path):
    """DA fold N-381 F1 (2026-07-09) — `-F "path with spaces"` MUST
    parse the quoted path, not fail on the quote character.
    """
    extract = _load_extractor()
    f = tmp_path / "path with spaces.txt"
    f.write_text("quoted-path body", encoding="utf-8")
    assert extract(f'git commit -F "{f}"') == "quoted-path body"


def test_extractor_dashfile_single_quoted_path(tmp_path):
    """DA fold N-381 F1 — `--file='shell-quoted'` MUST parse the
    single-quoted path.
    """
    extract = _load_extractor()
    f = tmp_path / "single-quoted.txt"
    f.write_text("single-quoted body", encoding="utf-8")
    assert extract(f"git commit --file='{f}'") == "single-quoted body"


def test_extractor_dashm_unquoted_word():
    """DA fold N-381 F2 (2026-07-09) — `-m WORD` (unquoted single-token)
    MUST parse, matching git's legal-command grammar.
    """
    extract = _load_extractor()
    assert extract("git commit -m hello") == "hello"


def test_extractor_dashmessage_equals_unquoted():
    """DA fold N-381 F2 — `--message=WORD` unquoted MUST parse."""
    extract = _load_extractor()
    assert extract("git commit --message=hello") == "hello"


def test_extractor_unreadable_dashF_falls_through_to_inline_message(tmp_path):
    """DA fold N-381 Attack B (2026-07-09) — a malicious sequence
    ``git commit -F /nonexistent/path --message="fake claim"`` MUST NOT
    silently bypass the verify-before-claim gate via the pre-fold
    early-return-on-unreadable behaviour. Branch (2) failing over an
    unreadable path MUST fall through to branch (3) so the inline
    `-m` / `--message` still parses.
    """
    extract = _load_extractor()
    missing = tmp_path / "does-not-exist-attack-b.txt"
    cmd = f'git commit -F {missing} --message="fallthrough wins"'
    assert extract(cmd) == "fallthrough wins", (
        "N-381 Attack B: unreadable -F path MUST fall through to the "
        "inline --message/--m parser, not short-circuit to empty."
    )
    # Same shape, swap flag order to prove parse is position-independent.
    cmd_swapped = f'git commit --message="inline first, unreadable -F second" -F {missing}'
    assert extract(cmd_swapped) == "inline first, unreadable -F second"
