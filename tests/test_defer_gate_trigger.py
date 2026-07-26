"""Unit tests for scripts/hooks/defer_gate.py trigger detection.

Design anchor: design_defer_gate_yubikey_only_2026-07-12.
Feedback anchor: feedback_dont_over_defer recurrence #8.

Covers the pure-function core of the gate (no git, no _op_approval):
* `_classify_path` — the backlog vs docs/defers/ vs other.
* `_row_is_terminal` — closed/done/shipped are terminal; open/parked/deferred/wip are not.
* `_parse_rows` — extracts {row_id: {status, line}} from a Markdown table.
* `_detect_defers` — flags NEW non-terminal rows AND terminal->non-terminal moves.
* `_project_edit` — single-substring Edit projection.
"""
from __future__ import annotations

import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO / "scripts" / "hooks"))

import defer_gate  # noqa: E402


# ---------------------------------------------------------------------------
# Path classifier
# ---------------------------------------------------------------------------

def test_classify_path_punch_list_root():
    assert defer_gate._classify_path("the backlog") == "the backlog"


def test_classify_path_punch_list_completed():
    assert defer_gate._classify_path("the backlog archive") == "the backlog"


def test_classify_path_punch_list_nested():
    assert defer_gate._classify_path("docs/the backlog") == "the backlog"


def test_classify_path_defer_file():
    assert defer_gate._classify_path("docs/defers/DEFER-2026-07-12-example.md") == "defer-file"


def test_classify_path_other_docs():
    # v3 (2026-07-15): prose-shape files fall into the 'prose' surface, NOT 'other'.
    # 'other' now covers only non-prose extensions + explicit prose-exempt paths.
    assert defer_gate._classify_path("internal documentation") == "prose"


def test_classify_path_src():
    # v3: .py source is prose-shape (comments/docstrings can carry defer-language).
    assert defer_gate._classify_path("src/email_triage/config.py") == "prose"


def test_classify_path_non_prose_ext():
    # Non-prose extensions still land in 'other'.
    assert defer_gate._classify_path("assets/logo.png") == "other"
    assert defer_gate._classify_path("data/fixture.json") == "other"


def test_classify_path_prose_exempt():
    # STATE drawers, RESUME_PROMPT, settings.json, hook infra, git-hooks, and
    # memory drawers are all exempt (operator-infra + self-grandfather).
    assert defer_gate._classify_path("memory/STATE_x.md") == "other"
    assert defer_gate._classify_path("RESUME_PROMPT.md") == "other"
    assert defer_gate._classify_path(".the AI assistant/settings.json") == "other"
    assert defer_gate._classify_path("scripts/hooks/defer_gate.py") == "other"
    assert defer_gate._classify_path("scripts/hooks/_defer_phrases.py") == "other"
    assert defer_gate._classify_path("scripts/git-hooks/commit-msg") == "other"
    assert defer_gate._classify_path("memory/feedback_dont_over_defer.md") == "other"


def test_classify_path_windows_backslash():
    # Path normalization: backslashes -> forward slashes.
    assert defer_gate._classify_path("docs\\defers\\DEFER-foo.md") == "defer-file"


# ---------------------------------------------------------------------------
# Terminal-state predicate
# ---------------------------------------------------------------------------

def test_row_is_terminal_closed():
    assert defer_gate._row_is_terminal("closed") is True


def test_row_is_terminal_done():
    assert defer_gate._row_is_terminal("done") is True


def test_row_is_terminal_shipped():
    assert defer_gate._row_is_terminal("shipped") is True


def test_row_is_terminal_open():
    assert defer_gate._row_is_terminal("open") is False


def test_row_is_terminal_parked():
    assert defer_gate._row_is_terminal("parked") is False


def test_row_is_terminal_deferred():
    assert defer_gate._row_is_terminal("deferred") is False


def test_row_is_terminal_wip():
    assert defer_gate._row_is_terminal("wip") is False


def test_row_is_terminal_in_progress():
    assert defer_gate._row_is_terminal("in progress") is False
    assert defer_gate._row_is_terminal("in-progress") is False


def test_row_is_terminal_empty():
    assert defer_gate._row_is_terminal("") is False


def test_row_is_terminal_case_insensitive():
    assert defer_gate._row_is_terminal("CLOSED") is True
    assert defer_gate._row_is_terminal("Open") is False


# ---------------------------------------------------------------------------
# Table row parsing
# ---------------------------------------------------------------------------

_HEADER = "| ID | Description | Status | Notes |\n"
_SEP = "|----|-------------|--------|-------|\n"


def _table(*rows: str) -> str:
    return _HEADER + _SEP + "".join(rows)


def test_parse_rows_extracts_status_from_status_cell():
    body = _table("| N-100 | do a thing | open | none |\n")
    rows = defer_gate._parse_rows(body)
    assert "N-100" in rows
    assert "open" in rows["N-100"]["status"]


def test_parse_rows_skips_header_and_separator():
    body = _table("| N-100 | x | closed | y |\n")
    rows = defer_gate._parse_rows(body)
    assert list(rows.keys()) == ["N-100"]


def test_parse_rows_multiple():
    body = _table(
        "| N-1 | a | open | . |\n",
        "| N-2 | b | closed | . |\n",
        "| N-3 | c | shipped | . |\n",
    )
    rows = defer_gate._parse_rows(body)
    assert set(rows.keys()) == {"N-1", "N-2", "N-3"}


# ---------------------------------------------------------------------------
# Defer detection
# ---------------------------------------------------------------------------

def test_detect_defers_new_open_row():
    before = _table("| N-100 | old thing | closed | . |\n")
    after = _table(
        "| N-100 | old thing | closed | . |\n",
        "| N-200 | NEW thing | open | . |\n",
    )
    defers = defer_gate._detect_defers(before, after)
    assert any("N-200" in d for d in defers), defers


def test_detect_defers_new_closed_row_is_ok():
    before = _table("| N-100 | old thing | closed | . |\n")
    after = _table(
        "| N-100 | old thing | closed | . |\n",
        "| N-200 | done thing | closed | . |\n",
    )
    defers = defer_gate._detect_defers(before, after)
    assert defers == [], defers


def test_detect_defers_new_parked_row_is_defer():
    before = _table("| N-100 | old thing | closed | . |\n")
    after = _table(
        "| N-100 | old thing | closed | . |\n",
        "| N-201 | parked thing | parked | . |\n",
    )
    defers = defer_gate._detect_defers(before, after)
    assert any("N-201" in d for d in defers), defers


def test_detect_defers_reopen_terminal_to_open():
    before = _table("| N-100 | shipped thing | shipped | . |\n")
    after = _table("| N-100 | shipped thing | open | . |\n")
    defers = defer_gate._detect_defers(before, after)
    assert any("N-100" in d and "shipped" in d and "open" in d for d in defers), defers


def test_detect_defers_close_row_is_ok():
    before = _table("| N-100 | open thing | open | . |\n")
    after = _table("| N-100 | open thing | closed | . |\n")
    defers = defer_gate._detect_defers(before, after)
    assert defers == [], defers


def test_detect_defers_no_change():
    body = _table(
        "| N-100 | a | open | . |\n",
        "| N-200 | b | closed | . |\n",
    )
    assert defer_gate._detect_defers(body, body) == []


def test_detect_defers_new_shipped_row_is_ok():
    before = ""
    after = _table("| N-100 | ok | shipped | . |\n")
    assert defer_gate._detect_defers(before, after) == []


# ---------------------------------------------------------------------------
# Edit projection
# ---------------------------------------------------------------------------

def test_project_edit_basic():
    assert defer_gate._project_edit("hello world", "world", "there") == "hello there"


def test_project_edit_missing_old_string_no_op():
    assert defer_gate._project_edit("hello", "missing", "x") == "hello"


def test_project_edit_empty_old_string_no_op():
    assert defer_gate._project_edit("hello", "", "x") == "hello"


def test_project_edit_first_occurrence_only():
    # Edit's contract is first-hit substitution.
    assert defer_gate._project_edit("aa aa", "aa", "b") == "b aa"
