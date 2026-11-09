"""Waste bd34bfec (2026-10-27 8:53 PM, 325K tokens): the backlog-append refused a row with
"lost_occurrences: 1 ... Escape every `|` inside a cell", but the helper already escapes every
pipe in a cell. The lost word was `name`, from `--only <name>...`: the renderer drops `<name>` as
an HTML tag. The refusal must still fire, and must now name the lost word and the tag.

``BD34_SCRIPTS_DIR`` loads another copy of scripts/ (the pre-change tree) for the both-ways red leg.
"""
from __future__ import annotations

import importlib.machinery
import importlib.util
import os
import sys
from pathlib import Path

import pytest

SCRIPTS = Path(os.environ.get("BD34_SCRIPTS_DIR") or Path(__file__).resolve().parents[1] / "scripts")
_FRESH = ("md_table_fidelity", "punch_status")


@pytest.fixture(scope="module")
def pla():
    """Load the backlog-append from SCRIPTS with FRESH copies of its two helpers (the both-ways red
    leg points SCRIPTS at another tree), then put sys.modules and sys.path back. The load used to
    run at import time and leave a fresh punch_status in sys.modules, so a reader loaded later in
    the sweep held a different STATUS_ENUM object than test_punch688 and its identity pin went red
    (2026-10-28 stack sweep)."""
    saved_path = list(sys.path)
    saved = {n: sys.modules.get(n) for n in _FRESH}
    sys.path.insert(0, str(SCRIPTS))
    for n in _FRESH:
        sys.modules.pop(n, None)
    try:
        path = SCRIPTS / "punch-list-append.py"
        spec = importlib.util.spec_from_file_location(
            "punch_list_append_bd34", path,
            loader=importlib.machinery.SourceFileLoader("punch_list_append_bd34", str(path)))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        yield mod
    finally:
        sys.path[:] = saved_path
        for n, m in saved.items():
            if m is None:
                sys.modules.pop(n, None)
            else:
                sys.modules[n] = m


HEADER = "| # | Sev | Status | Release | Feature | Item | Action | Impact |\n|---|---|---|---|---|---|---|---|\n"


def _refusal(pla, row: str) -> str:
    with pytest.raises(ValueError) as exc:
        pla.verify_renders_faithfully(HEADER + row + "\n", row)
    return str(exc.value)


def test_an_html_looking_word_is_named_with_its_cause(pla):
    row = ("| 704 | LOW | open | v0.2.x | Dev tooling | **worktree-gc.sh cannot be scoped.** | "
           "Add --only <name>... (and refuse APPLY=1) | An unscoped APPLY=1 discards live work |")
    msg = _refusal(pla, row)
    assert "lost at render: name" in msg, msg
    assert "`<name>` is read as an HTML tag" in msg, msg


def test_a_bare_pipe_is_still_refused_and_named(pla):
    row = "| 705 | LOW | open | v0.2.x | Dev tooling | a | b | c | extra words here |"
    msg = _refusal(pla, row)
    assert "lost at render: extra, here, words" in msg, msg
    assert "escape it as `\\|`" in msg, msg


def test_a_faithful_row_passes(pla):
    row = "| 706 | LOW | open | v0.2.x | Dev tooling | Add an --only NAME list | x | y |"
    pla.verify_renders_faithfully(HEADER + row + "\n", row)
