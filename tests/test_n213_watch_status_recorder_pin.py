"""N-213 R23 structural pin — watch-status recorder SSOT (2026-07-02).

Census run23 R23_4 (HIGH — `/watch/status` reliability): the recorder
SSOT `web/_watch_status_recorder.record_message_result` is the funnel
every per-message ingestion path MUST route through so
`WatcherManager._mb_state` counters (`processed`, `errors`,
`last_message`, `last_error`, `last_source`) reflect reality for
Gmail-push/Gmail-poll/O365-push/O365-poll/IMAP-poll — not just the
IDLE watcher.

Pin scope (initial ratchet): tree-wide bind-count of the SSOT symbol.
Baseline = 1 (the SSOT def itself, no caller yet). Every caller
migration decrements the pin's inverse-count target by 1.

N-213b follow-up migrates the 5 sibling sites + the 2 existing
watcher.py sites; then the ratchet moves to require ≥7 callers.
"""
from __future__ import annotations

import ast

from _pin_harness import SRC_ROOT, iter_files, parse_module, relpath


SSOT_MODULE = "web/_watch_status_recorder.py"
SSOT_FN = "record_message_result"


def _find_ssot_calls(tree: ast.AST) -> list[int]:
    hits = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        fn = node.func
        name = None
        if isinstance(fn, ast.Name):
            name = fn.id
        elif isinstance(fn, ast.Attribute):
            name = fn.attr
        if name == SSOT_FN:
            hits.append(node.lineno)
    return hits


def _find_ssot_def(tree: ast.AST) -> ast.FunctionDef | None:
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == SSOT_FN:
            return node
    return None


def test_recorder_ssot_is_defined_once():
    """Exactly ONE def of `record_message_result` — in
    `web/_watch_status_recorder.py`. A second def anywhere is a fork."""
    defs = []
    for path in iter_files(SRC_ROOT):
        tree = parse_module(path)
        if tree is None:
            continue
        if _find_ssot_def(tree) is not None:
            defs.append(relpath(path))
    assert defs == [SSOT_MODULE], (
        f"N-213 R23: `{SSOT_FN}` must be defined ONCE at `{SSOT_MODULE}`. "
        f"Got: {defs}. A duplicate def forks the SSOT."
    )


def test_recorder_has_callers_ratchet():
    """N-213b/c/d landed 4 callers (Gmail/O365 push consumer error + success,
    poll consumer per-UID success + error). Baseline ratchets UP as sibling
    ingestion paths adopt the SSOT — this prevents a regression that REMOVES
    the telemetry (which would silently return /watch/status to the pre-N-213
    "processed=0" lie for non-IMAP-IDLE accounts)."""
    total = 0
    for path in iter_files(SRC_ROOT):
        rel = relpath(path)
        if rel == SSOT_MODULE:
            continue
        tree = parse_module(path)
        if tree is None:
            continue
        total += len(_find_ssot_calls(tree))
    assert total >= 4, (
        f"N-213 R23 recorder-caller ratchet: {total} callers < required 4. "
        "N-213b/c/d landed the push consumer error + success + poll consumer "
        "per-UID success + error. A regression that removes any of them "
        "would silently return /watch/status to the pre-N-213 processed=0 "
        "lie for non-IMAP-IDLE accounts."
    )


def test_recorder_ssot_signature():
    """The SSOT's signature MUST accept `(manager, account_id, mailbox,
    source, *, success, message_id, error)` — a future refactor that renames
    a required kwarg breaks the interproc pin's downstream callers."""
    tree = parse_module(SRC_ROOT / "web" / "_watch_status_recorder.py")
    assert tree is not None
    fn = _find_ssot_def(tree)
    assert fn is not None
    args = fn.args
    positional = [a.arg for a in args.args]
    kwonly = [a.arg for a in args.kwonlyargs]
    assert positional == ["manager", "account_id", "mailbox", "source"], (
        f"positional args changed: {positional}"
    )
    assert set(kwonly) >= {"success", "message_id", "error"}, (
        f"kwonly args missing required: {kwonly}"
    )
