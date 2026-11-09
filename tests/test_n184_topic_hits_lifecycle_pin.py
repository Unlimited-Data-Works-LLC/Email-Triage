"""N-184 R20_16 structural pin — topic_hits soft-lifecycle bijection.

Census run20 R20_16 finding: `topic_hits` carries TWO soft-lifecycle columns —
`removed_at` (user-marked "this was wrong") and `expired_at` (retention-past
Topic's retention_days). Each is set-by-1-path, cleared-by-0-paths anywhere in
tree; the upvote-restore path cleared `removed_at = NULL` but did NOT clear
`expired_at`, so an expired-then-restored hit stayed hidden by the expired
filter.

This pin: any UPDATE topic_hits statement that clears ONE of the two
soft-lifecycle columns (SETs `= NULL`) MUST clear BOTH — the restore path is
either both-cleared or neither-cleared (never one-of-two).

Fix landed 2026-07-01 at actions/topic_configs.py:1041 (upvote-restore now
clears both).
"""
from __future__ import annotations

import ast
import re

from _pin_harness import SRC_ROOT, iter_files, parse_module, relpath


_SOFT_LIFECYCLE_COLS = frozenset({"removed_at", "expired_at"})

# Only walks src trees.
_SRC = SRC_ROOT

# Regex: an UPDATE topic_hits statement (single or multi-line SQL string).
_UPDATE_TOPIC_HITS_RE = re.compile(
    r"(?is)\bupdate\s+topic_hits\s+set\b(?P<body>[^;]+?)\bwhere\b"
)


def _find_topic_hits_updates(tree: ast.AST) -> list[tuple[int, str]]:
    """Every UPDATE topic_hits SET ... WHERE SQL literal in `tree`.
    Returns (lineno, body-between-SET-and-WHERE)."""
    hits: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Constant) and isinstance(node.value, str)):
            continue
        m = _UPDATE_TOPIC_HITS_RE.search(node.value)
        if not m:
            continue
        hits.append((node.lineno, m.group("body")))
    return hits


def _cleared_lifecycle_cols(update_body: str) -> set[str]:
    """The set of soft-lifecycle columns cleared to NULL in `update_body`
    (the substring between `SET` and `WHERE`)."""
    cleared: set[str] = set()
    for col in _SOFT_LIFECYCLE_COLS:
        # `col = NULL` (whitespace-tolerant, case-insensitive).
        if re.search(rf"(?i)\b{col}\s*=\s*NULL\b", update_body):
            cleared.add(col)
    return cleared


def test_topic_hits_restore_clears_both_lifecycle_cols():
    """ARM: any UPDATE topic_hits that clears one soft-lifecycle column
    must clear both — the restore path is both-or-neither."""
    offenders: list[str] = []
    for path in iter_files(_SRC):
        tree = parse_module(path)
        if tree is None:
            continue
        for lineno, body in _find_topic_hits_updates(tree):
            cleared = _cleared_lifecycle_cols(body)
            if cleared and cleared != _SOFT_LIFECYCLE_COLS:
                missing = sorted(_SOFT_LIFECYCLE_COLS - cleared)
                offenders.append(
                    f"{relpath(path)}:{lineno} clears {sorted(cleared)} "
                    f"but NOT {missing}"
                )
    assert not offenders, (
        "N-184 R20_16 topic_hits soft-lifecycle bijection violated — a "
        "restore path clears ONE soft-lifecycle column but not both:\n  "
        + "\n  ".join(offenders)
    )


def test_pin_has_teeth():
    """Planted bad shape must fire; good shape must not."""
    bad = """
def h(conn):
    conn.execute("UPDATE topic_hits SET removed_at = NULL WHERE id = ?", (1,))
"""
    tree = ast.parse(bad)
    updates = _find_topic_hits_updates(tree)
    assert updates, "detector must find the UPDATE"
    cleared = _cleared_lifecycle_cols(updates[0][1])
    assert cleared == {"removed_at"}, f"expected only removed_at cleared, got {cleared}"

    good = """
def h(conn):
    conn.execute(
        "UPDATE topic_hits SET source = 'included', removed_at = NULL, "
        "expired_at = NULL WHERE id = ?",
        (1,),
    )
"""
    tree = ast.parse(good)
    updates = _find_topic_hits_updates(tree)
    assert updates
    cleared = _cleared_lifecycle_cols(updates[0][1])
    assert cleared == _SOFT_LIFECYCLE_COLS, f"good shape must clear both, got {cleared}"

    # SET (not clearing) does NOT trigger cleared logic
    set_only = """
def h(conn, now):
    conn.execute("UPDATE topic_hits SET removed_at = ? WHERE id = ?", (now, 1))
"""
    tree = ast.parse(set_only)
    updates = _find_topic_hits_updates(tree)
    assert updates
    cleared = _cleared_lifecycle_cols(updates[0][1])
    assert cleared == set(), f"SET (non-NULL) must not count as cleared, got {cleared}"
