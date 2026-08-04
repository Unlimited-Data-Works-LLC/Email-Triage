"""N-234 R23 structural pin — row_get factory-agnostic column read (2026-07-02).

Census R23 discovered HIGH class: 90+ inline `hasattr(<row>, "keys")` +
`row["k"] if hasattr else row[N]` shape drift across the codebase. The
key HIPAA-adjacent site is `secrets.py:444/681` — secret decrypt with a
sqlcipher3-vs-sqlite3 Row-factory hazard: `isinstance(row, sqlite3.Row)`
silently goes False for a `sqlcipher3` row, steering the caller into the
positional-tuple branch with the WRONG index. `db/_helpers.py::row_get`
already exists (barely adopted; 2 importers pre-N-234).

N-234 landed:
  - 4 sites in `secrets.py` (secret decrypt path — the census-flagged
    HIPAA-secret hazard) migrated to `row_get(row, "key", <idx>)`.
  - This ratchet pin. Baseline = current count.

WHAT IT PINS (count-agnostic, growth-cap ratchet):

Every `hasattr(<Name>, "keys")` call tree-wide (outside the SSOT
`db/_helpers.py`) increments a counter. Total must not exceed
`_MAX_HASATTR_KEYS`. Migration commits decrement the baseline
(N-178/N-219/N-222/N-227 pattern).

SCOPE CAVEAT: matches `hasattr(<Name>, "keys")` on any Name — includes
row + non-row (e.g. `hasattr(cache, "keys")` for a dict-like probe).
The false-positive rate is low (~2 out of 90+ at HEAD are non-row
uses); the ratchet stays useful because a NEW row-factory drift can't
appear without either (a) firing the pin OR (b) requiring an explicit
allow-list adjustment.
"""
from __future__ import annotations

import ast

from _pin_harness import SRC_ROOT, iter_files, parse_module, relpath


_MAX_HASATTR_KEYS = 81  # 2026-07-02 N-234c R23: -10 (web/db.py — bulk regex migration on uniform-shape sites).
_SSOT_FILES = {"db/_helpers.py"}


def _count_sites_in_tree(tree: ast.AST) -> int:
    n = 0
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if not (isinstance(node.func, ast.Name) and node.func.id == "hasattr"):
            continue
        if len(node.args) != 2:
            continue
        arg1 = node.args[1]
        if not (isinstance(arg1, ast.Constant) and arg1.value == "keys"):
            continue
        n += 1
    return n


def test_ssot_exists():
    """Anti-vacuity: `db/_helpers.py::row_get` must exist."""
    from email_triage.db._helpers import row_get
    assert callable(row_get)


def test_hasattr_keys_growth_cap():
    """Total tree-wide `hasattr(<Name>, "keys")` sites (outside the SSOT)
    must be <= baseline."""
    total = 0
    per_file: list[tuple[str, int]] = []
    for path in iter_files(SRC_ROOT):
        rel = relpath(path)
        if rel in _SSOT_FILES:
            continue
        tree = parse_module(path)
        if tree is None:
            continue
        n = _count_sites_in_tree(tree)
        if n > 0:
            total += n
            per_file.append((rel, n))
    assert total <= _MAX_HASATTR_KEYS, (
        f"N-234 R23 row_get ratchet: `hasattr(<x>, \"keys\")` count "
        f"{total} > baseline {_MAX_HASATTR_KEYS}. NEW hand-rolls must "
        "route through `db/_helpers.row_get(row, key, idx)` — the "
        "factory-agnostic SSOT (N-16 sqlcipher3-vs-sqlite3 Row hazard).\n\n"
        + "\n".join(f"{p}: {n}" for p, n in per_file[:12])
    )
