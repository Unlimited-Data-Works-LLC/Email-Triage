"""N-235 R23 structural pin — _rows / _row dict-projection STRICT-0 (2026-07-02).

Census R23 discovered HIGH class: 3 byte-identical `_rows` / `_row`
SSOT copies each self-claiming "the single home":
  - `db/_helpers.py:141+150`  (canonical)
  - `db/audit.py:480+485`     (duplicate)
  - `web/db.py:461+470`       (duplicate)

Triple-home IS zero home: a future deep-copy-JSON edit lands in one
copy and drifts. N-235 landed:
  - Deleted the 2 duplicates + re-exported `_rows` / `_row` from
    `db/_helpers.py` at each former-def site.

WHAT IT PINS (count-agnostic, STRICT-0):

Every `def _rows(...)` and `def _row(...)` at MODULE-LEVEL tree-wide
outside `db/_helpers.py` fires the pin.

SCOPE CAVEAT: matches only the EXACT names `_rows` / `_row`. A sibling
like `_row_to_snapshot` (a domain-specific projection at
`web/acme_job_state.py:326`) does NOT fire — that's a different SSOT
concern (row → domain object, not row → dict).
"""
from __future__ import annotations

import ast

from _pin_harness import SRC_ROOT, iter_files, parse_module, relpath


_TARGET_NAMES = {"_rows", "_row"}
_SSOT_FILES = {"db/_helpers.py"}


def test_row_projection_ssot_singular():
    """Every `def _rows(...)` / `def _row(...)` at module level outside
    `db/_helpers.py` fires. STRICT-0 tree-wide."""
    offenders: list[str] = []
    for path in iter_files(SRC_ROOT):
        rel = relpath(path)
        if rel in _SSOT_FILES:
            continue
        tree = parse_module(path)
        if tree is None:
            continue
        for node in tree.body:  # module-level only, not nested
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if node.name in _TARGET_NAMES:
                    offenders.append(f"{rel}:{node.lineno}  def {node.name}(...)")
    assert not offenders, (
        "N-235 R23 _rows/_row STRICT-0: `def _rows(...)` or `def _row(...)` "
        "at module level outside `db/_helpers.py`. Route through the ONE "
        "SSOT via `from email_triage.db._helpers import _row, _rows`.\n\n"
        + "\n".join(offenders)
    )


def test_ssot_defined_at_helpers():
    """Anti-vacuity: `db/_helpers.py` must define both `_rows` and `_row`.
    If a rename removes them, migrations shipping `import _rows` from
    `_helpers` will import-error at boot."""
    from email_triage.db import _helpers
    assert hasattr(_helpers, "_rows")
    assert hasattr(_helpers, "_row")
    # Sanity math: an empty list → an empty list; None → None.
    assert _helpers._rows([]) == []
    assert _helpers._row(None) is None
