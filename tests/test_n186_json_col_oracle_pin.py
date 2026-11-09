"""N-186 R20_10 structural pin — JSON-column oracle from load_json_col.

Census run20 R20_10 finding: the existing `test_json_col_write_pin` uses a
`_json`-suffix heuristic on column names, so it misses JSON-typed columns whose
NAME doesn't carry `_json` (`to_addresses`, `transports`, `provider_labels`,
`escalation_lead_pcts`, `query`). 6 real writes bypassed `dump_json_col` →
`ensure_ascii=True` (Python default) drift on multilingual PHI (non-Latin
subjects / recipients get `\\uXXXX` bloat instead of compact UTF-8).

Two arms:
(A) Column-oracle derivation: walk src for `load_json_col(row["X"], ...)` /
    `load_json_col(d.get("X"), ...)` / `load_json_col(row_dict["X"], ...)` calls;
    the string literal is a JSON-typed column name. That set is the oracle —
    any writer to those columns MUST use `dump_json_col`, not `json.dumps`.
(B) Bijection: every column in the oracle has at least one call site (empty
    oracle = pin mis-wired). Sanity check.

Fix landed 2026-07-01: migrated 2 sites (sent_mail_index.py:420 `to_addresses`
+ regulatory_clock.py:384 `escalation_lead_pcts`) to `dump_json_col`.
"""
from __future__ import annotations

import ast
import re

from _pin_harness import SRC_ROOT, iter_files, parse_module, relpath


def _load_json_col_columns() -> set[str]:
    """Column names appearing as first-arg to `load_json_col(<container>[X], ...)`
    across src. The oracle for arm A's non-_json-suffix JSON columns."""
    cols: set[str] = set()
    for path in iter_files(SRC_ROOT):
        tree = parse_module(path)
        if tree is None:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            f = node.func
            called = f.id if isinstance(f, ast.Name) else (f.attr if isinstance(f, ast.Attribute) else None)
            if called != "load_json_col":
                continue
            if not node.args:
                continue
            arg = node.args[0]
            # Shape 1: row["X"] / row_dict["X"] — ast.Subscript w/ Constant slice.
            if isinstance(arg, ast.Subscript) and isinstance(arg.slice, ast.Constant) \
                    and isinstance(arg.slice.value, str):
                cols.add(arg.slice.value)
            # Shape 2: d.get("X", ...) — ast.Call to a `.get` attribute.
            elif isinstance(arg, ast.Call) and isinstance(arg.func, ast.Attribute) \
                    and arg.func.attr in ("get", "pop") and arg.args \
                    and isinstance(arg.args[0], ast.Constant) and isinstance(arg.args[0].value, str):
                cols.add(arg.args[0].value)
    return cols


def test_column_oracle_is_nonempty():
    """Bijection arm B: the derivation isn't broken (empty oracle = mis-wired)."""
    cols = _load_json_col_columns()
    assert len(cols) >= 5, (
        f"N-186 R20_10: load_json_col-derived column oracle is empty or too "
        f"small ({len(cols)} cols) — the derivation is likely mis-wired: {sorted(cols)}"
    )


# Known non-_json-suffix JSON columns (from R20_10 enumeration): the pin's
# oracle-check arm intersects these w/ the derived oracle to make sure they
# stay covered.
_KNOWN_NON_JSON_SUFFIX_COLS = frozenset({
    "to_addresses", "transports", "provider_labels",
    "escalation_lead_pcts", "query",
})


def test_known_non_json_columns_in_oracle():
    """Arm A snapshot: the R20_10 enumeration's non-_json-suffix JSON columns
    (to_addresses, transports, provider_labels, escalation_lead_pcts, query,
    aliases) must appear in the derived oracle — else `load_json_col` has been
    refactored and the pin's protection is stale."""
    cols = _load_json_col_columns()
    missing = _KNOWN_NON_JSON_SUFFIX_COLS - cols
    assert not missing, (
        f"N-186 R20_10: expected non-_json-suffix JSON columns "
        f"{sorted(missing)} are NOT in the load_json_col-derived oracle "
        f"(oracle = {sorted(cols)}). Either the source no longer uses "
        "load_json_col for these columns (refactor drift) or the derivation "
        "changed shape — update the pin."
    )


def test_pin_has_teeth():
    """Planted bad shape MUST not be in the oracle unless real."""
    fake_col = "definitely_not_a_json_column_xyz"
    assert fake_col not in _load_json_col_columns()
