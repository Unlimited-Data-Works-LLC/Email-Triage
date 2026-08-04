""" — naming-lint pin: NON-``_json``-suffixed JSON columns must be REGISTERED.

Census 's decode pin (``tests/test_json_col_decode_pin.py``) keys on the
``_json`` column-name suffix, so a JSON-valued column that does NOT carry that
suffix is invisible to it (the SCOPE CAVEAT documented there at lines ~34-45).
This pin closes that structural blind spot: it AST-scans every ``json.loads(…)``
/ ``load_json_col(…)`` whose argument reads a string-literal column name, and
asserts every NON-``_json`` such column is in an explicit registry below.

Effect: a NEW non-``_json``-named JSON column added in future fails this test
with an actionable message, forcing a conscious choice —
  (a) rename the column to ``*_json`` (then ``test_json_col_decode_pin`` covers
      its SSOT-decode automatically), OR
  (b) add it to ``_REGISTERED_NON_JSON_COLS`` here AND confirm it decodes via
      the ``db/_helpers.load_json_col`` SSOT (corrupt-tolerant), not a bare
      ``json.loads`` (which ``TypeError``/``JSONDecodeError``-crashes on a bad
      row).

Grounding: an empirical tree scan (2026-06-13) found exactly five columns —
the backlog's original "known 3" (``adds_labels`` / ``provider_labels`` /
``query``) was incomplete; ``to_addresses`` (``sent_mail_index``, a JSON
recipient array) and ``transports`` (``users``) were the two this pin surfaced.
Census run17 #7 routed two MORE — ``escalation_lead_pcts``
(``regulatory_clock_def``) and ``folders`` (``discover_runs``) — that this scan
had been BLIND to only because their decode sites used an *aliased* loads
(``json_mod.loads`` / ``_json_decode.loads``) that ``_is_decode_call`` (keyed on
the ``json`` / ``_json`` aliases) never recognised; once routed through
``load_json_col`` they became visible and are now registered. (Residual scope:
the alias-evasion of ``_is_decode_call`` itself — a future ``import json as jm;
jm.loads(row["x"])`` — is still a blind spot, tracked alongside #16b; there is
no live offender at HEAD.) No false positives (the codebase has no noisy
``json.loads(somedict["literal"])`` for non-columns).

A SECOND assertion (run17 #7) closes the other half of this pin's promise:
registration alone was enforced, but the comment-only "decode via load_json_col,
NOT a bare json.loads" half was NOT — so a registered column decoded by a bare
``json.loads`` (the exact ``query`` bypass run17 #7 fixed in profile.py /
embedding_reindex.py) passed silently. ``test_registered_non_json_cols_route_
through_load_json_col`` now makes that a hard failure.
"""

from __future__ import annotations

import ast

from _pin_harness import JSON_DECODE_ALIASES, iter_src_files, parse_module, relpath as _relpath  # N-350 R31

# Every JSON-valued DB column that does NOT use the `_json` suffix. Adding an
# entry is a CONSCIOUS act — pair it with confirming the column decodes via the
# load_json_col SSOT (not a bare json.loads). Remove an entry only when the
# column is gone / renamed (the dead-entry test below keeps this honest).
_REGISTERED_NON_JSON_COLS = frozenset({
    "adds_labels",      # list_rules.adds_labels   (JSON label list)
    "escalation_lead_pcts",  # regulatory_clock_def.escalation_lead_pcts (JSON int %-ladder)
    "folders",          # discover_runs.folders    (JSON folder-name array)
    "provider_labels",  # list_rules.provider_labels (JSON label list)
    "query",            # triage_jobs.query        (JSON job descriptor)
    "to_addresses",     # sent_mail_index.to_addresses (JSON recipient array)
    "transports",       # users.transports         (JSON transport config)
})

_SSOT_REL = "db/_helpers.py"


def _col_name(node: ast.AST):
    """Return the string column name from a column-read shape, else None.
    Mirrors the shapes ``test_json_col_decode_pin._is_col_read`` recognises."""
    if (isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Constant)
            and isinstance(node.slice.value, str)):
        return node.slice.value
    if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and node.func.attr in ("pop", "get") and node.args):
        a0 = node.args[0]
        if isinstance(a0, ast.Constant) and isinstance(a0.value, str):
            return a0.value
    if isinstance(node, ast.BoolOp):          # (col-read or "{}") guards
        for v in node.values:
            nm = _col_name(v)
            if nm:
                return nm
    if isinstance(node, ast.IfExp):           # N-16 dual-factory ternary
        return _col_name(node.body) or _col_name(node.orelse)
    return None


def _is_decode_call(n: ast.AST) -> bool:
    """``json.loads(…)`` / ``load_json_col(…)`` with >=1 positional arg."""
    if not (isinstance(n, ast.Call) and n.args):
        return False
    f = n.func
    if (isinstance(f, ast.Attribute) and f.attr == "loads"
            and isinstance(f.value, ast.Name) and f.value.id in JSON_DECODE_ALIASES):
        return True
    if isinstance(f, ast.Name) and f.id == "load_json_col":
        return True
    if isinstance(f, ast.Attribute) and f.attr == "load_json_col":
        return True
    return False


def _scan_non_json_decode_cols() -> dict[str, str]:
    """col-name -> 'relpath:lineno' for every non-_json column fed to a decode."""
    found: dict[str, str] = {}
    for p in iter_src_files():
        if _relpath(p) == _SSOT_REL:
            continue
        try:
            tree = parse_module(p); assert tree is not None  # N-350 R31
        except (SyntaxError, UnicodeDecodeError):  # pragma: no cover
            continue
        for fn in ast.walk(tree):
            if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            # taint: ``name = <col-read>`` -> name carries that column name.
            taint: dict[str, str] = {}
            for nd in ast.walk(fn):
                if (isinstance(nd, ast.Assign) and len(nd.targets) == 1
                        and isinstance(nd.targets[0], ast.Name)):
                    nm = _col_name(nd.value)
                    if nm:
                        taint[nd.targets[0].id] = nm
            for nd in ast.walk(fn):
                if not _is_decode_call(nd):
                    continue
                a0 = nd.args[0]
                col = _col_name(a0)
                if col is None and isinstance(a0, ast.Name):
                    col = taint.get(a0.id)
                if col and not col.endswith("_json"):
                    found.setdefault(col, f"{_relpath(p)}:{nd.lineno}")
    return found


def test_non_json_suffixed_json_columns_are_registered():
    found = _scan_non_json_decode_cols()
    unregistered = {c: loc for c, loc in found.items()
                    if c not in _REGISTERED_NON_JSON_COLS}
    assert not unregistered, (
        "Non-`_json`-suffixed JSON column(s) decoded but NOT registered "
        f": {unregistered}.\n"
        "Either rename the column to `*_json` (then test_json_col_decode_pin "
        "covers its SSOT decode automatically), OR add it to "
        "_REGISTERED_NON_JSON_COLS in this file AND confirm it decodes via the "
        "db/_helpers.load_json_col SSOT (corrupt-tolerant), not a bare json.loads."
    )


def test_registry_has_no_dead_entries():
    """Keep the registry honest: every registered column must still be decoded
    somewhere — a stale entry should be removed so the registry reflects HEAD."""
    found = set(_scan_non_json_decode_cols())
    dead = sorted(_REGISTERED_NON_JSON_COLS - found)
    assert not dead, (
        f"Registered non-`_json` JSON column(s) no longer decoded anywhere "
        f"(stale  registry entries): {dead}. Remove them from "
        "_REGISTERED_NON_JSON_COLS."
    )


# --------------------------------------------------------------------------- #
# run17 #7 — registered columns must DECODE via the load_json_col SSOT,
# not a bare json.loads. The registration check above proves a non-`_json` JSON
# column is KNOWN; this proves it is HANDLED corrupt-tolerantly (a corrupt
# column degrades to the default, never a 500). Without it, a registered
# column's bare ``json.loads(row["query"])`` passed silently — the exact gap
# run17 #7 closed in profile.py / embedding_reindex.py.
# --------------------------------------------------------------------------- #

def _is_bare_json_loads(n: ast.AST) -> bool:
    """``json.loads(...)`` / ``_json.loads(...)`` — NOT ``load_json_col(...)``.
    Mirrors ``test_json_col_decode_pin._is_loads_call`` (kept in sync by the
    sibling pins' shared ``json`` / ``_json`` alias convention)."""
    return (isinstance(n, ast.Call) and bool(n.args)
            and isinstance(n.func, ast.Attribute) and n.func.attr == "loads"
            and isinstance(n.func.value, ast.Name)
            and n.func.value.id in JSON_DECODE_ALIASES)


def _registered_bare_loads_in_tree(tree: ast.AST, lines: list[str]) -> dict[str, int]:
    """col-name -> lineno for a REGISTERED non-`_json` column fed to a BARE
    json.loads in this tree. Honours a line-local ``# json-col-ok`` marker (a
    site with custom corrupt-handling). col-resolution mirrors
    ``_scan_non_json_decode_cols`` (inline shape + per-function Name taint)."""
    found: dict[str, int] = {}
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        taint: dict[str, str] = {}
        for nd in ast.walk(fn):
            if (isinstance(nd, ast.Assign) and len(nd.targets) == 1
                    and isinstance(nd.targets[0], ast.Name)):
                nm = _col_name(nd.value)
                if nm:
                    taint[nd.targets[0].id] = nm
        for nd in ast.walk(fn):
            if not _is_bare_json_loads(nd):
                continue
            a0 = nd.args[0]
            col = _col_name(a0)
            if col is None and isinstance(a0, ast.Name):
                col = taint.get(a0.id)
            if not (col and not col.endswith("_json")
                    and col in _REGISTERED_NON_JSON_COLS):
                continue
            ln = nd.lineno
            marker_line = lines[ln - 1] if 0 < ln <= len(lines) else ""
            if "json-col-ok" in marker_line:
                continue
            found.setdefault(col, ln)
    return found


def _scan_registered_bare_loads() -> dict[str, str]:
    """col-name -> 'relpath:lineno' for every registered non-`_json` column
    decoded by a bare json.loads (bypassing the load_json_col SSOT)."""
    out: dict[str, str] = {}
    for p in iter_src_files():
        if _relpath(p) == _SSOT_REL:
            continue
        try:
            source_text = p.read_text(encoding="utf-8")
        except UnicodeDecodeError:  # pragma: no cover
            continue
        tree = parse_module(p)
        if tree is None:  # pragma: no cover
            continue
        for col, ln in _registered_bare_loads_in_tree(tree, source_text.splitlines()).items():
            out.setdefault(col, f"{_relpath(p)}:{ln}")
    return out


def test_registered_non_json_cols_route_through_load_json_col():
    offenders = _scan_registered_bare_loads()
    assert not offenders, (
        "Registered non-`_json` JSON column(s) decoded by a BARE json.loads "
        "instead of the db/_helpers.load_json_col SSOT ( / census #16b — a "
        f"corrupt column → 500): {offenders}. Route through "
        "load_json_col(raw, default={}/[]) — or, for a site with custom "
        "corrupt-handling, add the inline # json-col-ok marker."
    )


def test_registered_enforce_pin_has_teeth():
    # BAD: a registered column (`query`) via a bare json.loads — must flag.
    bad = ast.parse(
        "import json\n"
        "def f(row):\n"
        "    return json.loads(row['query'] or '{}')\n"
    )
    assert _registered_bare_loads_in_tree(bad, []) == {"query": 3}
    # GOOD-1: same column via the load_json_col SSOT — must NOT flag.
    ok1 = ast.parse(
        "def f(row):\n"
        "    return load_json_col(row['query'], default={})\n"
    )
    assert not _registered_bare_loads_in_tree(ok1, [])
    # GOOD-2: an UNregistered literal (not a JSON column) via bare loads — the
    # registration test owns that; this enforce-test only covers registered cols.
    ok2 = ast.parse(
        "import json\n"
        "def f(d):\n"
        "    return json.loads(d['not_a_registered_col'])\n"
    )
    assert not _registered_bare_loads_in_tree(ok2, [])
    # GOOD-3: a bare json.loads of a registered col carrying the inline marker.
    src = (
        "import json\n"
        "def f(row):\n"
        "    return json.loads(row['query'])  # json-col-ok (custom handling)\n"
    )
    assert not _registered_bare_loads_in_tree(ast.parse(src), src.splitlines())
