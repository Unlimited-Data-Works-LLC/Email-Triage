"""Persisted-JSON-column decode SSOT pin (divergence census 2026-06-09 ).

A bare ``json.loads(row["x_json"])`` raises ``JSONDecodeError`` on a corrupt
column and takes down the whole page or flow that reads the row. Route every
persisted-column JSON decode through ``db/_helpers.load_json_col(raw, *,
default)`` (NULL/corrupt/wrong-shape → a fresh copy of the default, never a
500).

Count-agnostic, two detection layers (no ``len(X) == N``):

  1. INLINE shape — ``json.loads(<x>.pop("…_json", …))`` /
     ``json.loads(<x>.get("…_json", …))`` / ``json.loads(<row>["…_json"])``,
     the N-16 dual-factory ternary ``json.loads(row["…_json"] if hasattr(row,
     "keys") else row[N])``, and those wrapped in a ``… or "{}"`` NULL-guard.

  2. TAINT-FOLLOW (added 2026-06-09 — this census run surfaced two-line
     instances, so the caveat's promised widening fired). Within ONE function,
     a name assigned from a ``*_json`` column-read shape — ``raw = row["x_json"]``,
     ``raw = d.pop("x_json", …)``, the N-16 ternary ``raw = row["x_json"] if
     hasattr(row, "keys") else row[N]``, OR a helper carrying a ``_json``
     constant arg (``raw = row_get(row, "value_json", 0)``) — taints that name,
     so a later bare ``json.loads(raw)`` is still flagged.

A line-local ``# json-col-ok`` marker (riding ON the flagged line, so it can't
go stale or mis-scope) exempts a site whose custom corrupt-handling the leaf
helper can't replicate — e.g. ``web/db.py`` get_setting logs the offending KEY
and skips the cache; ``integrations.py`` accepts an already-parsed dict that
``load_json_col`` would ``TypeError``→drop.

SCOPE CAVEAT (R38) — what this pin DOES NOT mechanically catch, and why each
known instance was instead HAND-CONVERGED in census  (so the residual is
*future* drift of these shapes, tracked as #16b):

  * **Non-``_json``-named JSON columns.** The whole detector keys on the
    ``_json`` column-name convention. Columns named ``query`` (job descriptor),
    ``adds_labels`` / ``provider_labels`` (list_rules) hold JSON but carry no
    ``_json`` suffix, so neither layer sees them. All known instances were
    routed by hand in  (jobs/topic_backscan.py, web/routers/ui/_shared.py).
    A structural catch would need a column-name registry the schema doesn't
    expose to the AST — #16b.
  * **Bare positional ``row[N]`` ALONE.** ``json.loads(row[0])`` with no keyed
    sibling has no column name at all and is indistinguishable from any tuple
    index. The one known instance (db/accounts.py read-modify-write) was routed
    by hand. (Note: the positional branch of the N-16 *ternary* IS recognised —
    because the keyed ``row["…_json"]`` branch names the column; only a lone
    positional, with no keyed branch anywhere, escapes.)
  * **Migration-time decodes** (web/migrations.py). Frozen historical code that
    runs once at controlled startup; the sites are already corrupt-safe
    (skip-and-continue on a bad row) and are NOT re-routed — editing a migration
    already applied in prod is churn-on-immutable-code for zero behavior gain.
    Now that the IfExp-aware pin SEES them, each carries an explicit line-local
    ``# json-col-ok migration-time (frozen, skip-safe)`` marker, so the
    exclusion is deliberate and visible, not a blind spot.
  * **Cross-function taint** (a name tainted in fn A, ``loads``-ed in fn B) is
    NOT followed — per-function only, to avoid false-positives on the common
    ``raw`` / ``parsed`` names shared with LLM-output / HTTP-body parses.
"""

from __future__ import annotations

import ast

from _pin_harness import SRC_ROOT, iter_src_files, parse_module, relpath as _relpath, parse_source  # N-350 R31

SSOT_REL = "db/_helpers.py"


def _is_json_col_key(v) -> bool:
    return isinstance(v, str) and v.endswith("_json")


def _is_col_read(node: ast.AST) -> bool:
    # <x>.pop("…_json", …) / <x>.get("…_json", …)
    if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and node.func.attr in ("pop", "get") and node.args):
        a0 = node.args[0]
        if isinstance(a0, ast.Constant) and _is_json_col_key(a0.value):
            return True
    # <row>["…_json"]
    if (isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Constant)
            and _is_json_col_key(node.slice.value)):
        return True
    # (<col-read> or "{}") / (<col-read> or "[]") NULL-guard wrappers
    if isinstance(node, ast.BoolOp):
        return any(_is_col_read(v) for v in node.values)
    # The N-16 dual-factory ternary:
    #   row["…_json"] if hasattr(row, "keys") else row[N]
    # Either branch being a col-read makes the whole expression one (the
    # else-branch is a bare positional row[N], deliberately NOT a col-read
    # on its own — see SCOPE CAVEAT — but paired with the keyed branch the
    # idiom is recognised). Catches it both as a taint-assignment value and
    # as a direct json.loads(...) argument.
    if isinstance(node, ast.IfExp):
        return _is_col_read(node.body) or _is_col_read(node.orelse)
    return False


def _is_col_read_call(node: ast.AST) -> bool:
    # A helper call carrying a "…_json" string constant arg, e.g.
    # row_get(row, "value_json", 0) — the assigned name is a column read.
    if isinstance(node, ast.Call):
        for a in list(node.args) + [kw.value for kw in node.keywords]:
            if isinstance(a, ast.Constant) and _is_json_col_key(a.value):
                return True
    return False


def _tainted_col_vars(func: ast.AST) -> set[str]:
    """Names assigned (anywhere in this function) from a column-read shape —
    so a later bare ``json.loads(<name>)`` is still a column decode. Walks
    nested functions too (conservative: over-taints rather than misses)."""
    out: set[str] = set()
    for n in ast.walk(func):
        if (isinstance(n, ast.Assign) and len(n.targets) == 1
                and isinstance(n.targets[0], ast.Name)
                and (_is_col_read(n.value) or _is_col_read_call(n.value))):
            out.add(n.targets[0].id)
    return out


def _is_loads_call(n: ast.AST) -> bool:
    return (isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
            and n.func.attr == "loads"
            and isinstance(n.func.value, ast.Name)
            and n.func.value.id in ("json", "_json") and bool(n.args))


def _loads_arg_is_col(node: ast.Call, tainted: set[str]) -> bool:
    a0 = node.args[0]
    if _is_col_read(a0):  # inline shape
        return True
    names: list[str] = []
    if isinstance(a0, ast.Name):
        names = [a0.id]
    elif isinstance(a0, ast.BoolOp):
        names = [v.id for v in a0.values if isinstance(v, ast.Name)]
    return any(nm in tainted for nm in names)


def _json_col_loads_lines(tree: ast.AST) -> list[int]:
    out: set[int] = set()
    # Function-scoped: inline shape + taint-follow.
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        tainted = _tainted_col_vars(fn)
        for n in ast.walk(fn):
            if _is_loads_call(n) and _loads_arg_is_col(n, tainted):
                out.add(n.lineno)
    # Module-level loads (outside any function): inline shape only.
    for n in ast.walk(tree):
        if _is_loads_call(n) and _is_col_read(n.args[0]):
            out.add(n.lineno)
    return sorted(out)


def test_no_bare_json_col_decode_outside_ssot():
    offenders = []
    for p in iter_src_files():
        if _relpath(p) == SSOT_REL:
            continue
        try:
            text = p.read_text(encoding="utf-8")
            tree = parse_source(text)
        except (SyntaxError, UnicodeDecodeError):  # pragma: no cover
            continue
        src = text.splitlines()
        # The ``# json-col-ok`` marker rides ON the flagged line, so it
        # can't go stale or mis-scope.
        locs = [
            ln for ln in _json_col_loads_lines(tree)
            if "json-col-ok" not in (src[ln - 1] if 0 < ln <= len(src) else "")
        ]
        if locs:
            offenders.append(f"{_relpath(p)}:{locs}")
    assert not offenders, (
        "a bare json.loads of a persisted *_json column outside the "
        f"db/_helpers.load_json_col SSOT (census #16 — corrupt column → 500): "
        f"{offenders}. Use load_json_col(raw, default={{}}/[]) — or, for a "
        "site with custom corrupt-handling, the inline # json-col-ok marker."
    )


def test_ssot_defines_load_json_col():
    tree = parse_module(SRC_ROOT / "db" / "_helpers.py"); assert tree is not None  # N-350 R31
    names = {n.name for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)}
    assert "load_json_col" in names


def test_load_json_col_survives_corruption():
    from email_triage.db._helpers import load_json_col
    assert load_json_col(None, default={}) == {}
    assert load_json_col("", default=[]) == []
    assert load_json_col("not json{", default={}) == {}        # corrupt → default
    assert load_json_col('"null"', default={}) == {}            # wrong shape → default
    assert load_json_col('{"a": 1}', default={}) == {"a": 1}    # valid passes through
    assert load_json_col('[1, 2]', default=[]) == [1, 2]
    # default is a fresh copy (no shared-mutable aliasing)
    d = {}
    out = load_json_col(None, default=d)
    out["x"] = 1
    assert d == {}


def test_pin_has_teeth_inline(tmp_path):
    bad = tmp_path / "m.py"
    bad.write_text(
        "import json\n"
        "def f(d, row):\n"
        "    a = json.loads(d.pop('config_json', '{}'))\n"
        "    b = json.loads(row['results_json'] or '[]')\n",
        encoding="utf-8",
    )
    tree = parse_module(bad); assert tree is not None
    assert len(_json_col_loads_lines(tree)) == 2


def test_pin_has_teeth_taint_follow(tmp_path):
    # Two-line ``raw = row["x_json"]; json.loads(raw)`` and the row_get helper
    # shape — both caught only by the taint-follow layer.
    bad = tmp_path / "t.py"
    bad.write_text(
        "import json as _json\n"
        "def f(row):\n"
        "    raw = row['settings_json']\n"
        "    parsed = _json.loads(raw)\n"            # two-line subscript
        "    val = row_get(row, 'value_json', 0)\n"
        "    other = _json.loads(val)\n"             # helper-call taint
        "    return parsed, other\n",
        encoding="utf-8",
    )
    tree = parse_module(bad); assert tree is not None
    assert len(_json_col_loads_lines(tree)) == 2


def test_pin_has_teeth_ternary(tmp_path):
    # N-16 dual-factory idiom: row["x_json"] if hasattr(row,"keys") else row[N]
    # — caught both as a taint-assignment value AND as a direct loads() arg.
    bad = tmp_path / "tx.py"
    bad.write_text(
        "import json as _json\n"
        "def f(row):\n"
        "    raw = row['descriptor_json'] if hasattr(row, 'keys') else row[0]\n"
        "    return _json.loads(raw or '{}')\n"          # taint via IfExp assignment
        "def g(row):\n"
        "    return _json.loads(\n"
        "        row['x_json'] if hasattr(row, 'keys') else row[0]\n"   # inline IfExp arg
        "    )\n",
        encoding="utf-8",
    )
    tree = parse_module(bad); assert tree is not None
    assert len(_json_col_loads_lines(tree)) == 2


def test_pin_ignores_non_column_loads(tmp_path):
    ok = tmp_path / "p.py"
    ok.write_text(
        "import json\n"
        "def f(raw, resp):\n"
        "    a = json.loads(raw)\n"            # bare param (LLM output etc.) — not a column shape
        "    b = json.loads(resp.text)\n"      # HTTP body — not a column
        "    c = json.loads(resp.read())\n",   # network read — not a column
        encoding="utf-8",
    )
    tree = parse_module(ok); assert tree is not None
    assert not _json_col_loads_lines(tree)


def test_pin_taint_is_per_function(tmp_path):
    # A name tainted in fn A must NOT taint the same name in fn B (where it
    # is an LLM-output param) — per-function scope, no cross-function bleed.
    ok = tmp_path / "q.py"
    ok.write_text(
        "import json\n"
        "def a(row):\n"
        "    raw = row['cfg_json']\n"
        "    return json.loads(raw)\n"         # flagged (tainted in a)
        "def b(raw):\n"
        "    return json.loads(raw)\n",        # NOT flagged (raw is a param in b)
        encoding="utf-8",
    )
    tree = parse_module(ok); assert tree is not None
    lines = _json_col_loads_lines(tree)
    assert len(lines) == 1  # only fn a's site


def test_pin_honors_inline_marker(tmp_path):
    marked = tmp_path / "r.py"
    marked.write_text(
        "import json\n"
        "def f(row):\n"
        "    raw = row['cfg_json']\n"
        "    return json.loads(raw)  # json-col-ok (custom handling)\n",
        encoding="utf-8",
    )
    text = marked.read_text(encoding="utf-8")
    src = text.splitlines()
    locs = [
        ln for ln in _json_col_loads_lines(parse_source(text))
        if "json-col-ok" not in src[ln - 1]
    ]
    assert not locs  # the marker exempts the only hit
