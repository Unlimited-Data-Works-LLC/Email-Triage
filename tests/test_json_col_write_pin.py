"""json-col WRITE pin — the SSOT twin of ``test_load_json_col_pin`` (run18 #4,
census  write-side).

``db/_helpers.dump_json_col`` is the WRITE twin of ``load_json_col``: every
PLAIN-STORE ``*_json`` DB-column write routes through it so the on-write
serialization (notably ``ensure_ascii=False`` — compact UTF-8 for non-Latin
PHI, not ``\\uXXXX`` bloat) lives in ONE place instead of ~60 hand-rolled
``json.dumps(...)`` sites that were each free to drift in their kwargs. The
read side already pins this (decode-pin + naming-pin + name-pin); without a
write twin a new ``*_json``-column writer silently re-forks the serialization.

What this pins
--------------
A ``json.dumps``/``_json.dumps`` Call whose result is written into a
``*_json``-suffixed DB column must route through ``dump_json_col`` — EXCEPT the
hash/HMAC-adjacent allow-list. A flagged site is resolved by ROUTING (after
which it is ``dump_json_col(...)`` — no longer a ``json.dumps`` — and this pin
no longer sees it), or by an ``_ALLOWLIST`` entry for a hash-preimage site whose
byte output must NOT change (re-keying it forks the audit SHA/HMAC chain — the
opposite of a fix).

Two count-agnostic detection signals (a dumps is flagged under EITHER):

  * **Signal A — SQL column alignment.** The dumps result (inline, OR via a
    same-scope ``x = json.dumps(...)`` local — the dumps→[local]→column-param
    hop) sits at params-position *i* of a ``.execute/.executemany(SQL_lit,
    params_tuple)`` whose INSERT/UPDATE *i*-th ``?`` column ends ``_json``.
    This is the WRITE mirror of the decode-pin's ``row["x_json"]`` column-name
    key (the column name lives in the SQL, not at the dumps site).
  * **Signal B — ``_json`` binding NAME.** The dumps result is bound to a
    ``*_json``-suffixed target: a local ``x_json = json.dumps(...)`` (the
    convention used when the value is then handed to a dynamic/cross-fn
    writer — engine/store dict snapshot, topic_configs locals), a ``*_json``
    dict string-key, or a ``*_json`` kwarg. This is the WRITE mirror of the
    name-pin's ``*_json``-suffixed-NAME key, and catches the dynamic-SQL /
    cross-function shapes Signal A's literal-params alignment can't reach.

Both signals UNWRAP a guard wrapper — an ``X or "{}"`` BoolOp and an
``json.dumps(x) if x else "{}"`` IfExp — to find the dumps (mirrors the read
pins' ``_unwrap_or`` / N-16 ternary handling), so a guarded extra_json write is
still seen (and then allow-listed).

Scope + exclusions (honest, per R38)
------------------------------------
  * **``*_json``-COLUMN scope.** Non-``_json``-suffixed JSON columns
    (``config``→``config_json`` IS in scope; ``to_addresses`` / ``transports``
    / ``query`` / ``adds_labels`` / ``provider_labels`` / ``folders`` /
    ``escalation_lead_pcts`` are NOT) are the registered-non-``_json`` family
    the READ-side naming-pin governs; routing their writers through
    ``dump_json_col`` is a deliberate FOLLOW-ON, tracked separately. This pin
    deliberately does not flag them (it would need a column-name oracle the
    write side can't cheaply build for every dynamic write).
  * **``@register`` migration bodies are EXCLUDED.** A shipped migration body is
    CHECKSUM-FROZEN (``incident_2026-06-11_migration_body_immutability``) and
    runs BOOT-only single-threaded; its ``json.dumps`` is byte-frozen and must
    NOT be edited. SSOT sweeps exclude ``@register`` — so does this one.
  * **Helper-return encoders are a Signal-A/B blind spot (routed anyway).** A
    ``def _encode(...) -> str: return json.dumps(...)`` whose result is stored
    cross-function (``engine/store._cls_to_json`` → classification_json,
    ``web/db._encode_backup_models`` → backup_models_json) is invisible to both
    signals (the dumps is a bare ``return``, not a column-param or ``_json``
    binding). Those two were ROUTED by hand at build time; a NEW such helper
    would slip until its writer is itself a flagged shape. Documented, not
    silently dropped.
  * **Alias evasion.** Keys on the ``json`` / ``_json`` / ``json_mod`` /
    ``_json_decode`` aliases (the shared ``JSON_DECODE_ALIASES``); a future
    ``import json as jm; jm.dumps(...)`` would slip. No live offender at HEAD.

Harness reuse (the iron rule)
-----------------------------
Built on ``tests/_pin_harness`` (``iter_src_files`` / ``parse_module`` /
``relpath`` / ``enclosing_fn`` / ``JSON_DECODE_ALIASES`` / ``parse_source``) —
the ONE shared structural-pin scaffold, so this pin can't drift in its scoping
(R5b/R6). The interprocedural dumps→[local]→param taint follows
``test_no_unguarded_secret_write._scan``'s in-scope single-hop taint pattern
(re-implemented for the dumps→column shape rather than the form→secrets.set
shape — the harness convergence point is ``_pin_harness``, not the
secrets-specific ``_scan`` body).
"""

from __future__ import annotations

import ast
import re

from _pin_harness import (
    JSON_DECODE_ALIASES,
    enclosing_fn,
    iter_src_files,
    parse_module,
    parse_source,
    relpath,
)

SSOT_REL = "db/_helpers.py"

# (relpath, enclosing_fn) -> reason. A ``*_json``-column write whose byte output
# is a SHA-256 / HMAC preimage: re-keying it through dump_json_col would fork the
# audit chain (the OPPOSITE of the fix). These keep a bare json.dumps.
_ALLOWLIST: dict[tuple[str, str], str] = {
    ("db/audit.py", "insert_log_entry"):
        "extra_json is the log_entries HMAC preimage — redact-then-dumps is fed "
        "verbatim to compute_log_row_hash AND stored (store == the hashed "
        "string); re-keying it would fork the H-02 HMAC chain.",
    ("triage_logging.py", "emit"):
        "SQLiteLogHandler.emit builds extra_json as the hot-path HMAC preimage "
        "(hash == store, run17 #1) and the gap-sentinel row's extra_json on the "
        "same chained log_entries column — both must stay a bare json.dumps.",
}


# --------------------------------------------------------------------------- #
# dumps detection (alias-aware, guard-unwrapping)
# --------------------------------------------------------------------------- #

def _is_dumps(n: ast.AST) -> bool:
    """``<alias>.dumps(...)`` with >=1 positional arg, alias in the shared set."""
    return (isinstance(n, ast.Call) and bool(n.args)
            and isinstance(n.func, ast.Attribute) and n.func.attr == "dumps"
            and isinstance(n.func.value, ast.Name)
            and n.func.value.id in JSON_DECODE_ALIASES)


def _dumps_in(expr: ast.AST) -> list[ast.Call]:
    """The dumps Call node(s) reachable from ``expr`` by unwrapping ONLY a guard
    wrapper — a direct dumps, an ``IfExp`` (``dumps(x) if c else "{}"``), or a
    ``BoolOp`` (``dumps(x) or "{}"``). Does NOT descend into arbitrary
    sub-expressions (a dumps buried in an unrelated call arg is not a column
    binding)."""
    if _is_dumps(expr):
        return [expr]  # type: ignore[list-item]
    if isinstance(expr, ast.IfExp):
        return _dumps_in(expr.body) + _dumps_in(expr.orelse)
    if isinstance(expr, ast.BoolOp):
        out: list[ast.Call] = []
        for v in expr.values:
            out += _dumps_in(v)
        return out
    return []


# --------------------------------------------------------------------------- #
# SQL ``?``-placeholder → column-name alignment (Signal A)
# --------------------------------------------------------------------------- #

def _split_top(s: str) -> list[str]:
    """Split on top-level commas (ignoring parens / quotes)."""
    out: list[str] = []
    depth = 0
    cur: list[str] = []
    q: str | None = None
    for ch in s:
        if q:
            cur.append(ch)
            if ch == q:
                q = None
            continue
        if ch in "'\"":
            q = ch
            cur.append(ch)
        elif ch in "([":
            depth += 1
            cur.append(ch)
        elif ch in ")]":
            depth -= 1
            cur.append(ch)
        elif ch == "," and depth == 0:
            out.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    if cur:
        out.append("".join(cur))
    return [x.strip() for x in out]


def _strip_col(c: str) -> str:
    return c.strip().strip('"').strip("`")


def _insert_ph_cols(sql: str) -> list[str | None] | None:
    """Ordered column for each ``?`` in an ``INSERT ... (cols) VALUES (...)`` —
    aligns the VALUES slots to the column list, skipping literal (non-``?``)
    value slots so a ``VALUES (?, ?, 0, ?)`` maps params correctly."""
    m = re.search(r"INSERT\s+INTO\s+[\w.\"]+\s*\(([^)]*)\)\s*VALUES\s*\((.*)\)",
                  sql, re.I | re.S)
    if not m:
        return None
    cols = [_strip_col(c) for c in _split_top(m.group(1))]
    out: list[str | None] = []
    for j, v in enumerate(_split_top(m.group(2))):
        if v.strip() == "?":
            out.append(cols[j] if j < len(cols) else None)
    return out


def _update_ph_cols(sql: str) -> list[str] | None:
    """Ordered column for each ``?`` in the SET clause of an ``UPDATE`` (the SET
    ``?``s bind params[0:k]; trailing WHERE ``?``s are not JSON columns)."""
    m = re.search(r"UPDATE\s+[\w.\"]+\s+SET\s+(.*?)(?:\sWHERE\s.*)?$",
                  sql, re.I | re.S)
    if not m:
        return None
    out: list[str] = []
    for a in _split_top(m.group(1)):
        if "=" not in a:
            continue
        col, _, rhs = a.partition("=")
        if rhs.strip() == "?":
            out.append(_strip_col(col))
    return out


def _ph_cols(sql: str) -> list[str | None] | None:
    head = sql.lstrip()[:6].upper()
    if head.startswith("INSERT"):
        return _insert_ph_cols(sql)
    if head.startswith("UPDATE"):
        return _update_ph_cols(sql)
    return None


def _const_str(node: ast.AST, str_consts: dict[str, str]) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Name):
        return str_consts.get(node.id)
    return None


# --------------------------------------------------------------------------- #
# @register migration-body exclusion (checksum-frozen — never edit)
# --------------------------------------------------------------------------- #

def _is_register_decorated(fn: ast.AST) -> bool:
    for d in getattr(fn, "decorator_list", []):
        f = d.func if isinstance(d, ast.Call) else d
        name = (f.id if isinstance(f, ast.Name)
                else f.attr if isinstance(f, ast.Attribute) else None)
        if name == "register":
            return True
    return False


def _in_registered_migration(node: ast.AST) -> bool:
    cur = getattr(node, "_ph_parent", None)
    while cur is not None:
        if isinstance(cur, (ast.FunctionDef, ast.AsyncFunctionDef)) \
                and _is_register_decorated(cur):
            return True
        cur = getattr(cur, "_ph_parent", None)
    return False


# --------------------------------------------------------------------------- #
# the detector — flagged dumps nodes in one parsed (+parent-annotated) tree
# --------------------------------------------------------------------------- #

def _flagged_dumps(tree: ast.AST) -> dict[int, ast.Call]:
    """``id(dumps_node) -> dumps_node`` for every json.dumps writing a ``*_json``
    column in this tree, under Signal A (SQL alignment) OR Signal B (``_json``
    binding name). Deduped by node identity (a site can match both signals)."""
    funcs = [n for n in ast.walk(tree)
             if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
    scopes: list[ast.AST] = [*funcs, tree]
    flagged: dict[int, ast.Call] = {}

    for scope in scopes:
        str_consts: dict[str, str] = {}
        dumps_locals: dict[str, ast.Call] = {}  # name -> dumps node (1-hop taint)
        for nd in ast.walk(scope):
            if isinstance(nd, ast.Assign) and len(nd.targets) == 1 \
                    and isinstance(nd.targets[0], ast.Name):
                if isinstance(nd.value, ast.Constant) and isinstance(nd.value.value, str):
                    str_consts[nd.targets[0].id] = nd.value.value
                ds = _dumps_in(nd.value)
                if ds:
                    dumps_locals[nd.targets[0].id] = ds[0]

        # Signal B — *_json binding NAME (local / dict-key / kwarg).
        for nd in ast.walk(scope):
            if isinstance(nd, ast.Assign):
                if any(isinstance(t, ast.Name) and t.id.endswith("_json")
                       for t in nd.targets):
                    for d in _dumps_in(nd.value):
                        flagged[id(d)] = d
            elif isinstance(nd, ast.AnnAssign) and nd.value is not None \
                    and isinstance(nd.target, ast.Name) and nd.target.id.endswith("_json"):
                for d in _dumps_in(nd.value):
                    flagged[id(d)] = d
            elif isinstance(nd, ast.NamedExpr) \
                    and isinstance(nd.target, ast.Name) and nd.target.id.endswith("_json"):
                for d in _dumps_in(nd.value):
                    flagged[id(d)] = d
            elif isinstance(nd, ast.Dict):
                for k, v in zip(nd.keys, nd.values):
                    if isinstance(k, ast.Constant) and isinstance(k.value, str) \
                            and k.value.endswith("_json"):
                        for d in _dumps_in(v):
                            flagged[id(d)] = d
            elif isinstance(nd, ast.Call):
                for kw in nd.keywords:
                    if kw.arg and kw.arg.endswith("_json"):
                        for d in _dumps_in(kw.value):
                            flagged[id(d)] = d

        # Signal A — SQL column alignment of an execute params tuple.
        for nd in ast.walk(scope):
            if not (isinstance(nd, ast.Call) and isinstance(nd.func, ast.Attribute)
                    and nd.func.attr in ("execute", "executemany")):
                continue
            if len(nd.args) < 2:
                continue
            sql = _const_str(nd.args[0], str_consts)
            if sql is None:
                continue
            cols = _ph_cols(sql)
            if not cols:
                continue
            params = nd.args[1]
            if not isinstance(params, (ast.Tuple, ast.List)):
                continue
            for i, el in enumerate(params.elts):
                if i >= len(cols):
                    break
                col = cols[i]
                if not (col and col.endswith("_json")):
                    continue
                inline = _dumps_in(el)
                if inline:
                    for d in inline:
                        flagged[id(d)] = d
                elif isinstance(el, ast.Name) and el.id in dumps_locals:
                    d = dumps_locals[el.id]
                    flagged[id(d)] = d

    return flagged


def _violations_in_tree(tree: ast.AST) -> list[tuple[str, int]]:
    """(enclosing_fn, lineno) for every flagged dumps NOT in a @register
    migration body. (Allow-list filtering is applied by the repo scan, which
    has the relpath.)"""
    out: list[tuple[str, int]] = []
    for d in _flagged_dumps(tree).values():
        if _in_registered_migration(d):
            continue
        out.append((enclosing_fn(d), d.lineno))
    return out


def _scan() -> tuple[list[tuple[str, str, int]], set[tuple[str, str]]]:
    """(violations, matched_allowlist) over src. A violation is a flagged
    ``*_json``-column json.dumps outside the SSOT, not in a @register body, and
    not allow-listed. ``matched_allowlist`` is the set of allow-list keys that
    actually fired (for the stale-entry guard)."""
    violations: list[tuple[str, str, int]] = []
    matched: set[tuple[str, str]] = set()
    for p in iter_src_files():
        rel = relpath(p)
        if rel == SSOT_REL:
            continue
        tree = parse_module(p)
        if tree is None:  # pragma: no cover
            continue
        for fn, lineno in _violations_in_tree(tree):
            key = (rel, fn)
            if key in _ALLOWLIST:
                matched.add(key)
                continue
            violations.append((rel, fn, lineno))
    return violations, matched


# --------------------------------------------------------------------------- #
# the pins
# --------------------------------------------------------------------------- #

def test_json_col_writes_route_through_dump_json_col():
    violations, _matched = _scan()
    assert not violations, (
        "A `*_json` DB-column write uses a bare json.dumps instead of the "
        "db/_helpers.dump_json_col SSOT (run18 #4 / census  write-side — "
        "ensure_ascii / serialization drift across ~60 sites):\n"
        + "\n".join(f"  {rel}::{fn} (line {ln})" for rel, fn, ln in violations)
        + "\n\nFix: route through dump_json_col(obj) (ensure_ascii=False, "
        "multilingual; round-trips through load_json_col unchanged). Only add "
        "to _ALLOWLIST if the value is a SHA/HMAC preimage whose bytes must NOT "
        "change (re-keying forks the audit chain) — with a one-line reason."
    )


def test_write_pin_allowlist_is_not_stale():
    """Every _ALLOWLIST entry must still name a real flagged ``*_json`` write —
    a routed/removed hash site must drop its entry so the allow-list stays
    honest (R38)."""
    _violations, matched = _scan()
    stale = set(_ALLOWLIST) - matched
    assert not stale, (
        "Stale _ALLOWLIST entr(ies) — no flagged `*_json`-column json.dumps "
        f"remains in these functions; remove them: {sorted(stale)}."
    )


def test_ssot_dump_json_col_importable_and_multilingual():
    from email_triage.db._helpers import dump_json_col, load_json_col

    # ensure_ascii=False — non-Latin stored as compact UTF-8, not \\uXXXX.
    out = dump_json_col({"name": "李华", "tag": "café"})
    assert "\\u" not in out
    assert "李华" in out and "café" in out
    # round-trips through the read SSOT unchanged.
    assert load_json_col(out, default={}) == {"name": "李华", "tag": "café"}
    # ASCII payload is byte-identical to a plain dumps (no churn for old rows).
    import json
    assert dump_json_col([1, "a", True]) == json.dumps([1, "a", True])
    # default container shapes round-trip.
    assert load_json_col(dump_json_col([]), default=[]) == []
    assert load_json_col(dump_json_col({}), default={}) == {}


# --------------------------------------------------------------------------- #
# teeth
# --------------------------------------------------------------------------- #

def test_pin_has_teeth_signal_a_inline():
    # BAD: inline json.dumps at a *_json INSERT column position.
    bad = parse_source(
        "import json\n"
        "def f(conn, cfg):\n"
        "    conn.execute(\n"
        "        'INSERT INTO t (id, config_json) VALUES (?, ?)',\n"
        "        (1, json.dumps(cfg)),\n"
        "    )\n"
    )
    assert _violations_in_tree(bad), "missed inline dumps into a _json column"
    # BAD-2: UPDATE SET col_json = ? via a dumps-local (the dumps→local→param hop).
    bad2 = parse_source(
        "import json\n"
        "def f(conn, v, rid):\n"
        "    val_json = json.dumps(v)\n"
        "    conn.execute('UPDATE t SET val_json = ? WHERE id = ?', (val_json, rid))\n"
    )
    assert _violations_in_tree(bad2), "missed dumps-local routed to a _json column"


def test_pin_has_teeth_signal_b_and_guard_unwrap():
    # BAD: *_json local binding (the topic_configs / email_watches convention).
    bad = parse_source(
        "import json\n"
        "def f(w):\n"
        "    filter_json = json.dumps(w)\n"
        "    return filter_json\n"
    )
    assert _violations_in_tree(bad), "missed a *_json-named local binding"
    # BAD-2: *_json dict-key (the engine/store snapshot shape).
    bad2 = parse_source(
        "import json\n"
        "def f(flow):\n"
        "    return {'state_bag_json': json.dumps(flow.state_bag)}\n"
    )
    assert _violations_in_tree(bad2), "missed a *_json dict-key binding"
    # BAD-3: an IfExp-GUARDED dumps bound to a *_json name (the extra_json shape)
    # — proves the guard unwrap (so the HMAC sites are SEEN and then allow-listed,
    # not silently invisible).
    bad3 = parse_source(
        "import json\n"
        "def f(extra):\n"
        "    extra_json = json.dumps(extra) if extra else '{}'\n"
        "    return extra_json\n"
    )
    assert _violations_in_tree(bad3), "guard-unwrap missed an IfExp-guarded dumps"


def test_pin_no_false_positive():
    # GOOD-1: routed through the SSOT — not a json.dumps, invisible here.
    ok1 = parse_source(
        "def f(conn, cfg):\n"
        "    conn.execute('INSERT INTO t (config_json) VALUES (?)', (dump_json_col(cfg),))\n"
    )
    assert not _violations_in_tree(ok1)
    # GOOD-2: a NON-_json column (registered-non-_json family — read-side's job).
    ok2 = parse_source(
        "import json\n"
        "def f(conn, terms, rid):\n"
        "    conn.execute('UPDATE t SET to_addresses = ? WHERE id = ?', (json.dumps(terms), rid))\n"
    )
    assert not _violations_in_tree(ok2)
    # GOOD-3: a dumps for an HTTP body / hash / log line (no execute, no _json name).
    ok3 = parse_source(
        "import json, hashlib\n"
        "def f(payload):\n"
        "    body = json.dumps(payload, separators=(',', ':')).encode()\n"
        "    h = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()\n"
        "    return body, h\n"
    )
    assert not _violations_in_tree(ok3)


def test_pin_excludes_register_migration_bodies():
    # A @register migration body is checksum-frozen — its dumps is NOT a
    # violation (must be excluded, never edited).
    mig = parse_source(
        "import json\n"
        "@register(7, 'backfill')\n"
        "def _v7_backfill(conn):\n"
        "    conn.execute('UPDATE t SET config_json = ? WHERE id = ?', (json.dumps({}), 1))\n"
    )
    assert not _violations_in_tree(mig), "must not flag a @register migration body"
