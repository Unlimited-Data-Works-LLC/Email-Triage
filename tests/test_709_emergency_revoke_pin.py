"""Punch 709: structural pins over the emergency revoke (db/audit.py, web/auth.py, web/routers/health.py).

The operator decided (2026-11-02 8:13 PM) that a compromised key must be stoppable when the HMAC
audit chain is broken, by an explicit, alarmed path that gives up the chained record of that one
event. Behaviour is pinned by ``tests/test_web/test_punch709_emergency_revoke.py``; this file pins the
SHAPE, so a later change cannot turn the emergency path into a silent fallback. Each property is read
over src on the shared harness (``_pin_harness.walk_src`` / ``docstring_constant_ids`` /
``assert_pin_has_teeth``) and has teeth:

1. FLAG: every function in src that calls ``record_emergency_revoke`` takes ``emergency_reason`` as a
   keyword-only parameter defaulting to None, validates it with ``check_emergency_reason``, makes the
   call only under an ``is not None`` guard, and opens its ``emergency_reason is not None`` branch with
   ``check_emergency_actor`` (enabled admin or the host CLI, PD-9) as the FIRST statement, ahead of its
   first SQL write (lead ruling 2026-11-03). No default-on path, no unvalidated reason or actor.
2. ONE FUNNEL PER EDGE (PD-18): the marker path is touched only inside db/audit.py; its write is in
   ``record_emergency_revoke`` alone and its removal in ``clear_emergency_revoke`` alone.
3. ONE WRITER PER EDGE ROW: the literal ``"emergency_revoke"`` (the set edge's helper name) and
   ``"emergency_revoke_cleared"`` (the clear edge's) each appear in no module but db/audit.py, and
   there only in their own edge function.
4. HEALTH: ``/health/detail``'s ``degraded`` expression reads ``emergency_revoke_pending``.
5. CLEAR RECORDED FIRST: ``clear_emergency_revoke`` writes its ``emergency_revoke_cleared`` row through
   ``_write_audit_gap_event`` before any ``unlink``, inside a ``try`` whose every handler returns, so a
   failed row never falls through to removing the marker (fail closed). Its FIRST statement is the same
   ``check_emergency_actor`` gate as the revoke (cycle P DA P709g S1, PD-9).
6. CLI ONLY (cycle P hipaa S1, DA P709g NOTE; PD-9, PD-2): ``source == "cli"`` with no user id is the
   gate's host-CLI branch, and it is the caller's own claim. So outside ``cli.py`` no call to
   ``set_user_disabled`` / ``delete_api_key`` / ``clear_emergency_revoke`` passes ``source="cli"``, a
   non-literal ``source``, ``emergency_reason=``, ``cli_principal=`` or ``**kwargs``. Calls are read
   direct, through a hop dispatcher (``db_call(f, ..)``, ``db_call(lambda: f(..))``) and through
   ``partial(f, ..)`` (the harness ``hop_target`` / ``unwrap_callable``); a function that forwards its
   own parameter into one of those keywords joins the actuator set, to a fixpoint, so its callers are
   held to the same rule (an unbound parameter is read through its default).
7. NO CALLER LABEL (cycle P hipaa S2): the funnel, the clear edge and both actuators take no parameter
   named ``actor`` or ending ``_label``; each edge builds the actor from the id the gate checked.

SCOPE: (1) and (5) read direct calls by name and line order; a call through a variable, dict or
``db_call`` hop is not followed (punch 721 gap 1). (1)'s "first SQL write" is the first non-docstring
string constant starting DELETE/UPDATE/INSERT. (2) and (3) read names and literals, not data flow. (6)
matches callees by NAME across modules (a same-named function elsewhere is held to the rule too: the
safe side); a callable stored in a variable, dict or attribute and called later is not followed.
"""
from __future__ import annotations

import ast
import re

import pytest

from _pin_harness import (
    assert_pin_has_teeth,
    call_name,
    docstring_constant_ids,
    hop_target,
    parse_source,
    unwrap_callable,
    walk_src,
)

_FUNNEL = "record_emergency_revoke"
_CLEAR_EDGE = "clear_emergency_revoke"
_MARKER_NAMES = frozenset({"EMERGENCY_REVOKE_MARKER", "_emergency_marker_path"})
_MARKER_LITERAL = ".audit-emergency-revoke"
_HELPER_LITERAL = "emergency_revoke"
_CLEARED_LITERAL = "emergency_revoke_cleared"
_HELPER_WRITERS = {_HELPER_LITERAL: _FUNNEL, _CLEARED_LITERAL: _CLEAR_EDGE}
_SQL_WRITE_RE = re.compile(r"\s*(?:DELETE|UPDATE|INSERT)\b")


def _fns(tree):
    return [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]


def _call_name(n: ast.AST) -> str | None:
    if isinstance(n, ast.Call):
        return getattr(n.func, "id", getattr(n.func, "attr", None))
    return None


def _calls(fn, name: str) -> list[ast.Call]:
    return [n for n in ast.walk(fn) if _call_name(n) == name]


def _is_not_none_test(test: ast.AST) -> bool:
    return (isinstance(test, ast.Compare) and len(test.ops) == 1 and isinstance(test.ops[0], ast.IsNot)
            and isinstance(test.comparators[0], ast.Constant) and test.comparators[0].value is None)


def _first_sql_write_line(fn, docs) -> int | None:
    return min((n.lineno for n in ast.walk(fn)
                if isinstance(n, ast.Constant) and isinstance(n.value, str) and id(n) not in docs
                and _SQL_WRITE_RE.match(n.value)), default=None)


def _flag_gaps(tree) -> list[str]:
    """For each function calling the funnel: what its explicit-flag shape lacks."""
    out = []
    docs = docstring_constant_ids(tree)
    for fn in _fns(tree):
        funnel_calls = _calls(fn, _FUNNEL)
        if not funnel_calls:
            continue
        kw = {a.arg: d for a, d in zip(fn.args.kwonlyargs, fn.args.kw_defaults)}
        if "emergency_reason" not in kw:
            out.append(f"{fn.name}: no keyword-only emergency_reason")
        elif not (isinstance(kw["emergency_reason"], ast.Constant) and kw["emergency_reason"].value is None):
            out.append(f"{fn.name}: emergency_reason does not default to None")
        if not _calls(fn, "check_emergency_reason"):
            out.append(f"{fn.name}: emergency_reason is never validated")
        first_write = _first_sql_write_line(fn, docs)
        led = [node for node in ast.walk(fn)
               if isinstance(node, ast.If) and _is_not_none_test(node.test)
               and getattr(node.test.left, "id", None) == "emergency_reason"
               and isinstance(node.body[0], ast.Expr)
               and _call_name(node.body[0].value) == "check_emergency_actor"
               and (first_write is None or node.lineno < first_write)]
        if not led:
            out.append(f"{fn.name}: the emergency actor check is not the first statement "
                       f"of the flag branch, before the first write")
        guarded = {id(c) for node in ast.walk(fn) if isinstance(node, ast.If) and _is_not_none_test(node.test)
                   for st in node.body for c in ast.walk(st)}
        out += [f"{fn.name}: funnel call at line {c.lineno} is not under an `is not None` guard"
                for c in funnel_calls if id(c) not in guarded]
    return out


def _callers(rel_filter=None) -> set[str]:
    return {fn.name for _p, rel, tree in walk_src() if rel_filter is None or rel == rel_filter
            for fn in _fns(tree) if _calls(fn, _FUNNEL)}


def test_every_caller_of_the_funnel_takes_the_explicit_flag():
    callers = _callers()
    # Anti-vacuity: the two containment sites the census found call it.
    assert {"delete_api_key", "set_user_disabled"} <= callers, callers
    offenders = [f"{rel}: {g}" for _p, rel, tree in walk_src() for g in _flag_gaps(tree)]
    assert not offenders, "The emergency path is not behind its explicit flag:\n  " + "\n  ".join(offenders)


def test_the_flag_pin_has_teeth():
    good = (
        "def f(conn, *, emergency_reason=None):\n"
        "    \"\"\"DELETE in prose is not a write.\"\"\"\n"
        "    failure = None\n"
        "    if emergency_reason is not None:\n"
        "        check_emergency_actor(conn, None, 'cli')\n"
        "        check_emergency_reason(emergency_reason)\n"
        "    conn.execute('DELETE FROM t')\n"
        "    if failure is not None:\n"
        "        record_emergency_revoke(conn, reason=emergency_reason)\n")
    assert_pin_has_teeth(_flag_gaps, good.replace("*, emergency_reason=None", "emergency_reason=None"), good)
    assert _flag_gaps(parse_source(good.replace("=None):", "='key_compromised'):"))) == [
        "f: emergency_reason does not default to None"]
    assert _flag_gaps(parse_source(good.replace("        check_emergency_reason(emergency_reason)\n", "        pass\n"))) == [
        "f: emergency_reason is never validated"]
    assert _flag_gaps(parse_source(good.replace("    if failure is not None:\n    ", "    if True:\n    "))) == [
        "f: funnel call at line 9 is not under an `is not None` guard"]
    actor_gap = ["f: the emergency actor check is not the first statement of the flag branch, "
                 "before the first write"]
    check = "        check_emergency_actor(conn, None, 'cli')\n"
    assert _flag_gaps(parse_source(good.replace(check, ""))) == actor_gap
    late = good.replace(check, "").replace(
        "    conn.execute('DELETE FROM t')\n",
        "    conn.execute('DELETE FROM t')\n    if emergency_reason is not None:\n" + check)
    assert _flag_gaps(parse_source(late)) == actor_gap  # checked only AFTER the write
    second = good.replace(check, "").replace(
        "        check_emergency_reason(emergency_reason)\n",
        "        check_emergency_reason(emergency_reason)\n" + check)
    assert _flag_gaps(parse_source(second)) == actor_gap  # not the branch's FIRST statement


def _marker_touchers(tree) -> dict[str, set[str]]:
    """{function: {'write'|'unlink'|'name'}} for every function that names the marker path."""
    out: dict[str, set[str]] = {}
    for fn in _fns(tree):
        names = {n.id for n in ast.walk(fn) if isinstance(n, ast.Name)} | {
            n.attr for n in ast.walk(fn) if isinstance(n, ast.Attribute)}
        if not names & _MARKER_NAMES:
            continue
        kinds = {"name"}
        if _calls(fn, "atomic_write_text"):
            kinds.add("write")
        if _calls(fn, "unlink"):
            kinds.add("unlink")
        out[fn.name] = kinds
    return out


def test_the_marker_is_set_and_cleared_through_one_funnel_each():
    touched: dict[str, set[str]] = {}
    for _p, rel, tree in walk_src():
        for name in _MARKER_NAMES | {_MARKER_LITERAL}:
            hits = [n for n in ast.walk(tree)
                    if (isinstance(n, ast.Name) and n.id == name)
                    or (isinstance(n, ast.Attribute) and n.attr == name)
                    or (isinstance(n, ast.Constant) and n.value == name)]
            if rel != "db/audit.py":
                assert not hits, f"{rel} touches the emergency marker ({name}); only db/audit.py may"
        if rel == "db/audit.py":
            touched = _marker_touchers(tree)
    writers = {f for f, k in touched.items() if "write" in k}
    clearers = {f for f, k in touched.items() if "unlink" in k}
    assert writers == {_FUNNEL}, writers
    assert clearers == {"clear_emergency_revoke"}, clearers
    assert {"emergency_revoke_pending", "_emergency_marker_path"} <= set(touched), touched


def test_the_marker_pin_has_teeth():
    bad = ("def sneaky(conn):\n    p = _emergency_marker_path(conn)\n    atomic_write_text(p, 'x')\n"
           "def sweeper(conn):\n    _emergency_marker_path(conn).unlink()\n")
    touched = _marker_touchers(parse_source(bad))
    assert touched == {"sneaky": {"name", "write"}, "sweeper": {"name", "unlink"}}
    assert_pin_has_teeth(
        lambda t: {f for f, k in _marker_touchers(t).items() if "write" in k} - {_FUNNEL}, bad,
        "def record_emergency_revoke(conn):\n    atomic_write_text(_emergency_marker_path(conn), 'x')\n")


def _helper_literal_sites(tree, literal: str = _HELPER_LITERAL) -> list[str]:
    docs = docstring_constant_ids(tree)
    return [f"{fn.name}@{n.lineno}" for fn in _fns(tree) for n in ast.walk(fn)
            if isinstance(n, ast.Constant) and n.value == literal and id(n) not in docs]


@pytest.mark.parametrize("literal", sorted(_HELPER_WRITERS))
def test_the_gap_rows_helper_name_has_one_writer(literal):
    sites = {}
    for _p, rel, tree in walk_src():
        found = _helper_literal_sites(tree, literal)
        if found:
            sites[rel] = found
    assert list(sites) == ["db/audit.py"], sites
    assert {s.split("@")[0] for s in sites["db/audit.py"]} == {_HELPER_WRITERS[literal]}, sites


def test_the_helper_name_pin_has_teeth():
    bad = "def other(conn):\n    _write_audit_gap_event(conn, helper_name='emergency_revoke')\n"
    assert_pin_has_teeth(_helper_literal_sites, bad, "def other(conn):\n    return 1\n")
    assert_pin_has_teeth(
        lambda t: _helper_literal_sites(t, _CLEARED_LITERAL),
        bad.replace("'emergency_revoke'", "'emergency_revoke_cleared'"), bad)


def _clear_edge_gaps(tree) -> list[str]:
    """What the clear edge lacks: its own chained row, written BEFORE the marker goes, with
    every failure of that write returning before the unlink (PD-18, fail closed)."""
    out = []
    for fn in _fns(tree):
        if fn.name != _CLEAR_EDGE:
            continue
        writes = [c for c in _calls(fn, "_write_audit_gap_event")
                  if any(k.arg == "helper_name" and isinstance(k.value, ast.Constant)
                         and k.value.value == _CLEARED_LITERAL for k in c.keywords)]
        body = [s for s in fn.body if not (isinstance(s, ast.Expr) and isinstance(s.value, ast.Constant)
                                           and isinstance(s.value.value, str))]
        if not (body and isinstance(body[0], ast.Expr) and _call_name(body[0].value) == "check_emergency_actor"):
            out.append(f"{fn.name}: the actor gate is not the first statement")
        if not writes:
            out.append(f"{fn.name}: writes no {_CLEARED_LITERAL} row")
            continue
        last = max(c.lineno for c in writes)
        out += [f"{fn.name}: unlink at line {u.lineno} is not after its row"
                for u in _calls(fn, "unlink") if u.lineno <= last]
        guarded = {id(c) for t in ast.walk(fn) if isinstance(t, ast.Try) and t.handlers
                   and all(h.body and isinstance(h.body[-1], ast.Return) for h in t.handlers)
                   for st in t.body for c in ast.walk(st)}
        out += [f"{fn.name}: a failed row at line {c.lineno} can fall through to the unlink"
                for c in writes if id(c) not in guarded]
    return out


def test_the_clear_edge_records_its_row_before_the_marker_goes():
    (tree,) = [t for _p, rel, t in walk_src() if rel == "db/audit.py"]
    assert _CLEAR_EDGE in {fn.name for fn in _fns(tree)}, "anti-vacuity: the clear edge is gone"
    assert _clear_edge_gaps(tree) == []


def test_the_clear_edge_pin_has_teeth():
    gate = "    check_emergency_actor(conn, actor_user_id, source)\n"
    good = (
        "def clear_emergency_revoke(conn, *, actor_user_id, source):\n"
        "    \"\"\"Docstring first is fine.\"\"\"\n"
        + gate +
        "    try:\n"
        "        _write_audit_gap_event(conn, helper_name='emergency_revoke_cleared')\n"
        "    except Exception:\n"
        "        return {'cleared': False}\n"
        "    path.unlink()\n")
    assert _clear_edge_gaps(parse_source(good)) == []
    assert_pin_has_teeth(_clear_edge_gaps, good.replace("'emergency_revoke_cleared'", "'other'"), good)
    swallowed = good.replace("        return {'cleared': False}\n", "        pass\n")
    assert _clear_edge_gaps(parse_source(swallowed)) == [
        "clear_emergency_revoke: a failed row at line 5 can fall through to the unlink"]
    early = good.replace("    path.unlink()\n", "").replace(gate, gate + "    path.unlink()\n")
    assert _clear_edge_gaps(parse_source(early)) == [
        "clear_emergency_revoke: unlink at line 4 is not after its row"]
    gate_gap = ["clear_emergency_revoke: the actor gate is not the first statement"]
    assert _clear_edge_gaps(parse_source(good.replace(gate, ""))) == gate_gap
    late_gate = good.replace(gate, "    path = marker(conn)\n" + gate)
    assert _clear_edge_gaps(parse_source(late_gate)) == gate_gap


def _degraded_reads(tree, name: str) -> bool:
    for n in ast.walk(tree):
        if (isinstance(n, ast.Assign) and any(getattr(t, "id", None) == "degraded" for t in n.targets)
                and any(isinstance(x, ast.Name) and x.id == name for x in ast.walk(n.value))):
            return True
    return False


def test_health_detail_degrades_on_the_pending_emergency_revoke():
    (tree,) = [t for _p, rel, t in walk_src() if rel == "web/routers/health.py"]
    assert _degraded_reads(tree, "emergency_revoke_pending"), (
        "/health/detail's `degraded` does not read emergency_revoke_pending: a revoke committed "
        "without its chained witness would not alarm")


def test_the_health_pin_has_teeth():
    assert_pin_has_teeth(
        lambda t: not _degraded_reads(t, "emergency_revoke_pending"),
        "degraded = a or b\n", "degraded = a or emergency_revoke_pending\n")


# (6) CLI ONLY -----------------------------------------------------------------------------------
_CLI_MODULE = "cli.py"
_ACTUATORS = frozenset({"set_user_disabled", "delete_api_key", _CLEAR_EDGE})
_CLI_ONLY_KWARGS = frozenset({"emergency_reason", "cli_principal"})


def _bad_value(kw: str, value: ast.AST | None) -> str | None:
    """Why passing ``value`` as ``kw`` outside cli.py claims the host-CLI path, else None."""
    if kw == "source":
        if isinstance(value, ast.Constant) and isinstance(value.value, str):
            return "source='cli'" if value.value == "cli" else None
        return "a non-literal source"
    if isinstance(value, ast.Constant) and value.value is None:
        return None
    return f"{kw}="


def _calls_of(tree, names):
    """``(fn or None, callee name, args, keywords, line)`` for every call of a name in
    ``names``: direct, handed to a hop dispatcher, or bound by ``partial``."""
    owner: dict[int, ast.AST] = {}
    # the innermost def owns a node: a nested def starts later, so it overwrites its parent
    for fn in sorted(_fns(tree), key=lambda f: f.lineno):
        for n in ast.walk(fn):
            if n is not fn:
                owner[id(n)] = fn
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        target = hop_target(node)
        if target is None and call_name(node) == "partial":
            target = unwrap_callable(node)
        if target is not None and target.name in names:
            yield owner.get(id(node)), target.name, target.args, target.keywords, node.lineno
        elif call_name(node) in names:
            yield owner.get(id(node)), call_name(node), node.args, node.keywords, node.lineno


def _params(fn) -> list[str]:
    names = [a.arg for a in (*fn.args.posonlyargs, *fn.args.args)]
    return names[1:] if names[:1] in (["self"], ["cls"]) else names


def _bound(fn, param: str, args, keywords) -> tuple[bool, ast.AST | None]:
    """``(bound, value)`` for ``param`` of ``fn`` at a call; unbound reads the default."""
    for k in keywords:
        if k.arg == param:
            return True, k.value
    pos = _params(fn)
    if param in pos and pos.index(param) < len(args):
        return True, args[pos.index(param)]
    if param in pos:
        defaults = fn.args.defaults
        idx = pos.index(param) - (len(pos) - len(defaults))
        return False, (defaults[idx] if idx >= 0 else None)
    kw = {a.arg: d for a, d in zip(fn.args.kwonlyargs, fn.args.kw_defaults)}
    return False, kw.get(param)


def _cli_flag_offenders(modules) -> list[str]:
    """Every call outside cli.py that claims the host-CLI emergency path (property 6)."""
    defs = {fn.name: fn for _rel, tree in modules for fn in _fns(tree)}
    # name -> {param: keyword it is forwarded into}; the actuators read their own keywords
    targets: dict[str, dict[str, str]] = {n: {} for n in _ACTUATORS}
    out: set[str] = set()
    changed = True
    while changed:
        changed = False
        for rel, tree in modules:
            for fn, name, args, keywords, line in _calls_of(tree, set(targets)):
                checks = []  # (keyword, bound?, value)
                if name in _ACTUATORS:
                    if any(k.arg is None for k in keywords):
                        checks.append(("**", True, None))
                    checks += [(k.arg, True, k.value) for k in keywords
                               if k.arg == "source" or k.arg in _CLI_ONLY_KWARGS]
                else:
                    for param, kw in targets[name].items():
                        bound, value = _bound(defs[name], param, args, keywords)
                        if bound or value is not None:
                            checks.append((kw, bound, value))
                for kw, _bound_, value in checks:
                    if kw == "**":
                        if rel != _CLI_MODULE:
                            out.add(f"{rel}:{line} {name}: **kwargs to an emergency actuator")
                        continue
                    if (fn is not None and isinstance(value, ast.Name)
                            and value.id in {a.arg for a in ast.walk(fn.args) if isinstance(a, ast.arg)}):
                        if targets.setdefault(fn.name, {}).get(value.id) != kw:
                            targets[fn.name][value.id] = kw
                            changed = True
                        continue
                    why = _bad_value(kw, value)
                    if why and rel != _CLI_MODULE:
                        out.add(f"{rel}:{line} {name}: {why}")
    return sorted(out)


def test_only_the_cli_claims_the_host_cli_emergency_path():
    modules = [(rel, tree) for _p, rel, tree in walk_src()]
    sites = [(rel, name, kws) for rel, tree in modules
             for _fn, name, _a, kws, _l in _calls_of(tree, _ACTUATORS)]
    # Anti-vacuity: the scan sees web callers of the actuators AND the CLI's own claims.
    assert any(rel != _CLI_MODULE for rel, _n, _k in sites), sites
    cli_claims = {name for rel, name, kws in sites if rel == _CLI_MODULE
                  for k in kws if k.arg == "source" and getattr(k.value, "value", None) == "cli"}
    assert cli_claims == set(_ACTUATORS), cli_claims
    offenders = _cli_flag_offenders(modules)
    assert not offenders, (
        "Only cli.py may claim the host-CLI emergency path (source='cli' with no user id passes "
        "check_emergency_actor on the caller's word; PD-9):\n  " + "\n  ".join(offenders))


def test_the_cli_only_pin_has_teeth():
    def run(src, rel="web/routers/x.py"):
        return _cli_flag_offenders([(rel, parse_source(src))])

    good = ("def route(db, k, u):\n"
            "    delete_api_key(db, k, actor_user_id=u, source='ui')\n"
            "    set_user_disabled(db, u, True, u, 'r', emergency_reason=None)\n")
    assert run(good) == []
    for bad, why in (
        ("def r(db, u):\n    set_user_disabled(db, u, True, None, '', source='cli')\n",
         "set_user_disabled: source='cli'"),
        ("def r(db, k):\n    delete_api_key(db, k, emergency_reason='suspected_intrusion')\n",
         "delete_api_key: emergency_reason="),
        ("def r(db):\n    clear_emergency_revoke(db, actor_user_id=None, source='cli')\n",
         "clear_emergency_revoke: source='cli'"),
        ("def r(db, k):\n    delete_api_key(db, k, cli_principal='root')\n",
         "delete_api_key: cli_principal="),
        ("def r(db, k, s):\n    delete_api_key(db, k, source=s + '')\n",
         "delete_api_key: a non-literal source"),
        ("def r(db, k, kw):\n    delete_api_key(db, k, **kw)\n",
         "delete_api_key: **kwargs to an emergency actuator"),
        # through a hop dispatcher, a lambda and partial (harness hop_target / unwrap_callable)
        ("async def r(db, u):\n    await db_call(set_user_disabled, db, u, True, source='cli')\n",
         "set_user_disabled: source='cli'"),
        ("async def r(db, k):\n    await db_call(lambda: delete_api_key(db, k, source='cli'))\n",
         "delete_api_key: source='cli'"),
        ("def r(db):\n    f = partial(clear_emergency_revoke, db, actor_user_id=None, source='cli')\n",
         "clear_emergency_revoke: source='cli'"),
    ):
        got = run(bad)
        assert got and all(why in g for g in got), (bad, got)
        assert run(bad, rel=_CLI_MODULE) == [], "cli.py itself may claim the CLI path"
    # PD-2: a helper forwarding its parameter is followed to its callers, and its default read.
    helper = "def helper(db, k, src):\n    delete_api_key(db, k, source=src)\n"
    assert run(helper + "def r(db, k):\n    helper(db, k, 'ui')\n") == []
    assert run(helper + "def r(db, k):\n    helper(db, k, 'cli')\n") == [
        "web/routers/x.py:4 helper: source='cli'"]
    assert run(helper + "def r(db, k):\n    helper(db, k, src='cli')\n") == [
        "web/routers/x.py:4 helper: source='cli'"]
    defaulted = helper.replace("k, src):", "k, src='cli'):") + "def r(db, k):\n    helper(db, k)\n"
    assert run(defaulted) == ["web/routers/x.py:4 helper: source='cli'"]
    two_hops = (helper + "def mid(db, k, s2):\n    helper(db, k, s2)\n"
                "def r(db, k):\n    mid(db, k, 'cli')\n")
    assert run(two_hops) == ["web/routers/x.py:6 mid: source='cli'"]
    reason = ("def helper(db, k, why=None):\n    delete_api_key(db, k, emergency_reason=why)\n"
              "def r(db, k):\n    helper(db, k, why='suspected_intrusion')\n")
    assert run(reason) == ["web/routers/x.py:4 helper: emergency_reason="]
    assert run(reason.replace("why='suspected_intrusion'", "why=None")) == []


# (7) NO CALLER LABEL ----------------------------------------------------------------------------
_LABEL_FREE = frozenset({_FUNNEL, *_ACTUATORS})


def _label_params(tree) -> list[str]:
    return [f"{fn.name}({a.arg})" for fn in _fns(tree) if fn.name in _LABEL_FREE
            for a in (*fn.args.posonlyargs, *fn.args.args, *fn.args.kwonlyargs)
            if a.arg == "actor" or a.arg.endswith("_label")]


def test_no_emergency_edge_takes_a_caller_supplied_actor_label():
    found = {fn.name for _p, _rel, tree in walk_src() for fn in _fns(tree)} & _LABEL_FREE
    assert found == _LABEL_FREE, found  # anti-vacuity
    offenders = [f"{rel}: {o}" for _p, rel, tree in walk_src() for o in _label_params(tree)]
    assert not offenders, (
        "An emergency edge takes the gap row's actor from its caller, which can contradict the "
        f"user id the gate checked (cycle P hipaa S2): {offenders}")


def test_the_label_pin_has_teeth():
    assert_pin_has_teeth(
        _label_params,
        "def delete_api_key(conn, k, *, emergency_actor_label=None):\n    pass\n",
        "def delete_api_key(conn, k, *, cli_principal=None):\n    pass\n")
    assert _label_params(parse_source("def clear_emergency_revoke(conn, *, actor):\n    pass\n")) == [
        "clear_emergency_revoke(actor)"]
