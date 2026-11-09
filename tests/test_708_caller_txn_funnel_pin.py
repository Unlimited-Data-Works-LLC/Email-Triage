"""Punch 708 (N-642): a funnel never ends a transaction its caller holds.

The N-342 / punch-696 pin (``test_n342_hipaa_cascade_no_nested_begin_pin.py``)
sees only the funnels that ANNOUNCE they are nested-aware (they read
``in_transaction`` into a flag). A funnel that commits or rolls back its
``conn`` parameter WITHOUT reading it is invisible there by construction. This
pin closes that from the other side: it finds every HOLDER, a function that has
a transaction open on a connection (an explicit ``BEGIN``, or a DML statement
under the deferred isolation level the app runs in, or a call to a helper that
leaves one open), and fails when, inside that open window, the holder hands the
connection to a funnel that ends it.

Interprocedural (PD-2): an END reached through any depth of helper calls counts,
and so does a call through ``db_call(f, conn, ..)`` (``hop_target``). The
connection is followed by FLOW, not by name: a callee's END on its parameter
``p`` counts against a caller only when the caller binds its open connection to
``p`` (positionally or by keyword). ``with helper(conn):`` is an END at the end
of the block (the ``_clock_txn`` context-manager shape). Two events in exclusive
arms (``if``/``else``, two ``except`` handlers, ``match`` cases), or an open
whose block returns or raises before the call, are not on one path.

The second test is the ``@db_write`` half of the class: inside an open window a
call to a ``@db_write`` helper that raises has its wrapper roll the HOLDER's
transaction back before the holder's own handler runs. A handler that then
swallows the exception reports writes that were rolled back; a handler that
issues a raw ``execute("ROLLBACK")`` raises "no transaction is active" and masks
the original exception.

SCOPE (what this pin does not read; census file ``clsC-708-census.md``):
callees resolve by NAME across modules (it over-approximates; a shared name binds
every def of it); a connection rebound to another name (``db = conn``), carried in
an object attribute (``self._conn``), a dict or a ``**kwargs`` spread, or a callee
reached through a variable, is not followed. Order is source order inside one
function with the exclusive-arm rule above; loops are not unrolled.
"""
from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field

from _pin_harness import call_site, callee_ref, iter_src_files, parse_module, parse_source, relpath

_END_SQL = re.compile(r"^\s*(COMMIT|ROLLBACK|END)\b", re.I)
_BEGIN_SQL = re.compile(r"^\s*(BEGIN|SAVEPOINT)\b", re.I)
_DML_SQL = re.compile(r"^\s*(INSERT|UPDATE|DELETE|REPLACE)\b", re.I)
_SCOPES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)
_CONN_NAME = re.compile(r"(^|[._])(conn|db|connection)$")

# (holder relpath, holder qualname, callee name) -> why the callee's commit of
# the holder's transaction is the intended design. A stale key fails the
# stale-entry test below.
_ALLOWED_HOLDER_ENDS: dict[tuple[str, str, str], str] = {
    ("web/embedding_update_runner.py", "_claim.<locals>._claim_db_work", "_update_state"): (
        "Panel T db R2-N1: the auto-attempt marker is written uncommitted BEFORE "
        "the status flip, whose own commit then carries both; a marker write that "
        "raises flips nothing"),
}


def _own_nodes(fn):
    stack = list(ast.iter_child_nodes(fn))
    while stack:
        n = stack.pop()
        if isinstance(n, _SCOPES):
            continue
        yield n
        stack.extend(ast.iter_child_nodes(n))


def _root(expr) -> str | None:
    if isinstance(expr, ast.Name):
        return expr.id
    if isinstance(expr, ast.Attribute) and isinstance(expr.value, ast.Name):
        return f"{expr.value.id}.{expr.attr}"
    return None


def _sql_head(call: ast.Call) -> str | None:
    if not call.args:
        return None
    a = call.args[0]
    if isinstance(a, ast.Constant) and isinstance(a.value, str):
        return a.value
    if isinstance(a, ast.JoinedStr) and a.values and isinstance(a.values[0], ast.Constant):
        return str(a.values[0].value)
    if isinstance(a, ast.BinOp) and isinstance(a.left, ast.Constant) and isinstance(a.left.value, str):
        return a.left.value
    return None


def _txn_event(node):
    """``(kind, receiver, how)`` for a txn-relevant node: kind END / BEGIN / DML."""
    if isinstance(node, ast.With):
        for item in node.items:
            r = _root(item.context_expr)
            if r and _CONN_NAME.search(r):
                return ("END", r, "with-conn")
        return None
    if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
        return None
    attr, r = node.func.attr, _root(node.func.value)
    if r is None:
        return None
    if attr in ("commit", "rollback"):
        return ("END", r, attr)
    if attr == "executescript":
        return ("END", r, "executescript")
    if attr in ("execute", "executemany"):
        s = _sql_head(node)
        if s is None:
            return None
        word = s.split()[0].upper() if s.split() else ""
        if _END_SQL.match(s):
            return ("END", r, "execute:" + word)
        if _BEGIN_SQL.match(s):
            return ("BEGIN", r, "execute:" + word)
        if _DML_SQL.match(s):
            return ("DML", r, word)
    return None


def _nested_flags(fn) -> set[str]:
    out: set[str] = set()
    for n in _own_nodes(fn):
        if isinstance(n, ast.Assign):
            targets, val = n.targets, n.value
        elif isinstance(n, ast.AnnAssign) and n.value is not None:
            targets, val = [n.target], n.value
        else:
            continue
        if any(isinstance(s, ast.Constant) and s.value == "in_transaction"
               or isinstance(s, ast.Attribute) and s.attr == "in_transaction"
               for s in ast.walk(val)):
            out |= {t.id for t in targets if isinstance(t, ast.Name)}
    return out


def _under_not_flag(node, fn, flags) -> bool:
    child, parent = node, getattr(node, "_ph_parent", None)
    while parent is not None and parent is not fn:
        if (isinstance(parent, ast.If) and child in parent.body
                and isinstance(parent.test, ast.UnaryOp) and isinstance(parent.test.op, ast.Not)
                and isinstance(parent.test.operand, ast.Name) and parent.test.operand.id in flags):
            return True
        child, parent = parent, getattr(parent, "_ph_parent", None)
    return False


def _path(node, fn):
    """Top-down ``(parent, field, index)`` steps from ``fn`` to ``node``."""
    out = []
    child, parent = node, getattr(node, "_ph_parent", None)
    while parent is not None and child is not fn:
        for fname, val in ast.iter_fields(parent):
            if isinstance(val, list) and any(v is child for v in val):
                out.append((parent, fname, next(i for i, v in enumerate(val) if v is child)))
                break
            if val is child:
                out.append((parent, fname, None))
                break
        child, parent = parent, getattr(parent, "_ph_parent", None)
    return out[::-1]


def _exclusive(a, b, fn) -> bool:
    """True when ``a`` (earlier) cannot fall through to ``b`` on one path."""
    pa, pb = _path(a, fn), _path(b, fn)
    i = 0
    while i < min(len(pa), len(pb)) and pa[i][0] is pb[i][0] and pa[i][1:] == pb[i][1:]:
        i += 1
    if i < len(pa) and i < len(pb) and pa[i][0] is pb[i][0]:
        p, fa, fb = pa[i][0], pa[i][1], pb[i][1]
        if isinstance(p, (ast.If, ast.IfExp)) and {fa, fb} == {"body", "orelse"}:
            return True
        if isinstance(p, ast.Try):
            if {fa, fb} == {"handlers", "orelse"}:
                return True
            if fa == fb == "handlers" and pa[i][2] != pb[i][2]:
                return True
        if isinstance(p, ast.Match) and fa == fb == "cases" and pa[i][2] != pb[i][2]:
            return True
    for j in range(i, len(pa)):
        p, fname, idx = pa[j]
        if idx is None:
            continue
        if j == i and isinstance(p, ast.Try) and fname == "body":
            continue  # a raise in the try body still reaches its handlers
        lst = getattr(p, fname)
        stop = len(lst)
        if j == i and j < len(pb) and pb[j][0] is p and pb[j][1] == fname and pb[j][2] is not None:
            stop = pb[j][2]
        if any(isinstance(s, (ast.Return, ast.Raise)) for s in lst[idx + 1:stop]):
            return True
    return False


@dataclass
class _Fn:
    rel: str
    qual: str
    node: ast.AST
    cls: str | None
    pos: list = field(default_factory=list)
    kw: list = field(default_factory=list)
    flags: set = field(default_factory=set)
    db_write: bool = False

    @property
    def key(self) -> str:
        return f"{self.rel}::{self.qual}"

    @property
    def params(self) -> list:
        return self.pos + self.kw


def _collect(modules):
    fns, by_name = [], {}

    def visit(rel, node, prefix, cls):
        for ch in ast.iter_child_nodes(node):
            if isinstance(ch, (ast.FunctionDef, ast.AsyncFunctionDef)):
                a = ch.args
                f = _Fn(rel, prefix + ch.name, ch, cls,
                        [x.arg for x in (*a.posonlyargs, *a.args)], [x.arg for x in a.kwonlyargs],
                        _nested_flags(ch),
                        any((d.id if isinstance(d, ast.Name) else getattr(d, "attr", "")).lstrip("_") == "db_write"
                            for d in ch.decorator_list))
                fns.append(f)
                by_name.setdefault(ch.name, []).append(f)
                visit(rel, ch, prefix + ch.name + ".<locals>.", None)
            elif isinstance(ch, ast.ClassDef):
                visit(rel, ch, prefix + ch.name + ".", ch.name)
            else:
                visit(rel, ch, prefix, cls)

    for rel, tree in modules:
        visit(rel, tree, "", None)
    return fns, by_name


def _bindings(call):
    callee, args, keywords = call_site(call)
    name = callee_ref(callee)
    if name is None:
        return None
    return name, list(args), list(keywords), isinstance(callee, ast.Attribute)


def _bound(callee: _Fn, args, kws, is_attr, var) -> set[str]:
    pos = callee.pos
    if callee.cls is not None and pos and pos[0] in ("self", "cls") and is_attr:
        pos = pos[1:]
    out = {pos[i] for i, a in enumerate(args)
           if isinstance(a, ast.Name) and a.id == var and i < len(pos)}
    out |= {k.arg for k in kws if k.arg and isinstance(k.value, ast.Name)
            and k.value.id == var and k.arg in callee.params}
    return out


@dataclass
class Census:
    fns: list
    events: dict          # fn key -> [(pos, kind, recv, how, node, guarded)]
    calls: dict           # fn key -> [dict(node, at, callee, param, var, guarded, ctx)]
    end_p: dict           # (fn key, param) -> witness chain (list of str)
    leaves_open: set      # (fn key, param)
    holder_ends: list     # dicts: holder fn, call, var, opened_by, chain
    dbwrite_windows: list  # dicts: holder fn, call, var, callee, handler verdict


def _pos(n):
    return (n.lineno, n.col_offset)


def analyze(modules) -> Census:
    fns, by_name = _collect(modules)
    events, calls = {}, {}
    for f in fns:
        evs, cs = [], []
        for n in _own_nodes(f.node):
            ev = _txn_event(n)
            if ev:
                kind, recv, how = ev
                g = kind in ("END", "BEGIN") and _under_not_flag(n, f.node, f.flags)
                at = (n.end_lineno, 10**6) if isinstance(n, ast.With) else _pos(n)
                evs.append((at, kind, recv, how, n, g))
            if not isinstance(n, ast.Call):
                continue
            b = _bindings(n)
            if not b:
                continue
            name, args, kws, is_attr = b
            ctx = next((w for w in [getattr(n, "_ph_parent", None)]
                        if isinstance(w, ast.withitem)), None)
            with_node = getattr(ctx, "_ph_parent", None) if ctx is not None else None
            vars_ = {a.id for a in args if isinstance(a, ast.Name)} | {
                k.value.id for k in kws if isinstance(k.value, ast.Name)}
            for g in by_name.get(name, ()):
                for v in vars_:
                    for p in _bound(g, args, kws, is_attr, v):
                        cs.append(dict(node=n, at=_pos(n), callee=g, param=p, var=v,
                                       guarded=_under_not_flag(n, f.node, f.flags), ctx=with_node))
        events[f.key], calls[f.key] = evs, cs

    end_p: dict = {}
    for f in fns:
        for at, kind, recv, how, n, g in events[f.key]:
            if kind == "END" and not g and recv in f.params and (f.key, recv) not in end_p:
                end_p[(f.key, recv)] = [f"{f.rel}:{at[0]} {f.qual} {how}"]
    changed = True
    while changed:
        changed = False
        for f in fns:
            for c in calls[f.key]:
                tgt = (c["callee"].key, c["param"])
                if c["guarded"] or c["var"] not in f.params or tgt not in end_p:
                    continue
                if (f.key, c["var"]) not in end_p:
                    end_p[(f.key, c["var"])] = [
                        f"{f.rel}:{c['at'][0]} {f.qual} -> {c['callee'].qual}({c['param']})", *end_p[tgt]]
                    changed = True

    leaves_open: set = set()

    def timeline(f, v):
        tl = []
        for at, kind, recv, how, n, g in events[f.key]:
            if recv == v and not g:
                tl.append((at, "open" if kind in ("BEGIN", "DML") else "end", how, n))
        for c in calls[f.key]:
            if c["var"] != v:
                continue
            k = (c["callee"].key, c["param"])
            if k in end_p and not c["guarded"]:
                w = c["ctx"]
                at = (w.end_lineno, 10**6) if w is not None else c["at"]
                tl.append((at, "end", "call:" + c["callee"].qual, w if w is not None else c["node"]))
            elif k in leaves_open:
                tl.append((c["at"], "open", "call:" + c["callee"].qual, c["node"]))
        return sorted(tl, key=lambda e: e[0])

    # A nested-aware funnel (it reads ``in_transaction``) is transparent: it
    # leaves an open transaction open and a closed one closed, so it is neither
    # an END (its ENDs sit under ``if not nested:``) nor a leave-open helper.
    changed = True
    while changed:
        changed = False
        for f in fns:
            for p in f.params:
                if f.flags or (f.key, p) in leaves_open:
                    continue
                tl = timeline(f, p)
                if tl and tl[-1][1] == "open":
                    leaves_open.add((f.key, p))
                    changed = True

    def open_before(f, c):
        prior = [e for e in timeline(f, c["var"])
                 if e[0] < c["at"] and e[3] is not c["node"] and not _exclusive(e[3], c["node"], f.node)]
        return prior[-1] if prior and prior[-1][1] == "open" else None

    holder_ends, dbw = [], []
    for f in fns:
        seen = set()
        for c in calls[f.key]:
            k = (c["callee"].key, c["param"])
            if c["guarded"]:
                continue
            opened = None
            if k in end_p or c["callee"].db_write:
                opened = open_before(f, c)
            if opened is None:
                continue
            if k in end_p and (c["at"], k) not in seen:
                seen.add((c["at"], k))
                holder_ends.append(dict(fn=f, call=c, var=c["var"], opened_by=opened[2],
                                        opened_line=opened[0][0], chain=end_p[k]))
            if c["callee"].db_write:
                dbw.append(dict(fn=f, call=c, var=c["var"], callee=c["callee"],
                                handler=_handler_verdict(c["node"], f.node, c["var"])))

    # Caller side of the declared-nesting rule: a call to a nested-aware funnel
    # must declare ``_in_caller_txn=True`` exactly when the connection it passes
    # is open there. Followed to ANY depth (panel AB MUST-C5: a two-hop
    # undeclared call, cascade -> ``set_auto_scan_enabled_for_account`` ->
    # ``update_account_config_keys``, refused every HIPAA flip while a one-hop
    # rule read it as closed). The entry state of a (function, parameter) is the
    # set of states its callers hand it, to a fixed point: a call hands "open"
    # from its own window, else the entry state of the caller's own parameter
    # when nothing on that variable happened before the call, else "closed".
    # A parameter no src call binds is an entry point: "closed".
    def prior(f, c):
        return [e for e in timeline(f, c["var"]) if e[0] < c["at"]]

    def call_states(f, c, entry):
        if open_before(f, c) is not None:
            return {"open"}
        if c["var"] in f.params and not prior(f, c):
            return entry.get((f.key, c["var"]), {"closed"})
        return {"closed"}

    bound = {(c["callee"].key, c["param"]) for f in fns for c in calls[f.key] if not c["guarded"]}
    entry: dict = {(f.key, p): ({"closed"} if (f.key, p) not in bound else set())
                   for f in fns for p in f.params}
    changed = True
    while changed:
        changed = False
        for f in fns:
            for c in calls[f.key]:
                if c["guarded"]:
                    continue
                k = (c["callee"].key, c["param"])
                add = call_states(f, c, entry) - entry.setdefault(k, set())
                if add:
                    entry[k] |= add
                    changed = True

    # The funnels whose callers must declare: every nested-aware funnel (bound on
    # its CONNECTION parameter, the receiver of its txn statements), plus, to a
    # fixed point, every function that forwards its own ``_in_caller_txn`` to one
    # (``_in_caller_txn=_in_caller_txn``): its callers carry the obligation.
    def declared_kind(f, c):
        for k in (_bindings(c["node"]) or (None, [], [], False))[2]:
            if k.arg != "_in_caller_txn":
                continue
            if isinstance(k.value, ast.Constant) and k.value.value in (True, False):
                return "True" if k.value.value else "False"
            if (isinstance(k.value, ast.Name) and k.value.id == "_in_caller_txn"
                    and "_in_caller_txn" in f.params):
                return "forwarded"
            return "dynamic"
        return "False"

    aware = {(f.key, e[2]) for f in fns if f.flags for e in events[f.key] if e[2] in f.params}
    changed = True
    while changed:
        changed = False
        for f in fns:
            for c in calls[f.key]:
                if ((c["callee"].key, c["param"]) in aware and not c["guarded"]
                        and c["var"] in f.params and (f.key, c["var"]) not in aware
                        and declared_kind(f, c) == "forwarded"):
                    aware.add((f.key, c["var"]))
                    changed = True

    nested_calls = []
    for f in fns:
        for c in calls[f.key]:
            if (c["callee"].key, c["param"]) not in aware or c["guarded"]:
                continue
            states = call_states(f, c, entry) or {"closed"}
            kind = declared_kind(f, c)
            if kind == "forwarded":
                # Transparent only when the state IS the entry state (no own
                # window, nothing on the variable before the call).
                ok = open_before(f, c) is None and c["var"] in f.params and not prior(f, c)
            else:
                ok = states == ({"open"} if kind == "True" else {"closed"}) and kind != "dynamic"
            nested_calls.append(dict(fn=f, call=c, open="/".join(sorted(states)),
                                     declared=kind, ok=ok))
    census = Census(fns, events, calls, end_p, leaves_open, holder_ends, dbw)
    census.nested_calls = nested_calls
    census.nesting_aware = aware
    return census


def _handler_verdict(call, fn, var) -> str:
    """How the nearest enclosing ``try`` around ``call`` treats a raise:
    ``reraise`` / ``swallow`` / ``raw-rollback`` (an unguarded
    ``<var>.execute("ROLLBACK")`` that raises once the wrapper rolled back) /
    ``none`` (no try: the raise propagates)."""
    child, parent = call, getattr(call, "_ph_parent", None)
    while parent is not None and parent is not fn:
        if isinstance(parent, ast.Try) and any(child is s for s in parent.body) and parent.handlers:
            verdicts = []
            for h in parent.handlers:
                body_nodes = [n for s in h.body for n in ast.walk(s)]
                raw = [n for n in body_nodes if isinstance(n, ast.Call)
                       and _txn_event(n) and _txn_event(n)[1] == var
                       and _txn_event(n)[2] in ("execute:ROLLBACK", "execute:COMMIT", "execute:END")
                       and not _inside_try(n, h)]
                if raw:
                    verdicts.append("raw-rollback")
                elif any(isinstance(n, ast.Raise) for n in body_nodes):
                    verdicts.append("reraise")
                else:
                    verdicts.append("swallow")
            for v in ("swallow", "raw-rollback"):
                if v in verdicts:
                    return v
            return "reraise"
        child, parent = parent, getattr(parent, "_ph_parent", None)
    return "none"


def _inside_try(node, stop) -> bool:
    cur = getattr(node, "_ph_parent", None)
    while cur is not None and cur is not stop:
        if isinstance(cur, ast.Try):
            return True
        cur = getattr(cur, "_ph_parent", None)
    return False


def _fmt_holder(h) -> str:
    return (f"{h['fn'].rel}:{h['call']['at'][0]} {h['fn'].qual} passes its open "
            f"{h['var']!r} (opened by {h['opened_by']} at :{h['opened_line']}) to "
            f"{' / '.join(h['chain'])}")


def holder_end_offenders(modules) -> tuple[list[str], set]:
    census = analyze(modules)
    out, used = [], set()
    for h in census.holder_ends:
        key = (h["fn"].rel, h["fn"].qual, h["call"]["callee"].qual.split(".")[-1])
        if key in _ALLOWED_HOLDER_ENDS:
            used.add(key)
            continue
        out.append(_fmt_holder(h))
    return sorted(set(out)), used


def dbwrite_window_offenders(modules) -> list[str]:
    return sorted({
        f"{d['fn'].rel}:{d['call']['at'][0]} {d['fn'].qual} -> @db_write "
        f"{d['callee'].qual} handler={d['handler']}"
        for d in analyze(modules).dbwrite_windows if d["handler"] in ("swallow", "raw-rollback")})


def src_modules():
    return [(relpath(p), t) for p in iter_src_files() for t in [parse_module(p)] if t]


def test_no_funnel_ends_a_transaction_its_caller_holds():
    modules = src_modules()
    census = analyze(modules)
    # Anti-vacuity: the net reads the shapes it claims to (a direct END funnel,
    # an END through a helper, and the ``with _clock_txn(conn):`` END).
    keys = {k[0].split("::")[1] for k in census.end_p}
    assert {"delete_setting", "mark_clock_breached", "_clock_txn"} <= keys, sorted(keys)[:20]
    assert any(k[0].endswith("::record_hipaa_access_event_txn") for k in census.leaves_open) or \
        any("record_" in k[0] and k[0].endswith("_txn") for k in census.leaves_open)
    offenders, _ = holder_end_offenders(modules)
    assert not offenders, (
        "A function with a transaction open hands that connection to a funnel that "
        "commits or rolls it back (N-642, punch 708): the caller's earlier writes "
        "become durable, or are discarded, partway through its own unit. Call the "
        "funnel's ``*_txn`` sibling (no commit) or make the funnel nested-aware:\n  "
        + "\n  ".join(offenders))


def test_a_raise_inside_an_open_window_is_never_swallowed_or_masked():
    offenders = dbwrite_window_offenders(src_modules())
    assert not offenders, (
        "Inside an open transaction a @db_write helper's raise makes its wrapper roll "
        "the CALLER's transaction back. The caller must re-raise (a swallow reports "
        "rolled-back writes as done) and must not then issue a raw "
        "execute('ROLLBACK') (it raises 'no transaction is active' and masks the "
        "original): use conn.rollback() or wrap it.\n  " + "\n  ".join(offenders))


def test_holder_end_allowlist_is_not_stale():
    _, used = holder_end_offenders(src_modules())
    stale = set(_ALLOWED_HOLDER_ENDS) - used
    assert not stale, f"allow-list entries no longer match a holder: {sorted(stale)}"


def _run_holder(src):
    return holder_end_offenders([("m.py", parse_source(src))])[0]


def _run_dbw(src):
    return dbwrite_window_offenders([("m.py", parse_source(src))])


_BAD = (
    "def delete_setting(conn, key):\n"
    "    conn.execute('DELETE FROM settings WHERE key = ?', (key,))\n"
    "    conn.commit()\n"
    "def update_account(conn, aid):\n"
    "    conn.execute('UPDATE email_accounts SET name = 1 WHERE id = ?', (aid,))\n"
    "    delete_setting(conn, 'k')\n"
    "    conn.commit()\n")


def test_the_holder_pin_has_teeth():
    assert len(_run_holder(_BAD)) == 1
    # The ``*_txn`` sibling leaves the commit to the holder.
    good = _BAD.replace("    conn.commit()\ndef update", "def update").replace(
        "delete_setting(conn, 'k')", "delete_setting_txn(conn, 'k')")
    assert good != _BAD and _run_holder(good) == []
    # Through a helper, and through a db_call hop, by keyword.
    hop = _BAD + ("def mid(c):\n    delete_setting(c, 'x')\n"
                  "def h2(db):\n    db.execute('INSERT INTO t VALUES (1)')\n"
                  "    db_call(mid, c=db)\n")
    assert len(_run_holder(hop)) == 2
    # Exclusive arms and an early return are not one path.
    excl = ("def f(conn):\n    conn.commit()\n"
            "def g(conn, x):\n    if x:\n        conn.execute('UPDATE t SET a=1')\n"
            "    else:\n        f(conn)\n"
            "def h(conn, x):\n    if x:\n        conn.execute('UPDATE t SET a=1')\n"
            "        return\n    f(conn)\n")
    assert _run_holder(excl) == []
    # An explicit BEGIN opens; ``with helper(conn):`` ends at the block's end.
    ctx = ("import contextlib\n@contextlib.contextmanager\n"
           "def txn(conn):\n    yield\n    conn.commit()\n"
           "def leaf(conn):\n    with txn(conn):\n        conn.execute('UPDATE t SET a=1')\n"
           "def holder(conn):\n    conn.execute('BEGIN')\n    leaf(conn)\n    conn.execute('COMMIT')\n"
           "def fine(conn):\n    leaf(conn)\n    leaf(conn)\n")
    assert [o.split(" ")[1] for o in _run_holder(ctx)] == ["holder"]
    # A nested-aware funnel (``if not nested:`` around its END) is not an END.
    aware = _BAD.replace(
        "    conn.execute('DELETE FROM settings WHERE key = ?', (key,))\n    conn.commit()\n",
        "    nested = conn.in_transaction\n"
        "    conn.execute('DELETE FROM settings WHERE key = ?', (key,))\n"
        "    if not nested:\n        conn.commit()\n")
    assert aware != _BAD and _run_holder(aware) == []


def test_the_dbwrite_window_pin_has_teeth():
    base = ("@db_write\ndef inner(conn):\n    conn.execute('UPDATE s SET a=1')\n    conn.commit()\n"
            "def outer(conn):\n    conn.execute('BEGIN')\n    try:\n"
            "        conn.execute('UPDATE t SET a=1')\n        inner(conn)\n"
            "        conn.execute('COMMIT')\n    except Exception:\n{H}")
    swallow = base.replace("{H}", "        pass\n")
    raw = base.replace("{H}", "        conn.execute('ROLLBACK')\n        raise\n")
    good = base.replace("{H}", "        conn.rollback()\n        raise\n")
    assert [o.rsplit("=", 1)[1] for o in _run_dbw(swallow)] == ["swallow"]
    assert [o.rsplit("=", 1)[1] for o in _run_dbw(raw)] == ["raw-rollback"]
    assert _run_dbw(good) == []
    # Outside an open window the wrapper rolls back only the helper's own work.
    assert _run_dbw(swallow.replace("    conn.execute('BEGIN')\n", "").replace(
        "        conn.execute('UPDATE t SET a=1')\n", "")) == []


# ---------------------------------------------------------------------------
# The leaked-transaction half (L1/L2 in the census). ``in_transaction`` cannot
# tell a caller's deliberate transaction from one leaked on the shared
# connection, so every nested-aware funnel (one that reads ``in_transaction``
# into a flag, the N-342 shape) also hands that flag to the ONE refusal,
# ``db._helpers.refuse_undeclared_nesting``, before its first write.
# ---------------------------------------------------------------------------

_REFUSAL = "refuse_undeclared_nesting"


def _undeclared_nesting_funnels(modules) -> list[str]:
    out = []
    for f in _collect(modules)[0]:
        if not f.flags:
            continue
        refusal = [n for n in _own_nodes(f.node) if isinstance(n, ast.Call)
                   and (getattr(n.func, "id", None) or getattr(n.func, "attr", None)) == _REFUSAL
                   and n.args and isinstance(n.args[0], ast.Name) and n.args[0].id in f.flags]
        first_write = min((_pos(n) for n in _own_nodes(f.node)
                           if (_txn_event(n) or (None,))[0] in ("BEGIN", "DML", "END")),
                          default=None)
        if not refusal or (first_write is not None and min(_pos(n) for n in refusal) > first_write):
            out.append(f"{f.rel}:{f.node.lineno} {f.qual}")
    return sorted(out)


def test_every_nested_aware_funnel_refuses_an_undeclared_transaction():
    modules = src_modules()
    aware = {f.qual for f in _collect(modules)[0] if f.flags}
    assert {"update_account_config_keys", "record_user_update"} <= aware, aware
    offenders = _undeclared_nesting_funnels(modules)
    assert not offenders, (
        "A nested-aware funnel reads in_transaction but does not pass the flag to "
        f"{_REFUSAL} before its first write (punch 708): a LEAKED transaction "
        "would be read as the caller's, and the funnel's write left uncommitted "
        "and reported done:\n  " + "\n  ".join(offenders))


def test_the_undeclared_nesting_pin_has_teeth():
    def run(src):
        return _undeclared_nesting_funnels([("m.py", parse_source(src))])

    bad = ("def f(conn, *, _in_caller_txn=False):\n"
           "    nested = conn.in_transaction\n"
           "    if not nested:\n        conn.execute('BEGIN IMMEDIATE')\n"
           "    conn.execute('UPDATE t SET a=1')\n")
    assert run(bad) == ["m.py:1 f"]
    good = bad.replace("    if not nested:",
                       "    refuse_undeclared_nesting(nested, _in_caller_txn, what='f')\n"
                       "    if not nested:")
    assert good != bad and run(good) == []
    # After the first write is too late; a refusal on another name is not this one.
    late = bad + "    refuse_undeclared_nesting(nested, _in_caller_txn, what='f')\n"
    assert run(late) == ["m.py:1 f"]
    assert run(good.replace("(nested,", "(other,")) == ["m.py:1 f"]
    # A function that never reads in_transaction is out of scope.
    assert run(bad.replace("conn.in_transaction", "conn.total_changes")) == []


def test_the_refusal_refuses_both_disagreements():
    import pytest
    from email_triage.db._helpers import refuse_undeclared_nesting

    refuse_undeclared_nesting(False, False, what="t")
    refuse_undeclared_nesting(True, True, what="t")
    with pytest.raises(RuntimeError, match="leaked"):
        refuse_undeclared_nesting(True, False, what="t")
    with pytest.raises(RuntimeError, match="holds no transaction"):
        refuse_undeclared_nesting(False, True, what="t")


def _nesting_mismatches(modules) -> list[str]:
    return sorted({
        f"{n['fn'].rel}:{n['call']['at'][0]} {n['fn'].qual} -> {n['call']['callee'].qual} "
        f"open={n['open']} declared={n['declared']}"
        for n in analyze(modules).nested_calls if not n["ok"]})


def test_every_call_to_a_nested_aware_funnel_declares_exactly_when_it_nests():
    """The caller half of the refusal (entry state followed to any depth)."""
    modules = src_modules()
    census = analyze(modules)
    calls = census.nested_calls
    assert any(n["declared"] == "True" for n in calls), "anti-vacuity: the cascade's declared call"
    # Anti-vacuity for the forwarding rule: the auto-scan wrapper is a funnel too.
    assert any(k.endswith("::set_auto_scan_enabled_for_account") for k, _ in census.nesting_aware)
    offenders = _nesting_mismatches(modules)
    assert not offenders, (
        "A call to a nested-aware funnel passes _in_caller_txn=True without an open "
        "transaction, or passes an open one without declaring it (punch 708). The "
        "funnel refuses both at runtime:\n  " + "\n  ".join(offenders))


def test_the_caller_declaration_pin_has_teeth():
    def run(src):
        return _nesting_mismatches([("m.py", parse_source(src))])

    funnel = ("def g(conn, *, _in_caller_txn=False):\n"
              "    nested = conn.in_transaction\n"
              "    refuse_undeclared_nesting(nested, _in_caller_txn, what='g')\n"
              "    if not nested:\n        conn.commit()\n")
    undeclared = funnel + "def h(conn):\n    conn.execute('UPDATE t SET a=1')\n    g(conn)\n"
    assert [o.split(" ")[1] for o in run(undeclared)] == ["h"]
    assert run(undeclared.replace("    g(conn)\n", "    g(conn, _in_caller_txn=True)\n")) == []
    # Declared with nothing open fires; one hop of entry state counts as open.
    assert [o.split(" ")[1] for o in run(funnel + "def k(conn):\n    g(conn, _in_caller_txn=True)\n")] == ["k"]
    hop = funnel + ("def mid(conn):\n    g(conn, _in_caller_txn=True)\n"
                    "def top(conn):\n    conn.execute('BEGIN')\n    mid(conn)\n    conn.execute('COMMIT')\n")
    assert run(hop) == []
    # Panel AB MUST-C3/C5, the live shape: two hops below an open window, with
    # the wrapper also called from a closed context. The undeclared wrapper call
    # fires at any depth; forwarding the flag moves the check to its callers.
    deep = funnel + ("def wrap(conn):\n    g(conn)\n"
                     "def cascade(conn):\n    wrap(conn)\n"
                     "def flip(conn):\n    conn.execute('BEGIN')\n    cascade(conn)\n    conn.execute('COMMIT')\n"
                     "def route(conn):\n    wrap(conn)\n")
    assert [o.split(" ")[1] for o in run(deep)] == ["wrap"]
    fwd = deep.replace("def wrap(conn):\n    g(conn)\n",
                       "def wrap(conn, *, _in_caller_txn=False):\n"
                       "    g(conn, _in_caller_txn=_in_caller_txn)\n")
    assert [o.split(" ")[1] for o in run(fwd)] == ["cascade"]
    fixed = fwd.replace("def cascade(conn):\n    wrap(conn)\n",
                        "def cascade(conn):\n    wrap(conn, _in_caller_txn=True)\n")
    assert run(fixed) == []
    # A forward after the wrapper opened its own window is not transparent, and
    # a constant True inside a wrapper with mixed callers fires.
    assert [o.split(" ")[1] for o in run(fixed.replace(
        "    g(conn, _in_caller_txn=_in_caller_txn)\n",
        "    conn.execute('UPDATE t SET a=1')\n    g(conn, _in_caller_txn=_in_caller_txn)\n"))] == ["wrap"]
    assert [o.split(" ")[1] for o in run(deep.replace("    g(conn)\n", "    g(conn, _in_caller_txn=True)\n"))] == ["wrap"]
