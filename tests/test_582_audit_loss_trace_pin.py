"""Punch 582: every audit-write loss site that no exception carries to the
``@db_write`` gap sentinel routes into the durable loss recorder.

The loss classes are enumerated in ``et-v020-fresh/582-enumeration.md``
(L1-L11). Behaviour is tested one class at a time in
``tests/test_web/test_582_audit_loss_trace.py``; this pin holds the structure,
count-agnostic over every parseable file under ``src/email_triage``
(``walk_src``), with teeth for each arm.

ARMS

1. **Loss sites reach the recorder.** Every def anywhere under src that logs a
   loss event (``audit_write_cancelled``, ``audit_write_cancelled_shielded``,
   ``audit_done_callback_swallow``, ``audit_write_failed``) or checks
   ``<x>.cancelled()`` calls ``record_audit_loss``, either directly or through a
   same-module def that does, closed to a fixpoint (interprocedural, PD-2). The
   innermost def is the unit, so a closure is checked on its own.
2. **Fire-and-forget audit tasks carry the done-callback.** Every
   ``create_task`` / ``ensure_future`` whose argument calls an *audit-writer
   coroutine* (derived: an async def under src that calls
   ``safe_audit_write_async``) sits in a function that also calls
   ``attach_audit_done_callback``, or is a reasoned ALLOW entry.
3. **The writer refuses after STOP, and reports an abandoned queue.**
   ``SqliteWriterThread.submit_write`` raises ``WriterStopped`` under an
   ``if self._stopping`` before its ``put_nowait``; ``shutdown`` calls
   ``record_audit_loss``.
4. **Lifespan order.** Inside ``web/app.py``'s ``lifespan``:
   ``register_audit_loss_sink(<sink>)`` comes before ``yield``; after it,
   ``drain_inflight_audit_writes`` comes before the writer's ``shutdown()``
   and before both sinks are unregistered.
5. **One chain, one writer.** ``db/audit.record_audit_write_loss`` calls
   ``_write_audit_gap_event`` and carries no SQL of its own;
   ``web/_audit.record_audit_loss`` never touches a connection.
6. **No double record.** Every def outside ``db/audit.py`` whose body (closures
   included) calls ``_write_audit_gap_event`` also calls
   ``mark_audit_gap_recorded``, so the best-effort SSOT one layer out does not
   record the same loss again.

7. **Presumptive classes are known classes.** Every class in
   ``db/audit.PRESUMPTIVE_LOSS_CLASSES`` is in ``AUDIT_WRITE_LOSS_CLASSES``
   (panel B7, hipaa F2), so the ``certainty=presumptive`` suffix can never
   name a class the recorder refuses.
8. **The L6 sentinel is wired before any lock wait** (panel B7, DB-2). The
   lifespan replays ``.audit-writer-abandoned`` after the loss sink registers
   and before ``yield``, and passes ``on_abandoned=`` to the writer's
   ``shutdown()``; ``SqliteWriterThread.shutdown`` calls ``on_abandoned``
   before ``record_audit_loss``.
9. **A PD-14 emitter's loss row names its table** (panel B7, hipaa F1).
   Every ``safe_audit_write*`` call whose FIRST ARGUMENT reaches
   ``record_hipaa_access_event`` or ``record_access_event`` passes the
   literal ``table=`` and ``emitter=`` for that emitter. "Reaches" is
   interprocedural within the module: the names in the argument expression
   (a ``lambda: db_call(record_hipaa_access_event, ...)``), import aliases
   resolved, closed over every same-module def those names call, to a
   fixpoint (``lambda: asyncio.to_thread(_emit)``).

10. **The write lock exposes its ownership probe** (DA fold-check, panel
    B7). The loss sink reads ``lock._is_owned()`` to tell a caller's own
    open transaction (refuse) from orphaned residue (roll back). Its
    fallback, "probe missing, so assume owned", must stay unreachable: a
    lock swap without the probe would silently send every residue case to
    the refusal path.

WHAT A GREEN RUN DOES NOT PROVE (fail-OPEN directions, stated):
- Arm 1 checks that the recorder is reachable from the def, not that every
  branch of it records (no path analysis); the behaviour tests carry that.
- A loss produced by a mechanism no arm names (an emitter call that bypasses
  both funnels and is swallowed elsewhere, an OS kill, a loss after commit) is
  not seen: enumeration_complete=false in the enumeration.
- Arm 2 follows only direct calls of a derived audit-writer coroutine passed
  to ``create_task`` / ``ensure_future``.
- Arm 9 does not follow a call into ANOTHER module (a first argument that
  calls an imported helper which in turn writes a PD-14 row is not seen),
  and matches defs by bare name within the module.
"""

from __future__ import annotations

import ast

from _pin_harness import (
    SRC_ROOT, assert_pin_has_teeth, enclosing_scope_chain, innermost_fn_at_lineno,
    parse_module, parse_source, relpath, walk_src,
)

_RECORDER = "record_audit_loss"
_LOSS_EVENTS = frozenset({
    "audit_write_cancelled",
    "audit_write_cancelled_shielded",
    "audit_done_callback_swallow",
    "audit_write_failed",
})
_SPAWNERS = frozenset({"create_task", "ensure_future"})

#: ``(relpath, enclosing function) -> reason`` for a spawn of an audit-writer
#: coroutine without the done-callback. A stale entry fails its test.
ALLOW_SPAWN: dict[tuple[str, str], str] = {}

#: Arm 1: ``(repo-relative path, function) -> reason`` for a def the loss-site
#: scan flags (a ``.cancelled()`` check) that is NOT an audit-write loss site.
#: Keyed by repo-relative path (R38), never basename; the function is the
#: scan's unit (``_defs``: a top-level def's name is its qualname). An entry
#: hides only that function in that file, and a stale entry (gone, or no
#: longer flagged) fails ``test_every_loss_site_reaches_the_recorder``.
ALLOW_LOSS_CHECK: dict[tuple[str, str], str] = {
    ("src/email_triage/tls.py", "_log_late_cert_failure"): (
        "TLS log done-callback (panel M M-DA-7/M-DA-13), not an audit write: it "
        "logs a late certificate-verification failure of an aioimaplib handshake; "
        "a cancelled handshake has no result to lose, so there is no audit loss "
        "to record."
    ),
    ("src/email_triage/providers/imap_fetch_transport.py", "aioimaplib_wait_hello"): (
        "IMAP greeting wait (t20), not an audit write: it reads aioimaplib's connection "
        "task to raise a failed connect at once; a cancelled connection task is not "
        "an error to raise, the greeting wait runs on to its deadline, and there is no "
        "audit loss to record."
    ),
}


def _name_of(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _defs(tree: ast.AST) -> list[ast.AST]:
    return [n for n in ast.walk(tree)
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]


def _own_calls(fn: ast.AST) -> set[str]:
    """Names called in ``fn``'s own body, nested defs excluded."""
    out: set[str] = set()
    stack = list(ast.iter_child_nodes(fn))
    while stack:
        n = stack.pop()
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            continue
        if isinstance(n, ast.Call):
            nm = _name_of(n.func)
            if nm:
                out.add(nm)
        stack.extend(ast.iter_child_nodes(n))
    return out


def _is_loss_site(fn: ast.AST) -> bool:
    stack = list(ast.iter_child_nodes(fn))
    while stack:
        n = stack.pop()
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            continue
        if isinstance(n, ast.Call):
            nm = _name_of(n.func)
            if nm == "cancelled" and not n.args:
                return True
            if (nm in {"debug", "info", "warning", "error", "exception"}
                    and n.args and isinstance(n.args[0], ast.Constant)
                    and n.args[0].value in _LOSS_EVENTS):
                return True
        stack.extend(ast.iter_child_nodes(n))
    return False


def reachers(tree: ast.AST) -> set[str]:
    """Defs in ``tree`` that call the recorder, directly or through another
    def of the same module, to a fixpoint."""
    defs = _defs(tree)
    calls = {fn.name: _own_calls(fn) for fn in defs}
    reach = {name for name, c in calls.items() if _RECORDER in c}
    changed = True
    while changed:
        changed = False
        for name, c in calls.items():
            if name not in reach and c & (reach | {_RECORDER}):
                reach.add(name)
                changed = True
    return reach


def unrecorded_loss_sites(tree: ast.AST) -> list[str]:
    reach = reachers(tree) | {_RECORDER}
    return [
        fn.name for fn in _defs(tree)
        if fn.name != _RECORDER and _is_loss_site(fn) and not (_own_calls(fn) & reach)
    ]


def _repo_rel(rel: str) -> str:
    """``walk_src`` paths are relative to ``src/email_triage``."""
    return f"src/email_triage/{rel}"


def unallowed_loss_sites(rel: str, tree: ast.AST) -> list[str]:
    """``unrecorded_loss_sites`` minus the ``ALLOW_LOSS_CHECK`` entries for
    this file (``rel`` as ``walk_src`` gives it)."""
    return [s for s in unrecorded_loss_sites(tree)
            if (_repo_rel(rel), s) not in ALLOW_LOSS_CHECK]


def audit_writer_coroutines(trees: list[ast.AST]) -> set[str]:
    return {
        fn.name for tree in trees for fn in _defs(tree)
        if isinstance(fn, ast.AsyncFunctionDef) and "safe_audit_write_async" in _own_calls(fn)
        and fn.name != "safe_audit_write_async"
    }


def unguarded_spawns(tree: ast.AST, writers: set[str]) -> list[tuple[str, int]]:
    out = []
    for n in ast.walk(tree):
        if not (isinstance(n, ast.Call) and _name_of(n.func) in _SPAWNERS and n.args):
            continue
        arg = n.args[0]
        if not (isinstance(arg, ast.Call) and _name_of(arg.func) in writers):
            continue
        fn = innermost_fn_at_lineno(tree, n.lineno)
        if fn is None or "attach_audit_done_callback" not in _own_calls(fn):
            out.append((fn.name if fn is not None else "<module>", n.lineno))
    return out


def writer_guard_violations(tree: ast.AST) -> list[str]:
    bad = []
    cls = next((n for n in ast.walk(tree)
                if isinstance(n, ast.ClassDef) and n.name == "SqliteWriterThread"), None)
    if cls is None:
        return ["SqliteWriterThread not found"]
    meths = {n.name: n for n in cls.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
    submit = meths.get("submit_write")
    put_line = min((n.lineno for n in ast.walk(submit) if isinstance(n, ast.Call)
                    and _name_of(n.func) == "put_nowait"), default=None) if submit else None
    guard_line = None
    for n in ast.walk(submit) if submit else ():
        if (isinstance(n, ast.If) and any(isinstance(t, ast.Attribute) and t.attr == "_stopping"
                                          for t in ast.walk(n.test))
                and any(isinstance(s, ast.Raise) and isinstance(s.exc, ast.Call)
                        and _name_of(s.exc.func) == "WriterStopped" for s in n.body)):
            guard_line = n.lineno
    if put_line is None or guard_line is None or guard_line > put_line:
        bad.append("submit_write does not refuse with WriterStopped before put_nowait")
    shutdown = meths.get("shutdown")
    if shutdown is None or _RECORDER not in _own_calls(shutdown):
        bad.append("shutdown does not record an abandoned queue")
    return bad


def lifespan_order_violations(tree: ast.AST) -> list[str]:
    life = next((n for n in ast.walk(tree)
                 if isinstance(n, ast.AsyncFunctionDef) and n.name == "lifespan"), None)
    if life is None:
        return ["lifespan not found"]
    yields = [n.lineno for n in ast.walk(life) if isinstance(n, (ast.Yield, ast.YieldFrom))]
    if not yields:
        return ["lifespan has no yield"]
    y = yields[0]

    def _lines(pred) -> list[int]:
        return sorted(n.lineno for n in ast.walk(life) if isinstance(n, ast.Call) and pred(n))

    def _reg(name: str, none: bool):
        return lambda c: (_name_of(c.func) == name and c.args
                          and (isinstance(c.args[0], ast.Constant) and c.args[0].value is None) == none)

    bad = []
    if not [ln for ln in _lines(_reg("register_audit_loss_sink", False)) if ln < y]:
        bad.append("register_audit_loss_sink(<sink>) is not before yield")
    drains = [ln for ln in _lines(lambda c: _name_of(c.func) == "drain_inflight_audit_writes") if ln > y]
    if not drains:
        return bad + ["drain_inflight_audit_writes is not called after yield"]
    d = drains[0]
    for label, pred in (
        ("writer shutdown()", lambda c: _name_of(c.func) == "shutdown"),
        ("register_audit_failure_sink(None)", _reg("register_audit_failure_sink", True)),
        ("register_audit_loss_sink(None)", _reg("register_audit_loss_sink", True)),
    ):
        after = [ln for ln in _lines(pred) if ln > y]
        if not after or min(after) < d:
            bad.append(f"{label} is not after the audit drain")
    return bad


_SQL_CALLS = frozenset({"execute", "executemany", "executescript"})


def own_sql_violations(fn: ast.AST) -> list[str]:
    """SQL ``fn`` carries itself: a call to ``execute``/``executemany``/
    ``executescript``, or a string constant naming an INSERT. The docstring is
    prose, not SQL, so it is skipped (it may say "no raw INSERT")."""
    doc = None
    body = getattr(fn, "body", [])
    if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
        doc = body[0].value
    out = []
    for n in ast.walk(fn):
        if isinstance(n, ast.Call) and _name_of(n.func) in _SQL_CALLS:
            out.append(f"{_name_of(n.func)}() at line {n.lineno}")
        elif (isinstance(n, ast.Constant) and n is not doc and isinstance(n.value, str)
              and "INSERT" in n.value.upper()):
            out.append(f"INSERT literal at line {n.lineno}")
    return out


def sentinel_wiring_violations(life_tree: ast.AST, writer_tree: ast.AST) -> list[str]:
    """Arm 8 (panel B7 DB-2): the lifespan replays the L6 sentinel after the
    loss sink registers and before ``yield``, and passes ``on_abandoned=`` to
    the writer's ``shutdown()`` after it; ``SqliteWriterThread.shutdown``
    calls ``on_abandoned`` before ``record_audit_loss``."""
    bad = []
    life = next((n for n in ast.walk(life_tree)
                 if isinstance(n, ast.AsyncFunctionDef) and n.name == "lifespan"), None)
    if life is None:
        return ["lifespan not found"]
    yields = [n.lineno for n in ast.walk(life) if isinstance(n, (ast.Yield, ast.YieldFrom))]
    calls = [n for n in ast.walk(life) if isinstance(n, ast.Call)]
    regs = [c.lineno for c in calls if _name_of(c.func) == "register_audit_loss_sink"
            and c.args and not (isinstance(c.args[0], ast.Constant) and c.args[0].value is None)]
    replays = [c.lineno for c in calls if _name_of(c.func) == "replay_writer_abandoned_sentinel"]
    if not (yields and regs and [ln for ln in replays if min(regs) < ln < yields[0]]):
        bad.append("replay_writer_abandoned_sentinel is not between the sink registration and yield")
    if not [c for c in calls if _name_of(c.func) == "shutdown" and yields and c.lineno > yields[0]
            and any(k.arg == "on_abandoned" for k in c.keywords)]:
        bad.append("the writer shutdown() after yield does not pass on_abandoned=")
    cls = next((n for n in ast.walk(writer_tree)
                if isinstance(n, ast.ClassDef) and n.name == "SqliteWriterThread"), None)
    shut = next((n for n in (cls.body if cls else [])
                 if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == "shutdown"), None)
    if shut is None:
        return bad + ["SqliteWriterThread.shutdown not found"]
    cb = [n.lineno for n in ast.walk(shut) if isinstance(n, ast.Call) and _name_of(n.func) == "on_abandoned"]
    rec = [n.lineno for n in ast.walk(shut) if isinstance(n, ast.Call) and _name_of(n.func) == _RECORDER]
    if not cb or not rec or min(cb) > min(rec):
        bad.append("shutdown does not call on_abandoned before record_audit_loss")
    return bad


#: The PD-14 emitters whose lost rows must name their table (arm 9).
PD14_EMITTER_TABLES: dict[str, str] = {
    "record_hipaa_access_event": "hipaa_access_events",
    "record_access_event": "access_log",
}
_SAFE_WRITERS = frozenset({"safe_audit_write", "safe_audit_write_async"})


def pd14_emitter_sites(tree: ast.AST) -> list[tuple[ast.Call, set[str]]]:
    """Every ``safe_audit_write*`` call whose first argument reaches a PD-14
    emitter, with the emitters it reaches (arm 9)."""
    aliases = {a.asname: a.name for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)
               for a in n.names if a.asname}

    def names_in(node: ast.AST) -> set[str]:
        raw = {_name_of(n) for n in ast.walk(node)
               if isinstance(n, (ast.Name, ast.Attribute))} - {None}
        return raw | {aliases[n] for n in raw if n in aliases}

    defs: dict[str, list[ast.AST]] = {}
    for fn in _defs(tree):
        defs.setdefault(fn.name, []).append(fn)
    out = []
    for c in ast.walk(tree):
        if not (isinstance(c, ast.Call) and _name_of(c.func) in _SAFE_WRITERS and c.args):
            continue
        names = names_in(c.args[0])
        frontier, seen = [n for n in names if n in defs], set()
        while frontier:
            d = frontier.pop()
            if d in seen:
                continue
            seen.add(d)
            for fn in defs[d]:
                new = names_in(fn) - names
                names |= new
                frontier += [n for n in new if n in defs]
        reached = names & set(PD14_EMITTER_TABLES)
        if reached:
            out.append((c, reached))
    return out


def pd14_table_violations(tree: ast.AST) -> list[str]:
    bad = []
    for c, reached in pd14_emitter_sites(tree):
        kw = {k.arg: k.value for k in c.keywords}
        for em in sorted(reached):
            tbl, emitter = kw.get("table"), kw.get("emitter")
            if not (isinstance(tbl, ast.Constant) and tbl.value == PD14_EMITTER_TABLES[em]
                    and isinstance(emitter, ast.Constant) and emitter.value == em):
                bad.append(f"line {c.lineno}: reaches {em} without "
                           f"table={PD14_EMITTER_TABLES[em]!r}, emitter={em!r}")
    return bad


def double_record_violations(tree: ast.AST, rel: str) -> list[str]:
    if rel == "db/audit.py":
        return []
    out = []
    for n in ast.walk(tree):
        if isinstance(n, ast.Call) and _name_of(n.func) == "_write_audit_gap_event":
            chain = enclosing_scope_chain(tree, n.lineno)
            outer = chain[-2] if len(chain) >= 2 else None
            names = {_name_of(c.func) for c in ast.walk(outer) if isinstance(c, ast.Call)} if outer else set()
            if "mark_audit_gap_recorded" not in names:
                out.append(f"{rel}:{n.lineno}")
    return out


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_every_loss_site_reaches_the_recorder():
    bad, seen, flagged = [], [], set()
    for _p, rel, tree in walk_src():
        sites = [fn.name for fn in _defs(tree) if _is_loss_site(fn)]
        seen += [f"{rel}:{s}" for s in sites]
        flagged |= {(_repo_rel(rel), s) for s in unrecorded_loss_sites(tree)}
        bad += [f"{rel}:{s}" for s in unallowed_loss_sites(rel, tree)]
    stale = [k for k in ALLOW_LOSS_CHECK if k not in flagged]
    assert not stale, f"stale ALLOW_LOSS_CHECK entry (gone, or no longer flagged): {stale}"
    for known in ("web/_audit.py:safe_audit_write", "web/_audit.py:safe_audit_write_async",
                  "web/_audit.py:_cb", "web/_audit.py:_inner_write_done"):
        assert known in seen, f"loss-site scan missed {known}: {seen}"
    assert not bad, f"audit-write loss sites that never reach {_RECORDER}: {bad}"


def test_every_fire_and_forget_audit_task_carries_the_done_callback():
    trees = [(rel, tree) for _p, rel, tree in walk_src()]
    writers = audit_writer_coroutines([t for _r, t in trees])
    assert "_audit_write" in writers, sorted(writers)
    flagged = {(rel, fn): ln for rel, tree in trees for fn, ln in unguarded_spawns(tree, writers)}
    offenders = {k: v for k, v in flagged.items() if k not in ALLOW_SPAWN}
    assert not offenders, f"fire-and-forget audit tasks without attach_audit_done_callback: {offenders}"
    assert not [k for k in ALLOW_SPAWN if k not in flagged], "stale ALLOW_SPAWN entry"


def test_writer_refuses_after_stop_and_reports_an_abandoned_queue():
    assert writer_guard_violations(parse_module(SRC_ROOT / "db/_writer.py")) == []


def test_lifespan_drains_before_the_writer_and_the_sinks_go():
    assert lifespan_order_violations(parse_module(SRC_ROOT / "web/app.py")) == []


def test_loss_rows_use_the_one_gap_writer():
    audit_defs = {fn.name: fn for fn in _defs(parse_module(SRC_ROOT / "db/audit.py"))}
    rec = audit_defs["record_audit_write_loss"]
    assert "_write_audit_gap_event" in _own_calls(rec)
    assert own_sql_violations(rec) == []
    # The sink is a partial over a module-level body that records through
    # the same SSOT.
    assert "record_audit_write_loss" in _own_calls(audit_defs["_record_audit_write_loss_locked"])
    assert "_record_audit_write_loss_locked" in {
        n.id for n in ast.walk(audit_defs["make_audit_loss_sink"]) if isinstance(n, ast.Name)}
    web = {fn.name: fn for fn in _defs(parse_module(SRC_ROOT / "web/_audit.py"))}
    assert "execute" not in _own_calls(web[_RECORDER])


def presumptive_violations(presumptive, known) -> list[str]:
    """Presumptive classes that are not known loss classes (arm 7)."""
    return sorted(set(presumptive) - set(known))


def test_presumptive_classes_are_known_loss_classes():
    from email_triage.db.audit import AUDIT_WRITE_LOSS_CLASSES, PRESUMPTIVE_LOSS_CLASSES
    assert PRESUMPTIVE_LOSS_CLASSES, "the presumptive set is empty"
    assert presumptive_violations(PRESUMPTIVE_LOSS_CLASSES, AUDIT_WRITE_LOSS_CLASSES) == []


def test_presumptive_arm_has_teeth():
    known = {"shutdown_undrained", "done_callback_swallow", "inner_cancelled"}
    assert presumptive_violations({"shutdown_undrianed"}, known) == ["shutdown_undrianed"]
    assert presumptive_violations({"shutdown_undrained"}, known) == []


def test_gap_writer_callers_mark_the_exception():
    bad = []
    for _p, rel, tree in walk_src():
        bad += double_record_violations(tree, rel)
    assert not bad, f"_write_audit_gap_event callers that do not mark_audit_gap_recorded: {bad}"


# ---------------------------------------------------------------------------
# Teeth
# ---------------------------------------------------------------------------


def test_loss_site_arm_has_teeth():
    assert_pin_has_teeth(
        unrecorded_loss_sites,
        "def _cb(t):\n    if t.cancelled():\n        stash()\n",
        "def _cb(t):\n    if t.cancelled():\n        record_audit_loss('x')\n",
    )
    # Through a same-module helper (interprocedural) is clean.
    assert not unrecorded_loss_sites(parse_source(
        "def _note():\n    record_audit_loss('x')\n"
        "def f():\n    try:\n        w()\n    except BaseException:\n"
        "        log.debug('audit_write_cancelled')\n        _note()\n        raise\n"))
    # A logged loss event with no recorder is flagged; a closure is its own unit.
    assert unrecorded_loss_sites(parse_source(
        "def f():\n    try:\n        w()\n    except Exception:\n"
        "        log.warning('audit_write_failed')\n"))
    assert unrecorded_loss_sites(parse_source(
        "def outer():\n    record_audit_loss('x')\n"
        "    def _cb(t):\n        if t.cancelled():\n            pass\n"
        "    return _cb\n")) == ["_cb"]


def test_loss_check_allow_list_has_teeth():
    """An ALLOW_LOSS_CHECK entry hides exactly its own (file, function): a real
    audit done-callback that checks ``.cancelled()`` and never reaches the
    recorder is still flagged, in the allowed file and anywhere else."""
    tree = parse_source(
        "def _log_late_cert_failure(fut):\n    if fut.cancelled():\n        return\n"
        "def _audit_done(t):\n    if t.cancelled():\n        stash()\n"
    )
    assert sorted(unrecorded_loss_sites(tree)) == ["_audit_done", "_log_late_cert_failure"]
    # Same file as the entry: only the allowed function is hidden.
    assert unallowed_loss_sites("tls.py", tree) == ["_audit_done"]
    # Another file: the entry hides nothing (path-keyed, not name-keyed).
    assert sorted(unallowed_loss_sites("web/other.py", tree)) == [
        "_audit_done", "_log_late_cert_failure"]
    # The entry's own function still counts as a loss site to the scan.
    assert ("src/email_triage/tls.py", "_log_late_cert_failure") in ALLOW_LOSS_CHECK


def test_spawn_arm_has_teeth():
    writers = {"_audit_write"}
    assert unguarded_spawns(parse_source(
        "async def d():\n    t = asyncio.create_task(_audit_write(x=1))\n"), writers)
    assert not unguarded_spawns(parse_source(
        "async def d():\n    t = asyncio.create_task(_audit_write(x=1))\n"
        "    attach_audit_done_callback(t, 'd')\n"), writers)
    assert not unguarded_spawns(parse_source(
        "async def d():\n    asyncio.create_task(other())\n"), writers)
    assert audit_writer_coroutines([parse_source(
        "async def _w():\n    await safe_audit_write_async(lambda: 1, description='d')\n"
        "def _sync():\n    safe_audit_write_async\n")]) == {"_w"}


def test_writer_and_lifespan_arms_have_teeth():
    good_writer = (
        "class SqliteWriterThread:\n"
        "    async def submit_write(self, fn):\n"
        "        if self._stopping:\n            raise WriterStopped('x')\n"
        "        self._q.put_nowait(fn)\n"
        "    async def shutdown(self):\n        record_audit_loss('writer_queue_abandoned')\n")
    assert writer_guard_violations(parse_source(good_writer)) == []
    assert writer_guard_violations(parse_source(good_writer.replace(
        "        if self._stopping:\n            raise WriterStopped('x')\n", "")))
    assert writer_guard_violations(parse_source(good_writer.replace(
        "record_audit_loss('writer_queue_abandoned')", "pass")))
    good_life = (
        "async def lifespan(app):\n"
        "    register_audit_loss_sink(make_audit_loss_sink(conn))\n"
        "    yield\n"
        "    await drain_inflight_audit_writes(5)\n"
        "    await writer.shutdown()\n"
        "    register_audit_failure_sink(None)\n"
        "    register_audit_loss_sink(None)\n")
    assert lifespan_order_violations(parse_source(good_life)) == []
    late = good_life.replace("    await drain_inflight_audit_writes(5)\n", "") + \
        "    await drain_inflight_audit_writes(5)\n"
    assert lifespan_order_violations(parse_source(late))
    assert lifespan_order_violations(parse_source(good_life.replace(
        "    register_audit_loss_sink(make_audit_loss_sink(conn))\n", "")))


def test_one_writer_arm_has_teeth():
    def _detector(tree):
        return own_sql_violations(_defs(tree)[0])

    good = (
        "def record_audit_write_loss(conn):\n"
        "    '''Through the gap writer; no raw INSERT.'''\n"
        "    _write_audit_gap_event(conn)\n")
    assert_pin_has_teeth(
        _detector,
        good.replace("    _write_audit_gap_event(conn)\n",
                     "    conn.execute('INSERT INTO audit_gap_events VALUES (1)')\n"),
        good,
    )
    assert _detector(parse_source(good.replace(
        "    _write_audit_gap_event(conn)\n", "    sql = 'insert into t values (1)'\n")))


def test_l6_sentinel_is_wired_before_any_lock_wait():
    assert sentinel_wiring_violations(
        parse_module(SRC_ROOT / "web/app.py"), parse_module(SRC_ROOT / "db/_writer.py"),
    ) == []


def test_sentinel_arm_has_teeth():
    life = (
        "async def lifespan(app):\n"
        "    register_audit_loss_sink(make_audit_loss_sink(conn))\n"
        "    replay_writer_abandoned_sentinel(d)\n"
        "    yield\n"
        "    await w.shutdown(on_abandoned=cb)\n")
    writer = (
        "class SqliteWriterThread:\n"
        "    async def shutdown(self, on_abandoned=None):\n"
        "        on_abandoned(1)\n"
        "        record_audit_loss('writer_queue_abandoned')\n")
    assert sentinel_wiring_violations(parse_source(life), parse_source(writer)) == []
    assert sentinel_wiring_violations(parse_source(life.replace(
        "    replay_writer_abandoned_sentinel(d)\n", "")), parse_source(writer))
    assert sentinel_wiring_violations(parse_source(life.replace(
        "on_abandoned=cb", "")), parse_source(writer))
    assert sentinel_wiring_violations(parse_source(life), parse_source(writer.replace(
        "        on_abandoned(1)\n        record_audit_loss('writer_queue_abandoned')\n",
        "        record_audit_loss('writer_queue_abandoned')\n        on_abandoned(1)\n")))


def test_pd14_emitter_loss_rows_name_their_table():
    bad, per_emitter = [], {em: 0 for em in PD14_EMITTER_TABLES}
    for _p, rel, tree in walk_src():
        for _c, reached in pd14_emitter_sites(tree):
            for em in reached:
                per_emitter[em] += 1
        bad += [f"{rel}: {v}" for v in pd14_table_violations(tree)]
    # Non-vacuous: the predicate reaches both emitters' sites.
    assert all(per_emitter.values()), per_emitter
    assert not bad, f"PD-14 audit writes whose loss row would say table=unknown: {bad}"


def test_pd14_arm_has_teeth():
    bad = (
        "async def h():\n"
        "    await safe_audit_write_async(\n"
        "        lambda: db_call(record_hipaa_access_event, conn, x=1),\n"
        "        description='d')\n")
    good = bad.replace("description='d')",
                       "description='d', table='hipaa_access_events',\n"
                       "        emitter='record_hipaa_access_event')")
    assert_pin_has_teeth(pd14_table_violations, bad, good)
    # The wrong table is flagged.
    assert pd14_table_violations(parse_source(good.replace("'hipaa_access_events'", "'access_log'")))
    # Through an import alias and a same-module def (interprocedural).
    via = (
        "from email_triage.web.db import record_access_event as _rae\n"
        "def _emit():\n"
        "    _rae(conn)\n"
        "async def h():\n"
        "    await safe_audit_write_async(lambda: asyncio.to_thread(_emit), description='d')\n")
    assert pd14_table_violations(parse_source(via))
    assert not pd14_table_violations(parse_source(via.replace(
        "description='d')", "description='d', table='access_log', emitter='record_access_event')")))
    # A call that reaches no PD-14 emitter is not a site.
    assert not pd14_emitter_sites(parse_source(
        "def f():\n    safe_audit_write(lambda: record_auth_event(c), description='d')\n"))


def lock_probe_violations(lock) -> list[str]:
    """Arm 10: the write lock must expose a callable ``_is_owned``."""
    return [] if callable(getattr(lock, "_is_owned", None)) else [
        f"{type(lock).__name__} has no callable _is_owned"]


def test_write_lock_exposes_its_ownership_probe():
    from email_triage.web.db_writelock import get_write_lock
    assert lock_probe_violations(get_write_lock()) == []


def test_lock_probe_arm_has_teeth():
    import threading
    assert lock_probe_violations(object())
    assert lock_probe_violations(threading.Lock())  # a plain Lock has no _is_owned
    assert lock_probe_violations(threading.RLock()) == []


def test_double_record_arm_has_teeth():
    bad = "def db_write(fn):\n    def wrapper():\n        _write_audit_gap_event(conn)\n    return wrapper\n"
    assert double_record_violations(parse_source(bad), "web/x.py")
    good = bad.replace("_write_audit_gap_event(conn)\n",
                       "_write_audit_gap_event(conn)\n        mark_audit_gap_recorded(exc)\n")
    assert not double_record_violations(parse_source(good), "web/x.py")
    assert not double_record_violations(parse_source(bad), "db/audit.py")
    assert relpath(SRC_ROOT / "db/audit.py") == "db/audit.py"
