""" — sync-sqlite-in-async ratchet pin.

Python's `sqlite3` module holds the GIL for the entire query execution,
so calling `.execute(...)`/`.fetchall()`/`.fetchone()`/`.executemany()`
directly from an `async def` blocks the entire event loop for the
query duration. Best practice is to route through `await asyncio.to_thread(
...)` or the project's `db_call(...)` helper (which off-loads the query
onto a threadpool worker).

Not every direct call is a defect: a single-row PK lookup returns in
microseconds and the block is negligible. But a table scan, an
aggregation, or a batch fetch on a hot route WILL stall the entire
async worker for milliseconds under load.

This pin is a RATCHET: the 46 pre-#141 `(rel, async_fn)` pairs at
2026-07-11 baseline are grandfathered; NEW sync-sqlite calls inside
an async fn NOT in baseline fail CI. As sites migrate to
`await db_call(fn, ...)` / `await asyncio.to_thread(fn, ...)`, the
baseline shrinks via `test_baseline_never_grows`.

Prime Directive #6: routes through `_pin_harness`. Name-anchored per
 R38.

Grounding: 2026-07-11 workflow `wf_6b905503-f84` sync-sqlite-in-async
audit reported 112 sites in 26 files; direct AST verification counted
116 direct call sites collapsed into 46 unique `(rel, async_fn)` pairs.
"""
from __future__ import annotations

import ast

from _pin_harness import iter_src_files, parse_module, relpath


_DB_METHOD_NAMES: frozenset[str] = frozenset({
    "execute", "fetchall", "fetchone", "executemany",
})


# Baseline: the `(rel, async_fn)` pairs that still run a direct sqlite call ON
# THE EVENT LOOP. First generated 2026-07-11 at HEAD `34373c60` (46 pairs).
# 2026-11-07 (allow-list class sync-sqlite): the detector now skips nested sync
# helpers that are only handed to `db_call` / `to_thread` / `run_in_executor`
# (they run on a worker thread). 39 pairs were already migrated that way under
#  but the old detector could never see it; they are cut.
_BASELINE_SYNC_SQLITE: frozenset[tuple[str, str]] = frozenset({
    ("cli.py", "_run"),
    ("engine/flow.py", "route_and_act"),
    ("web/app.py", "lifespan"),
    ("web/triage_one.py", "triage_single_message"),
})


# Calls that run their callable argument on a worker thread, off the event
# loop. Bare names: the project's `db_call` (and its `_db_call` alias) and
# `from asyncio import to_thread`. Attributes: only `asyncio.to_thread(fn)`
# and `<loop>.run_in_executor(executor, fn)` (callable second); any other
# `obj.db_call(...)` is NOT trusted as an offload (fail closed).
_OFFLOAD_BARE_NAMES: frozenset[str] = frozenset({"db_call", "_db_call", "to_thread"})


def _callee_name(call: ast.Call) -> str | None:
    f = call.func
    if isinstance(f, ast.Name):
        return f.id
    if isinstance(f, ast.Attribute):
        return f.attr
    return None


def _offload_arg_index(call: ast.Call) -> int | None:
    f = call.func
    if isinstance(f, ast.Name) and f.id in _OFFLOAD_BARE_NAMES:
        return 0
    if isinstance(f, ast.Attribute):
        if (f.attr == "to_thread" and isinstance(f.value, ast.Name)
                and f.value.id == "asyncio"):
            return 0
        if f.attr == "run_in_executor":
            return 1
    return None


def _offloaded_callable(call: ast.Call) -> ast.AST | None:
    """The callable argument an offload call hands to a worker thread, with
    one `functools.partial(fn, ...)` layer unwrapped; else None."""
    idx = _offload_arg_index(call)
    if idx is None or len(call.args) <= idx:
        return None
    arg = call.args[idx]
    if (isinstance(arg, ast.Call) and _callee_name(arg) == "partial"
            and arg.args):
        arg = arg.args[0]
    return arg


def _runs_at_definition(fn_node: ast.AST) -> list[ast.AST]:
    """Parts of a def/lambda that run where it is DEFINED (on the loop), not
    where it is called: decorators and default values."""
    parts: list[ast.AST] = list(getattr(fn_node, "decorator_list", []))
    args = fn_node.args
    parts.extend(args.defaults)
    parts.extend(d for d in args.kw_defaults if d is not None)
    return parts


def _async_fn_has_sync_sqlite(fn: ast.AsyncFunctionDef) -> bool:
    """True when `fn` runs a direct sqlite method ON THE EVENT LOOP.

    A nested sync `def` runs on a worker thread, so its BODY is not counted,
    only when EVERY load of its name inside `fn` is the callable argument of
    an offload call (`db_call` / `asyncio.to_thread` / `run_in_executor`).
    Any other use (a direct call, an alias, `partial(f)()`, a callback, a
    sync helper) may run it on the loop, so it is counted. A generator def is
    never skipped (its results are consumed where it is iterated). Same rule
    for a lambda that is itself the offload argument. Decorators and default
    values of a skipped def still run on the loop and are always scanned."""
    offload_arg_nodes: set[int] = set()
    for n in ast.walk(fn):
        if isinstance(n, ast.Call):
            target = _offloaded_callable(n)
            if target is not None:
                offload_arg_nodes.add(id(target))

    nested_defs = [
        n for n in ast.walk(fn)
        if isinstance(n, ast.FunctionDef)
        and not any(isinstance(y, (ast.Yield, ast.YieldFrom)) for y in ast.walk(n))
    ]
    skip_def_ids: set[int] = set()
    for d in nested_defs:
        loads = [
            n for n in ast.walk(fn)
            if isinstance(n, ast.Name) and n.id == d.name
            and isinstance(n.ctx, ast.Load)
        ]
        if loads and all(id(n) in offload_arg_nodes for n in loads):
            skip_def_ids.add(id(d))

    stack: list[ast.AST] = list(ast.iter_child_nodes(fn))
    while stack:
        node = stack.pop()
        if id(node) in skip_def_ids or (
                isinstance(node, ast.Lambda) and id(node) in offload_arg_nodes):
            stack.extend(_runs_at_definition(node))
            continue
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr in _DB_METHOD_NAMES):
            return True
        stack.extend(ast.iter_child_nodes(node))
    return False


def _offenders_in_tree(tree: ast.AST) -> set[str]:
    return {
        node.name
        for node in ast.walk(tree)
        if isinstance(node, ast.AsyncFunctionDef)
        and _async_fn_has_sync_sqlite(node)
    }


def _collect_offenders() -> set[tuple[str, str]]:
    out: set[tuple[str, str]] = set()
    for path in iter_src_files():
        rel = relpath(path)
        tree = parse_module(path)
        if not isinstance(tree, ast.Module):
            continue
        out.update((rel, name) for name in _offenders_in_tree(tree))
    return out


def test_no_new_sync_sqlite_in_async_outside_baseline():
    """Ban NEW direct `.execute` / `.fetchall` / `.fetchone` /
    `.executemany` inside an `async def` in a `(rel, fn)` pair NOT
    in the 2026-07-11 baseline. Route through `await db_call(...)`
    or `await asyncio.to_thread(...)` to keep the event loop free."""
    fresh = _collect_offenders() - _BASELINE_SYNC_SQLITE
    assert not fresh, (
        "#141 sync-sqlite-in-async ratchet: NEW direct sqlite call "
        "inside `async def` in a (rel, fn) pair NOT in baseline. "
        "Python's sqlite3 GIL-holds the query — direct calls block "
        "the event loop. Route via `await db_call(fn, ...)` or "
        "`await asyncio.to_thread(fn, ...)`. If a genuinely fast "
        "single-row PK lookup is truly non-blocking, add "
        "`(rel, async_fn)` to `_BASELINE_SYNC_SQLITE` with a "
        "justification comment.\n\n"
        + "\n".join(f"  {rel}::{fn}" for rel, fn in sorted(fresh))
    )


def test_baseline_never_grows():
    """Strict-shrink: baseline entries whose (rel, async_fn) no
    longer contains direct sync-sqlite MUST be pruned so the ratchet
    ratchets."""
    live = _collect_offenders()
    stale = _BASELINE_SYNC_SQLITE - live
    assert not stale, (
        "#141 sync-sqlite-in-async ratchet: baseline shrunk — prune "
        "the following (rel, async_fn) pairs from `_BASELINE_SYNC_"
        "SQLITE` (their direct sync-sqlite call has been removed):\n\n"
        + "\n".join(f"  {rel}::{fn}" for rel, fn in sorted(stale))
    )


# --- teeth: the offload-aware detector over synthetic source ---------------

_TEETH_SRC = '''
import asyncio
from functools import partial

async def direct(db):
    db.execute("select 1").fetchall()

async def offloaded_def(db):
    def _work(conn):
        return conn.execute("select 1").fetchall()
    return await db_call(_work, db)

async def offloaded_partial(db):
    def _work(conn, n):
        return conn.execute("select ?", (n,)).fetchone()
    return await asyncio.to_thread(partial(_work, db, 1))

async def offloaded_executor(db, loop):
    def _work():
        return db.execute("select 1").fetchone()
    return await loop.run_in_executor(None, _work)

async def offloaded_lambda(db):
    return await db_call(lambda: db.execute("select 1").fetchall())

async def def_also_called_inline(db):
    def _work(conn):
        return conn.execute("select 1").fetchall()
    _work(db)
    return await db_call(_work, db)

async def nested_def_called_inline(db):
    def _work(conn):
        return conn.execute("select 1").fetchall()
    return _work(db)

async def hole_alias(db):
    def _work(conn):
        return conn.execute("select 1").fetchall()
    f = _work
    f(db)
    return await db_call(_work, db)

async def hole_sync_helper(db):
    def _work(conn):
        return conn.execute("select 1").fetchall()
    run_now(_work, db)
    return await db_call(_work, db)

async def hole_partial_inline(db):
    def _work(conn):
        return conn.execute("select 1").fetchall()
    partial(_work, db)()
    return await db_call(_work, db)

async def hole_default_arg(db):
    def _work(conn, row=db.execute("select 1").fetchone()):
        return row
    return await db_call(_work, db)

async def hole_generator(db):
    def _rows(conn):
        yield from conn.execute("select 1").fetchall()
    return await db_call(_rows, db)

async def hole_untrusted_attr_offload(db, obj):
    def _work(conn):
        return conn.execute("select 1").fetchall()
    return await obj.db_call(_work, db)
'''


def test_teeth_offload_aware_detector():
    found = _offenders_in_tree(ast.parse(_TEETH_SRC))
    assert found == {
        "direct", "def_also_called_inline", "nested_def_called_inline",
        "hole_alias", "hole_sync_helper", "hole_partial_inline",
        "hole_default_arg", "hole_generator", "hole_untrusted_attr_offload",
    }, found
