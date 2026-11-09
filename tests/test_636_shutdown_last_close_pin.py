"""Pin (punch 636): at lifespan shutdown the app connection is the LAST
connection to close, after the writer drained and the final WAL checkpoint ran.

The defect (measured 2026-10-14, design drawer for punch 636): the final
``checkpoint_wal_truncate`` ran before the httpx drains and the writer stop, and
three connections (the audit-chain log handler's, the single_flight lock
connection, the ACME job-state connection) stayed open to process exit. The app
connection was never the last to close, so SQLite's last-close checkpoint
(sqlite.org/wal.html, sections 4 and 6: "When the last connection to a database
closes, that connection does one last checkpoint and then deletes the WAL")
never ran, and every clean stop left WAL frames.

The guarantee is the last close; the explicit TRUNCATE is the belt. The
shutdown log rows stay in the HMAC-chained ``log_entries`` (they are written
after the TRUNCATE and folded by the last close).

Two arms over ``web/app.py``'s ``lifespan``, after its ``yield``:

1. ORDER: the writer stop, then the final checkpoint, then ``mark_app_stopped()``,
   then ``conn.close()``. No audit drain after the checkpoint. When the startup
   attached the audit-chain log handler, it is removed (its connection closed)
   before ``conn.close()``.
2. SINGLETONS (count-agnostic): EVERY module-level variable in src annotated as
   a ``Connection`` has a closer in its module (a function that calls
   ``<name>.close()``; test-only helpers excluded), and one of its closers runs
   in the lifespan shutdown BEFORE ``conn.close()``. A new long-lived connection
   singleton fails this pin until the shutdown closes it.

A connection held some other way (a handler attribute, a local) is out of arm
2's reach; the runtime twin ``tests/test_636_shutdown_last_close.py`` records
EVERY connection opened on the database file during an app lifetime and asserts
each is closed and the app connection closes last.
"""

from __future__ import annotations

import ast

from _pin_harness import SRC_ROOT, assert_pin_has_teeth, parse_module, parse_source, walk_src

_CHECKPOINT = "checkpoint_wal_truncate"


def _name_of(func: ast.AST) -> str | None:
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


def _lifespan(tree: ast.AST):
    return next((n for n in ast.walk(tree)
                 if isinstance(n, ast.AsyncFunctionDef) and n.name == "lifespan"), None)


def _yield_line(life: ast.AST) -> int | None:
    lines = [n.lineno for n in ast.walk(life) if isinstance(n, (ast.Yield, ast.YieldFrom))]
    return min(lines) if lines else None


def _calls(life: ast.AST) -> list[ast.Call]:
    return sorted((n for n in ast.walk(life) if isinstance(n, ast.Call)),
                  key=lambda c: (c.lineno, c.col_offset))


def _is_checkpoint(call: ast.Call) -> bool:
    if _name_of(call.func) == _CHECKPOINT:
        return True
    return (_name_of(call.func) == "db_call" and bool(call.args)
            and isinstance(call.args[0], ast.Name) and call.args[0].id == _CHECKPOINT)


def _shutdown_anchors(life: ast.AST) -> tuple[int | None, int | None, int | None]:
    """(yield line, final checkpoint line, app-connection close line)."""
    y = _yield_line(life)
    if y is None:
        return None, None, None
    after = [c for c in _calls(life) if c.lineno > y]
    checkpoints = [c.lineno for c in after if _is_checkpoint(c)]
    closes = [c.lineno for c in after if _name_of(c.func) == "close"
              and isinstance(c.func, ast.Attribute) and isinstance(c.func.value, ast.Name)
              and c.func.value.id == "conn"]
    return y, (max(checkpoints) if checkpoints else None), (max(closes) if closes else None)


def shutdown_order_violations(tree: ast.AST) -> list[str]:
    life = _lifespan(tree)
    if life is None:
        return ["lifespan not found"]
    y, c_line, m_line = _shutdown_anchors(life)
    if y is None:
        return ["lifespan has no yield"]
    if c_line is None:
        return ["no final checkpoint_wal_truncate after yield"]
    if m_line is None:
        return ["no conn.close() after yield"]
    calls = _calls(life)
    after = [c for c in calls if c.lineno > y]
    bad: list[str] = []
    writer_stop = [c.lineno for c in after if _name_of(c.func) == "shutdown"
                   and any(k.arg == "on_abandoned" for k in c.keywords)]
    if not writer_stop:
        bad.append("no writer shutdown(on_abandoned=...) after yield")
    elif max(writer_stop) > c_line:
        bad.append(f"the writer stops (line {max(writer_stop)}) after the final "
                   f"checkpoint (line {c_line}); its queued writes land after it")
    if [c for c in after if _name_of(c.func) == "drain_inflight_audit_writes" and c.lineno > c_line]:
        bad.append("an audit drain runs after the final checkpoint")
    if m_line < c_line:
        bad.append("conn.close() runs before the final checkpoint")
    stopped = [c.lineno for c in after if _name_of(c.func) == "mark_app_stopped"]
    if not stopped or min(stopped) < c_line or max(stopped) > m_line:
        bad.append("mark_app_stopped() is not between the final checkpoint and conn.close()")
    if [c for c in calls if c.lineno < y and _name_of(c.func) == "add_sqlite_handler"]:
        removes = [c.lineno for c in after if _name_of(c.func) == "remove_sqlite_handlers"]
        if not [ln for ln in removes if ln < m_line]:
            bad.append("the audit-chain log handler's connection is not closed before "
                       "conn.close(); the app connection is then not the last close")
    return bad


def _connection_singletons(tree: ast.AST) -> list[str]:
    out = []
    for node in getattr(tree, "body", []):
        if (isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name)
                and "Connection" in ast.unparse(node.annotation)):
            out.append(node.target.id)
    return out


def _closers(tree: ast.AST, name: str) -> set[str]:
    out = set()
    for fn in getattr(tree, "body", []):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)) or fn.name.endswith("_for_tests"):
            continue
        for n in ast.walk(fn):
            if (isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "close"
                    and isinstance(n.func.value, ast.Name) and n.func.value.id == name):
                out.add(fn.name)
    return out


def singleton_close_violations(modules, life_tree: ast.AST) -> list[str]:
    life = _lifespan(life_tree)
    if life is None:
        return ["lifespan not found"]
    y, _c_line, m_line = _shutdown_anchors(life)
    if y is None or m_line is None:
        return ["no lifespan yield or conn.close()"]
    shutdown_calls = {_name_of(c.func) for c in _calls(life) if y < c.lineno < m_line}
    bad = []
    for rel, tree in modules:
        for name in _connection_singletons(tree):
            closers = _closers(tree, name)
            if not closers:
                bad.append(f"{rel}::{name} has no closer (no function calls {name}.close())")
            elif not closers & shutdown_calls:
                bad.append(f"{rel}::{name}: none of {sorted(closers)} runs in the lifespan "
                           f"shutdown before conn.close()")
    return bad


def test_the_app_connection_closes_last_after_the_final_checkpoint():
    assert shutdown_order_violations(parse_module(SRC_ROOT / "web/app.py")) == []


def test_every_connection_singleton_closes_before_the_app_connection():
    modules = [(rel, tree) for _p, rel, tree in walk_src()]
    found = [name for _rel, tree in modules for name in _connection_singletons(tree)]
    assert found, "the singleton scan found no Connection-annotated module variable (scan broken)"
    assert singleton_close_violations(modules, parse_module(SRC_ROOT / "web/app.py")) == []


# ---------------------------------------------------------------------------
# Teeth
# ---------------------------------------------------------------------------

_GOOD_LIFE = (
    "async def lifespan(app):\n"
    "    add_sqlite_handler(conn)\n"
    "    yield\n"
    "    await drain_inflight_audit_writes(5)\n"
    "    await writer.shutdown(on_abandoned=cb)\n"
    "    close_lock_conn()\n"
    "    await db_call(checkpoint_wal_truncate, conn)\n"
    "    mark_app_stopped()\n"
    "    remove_sqlite_handlers()\n"
    "    conn.close()\n"
)

_CKPT = "    await db_call(checkpoint_wal_truncate, conn)\n"
_WRITER = "    await writer.shutdown(on_abandoned=cb)\n"


def _moved(src: str, line: str, before: str) -> str:
    """``src`` with ``line`` moved to just before ``before``."""
    return src.replace(line, "").replace(before, line + before)


def test_order_arm_has_teeth():
    good = _GOOD_LIFE
    assert shutdown_order_violations(parse_source(good)) == []
    # The pre-636 order: the checkpoint before the writer stop.
    assert_pin_has_teeth(shutdown_order_violations, _moved(good, _CKPT, _WRITER), good)
    # The log handler never removed, or removed after the app connection closed.
    assert shutdown_order_violations(parse_source(good.replace("    remove_sqlite_handlers()\n", "")))
    assert shutdown_order_violations(parse_source(
        good.replace("    remove_sqlite_handlers()\n", "") + "    remove_sqlite_handlers()\n"))
    # The app connection closed before the checkpoint.
    assert shutdown_order_violations(parse_source(_moved(good, "    conn.close()\n", _CKPT)))
    # The app-live gate cleared before the checkpoint.
    assert shutdown_order_violations(parse_source(_moved(good, "    mark_app_stopped()\n", _CKPT)))
    # An audit drain after the checkpoint.
    assert shutdown_order_violations(parse_source(
        _moved(good, "    await drain_inflight_audit_writes(5)\n", "    mark_app_stopped()\n")))


def test_singleton_arm_has_teeth():
    life = parse_source(_GOOD_LIFE)
    closed = parse_source(
        "_LOCK_CONN: sqlite3.Connection | None = None\n"
        "def close_lock_conn():\n    _LOCK_CONN.close()\n"
        "def _reset_lock_conn_for_tests():\n    _LOCK_CONN.close()\n")
    assert singleton_close_violations([("m.py", closed)], life) == []
    # A new singleton whose closer the shutdown never calls.
    unclosed = parse_source(
        "_NEW_CONN: sqlite3.Connection | None = None\n"
        "def close_new_conn():\n    _NEW_CONN.close()\n")
    assert singleton_close_violations([("n.py", unclosed)], life)
    # A singleton with only a test-only closer.
    test_only = parse_source(
        "_X: 'sqlite3.Connection | None' = None\n"
        "def _reset_x_for_tests():\n    _X.close()\n")
    assert singleton_close_violations([("x.py", test_only)], life)
    # A closer that runs only AFTER the app connection closed is too late.
    late_life = parse_source(_GOOD_LIFE.replace("    close_lock_conn()\n", "") + "    close_lock_conn()\n")
    assert singleton_close_violations([("m.py", closed)], late_life)
