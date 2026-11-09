""" Phase 3 / Refinement 3 — count-agnostic pin: no
``asyncio.to_thread(<fn>, ...)`` (or ``loop.run_in_executor(...)``)
where the target ``<fn>``'s body touches a ``sqlite3.Connection``
method outside a protection envelope.

Background
----------
The n=10 pin (``test_no_direct_app_state_db_method``) catches direct
``app.state.db.<method>(...)`` use outside the protection envelope.
It misses one shape that DA's  cross-audit caught:
``asyncio.to_thread(_sync_helper, ...)`` where ``_sync_helper`` is
a sync def (or closure) that internally touches a connection —
because the chain expression isn't ``app.state.db.<method>`` but a
bare-name on a closure variable.

``single_flight.acquire_db_lock_async`` (pre-#288 Phase 3) was the
canonical offender: the ``@contextmanager`` generator's body issued
``lock_conn.execute(...)`` + ``lock_conn.commit()`` on a closure
variable, and the async wrapper dispatched the ``__enter__`` /
``__exit__`` via ``asyncio.to_thread`` — which the n=10 pin could
not see because the chain wasn't ``state.db``.

This pin is the n=11 instance of the count-agnostic structural-
drift-catch pattern (extending the n=10 list). It complements the
existing pin rather than replacing it.

The invariant
-------------
For every async def under ``src/email_triage/**.py``, every
``asyncio.to_thread(<target>, …)`` call whose ``<target>`` is a
locally-defined sync function (or closure) MUST have at least one
of these protections inside the target's body:

  (a) decorated with ``@db_write`` (or alias ``@_db_write``);
  (b) wraps its body in ``with get_write_lock():`` /
      ``with _LOCK_CONN_RLOCK:`` / ``with acquire_db_lock(...):``;
  (c) target is ``db_call`` itself or another known lock-acquirer
      (whose closures are already serialised at the wrapping layer);
  (d) target body contains NO ``.execute/.commit/.rollback/
      .executescript/.cursor`` calls — i.e. doesn't touch SQLite at
      all (so the dispatch is for some other off-loop work);
  (e) line carries an ``# async-db-ok`` opt-out comment.

Phase 3 fixes the canonical offender (``acquire_db_lock``) by
wrapping its body in ``_LOCK_CONN_RLOCK`` — so under the broadened
pin both ``db_call`` and ``acquire_db_lock`` are recognised as
protected and the in-tree finding count is zero at the Phase 3 HEAD.

Drift-defense pattern (n=11)
----------------------------
Adds to the n=10 catalogue in
``tests/test_no_direct_app_state_db_method.py``:
  10. (n=10) direct ``app.state.db.<method>`` shape detection
  11. THIS GUARD — ``asyncio.to_thread`` of a sqlite-touching
      closure / sync def
"""

from __future__ import annotations

import ast
import io
import tokenize
from pathlib import Path

import pytest

from _pin_harness import SRC_ROOT, iter_src_files, parse_module, relpath


# ---------------------------------------------------------------------------
# Module discovery — every `.py` under `src/email_triage`
# ---------------------------------------------------------------------------
# Discovery + relpath now route through the shared pin harness (R5b) so this
# pin cannot drift in its src-root spelling, its ``rglob`` / ``__pycache__``
# skip, or its forward-slash relpath base. ``relpath()`` is relative to
# ``SRC_ROOT`` → ``web/db.py`` form — IDENTICAL base to the previous
# ``relative_to(_src_root())`` spelling, so no allow-list re-keying is needed
# (this pin has no relpath-keyed allow-list anyway; relpath is used only for
# parametrize ids + violation messages).

def _src_root() -> Path:
    return SRC_ROOT


def _all_modules() -> list[Path]:
    root = _src_root()
    assert root.is_dir(), f"src tree not found at {root}"
    return list(iter_src_files())


# ---------------------------------------------------------------------------
# DB-method recognition
# ---------------------------------------------------------------------------

_DB_METHODS = {
    "execute", "executemany", "executescript",
    "commit", "rollback", "cursor",
}


def _is_db_method_call(node: ast.Call) -> bool:
    """True when ``node`` is ``<X>.<DB_METHOD>(...)`` — regardless of
    what ``X`` is. Both bare-name calls (``conn.execute(...)``) and
    attribute-chain calls (``app.state.db.execute(...)``) are caught,
    so this is the broadest possible match for "this site touches a
    sqlite-connection-shaped object".

    Conservative-by-design: a non-sqlite ``foo.execute(...)`` call
    (e.g. a thread-pool executor) is a potential false positive, but
    keeping the pin loose here means a new sqlite-touching site can
    never escape. The protection-envelope check (below) is what
    accepts known-safe sites.
    """
    f = node.func
    return isinstance(f, ast.Attribute) and f.attr in _DB_METHODS


# ---------------------------------------------------------------------------
# Lock-acquirer recognition (protection envelope)
# ---------------------------------------------------------------------------

_LOCK_ACQUIRERS = {
    "get_write_lock", "_write_lock",
    "acquire_db_lock", "acquire_db_lock_async",
    "_LOCK_CONN_RLOCK",
}

_DB_WRITE_DECORATORS = {"db_write", "_db_write"}


def _with_uses_lock_acquirer(items) -> bool:
    """Return True when any ``with X():`` / ``with X:`` context-expr
    refers to a known lock acquirer. Catches both call form
    (``with get_write_lock():``) and bare-Name form
    (``with _LOCK_CONN_RLOCK:`` for an already-instantiated RLock)."""
    for item in items:
        ctx = item.context_expr
        name = None
        if isinstance(ctx, ast.Call):
            f = ctx.func
            if isinstance(f, ast.Name):
                name = f.id
            elif isinstance(f, ast.Attribute):
                name = f.attr
        elif isinstance(ctx, ast.Name):
            name = ctx.id
        elif isinstance(ctx, ast.Attribute):
            name = ctx.attr
        if name in _LOCK_ACQUIRERS:
            return True
    return False


def _fn_has_db_write_decorator(fn) -> bool:
    """True when ``fn`` is decorated with ``@db_write`` or
    ``@_db_write`` (alias)."""
    for d in fn.decorator_list:
        name = None
        if isinstance(d, ast.Name):
            name = d.id
        elif isinstance(d, ast.Attribute):
            name = d.attr
        elif isinstance(d, ast.Call):
            inner = d.func
            if isinstance(inner, ast.Name):
                name = inner.id
            elif isinstance(inner, ast.Attribute):
                name = inner.attr
        if name in _DB_WRITE_DECORATORS:
            return True
    return False


def _fn_body_uses_lock_acquirer(
    fn: ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda,
) -> bool:
    """True when ``fn``'s own body (NOT crossing into nested funcs)
    issues a ``with <lock_acquirer>:`` block somewhere in its top-
    level body OR uses ``<lock_acquirer>.acquire()`` / explicit
    ``acquire()`` on a Name in ``_LOCK_ACQUIRERS``.

    The walker descends into all syntactic constructs INSIDE the fn
    body but stops at nested function definitions (a nested
    ``def _inner():`` is its own scope and not part of THIS fn's
    protection envelope).
    """
    if isinstance(fn, ast.Lambda):
        # Lambdas can't have ``with`` blocks. They can only call
        # functions; bare protection-via-call (``with get_write_lock():
        # ...`` inside a lambda) isn't expressible.
        return False

    stack: list[ast.AST] = list(fn.body)
    while stack:
        node = stack.pop()
        # Stop at nested function definitions — their bodies are
        # separate scopes.
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if isinstance(node, (ast.With, ast.AsyncWith)):
            if _with_uses_lock_acquirer(node.items):
                return True
        # Detect ``_LOCK_CONN_RLOCK.acquire()`` / ``.release()``
        # — the manual try/finally form used in single_flight.py.
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in ("acquire", "release")
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id in _LOCK_ACQUIRERS
        ):
            return True
        stack.extend(ast.iter_child_nodes(node))
    return False


def _fn_body_touches_sqlite(
    fn: ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda,
) -> bool:
    """True when ``fn``'s body contains any ``<X>.<DB_METHOD>(...)``
    call. Descends into all syntactic constructs but stops at nested
    function definitions (those are their own scope and have to be
    checked separately if a caller passes them to ``to_thread``)."""
    body: list[ast.AST]
    if isinstance(fn, ast.Lambda):
        body = [fn.body]
    else:
        body = list(fn.body)
    stack: list[ast.AST] = body
    while stack:
        node = stack.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if isinstance(node, ast.Call) and _is_db_method_call(node):
            return True
        stack.extend(ast.iter_child_nodes(node))
    return False


# ---------------------------------------------------------------------------
# Opt-out detection (real COMMENT tokens only)
# ---------------------------------------------------------------------------

def _optout_lines(src: str) -> set[int]:
    flagged: set[int] = set()
    try:
        toks = tokenize.generate_tokens(io.StringIO(src).readline)
        for tok in toks:
            if tok.type != tokenize.COMMENT:
                continue
            body = tok.string.lstrip("#").strip()
            words = body.replace(",", " ").split()
            for w in words:
                if w.rstrip(":-").lower() in (
                    "async-db-ok", "async-db-todo",
                ):
                    flagged.add(tok.start[0])
                    break
    except (tokenize.TokenError, IndentationError, SyntaxError):
        pass
    return flagged


# ---------------------------------------------------------------------------
# The walker
# ---------------------------------------------------------------------------

class _AsyncToThreadFinder(ast.NodeVisitor):
    """Find every ``asyncio.to_thread(<target>, ...)`` /
    ``loop.run_in_executor(..., <target>, ...)`` call. For each, look
    up ``<target>`` against the locally-defined sync helpers in the
    same module; if it touches sqlite without a protection envelope,
    record a finding.

    Pattern: build a map of local sync-fn defs (FunctionDef, NOT
    AsyncFunctionDef) keyed by name. Resolve each ``to_thread`` call
    target's name and look it up. ``Lambda``-form targets are walked
    inline (anonymous, no name to look up).
    """

    def __init__(self, src: str, tree: ast.Module) -> None:
        self._optout = _optout_lines(src)
        # Map: sync-fn name → AST node. Built by scanning module top-
        # level + every nested scope's direct children. A nested
        # ``def _helper()`` defined inside an ``async def`` IS a
        # candidate target — that's the canonical ``db_call`` /
        # ``acquire_db_lock`` shape — and the lookup needs to find
        # them. Doing a full traversal: every FunctionDef anywhere
        # in the module is indexed.
        self._sync_fns: dict[str, ast.FunctionDef] = {}
        for n in ast.walk(tree):
            if isinstance(n, ast.FunctionDef):
                # Multiple defs with the same name (rare; usually
                # decorator-stacking or conditional defs) — keep the
                # last one walked. Pin behaviour is approximate here;
                # a false negative for the same-name-multiple-defs
                # shape is acceptable.
                self._sync_fns[n.name] = n
        self.findings: list[tuple[int, int, str, str]] = []

    def _opted_out(self, lineno: int) -> bool:
        return lineno in self._optout or (lineno - 1) in self._optout

    def visit_Call(self, node: ast.Call) -> None:
        # Match ``asyncio.to_thread(target, ...)`` and
        # ``<X>.run_in_executor(executor, target, ...)``.
        func = node.func
        target: ast.AST | None = None
        which: str | None = None

        if isinstance(func, ast.Attribute) and func.attr == "to_thread":
            # asyncio.to_thread(target, ...)
            if node.args:
                target = node.args[0]
                which = "asyncio.to_thread"
        elif (
            isinstance(func, ast.Attribute)
            and func.attr == "run_in_executor"
        ):
            # loop.run_in_executor(executor, target, ...)
            if len(node.args) >= 2:
                target = node.args[1]
                which = "run_in_executor"

        if target is not None and not self._opted_out(node.lineno):
            self._inspect_target(node, target, which or "?")

        self.generic_visit(node)

    def _inspect_target(
        self, call: ast.Call, target: ast.AST, which: str,
    ) -> None:
        """Resolve ``target`` to a sync def (or lambda) and check
        whether it touches sqlite without protection."""
        target_fn: (
            ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda | None
        ) = None
        target_name: str | None = None

        if isinstance(target, ast.Name):
            # Bare name — look up in the local sync-fn map.
            target_name = target.id
            target_fn = self._sync_fns.get(target.id)
        elif isinstance(target, ast.Lambda):
            # Inline lambda — walk directly.
            target_fn = target
            target_name = "<lambda>"
        elif isinstance(target, ast.Attribute):
            # Attribute access — e.g. ``cm.__enter__``. We can't
            # statically follow attribute chains in general (the
            # target's body lives in another module). Skip — out of
            # scope for this pin. The transitive guard
            # ``test_async_db_safety.py`` covers the catalogued
            # helper case.
            return
        else:
            return

        if target_fn is None:
            # Unknown sync function (defined in another module,
            # imported, etc.) — skip. Cross-module resolution is
            # out of scope; the n=10 + transitive guard handle the
            # imported-name case.
            return

        # Protection checks — any one passes.
        if isinstance(target_fn, ast.Lambda):
            # Lambdas cannot carry decorators or with-blocks. The
            # only way a lambda is safe is via opt-out OR the body
            # doesn't touch sqlite.
            if not _fn_body_touches_sqlite(target_fn):
                return
            self.findings.append((
                call.lineno, call.col_offset, target_name,
                f"{which}(<lambda>) — touches sqlite, no envelope",
            ))
            return

        if _fn_has_db_write_decorator(target_fn):
            return
        if _fn_body_uses_lock_acquirer(target_fn):
            return
        if not _fn_body_touches_sqlite(target_fn):
            return

        # Touches sqlite, no protection envelope, no opt-out.
        self.findings.append((
            call.lineno, call.col_offset, target_name,
            f"{which}({target_name}) — body touches sqlite without "
            "@db_write / lock-acquirer",
        ))


# ---------------------------------------------------------------------------
# The pin — parametrised per-module
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "module_path",
    _all_modules(),
    ids=lambda p: relpath(p),
)
def test_no_unprotected_asyncio_to_thread_sqlite(module_path: Path):
    """No ``asyncio.to_thread(<sync_fn>, ...)`` /
    ``loop.run_in_executor(_, <sync_fn>, ...)`` may target a locally-
    defined sync function whose body touches a ``sqlite3.Connection``
    method outside the protection envelope (``@db_write`` decorator,
    ``with get_write_lock()`` / ``with _LOCK_CONN_RLOCK:`` /
    ``acquire_db_lock`` lock acquirer, or ``# async-db-ok`` opt-out).

    This is the n=11 sibling pin to
    ``test_no_direct_app_state_db_method`` (n=10). It catches the
    ``single_flight.acquire_db_lock``-shape bypass DA flagged after
    Phase 2: a sync helper closing over a ``sqlite3.Connection`` and
    dispatched off-loop via ``asyncio.to_thread`` — the chain isn't
    ``state.db`` so n=10 misses it; the body's DB touch isn't through
    a catalogued helper so the transitive guard
    ``test_async_db_safety.py`` misses it; the cursor-corruption
    cascade live on the test container (2026-05-25) was reproducing through
    exactly this seam.

    Fix shape when this guard fires:
      1. If the target IS a write-lock acquirer, wrap its body in
         ``with get_write_lock():`` or its dedicated lock (e.g.
         ``with _LOCK_CONN_RLOCK: ...``).
      2. If the target is a normal write helper, add ``@db_write``.
      3. If the target is a genuine startup / single-threaded path
         that doesn't race, add ``# async-db-ok: <reason>`` on the
         line.
    """
    try:
        source_text = module_path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        # Fail-CLOSED: this is the guard's OWN scanner machinery, not an
        # optional runtime dep. A src module that won't decode is itself
        # a defect — skipping would let it silently escape the invariant.
        pytest.fail(f"{module_path} did not decode ({exc!r}) — a non-decoding "
                    "src module is a defect this guard must surface, not skip")
    tree = parse_module(module_path)
    if tree is None:
        # Fail-CLOSED: parse_module returns None on SyntaxError/UnicodeDecodeError.
        pytest.fail(f"{module_path} did not parse — a non-parsing "
                    "src module is a defect this guard must surface, not skip")

    finder = _AsyncToThreadFinder(source_text, tree)
    finder.visit(tree)

    if finder.findings:
        rel = relpath(module_path)
        lines = "\n".join(
            f"  {rel}:{lineno}:{col}  {sig}"
            for lineno, col, _, sig in finder.findings
        )
        pytest.fail(
            f"{len(finder.findings)} unprotected ``asyncio.to_thread`` "
            f"sqlite-touching dispatch site(s) in {rel}:\n{lines}\n\n"
            "Each off-loop dispatch of a sync function that touches "
            "sqlite must wrap its body in a lock-acquirer "
            "(``with get_write_lock():`` / ``with _LOCK_CONN_RLOCK:`` "
            "/ ``with acquire_db_lock(...):``), or carry the "
            "``@db_write`` decorator, or be marked ``# async-db-ok`` "
            "with a rationale. See #288 Phase 3 DA Refinement 3."
        )


# ---------------------------------------------------------------------------
# Pin-the-pin — synthetic-source sanity tests
# ---------------------------------------------------------------------------

def _detect_on(src: str) -> list[tuple[int, int, str, str]]:
    tree = ast.parse(src)
    f = _AsyncToThreadFinder(src, tree)
    f.visit(tree)
    return f.findings


class TestDetectorSanity:
    """Regression-prevention only-pin: detector must fire on the
    bypass shape and skip every protection envelope."""

    def test_to_thread_of_unprotected_sync_def_is_caught(self):
        src = (
            "import asyncio\n"
            "import sqlite3\n"
            "async def h(conn):\n"
            "    def _worker():\n"
            "        conn.execute('INSERT INTO t VALUES (1)')\n"
            "        conn.commit()\n"
            "    await asyncio.to_thread(_worker)\n"
        )
        finds = _detect_on(src)
        assert len(finds) == 1
        assert "_worker" in finds[0][3]

    def test_to_thread_of_lambda_touching_db_is_caught(self):
        src = (
            "import asyncio\n"
            "async def h(conn):\n"
            "    await asyncio.to_thread(lambda: conn.execute('SELECT 1'))\n"
        )
        finds = _detect_on(src)
        assert len(finds) == 1
        assert "<lambda>" in finds[0][3]

    def test_to_thread_of_db_write_decorated_fn_is_safe(self):
        src = (
            "import asyncio\n"
            "@db_write\n"
            "def _writer(conn):\n"
            "    conn.execute('UPDATE t SET v=1')\n"
            "    conn.commit()\n"
            "async def h(conn):\n"
            "    await asyncio.to_thread(_writer, conn)\n"
        )
        finds = _detect_on(src)
        assert finds == []

    def test_to_thread_of_db_write_aliased_fn_is_safe(self):
        # ``_db_write`` is the canonical alias used in
        # ``db_auth_helpers.py``.
        src = (
            "import asyncio\n"
            "@_db_write\n"
            "def _writer(conn):\n"
            "    conn.execute('UPDATE t SET v=1')\n"
            "async def h(conn):\n"
            "    await asyncio.to_thread(_writer, conn)\n"
        )
        finds = _detect_on(src)
        assert finds == []

    def test_to_thread_of_fn_using_get_write_lock_is_safe(self):
        src = (
            "import asyncio\n"
            "def _worker(conn):\n"
            "    with get_write_lock():\n"
            "        conn.execute('INSERT INTO t VALUES (1)')\n"
            "        conn.commit()\n"
            "async def h(conn):\n"
            "    await asyncio.to_thread(_worker, conn)\n"
        )
        finds = _detect_on(src)
        assert finds == []

    def test_to_thread_of_fn_using_lock_conn_rlock_is_safe(self):
        # Phase 3 shape — the singleton's dedicated RLock counts as
        # a protection envelope.
        src = (
            "import asyncio\n"
            "def _worker(conn):\n"
            "    with _LOCK_CONN_RLOCK:\n"
            "        conn.execute('INSERT INTO single_flight_locks "
            "VALUES (1)')\n"
            "        conn.commit()\n"
            "async def h(conn):\n"
            "    await asyncio.to_thread(_worker, conn)\n"
        )
        finds = _detect_on(src)
        assert finds == []

    def test_to_thread_of_fn_with_manual_acquire_release_is_safe(self):
        # Phase 3's ``acquire_db_lock`` uses
        # ``_LOCK_CONN_RLOCK.acquire()`` / ``.release()`` rather than
        # a ``with`` block. The pin must recognise that too.
        src = (
            "import asyncio\n"
            "def _worker(conn):\n"
            "    _LOCK_CONN_RLOCK.acquire()\n"
            "    try:\n"
            "        conn.execute('INSERT INTO t VALUES (1)')\n"
            "    finally:\n"
            "        _LOCK_CONN_RLOCK.release()\n"
            "async def h(conn):\n"
            "    await asyncio.to_thread(_worker, conn)\n"
        )
        finds = _detect_on(src)
        assert finds == []

    def test_to_thread_of_fn_not_touching_sqlite_is_safe(self):
        # Off-loop dispatch of work that doesn't touch sqlite is
        # out of scope.
        src = (
            "import asyncio\n"
            "def _crunch(x):\n"
            "    return sum(range(x))\n"
            "async def h():\n"
            "    await asyncio.to_thread(_crunch, 1000000)\n"
        )
        finds = _detect_on(src)
        assert finds == []

    def test_optout_on_to_thread_line_is_safe(self):
        src = (
            "import asyncio\n"
            "def _worker(conn):\n"
            "    conn.execute('INSERT INTO t VALUES (1)')\n"
            "async def h(conn):\n"
            "    await asyncio.to_thread(_worker, conn)  # async-db-ok: provably-safe\n"
        )
        finds = _detect_on(src)
        assert finds == []

    def test_run_in_executor_of_unprotected_fn_is_caught(self):
        # ``loop.run_in_executor(executor, target, ...)`` is the
        # sibling shape — second positional arg is the target.
        src = (
            "import asyncio\n"
            "async def h(loop, conn):\n"
            "    def _worker():\n"
            "        conn.execute('INSERT INTO t VALUES (1)')\n"
            "    await loop.run_in_executor(None, _worker)\n"
        )
        finds = _detect_on(src)
        assert len(finds) == 1
        assert "run_in_executor" in finds[0][3]


class TestNoFalsePositivesInTree:
    """Sanity: every module under ``src/email_triage`` must pass the
    pin AT THE PHASE 3 HEAD. The Phase 3 fix wraps
    ``acquire_db_lock``'s body in ``_LOCK_CONN_RLOCK`` —
    ``db_call``'s body was already in ``with _lock:`` — so both of
    the previously-suspect sites are now recognised as protected.
    """

    def test_baseline_is_zero(self):
        """Whole-tree finding count is 0 at Phase 3 HEAD. A failure
        here means either a NEW unprotected ``asyncio.to_thread``
        site landed, OR the Phase 3 fix's lock-acquirer recognition
        is no longer covering ``acquire_db_lock`` / ``db_call``."""
        total = 0
        per_module: dict[str, int] = {}
        for mod in _all_modules():
            try:
                source_text = mod.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue
            tree = parse_module(mod)
            if tree is None:
                continue
            finder = _AsyncToThreadFinder(source_text, tree)
            finder.visit(tree)
            if finder.findings:
                rel = relpath(mod)
                per_module[rel] = [
                    f"L{ln}: {sig}" for ln, _col, _, sig in finder.findings
                ]
                total += len(finder.findings)
        assert total == 0, (
            f"Phase 3 / Refinement 3 baseline broken: {total} "
            f"unprotected ``asyncio.to_thread`` sqlite-touching "
            f"dispatch site(s) across {len(per_module)} module(s): "
            f"{per_module}. Investigate before suppressing."
        )
