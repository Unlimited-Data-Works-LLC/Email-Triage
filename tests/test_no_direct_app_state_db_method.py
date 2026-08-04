""" — count-agnostic structural pin: no direct method call on the
shared connection chain ``<X>.state.db`` outside the protection
envelope.

Background
----------
The app keeps ONE shared ``sqlite3.Connection`` reachable as
``app.state.db``. Every async-reachable touch MUST be routed through
``web/db_threadpool.db_call`` (which acquires the process-wide DB write
lock for the dispatched call's duration), through a ``@db_write``-
decorated helper, or inside an explicit ``with get_write_lock():`` /
``with acquire_db_lock():`` block. Any direct ``app.state.db.execute(...)``
/ ``.commit()`` / ``.rollback()`` / ``.executescript()`` / etc. on the
shared chain — outside that envelope — can race with a locked writer
mid-``BEGIN…COMMIT`` and trigger ``sqlite3.OperationalError: cannot
start a transaction within a transaction`` (the class  Phase 1
reproduced at ``tests/test_web/test_288_concurrent_connection_use.py``).

Phase 2 baseline
----------------
The Phase 2 audit (a one-time scratch scan, since removed) measured the
in-tree count of direct ``<…>.state.db.<method>(...)`` call sites at
**0** — the codebase always binds ``db = request.app.state.db`` first
and passes ``db`` to helpers that the call sites dispatch through
``db_call``. So this pin's baseline is exactly zero: any future
regression that introduces a direct shape MUST trip CI.

Drift-defense pattern
---------------------
This is the **10th instance** of the count-agnostic structural-drift-
catch pattern. Earlier exemplars:
  1.  connection-holding ratchet (AST scan)
  2.  async-DB-scan guard (AST scan, transitive)
  3.  idempotency contract (``Action.__subclasses__()`` + module-
     path filter)
  4.  watch-delivery retry call-site pin (regex live-path + drainer
     exclusion)
  5.  connection-holding count-agnostic xfail-reason
  6.  classify-async-helper AST pin (``visit_AsyncFunctionDef`` +
     ``visit_Call`` walker)
  7.  / N-03 Attachment.data drop (AST guard over 3 provider
     ``Attachment(...)`` constructors)
  8.  IMAP batch-fetch wiring pin (AST guard over ``poll_once`` body
     for ``fetch_messages_batch`` invocation)
  9. -followup-B LEGB-shadow ``import asyncio`` detection
  10. THIS GUARD — direct ``app.state.db.<method>`` shape detection

How this differs from ``test_async_db_safety.py``
-------------------------------------------------
The / async-DB guard is the TRANSITIVE guard: it walks every
``async def`` looking for calls (direct or via catalogued helpers) to
DB-touching names. It is broader and harder to maintain — its
correctness rests on the cross-module + Pass 1 fixpoint + helper
catalogue.

This pin is the NARROW STRUCTURAL guard: it matches one syntactic
shape (the ``<…>.state.db.<method>(...)`` chain itself, not anything
the chain is passed to) and fails on it outside the protection envelope.
The two are complementary — the transitive guard catches indirect
offenders; this pin catches the direct shape that bypasses
``db_call`` entirely (the exact shape Phase 1 reproduced).

Legitimate exception: the ``# async-db-ok`` opt-out
----------------------------------------------------
A direct touch inside the FastAPI ``lifespan`` startup body (runs ONCE
before request serving) or a CLI entrypoint (single-threaded, no loop)
is provably race-free. Such sites carry ``# async-db-ok`` with a
rationale on the call's line or the line above. The pin honours that
opt-out by skipping flagged lines.
"""

from __future__ import annotations

import ast
import io
import tokenize
from pathlib import Path

import pytest

from _pin_harness import iter_src_files, relpath, parse_source


# ---------------------------------------------------------------------------
# Module discovery — every `.py` under `src/email_triage`
# ---------------------------------------------------------------------------
# Discovery + relpath route through the shared harness (R5b): the
# package-root walk, the ``__pycache__`` skip, and the canonical
# ``web/db.py`` relpath all live in ``tests/_pin_harness.py`` so this pin
# cannot drift in its scoping. The harness ``relpath`` base is identical
# to this pin's former ``relative_to(_src_root())`` base, so no allow-list
# re-key is needed (this pin keys nothing on relpath — baseline is zero;
# relpath appears only in test ids and the violation message).

def _all_modules() -> list[Path]:
    return list(iter_src_files())


# ---------------------------------------------------------------------------
# Shape detection — the ``<X>.state.db`` chain
# ---------------------------------------------------------------------------

# DB methods whose call mutates SQLite state (i.e. anything beyond a
# pure attribute read). ``cursor`` is included because a follow-up
# ``cursor.execute(...)`` lands the same hazard via the cursor object.
_DB_METHODS = {
    "execute", "executemany", "executescript",
    "commit", "rollback", "cursor",
}


def _is_state_db_chain(node: ast.AST) -> bool:
    """True when ``node`` is the AST ``<X>.state.db`` (any head).

    Matches:
      - ``app.state.db``
      - ``request.app.state.db``
      - ``self.app.state.db``
      - ``self.request.app.state.db``
      - any other one-or-more attribute chain ending in ``.state.db``

    The trailing ``.state.db`` is the load-bearing part; the head can
    be anything because the FastAPI app object travels by many local
    names in this codebase.
    """
    if not isinstance(node, ast.Attribute):
        return False
    if node.attr != "db":
        return False
    state_node = node.value
    if not isinstance(state_node, ast.Attribute):
        return False
    return state_node.attr == "state"


# ---------------------------------------------------------------------------
# Opt-out detection (real COMMENT tokens only)
# ---------------------------------------------------------------------------

def _optout_lines(src: str) -> set[int]:
    """Line numbers carrying a real ``# async-db-ok`` opt-out comment.

    Mirrors the ``test_async_db_safety.py`` opt-out semantics: the
    marker must be a standalone token inside a genuine COMMENT token
    (not inside a string literal). Tolerates a trailing ``:`` so
    ``# async-db-ok: <rationale>`` works.
    """
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
# Protection-envelope detection
# ---------------------------------------------------------------------------

def _is_db_call(func: ast.AST) -> bool:
    """True when ``func`` is a ``db_call`` reference (bare or attr)."""
    if isinstance(func, ast.Name):
        return func.id == "db_call"
    if isinstance(func, ast.Attribute):
        return func.attr == "db_call"
    return False


def _lock_acquirer_name(call: ast.Call) -> str | None:
    """If ``call`` is a known lock acquirer (``get_write_lock()``,
    ``acquire_db_lock(...)``, ``acquire_db_lock_async(...)``), return
    the canonical name. Else None.

    A ``with`` block on any of these is a protection envelope. The
    name match is intentionally bare — aliasing is rare for these and
    a future alias is itself worth flagging.
    """
    f = call.func
    name = None
    if isinstance(f, ast.Name):
        name = f.id
    elif isinstance(f, ast.Attribute):
        name = f.attr
    if name in ("get_write_lock", "acquire_db_lock",
                "acquire_db_lock_async"):
        return name
    return None


# ---------------------------------------------------------------------------
# The walker — collects unprotected direct-touch sites
# ---------------------------------------------------------------------------

class _DirectTouchFinder(ast.NodeVisitor):
    """Walks a module's AST, recording every direct
    ``<X>.state.db.<METHOD>(...)`` call that is NOT inside the
    protection envelope.

    Protection layers tracked (any one suffices):
      * inside a ``db_call(...)`` argument subtree
        (``self._dbcall_depth > 0``)
      * inside the body of a function with a ``@db_write`` decorator
        (``self._fn_db_write_depth > 0``)
      * inside a ``with get_write_lock():`` / ``with acquire_db_lock():``
        / ``async with acquire_db_lock_async():`` block
        (``self._lock_depth > 0``)
      * call site carries the ``# async-db-ok`` opt-out

    Nested ``def`` / ``async def`` INHERIT the enclosing protection
    envelope — same semantics as ``with get_write_lock():`` blocks,
    where the lock covers everything in the lexical subtree. The
    parent's ``@db_write`` decorator (or enclosing ``with`` lock) is
    still in scope on the ``_fn_dbwrite_stack`` / ``_lock_depth`` when
    the nested body's calls are visited. A nested def that is
    *returned* and called from a later unprotected caller would in
    fact race, but the pin cannot distinguish "called inline" from
    "returned and called later" at AST level — the transitive guard
    (``test_async_db_safety.py``) is the layer that catches cross-
    call-graph leaks.
    """

    def __init__(self, src: str) -> None:
        self._optout = _optout_lines(src)
        self._dbcall_depth = 0
        self._lock_depth = 0
        # Stack of @db_write flags, one entry per enclosing function.
        self._fn_dbwrite_stack: list[bool] = []
        self.findings: list[tuple[int, int, str]] = []

    @property
    def _in_db_write(self) -> bool:
        return any(self._fn_dbwrite_stack)

    def _opted_out(self, lineno: int) -> bool:
        return lineno in self._optout or (lineno - 1) in self._optout

    def _fn_has_db_write(self, fn) -> bool:
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
            # Bare or aliased — ``db_write`` and ``_db_write`` both
            # protect (the latter is the canonical alias used in
            # ``db_auth_helpers.py``).
            if name in ("db_write", "_db_write"):
                return True
        return False

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._fn_dbwrite_stack.append(self._fn_has_db_write(node))
        self.generic_visit(node)
        self._fn_dbwrite_stack.pop()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._fn_dbwrite_stack.append(self._fn_has_db_write(node))
        self.generic_visit(node)
        self._fn_dbwrite_stack.pop()

    def _scan_with_items(self, items) -> int:
        opened = 0
        for item in items:
            ctx = item.context_expr
            if isinstance(ctx, ast.Call) and _lock_acquirer_name(ctx):
                opened += 1
        return opened

    def visit_With(self, node: ast.With) -> None:
        opened = self._scan_with_items(node.items)
        self._lock_depth += opened
        self.generic_visit(node)
        self._lock_depth -= opened

    def visit_AsyncWith(self, node) -> None:
        opened = self._scan_with_items(node.items)
        self._lock_depth += opened
        self.generic_visit(node)
        self._lock_depth -= opened

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func

        # db_call(...) opens a safe zone for its argument subtree.
        if _is_db_call(func):
            self._dbcall_depth += 1
            for a in node.args:
                self.visit(a)
            for kw in node.keywords:
                self.visit(kw.value)
            self._dbcall_depth -= 1
            return

        # The shape we catch: <X>.state.db.<METHOD>(...)
        if (
            isinstance(func, ast.Attribute)
            and func.attr in _DB_METHODS
            and _is_state_db_chain(func.value)
        ):
            protected = (
                self._dbcall_depth > 0
                or self._lock_depth > 0
                or self._in_db_write
                or self._opted_out(node.lineno)
            )
            if not protected:
                # Reconstruct a short signature for the error message:
                # the method name + (best-effort) first SQL keyword.
                kw = ""
                if node.args and isinstance(node.args[0], ast.Constant):
                    if isinstance(node.args[0].value, str):
                        first = node.args[0].value.strip().split()
                        if first:
                            kw = first[0].rstrip(";").upper()
                sig = f"{func.attr}({kw or '...'})"
                self.findings.append(
                    (node.lineno, node.col_offset, sig),
                )

        self.generic_visit(node)


# ---------------------------------------------------------------------------
# The pin — parametrised per-module so a failure names the file directly
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "module_path",
    _all_modules(),
    ids=relpath,
)
def test_no_direct_app_state_db_method_call(module_path: Path):
    """No direct ``<X>.state.db.<METHOD>(...)`` call may appear outside
    the protection envelope (``db_call`` arg subtree, ``@db_write``-
    decorated function body, ``with get_write_lock()``/
    ``acquire_db_lock()`` block, or ``# async-db-ok`` opt-out).

    This is the structural pin for . The Phase 1 reproducer at
    ``tests/test_web/test_288_concurrent_connection_use.py`` proves the
    direct shape can race with a locked writer mid-``BEGIN…COMMIT`` and
    raise ``sqlite3.OperationalError``. The Phase 2 audit measured the
    current count of such sites at **0**. Any future regression that
    introduces a direct shape outside the envelope MUST trip this
    test.

    Fix shape when this guard fires:
      1. Pull the surrounding work into a sync helper that takes the
         connection as a parameter.
      2. Dispatch the helper via ``await db_call(helper, db, ...)``
         from the async caller. The helper runs off the loop, under
         the process-wide DB write lock, on a worker thread.
      3. If the call genuinely runs single-threaded (FastAPI lifespan
         startup, CLI entrypoint), add ``# async-db-ok: <reason>`` on
         the call's line or the line above instead.

    See also:
      - ``src/email_triage/web/db_threadpool.py`` — ``db_call``.
      - ``src/email_triage/web/db_writelock.py`` — the write lock.
      - ``tests/test_web/test_async_db_safety.py`` — the transitive
        guard (catches indirect offenders via catalogued helpers).
      - ``tests/test_web/test_288_concurrent_connection_use.py`` —
        the runtime reproducer of the race class.
    """
    try:
        src = module_path.read_text(encoding="utf-8")
        tree = parse_source(src)
    except (SyntaxError, UnicodeDecodeError) as exc:
        # Fail-CLOSED: this is the guard's OWN scanner machinery, not an
        # optional runtime dep. A src module that won't parse/decode is itself
        # a defect — skipping would let it silently escape the invariant.
        pytest.fail(f"{module_path} did not parse ({exc!r}) — a non-parsing "
                    "src module is a defect this guard must surface, not skip")

    finder = _DirectTouchFinder(src)
    finder.visit(tree)

    if finder.findings:
        rel = relpath(module_path)
        lines = "\n".join(
            f"  {rel}:{lineno}:{col}  <…>.state.db.{sig}"
            for lineno, col, sig in finder.findings
        )
        pytest.fail(
            f"{len(finder.findings)} unprotected direct-touch site(s) "
            f"on the shared connection chain in {rel}:\n{lines}\n\n"
            "These sites bypass `db_call` / `@db_write` / "
            "`with get_write_lock()` and can race with a locked writer "
            "mid-BEGIN…COMMIT on the shared `sqlite3.Connection`, "
            "raising `sqlite3.OperationalError: cannot start a "
            "transaction within a transaction` (the class reproduced "
            "at tests/test_web/test_288_concurrent_connection_use.py). "
            "Fix shape: bind `db = request.app.state.db`, pull the "
            "work into a sync helper, then `await db_call(helper, db, "
            "...)` from the async caller. If the site genuinely runs "
            "single-threaded (FastAPI lifespan / CLI), add `# async-"
            "db-ok: <reason>` on the line or the line above. See ."
        )


# ---------------------------------------------------------------------------
# Pin-the-pin — synthetic-source sanity tests
# ---------------------------------------------------------------------------

def _detect_on(src: str) -> list[tuple[int, int, str]]:
    """Run the finder on a synthetic source string. Returns the
    finding list (empty when clean)."""
    tree = parse_source(src)
    f = _DirectTouchFinder(src)
    f.visit(tree)
    return f.findings


class TestDetectorSanity:
    """A regression-prevention guard whose detector silently passed
    every module would be useless. These synthetic-source cases prove
    the detector fires on the shapes it's designed to catch AND skips
    every protection envelope.
    """

    def test_direct_execute_outside_db_call_is_caught(self):
        src = (
            "async def h(app):\n"
            "    app.state.db.execute('SELECT 1')\n"
        )
        finds = _detect_on(src)
        assert len(finds) == 1
        assert finds[0][2].startswith("execute(")

    def test_direct_commit_outside_db_call_is_caught(self):
        src = (
            "async def h(app):\n"
            "    app.state.db.commit()\n"
        )
        finds = _detect_on(src)
        assert len(finds) == 1
        assert finds[0][2].startswith("commit(")

    def test_direct_executescript_outside_db_call_is_caught(self):
        src = (
            "async def h(app):\n"
            "    app.state.db.executescript('CREATE TABLE t (id INT);')\n"
        )
        finds = _detect_on(src)
        assert len(finds) == 1
        assert finds[0][2].startswith("executescript(")

    def test_chain_through_request_is_caught(self):
        # ``request.app.state.db`` is the same hazard class.
        src = (
            "async def h(request):\n"
            "    request.app.state.db.execute('BEGIN')\n"
        )
        finds = _detect_on(src)
        assert len(finds) == 1

    def test_chain_through_self_is_caught(self):
        # ``self.app.state.db`` (FlowStore / app middleware) too.
        src = (
            "class M:\n"
            "    async def __call__(self):\n"
            "        self.app.state.db.execute('SELECT 1')\n"
        )
        finds = _detect_on(src)
        assert len(finds) == 1

    def test_inside_db_call_arg_is_safe(self):
        # The pin must NOT fire when the touch is inside a
        # ``db_call(...)`` argument subtree — typically a lambda or
        # closure passed in as the first positional.
        src = (
            "async def h(app):\n"
            "    await db_call(lambda: app.state.db.execute('SELECT 1'))\n"
        )
        finds = _detect_on(src)
        assert finds == []

    def test_inside_db_write_decorated_fn_is_safe(self):
        # A ``@db_write`` body owns the lock for its whole duration —
        # any direct touch inside is safe.
        src = (
            "@db_write\n"
            "def f(app):\n"
            "    app.state.db.execute('UPDATE t SET v=1')\n"
        )
        finds = _detect_on(src)
        assert finds == []

    def test_inside_db_write_aliased_is_safe(self):
        # ``_db_write`` is the canonical alias (db_auth_helpers.py).
        src = (
            "@_db_write\n"
            "def f(app):\n"
            "    app.state.db.execute('UPDATE t SET v=1')\n"
        )
        finds = _detect_on(src)
        assert finds == []

    def test_inside_with_get_write_lock_is_safe(self):
        src = (
            "def f(app):\n"
            "    with get_write_lock():\n"
            "        app.state.db.execute('SELECT 1')\n"
        )
        finds = _detect_on(src)
        assert finds == []

    def test_inside_with_acquire_db_lock_is_safe(self):
        src = (
            "def f(app):\n"
            "    with acquire_db_lock(app.state.db, 'job'):\n"
            "        app.state.db.execute('SELECT 1')\n"
        )
        finds = _detect_on(src)
        # The ``with`` context_expr itself contains the chain, but the
        # body is what's tested for the call. The lock acquirer's
        # construction call is not a DB method call (it's a function
        # call returning a context manager) — so only the body's
        # execute is a candidate, and that body is inside the lock.
        assert finds == []

    def test_inside_async_with_acquire_db_lock_async_is_safe(self):
        src = (
            "async def f(app):\n"
            "    async with acquire_db_lock_async(app.state.db, 'j'):\n"
            "        app.state.db.execute('SELECT 1')\n"
        )
        finds = _detect_on(src)
        assert finds == []

    def test_optout_on_same_line_is_safe(self):
        src = (
            "async def h(app):\n"
            "    app.state.db.execute('SELECT 1')  # async-db-ok: startup\n"
        )
        finds = _detect_on(src)
        assert finds == []

    def test_optout_on_previous_line_is_safe(self):
        src = (
            "async def h(app):\n"
            "    # async-db-ok: lifespan startup, single-threaded\n"
            "    app.state.db.executescript('CREATE TABLE t (i INT);')\n"
        )
        finds = _detect_on(src)
        assert finds == []

    def test_optout_substring_in_string_does_not_suppress(self):
        # A coincidental ``async-db-ok`` inside a string literal must
        # NOT count as an opt-out (real COMMENT token only).
        src = (
            "async def h(app):\n"
            "    msg = 'async-db-ok was once tried'\n"
            "    app.state.db.execute('SELECT 1')\n"
        )
        finds = _detect_on(src)
        assert len(finds) == 1

    def test_passing_db_to_helper_is_not_caught(self):
        # The pin matches ``<chain>.<METHOD>(...)`` only. Passing
        # ``app.state.db`` as an ARGUMENT to a helper is the safe
        # idiom — the helper will be dispatched through ``db_call``
        # at its call site.
        src = (
            "async def h(app):\n"
            "    rows = list_email_accounts(app.state.db)\n"
        )
        finds = _detect_on(src)
        assert finds == []

    def test_generic_conn_outside_state_chain_is_not_caught(self):
        # ``init_db`` / ``migrations.run_migrations`` / etc. take a
        # generic ``conn`` parameter and run ``conn.execute(...)``.
        # That is OUT OF SCOPE — the pin targets the
        # ``<...>.state.db`` chain only, not bare ``conn``. The
        # transitive guard (``test_async_db_safety.py``) is where the
        # generic-``conn`` family lives.
        src = (
            "def init_db(conn):\n"
            "    conn.executescript('CREATE TABLE t (i INT);')\n"
        )
        finds = _detect_on(src)
        assert finds == []

    def test_local_db_alias_method_call_is_not_caught(self):
        # ``db = request.app.state.db; db.execute(...)`` — local
        # alias, not the chain. Out of scope for this pin (the
        # transitive guard owns that family).
        src = (
            "async def h(request):\n"
            "    db = request.app.state.db\n"
            "    db.execute('SELECT 1')\n"
        )
        finds = _detect_on(src)
        assert finds == []

    def test_nested_def_inside_db_write_inherits_protection(self):
        # A nested sync def inside a ``@db_write`` parent inherits the
        # parent's protection envelope — same semantics as ``with
        # get_write_lock(): def inner(): ...`` blocks. The lock the
        # parent holds covers every direct touch in the lexical
        # subtree, including nested-def bodies that get called from
        # inside the parent's body.
        #
        # A nested def that is RETURNED from ``outer`` and called from
        # a later (unprotected) caller IS a hazard — but the pin
        # cannot distinguish "called inline" from "returned and called
        # later" at AST level. The conservative choice is to trust the
        # parent envelope; the transitive guard
        # (``test_async_db_safety.py``) is the layer that catches
        # cross-call-graph leaks.
        src = (
            "@db_write\n"
            "def outer(app):\n"
            "    def inner():\n"
            "        app.state.db.execute('SELECT 1')\n"
            "    return inner\n"
        )
        finds = _detect_on(src)
        assert finds == []


class TestNoFalsePositivesInTree:
    """Sanity: every module under ``src/email_triage`` MUST pass the
    pin TODAY (Phase 2 baseline). A failure here means either:
      (a) the pin's detector is wrong (false positive — fix the
          detector), or
      (b) a NEW direct-touch site landed since the baseline was set
          (real regression — fix the call site).
    """

    def test_baseline_is_zero(self):
        """The whole-tree finding count is 0 — the structural pin
        starts from a clean baseline."""
        total = 0
        per_module: dict[str, int] = {}
        for mod in _all_modules():
            try:
                src = mod.read_text(encoding="utf-8")
                tree = parse_source(src)
            except (SyntaxError, UnicodeDecodeError):
                continue
            f = _DirectTouchFinder(src)
            f.visit(tree)
            if f.findings:
                rel = relpath(mod)
                per_module[rel] = len(f.findings)
                total += len(f.findings)
        assert total == 0, (
            f"Phase 2 baseline broken: {total} direct-touch site(s) "
            f"found across {len(per_module)} module(s): {per_module}. "
            "Either a real regression landed or the detector grew a "
            "false positive — investigate before suppressing."
        )
