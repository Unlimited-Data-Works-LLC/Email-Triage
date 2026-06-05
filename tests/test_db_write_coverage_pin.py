""" (DA + plan §5) — count-agnostic structural pin: every shared-
connection DML+commit helper is serialized by a recognized mechanism.

What this defends
-----------------
The v0.1.2 single-file encryption write path is serialized at ONE chokepoint: the
``@db_write`` decorator (which routes through the  ``get_write_lock()``
RLock and, when the writer backend is enabled, the single writer thread).
The decorator is a "magic tag" — a helper that does
``conn.execute(<DML>)`` + ``conn.commit()`` on its connection parameter
but FORGETS the tag is NOT statically distinguishable from one that has
it, so it would silently run UN-serialized and re-open the
concurrent-shared-connection corruption class Phase 0 closed.

This pin converts that magic tag into an ENFORCED INVARIANT: a helper
whose FIRST parameter is the shared connection (``conn`` / ``session`` /
``db``) and that mutates+commits it MUST be one of:

  1. ``@db_write``-decorated (the chokepoint — serialized in-process), OR
  2. inside a ``with get_write_lock():`` / ``acquire_db_lock()`` block
     (explicit lock envelope), OR
  3. carrying a ``# async-db-ok`` opt-out (provably single-threaded —
     lifespan startup / CLI entrypoint), OR
  4. in the DOCUMENTED caller-serialized baseline below — helpers that
     are invoked ONLY through ``db_call(...)`` (which holds the RLock for
     the dispatched call's whole duration), so the serialization lives at
     the call site, not the definition.

Any NEW conn-first DML+commit helper that fits none of these trips CI.

Scope (per the lead's pre-authorization 2026-05-29)
---------------------------------------------------
A full-tree AST version is too false-positive-prone: ~62 router/handler
helpers do conn-first DML+commit but are serialized TRANSITIVELY by a
``db_call`` caller — a property a per-function AST walk cannot see (it
needs the call graph, which ``test_async_db_safety.py`` already walks).
So this pin is SCOPED to the canonical shared-connection write-helper
modules (``_WRITE_HELPER_MODULES``) — the files that define conn-first
helpers as their primary surface. Router/UI/CLI modules are covered for
the un-serialized-touch shape by ``test_no_direct_app_state_db_method.py``
(direct ``.state.db`` touch) + ``test_async_db_safety.py`` (transitive
async-reachable touch). This is the count-agnostic structural-drift-catch
pattern (``pattern_count_agnostic_structural_drift_catch.md``): it asserts
a PROPERTY (every match is serialized by a recognized mechanism), not a
count.

Baseline honesty
----------------
``_CALLER_SERIALIZED_BASELINE`` is NOT a count — it is the explicit set
of existing helpers that predate / sit outside the ``@db_write``
convention and rely on ``db_call`` caller-side locking. Each is
``db_call``-dispatched at every call site (verified 2026-05-29). The pin
fails if a member is REMOVED-but-still-matches (stale entry) OR if a NEW
match appears that is not decorated, lock-wrapped, opted-out, or listed.
The honest fix for a NEW match is to add ``@db_write`` (preferred) — only
add to the baseline if the helper is genuinely caller-serialized via
``db_call`` and decorating it would double-acquire / change semantics.
"""

from __future__ import annotations

import ast
import io
import tokenize
from pathlib import Path


# ---------------------------------------------------------------------------
# Scope + baseline
# ---------------------------------------------------------------------------

# Canonical shared-connection write-helper modules (paths relative to
# ``src/email_triage``, forward-slash normalized). These define conn-first
# helpers as their primary surface — the place a forgotten-@db_write
# regression is most likely to land.
_WRITE_HELPER_MODULES = {
    "web/db.py",
    "db/audit.py",
    "web/db_auth_helpers.py",
    "web/email_watches.py",
    "actions/base.py",
    "web/acme_job_state.py",
    "web/watch_runner.py",
}

# Helpers in the scoped modules that do conn-first DML+commit WITHOUT
# ``@db_write`` because they are serialized by their ``db_call`` caller
# (the RLock is held for the dispatched call). Each verified
# db_call-dispatched at every call site 2026-05-29. ``(module, funcname)``.
_CALLER_SERIALIZED_BASELINE = {
    # gap-event writer — invoked from the @db_write recovery path (already
    # under the write lock) AND from db_call's shed handler under the lock
    # (db_threadpool._record_shed_audit_write wraps it in get_write_lock()).
    # NOT itself @db_write because it is the recovery-path writer the
    # decorator calls; decorating it would re-enter the wrapper.
    ("db/audit.py", "_write_audit_gap_event"),
    # watch helpers — dispatched via db_call(...) from routers/openclaw.py
    # (upsert_watch) + watch_runner.py (_record_watch_fired); db_call holds
    # the  RLock for the dispatched call's whole duration, so these are
    # serialized at the call site, not the definition.
    ("web/email_watches.py", "upsert_watch"),
    ("web/email_watches.py", "delete_watch"),
    ("web/watch_runner.py", "_record_watch_fired"),
}
# NOTE: the ~11 db_auth_helpers.py conn-first writers are NOT here — they
# ARE serialized at the chokepoint via the ``@_db_write`` decorator alias
# (``_has_db_write`` recognizes both ``db_write`` and ``_db_write``).

_DML_PREFIXES = (
    "INSERT", "UPDATE", "DELETE", "REPLACE", "CREATE", "DROP", "ALTER",
)
_CONN_PARAM_NAMES = {"conn", "session", "db"}
_LOCK_FNS = {"get_write_lock", "acquire_db_lock", "acquire_db_lock_async"}


def _src_root() -> Path:
    return Path(__file__).resolve().parent.parent / "src" / "email_triage"


def _first_arg_is_dml(call: ast.Call) -> bool:
    """True when the first positional arg is a string literal whose first
    SQL keyword is a DML/DDL verb (the body MUTATES, not just reads)."""
    if not call.args:
        return False
    arg = call.args[0]
    sql = None
    if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
        sql = arg.value
    elif isinstance(arg, ast.JoinedStr):
        # f-string: inspect the leading literal chunk.
        for v in arg.values:
            if isinstance(v, ast.Constant) and isinstance(v.value, str):
                sql = v.value
                break
    if not sql:
        return False
    head = sql.lstrip().upper().lstrip("(").lstrip()
    return head.startswith(_DML_PREFIXES)


def _has_db_write(fn: ast.AST) -> bool:
    for d in fn.decorator_list:  # type: ignore[attr-defined]
        inner = d.func if isinstance(d, ast.Call) else d
        name = None
        if isinstance(inner, ast.Name):
            name = inner.id
        elif isinstance(inner, ast.Attribute):
            name = inner.attr
        if name in ("db_write", "_db_write"):
            return True
    return False


def _first_param(fn: ast.AST) -> str | None:
    args = fn.args.args  # type: ignore[attr-defined]
    return args[0].arg if args else None


def _optout_lines(src: str) -> set[int]:
    """Line numbers carrying a real ``# async-db-ok`` opt-out comment.

    Same semantics as ``test_async_db_safety.py`` — a standalone marker
    token inside a genuine COMMENT token, not a string-literal substring.
    """
    flagged: set[int] = set()
    try:
        for tok in tokenize.generate_tokens(io.StringIO(src).readline):
            if tok.type != tokenize.COMMENT:
                continue
            for w in tok.string.lstrip("#").replace(",", " ").split():
                if w.rstrip(":-").lower() in ("async-db-ok", "async-db-todo"):
                    flagged.add(tok.start[0])
                    break
    except (tokenize.TokenError, IndentationError, SyntaxError):
        pass
    return flagged


def _lock_block_ranges(tree: ast.AST) -> list[tuple[int, int]]:
    """Line ranges (inclusive) covered by a ``with``/``async with`` block
    whose context manager is a recognized lock acquirer."""
    ranges: list[tuple[int, int]] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.With, ast.AsyncWith)):
            continue
        for item in node.items:
            ce = item.context_expr
            f = ce.func if isinstance(ce, ast.Call) else ce
            name = (
                f.id if isinstance(f, ast.Name)
                else f.attr if isinstance(f, ast.Attribute)
                else None
            )
            if name in _LOCK_FNS:
                ranges.append((node.lineno, node.end_lineno or node.lineno))
                break
    return ranges


def _matches(node: ast.AST, conn_name: str) -> bool:
    """True when ``node``'s body does ``<conn_name>.execute(<DML>)`` AND
    ``<conn_name>.commit()`` — the mutate-and-commit shape."""
    saw_dml_exec = False
    saw_commit = False
    for sub in ast.walk(node):
        if not (isinstance(sub, ast.Call) and isinstance(sub.func, ast.Attribute)):
            continue
        target = sub.func.value
        if not (isinstance(target, ast.Name) and target.id == conn_name):
            continue
        if sub.func.attr in ("execute", "executemany", "executescript"):
            if _first_arg_is_dml(sub):
                saw_dml_exec = True
        elif sub.func.attr == "commit":
            saw_commit = True
    return saw_dml_exec and saw_commit


def _scan() -> tuple[set[tuple[str, str]], list[tuple[str, str, int]]]:
    """Return (matched_in_baseline, unexplained_violations).

    A function is a "match" if it lives in a scoped module, its first
    parameter names the connection, and it does conn-first DML+commit.
    A match is EXPLAINED by: @db_write, enclosing lock block, opt-out, or
    membership in the documented caller-serialized baseline.
    """
    root = _src_root()
    matched_baseline: set[tuple[str, str]] = set()
    violations: list[tuple[str, str, int]] = []
    for p in root.rglob("*.py"):
        if "__pycache__" in p.parts:
            continue
        rel = str(p.relative_to(root)).replace("\\", "/")
        if rel not in _WRITE_HELPER_MODULES:
            continue
        src = p.read_text(encoding="utf-8")
        tree = ast.parse(src)
        optout = _optout_lines(src)
        lock_ranges = _lock_block_ranges(tree)
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            conn_name = _first_param(node)
            if conn_name not in _CONN_PARAM_NAMES:
                continue
            if not _matches(node, conn_name):
                continue
            key = (rel, node.name)
            # Escape hatch 1 — @db_write chokepoint.
            if _has_db_write(node):
                continue
            # Escape hatch 2 — whole function body inside a lock block.
            end = node.end_lineno or node.lineno
            if any(a <= node.lineno and end <= b for (a, b) in lock_ranges):
                continue
            # Escape hatch 3 — opt-out anywhere in the function span.
            if any(node.lineno <= ln <= end for ln in optout):
                continue
            # Escape hatch 4 — documented caller-serialized baseline.
            if key in _CALLER_SERIALIZED_BASELINE:
                matched_baseline.add(key)
                continue
            violations.append((rel, node.name, node.lineno))
    return matched_baseline, violations


# ---------------------------------------------------------------------------
# The pin
# ---------------------------------------------------------------------------

def test_no_unserialized_shared_conn_write_helper():
    """Every conn-first DML+commit helper in the write-helper modules is
    serialized by a recognized mechanism (the count-agnostic property)."""
    _matched, violations = _scan()
    assert not violations, (
        "Un-serialized shared-connection write helper(s) found — a "
        "conn-first helper does conn.execute(<DML>) + conn.commit() but "
        "is NOT @db_write-decorated, NOT inside a get_write_lock()/"
        "acquire_db_lock() block, NOT marked # async-db-ok, and NOT in "
        "the documented caller-serialized baseline:\n"
        + "\n".join(
            f"  {rel}::{name} (line {lineno})" for rel, name, lineno in violations
        )
        + "\n\nFix (preferred): add @db_write so the write serializes "
        "through the  RLock / writer thread. Only add to "
        "_CALLER_SERIALIZED_BASELINE if the helper is invoked ONLY via "
        "db_call(...) (caller holds the lock) AND decorating it would "
        "double-acquire or change semantics — and document why."
    )


def test_caller_serialized_baseline_is_not_stale():
    """Every documented baseline entry still matches the shape — a stale
    entry (helper deleted / decorated / refactored) must be pruned so the
    baseline stays an honest record, not a graveyard."""
    matched, _violations = _scan()
    stale = _CALLER_SERIALIZED_BASELINE - matched
    assert not stale, (
        "Stale _CALLER_SERIALIZED_BASELINE entries — these no longer "
        "match the conn-first DML+commit shape (helper removed, now "
        "@db_write-decorated, or refactored). Remove them from the "
        "baseline:\n"
        + "\n".join(f"  {rel}::{name}" for rel, name in sorted(stale))
    )
