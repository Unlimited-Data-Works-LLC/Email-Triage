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

from _pin_harness import iter_src_files, parse_module, relpath  # N-350 R31


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
    # watch helpers — dispatched via db_call(...) from routers/agent_api.py
    # (upsert_watch, delete_watch) + watch_runner.py (_record_watch_fired,
    # maybe_auto_retire_watch); db_call holds the  RLock for the dispatched
    # call's whole duration, so these are serialized at the call site, not the
    # definition. maybe_auto_retire_watch is db_call-dispatched at its
    # sole src call site (watch_runner.py fire_watches_for_message, :946 at
    # 542da8bc) and runs its own DELETE/UPDATE + commits; baselining (not
    # @db_write) keeps it consistent with its siblings and avoids
    # double-dispatch. Punch 544 (N-539) split upsert_watch / delete_watch into
    # an own-commit wrapper over a non-committing *_txn; they still match
    # through the same-module hop in ``_dml_defs``. Not @db_write: that would
    # move the agent_api db_call sites onto the writer thread (not
    # behaviour-neutral, panel B2 db F1).
    ("web/email_watches.py", "upsert_watch"),
    ("web/email_watches.py", "delete_watch"),
    ("web/email_watches.py", "maybe_auto_retire_watch"),
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


def _own_dml_and_commit(node: ast.AST, conn_name: str) -> tuple[bool, bool]:
    """(does ``<conn_name>.execute(<DML>)``, does ``<conn_name>.commit()``) in
    ``node``'s own body."""
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
    return saw_dml_exec, saw_commit


def _calls_dml_def(node: ast.AST, conn_name: str, dml_defs: set[str]) -> bool:
    """``node`` calls a same-module def in ``dml_defs`` passing ``conn_name``
    as its first positional argument (``foo_txn(conn, …)``) or as a keyword
    named like a connection parameter (``foo_txn(conn=conn, …)``; panel B2
    landing, db-sme + devils-advocate).

    Stated limits (fail-OPEN, none present in src at 2026-10-06): the
    connection passed second-positionally, through an alias (``c = conn``),
    or to a cross-module attribute call (``ew.upsert_watch_txn(conn, …)``)
    is not followed."""
    for sub in ast.walk(node):
        if not (isinstance(sub, ast.Call) and isinstance(sub.func, ast.Name)
                and sub.func.id in dml_defs):
            continue
        if (sub.args and isinstance(sub.args[0], ast.Name)
                and sub.args[0].id == conn_name):
            return True
        if any(kw.arg in _CONN_PARAM_NAMES and isinstance(kw.value, ast.Name)
               and kw.value.id == conn_name for kw in sub.keywords):
            return True
    return False


def _dml_defs(tree: ast.AST) -> set[str]:
    """Module-level conn-first defs that execute DML on their connection,
    directly or through a same-module conn-first def (fixpoint). PD-2: the N-520
    ``*_txn`` split puts the DML in a non-committing sibling and the commit in
    an own-commit wrapper, so a writer is only visible across that one hop."""
    defs = {
        n.name: n for n in getattr(tree, "body", [])
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
        and _first_param(n) in _CONN_PARAM_NAMES
    }
    out = {name for name, fn in defs.items()
           if _own_dml_and_commit(fn, _first_param(fn))[0]}
    changed = True
    while changed:
        changed = False
        for name, fn in defs.items():
            if name not in out and _calls_dml_def(fn, _first_param(fn), out):
                out.add(name)
                changed = True
    return out


def _matches(node: ast.AST, conn_name: str, dml_defs: set[str] = frozenset()) -> bool:
    """True when ``node``'s body commits ``<conn_name>`` AND mutates it, either
    by its own ``<conn_name>.execute(<DML>)`` or by calling a same-module
    DML-bearing def (``dml_defs``) with ``<conn_name>`` first — the
    mutate-and-commit shape, one wrapper hop included."""
    dml, commit = _own_dml_and_commit(node, conn_name)
    return commit and (dml or _calls_dml_def(node, conn_name, dml_defs))


def _scan() -> tuple[set[tuple[str, str]], list[tuple[str, str, int]]]:
    """Return (matched_in_baseline, unexplained_violations).

    A function is a "match" if it lives in a scoped module, its first
    parameter names the connection, and it does conn-first DML+commit.
    A match is EXPLAINED by: @db_write, enclosing lock block, opt-out, or
    membership in the documented caller-serialized baseline.
    """
    matched_baseline: set[tuple[str, str]] = set()
    violations: list[tuple[str, str, int]] = []
    for p in iter_src_files():
        rel = relpath(p)
        if rel not in _WRITE_HELPER_MODULES:
            continue
        source_text = p.read_text(encoding="utf-8")
        tree = parse_module(p)
        if tree is None:
            import pytest
            pytest.fail(
                f"{p} did not parse — a non-parsing src module is a defect "
                "this guard must surface, not skip"
            )
        m, v = _scan_tree(rel, tree, source_text)
        matched_baseline |= m
        violations += v
    return matched_baseline, violations


def _scan_tree(
    rel: str, tree: ast.AST, source_text: str,
) -> tuple[set[tuple[str, str]], list[tuple[str, str, int]]]:
    """``_scan``'s per-module body (also driven by the teeth test)."""
    matched_baseline: set[tuple[str, str]] = set()
    violations: list[tuple[str, str, int]] = []
    optout = _optout_lines(source_text)
    lock_ranges = _lock_block_ranges(tree)
    dml_defs = _dml_defs(tree)
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        conn_name = _first_param(node)
        if conn_name not in _CONN_PARAM_NAMES:
            continue
        if not _matches(node, conn_name, dml_defs):
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


def test_one_hop_split_writer_is_seen():
    """Teeth (panel B2 db F1 / DA-2): an undecorated own-commit wrapper over a
    non-committing ``*_txn`` is a violation, at one hop and at two; the same
    wrapper ``@db_write``-decorated is not; a ``*_txn`` alone (no commit) is
    not a writer."""
    from _pin_harness import parse_source

    planted = (
        "def thing_txn(conn, x):\n"
        "    conn.execute('INSERT INTO t VALUES (?)', (x,))\n"
        "def outer_txn(conn, x):\n"
        "    thing_txn(conn, x)\n"
        "def thing(conn, x):\n"
        "    thing_txn(conn, x)\n"
        "    conn.commit()\n"
        "def outer(conn, x):\n"
        "    outer_txn(conn, x)\n"
        "    conn.commit()\n"
        "@db_write\n"
        "def safe(conn, x):\n"
        "    thing_txn(conn, x)\n"
        "    conn.commit()\n"
        "def by_keyword(conn, x):\n"
        "    thing_txn(conn=conn, x=x)\n"
        "    conn.commit()\n"
    )
    _m, v = _scan_tree("planted.py", parse_source(planted), planted)
    assert sorted(name for _r, name, _l in v) == ["by_keyword", "outer", "thing"], v


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
        "through the #211 RLock / writer thread. Only add to "
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


# ---------------------------------------------------------------------------
# Comprehensiveness meta-pin (R5c — census the censuser). The per-writer _scan
# above is BLIND to any conn-first-write-helper module OUTSIDE the hardcoded
# _WRITE_HELPER_MODULES — divergence census run11 §10 proved the vacuous-pass
# (purge_account_local_state in db/accounts.py, run_migrations in web/migrations.py,
# … silently un-scanned). This DERIVES every conn-first-write-helper module and
# asserts each is scanned here OR documented serialized-elsewhere, so a NEW one
# can't silently escape the scope.
# ---------------------------------------------------------------------------

# The ONE permitted hardcode (dynamic-over-hardcoding): a DOCUMENTED exceptions
# list of conn-first-write-helper modules whose writers are serialized by a
# mechanism OTHER than this pin's per-writer scan — classified + verified
# 2026-06-21. Per-writer un-serialized writes in these are ALSO caught repo-wide
# by the async-reachable sibling test_async_db_safety.py (+ the router
# .state.db shape by test_no_direct_app_state_db_method.py); this list records
# WHY each is out of the scan, and the test below fails if a NEW module appears
# in neither set. (A future cycle may MIGRATE an entry into _WRITE_HELPER_MODULES
# for per-writer coverage here, baselining its db_call-dispatched writers.)
_COVERED_ELSEWHERE = {
    # db/ helper modules — writers @db_write and/or db_call-dispatched ( RLock
    # held for the dispatched call at every call site).
    "db/accounts.py": "writers @db_write (15) / db_call-dispatched; the uncalled "
                      "delete_email_account primitive is pinned uncalled (N-108).",
    "db/users.py": "writers @db_write (12) / db_call-dispatched (#211).",
    "db/style.py": "writers @db_write (21).",
    "db/regulatory_clock.py": "writers @db_write (16).",
    "actions/topic_configs.py": "writers @db_write (9).",
    "web/auth.py": "writers @db_write (14) + lock-wrapped.",
    "web/mfa.py": "writers @db_write (5).",
    "web/background_sweepers.py": "writers @db_write (10) / lease-locked.",
    "jobs/topic_backscan.py": "back-scan writer @db_write / db_call-dispatched.",
    "embedding_bits/__init__.py": "embedding-cache writer; db_call-dispatched.",
    "web/settings_keys.py": "settings-table SSOT; writers db_call-dispatched at "
                            "every call site (#211).",
    # The db-write-LOCK SSOT itself — its lease writes ARE the serialization.
    "single_flight.py": "the db-write-lock SSOT (21 lock fns); its lease-conn "
                        "writes are the serialization mechanism, not a subject of it.",
    # BOOT-only — single-threaded startup, no concurrent writers.
    "web/migrations.py": "run_migrations + migration bodies run at BOOT only "
                        "(cli.py:1765 / web/db.py:885), single-threaded startup.",
    # Routers — covered by the async-safety + direct-.state.db sibling pins.
    "web/routers/api.py": "router; async-reachable writes covered by "
                          "test_async_db_safety.py + test_no_direct_app_state_db_method.py.",
    "web/routers/ui/_shared.py": "router; covered by the async-safety siblings.",
    "web/routers/ui/users.py": "router; covered by the async-safety siblings.",
}


def _module_has_write_helper(tree: ast.AST) -> bool:
    """``tree`` DEFINES a conn-first DML+commit helper — the SAME detector the
    scan uses (`_first_param` ∈ conn-names AND `_matches` with the module's
    `_dml_defs`), so a module whose writers are all split-shaped (DML in a
    ``*_txn``, commit in its wrapper) is derived too (panel B2 landing, db-sme:
    without the hop it was never forced into either set)."""
    dml_defs = _dml_defs(tree)
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        cn = _first_param(node)
        if cn in _CONN_PARAM_NAMES and _matches(node, cn, dml_defs):
            return True
    return False


def _modules_with_write_helper() -> set[str]:
    """Every src module DEFINING a conn-first DML+commit helper, by
    `_module_has_write_helper`, so it cannot drift from the scan's notion of a
    write helper."""
    mods: set[str] = set()
    for p in iter_src_files():
        try:
            tree = parse_module(p); assert tree is not None  # N-350 R31
        except SyntaxError:  # pragma: no cover
            continue
        if _module_has_write_helper(tree):
            mods.add(relpath(p))
    return mods


def test_split_only_module_is_derived():
    """Teeth (panel B2 landing, db-sme): a module whose only writer is the
    split shape (DML in ``thing_txn``, commit in ``thing``) is derived as a
    write-helper module; a module with only the non-committing ``*_txn`` is not."""
    from _pin_harness import parse_source

    split_only = (
        "def thing_txn(conn, x):\n"
        "    conn.execute('INSERT INTO t VALUES (?)', (x,))\n"
        "def thing(conn, x):\n"
        "    thing_txn(conn, x)\n"
        "    conn.commit()\n"
    )
    txn_only = (
        "def thing_txn(conn, x):\n"
        "    conn.execute('INSERT INTO t VALUES (?)', (x,))\n"
    )
    assert _module_has_write_helper(parse_source(split_only))
    assert not _module_has_write_helper(parse_source(txn_only))


def test_write_helper_module_set_is_comprehensive():
    """R5c — no conn-first-write-helper module silently escapes the scope. DERIVE
    every such module; assert each is in _WRITE_HELPER_MODULES (per-writer scanned
    here) OR _COVERED_ELSEWHERE (documented serialized-elsewhere). A NEW one in
    neither FAILS — closing the run11 §10 vacuous-pass (the 7-module hardcoded
    scope was blind to new write-helper modules)."""
    derived = _modules_with_write_helper()
    known = set(_WRITE_HELPER_MODULES) | set(_COVERED_ELSEWHERE)
    escaped = sorted(derived - known)
    assert not escaped, (
        "conn-first-write-helper module(s) in NEITHER _WRITE_HELPER_MODULES "
        "(scanned here) NOR _COVERED_ELSEWHERE (documented serialized-elsewhere):\n  "
        + "\n  ".join(escaped)
        + "\nEither add to _WRITE_HELPER_MODULES (and ensure each conn-first writer "
        "is @db_write / lock-wrapped / baselined), OR document the serialization "
        "mechanism in _COVERED_ELSEWHERE. Never leave it silently un-scanned."
    )


def test_comprehensiveness_meta_pin_has_teeth():
    """Guard the meta-pin: a brand-new write-helper module outside both sets must
    be flagged (the escape-set must have teeth)."""
    known = set(_WRITE_HELPER_MODULES) | set(_COVERED_ELSEWHERE)
    assert ({"some/brand_new_writer.py"} - known), (
        "meta-pin would not flag a brand-new write-helper module"
    )


def test_covered_elsewhere_entries_exist():
    """PD#7 rot-guard (census run15 §10 — the comprehensiveness meta-pin's
    ``_COVERED_ELSEWHERE`` lacked the rot-guard its sibling
    ``_CALLER_SERIALIZED_BASELINE`` has via
    ``test_caller_serialized_baseline_is_not_stale``). Every documented
    ``_COVERED_ELSEWHERE`` entry must name a src module that STILL EXISTS — a
    renamed/deleted/moved module leaves a DEAD exemption that would silently
    exempt a FUTURE conn-first-write-helper module which happens to land on the
    stale path. (File-existence, not write-helper-shape: the 3 router entries are
    listed because their async-reachable writes are covered by the sibling pins,
    not because they define a conn-first helper, so a shape check would
    false-flag them.)"""
    from _pin_harness import SRC_ROOT

    missing = sorted(m for m in _COVERED_ELSEWHERE if not (SRC_ROOT / m).is_file())
    assert not missing, (
        "Stale _COVERED_ELSEWHERE entries — these src modules no longer exist "
        "(renamed / deleted / moved), so the documented serialized-elsewhere "
        "exemption is dead weight (PD#7 — keep the exemption list honest):\n  "
        + "\n  ".join(missing)
        + "\nRemove them, or update the path to the module's new location."
    )
