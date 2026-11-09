"""Audit-emit SWALLOW disposition pin (PD#1, PD#2, PD#3, PD#6).

A best-effort audit-event emit (any ``@audit_emitter`` helper — direct OR via
the ``db_call``/``to_thread``/``run_in_executor`` seam) that is SWALLOWED — it
sits in a ``try`` whose handler CATCHES its failure (``Exception`` /
``BaseException`` / bare ``except:`` / a tuple including those) and is NOT
GUARANTEED to re-raise — must route through the ``web._audit.safe_audit_write``
/ ``safe_audit_write_async`` SSOT (log-on-failure, visible to /health's
audit-failure drift counter), never a hand-rolled bare ``except: pass`` or an
ad-hoc-logged ``try``. After conversion the emit lives in a ``safe_audit_write*``
lambda (no enclosing ``try``) → it passes.

THE EMITTER NET IS DERIVED STRUCTURALLY (run18 #2 — generalises N-135).
``_EMITTERS`` is **not** a hardcoded name list — it is the full set of
``@audit_emitter``-decorated helpers, read from the decorator itself via the
SHARED ``_pin_harness.audit_emitter_defs`` walker (the SAME walker the N-36
redaction-map + inverse pins use — PD#6, never a forked scanner). Today that
yields ~11 emitters (``record_hipaa_access_event``, ``record_access_event``,
``record_auth_event``, ``record_hipaa_boundary``, ``record_user_status_event``,
``set_user_disabled``, ``update_hipaa_access_event``, ``record_clock_event``,
``record_discover_run``, ``record_api_key_event``, ``record_style_distill_event``).
N-135 shipped this pin with a HARDCODED 3-name net (``record_hipaa_access_event``
/ ``record_access_event`` / ``record_auth_event``); db-sme verified that net as
PARTIAL (the PD#2 hardcoded-net trap — it was blind to swallowed emits of the
other 8 emitters, e.g. every ``update_hipaa_access_event`` finalise). Deriving
the net from the decorator closes that gap and keeps it closed as emitters are
added/removed.

The decorator walker reads only ``_pin_harness.AUDIT_EMITTER_MODULES`` (a
2-module fast path — ``db/audit.py`` + ``db/style.py`` — so the hot net build
parses 2 files, not all of src). That MODULE tuple is the SAME hardcoded-list
trap one grain up: a future ``@audit_emitter`` in a THIRD module would escape
BOTH this pin and the N-36 redaction pin. ``test_audit_emitter_modules_is_
structurally_complete`` is its drift-guard — a full-src walk
(``discover_audit_emitter_modules``) that fails loudly if the structural module
set diverges from the tuple, forcing a conscious add (PD#1/#7).

NET-COMPLETENESS (PD#4 — honest, NOT circular). N-135's docstring claimed "the
structural pin IS the enumeration-completeness proof" while the net was a
hardcoded 3-name list — that was CIRCULAR (a pin can only prove completeness
over the population it actually enumerates; a hardcoded net cannot enumerate the
emitter FAMILY). The real, non-circular claim: the emitter net is enumerated
from the ``@audit_emitter`` decorator (so it tracks the family with no hand
count), and the swallow scan is complete over THAT net — so a green run proves
no UNROUTED, catch-all-swallowed emit of ANY ``@audit_emitter`` survives outside
the ``_ALLOW`` dispositions below. What it does NOT prove is in BOUNDED GAPS.

SEVERITY (hipaa-sme + DA, N-135). A swallowed emit is NOT a §164.312(b) ROW
LOSS — every ``@audit_emitter`` durably writes a tamper-evident, HMAC-chained
``audit_gap_events`` ledger row BEFORE re-raising. So this is an OBSERVABILITY
convergence (uniform /health drift visibility), not a row-loss fix. That is also
why "gap-ledger-backstopped" ALONE is NOT a sufficient ``_ALLOW`` reason (it is
true of EVERY emitter — it would make the pin toothless); an allow-list entry
must carry a STRUCTURAL reason the swallow is already observable (see ``_ALLOW``).

BOUNDED GAPS — honest SCOPE CAVEAT ("a pin exists" ≠ proof of safety). Does NOT
catch:
  (a) a NARROW except that IS the emit's TRUE failure mode — e.g.
      ``except sqlite3.OperationalError: pass`` directly wrapping an emit (the
      emitters CAN raise OperationalError on lock contention). Catch-all-only is
      the deliberate FP guard, so a future narrow-except-on-the-failure-mode
      swallow slips. A true-up should re-scan (a) since the emitters raise DB
      errors.
  (b) a seam emitter reaching ``db_call``/``to_thread``/etc. NOT as a positional
      ``ast.Name`` — via ``functools.partial``, a keyword arg
      (``db_call(fn=record_…)``), or an ``Attribute`` (``self.record_…``).
      ImportFrom asname aliasing IS tracked, for BOTH the emitter name AND the
      seam wrapper (``db_call as _db_call`` — the N-135 access_audit miss).
  (c) dispatch outside ``_SEAM`` (anyio ``run_sync``, ``executor.submit``).
  (d) ``_ALLOW`` keys on ``relpath:funcname`` (line-shift-stable per R38), so a
      future NON-finalise swallow added to an allow-listed finalise function
      would be masked. ``test_allow_list_is_not_stale`` proves each entry still
      matches a live swallow; the funcname grain is the documented residual.
  (e) a swallowed FINALISE failure does NOT bump /health's ``audit_failures``
      drift counter. That counter (``app.state.audit_failures``, surfaced by
      ``/health``) is bumped only on the ``access_log`` path
      (``web/access_audit.py``); a hand-rolled finalise swallow neither bumps it
      NOR emits the ``safe_audit_write`` ``audit_write_failed`` WARNING (it never
      routes through the SSOT). Only the ``@db_write`` wrapper's
      ``audit_gap_events`` gap-ledger row records the miss — durable
      (HMAC-chained) but NOT /health-visible, so surfacing an allow-listed
      finalise swallow is a manual gap-ledger inspection (the residual the
      ``_ALLOW`` entries knowingly accept; see the ``_ALLOW`` rationale below).

RE-RAISE DETECTION IS GUARANTEED-ONLY (run18 #2). A handler re-raises (→ NOT a
swallow) only when a ``raise`` is GUARANTEED to execute if the handler runs — a
bare ``raise`` at handler level, or one inside an unconditionally-entered
``with`` / a ``finally`` / a both-branches ``if``. A CONDITIONAL ``if cond:
raise`` is NOT a guaranteed re-raise: the common (cond-false) path swallows. The
N-135 net read access_audit's ``if STRICT: raise`` as a re-raise and passed it;
the guaranteed-only rule flags that shape (access_audit itself is now converged,
so it no longer appears — but the teeth prove the rule has bite).

The guarantee is computed over the handler body's CONTROL FLOW, not just "is
there a ``raise`` somewhere" — a ``return`` / ``break`` / ``continue`` is a
NON-raising exit, so a ``raise`` reachable only AFTER one (``if benign: return``
then a trailing ``raise``) does NOT count as guaranteed (the benign path
swallows). Modelling those terminators is the same root-class fix as the bug
this pin catches; ``_block_outcomes`` is the 3-outcome analyser and the teeth
plant the early-return-then-raise shape.
"""

from __future__ import annotations

import ast

from _pin_harness import (
    AUDIT_EMITTER_MODULES,
    audit_emitter_names,
    chain_writer_names,
    discover_audit_emitter_modules,
    discover_chain_writers,
    is_emergency_sanctioned_handler,
    iter_src_files,
    relpath,
    parse_source,
)

# The audit-event emitter SSOTs — the FULL ``@audit_emitter`` family, derived
# STRUCTURALLY from the decorator via the shared harness walker (PD#1/#2/#6),
# never a hardcoded name list. A swallowed emit of ANY of them is a
# /health-invisible audit-failure (the observability convergence).
_EMITTERS = frozenset(audit_emitter_names())

# Off-loop dispatch seams an emit can hop through. Per-file ImportFrom asname
# aliases are added in :func:`_seam_aliases` (``db_call as _db_call``).
_SEAM = frozenset({"db_call", "db_call_async", "to_thread", "run_in_executor"})
_SAFE_WRAPPERS = frozenset({"safe_audit_write", "safe_audit_write_async"})
# Catch-all exception types whose handler suppresses ANY exception (so a
# swallowing one hides the emit failure). A NARROW ``except ValueError:`` cannot
# catch the emit failure → NOT a swallow (DA guard).
_CATCH_ALL = frozenset({"Exception", "BaseException"})

# N-366 R31 (2026-07-05 trust-repair fix-forward per Census run22 §2 +
# the backlog  = TASK ): SQL-shape exception names that CAN catch
# an audit-emit failure. The emit path goes DB → sqlite3.execute() →
# `_chain_insert`, so a narrow `except sqlite3.OperationalError: pass`
# directly wrapping an emit IS a real swallow — it catches the exact
# failure class the emit throws. Add these to the "catches all"-for-
# this-emit set so a narrow SQL-except is flagged. The DA guard for
# arbitrary narrow-excepts (e.g. `except ValueError: pass`, which
# genuinely CAN'T catch the emit's sqlite errors) is preserved for
# non-SQL-shape names.
_CATCH_SQL_EMIT_FAILURE = frozenset({
    "OperationalError",     # sqlite3.OperationalError — DB busy, locked, etc.
    "IntegrityError",       # FK violation, uniqueness
    "DatabaseError",        # sqlite3.DatabaseError parent
    "Error",                # sqlite3.Error (broadest sqlite3 hierarchy root)
    "sqlite3",              # `sqlite3.Error` via attribute — surfaced below
})

# (relpath:funcname) — a swallowing emit that is a SANCTIONED disposition, not a
# best-effort write to converge. "gap-ledger-backstopped" alone is NOT enough
# (true of every emitter); each entry carries the STRUCTURAL reason the swallow
# is already observable.
#
# These six functions all SWALLOW an ``update_hipaa_access_event`` FINALISE — the
# terminal/finally close of a start→finalise §164.312(b) bracket. The bracket's
# START (``record_hipaa_access_event``, outcome="in_progress") is emitted
# ELSEWHERE (accounts.py / profile.py / _shared.py / triage_classify.py), NOT in
# these finalise functions — and no START is swallowed ANYWHERE: that is globally
# pin-enforced (0 ``record_hipaa_access_event`` start sites are allow-listed), so
# a bracket-INITIATION failure always surfaces. The finalise is itself
# ``@audit_emitter`` (so a failed finalise writes the HMAC-chained
# ``audit_gap_events`` gap-ledger row) AND lives in a ``finally`` / terminal-error
# branch where a hand-rolled context log carries job-specific forensic detail and
# a raise would mask the job's real outcome.
# A failed finalise leaves the row at its start outcome ("in_progress"), recorded
# by the durable HMAC ``audit_gap_events`` gap-ledger but NOT auto-reconciled:
# ``db/reconciliation.py`` EXCLUDES ``hipaa_access_events`` by design (reconciling
# audit against audit is circular — it is a PHI-table-vs-chain tamper detector,
# and a chain-consistent "in_progress" row is not a tamper), so surfacing a stuck
# "in_progress" row needs MANUAL gap-ledger inspection (see BOUNDED GAP (e)).
# (run18 #2 triage.)
# Allow-list step 2 (2026-11-05, B1): all six finalise sites now route through
# safe_audit_write / safe_audit_write_async, so the entries are cut and the set
# is empty; a new swallowed finalise fails the pin.
_ALLOW: frozenset[str] = frozenset()
# Punch 709 (operator decision 2026-11-02 8:13 PM): the EMERGENCY revoke is NOT an
# ``_ALLOW`` name entry (cycle P db-sme P2 item 2: a name exempts every future swallow in
# the function). A catch-all handler is not a swallow when it is a sanctioned emergency
# handler by the shared predicate ``_pin_harness.is_emergency_sanctioned_handler``: it
# re-raises under ``if emergency_reason is None:`` and its function calls
# ``record_emergency_revoke``, which writes the PHI-free ``audit_gap_events`` row, logs
# CRITICAL and sets the ``/health/detail`` marker. The same predicate scopes the session-
# epoch pin's exemption (PD-6). Delete the guard and the site is a swallow again.
# web/_audit.py (the SSOT) is scanned like every other file: its old hard-exclude was cut
# 2026-11-05 (allow-list step 6) because removing it kept this pin green.


def _collect_aliases(tree: ast.AST, base: frozenset[str]) -> set[str]:
    """``base`` plus every ``from … import X as Y`` asname for an ``X`` in
    ``base`` (per-file). Used for BOTH the emitter names and the ``_SEAM``
    wrappers, so an aliased emitter OR an aliased seam (``db_call as _db_call``)
    is still recognised."""
    al = set(base)
    for n in ast.walk(tree):
        if isinstance(n, ast.ImportFrom):
            for a in n.names:
                if a.name in base:
                    al.add(a.asname or a.name)
    return al


def _aliases(tree: ast.AST) -> set[str]:
    return _collect_aliases(tree, _EMITTERS)


def _seam_aliases(tree: ast.AST) -> set[str]:
    return _collect_aliases(tree, _SEAM)


def _is_emit(call: ast.Call, aliases: set[str], seam: set[str]) -> bool:
    f = call.func
    if isinstance(f, ast.Name) and f.id in aliases:
        return True
    if isinstance(f, ast.Attribute) and f.attr in _EMITTERS:
        return True
    name = f.id if isinstance(f, ast.Name) else (f.attr if isinstance(f, ast.Attribute) else None)
    if name in seam and any(isinstance(a, ast.Name) and a.id in aliases for a in call.args):
        return True
    return False


def _handler_is_bare_pass(handler: ast.ExceptHandler) -> bool:
    """N-366 helper: True iff the except handler body is JUST `pass`
    (no logging, no recovery, no re-emit, no re-raise). Matches the
    Census run22 §2 fifth-teeth target shape specifically — a
    catch-and-drop with zero side effect."""
    return len(handler.body) == 1 and isinstance(handler.body[0], ast.Pass)


def _handler_catches_all(handler: ast.ExceptHandler) -> bool:
    """True if this except clause can catch the emit's failure: bare ``except:``,
    ``except Exception``/``BaseException``, or a tuple including one of those.

    N-366 R31 (2026-07-05): also True for BARE-PASS narrow SQL-shape
    excepts that CAN catch an audit-emit failure — `sqlite3.
    OperationalError`, `sqlite3.IntegrityError`, `sqlite3.DatabaseError`,
    `sqlite3.Error` (bare `OperationalError` etc. via `from sqlite3
    import OperationalError` too). The emit path goes DB → sqlite3.
    execute() → `_chain_insert` so these are the exact failure class
    the emit throws — catching WITH a bare `pass` IS a swallow.

    Narrow SQL-excepts with a NON-PASS body (defensive-recover +
    re-emit, log-and-continue, etc.) are NOT flagged — the census's
    specific concern was the bare-pass shape (0 sites today). Preserves
    the DA guard for unrelated narrow-excepts (e.g. `except ValueError:
    pass` genuinely CAN'T catch the emit's sqlite errors either).
    """
    t = handler.type
    if t is None:  # bare except:
        return True
    if isinstance(t, ast.Name) and t.id in _CATCH_ALL:
        return True
    # N-366: bare-name SQL form (`from sqlite3 import OperationalError`
    # then `except OperationalError:`). Requires bare-pass body.
    if isinstance(t, ast.Name) and t.id in _CATCH_SQL_EMIT_FAILURE:
        return _handler_is_bare_pass(handler)
    # N-366: attribute-chain SQL form (`except sqlite3.OperationalError:`
    # or `except sqlite3.Error:`). Requires bare-pass body.
    if isinstance(t, ast.Attribute):
        if (
            isinstance(t.value, ast.Name)
            and t.value.id == "sqlite3"
            and t.attr in _CATCH_SQL_EMIT_FAILURE
        ):
            return _handler_is_bare_pass(handler)
    if isinstance(t, ast.Tuple):
        if any(isinstance(e, ast.Name) and e.id in _CATCH_ALL for e in t.elts):
            return True
        # N-366: any SQL-shape entry in the tuple — bare-pass body required.
        has_sql = False
        for elt in t.elts:
            if isinstance(elt, ast.Name) and elt.id in _CATCH_SQL_EMIT_FAILURE:
                has_sql = True
                break
            if (
                isinstance(elt, ast.Attribute)
                and isinstance(elt.value, ast.Name)
                and elt.value.id == "sqlite3"
                and elt.attr in _CATCH_SQL_EMIT_FAILURE
            ):
                has_sql = True
                break
        if has_sql:
            return _handler_is_bare_pass(handler)
    return False


# 3-outcome control-flow labels for a statement / block (run18 #2, SHOULD-FIX 3).
# ``_RAISE`` — a path raises; ``_EXIT`` — a path returns/breaks/continues (leaves
# WITHOUT raising); ``_FALL`` — a path runs off the end normally. A block
# GUARANTEES a raise iff its ONLY outcome is ``{_RAISE}`` (no non-raising path).
_RAISE, _EXIT, _FALL = "raise", "exit", "fall"


def _block_outcomes(stmts: list[ast.stmt]) -> set[str]:
    """The set of control-flow outcomes of executing ``stmts`` in order
    (:data:`_RAISE` / :data:`_EXIT` / :data:`_FALL`). Walks statements; a
    ``raise`` or a ``return``/``break``/``continue`` is TERMINAL (control does
    not reach the next statement on that path), so a ``raise`` reachable only
    after a non-raising exit is NOT a guaranteed raise — the early-return bug
    SHOULD-FIX 3 closes."""
    result: set[str] = set()
    reachable = True  # can control fall INTO the current statement?
    for st in stmts:
        if not reachable:
            break  # dead code after an always-terminal statement
        outs = _stmt_outcomes(st)
        if _RAISE in outs:
            result.add(_RAISE)
        if _EXIT in outs:
            result.add(_EXIT)
        # control reaches the NEXT statement only if this one can fall through
        reachable = _FALL in outs
    if reachable:
        result.add(_FALL)  # the block can run off its end
    return result


def _stmt_outcomes(st: ast.stmt) -> set[str]:
    """Control-flow outcomes of a SINGLE statement. ``raise`` →
    ``{_RAISE}``; ``return``/``break``/``continue`` → ``{_EXIT}`` (a NON-raising
    exit — modelling these is the fix). ``if`` unions both branches (an empty
    ``else`` is an implicit fall-through). ``with`` mirrors its body. Everything
    else (``Expr``, ``Assign``, ``for``/``while``, nested ``def``/``class`` …) is
    treated as falling through and is NOT descended into — a raise inside a
    nested ``def``/``lambda`` or an exotic loop is not THIS handler's guaranteed
    re-raise (DA guard), and reporting fall-through means we never OVER-claim a
    guarantee (fail-closed: an unproven guarantee is treated as a swallow)."""
    if isinstance(st, ast.Raise):
        return {_RAISE}
    if isinstance(st, (ast.Return, ast.Break, ast.Continue)):
        return {_EXIT}
    if isinstance(st, ast.If):
        body = _block_outcomes(st.body)
        orelse = _block_outcomes(st.orelse) if st.orelse else {_FALL}
        return body | orelse
    if isinstance(st, (ast.With, ast.AsyncWith)):
        return _block_outcomes(st.body)
    if isinstance(st, ast.Try):
        return _try_outcomes(st)
    return {_FALL}


def _try_outcomes(st: ast.Try) -> set[str]:
    """Control-flow outcomes of a ``try`` (conservative). A ``finally`` runs on
    every path: if it never falls through (always raises and/or exits) it
    DOMINATES. Otherwise the outcome is the body (then ``else`` on the no-raise
    path) folded with every handler's outcomes — a body that can ``raise`` keeps
    ``_RAISE`` (an uncaught / re-raised exception) so the only way a ``try``
    guarantees a raise is the clean case body=={_RAISE} AND every handler
    =={_RAISE} with no escaping ``finally`` (matches the prior pin's two
    accepted shapes, now expressed in the outcome model)."""
    fin = _block_outcomes(st.finalbody) if st.finalbody else {_FALL}
    if _FALL not in fin:
        return fin  # finally always raises/exits → dominates the try
    body = _block_outcomes(st.body)
    if st.orelse and _FALL in body:
        # the else-block runs when the body completes normally (no exception)
        body = (body - {_FALL}) | _block_outcomes(st.orelse)
    out: set[str] = set(body)
    for h in st.handlers:
        out |= _block_outcomes(h.body)  # a handler runs when the body raises
    out |= (fin - {_FALL})  # finally still runs; fold its non-fall outcomes
    return out


def _stmts_guarantee_raise(stmts: list[ast.stmt]) -> bool:
    """True if executing ``stmts`` is GUARANTEED to raise (run18 #2) — i.e. its
    only control-flow outcome is :data:`_RAISE`, with NO non-raising path
    (``return``/``break``/``continue`` exit, or fall-through). Thin wrapper over
    :func:`_block_outcomes`; SHOULD-FIX 3 replaced a first-``raise``-wins scan
    that read ``if benign: return`` ... ``raise`` as a guaranteed re-raise."""
    return _block_outcomes(stmts) == {_RAISE}


def _handler_reraises(handler: ast.ExceptHandler) -> bool:
    """True if the handler is GUARANTEED to re-raise (so the emit failure
    propagates, NOT swallowed). Guaranteed-only — a conditional ``if c: raise``
    is NOT a guaranteed re-raise (run18 #2)."""
    return _stmts_guarantee_raise(handler.body)


def _unsafe_emit_lines_in(node: ast.AST, aliases: set[str], seam: set[str]):
    """Yield linenos of emit calls under ``node`` that are NOT lexically inside a
    ``safe_audit_write``/``safe_audit_write_async`` wrapper call. An emit wrapped
    in the SSOT is already routed — even when that wrapper call itself sits inside
    a broad job-level ``try`` (the FP that flagged the 3 sites I'd already fixed)."""
    def _descend(n: ast.AST, under_safe: bool):
        if isinstance(n, ast.Call):
            f = n.func
            fname = (f.id if isinstance(f, ast.Name)
                     else f.attr if isinstance(f, ast.Attribute) else None)
            now_safe = under_safe or fname in _SAFE_WRAPPERS
            if not now_safe and _is_emit(n, aliases, seam):
                yield n.lineno
            for c in ast.iter_child_nodes(n):
                yield from _descend(c, now_safe)
            return
        for c in ast.iter_child_nodes(n):
            yield from _descend(c, under_safe)
    yield from _descend(node, False)


def _swallowing_emit_lines(
    tree: ast.AST, aliases: set[str], seam: set[str] | None = None,
) -> list[tuple[int, str]]:
    """(lineno, enclosing_fn) for every UNROUTED emit inside a Try.body whose
    handler set catches-all AND not every catch-all handler is GUARANTEED to
    re-raise (→ swallowed). An emit already wrapped in the safe_audit_write SSOT
    is routed. ``seam`` defaults to the base ``_SEAM`` (teeth call with literal
    ``db_call``); ``_find_violations`` passes the per-file alias-expanded set."""
    if seam is None:
        seam = set(_SEAM)
    out: list[tuple[int, str]] = []

    def _enclosing_fn(stack: list[ast.AST]) -> str:
        for nd in reversed(stack):
            if isinstance(nd, (ast.FunctionDef, ast.AsyncFunctionDef)):
                return nd.name
        return "__module__"

    def _walk_try_bodies(node: ast.AST, fn_stack: list[ast.AST]) -> None:
        if isinstance(node, ast.Try):
            catchers = [h for h in node.handlers if _handler_catches_all(h)]
            fn = fn_stack[-1] if fn_stack else None
            swallowed = bool(catchers) and not all(
                _handler_reraises(h)
                or (fn is not None and is_emergency_sanctioned_handler(fn, h))
                for h in catchers)
            if swallowed:
                for stmt in node.body:  # only the TRY body (not the handlers)
                    for lineno in _unsafe_emit_lines_in(stmt, aliases, seam):
                        out.append((lineno, _enclosing_fn(fn_stack)))
        # recurse, tracking the enclosing-fn stack
        for child in ast.iter_child_nodes(node):
            push = isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
            if push:
                fn_stack.append(child)
            _walk_try_bodies(child, fn_stack)
            if push:
                fn_stack.pop()

    _walk_try_bodies(tree, [])
    return out


def _iter_swallow_sites():
    """Yield (rel, lineno, fn) for every UNROUTED, catch-all-swallowed emit
    across src — the RAW enumeration, BEFORE the ``_ALLOW`` disposition filter."""
    for fpath in iter_src_files():
        rel = relpath(fpath)
        text = fpath.read_text(encoding="utf-8")
        if not any(e in text for e in _EMITTERS):
            continue
        tree = parse_source(text, filename=str(fpath))
        aliases = _aliases(tree)
        seam = _seam_aliases(tree)
        for lineno, fn in _swallowing_emit_lines(tree, aliases, seam):
            yield rel, lineno, fn


def _find_violations() -> list[str]:
    return [
        f"{rel}:{lineno} ({fn})"
        for rel, lineno, fn in _iter_swallow_sites()
        if f"{rel}:{fn}" not in _ALLOW
    ]


def test_no_swallowed_audit_emit_outside_safe_audit_write():
    offenders = _find_violations()
    assert offenders == [], (
        "An @audit_emitter emit is SWALLOWED in a hand-rolled try/except "
        f"(invisible to /health's drift counter): {offenders}. Route it through "
        "web._audit.safe_audit_write (sync) / safe_audit_write_async (await-seam), "
        "OR add a _ALLOW entry with the STRUCTURAL reason it is already observable "
        "(NOT just 'gap-ledger-backstopped')."
    )


def test_emitter_net_is_the_audit_emitter_family():
    """The net is the structurally-derived ``@audit_emitter`` family, not a
    hardcoded list (PD#1/#2) — and it still covers N-135's original 3 (no
    regression) and is not vacuous (the walker didn't silently yield 0)."""
    assert _EMITTERS == audit_emitter_names()
    assert {
        "record_hipaa_access_event", "record_access_event", "record_auth_event",
    } <= _EMITTERS
    assert len(_EMITTERS) >= 9, (
        f"only {len(_EMITTERS)} @audit_emitter helpers in the net — expected "
        ">=9; the shared walker may have stopped discovering them (vacuous-pass "
        "guard)."
    )


def test_audit_emitter_modules_is_structurally_complete():
    """MUST-FIX 2 (PD#1/#7) — the emitter walker reads only the hardcoded
    ``AUDIT_EMITTER_MODULES`` fast-path tuple. This is its DRIFT-GUARD: a full-src
    walk for the ``@audit_emitter`` decorator must yield EXACTLY that tuple. A
    future ``@audit_emitter`` in a 3rd module fails HERE (it would otherwise
    silently escape BOTH this swallow pin AND the N-36 redaction pin — N-135's
    hardcoded-NAME-list trap lifted to the MODULE grain). Structural (AST
    decorator) detection, NOT a text grep: 4 src files only MENTION
    ``@audit_emitter`` (its definition / comments / the runtime ``_is_audit_
    emitter`` checks) without applying it — a grep would false-positive on them."""
    discovered = set(discover_audit_emitter_modules())
    assert discovered == set(AUDIT_EMITTER_MODULES), (
        "@audit_emitter MODULE set drifted from the AUDIT_EMITTER_MODULES "
        f"fast-path tuple: full-src walk found {sorted(discovered)} vs hardcoded "
        f"{sorted(AUDIT_EMITTER_MODULES)}. Add the new emitter module to "
        "AUDIT_EMITTER_MODULES in tests/_pin_harness.py (and review its "
        "redaction-map entry + swallow routing) — else the redaction + "
        "audit-emit-swallow pins go blind to it."
    )
    # Non-vacuous floor: the walk actually found the known emitter homes (so a
    # silently-broken walker yielding ``{}`` can't pass against an empty tuple).
    assert {"db/audit.py", "db/style.py"} <= discovered, (
        f"vacuous-walk guard: discover_audit_emitter_modules() found "
        f"{sorted(discovered)} — expected at least the two known emitter homes."
    )


def test_allow_list_is_not_stale():
    """R38 / PD#7 — every ``_ALLOW`` key must still match a live swallow site on
    HEAD; a stale entry (the finalise was routed/removed/renamed) is flagged so
    the allow-list can't silently grant a future namesake a pass."""
    live = {f"{rel}:{fn}" for rel, _, fn in _iter_swallow_sites()}
    stale = set(_ALLOW) - live
    assert not stale, (
        "Stale _ALLOW entries (no longer a swallowed-emit site on HEAD): "
        f"{sorted(stale)}. Remove them — a stale entry would silently exempt a "
        "future same-named function."
    )


def test_pin_has_teeth():
    # bare except: pass swallow → flagged
    bad = ast.parse(
        "def h(db, u, a):\n"
        "    try:\n"
        "        record_hipaa_access_event(db, u, a, 'op', outcome='ok')\n"
        "    except Exception:\n"
        "        pass\n"
    )
    assert _swallowing_emit_lines(bad, {"record_hipaa_access_event"}) == [(3, "h")]
    # db_call SEAM swallow → flagged
    seam = ast.parse(
        "async def h(db, u, a):\n"
        "    try:\n"
        "        await db_call(record_hipaa_access_event, db, u, a, 'op', 'ok')\n"
        "    except Exception as e:\n"
        "        log.warning('x', error=e)\n"
    )
    assert _swallowing_emit_lines(seam, {"record_hipaa_access_event"}) == [(3, "h")]
    # ALIASED seam (db_call as _db_call) swallow → still flagged when the
    # per-file seam alias set is supplied (the N-135 access_audit miss).
    aliased_seam = ast.parse(
        "from email_triage.web.db_threadpool import db_call as _db_call\n"
        "async def h(db, u, a):\n"
        "    try:\n"
        "        await _db_call(record_hipaa_access_event, db, u, a, 'op')\n"
        "    except Exception:\n"
        "        pass\n"
    )
    _alias_seam = _seam_aliases(aliased_seam)
    assert "_db_call" in _alias_seam
    assert _swallowing_emit_lines(
        aliased_seam, {"record_hipaa_access_event"}, _alias_seam,
    ) == [(4, "h")]
    # WITHOUT the alias set the bare _SEAM default does NOT see _db_call (proves
    # the alias tracking is what catches it, not an accident).
    assert _swallowing_emit_lines(
        aliased_seam, {"record_hipaa_access_event"},
    ) == []
    # routed through safe_audit_write (no enclosing try) → NOT flagged
    ok = ast.parse(
        "def h(db, u, a):\n"
        "    safe_audit_write(lambda: record_hipaa_access_event(db, u, a, 'op'), description='x')\n"
    )
    assert _swallowing_emit_lines(ok, {"record_hipaa_access_event"}) == []
    # safe_audit_write wrapper INSIDE a broad job-level swallowing try → routed,
    # NOT flagged (the FP that caught the 3 sites I'd already fixed)
    wrapped_in_try = ast.parse(
        "async def job(db, u, a):\n"
        "    try:\n"
        "        do_work()\n"
        "        await safe_audit_write_async(lambda: db_call(record_hipaa_access_event, db, u, a, 'op'), description='x')\n"
        "    except Exception:\n"
        "        log.error('job failed')\n"
    )
    assert _swallowing_emit_lines(wrapped_in_try, {"record_hipaa_access_event"}) == []
    # NARROW except (can't catch the emit failure) → NOT a swallow (DA guard)
    narrow = ast.parse(
        "def h(db, u, a):\n"
        "    try:\n"
        "        record_hipaa_access_event(db, u, a, 'op')\n"
        "    except ValueError:\n"
        "        pass\n"
    )
    assert _swallowing_emit_lines(narrow, {"record_hipaa_access_event"}) == []
    # handler GUARANTEED-re-raises (bare raise) → not swallowed → NOT flagged
    reraise = ast.parse(
        "def h(db, u, a):\n"
        "    try:\n"
        "        record_hipaa_access_event(db, u, a, 'op')\n"
        "    except Exception:\n"
        "        raise\n"
    )
    assert _swallowing_emit_lines(reraise, {"record_hipaa_access_event"}) == []
    # N-366 R31 (Census run22 §2 fifth teeth for bounded-gap (a)): NARROW
    # `except sqlite3.OperationalError: pass` directly wrapping an emit
    # IS a swallow — the SQL-shape exception CAN catch the emit failure.
    # 0 sites today; prevents regression.
    sql_narrow = ast.parse(
        "import sqlite3\n"
        "def h(db, u, a):\n"
        "    try:\n"
        "        record_hipaa_access_event(db, u, a, 'op')\n"
        "    except sqlite3.OperationalError:\n"
        "        pass\n"
    )
    assert _swallowing_emit_lines(sql_narrow, {"record_hipaa_access_event"}) == [(4, "h")]
    # Bare-name via `from sqlite3 import OperationalError`.
    sql_bare_narrow = ast.parse(
        "from sqlite3 import OperationalError\n"
        "def h(db, u, a):\n"
        "    try:\n"
        "        record_hipaa_access_event(db, u, a, 'op')\n"
        "    except OperationalError:\n"
        "        pass\n"
    )
    assert _swallowing_emit_lines(sql_bare_narrow, {"record_hipaa_access_event"}) == [(4, "h")]
    # DA guard preserved: NON-SQL narrow except (can't catch the emit
    # failure) → NOT flagged.
    non_sql_narrow = ast.parse(
        "def h(db, u, a):\n"
        "    try:\n"
        "        record_hipaa_access_event(db, u, a, 'op')\n"
        "    except KeyError:\n"
        "        pass\n"
    )
    assert _swallowing_emit_lines(non_sql_narrow, {"record_hipaa_access_event"}) == []


def test_conditional_raise_is_not_a_guaranteed_reraise():
    """run18 #2 — an ``if cond: raise`` handler is a SWALLOW on the common
    (cond-false) path, NOT a re-raise. The N-135 net read access_audit's
    ``if STRICT: raise`` as a re-raise and let the swallow through; the
    guaranteed-only rule flags it."""
    conditional = ast.parse(
        "def h(db, u, a):\n"
        "    try:\n"
        "        record_hipaa_access_event(db, u, a, 'op')\n"
        "    except Exception:\n"
        "        bump()\n"
        "        if STRICT:\n"
        "            raise\n"
    )
    assert _swallowing_emit_lines(conditional, {"record_hipaa_access_event"}) == [(3, "h")]
    # SHOULD-FIX 3 — an early NON-raising exit (``return``/``break``/``continue``)
    # before a trailing ``raise`` is a SWALLOW on that exit path, NOT a guaranteed
    # re-raise. A first-``raise``-wins scan saw the trailing ``raise`` and wrongly
    # passed it; the 3-outcome model flags it (the ``benign`` path returns).
    early_return = ast.parse(
        "def h(db, u, a):\n"
        "    try:\n"
        "        record_hipaa_access_event(db, u, a, 'op')\n"
        "    except Exception:\n"
        "        if benign:\n"
        "            return\n"
        "        raise\n"
    )
    assert _swallowing_emit_lines(early_return, {"record_hipaa_access_event"}) == [(3, "h")]
    # …but a bare unconditional raise AFTER side effects still passes (the
    # access_audit strict branch shape post-convergence).
    guaranteed = ast.parse(
        "def h(db, u, a):\n"
        "    try:\n"
        "        record_hipaa_access_event(db, u, a, 'op')\n"
        "    except Exception:\n"
        "        bump()\n"
        "        raise\n"
    )
    assert _swallowing_emit_lines(guaranteed, {"record_hipaa_access_event"}) == []
    # a raise inside a nested def in the handler is NOT this handler's re-raise
    nested = ast.parse(
        "def h(db, u, a):\n"
        "    try:\n"
        "        record_hipaa_access_event(db, u, a, 'op')\n"
        "    except Exception:\n"
        "        def _later():\n"
        "            raise\n"
    )
    assert _swallowing_emit_lines(nested, {"record_hipaa_access_event"}) == [(3, "h")]


# ---------------------------------------------------------------------------
# N-182 companion drift-guard (DA must-fix + hipaa-sme M4) — a new chain
# writer discovered structurally BUT not in the declared chain_writer_names()
# hardcoded set is a swallow-pin blind spot. Fail LOUDLY (matching the
# discover_audit_emitter_modules pattern for AUDIT_EMITTER_MODULES).
# ---------------------------------------------------------------------------

# Chain-primitive helpers whose bodies touch the HMAC chain but are READERS or
# adapters, not row writers — legitimately excluded from chain_writer_names.
# Each entry needs a reason.
_CHAIN_WRITER_ALLOW: frozenset[str] = frozenset({
    "verify_log_chain",           # READER: verifies HMAC chain, no INSERT
    "emit",                       # SQLiteLogHandler.emit (hot path). N-182b,
                                  # allow-list step 2 B2: both failure arms
                                  # bump the /health audit-failure counter via
                                  # triage_logging._bump_chain_write_failure
                                  # (not safe_audit_write: its WARNING would
                                  # re-enter the handler). Not declared in
                                  # chain_writer_names(): the bare name collides
                                  # with logging.Handler.emit and would make any
                                  # x.emit(...) a witness to the name-keyed n543
                                  # net (s2 panel MUST-B1). Enforced by
                                  # tests/test_n182b_chain_write_failure_counter.py.
})


def test_chain_writer_names_matches_discovery():
    """N-182 drift-guard (DA must-fix + hipaa-sme M4): the hardcoded
    chain_writer_names() set MUST equal `discover_chain_writers() -
    _CHAIN_WRITER_ALLOW`. A new function calling the HMAC-chain helpers
    (get_last_log_row_hash / compute_log_row_hash) fails this test rather
    than silently escaping the swallow pin's net."""
    discovered = discover_chain_writers()
    expected = discovered - _CHAIN_WRITER_ALLOW
    declared = chain_writer_names()
    unseen_by_declared = expected - declared
    assert not unseen_by_declared, (
        f"N-182 drift: {sorted(unseen_by_declared)} are new chain-writers "
        "discovered structurally but not declared in "
        "`tests/_pin_harness.py::chain_writer_names()`. Either add them to "
        "the declared set (they belong in the swallow-pin net) or add them "
        "to `_CHAIN_WRITER_ALLOW` with a stated reason (they're readers / "
        "already-routed / N-182b follow-ups)."
    )
    stale_declared = declared - discovered - {"_chain_insert"}
    # `_chain_insert` is the SSOT primitive itself, not a helper that CALLS
    # get_last_log_row_hash — it's structurally distinct from the discovery
    # heuristic. Grandfather it so a rename of _chain_insert stays loud.
    assert not stale_declared, (
        f"N-182 drift: {sorted(stale_declared)} are declared chain-writers "
        "that discover_chain_writers() no longer finds — a rename/deletion "
        "left a stale entry in chain_writer_names()."
    )


def test_the_emergency_revoke_handler_is_sanctioned_only_with_its_guard():
    """Punch 709 / cycle P db-sme P2 item 2: the emergency handler is exempt by the
    shared structural predicate, not by function name. Without the guard, or without
    the funnel call, the same handler is a swallow again; set_user_disabled is live
    in the raw scan only as a sanctioned site, never through ``_ALLOW``."""
    good = (
        "def set_user_disabled(conn, *, emergency_reason=None):\n"
        "    failure = None\n"
        "    try:\n"
        "        _chain_insert(conn, 'user_status_events', {})\n"
        "    except Exception as exc:\n"
        "        if emergency_reason is None:\n"
        "            raise\n"
        "        failure = exc\n"
        "    if failure is not None:\n"
        "        record_emergency_revoke(conn, kind='user')\n"
    )

    def sites(src):
        return _swallowing_emit_lines(parse_source(src), {"_chain_insert"})

    assert sites(good) == []
    for bad in (
        good.replace("        if emergency_reason is None:\n            raise\n", ""),
        good.replace("        record_emergency_revoke(conn, kind='user')\n", "        pass\n"),
        good.replace("            raise\n", "            return None\n"),
        good.replace("emergency_reason is None", "emergency_reason is not None"),
    ):
        assert bad != good
        assert sites(bad) == [(4, "set_user_disabled")], bad
    assert not any(k.endswith(":set_user_disabled") for k in _ALLOW)
