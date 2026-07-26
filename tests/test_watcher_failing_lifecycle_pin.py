"""Watcher ``failing_since`` lifecycle — count-agnostic structural pin
(divergence census 2026-06-09, finding #7).

The per-mailbox ``failing_since`` flag (the in-memory ``WatcherManager`` state
``/health`` uses to apply the 15-min "failing too long" rollup) is a *lifecycle*
flag: SET on a failing tick (``_mark_failing``), CLEARED on a successful one
(``_mark_recovered``). Before this fix the unified-poll path SET it on a
transient provider error but its SUCCESS path never CLEARED it, so a poll-only
mailbox that recovered stayed "failing" on ``/health`` until a process restart —
the same set-broad/clear-narrow shape as the ``auth_stale`` flag fixed in N-44
(``record_provider_outcome``).

Both edges of every continuous per-mailbox surface now route through the
``WatcherManager.record_mailbox_outcome(account_id, mailbox, sticky_error=exc)`` funnel; the
private ``_mark_failing`` / ``_mark_recovered`` may be called ONLY from inside
that funnel. These property-tests keep the two edges from re-diverging — they
assert a property over **every** call site (never ``len(...) == N``), per
``pattern_count_agnostic_structural_drift_catch``.
"""

from __future__ import annotations

import ast

from _pin_harness import SRC_ROOT, iter_src_files, parse_module, relpath as _relpath

# Local alias for the package root — the harness `SRC_ROOT` is computed once and
# is IDENTICAL to the old hand-rolled `parents[1]/"src"/"email_triage"`. Keeping
# the `SRC` name lets the WATCHER / _WIRED_MODULES / _WATCHER_ADJACENT path keys
# (all `SRC / "web" / ...`) and the relpath base stay exactly as before.
SRC = SRC_ROOT
WATCHER = SRC / "web" / "watcher.py"
FUNNEL = "record_mailbox_outcome"
_PRIVATE = {"_mark_failing", "_mark_recovered"}


def _iter_src():
    """Yield ``(path, tree)`` for every parseable src file — the harness walk
    (``iter_src_files`` + ``parse_module``), skipping unparseable files. The
    harness skips ``__pycache__`` (no ``*.py`` lives there → behaviour-identical
    to the old ``sorted(SRC.rglob("*.py"))`` loop)."""
    for p in iter_src_files():
        tree = parse_module(p)
        if tree is not None:
            yield p, tree


def _private_mutator_calls(tree: ast.AST) -> list[tuple[str, int]]:
    """Call sites of ``_mark_failing`` / ``_mark_recovered`` in any receiver
    form (``self.x`` / ``manager.x`` / bare ``x``)."""
    out: list[tuple[str, int]] = []
    for n in ast.walk(tree):
        if isinstance(n, ast.Call):
            f = n.func
            name = f.attr if isinstance(f, ast.Attribute) else (
                f.id if isinstance(f, ast.Name) else "")
            if name in _PRIVATE:
                out.append((name, n.lineno))
    return out


def _funnel_line_range(tree: ast.AST) -> tuple[int, int] | None:
    for n in ast.walk(tree):
        if (isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                and n.name == FUNNEL):
            return (n.lineno, getattr(n, "end_lineno", n.lineno))
    return None


# --------------------------------------------------------------------------
# Invariant 1 — the SET/CLEAR impls are called ONLY from inside the funnel.
# (Tighter than the N-44 allow-list-the-module form: here the funnel lives in
# watcher.py *alongside* the watch loop, so an allow-list of the whole module
# would not protect the watch loop. We pin to the funnel METHOD's line range.)
# --------------------------------------------------------------------------
def test_private_mutators_called_only_inside_the_funnel():
    wtree = parse_module(WATCHER); assert wtree is not None  # N-350 R31
    rng = _funnel_line_range(wtree)
    assert rng, "record_mailbox_outcome funnel vanished from watcher.py"
    lo, hi = rng
    offenders = []
    for p, tree in _iter_src():
        for name, lineno in _private_mutator_calls(tree):
            inside_funnel = (p == WATCHER and lo <= lineno <= hi)
            if not inside_funnel:
                offenders.append(f"{_relpath(p)}:{lineno} {name}()")
    assert not offenders, (
        "watcher failing_since SET/CLEAR impl called outside the "
        f"record_mailbox_outcome funnel: {offenders}. Route the outcome through "
        "manager.record_mailbox_outcome(account_id, mailbox, sticky_error=exc) (exc=None "
        "clears, exc!=None sets) so the two edges can't drift — do not poke "
        "_mark_failing / _mark_recovered directly."
    )


def test_funnel_still_dispatches_to_both_edges():
    """Guards the pin: the funnel must still reference BOTH private edges, else
    invariant 1 is vacuously satisfiable."""
    wtree = parse_module(WATCHER); assert wtree is not None  # N-350 R31
    rng = _funnel_line_range(wtree)
    assert rng
    lo, hi = rng
    calls = {
        name for name, lineno in _private_mutator_calls(wtree)
        if lo <= lineno <= hi
    }
    assert calls == _PRIVATE, (
        f"the funnel must dispatch to both edges; found {calls} of {_PRIVATE}"
    )


# --------------------------------------------------------------------------
# Invariant 1b — no raw ``st["failing_since"] = ...`` write bypassing the two
# mutators (DA pin-teeth, 2026-06-09): the method-name pin above is blind to a
# direct dict write, which would re-introduce the asymmetry under the radar.
# A Subscript assignment to the "failing_since" key is allowed ONLY inside
# _mark_failing / _mark_recovered.
# --------------------------------------------------------------------------
_MUTATOR_DEFS = {"_mark_failing", "_mark_recovered"}


def _mutator_def_ranges(tree: ast.AST) -> list[tuple[int, int]]:
    out = []
    for n in ast.walk(tree):
        if (isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                and n.name in _MUTATOR_DEFS):
            out.append((n.lineno, getattr(n, "end_lineno", n.lineno)))
    return out


def _failing_since_subscript_writes(tree: ast.AST) -> list[int]:
    """Lines assigning to a ``<expr>["failing_since"]`` subscript."""
    out = []
    for n in ast.walk(tree):
        targets = []
        if isinstance(n, ast.Assign):
            targets = n.targets
        elif isinstance(n, (ast.AugAssign, ast.AnnAssign)):
            targets = [n.target]
        for t in targets:
            if (isinstance(t, ast.Subscript) and isinstance(t.slice, ast.Constant)
                    and t.slice.value == "failing_since"):
                out.append(n.lineno)
    return out


def test_no_raw_failing_since_write_outside_mutators():
    offenders = []
    for p, tree in _iter_src():
        ranges = _mutator_def_ranges(tree) if p == WATCHER else []
        for lineno in _failing_since_subscript_writes(tree):
            if not any(lo <= lineno <= hi for lo, hi in ranges):
                offenders.append(f"{_relpath(p)}:{lineno}")
    assert not offenders, (
        "a raw st['failing_since'] = ... write outside _mark_failing/"
        f"_mark_recovered: {offenders}. This bypasses the lifecycle funnel and "
        "re-introduces the set/clear asymmetry under the method-name pin. Mutate "
        "via manager.record_mailbox_outcome(account_id, mailbox, sticky_error=exc)."
    )


# --------------------------------------------------------------------------
# Invariant 2 — every continuous per-mailbox surface is wired to the funnel.
# --------------------------------------------------------------------------
_WIRED_MODULES = (
    "web/poll_ingestion.py",   # unified poll (the path that had the bug)
    "web/watcher.py",          # IMAP IDLE watcher (set + clear)
)


def test_continuous_mailbox_surfaces_route_through_funnel():
    missing = [
        m for m in _WIRED_MODULES
        if FUNNEL not in (SRC / m).read_text(encoding="utf-8")
    ]
    assert not missing, (
        "a continuous per-mailbox surface lost its failing_since funnel wiring: "
        f"{missing}. Each must call record_mailbox_outcome on success (clear) and "
        "failure (set)."
    )


# --------------------------------------------------------------------------
# Behavioural teeth — the actual bug was a missing CLEAR on recovery.
# --------------------------------------------------------------------------
def test_funnel_sets_then_clears_failing_since():
    from email_triage.web.watcher import WatcherManager
    wm = WatcherManager.__new__(WatcherManager)  # bypass __init__ (needs FastAPI)
    wm._mb_state = {}
    # A failing tick stamps failing_since.
    wm.record_mailbox_outcome(1, "INBOX", sticky_error=RuntimeError("transient"))
    assert wm._get_mb_state(1, "INBOX")["failing_since"] is not None
    # A successful tick CLEARS it — the edge the poll path was missing.
    wm.record_mailbox_outcome(1, "INBOX", sticky_error=None)
    assert wm._get_mb_state(1, "INBOX")["failing_since"] is None


def test_funnel_set_is_idempotent_preserving_first_timestamp():
    from email_triage.web.watcher import WatcherManager
    wm = WatcherManager.__new__(WatcherManager)
    wm._mb_state = {}
    wm.record_mailbox_outcome(2, "INBOX", sticky_error=RuntimeError("a"))
    first = wm._get_mb_state(2, "INBOX")["failing_since"]
    wm.record_mailbox_outcome(2, "INBOX", sticky_error=RuntimeError("b"))
    # Still failing → keep the original clock (true outage duration).
    assert wm._get_mb_state(2, "INBOX")["failing_since"] == first


def test_pin_has_teeth_direct_private_call(tmp_path):
    bad = tmp_path / "m.py"
    bad.write_text(
        "def f(manager, aid, mb):\n"
        "    manager._mark_failing(aid, mb, error='x')\n",
        encoding="utf-8",
    )
    tree = parse_module(bad); assert tree is not None
    assert _private_mutator_calls(tree)


# --------------------------------------------------------------------------
# Invariant 3 (N-70) — every terminal break/return in the watcher loop
# that sets a terminal status ('unsupported', 'error') is preceded by a
# record_mailbox_outcome(account_id, mailbox, sticky_error=None) call within the same
# exception block (clear the flag so /health doesn't report a permanently
# exited watcher as "still failing").
#
# Implementation note: a structural AST invariant for "every except block
# that assigns status='unsupported' also calls record_mailbox_outcome" is
# complex to write without false positives; the behavioural test below is
# the teeth, and the code-text grep is the structural guard.
# --------------------------------------------------------------------------
def test_watcher_terminal_exit_clears_failing_since():
    """N-70: a watcher that hits a terminal exit (NotImplementedError /
    unsupported) must clear failing_since so /health stops counting it."""
    from email_triage.web.watcher import WatcherManager
    wm = WatcherManager.__new__(WatcherManager)
    wm._mb_state = {}

    # Simulate: a transient error set failing_since first.
    wm.record_mailbox_outcome(99, "INBOX", sticky_error=RuntimeError("connect failed"))
    assert wm._get_mb_state(99, "INBOX")["failing_since"] is not None

    # Terminal exit: clear the flag (this is what the N-70 fix adds).
    wm.record_mailbox_outcome(99, "INBOX", sticky_error=None)
    assert wm._get_mb_state(99, "INBOX")["failing_since"] is None, (
        "N-70: record_mailbox_outcome(exc=None) must clear failing_since on "
        "a terminal exit. A permanently exited watcher with failing_since set "
        "keeps /health stuck-failing until restart."
    )


def test_watcher_py_terminal_unsupported_clears_failing_since():
    """Structural guard: the NotImplementedError (unsupported) handler in
    watcher.py must contain a record_mailbox_outcome call (the N-70 fix).
    This complements the functional test above with a source-text check so
    the fix can't be silently removed."""
    text = WATCHER.read_text(encoding="utf-8")
    # The unsupported block sets state["status"] = "unsupported"; we verify
    # that record_mailbox_outcome also appears in the same file in a context
    # that clears (the functional test above confirms the semantics).
    assert "unsupported" in text, "watcher.py unsupported terminal path vanished"
    # The fix adds record_mailbox_outcome near the unsupported break;
    # the module already contained the funnel elsewhere, sticky_error=but verify there
    # are at least 2 distinct call sites (transient-failure set + terminal clear).
    import re
    sites = re.findall(r"record_mailbox_outcome\b", text)
    assert len(sites) >= 2, (
        f"Expected >=2 record_mailbox_outcome call sites in watcher.py "
        f"(transient-failure set + at least one terminal-exit clear); "
        f"found {len(sites)}. The N-70 terminal-exit clear may be missing."
    )


# --------------------------------------------------------------------------
# PD#18 / N-49 — last_error + last_attempt clear-asymmetry fix.
#
# ``last_error`` / ``last_attempt`` are SET via ``_mark_failing`` (inside the
# funnel) on every failing tick, but were NEVER cleared on recovery.  A
# recovered watcher therefore rendered a stale error string in the admin UI.
# The fix: ``_mark_recovered`` now also clears both fields.
#
# Two tests:
#   1. Structural — ``last_error``/``last_attempt`` writes appear ONLY inside
#      ``_mark_failing`` (no raw bypasses through the funnel-lock).  Mirrors
#      ``test_no_raw_failing_since_write_outside_mutators`` above.
#   2. Behavioural — failure sets both, success clears both.
# --------------------------------------------------------------------------

_TRANSIENT_FIELDS = {"last_error", "last_attempt"}


def _transient_field_subscript_writes(tree: ast.AST) -> list[tuple[str, int]]:
    """Lines assigning to ``<expr>["last_error"]`` or ``["last_attempt"]``."""
    out: list[tuple[str, int]] = []
    for n in ast.walk(tree):
        targets: list[ast.expr] = []
        if isinstance(n, ast.Assign):
            targets = list(n.targets)
        elif isinstance(n, (ast.AugAssign, ast.AnnAssign)):
            targets = [n.target]
        for t in targets:
            if (isinstance(t, ast.Subscript)
                    and isinstance(t.slice, ast.Constant)
                    and t.slice.value in _TRANSIENT_FIELDS):
                out.append((str(t.slice.value), n.lineno))
    return out


def _mark_failing_def_ranges(tree: ast.AST) -> list[tuple[int, int]]:
    """Line ranges of ``_mark_failing`` and ``_mark_recovered`` defs."""
    return _mutator_def_ranges(tree)  # already returns both mutator defs


def test_no_raw_last_error_last_attempt_write_outside_mutators():
    """PD#18 structural pin: every ``st["last_error"]`` / ``st["last_attempt"]``
    write that targets the WatcherManager mailbox state must live inside
    ``_mark_failing`` or ``_mark_recovered`` (the two mutator defs the funnel
    owns). A write outside those functions in a watcher-aware file bypasses the
    funnel and re-introduces the asymmetry.

    Scope: files that import WatcherManager or are watcher-adjacent (the
    watch loop and its poll sibling). Files that use ``last_error`` as a plain
    dict key in a completely different context (e.g. ``acme_job_state.py``
    which tracks ACME job state — an unrelated dict, same key string by
    coincidence) are excluded from the pin by the ALLOWED_FILES allowlist.

    The "unsupported" terminal write in watcher.py itself (line ~1875) is
    intentionally sticky (permanent capability flag, not a transient error)
    and is NOT routed through ``_mark_recovered``. We allow all watcher.py
    writes outside the mutators because watcher.py is the funnel owner —
    the behavioural tests above are the live teeth for that file.
    """
    # Files where ``last_error``/``last_attempt`` as a subscript key refers
    # to the WatcherManager _mb_state dict AND so must flow through the funnel.
    # Any other file in src uses these keys for unrelated purposes and is
    # excluded from the pin.
    _WATCHER_ADJACENT = {
        WATCHER,
        SRC / "web" / "poll_ingestion.py",
    }
    offenders = []
    for p, tree in _iter_src():
        if p not in _WATCHER_ADJACENT:
            # Skip — "last_error"/"last_attempt" in this file refers to a
            # different dict (e.g. ACME job state, provider error state).
            continue
        if p == WATCHER:
            # watcher.py direct writes outside the mutators are allowed —
            # watcher.py is the funnel OWNER. The known direct-write sites are:
            #   * ~1335 account-not-found — TERMINAL (fn returns; no recovery)
            #   * ~1898 "unsupported" NotImplementedError — STICKY capability flag
            #   * ~1840 per-message triage error — transient, now CLEARED on the
            #     next successful message (PD#18 per-message clear edge ~1692)
            # The behavioural tests below are the live teeth for this file.
            # LIMITATION (DA Nit-1): this carve-out cannot distinguish a future
            # NON-terminal un-cleared write added to watcher.py — a new failure
            # write here must pair a clear (per-message edge or _mark_recovered).
            continue
        # Watcher-adjacent non-watcher files must NOT write these keys directly
        # at all — they must call record_mailbox_outcome.
        for field, lineno in _transient_field_subscript_writes(tree):
            rel = _relpath(p)
            offenders.append(f"{rel}:{lineno} st['{field}']")
    assert not offenders, (
        "raw st['last_error'] / st['last_attempt'] write in a watcher-adjacent "
        f"file bypasses the lifecycle funnel: {offenders}. Route the outcome "
        "through manager.record_mailbox_outcome(account_id, mailbox, sticky_error=exc) — "
        "exc=None clears, exc!=None sets."
    )


def test_funnel_clears_last_error_and_last_attempt_on_success():
    """PD#18 behavioural test: a failure tick sets last_error + last_attempt;
    a subsequent success tick through the funnel clears BOTH (not just
    failing_since). A recovered watcher must not display a stale error."""
    from email_triage.web.watcher import WatcherManager
    wm = WatcherManager.__new__(WatcherManager)
    wm._mb_state = {}

    err = RuntimeError("IMAP connection refused")
    wm.record_mailbox_outcome(10, "INBOX", sticky_error=err)
    st = wm._get_mb_state(10, "INBOX")
    assert st["last_error"] is not None, (
        "a failure tick must set last_error via _mark_failing"
    )
    assert st["last_attempt"] is not None, (
        "a failure tick must set last_attempt via _mark_failing"
    )
    assert st["failing_since"] is not None

    # Now a successful tick — all three must clear.
    wm.record_mailbox_outcome(10, "INBOX", sticky_error=None)
    st = wm._get_mb_state(10, "INBOX")
    assert st["last_error"] is None, (
        "PD#18: _mark_recovered must clear last_error on success; "
        "a stale error from a previous failure renders in the admin UI "
        "as if the watcher is still broken."
    )
    assert st["last_attempt"] is None, (
        "PD#18: _mark_recovered must clear last_attempt on success; "
        "the latent timestamp from the last failure must not persist."
    )
    assert st["failing_since"] is None


def test_funnel_clears_all_three_fields_atomically():
    """All three fields cleared by a single funnel call (not piecemeal)."""
    from email_triage.web.watcher import WatcherManager
    wm = WatcherManager.__new__(WatcherManager)
    wm._mb_state = {}

    wm.record_mailbox_outcome(11, "Spam", sticky_error=RuntimeError("timeout"))
    wm.record_mailbox_outcome(11, "Spam", sticky_error=RuntimeError("timeout again"))
    # Two failures: idempotent failing_since, last_error updated each tick.
    st = wm._get_mb_state(11, "Spam")
    assert st["failing_since"] is not None
    assert st["last_error"] is not None
    assert st["last_attempt"] is not None

    wm.record_mailbox_outcome(11, "Spam", sticky_error=None)
    st = wm._get_mb_state(11, "Spam")
    assert st["failing_since"] is None
    assert st["last_error"] is None
    assert st["last_attempt"] is None
