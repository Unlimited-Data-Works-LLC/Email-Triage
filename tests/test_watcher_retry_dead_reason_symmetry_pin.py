"""watcher_retry_queue ``dead_reason`` lifecycle — count-agnostic structural pin
(N-386, backlog 2026-07-10).

The ``watcher_retry_queue`` transitions rows to ``state='dead'`` with exactly one
of ``WATCHER_RETRY_DEAD_REASONS``. Before this pin, ``auth_revoked`` was
SET-broad / CLEAR-narrow (Prime Directive 18): the only way back to ``pending``
was ``enqueue_retry``'s dead-branch resurrection — which requires the SAME
(account_id, addressing-tuple) to fire ANOTHER watcher exception with a
resurrectable path, rare after a provider outage recovers. So a mid-outage
frozen row stayed dead forever while the account itself was healthy again.

The fix routes the CLEAR through the ``record_provider_outcome`` funnel via
``_resurrect_auth_revoked_retries`` (app.py) → ``resurrect_auth_revoked_retries``
(db.py). This pin locks in the symmetry:

  * **Invariant 1** — every value in ``WATCHER_RETRY_DEAD_REASONS`` is either
    listed in ``_TERMINAL_BY_DESIGN`` OR a ``resurrect_<reason>_retries``
    helper is exported from ``web/db.py``.
  * **Invariant 2** — the ``record_provider_outcome`` funnel (``web/app.py``)
    invokes ``_resurrect_auth_revoked_retries`` inside its ``exc is None``
    branch.
  * **Invariant 3** — ``WATCHER_RETRY_DEAD_REASONS`` and ``_TERMINAL_BY_DESIGN``
    together cover every distinct ``reason=`` literal passed to
    ``mark_retry_dead`` across the codebase (a new reason not registered in
    either set is caught).

Teeth-tests confirm each invariant catches a planted regression.
"""

from __future__ import annotations

import ast

from _pin_harness import SRC_ROOT, parse_module, relpath, walk_src  # N-350 R31

# ---- SSOT locations ------------------------------------------------------

_DB_MODULE = SRC_ROOT / "web" / "db.py"
_APP_MODULE = SRC_ROOT / "web" / "app.py"

# The valid dead_reasons, per the DB SSOT. Kept in sync with
# ``WATCHER_RETRY_DEAD_REASONS`` in ``web/db.py`` — Invariant 3 covers drift.
_ALL_DEAD_REASONS = frozenset({
    "max_attempts_exceeded",
    "uidvalidity_changed",
    "message_gone",
    "message_expunged",
    "auth_revoked",
    "operator_abandoned",
    "llm_unreachable_expired",
})

# Terminal by design — spec: no recovery path exists (or is desired) for a row
# with this reason. Reviewer rationale must accompany any additions here.
_TERMINAL_BY_DESIGN = frozenset({
    "max_attempts_exceeded",   # spec: retry ceiling per WATCHER_RETRY_SCHEDULE
    # punch 593: the llm_unreachable retry ceiling, as age (LLM_UNREACHABLE_MAX_AGE
    # = the schedule's span). Same terminal shape as max_attempts_exceeded.
    "llm_unreachable_expired",
    "uidvalidity_changed",     # spec: UID no longer valid, message unaddressable
    "message_gone",            # spec: message deleted at the provider
    "message_expunged",        # spec: message benignly expunged (verified)
    "operator_abandoned",      # spec: operator explicitly gave up on the row
})

# Reasons that MUST have a symmetric CLEAR path in the SSOT.
_RECOVERABLE = _ALL_DEAD_REASONS - _TERMINAL_BY_DESIGN


# --------------------------------------------------------------------------
# Invariant 1 — every recoverable dead_reason has a `resurrect_<reason>_retries`
# helper defined in web/db.py.
# --------------------------------------------------------------------------
def _defined_top_level_functions(tree: ast.AST) -> set[str]:
    return {
        n.name for n in tree.body
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
    }


def test_every_recoverable_reason_has_resurrect_helper():
    tree = parse_module(_DB_MODULE); assert tree is not None  # N-350 R31
    fns = _defined_top_level_functions(tree)
    missing = [
        r for r in sorted(_RECOVERABLE)
        if f"resurrect_{r}_retries" not in fns
    ]
    assert not missing, (
        f"recoverable dead_reason(s) missing a symmetric CLEAR helper in "
        f"web/db.py: {missing}. Add `resurrect_<reason>_retries(conn, "
        "account_id)` (mirror `resurrect_auth_revoked_retries` — the N-386 "
        "pattern) AND wire it into `record_provider_outcome` alongside "
        "`_resurrect_auth_revoked_retries`, OR move the reason into "
        "`_TERMINAL_BY_DESIGN` with a spec-level rationale."
    )


# --------------------------------------------------------------------------
# Invariant 2 — record_provider_outcome (web/app.py) invokes
# _resurrect_auth_revoked_retries in the exc=None branch.
# --------------------------------------------------------------------------
def _funnel_body(tree: ast.AST) -> ast.FunctionDef | None:
    for n in tree.body:
        if isinstance(n, ast.FunctionDef) and n.name == "record_provider_outcome":
            return n
    return None


def _exc_is_none_branch(fn: ast.FunctionDef) -> list[ast.stmt]:
    """Return the body statements that execute on ``exc is None`` (the CLEAR
    branch). Handles both ``if exc is None: ...`` and (defensively) an ``elif``
    inversion."""
    for n in ast.walk(fn):
        if not isinstance(n, ast.If):
            continue
        t = n.test
        if (
            isinstance(t, ast.Compare)
            and isinstance(t.left, ast.Name) and t.left.id == "exc"
            and len(t.ops) == 1 and isinstance(t.ops[0], ast.Is)
            and len(t.comparators) == 1
            and isinstance(t.comparators[0], ast.Constant)
            and t.comparators[0].value is None
        ):
            return list(n.body)
    return []


def _branch_calls_name(stmts: list[ast.stmt], target: str) -> bool:
    for s in stmts:
        for n in ast.walk(s):
            if isinstance(n, ast.Call):
                f = n.func
                name = f.id if isinstance(f, ast.Name) else (
                    f.attr if isinstance(f, ast.Attribute) else "")
                if name == target:
                    return True
    return False


def test_funnel_exc_none_branch_resurrects_auth_revoked_retries():
    tree = parse_module(_APP_MODULE); assert tree is not None  # N-350 R31
    fn = _funnel_body(tree)
    assert fn is not None, "record_provider_outcome missing from web/app.py"
    branch = _exc_is_none_branch(fn)
    assert branch, (
        "record_provider_outcome no longer has a recognisable "
        "`if exc is None:` branch — the pin can't find the CLEAR path"
    )
    assert _branch_calls_name(branch, "_resurrect_auth_revoked_retries"), (
        "record_provider_outcome's `exc is None` branch does NOT invoke "
        "`_resurrect_auth_revoked_retries` (N-386). Sibling of "
        "`_clear_auth_stale`: both must fire on every provider-success path "
        "so the watcher_retry_queue auth_revoked lifecycle stays symmetric."
    )


# --------------------------------------------------------------------------
# Invariant 3 — the two SSOT sets cover every mark_retry_dead(reason=X) literal
# used across the src tree. A new reason not registered in either set is caught.
# --------------------------------------------------------------------------
def _reason_literals_at_mark_retry_dead(tree: ast.AST) -> set[str]:
    """Collect every string literal passed as ``reason=`` to a
    ``mark_retry_dead(...)`` call in this module. Reason strings computed at
    runtime (e.g. ``reason=verdict.split(':')[1]``) are NOT string literals —
    those are already covered by the runtime validator in ``mark_retry_dead``
    (raises on any value outside ``WATCHER_RETRY_DEAD_REASONS``); this walk
    catches the OPPOSITE direction (a stray literal not registered in either
    SSOT set)."""
    literals: set[str] = set()
    for n in ast.walk(tree):
        if not isinstance(n, ast.Call):
            continue
        f = n.func
        name = f.id if isinstance(f, ast.Name) else (
            f.attr if isinstance(f, ast.Attribute) else "")
        if name != "mark_retry_dead":
            continue
        for kw in n.keywords:
            if kw.arg != "reason":
                continue
            v = kw.value
            if isinstance(v, ast.Constant) and isinstance(v.value, str):
                literals.add(v.value)
    return literals


def test_every_mark_retry_dead_literal_registered():
    seen: set[str] = set()
    for _p, _rel, tree in walk_src():
        seen |= _reason_literals_at_mark_retry_dead(tree)
    unregistered = sorted(seen - _ALL_DEAD_REASONS)
    assert not unregistered, (
        f"mark_retry_dead was called with reason literal(s) not in "
        f"WATCHER_RETRY_DEAD_REASONS: {unregistered}. Add to the SSOT set in "
        f"web/db.py AND classify in this pin as either recoverable (add a "
        f"resurrect_<reason>_retries helper) or `_TERMINAL_BY_DESIGN`."
    )


def test_terminal_and_recoverable_partition_the_ssot():
    """Guard the pin itself: the two classification sets MUST partition the SSOT.
    An overlap or a gap means the recoverable-set derivation is wrong."""
    assert _TERMINAL_BY_DESIGN.issubset(_ALL_DEAD_REASONS)
    assert _RECOVERABLE.isdisjoint(_TERMINAL_BY_DESIGN)
    assert _TERMINAL_BY_DESIGN | _RECOVERABLE == _ALL_DEAD_REASONS


# --------------------------------------------------------------------------
# Teeth — the pin must actually catch a planted regression.
# --------------------------------------------------------------------------
def test_pin_teeth_invariant1_missing_helper(tmp_path):
    """Simulate a db.py that lost `resurrect_auth_revoked_retries`."""
    bad = tmp_path / "db_missing_helper.py"
    bad.write_text(
        "def mark_retry_dead(conn, retry_id, *, reason):\n    pass\n",
        encoding="utf-8",
    )
    tree = parse_module(bad); assert tree is not None
    fns = _defined_top_level_functions(tree)
    for r in _RECOVERABLE:
        assert f"resurrect_{r}_retries" not in fns


def test_pin_teeth_invariant1_helper_present(tmp_path):
    ok = tmp_path / "db_helper_present.py"
    body = "".join(
        f"def resurrect_{r}_retries(conn, account_id):\n    return 0\n"
        for r in _RECOVERABLE
    )
    ok.write_text(body, encoding="utf-8")
    tree = parse_module(ok); assert tree is not None
    fns = _defined_top_level_functions(tree)
    for r in _RECOVERABLE:
        assert f"resurrect_{r}_retries" in fns


def test_pin_teeth_invariant2_funnel_unwired(tmp_path):
    """A funnel whose `exc is None` branch does NOT resurrect trips the pin."""
    bad = tmp_path / "app_unwired.py"
    bad.write_text(
        "def record_provider_outcome(db, acct, exc):\n"
        "    if exc is None:\n"
        "        _clear_auth_stale(db, acct['id'])\n"
        "    else:\n"
        "        pass\n",
        encoding="utf-8",
    )
    tree = parse_module(bad); assert tree is not None
    fn = _funnel_body(tree); assert fn is not None
    branch = _exc_is_none_branch(fn); assert branch
    assert not _branch_calls_name(branch, "_resurrect_auth_revoked_retries")


def test_pin_teeth_invariant2_funnel_wired(tmp_path):
    ok = tmp_path / "app_wired.py"
    ok.write_text(
        "def record_provider_outcome(db, acct, exc):\n"
        "    if exc is None:\n"
        "        _clear_auth_stale(db, acct['id'])\n"
        "        _resurrect_auth_revoked_retries(db, acct['id'])\n"
        "    else:\n"
        "        pass\n",
        encoding="utf-8",
    )
    tree = parse_module(ok); assert tree is not None
    fn = _funnel_body(tree); assert fn is not None
    branch = _exc_is_none_branch(fn); assert branch
    assert _branch_calls_name(branch, "_resurrect_auth_revoked_retries")


def test_pin_teeth_invariant3_unregistered_literal(tmp_path):
    """A mark_retry_dead call with an unregistered reason literal is caught."""
    bad = tmp_path / "sweeper_unreg.py"
    bad.write_text(
        "def sweep():\n"
        "    mark_retry_dead(conn, 1, reason='mystery_reason_2027')\n",
        encoding="utf-8",
    )
    tree = parse_module(bad); assert tree is not None
    literals = _reason_literals_at_mark_retry_dead(tree)
    assert "mystery_reason_2027" in literals
    assert "mystery_reason_2027" not in _ALL_DEAD_REASONS


def test_pin_teeth_invariant3_registered_literal_passes(tmp_path):
    ok = tmp_path / "sweeper_reg.py"
    ok.write_text(
        "def sweep():\n"
        "    mark_retry_dead(conn, 1, reason='auth_revoked')\n",
        encoding="utf-8",
    )
    tree = parse_module(ok); assert tree is not None
    literals = _reason_literals_at_mark_retry_dead(tree)
    assert literals <= _ALL_DEAD_REASONS
