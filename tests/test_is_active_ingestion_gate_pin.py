"""is_active ingestion-teardown — count-agnostic structural pin
(Loop-5 census, deactivation-teardown defect).

Deactivating an account (``is_active`` -> False, via the edit-save handler or
the account-active funnel) must STOP live ingestion: the IMAP IDLE watcher, the
Gmail / O365 push consumers, and BOTH push renewers must each fail-closed on an
inactive account, otherwise a paused HIPAA account keeps reading + classifying +
acting on PHI until the next process restart (the live defect:
§164.502(a)(1) / §164.312(a)).

The fix planted a fail-closed ``is_active`` gate at every ingestion ACTUATOR.
This pin keeps that net complete as the code evolves: it asserts a property over
**every** named ingestion entrypoint (never ``len(...) == N``), per
``pattern_count_agnostic_structural_drift_catch`` — so a NEW provider transport
that copies one of these entrypoint shapes inherits the requirement, and a
future refactor can't silently drop a gate from one site.

Two invariants:

  * Invariant 1 (interprocedural, by-name) — each ENTRYPOINT function listed in
    ``_ENTRYPOINTS`` must, somewhere in its own body (incl. nested defs), gate on
    ``is_active`` — detected as a read of the ``is_active`` key / attribute / the
    cheap ``account_is_active`` helper. This is the count-agnostic net the
    verifier asked for.
  * Invariant 2 (SSOT funnel exists + is wired) — the ``apply_account_active_state``
    funnel exists on the WatcherManager and the edit-save handler + the wizard
    finish route it; the funnel is the single place that translates an
    ``is_active`` transition into a start/teardown.
"""

from __future__ import annotations

import ast

from _pin_harness import SRC_ROOT, annotate_parents, parse_module, relpath  # N-350 R31

SRC = SRC_ROOT

# Each entry: (repo-relative module, entrypoint function name). These are the
# ingestion ACTUATORS — the surfaces that fetch→classify→act, re-arm a push
# registration, or (re)start a watcher. A new continuous/push transport that
# adds its own such entrypoint MUST be added here AND carry the gate; that is
# the deliberate "a new provider inherits the requirement" tax.
_ENTRYPOINTS = [
    ("web/watcher.py", "start"),                       # WatcherManager.start
    ("web/watcher.py", "_watch_account"),              # IMAP IDLE loop
    ("web/ingestion_push.py", "_process_push_item"),   # Gmail push consumer
    ("web/ingestion_push.py", "_process_office365_push_item"),  # O365 consumer
    ("web/ingestion_push.py", "_run_watch_renewal_sweep"),      # Gmail renewer
    ("web/o365_renewer.py", "_run_o365_renewal_sweep"),         # O365 renewer
]

# The shapes that count as "gates on is_active":
#   * a subscript read of the "is_active" key   acct["is_active"] / .get("is_active"...)
#   * an attribute named is_active
#   * a call to the cheap helper account_is_active (any receiver / alias)
_HELPER_NAMES = {"account_is_active", "_account_is_active"}


def _relpath(p) -> str:
    return relpath(p)  # harness SSOT (SRC == SRC_ROOT)


def _parse(relpath: str) -> ast.AST:
    _t = parse_module(SRC / relpath); assert _t is not None; return _t  # N-350 R31


def _find_func(tree: ast.AST, name: str) -> ast.AST | None:
    """First MODULE-LEVEL or one-level-nested (method) function by name."""
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and (
            node.name == name
        ):
            return node
    return None


def _gates_on_is_active(node: ast.AST) -> bool:
    """True if the function body references an is_active gate in any shape."""
    for n in ast.walk(node):
        # "is_active" string-literal key (subscript or .get("is_active"))
        if isinstance(n, ast.Constant) and n.value == "is_active":
            return True
        # bare/attribute reference named is_active
        if isinstance(n, ast.Attribute) and n.attr == "is_active":
            return True
        if isinstance(n, ast.Name) and n.id == "is_active":
            return True
        # reference to the cheap helper in ANY form: a direct call
        # ``account_is_active(...)``, an attribute call, OR a bare name
        # passed through an indirection like ``db_call(_account_is_active,
        # ...)`` (the interprocedural seam — same pattern the auth_stale
        # pin matches for ``db_call(_clear_auth_stale, ...)``).
        if isinstance(n, ast.Name) and n.id in _HELPER_NAMES:
            return True
        if isinstance(n, ast.Attribute) and n.attr in _HELPER_NAMES:
            return True
    return False


# --------------------------------------------------------------------------
# Invariant 1 — every named ingestion entrypoint gates on is_active.
# --------------------------------------------------------------------------
def test_every_ingestion_entrypoint_gates_on_is_active():
    offenders: list[str] = []
    missing_funcs: list[str] = []
    for relpath, fname in _ENTRYPOINTS:
        tree = _parse(relpath)
        node = _find_func(tree, fname)
        if node is None:
            missing_funcs.append(f"{relpath}::{fname}")
            continue
        if not _gates_on_is_active(node):
            offenders.append(f"{relpath}::{fname}:{node.lineno}")
    assert not missing_funcs, (
        "an ingestion entrypoint named in the pin no longer exists (renamed / "
        f"moved?): {missing_funcs}. Update _ENTRYPOINTS to the new name so the "
        "gate stays enforced — do not delete the row."
    )
    assert not offenders, (
        "an ingestion ACTUATOR no longer gates on is_active — a deactivated "
        f"HIPAA account would keep ingesting PHI: {offenders}. Add the fail-"
        "closed gate (early-return / continue / skip when "
        "`not acct.get('is_active', True)`), mirroring the sibling actuators."
    )


# --------------------------------------------------------------------------
# Invariant 2 — the funnel exists + is wired at the operator-facing surfaces.
# --------------------------------------------------------------------------
def test_funnel_exists_on_watcher_manager():
    tree = _parse("web/watcher.py")
    node = _find_func(tree, "apply_account_active_state")
    assert node is not None, (
        "apply_account_active_state vanished from web/watcher.py — the is_active "
        "lifecycle funnel that the edit-save + wizard routes depend on."
    )
    # The funnel must call self.stop on the DEACTIVATE (`not active`) branch and
    # self.start on the activate path — branch-correct, not a substring (DA
    # LOW-3: `"start" in ast.dump` passes on `started_at`/`start_history_id` and
    # would not catch a swapped branch).
    annotate_parents(node)

    def _calls(method: str):
        return [n for n in ast.walk(node)
                if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                and n.func.attr == method]

    def _under_not_active(call) -> bool:
        cur = getattr(call, "_ph_parent", None)
        while cur is not None:
            if isinstance(cur, ast.If):
                for m in ast.walk(cur.test):
                    if (isinstance(m, ast.UnaryOp) and isinstance(m.op, ast.Not)
                            and any(isinstance(x, ast.Name) and x.id == "active"
                                    for x in ast.walk(m.operand))):
                        return True
            if cur is node:
                break
            cur = getattr(cur, "_ph_parent", None)
        return False

    stops, starts = _calls("stop"), _calls("start")
    assert stops, "funnel must call self.stop (deactivate teardown)"
    assert starts, "funnel must call self.start (reactivate restart)"
    assert any(_under_not_active(c) for c in stops), (
        "self.stop is not on the `if not active:` deactivate branch — a "
        "swapped/missing branch would silently fail to tear down ingestion."
    )
    assert any(not _under_not_active(c) for c in starts), (
        "self.start is not on the activate path (it must NOT be under "
        "`if not active:`)."
    )


def test_edit_save_and_wizard_route_through_funnel():
    """The two operator surfaces that flip is_active must call the funnel."""
    for relpath in ("web/routers/ui/accounts.py", "web/routers/ui/wizard.py"):
        src = (SRC / relpath).read_text(encoding="utf-8")
        assert "apply_account_active_state" in src, (
            f"{relpath} flips is_active but does not route the transition "
            "through apply_account_active_state — a deactivation there would not "
            "tear down live ingestion."
        )


# --------------------------------------------------------------------------
# Teeth — the pin must catch a planted regression.
# --------------------------------------------------------------------------
def test_pin_has_teeth_ungated_entrypoint():
    code = (
        "async def _process_push_item(app, item):\n"
        "    acct = lookup(item)\n"
        "    if acct is None:\n"
        "        return\n"
        "    classify(acct, item)\n"          # no is_active gate
    )
    node = _find_func(ast.parse(code), "_process_push_item")
    assert node is not None and not _gates_on_is_active(node)


def test_pin_has_teeth_gated_entrypoint_passes():
    code = (
        "async def _process_push_item(app, item):\n"
        "    acct = lookup(item)\n"
        "    if acct is None:\n"
        "        return\n"
        "    if not acct.get('is_active', True):\n"
        "        return\n"
        "    classify(acct, item)\n"
    )
    node = _find_func(ast.parse(code), "_process_push_item")
    assert node is not None and _gates_on_is_active(node)


def test_pin_has_teeth_helper_call_counts_as_gate():
    code = (
        "async def _watch_account(mgr, account_id):\n"
        "    if not await db_call(_account_is_active, db, account_id):\n"
        "        return\n"
    )
    node = _find_func(ast.parse(code), "_watch_account")
    assert node is not None and _gates_on_is_active(node)
