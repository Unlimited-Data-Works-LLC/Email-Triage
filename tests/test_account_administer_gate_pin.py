"""Account-administer gate pin (divergence census 2026-06-11, batch 4).

The SENSITIVE per-account mutators — flip the HIPAA flag, delete the account,
grant/revoke a delegate — are ``owner-or-admin, NO delegate`` operations: a
delegate may *run* the account but must never escalate (grant/revoke further
delegation), flip the audit posture, or destroy it. That decision was inlined
as ``acct["user_id"] == user["id"] or is_admin`` across four handlers; it is
now the SSOT ``db.accounts.can_administer_account`` (admin OR owner, strictly
no delegate — distinct from the delegate-permitting ``can_manage_account``).

The drift this pin prevents: a future handler reaching one of these mutators
guards it with ``can_manage_account`` (which returns True for a delegate) or
inlines a divergent owner check — silently letting a delegate escalate. The
pin is keyed on the ACTUATOR (the mutator call), per PD-9 ("gate at the
actuator, not just the writer"), and is **seam-aware** (PD-2): it recognises
both a direct ``mutator(...)`` call and the ``db_call(mutator, …)`` /
``run_in_threadpool(mutator, …)`` off-loop hop.

INVARIANT: every function that invokes a sensitive account-mutator also
references ``can_administer_account`` (the gate and the mutator live in the
same top-level handler — including its nested ``db_call`` closures, which the
source segment captures). Count-agnostic: walks every ``*.py`` under
``src/email_triage`` (``ast.walk``), never ``len(X)==N``.

SCOPE CAVEAT (honest): the pin asserts the gate is REFERENCED in the same
top-level function as the mutator — it does NOT prove the reference dominates
the call on every path (a reference in a dead branch would satisfy it). That
edge is covered by the behavioural delegate-DENIED tests in
``tests/test_web/test_account_delegates.py`` / ``test_accounts.py`` (the
N-57 lesson: a structural reference pin needs a behavioural edge test). It
also assumes the mutator and its gate share a top-level function; a future
refactor that moves a mutator into a module-level helper gated by its caller
must either pass an already-administer-checked flag or extend this pin
interprocedurally (and add a justified allow-list entry).

RESIDUAL (R1): ``SENSITIVE_MUTATORS`` is a curated set — but it is the set of
ACTUATORS protected, not a list of call SITES, and the pin scans EVERY
function for an invocation of any of them (a property over all sites, not
``len(sites)==N``). The residual is membership: a NEW no-delegate sensitive
account-mutator (a 5th) must be ADDED here when it is born, or the pin is
blind to it — the decay any actuator-keyed pin carries. The mutators are
defined in one place (``db/accounts.py``); adding one there without adding it
here (and gating its callers) is the lapse to watch for at the true-up.
"""

from __future__ import annotations

import ast

from _pin_harness import SRC_ROOT, relpath, walk_src, parse_source

# The sensitive, no-delegate account mutators (the actuators). DELIBERATELY
# EXCLUDED (hipaa-sme, batch-4 review): ``set_account_active`` — pausing/
# enabling an account is an OPERATIONAL "manage" op a delegate may legitimately
# run; it neither downgrades audit posture nor destroys data, so it is gated by
# can_manage_account (delegate-permitting), NOT this no-delegate set. Adding a
# 5th genuinely posture-downgrading / destructive mutator means adding it here.
SENSITIVE_MUTATORS = frozenset({
    "set_account_hipaa",       # downgrades §164.312 audit posture
    "delete_email_account",    # destroys the account + its boundary-event history
    "add_account_delegate",    # widens the actor set (escalation)
    "remove_account_delegate",
})
GATE = "can_administer_account"
# Off-loop seam wrappers whose FIRST positional is the callee (PD-2). Only
# ``db_call`` is used in src today; the other two are aspirational forward-
# coverage so the pin already fences them if a future hop adopts them.
_SEAM_WRAPPERS = frozenset({"db_call", "db_call_async", "run_in_threadpool"})
# Repo-relative (NEVER basename, R38): the def home + the re-export shim
# legitimately name these mutators without gating them.
_ALLOWED_FILES = {
    "db/accounts.py",      # defines the mutators (and the gate)
    "web/db.py",           # re-export shim
}


def _invokes_mutator(node: ast.AST) -> set[str]:
    """Names of sensitive mutators INVOKED (called or seam-dispatched)
    anywhere inside ``node`` — NOT merely imported/named."""
    found: set[str] = set()
    for n in ast.walk(node):
        if not isinstance(n, ast.Call):
            continue
        fn = n.func
        # direct: mutator(...)
        if isinstance(fn, ast.Name) and fn.id in SENSITIVE_MUTATORS:
            found.add(fn.id)
        # seam: db_call(mutator, …) / run_in_threadpool(mutator, …)
        if isinstance(fn, ast.Name) and fn.id in _SEAM_WRAPPERS:
            for arg in n.args:
                if isinstance(arg, ast.Name) and arg.id in SENSITIVE_MUTATORS:
                    found.add(arg.id)
    return found


def _references_gate(node: ast.AST) -> bool:
    return any(
        isinstance(n, ast.Name) and n.id == GATE for n in ast.walk(node)
    )


def _find_violations() -> list[str]:
    violations: list[str] = []
    for _path, rel, tree in walk_src():
        if rel in _ALLOWED_FILES:
            continue
        # Top-level functions only — their source segment includes every
        # nested db_call closure, so the gate (which may sit in a sibling
        # closure) is in scope of the check.
        for node in tree.body:
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            muts = _invokes_mutator(node)
            if muts and not _references_gate(node):
                violations.append(
                    f"{rel}:{node.lineno} ({node.name!r} invokes "
                    f"{sorted(muts)} without {GATE})"
                )
    return violations


def test_sensitive_mutators_gated_by_can_administer_account():
    violations = _find_violations()
    assert violations == [], (
        "A sensitive account-mutator is invoked outside an "
        f"{GATE} gate (a delegate could escalate):\n  "
        + "\n  ".join(violations)
        + f"\nGuard the handler with db.accounts.{GATE} (admin-or-owner, NO "
        "delegate) — NEVER can_manage_account (which admits delegates)."
    )


def test_gate_ssot_exists_and_excludes_delegate():
    """The SSOT must exist and must NOT consult the delegate table —
    that's the whole point (strictly stronger than can_manage_account)."""
    src = (SRC_ROOT / "db" / "accounts.py").read_text(encoding="utf-8")
    tree = parse_source(src)
    fn = next(
        (n for n in ast.walk(tree)
         if isinstance(n, ast.FunctionDef) and n.name == GATE),
        None,
    )
    assert fn is not None, f"{GATE} SSOT vanished from db/accounts.py"
    seg = ast.get_source_segment(src, fn) or ""
    assert "is_account_delegate" not in seg, (
        f"{GATE} must NOT consult is_account_delegate — a delegate is not an "
        "administrator; that's what separates it from can_manage_account"
    )


def test_pin_has_teeth():
    # A handler that calls a mutator with NO administer gate is flagged...
    bad = ast.parse(
        "def h(db, user, acct):\n"
        "    return set_account_hipaa(db, acct['id'], True)\n"
    )
    assert any(
        _invokes_mutator(n) and not _references_gate(n)
        for n in bad.body if isinstance(n, ast.FunctionDef)
    ), "pin missed an ungated direct mutator call"

    # ...including via the db_call seam...
    bad_seam = ast.parse(
        "async def h(db, account_id):\n"
        "    await db_call(delete_email_account, db, account_id)\n"
    )
    assert any(
        _invokes_mutator(n) and not _references_gate(n)
        for n in bad_seam.body if isinstance(n, ast.AsyncFunctionDef)
    ), "pin missed an ungated db_call-seam mutator dispatch"

    # ...but a handler that references the gate (even in a nested closure)
    # passes.
    good = ast.parse(
        "async def h(db, user, account_id):\n"
        "    def _snap(db, account_id):\n"
        "        acct = get_email_account(db, account_id)\n"
        "        if not can_administer_account(db, user, acct):\n"
        "            return 'forbidden', None\n"
        "        return 'ok', acct\n"
        "    await db_call(_snap, db, account_id)\n"
        "    await db_call(delete_email_account, db, account_id)\n"
    )
    assert all(
        not (_invokes_mutator(n) and not _references_gate(n))
        for n in good.body if isinstance(n, ast.AsyncFunctionDef)
    ), "a gated handler must NOT be flagged"


def test_allow_list_entries_are_real():
    """R38 non-staleness: every allow-listed file must exist and actually
    name a sensitive mutator (else the exemption is dead and should go)."""
    for rel in _ALLOWED_FILES:
        p = SRC_ROOT / rel
        assert p.exists(), f"allow-listed {rel} no longer exists"
        text = p.read_text(encoding="utf-8")
        assert any(m in text for m in SENSITIVE_MUTATORS), (
            f"allow-listed {rel} no longer names any sensitive mutator — "
            "drop the stale exemption"
        )
