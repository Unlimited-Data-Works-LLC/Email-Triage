"""Self-scoped manageable-account-set SSOT pin (divergence census run12 #1, the
multi-id / ownership half — PD#9).

The "manageable set" is a requester's OWN multi-account scope (Topic digests,
style data): owner + delegate, **NO admin-global bypass** — deliberately distinct
from ``db.accounts.can_manage_account`` (which carries the admin bypass) and from
``web/routers/ui/routes.py``'s admin-global route-picker list. Its SSOT is
``web/account_scope.py``:

  * ``manageable_account_ids(db, user) -> set[int]``  (BUILD)
  * ``manageable_accounts(db, user) -> list[dict]``   (BUILD, dicts)
  * ``is_manageable(account_id, db, user) -> bool``   (GATE, single client id)
  * ``filter_to_manageable(ids, db, user) -> list[int]``   (client id list)
  * ``filter_to_manageable_accounts(ids, db, user) -> list[dict]``  (→ dicts)
  * ``intersect_ids(ids, manageable_set) -> list[int]``  (pure, build-once loops)

PD#9 contract: every client-submitted account_id is intersected with the
manageable set BEFORE acting (read AND write), gated at the ACTUATOR, fail-closed.
The COUNT-AGNOSTIC inverse property this pin enforces: **no inline
``<id> in/not in manageable*`` membership Compare anywhere under ``web/`` outside
the SSOT module** — the membership lives ONLY in ``account_scope.py``, so a new
actuator that hand-rolls ``if aid not in manageable: ...`` (skipping the funnel)
trips this before CI. A comprehension *iter* (``for a in manageable``) is NOT a
membership Compare and is not flagged.

KNOWN LIMITATION (honest — devils-advocate completeness review): this pin keys on
the ``manageable*`` NAMING CONVENTION, so a set holding authorized account ids
under a DIFFERENT name evades it. Two such names exist today, both legitimate and
deliberately NOT flagged — do NOT read the pass as "every authorized-id membership
is funnel-routed":
  * ``_shared.py``'s ``owned_ids`` — an ADMIN-GLOBAL display filter
    (``list_email_accounts(db)`` for admins), a DIFFERENT concept from the
    self-scoped set (like ``routes.py``'s admin-global picker), filtering
    server-side watcher state (never a client-submitted id) — not a PD#9 actuator.
  * ``topic_digest_sender.py``'s ``_managed_ids`` — the digest-send's authorized
    subset, itself BUILT via the SSOT funnel ``intersect_ids(...)``; the
    downstream ``h["account_id"] in _managed_ids`` hits-filter merely APPLIES that
    already-funnel-authorized set.
A self-scoped manageable SET deliberately named outside ``manageable*`` to evade
would be missed; the convention (name it ``manageable``/``manageable_ids``) is the
mitigation. The census re-run is the backstop for a renamed straggler.
"""

from __future__ import annotations

import ast

from _pin_harness import SRC_ROOT, iter_src_files, parse_module, relpath

WEB_SUBDIR = "web"
SSOT_REL = "web/account_scope.py"
_FUNNELS = {
    "manageable_account_ids",
    "manageable_accounts",
    "is_manageable",
    "filter_to_manageable",
    "filter_to_manageable_accounts",
    "intersect_ids",
}


def _is_manageable_name(name: str) -> bool:
    """A local holding the manageable ID SET: ``manageable`` / ``manageable_ids``
    / ``manageable_set`` / ``manageable_accounts`` …

    Deliberately does NOT match a LEADING-underscore ``_manageable``: that name is
    used by ``web/triage_one.py::_owner_can_manage`` for a ``(owner, account) ->
    bool`` memoization CACHE of ``can_manage_account`` — a different concept (a
    cache-presence check ``key not in _manageable``, NOT an account-id authz
    membership), already routed through the ``can_manage_account`` SSOT. Matching
    it would false-flag that cache. The convention: the manageable-account-SET is
    named without a leading underscore."""
    return name == "manageable" or name.startswith("manageable_")


def _inline_manageable_membership(tree: ast.AST) -> list[str]:
    """``<x> in manageable*`` / ``<x> not in manageable*`` Compares — the inline
    membership the SSOT funnels must replace. NOT a ``for a in manageable``
    comprehension iter (that's a generator, not a Compare)."""
    out: list[str] = []
    for n in ast.walk(tree):
        if not isinstance(n, ast.Compare):
            continue
        for op, cmp_node in zip(n.ops, n.comparators):
            if (isinstance(op, (ast.In, ast.NotIn))
                    and isinstance(cmp_node, ast.Name)
                    and _is_manageable_name(cmp_node.id)):
                out.append(f"line {n.lineno}")
    return out


def test_no_inline_manageable_membership_outside_ssot():
    offenders = []
    for p in iter_src_files(WEB_SUBDIR):
        rel = relpath(p)
        if rel == SSOT_REL:
            continue
        tree = parse_module(p)
        if tree is None:  # pragma: no cover
            continue
        hits = _inline_manageable_membership(tree)
        if hits:
            offenders.append(f"{rel}: {hits}")
    assert not offenders, (
        "Inline manageable-set membership found under web/ outside the SSOT "
        f"(account_scope.py): {offenders}. A client-submitted account_id must be "
        "intersected via the account_scope funnels — is_manageable(aid, db, user) "
        "for a single id, filter_to_manageable(ids, db, user) for a list, or "
        "intersect_ids(ids, manageable_set) inside a build-once loop — never an "
        "inline `if aid in manageable`. PD#9: gate at the actuator, fail-closed."
    )


def test_account_scope_funnels_exist():
    tree = parse_module(SRC_ROOT / SSOT_REL)
    assert tree is not None, "web/account_scope.py (the SSOT) is missing"
    names = {
        n.name for n in ast.walk(tree)
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    missing = _FUNNELS - names
    assert not missing, (
        f"account_scope SSOT funnels vanished: {missing}. The manageable-set "
        "membership routes through these — losing one re-opens inline copies."
    )


def test_pin_has_teeth():
    bad = (
        "def f(aid, manageable):\n"
        "    if aid not in manageable:\n"
        "        return False\n"
        "    return True\n"
    )
    assert _inline_manageable_membership(ast.parse(bad)), (
        "pin failed to catch an inline manageable-membership reject"
    )
    bad_ids = "def g(aid, manageable_ids):\n    return aid in manageable_ids\n"
    assert _inline_manageable_membership(ast.parse(bad_ids)), (
        "pin missed the `aid in manageable_ids` shape"
    )
    # The SSOT-routed shape and a comprehension iter are NOT flagged.
    good = "def f(aid, db, user):\n    return is_manageable(aid, db, user)\n"
    assert not _inline_manageable_membership(ast.parse(good))
    comp_iter = "def h(manageable):\n    return [a['id'] for a in manageable]\n"
    assert not _inline_manageable_membership(ast.parse(comp_iter)), (
        "a `for a in manageable` comprehension iter must NOT be flagged"
    )
