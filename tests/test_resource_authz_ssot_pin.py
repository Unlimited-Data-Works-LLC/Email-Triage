"""Resource-ownership authz SSOT pin (divergence census run14 #2).

A "may I modify/delete a resource I OWN?" gate must route through
``email_triage.web._resource_authz.can_modify_owned_resource`` — NOT a hand-rolled
inline ``<resource>.user_id != <requester>`` comparison. ~14 such inline gates
(10 of them on saved Topics) were replicated across profile.py / api.py /
_shared.py with no SSOT; that is the N-60 horizontal-privilege shape — one copy
written wrong (or a new handler copying a stale variant) is a silent IDOR /
over-grant. The decision lives in one place; this pin keeps it there.

SCOPE — the ``user_id`` owner column (the resource-ownership concern). The
``owner_id`` + ``is_global`` classification-LIST gates are a SEPARATE concern
with their own SSOT (``_list_authz.is_list_writable_by`` — note its READ gate
makes ``is_global`` lists public, a DIFFERENT policy than owner-only resources),
so this pin deliberately does NOT touch the ``owner_id`` shape.

COUNT-AGNOSTIC PROPERTY (over every ``*.py`` in ``src/email_triage/web`` except
the SSOT module): no ``Compare`` may pit an OWNER field (``<X>.user_id`` /
``<X>["user_id"]`` / ``<X>.get("user_id")``, optionally ``int()``-wrapped) against
a REQUESTER ref (``user_id`` / ``actor_user_id`` / ``<X>["id"]``, optionally
``int()``-wrapped) with ``!=`` / ``==``. The ``ast.walk`` catches the shape
wherever it lives — INCLUDING inside a ``db_call`` closure (interprocedural by
construction) — so a gate hidden in an off-loop helper is covered. No
``len(...)==N``.
"""

from __future__ import annotations

import ast

from _pin_harness import enclosing_fn, iter_src_files, parse_module, parse_source, relpath

_ALLOWED_FILE = {"_resource_authz.py"}
# (relpath, fn) sites that match the user_id-vs-requester SHAPE but are a
# DIFFERENT concern than resource-ownership-modify — verified per-site.
#
# The 7 ACCOUNT-ownership sites (HIPAA audit-emit gates, the data-subject knob
# opt-in, the admin-view display flag, the openclaw owner branch, the surrogate
# picker filter) USED to live here as exemptions; census run14 follow-up gave that
# concern its OWN SSOT — ``account_scope.is_account_owner`` (strict ownership =
# ``can_modify_owned_resource(..., admin_bypass=False)``; NO delegate/admin fold).
# They now CALL it, so they no longer hand-roll the comparison and have LEFT this
# allow-list (the PD#7 rot-guard would flag them as stale otherwise). What remains
# are the WEBAUTHN credential-binding AUTH checks (a genuinely different concern):
_ALLOWED_SITES: set[tuple[str, str]] = {
    # WEBAUTHN credential-binding AUTH checks (the §164.312(d) authentication
    # path, not a resource the user modifies; admin_bypass would be a DEFECT):
    ("web/webauthn_auth.py", "finish_authentication"),                   # the passkey's user_id must match the authenticating user
    ("web/webauthn_auth.py", "finish_passkey_authentication"),           # the resolved user_handle owner must match the credential's user_id
    # N-208 R22 CI fix (2026-07-02): owner-self-preview-[redacted] viewer-
    # AWARE display gates (R20_X earlier in the session). Not authz decisions —
    # they gate `redact_pii=` and template flags on the RENDER side: the
    # request is already authorized to reach this handler (upstream account-
    # scope check), so `<owner> != <viewer>` here selects the redacted-view
    # variant, not access. `can_modify_owned_resource` doesn't fit — it would
    # BLOCK the view for a non-owner authorized non-owner (e.g., a delegate
    # authorized to preview the account's digest with redaction).
    ("web/routers/ui/accounts.py", "digest_candidates"),                 # viewer-aware redaction, not access gate
    ("web/routers/ui/accounts.py", "digest_preview"),                    # viewer-aware redact_pii= flag, not access gate
}

_OWNER_KEYS = {"user_id"}            # the resource-owner column this SSOT governs
_REQUESTER_NAMES = {"user_id", "actor_user_id", "requester_id", "actor_id"}


def _unwrap_int(node: ast.AST) -> ast.AST:
    """Strip ``int(...)`` wrappers AND ``X or <default>`` BoolOp guards down to
    the underlying owner/requester expression — handlers write
    ``int(topic.user_id) != int(user["id"])`` and
    ``int(account.get("user_id") or 0) != int(actor_user_id)`` (the ``or 0``
    default would otherwise hide the owner field — DA blind-spot, run14 #2)."""
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "int"
        and node.args
    ):
        return _unwrap_int(node.args[0])
    if isinstance(node, ast.BoolOp) and isinstance(node.op, ast.Or) and node.values:
        # ``X or <default>`` — the owner/requester is the first (non-default) operand
        return _unwrap_int(node.values[0])
    return node


def _str_const(node: ast.AST) -> str | None:
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def _is_owner_field(node: ast.AST) -> bool:
    """``<X>.user_id`` / ``<X>["user_id"]`` / ``<X>.get("user_id")`` (int-unwrapped)."""
    node = _unwrap_int(node)
    if isinstance(node, ast.Attribute) and node.attr in _OWNER_KEYS:
        return True
    if isinstance(node, ast.Subscript) and _str_const(node.slice) in _OWNER_KEYS:
        return True
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "get"
        and node.args
        and _str_const(node.args[0]) in _OWNER_KEYS
    ):
        return True
    return False


def _is_requester(node: ast.AST) -> bool:
    """``user_id`` / ``actor_user_id`` (bare names), ``<X>["id"]``, or
    ``<X>.get("id")`` (all int-unwrapped). The ``.get("id")`` form was a DA
    blind-spot (openclaw `user.get("id")`, run14 #2)."""
    node = _unwrap_int(node)
    if isinstance(node, ast.Name) and node.id in _REQUESTER_NAMES:
        return True
    if isinstance(node, ast.Subscript) and _str_const(node.slice) == "id":
        return True
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "get"
        and node.args
        and _str_const(node.args[0]) == "id"
    ):
        return True
    return False


def _is_owner_gate(node: ast.AST) -> bool:
    """A ``Compare`` (single ``!=`` / ``==``) of an owner field against a
    requester ref, in either order."""
    if not isinstance(node, ast.Compare) or len(node.ops) != 1:
        return False
    if not isinstance(node.ops[0], (ast.NotEq, ast.Eq)):
        return False
    left, right = node.left, node.comparators[0]
    return (
        (_is_owner_field(left) and _is_requester(right))
        or (_is_requester(left) and _is_owner_field(right))
    )


def _offenders(tree: ast.AST, rel: str) -> list[str]:
    out: list[str] = []
    for node in ast.walk(tree):
        if _is_owner_gate(node):
            fn = enclosing_fn(node)
            if (rel, fn) in _ALLOWED_SITES:
                continue
            out.append(f"{rel}:{getattr(node, 'lineno', -1)} ({fn})")
    return out


def test_owner_gate_routes_through_ssot():
    offenders: list[str] = []
    for p in iter_src_files("web"):
        if p.name in _ALLOWED_FILE:
            continue
        tree = parse_module(p)
        if tree is None:  # pragma: no cover
            continue
        offenders.extend(_offenders(tree, relpath(p)))
    assert not offenders, (
        "A resource-ownership gate is hand-rolled as an inline "
        "`<resource>.user_id != <requester>` comparison instead of routing "
        f"through the SSOT (census run14 #2): {offenders}. Replace with "
        "`can_modify_owned_resource(owner_id, requester_id=..., admin_bypass=...)` "
        "(admin_bypass=False for owner-only resources like Topics). If this is "
        "genuinely NOT an authz gate, add (relpath, fn) to _ALLOWED_SITES with a "
        "justification."
    )


def test_pin_has_teeth():
    # The owner-gate shape IS flagged — attr / subscript / .get / int-wrapped,
    # both operand orders.
    for bad in (
        'x = topic.user_id != user["id"]\n',
        'y = int(topic.user_id) != int(user["id"])\n',
        'z = row["user_id"] != user_id\n',
        'w = cat.get("user_id") != user_id\n',
        'v = user["id"] != existing.user_id\n',            # reversed order
        'u = actor_user_id == obj.user_id\n',              # == form
    ):
        assert _offenders(parse_source(bad), "web/x.py"), f"missed an owner gate: {bad!r}"
    # NOT flagged: the SSOT call, an owner_id (classification-list) gate, and a
    # non-authz user_id comparison shape.
    for ok in (
        'a = can_modify_owned_resource(topic.user_id, requester_id=user["id"])\n',
        'b = row["owner_id"] != user["id"]\n',              # owner_id = the _list_authz concern
        'c = topic.user_id != other.user_id\n',             # owner-vs-owner, not a requester
        'd = row["status"] != user_id\n',                   # not an owner field
        'e = topic.account_id != user["id"]\n',             # account_id, not user_id
    ):
        assert not _offenders(parse_source(ok), "web/x.py"), f"false-flagged: {ok!r}"
    # A gate hidden in a db_call closure IS caught (interprocedural by ast.walk)
    closured = (
        'def handler():\n'
        '    def _work(db):\n'
        '        if topic.user_id != user["id"]:\n'
        '            return "forbidden"\n'
        '    return db_call(_work)\n'
    )
    assert _offenders(parse_source(closured), "web/x.py"), "missed a gate inside a db_call closure"


def test_ssot_decision_table():
    from email_triage.web._resource_authz import can_modify_owned_resource as c

    # OWNER → always (regardless of admin_bypass)
    assert c(5, requester_id=5) is True
    assert c(5, requester_id=5, admin_bypass=False) is True
    # str-vs-int coerces — a DB-str owner vs session-int requester (or vice
    # versa) must NOT read as a different owner (that would be a privilege bug).
    assert c("5", requester_id=5) is True
    assert c(5, requester_id="5") is True
    # ADMIN → only when admin_bypass (owner-only resources pass admin_bypass=False)
    assert c(7, requester_id=5, role="admin", admin_bypass=True) is True
    assert c(7, requester_id=5, role="admin", admin_bypass=False) is False
    # non-owner non-admin → refuse
    assert c(7, requester_id=5, role="user") is False
    assert c(7, requester_id=5) is False
    # FAIL-CLOSED: None / uncoercible owner or requester → refuse, never raise
    assert c(None, requester_id=5) is False
    assert c(5, requester_id=None) is False
    assert c("abc", requester_id=5) is False
    assert c(5, requester_id="xyz") is False
    # …but a valid admin survives an uncoercible requester (admin checked first)
    assert c(5, requester_id="xyz", role="admin", admin_bypass=True) is True


def test_allow_list_has_no_rot():
    """PD#7 (census the censusers) — every ``_ALLOWED_SITES`` entry must still
    match a REAL owner-gate in the source. Without this, a function rename or a
    deleted gate leaves a stale exemption that silently un-pins a NEW gate later
    written under the same (relpath, fn) name."""
    caught: set[tuple[str, str]] = set()
    for p in iter_src_files("web"):
        if p.name in _ALLOWED_FILE:
            continue
        tree = parse_module(p)
        if tree is None:  # pragma: no cover
            continue
        for node in ast.walk(tree):
            if _is_owner_gate(node):
                caught.add((relpath(p), enclosing_fn(node)))
    stale = _ALLOWED_SITES - caught
    assert not stale, (
        "_ALLOWED_SITES entries no longer match any owner-gate in the source "
        f"(rename/deletion → allow-list rot): {sorted(stale)}. Remove them — a "
        "stale exemption silently un-pins a new gate written under the same name."
    )
