"""the backlog  (DI-annotation-only handler behavioral-pin STRUCTURAL variant).

Behavioral form of the census run22 §3(b) sibling: for each
``DI_annotation_only`` handler alias, prove the DI is LOAD-BEARING —
a mistakenly-removed ``Depends()`` decorator MUST NOT silently downgrade
the handler to unauthenticated 200.

This pin implements the STRUCTURAL guard rather than the full behavioral
override (which would need per-alias test-app spin-up + monkeypatched
resolvers hitting representative handlers). The structural invariant is:
each of the four DI aliases in :data:`_DI_ALIAS_NAMES` MUST be defined
via ``<NAME> = Annotated[<type>, Depends(<resolver>)]`` — a
``Depends(...)`` call SOMEWHERE in the ``Annotated[...]`` tail. If a
future edit strips the ``Depends()`` (e.g. an accidental
``Annotated[<type>, None]`` or a bare ``Annotated[<type>]``), FastAPI
falls through to treating the param as a query/body binding, the alias
loses its DI intercept, and every handler that uses the alias silently
degrades to unauthenticated 200. The pin fires red at DEFINITION time,
before the degrade can reach any route.

Same class as ``feedback_dynamic_over_hardcoding`` applied to DI wiring:
derive the load-bearing intercept from the alias definition itself, not
from a snapshot of "current handlers" — the SAME LINE gates every
consumer.

The full behavioral counterpart (override the resolver with a
``force_401`` shim + hit each of the ~30 DI-only handlers + assert 4xx
lands on every one) is queued as a follow-up ratchet if a future
census surfaces DI-remove regressions in the wild.
"""

from __future__ import annotations

import ast

from _pin_harness import SRC_ROOT, parse_module


# The four DI aliases enforced by the sibling
# ``test_authz_by_id_fetch_pin._DI_ALIAS_NAMES`` frozenset. Kept in sync
# manually — the sibling pin already treats these as gate-name-role-
# carriers, this pin adds the load-bearing intercept guard.
_DI_ALIAS_NAMES: frozenset[str] = frozenset({
    "OwnedAccount",
    "OwnedAccountOrLogin",
    "OwnedGmailApiAccount",
    "OwnedAccountForProvider",
})


_DEPENDENCIES_PY = SRC_ROOT / "web" / "dependencies.py"


def _annotated_tail_has_depends(value: ast.expr) -> bool:
    """True iff ``value`` matches ``Annotated[<type>, Depends(...), ...]``
    with a ``Depends(...)`` call anywhere in the metadata tail.

    Accepts both single-metadata (``Annotated[T, Depends(x)]``) and
    multi-metadata (``Annotated[T, m1, Depends(x), m2, ...]``) shapes.
    """
    # ``Annotated[...]`` at expression scope is an ``ast.Subscript``.
    if not isinstance(value, ast.Subscript):
        return False
    # The subscript BASE must be a bare ``Annotated`` name (or the
    # ``typing.Annotated`` attribute-chain). Reject a plain
    # ``list[...]`` / ``tuple[...]`` — those are types, not DI aliases.
    base = value.value
    base_name = (
        base.id if isinstance(base, ast.Name)
        else base.attr if isinstance(base, ast.Attribute) else None
    )
    if base_name != "Annotated":
        return False
    # The subscript slice is a Tuple: (T, meta1, meta2, ...). Python 3.9+
    # normalises this to an ast.Tuple. Older parsers wrap in ast.Index.
    slice_node = value.slice
    if isinstance(slice_node, ast.Index):  # pragma: no cover — old py
        slice_node = slice_node.value  # type: ignore[attr-defined]
    if not isinstance(slice_node, ast.Tuple) or len(slice_node.elts) < 2:
        return False
    # Any of the metadata elements can be the ``Depends(...)`` call.
    for elt in slice_node.elts[1:]:
        if isinstance(elt, ast.Call):
            f = elt.func
            fname = (
                f.id if isinstance(f, ast.Name)
                else f.attr if isinstance(f, ast.Attribute) else None
            )
            if fname == "Depends":
                return True
    return False


def _collect_alias_definitions() -> dict[str, ast.expr | None]:
    """Return ``{alias_name: RHS-expr | None}`` for each name in
    :data:`_DI_ALIAS_NAMES`. Missing aliases return None.

    Handles two definition shapes:
      * ``OwnedAccount = Annotated[...]``  — module-level Assign.
      * ``def OwnedAccountForProvider(provider_type): ...``  — factory
        function that RETURNS an alias-shaped value. For factories the
        RHS is the ``return`` expression's ``ast.Return.value``.
    """
    tree = parse_module(_DEPENDENCIES_PY)
    assert tree is not None, f"parse failed on {_DEPENDENCIES_PY}"
    result: dict[str, ast.expr | None] = {n: None for n in _DI_ALIAS_NAMES}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target = node.targets[0]
            if isinstance(target, ast.Name) and target.id in _DI_ALIAS_NAMES:
                result[target.id] = node.value
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.name in _DI_ALIAS_NAMES:
                # Factory: find the RETURN's inner call and check its
                # signature — the factory's returned callable is the
                # actual DI resolver, so the load-bearing check on the
                # factory shape is that the returned callable EXISTS.
                # For the OwnedAccountForProvider factory, this is
                # ``def _dep(...) -> ...: ... return _dep``. Presence
                # of that inner def is the load-bearing shape.
                for sub in node.body:
                    if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        # Store the inner def as a sentinel — the
                        # invariant test treats "inner def present" as
                        # PASS since callers use it via
                        # ``Depends(OwnedAccountForProvider("gmail_api"))``.
                        result[node.name] = sub
                        break
    return result


def test_every_di_alias_has_load_bearing_depends():
    """For each of the four DI aliases in :data:`_DI_ALIAS_NAMES`, the
    definition MUST carry a ``Depends(...)`` call in its Annotated tail
    (or, for the factory shape, an inner-def that callers wrap in
    ``Depends(<factory>(...))``)."""
    defs = _collect_alias_definitions()
    offenders: list[str] = []
    for name, value in sorted(defs.items()):
        if value is None:
            offenders.append(
                f"{name}: DI alias name missing entirely from "
                f"web/dependencies.py — either the alias was deleted "
                f"OR its definition shape drifted away from the two "
                f"supported forms (Annotated assign, factory function)."
            )
            continue
        # Factory case: an inner FunctionDef stored as the value
        # sentinel. The alias itself doesn't have an Annotated tail;
        # callers do. Consider load-bearing SATISFIED here since the
        # factory produces a callable + callers wrap it in Depends()
        # per the docstring example.
        if isinstance(value, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        # Assign case: the RHS MUST be ``Annotated[T, ..., Depends(...)]``.
        if not _annotated_tail_has_depends(value):
            offenders.append(
                f"{name}: Annotated tail is missing a ``Depends(...)`` "
                f"call. A DI-annotation alias MUST wrap its resolver "
                f"in ``Depends()`` — otherwise FastAPI treats the "
                f"parameter as a query/body binding + the alias loses "
                f"its intercept + every consumer handler silently "
                f"downgrades to unauthenticated 200. Restore the "
                f"``Annotated[<T>, Depends(<resolver>)]`` shape."
            )
    assert not offenders, (
        "PUNCH-LIST #107 (STRUCTURAL) — DI-annotation-only handler "
        "load-bearing intercept guard tripped:\n\n"
        + "\n".join(f"  * {o}" for o in offenders)
    )


def test_pin_has_teeth_missing_depends_is_flagged():
    """Planted-bad-source teeth: an ``Annotated[<T>]`` without a
    ``Depends()`` in the tail MUST be rejected by
    :func:`_annotated_tail_has_depends`."""
    good_src = (
        "from typing import Annotated\n"
        "from fastapi import Depends\n"
        "def _resolver(): pass\n"
        "OwnedAccount = Annotated[int, Depends(_resolver)]\n"
    )
    bad_src = (
        "from typing import Annotated\n"
        "OwnedAccount = Annotated[int, None]\n"  # NO Depends() — degrade
    )
    good_tree = ast.parse(good_src)
    bad_tree = ast.parse(bad_src)
    good_rhs = next(
        n.value for n in good_tree.body
        if isinstance(n, ast.Assign) and n.targets[0].id == "OwnedAccount"  # type: ignore[union-attr]
    )
    bad_rhs = next(
        n.value for n in bad_tree.body
        if isinstance(n, ast.Assign) and n.targets[0].id == "OwnedAccount"  # type: ignore[union-attr]
    )
    assert _annotated_tail_has_depends(good_rhs) is True
    assert _annotated_tail_has_depends(bad_rhs) is False, (
        "Anti-vacuity: an ``Annotated[T, None]`` (Depends stripped) "
        "MUST fire the pin. If this test passes when it shouldn't, "
        "the walker has drifted and the load-bearing guard is "
        "silently green."
    )
