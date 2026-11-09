"""the backlog  — shared predicates for the canonical-email SSOT
pin family (per Prime Directive #6: pins obey the SSOT rule; two
mirrored pins WILL drift).

Callers:
* ``tests/test_canonical_email_ssot_pin.py`` — scope ``web/routers/``.
* ``tests/test_canonical_email_ssot_providers_pin.py`` — scope
  ``providers/`` + ``style_learning/`` + ``actions/`` + ``web/``
  (with ``web/routers/`` exempted).

Both pins share the SAME predicate — the ONLY axis of variation is
scope + allow-list. Extracting keeps the predicate semantics
convergent under a single edit surface (a tightening at N-317 or
similar lands in ONE file; both pins pick it up).
"""
from __future__ import annotations

import ast


# Identifier substrings that mark a receiver as "email/address-shape". A
# ``.strip().lower()`` chain on a value that does NOT touch any of these
# is almost never a canonical-email defect — categories, labels, rule
# slugs, tags, sort keys, etc. all have legitimate reasons to lowercase.
#
# DA-fold R3 (2026-07-09) — dropped bare "actor" from the marker set.
# ``actor`` on its own catches ``actor_user_id`` (numeric), ``actor_type``
# (str enum), ``actor_context`` (dict) — none of which are address-
# shape. ``actor_email`` / ``actor_address`` are covered by the
# ``email`` / ``address`` markers. ``from_addr`` / ``to_addr`` are
# kept for the ``mail_headers`` routing keys they name.
EMAIL_SHAPE_MARKERS: tuple[str, ...] = (
    "email", "address", "alias", "recipient", "sender",
    "from_addr", "to_addr", "user_email",
)


def expr_names(node: ast.AST):
    """Yield every identifier substring appearing in ``node`` — union of
    every ``ast.Name.id`` / ``ast.Attribute.attr`` / string-literal
    subtree, lowercased, so a case-insensitive substring test suffices.
    """
    for sub in ast.walk(node):
        if isinstance(sub, ast.Name):
            yield sub.id.lower()
        elif isinstance(sub, ast.Attribute):
            yield sub.attr.lower()
        elif isinstance(sub, ast.Constant) and isinstance(sub.value, str):
            # A ``.get("email")`` / ``body["email"]`` — the LITERAL key
            # names the shape as clearly as an identifier does.
            yield sub.value.lower()


def is_email_shape(receiver: ast.AST) -> bool:
    """True when ``receiver`` (the expr on which ``.strip().lower()`` is
    called) contains ANY identifier / literal string matching one of the
    email-shape markers. Case-insensitive substring test."""
    for name in expr_names(receiver):
        for marker in EMAIL_SHAPE_MARKERS:
            if marker in name:
                return True
    return False


def is_lower_call(node: ast.AST) -> bool:
    """True when ``node`` is ``<expr>.lower()``."""
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "lower"
        and not node.args
        and not node.keywords
    )


def is_strip_lower_chain(node: ast.AST) -> bool:
    """True when ``node`` is ``<expr>.strip().lower()`` — the exact
    census-flagged shape. The ``.strip()`` is the tell: naked
    ``.lower()`` on already-canonical data is defensive; a
    ``.strip()`` implies raw user input still.
    """
    if not is_lower_call(node):
        return False
    inner = node.func.value  # type: ignore[union-attr]
    return (
        isinstance(inner, ast.Call)
        and isinstance(inner.func, ast.Attribute)
        and inner.func.attr == "strip"
        and not inner.args
        and not inner.keywords
    )


def fn_calls_canonical_email(fn_node: ast.AST) -> bool:
    """True when the enclosing fn body references ``canonical_email(...)``.

    Presence of the SSOT call anywhere in the fn implies the author knows
    the class — the .strip().lower() may be intentional post-canonicalize
    (a redundant safety belt on already-canonical data).
    """
    for sub in ast.walk(fn_node):
        if not isinstance(sub, ast.Call):
            continue
        f = sub.func
        name = (
            f.id if isinstance(f, ast.Name)
            else f.attr if isinstance(f, ast.Attribute) else None
        )
        if name == "canonical_email":
            return True
    return False
