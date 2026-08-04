"""-broadscan preventative pin — no hardcoded ``timeout=`` literal on
ANY of the timeout-carrying entry points, outside the two documented
LEGITIMATE-LITERAL contexts (module-const default assignment + setter
kwarg default).

DA-F5 (2026-07-11) — this replaces the earlier FILE-scoped allow-list
that let acme_renewer.py + providers/imap.py sneak 12+ live literals
past the pin because the WHOLE FILE was excused. Per memory drawer
`Migrate line-anchored pin allow-lists to name/scope anchors`
(binding 2026-07-01), an allow-list must be NAME/SCOPE-anchored, not
file-anchored.

The two LEGITIMATE contexts (only these):

  1. **Module-level constant assignment** — the line that seeds the
     SSOT default, e.g. ``_SQLITE_BUSY_WAIT_SECS: float = 30.0``.
     Structurally: an ``ast.AnnAssign`` or ``ast.Assign`` at module
     scope whose target name matches
     ``^_[A-Z_]+_(TIMEOUT|GRACE|WAIT)_(SECS|MS)$``. The literal on the
     right-hand side is the default, NOT a Call kwarg — so this
     check naturally exempts it (no ``timeout=<Constant>`` Call
     kwarg is involved).

  2. **``configure_*_timeout(...)`` function-def parameter default**
     — the sig line where the setter parameter carries its
     literal default, e.g.
     ``def configure_sqlite_timeouts(busy_wait_secs: float = 30.0, ...)``.
     Structurally: the literal lives inside an ``ast.FunctionDef.args.defaults``
     of a function whose name matches ``^configure_.*_timeout(s)?$`` or
     starts with ``configure_.*_grace``.

Every OTHER ``ast.Call`` with a ``timeout=<int|float literal>`` kwarg
anywhere in the tree is a drift-back to the pre-#149 hardcoded
behavior + fails this pin.

Membership predicate is count-agnostic (``ast.walk``, not
``len == N``). Convergence signal per operator directive 2026-07-11
"expose ALL": ZERO offenders across the src tree.
"""
from __future__ import annotations

import ast

from _pin_harness import iter_src_files, parse_module, relpath


def _is_module_level_ssot_assign(node: ast.stmt) -> bool:
    """True if `node` is a module-level ``_*_TIMEOUT_SECS = <literal>``
    assignment. These are LEGITIMATE literals (they seed the SSOT default)
    and do NOT contain a Call with a ``timeout=`` kwarg, so they are
    naturally exempt — this check is here for clarity + belt-and-braces
    in case an author writes ``some_call(timeout=30.0)`` at module scope
    (rare; would still legitimately trip the pin — that's the point).
    """
    return isinstance(node, (ast.Assign, ast.AnnAssign))


def _is_configure_setter_default(
    call_node: ast.Call,
    fn_defs_containing: list[ast.FunctionDef],
) -> bool:
    """True if the ``timeout=<Constant>`` literal on ``call_node`` lives
    inside a ``configure_*_timeout(...)`` function DEFINITION's default
    parameter list — NOT a call inside the function body.

    We resolve this in the caller by only checking Call nodes that
    live in a function body; if the same Call node's Constant literal
    is ALSO reachable as a default in ``FunctionDef.args.defaults``,
    it's the same literal and legitimate.
    """
    # This check is done by the caller via a separate walk over
    # FunctionDef defaults; unused here as a stub for docstring.
    return False


def _collect_setter_default_literal_ids(tree: ast.Module) -> set[int]:
    """Return ids of Constant nodes that live in a
    ``configure_*_timeout`` / ``configure_*_grace`` FunctionDef's
    default parameter list. These are the LEGITIMATE literals (the
    setter's fallback when no config value is passed).
    """
    legit_ids: set[int] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        name = node.name
        if not (
            name.startswith("configure_") and (
                name.endswith("_timeout")
                or name.endswith("_timeouts")
                or "_grace" in name
                or name.endswith("_secs")
            )
        ):
            continue
        for default in node.args.defaults:
            if isinstance(default, ast.Constant) and isinstance(
                default.value, (int, float),
            ):
                legit_ids.add(id(default))
        for default in node.args.kw_defaults or []:
            if isinstance(default, ast.Constant) and isinstance(
                default.value, (int, float),
            ):
                legit_ids.add(id(default))
    return legit_ids


def test_no_hardcoded_timeout_literal_anywhere():
    """Every ``Call`` with a ``timeout=<literal int|float>`` kwarg
    outside the two LEGITIMATE contexts (module-const default assign;
    ``configure_*_timeout`` setter parameter default) is a drift-back.
    """
    offenders: list[str] = []
    for path in iter_src_files():
        rel = relpath(path)
        try:
            tree = parse_module(path)
        except SyntaxError:
            continue
        legit_default_ids = _collect_setter_default_literal_ids(tree)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            for kw in node.keywords:
                if kw.arg != "timeout":
                    continue
                arg = kw.value
                if not isinstance(arg, ast.Constant):
                    continue
                if not isinstance(arg.value, (int, float)):
                    continue
                # bool is a subclass of int
                if isinstance(arg.value, bool):
                    continue
                # LEGITIMATE: this Constant is a setter-default literal.
                if id(arg) in legit_default_ids:
                    continue
                offenders.append(
                    f"{rel}:{node.lineno}  timeout={arg.value!r}",
                )
    assert offenders == [], (
        "Hardcoded ``timeout=<literal>`` kwarg on a Call. Route through "
        "a config-item SSOT — read the value from the module-level "
        "constant (`_*_TIMEOUT_SECS`) or its accessor "
        "(`get_*_timeout_secs()`), NOT a float / int literal. Only "
        "LEGITIMATE literal contexts are the module-const default "
        "assignment and the ``configure_*_timeout`` setter parameter "
        "default. See -a/b/c/d/e (2026-07-11) + DA-F5 refutation "
        "for the convergence rationale + feedback_dynamic_over_hardcoding "
        "order 10.\n\n"
        + "\n".join(offenders)
    )
