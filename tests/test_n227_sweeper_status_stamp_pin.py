"""N-227 R22 structural pin — sweeper _tick must stamp app.state.<name>_status (2026-07-02).

Census R22 (run22 discovered class — MED, /admin observability):
`sweeper _status stamp on failure` — 12 supervised loops never stamp
`app.state.<name>_status` at all. `/admin` observability is blind to:
backup, sent-mail-capture, log-prune, digest senders, ACME, O365 renewer,
unified-poll outcomes. Structural enumeration at HEAD (2026-07-02)
authoritatively found 14 `_tick` shapes tree-wide, 5 stamp + 9 don't.

WHAT IT PINS (count-agnostic, tree-wide):

Every module-level `async def _tick` nested inside a sweep entrypoint
MUST contain at least one `app.state.<name>_status = <value>` assign
inside its body (a stamp on success). The 9 currently-unstamped sites
are allow-listed at HEAD. Migration commits decrement the allow-list;
new `_tick` shapes fire the pin.

SCOPE CAVEAT (honest): the pin currently enforces STAMP-ON-SUCCESS
only. Full census recommendation (stamp on BOTH success AND failure
edges via `try/finally` + `stamp_sweep_status(app, name, *, ok,
summary, error=None)` funnel) is a follow-up broader migration —
requires touching every sweep body. This pin caps growth + prevents
NEW blind sweepers.
"""
from __future__ import annotations

import ast

from _pin_harness import SRC_ROOT, iter_files, parse_module, relpath


# N-227c R22 STRICT-0 CONVERGED: all 9 sweepers now stamp their
# `app.state.<name>_status`. `_ALLOW` intentionally empty; every future
# `async def _tick` shape must stamp OR add an explicit entry
# with a justification.
_ALLOW: frozenset[tuple[str, str]] = frozenset()


def _is_status_stamp(node: ast.AST) -> bool:
    """True if `node` is `app.state.<x>_status = ...`."""
    if not isinstance(node, ast.Assign):
        return False
    for tgt in node.targets:
        if isinstance(tgt, ast.Attribute) and tgt.attr.endswith("_status"):
            v = tgt.value
            if isinstance(v, ast.Attribute) and v.attr == "state":
                return True
    return False


def _find_nested_ticks(outer: ast.AST) -> list[ast.AsyncFunctionDef]:
    ticks: list[ast.AsyncFunctionDef] = []
    for inner in ast.walk(outer):
        if inner is outer:
            continue
        if isinstance(inner, ast.AsyncFunctionDef) and inner.name == "_tick":
            ticks.append(inner)
    return ticks


def test_sweeper_ticks_stamp_app_state_status():
    """Every nested `async def _tick` in a supervised sweep MUST stamp
    `app.state.<name>_status = <value>` in its body (currently-unstamped
    sites are allow-listed at HEAD)."""
    offenders: list[str] = []
    for path in iter_files(SRC_ROOT):
        rel = relpath(path)
        tree = parse_module(path)
        if tree is None:
            continue
        for outer in ast.walk(tree):
            if not isinstance(outer, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for tick in _find_nested_ticks(outer):
                stamps = sum(1 for n in ast.walk(tick) if _is_status_stamp(n))
                if stamps == 0 and (rel, outer.name) not in _ALLOW:
                    offenders.append(
                        f"{rel}:{tick.lineno}  {outer.name}::_tick "
                        "has no `app.state.<name>_status = ...` stamp"
                    )
    assert not offenders, (
        "N-227 R22 sweeper _status stamp: every `async def _tick` inside a "
        "supervised sweep entrypoint must stamp `app.state.<name>_status = "
        "<value>` at least once in its body — otherwise `/admin` is blind to "
        "the sweeper's outcome. If this is a new sweeper, wire the stamp OR "
        "add the (relpath, outer_fn_name) entry to `_ALLOW` explaining why "
        "(e.g. sweeper tracks state via a different channel).\n\n"
        + "\n".join(offenders)
    )


def test_allow_list_entries_are_real():
    """Anti-vacuity: every _ALLOW entry must correspond to a REAL sweeper
    at HEAD. If a sweeper is deleted or renamed, the stale allow-list
    entry hides a NEW missing-stamp regression that copies its name."""
    real: set[tuple[str, str]] = set()
    for path in iter_files(SRC_ROOT):
        rel = relpath(path)
        tree = parse_module(path)
        if tree is None:
            continue
        for outer in ast.walk(tree):
            if not isinstance(outer, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if _find_nested_ticks(outer):
                real.add((rel, outer.name))
    stale = _ALLOW - real
    assert not stale, (
        "N-227 R22 anti-vacuity: `_ALLOW` entries that no longer correspond "
        "to a real sweeper _tick shape at HEAD (probable rename/delete). "
        "Remove them so a future sweeper of the same name doesn't inherit "
        "a stale exception.\n\n"
        + "\n".join(f"  {rel}::{fn}" for rel, fn in stale)
    )
