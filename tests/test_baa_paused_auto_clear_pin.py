"""the backlog  (Census v3 finding #1) — Prime Directive  pin.

Structural: every SET side of the ``pause_style_distill_(account|contact)``
BAA-lapse flag has a REACHABLE CLEAR path — the bulk helpers
:func:`email_triage.db.style.unpause_baa_paused_style_distill_accounts` +
:func:`unpause_baa_paused_style_distill_contacts` — each with ≥1
non-test caller in ``src/``.

Motivating drift:
Before this fix, ``pause_style_distill_account`` was called on the
BAA-lapse path (``style_learning/distill_hipaa.py:508``) and the
per-row ``unpause_style_distill_account`` was reachable ONLY from
tests. A BAA-lapsed mailbox was PARKED permanently; the per-account
HIPAA overlay silently degraded to the global scrubber
(§164.308(b)(1) BAA-gate lifecycle / PD#18 SET-must-CLEAR gap).
Census v3 Discover surfaced the SSOT-orphan CLEAR (unpause_*
re-exported, 0 in-tree callers). This pin structurally forbids the
class of "SET-flag with no CLEAR path in src" for the BAA sub-shape.

Sibling gap (deferred per DA panel review, not a same-drive fold):
``pause_style_distill_account`` is ALSO SET on ``scrubber_fail``.
The CLEAR seam for that sub-shape is not obvious in the current
codebase (no operator-facing "scrubber fixed" event equivalent to
BAA-ack). Tracked as a follow-up task; do NOT re-defer.

Prime Directive #6: routes through the shared ``_pin_harness``
walker — no hand-rolled AST scaffolding.
"""
from __future__ import annotations

import ast

from _pin_harness import iter_src_files, parse_module, relpath


_BULK_CLEAR_HELPERS = frozenset({
    "unpause_baa_paused_style_distill_accounts",
    "unpause_baa_paused_style_distill_contacts",
    # DA panel F2 same-drive closure — scrubber_fail sub-shape CLEAR
    # from ``config_save`` on any classifier (backend, model) change.
    "unpause_scrubber_fail_style_distill_accounts",
    "unpause_scrubber_fail_style_distill_contacts",
})


def _walk_direct_callers(target_name: str) -> list[tuple[str, int]]:
    """Return (relpath, lineno) for every ``target_name(...)`` call site
    under ``src/email_triage/`` (excludes the def itself + tests).
    """
    out: list[tuple[str, int]] = []
    for path in iter_src_files():
        tree = parse_module(path)
        if tree is None or not isinstance(tree, ast.Module):
            continue
        rp = relpath(path)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func = node.func
                # Bare Name: `target_name(...)`
                if isinstance(func, ast.Name) and func.id == target_name:
                    out.append((rp, node.lineno))
                # Attribute chain: `x.target_name(...)`
                elif isinstance(func, ast.Attribute) and func.attr == target_name:
                    out.append((rp, node.lineno))
    return out


_DISPATCHER_NAMES = frozenset({
    # PD#2: interprocedural — cover the dispatcher-seam family that
    # hops a helper through a wrapper. The pin fires when ``target_name``
    # appears as an ``ast.Name`` argument OR is called inside a
    # ``lambda:`` body handed to any of these dispatchers.
    "db_call",         # canonical sync-to-worker hop for @db_write
    "to_thread",       # asyncio.to_thread(helper, ...) — sync fallback
    "run_in_executor", # loop.run_in_executor(None, helper, ...)
})


def _walk_dispatcher_argrefs(target_name: str) -> list[tuple[str, int]]:
    """Dispatcher-seam callers.

    DA F3 (PD#2 interprocedural): match ``target_name`` when it appears
    as (a) a positional ``ast.Name`` argument to a dispatcher call
    (``db_call(helper, …)``, ``asyncio.to_thread(helper, …)``,
    ``loop.run_in_executor(None, helper, …)``); OR (b) inside a
    ``lambda:`` body handed to a dispatcher (``db_call(lambda:
    helper(...))``).

    Both shapes appear elsewhere in the tree — see
    ``per_contact_hipaa.py`` for the direct-arg form and
    ``web/routers/backup.py``/``auth_keys.py`` for the lambda-wrap
    form. Missing either would leave a future ACK-path migration
    silently invisible to this pin.
    """
    out: list[tuple[str, int]] = []
    for path in iter_src_files():
        tree = parse_module(path)
        if tree is None or not isinstance(tree, ast.Module):
            continue
        rp = relpath(path)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            is_dispatcher = (
                (isinstance(func, ast.Name) and func.id in _DISPATCHER_NAMES)
                or (isinstance(func, ast.Attribute) and func.attr in _DISPATCHER_NAMES)
            )
            if not is_dispatcher:
                continue
            for arg in node.args:
                # Direct positional Name arg — the canonical shape.
                if isinstance(arg, ast.Name) and arg.id == target_name:
                    out.append((rp, node.lineno))
                    break
                # Lambda-body form — descend the body for a direct
                # ``target_name(...)`` call. `ast.walk` covers nested
                # ternaries and chained-attr calls without extra
                # scaffolding.
                if isinstance(arg, ast.Lambda):
                    for sub in ast.walk(arg.body):
                        if not isinstance(sub, ast.Call):
                            continue
                        f = sub.func
                        if isinstance(f, ast.Name) and f.id == target_name:
                            out.append((rp, node.lineno))
                            break
                        if isinstance(f, ast.Attribute) and f.attr == target_name:
                            out.append((rp, node.lineno))
                            break
    return out


def test_every_bulk_baa_clear_helper_has_a_non_test_caller():
    """PD#18 — SET on BackendBAARequiredError has a CLEAR side.

    Each helper in ``_BULK_CLEAR_HELPERS`` must appear at least once
    as a direct call OR a ``db_call`` argument in ``src/`` (excludes
    the def itself, which lives in ``src/email_triage/db/style.py``
    and is skipped by the caller enumeration — direct-call detection
    doesn't count a ``def`` node).
    """
    missing: list[str] = []
    for helper in sorted(_BULK_CLEAR_HELPERS):
        direct = _walk_direct_callers(helper)
        argref = _walk_dispatcher_argrefs(helper)
        # Skip the `def` site itself (it lives at db/style.py — the
        # direct-call walker sees `ast.Call`, not `ast.FunctionDef`, so
        # the def line is already excluded).
        callers = [
            (rp, ln) for rp, ln in (direct + argref)
            if not (rp == "db/style.py" and ln < 100)
        ]
        if not callers:
            missing.append(helper)
    assert not missing, (
        "the backlog  / PD#18: bulk BAA-CLEAR helper has NO reachable "
        "caller under ``src/email_triage/`` — the SET on "
        "BackendBAARequiredError does not have a matching CLEAR path, "
        "so a BAA-lapsed style_distill row is PARKED permanently and "
        "the per-account HIPAA overlay degrades to the global scrubber "
        "(§164.308(b)(1) BAA-gate lifecycle / PD#18 SET-must-CLEAR):\n" +
        "\n".join(f"  {name}" for name in missing)
    )


def test_helpers_defined_in_expected_ssot():
    """Sanity — the bulk clear helpers live in ``db/style.py``.

    Guards against a rename / relocation that would still leave both
    caller-check tests passing (helpers are IMPORTED somewhere, so
    the caller check finds SOMETHING) while the SSOT drifted. If a
    future migration moves them out of ``db/style.py``, this pin
    fails loud + the migration author updates the expected path.
    """
    import email_triage.db.style as style_mod
    for helper in sorted(_BULK_CLEAR_HELPERS):
        assert hasattr(style_mod, helper), (
            f"{helper} missing from ``email_triage.db.style`` — the "
            "PD#18 CLEAR SSOT has drifted. Restore or update this pin."
        )
