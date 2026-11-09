"""Structural pin (census wf_56d1585d 2026-07-09 MED-UX ): every
mutation seam that touches ``email_accounts.config_json`` /
``.provider_type`` / ``.is_active`` MUST also flush the 5-min-TTL
provider-labels cache via ``invalidate_cache_for_account(account_id)``.

What this defends
-----------------
The picker-staleness class the census flagged (`provider_labels`
cache-invalidation gap):

- A mutation on ``email_accounts`` (activate / deactivate / config
  change / provider_type flip) changes what labels the picker should
  show but does NOT drop the 5-min-TTL entries the picker reads.
- The picker serves stale labels for up to 5 minutes after the change.
- Prior sibling `set_account_active` (db/accounts.py:723) landed
  WITHOUT the invalidator; the census caught the gap in the same
  mutation family delete_email_account already covered.

Count-agnostic + interprocedural
--------------------------------
Per ``pattern_count_agnostic_structural_drift_catch.md`` — asserts a
PROPERTY over every mutation-fn (any body containing an
``email_accounts SET (config_json|provider_type|is_active)`` UPDATE
must ALSO call ``invalidate_cache_for_account`` somewhere in the same
body), not a count. Interprocedural in the R2/R5b sense: the pin
inspects the SEAM (the fn that owns the UPDATE), not a call graph.

Scope + allow-list
------------------
Scoped to ``src/email_triage/**/*.py`` via the shared harness.
``_ALLOWED_UNINVALIDATED_MUTATIONS`` is the explicit, documented set of
``(relpath, funcname)`` exemptions for mutation-fns that legitimately
skip invalidation (migration helpers that run at startup before the
picker is queryable; config-scrub helpers that only touch
client_id/secret and never affect labels).

Meta-drift guarantee (PD#7)
---------------------------
Routes the walk through ``_pin_harness.iter_src_files`` +
``parse_module`` + ``relpath`` + ``innermost_fn_at_lineno`` so the pin
cannot drift in its scoping (per the run15 meta-pin covenant).
"""
from __future__ import annotations

import ast
import re

from _pin_harness import (
    innermost_fn_at_lineno,
    iter_src_files,
    parse_module,
    parse_source,
    relpath,
)


# (relpath, funcname) exemptions — legit mutation-fns that skip
# invalidation. Each MUST carry a one-line justification.
_ALLOWED_UNINVALIDATED_MUTATIONS: set[tuple[str, str]] = {
    # web/migrations.py — schema/data migrations run at startup before
    # the picker cache exists; all UPDATE email_accounts SET config_json
    # touches migrate label-adjacent JSON keys en masse. Invalidation
    # would be a no-op at that phase (no cache entries yet).
    ("web/migrations.py", "_v6_backfill_account_tz_default"),
    ("web/migrations.py", "_v20_sent_folder_override_string_to_list"),
    #  R32 CLOSED (2026-07-09 late-late-session): the temporary
    # ratchet-forward reversal at 57a1a3ba for `set_account_active` +
    # `update_email_account` is REMOVED same-commit as this batch lands
    # the invalidate_cache_for_account calls in both fns.
}


# The mutation SQL shape the pin flags. Case-insensitive; matches the
# canonical form the codebase uses (`UPDATE email_accounts SET
# <col> = ?`). Multi-column UPDATEs matching ANY of the three trigger.
_MUTATION_RE = re.compile(
    r"UPDATE\s+email_accounts\s+SET\b[^;]*"
    r"\b(?:config_json|provider_type|is_active)\s*=",
    re.IGNORECASE | re.DOTALL,
)


def _fn_calls(fn_node: ast.AST, target_names: set[str]) -> bool:
    """True when ``fn_node`` body contains a Call to any name in
    ``target_names`` (bare Name or Attribute attr)."""
    for sub in ast.walk(fn_node):
        if not isinstance(sub, ast.Call):
            continue
        f = sub.func
        name = (
            f.id if isinstance(f, ast.Name)
            else f.attr if isinstance(f, ast.Attribute) else None
        )
        if name in target_names:
            return True
    return False


def _fn_has_mutation(fn_node: ast.AST) -> bool:
    """True when ``fn_node`` body contains an
    ``UPDATE email_accounts SET (config_json|provider_type|is_active)``
    string literal (the SQL is a string constant to
    ``conn.execute(...)``)."""
    for sub in ast.walk(fn_node):
        if isinstance(sub, ast.Constant) and isinstance(sub.value, str):
            if _MUTATION_RE.search(sub.value):
                return True
    return False


def _scan() -> list[tuple[str, str, int]]:
    """Repo-wide scan. Returns ``[(relpath, funcname, lineno), ...]`` for
    every fn that mutates ``email_accounts`` on a label-affecting column
    but does NOT call ``invalidate_cache_for_account`` — minus the
    allow-listed exemptions.
    """
    invalidator_names = {"invalidate_cache_for_account"}
    offenders: list[tuple[str, str, int]] = []
    for path in iter_src_files():
        tree = parse_module(path)
        if tree is None:
            continue
        rp = relpath(path)
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if not _fn_has_mutation(node):
                continue
            if _fn_calls(node, invalidator_names):
                continue
            if (rp, node.name) in _ALLOWED_UNINVALIDATED_MUTATIONS:
                continue
            offenders.append((rp, node.name, node.lineno))
    return offenders


def test_no_uninvalidated_email_accounts_mutation():
    """Every ``UPDATE email_accounts SET config_json|provider_type|
    is_active`` in a fn body must be paired with a call to
    ``invalidate_cache_for_account`` in the same fn (interprocedural
    at the seam).

    Failure prints ``relpath:fn:lineno`` per violation.
    """
    offenders = _scan()
    if offenders:
        lines = [
            f"  {rp}:{ln} in `{fn}`"
            for rp, fn, ln in offenders
        ]
        raise AssertionError(
            "provider_labels cache-invalidation gap — mutation of "
            "email_accounts (config_json|provider_type|is_active) in a "
            "fn body that does NOT call `invalidate_cache_for_account` "
            "in the same body. Picker will serve up to 5 min of stale "
            "labels for that account. Census wf_56d1585d 2026-07-09 "
            "MED-UX #322.\n\n"
            + "\n".join(lines)
        )


def test_pin_has_teeth():
    """Detector flags a planted bad shape and passes a clean one."""
    bad = (
        "def flip_active(conn, account_id, active):\n"
        "    conn.execute(\n"
        "        'UPDATE email_accounts SET is_active = ? WHERE id = ?',\n"
        "        (int(active), account_id),\n"
        "    )\n"
    )
    good = (
        "def flip_active(conn, account_id, active):\n"
        "    conn.execute(\n"
        "        'UPDATE email_accounts SET is_active = ? WHERE id = ?',\n"
        "        (int(active), account_id),\n"
        "    )\n"
        "    invalidate_cache_for_account(int(account_id))\n"
    )
    bad_tree = parse_source(bad)
    bad_fn = next(
        n for n in ast.walk(bad_tree)
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
    )
    good_tree = parse_source(good)
    good_fn = next(
        n for n in ast.walk(good_tree)
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
    )
    assert _fn_has_mutation(bad_fn), "detector missed a planted mutation"
    assert not _fn_calls(bad_fn, {"invalidate_cache_for_account"}), \
        "planted bad fixture would be a false-positive"
    assert _fn_has_mutation(good_fn), "good fixture must contain mutation"
    assert _fn_calls(good_fn, {"invalidate_cache_for_account"}), \
        "good fixture must call the invalidator"


def test_allow_list_is_grounded():
    """Every allow-list entry must correspond to a real mutating fn at
    HEAD — stale exemption silently widens the net."""
    live: set[tuple[str, str]] = set()
    for path in iter_src_files():
        tree = parse_module(path)
        if tree is None:
            continue
        rp = relpath(path)
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if _fn_has_mutation(node):
                live.add((rp, node.name))
    stale = _ALLOWED_UNINVALIDATED_MUTATIONS - live
    assert not stale, (
        f"Stale _ALLOWED_UNINVALIDATED_MUTATIONS entries (no matching "
        f"HEAD mutation fn — delete): {sorted(stale)}"
    )


def test_ssot_is_reachable():
    """Anti-vacuity: `invalidate_cache_for_account` is a real callable
    exported from `provider_labels`."""
    from email_triage.providers.provider_labels import (
        invalidate_cache_for_account,
    )
    assert callable(invalidate_cache_for_account)
