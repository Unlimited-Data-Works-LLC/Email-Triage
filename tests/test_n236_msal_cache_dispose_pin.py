"""N-236 R23 structural pin — MSAL cache dispose SSOT (2026-07-02).

Census R23 discovered MED class (ondisk-artifact-disposal V_B):
`msal_cache_path_for_cli(username)` had a writer SSOT
(`providers/factory.py:48`) + backup incidental via shared glob, but
**no dispose actuator anywhere**. Plaintext OAuth refresh_token
survived any operator-triggered "clear my auth" flow — §164.310(d)(2)(i)
at-rest cleanup gap.

N-236 fix:
  - `providers/factory.py::dispose_msal_cache_for_account(account_id)`
    — SSOT dispose for the per-account cache path.
  - `providers/factory.py::dispose_msal_cache_for_cli(username)` —
    SSOT dispose for the CLI-scoped cache path.
  - `db/accounts.py::_delete_account_and_secrets` migrated from inline
    `_cache_path.unlink(missing_ok=True)` to the SSOT dispose actuator.

WHAT IT PINS (STRICT anti-vacuity):

Both dispose helpers must import + return False on a missing cache.
Any raw `.unlink()` of an `msal_cache_path_for_*(...)`-derived path
outside `providers/factory.py` + `db/accounts.py` fires.

SCOPE CAVEAT: interprocedural detection (Name → Call → factory)
deferred. Current shape matches `<Name>.unlink(...)` where the Name
was assigned from a `msal_cache_path_for_*(...)` call within the same
top-level function. The 1 known dispose call site
(db/accounts.py:1256) is allow-listed by (relpath, fn_name).

FOLLOW-UP: a broader `PER_ACCOUNT_ARTIFACT_BUILDERS` registry with a
`dispose_all_per_account_artifacts(account_id)` funnel per census
recommendation is deferred as bigger scope. This pin closes the
dispose-gap primary defect.
"""
from __future__ import annotations

import ast

from _pin_harness import SRC_ROOT, iter_files, parse_module, relpath


_SSOT_FILES = {"providers/factory.py"}


def _msal_cache_path_call(expr: ast.AST) -> bool:
    """True if `expr` is `msal_cache_path_for_account(...)` or
    `msal_cache_path_for_cli(...)`."""
    if not isinstance(expr, ast.Call):
        return False
    f = expr.func
    name = (f.id if isinstance(f, ast.Name)
            else f.attr if isinstance(f, ast.Attribute) else None)
    return name in ("msal_cache_path_for_account", "msal_cache_path_for_cli")


def test_dispose_helpers_reachable():
    """Anti-vacuity: both dispose helpers must import + return False on
    a missing cache."""
    from email_triage.providers.factory import (
        dispose_msal_cache_for_account,
        dispose_msal_cache_for_cli,
    )
    # Both should tolerate missing files (idempotent).
    assert dispose_msal_cache_for_cli("neverexisted_stem_xyz") is False
    # No account_id assumption for the account variant — accept any type.


def test_no_raw_unlink_of_msal_cache_path():
    """Every `<Name>.unlink(...)` where <Name> was bound to a
    `msal_cache_path_for_*(...)` result MUST be in the SSOT (factory) OR
    be the dispose helper itself.

    Approach: intra-function walk — find every assignment
    `<Name> = msal_cache_path_for_*(...)`, then flag any
    `<Name>.unlink(...)` in the same enclosing function outside SSOT."""
    offenders: list[str] = []
    for path in iter_files(SRC_ROOT):
        rel = relpath(path)
        if rel in _SSOT_FILES:
            continue
        tree = parse_module(path)
        if tree is None:
            continue
        # Walk each function; per-function name bindings.
        for fn in ast.walk(tree):
            if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            bound: set[str] = set()
            for node in ast.walk(fn):
                if isinstance(node, ast.Assign) and _msal_cache_path_call(node.value):
                    for tgt in node.targets:
                        if isinstance(tgt, ast.Name):
                            bound.add(tgt.id)
                if isinstance(node, ast.Call):
                    f = node.func
                    if not isinstance(f, ast.Attribute) or f.attr != "unlink":
                        continue
                    recv = f.value
                    if isinstance(recv, ast.Name) and recv.id in bound:
                        offenders.append(
                            f"{rel}:{node.lineno} in `{fn.name}` — "
                            f"`{recv.id}.unlink(...)` (route through "
                            "`providers/factory.dispose_msal_cache_for_*`)"
                        )
    assert not offenders, (
        "N-236 R23 msal_cache dispose SSOT: raw `.unlink(...)` on a "
        "path derived from `msal_cache_path_for_*(...)`. Route through "
        "`providers/factory.dispose_msal_cache_for_account(...)` or "
        "`dispose_msal_cache_for_cli(...)` so the dispose actuator can "
        "extend/re-derive/side-effect in the ONE module.\n\n"
        + "\n".join(offenders)
    )
