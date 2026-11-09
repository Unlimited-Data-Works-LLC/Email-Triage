"""N-255 R25 structural pin — record_provider_outcome funnel adoption ratchet (2026-07-03).

Census R25 discovered HIGH #2 (record_provider_outcome funnel adoption):
27+ operator-facing per-account provider surfaces call provider ops
(`search` / `fetch_message` / `move_message` / `archive` /
`list_folders` / `create_folder` / `register_watch` /
`renew_subscription`) WITHOUT calling the SSOT `record_provider_outcome`
on both success + exc edges. Consequence: an auth-revoked account's
auth_stale chip goes stale until next sweep; a healthy manual re-triage
click can't heal.

FULL migration is L-effort and needs SME judgment on the interprocedural
seam (some non-decisional render paths correctly do NOT touch the auth
lifecycle). This commit lands the growth-cap ratchet at baseline 47 —
NEW hand-rolls fire immediately; existing sites migrate via follow-up
per-file sweeps decrementing the baseline.

WHAT IT PINS (count-agnostic, growth-cap):

Any function `def <name>(...)` OR `async def <name>(...)` under
`src/email_triage/web/**/*.py` whose body calls
`<x>.(search|fetch_message|move_message|archive|list_folders|
create_folder|register_watch|renew_subscription)(...)` AND does NOT
call `record_provider_outcome(...)` counts. Total must be <= baseline.
"""
from __future__ import annotations

import ast

from _pin_harness import SRC_ROOT, iter_files, parse_module, relpath


_PROVIDER_OPS = frozenset({
    "search", "fetch_message", "move_message", "archive",
    "list_folders", "create_folder", "register_watch",
    "renew_subscription",
})

_MAX_BYPASS_FNS = 47  # 2026-07-03 N-255 R25 baseline (census run25 discovered).


def _fn_bypasses_ssot(fn: ast.AST) -> bool:
    touches_op = False
    touches_ssot = False
    for n in ast.walk(fn):
        if not isinstance(n, ast.Call):
            continue
        f = n.func
        if isinstance(f, ast.Attribute) and f.attr in _PROVIDER_OPS:
            touches_op = True
        # SSOT call — either `record_provider_outcome(...)` (bare Name)
        # or `<x>.record_provider_outcome(...)` (Attribute).
        if isinstance(f, ast.Name) and f.id == "record_provider_outcome":
            touches_ssot = True
        if isinstance(f, ast.Attribute) and f.attr == "record_provider_outcome":
            touches_ssot = True
    return touches_op and not touches_ssot


def test_record_provider_outcome_adoption_growth_cap():
    """Total functions in `src/email_triage/web/` that touch a provider
    op WITHOUT calling `record_provider_outcome` must be <= baseline.
    Migrations decrement; NEW hand-rolls fire."""
    web_root = SRC_ROOT / "web"
    total = 0
    per_file: dict[str, int] = {}
    for path in iter_files(web_root):
        rel = relpath(path)
        tree = parse_module(path)
        if tree is None:
            continue
        for fn in ast.walk(tree):
            if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if _fn_bypasses_ssot(fn):
                total += 1
                per_file[rel] = per_file.get(rel, 0) + 1
    assert total <= _MAX_BYPASS_FNS, (
        f"N-255 R25 record_provider_outcome funnel adoption ratchet: "
        f"bypass-fn count {total} > baseline {_MAX_BYPASS_FNS}. NEW "
        "provider-op call sites must call `record_provider_outcome` on "
        "both success and exc edges — otherwise an auth-revoked account's "
        "auth_stale chip stays cold until next sweep.\n\n"
        "Top-file counts:\n"
        + "\n".join(
            f"  {p}: {n}"
            for p, n in sorted(per_file.items(), key=lambda x: -x[1])[:15]
        )
    )


def test_record_provider_outcome_ssot_reachable():
    """Anti-vacuity: the SSOT must import."""
    from email_triage.web.app import record_provider_outcome
    assert callable(record_provider_outcome)
