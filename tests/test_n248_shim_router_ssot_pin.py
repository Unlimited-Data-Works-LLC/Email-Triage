"""N-248 R24 structural pin — router `_get_<templates|db|config|secrets>` shim growth-cap (2026-07-03).

Census R24 discovered LOW (local `_get_templates` router shims): 14
shim funcs (4× `_get_templates` + 4× `_get_db` + 4× `_get_config` +
2× `_get_secrets`) across 4 non-UI routers each returning
`request.app.state.<attr>` — pure re-exports of the SSOTs in
`web/app.py::get_{templates,db,config,secrets}`. Any SSOT-side change
(cache decoration, kwargs) is INVISIBLE through the shims.

N-248 lands the growth-cap ratchet at baseline 14. Migration to the
SSOT (delete shims + inline `request.app.state.<attr>` OR import
`web.app.get_<attr>`) is a mechanical follow-up — pin prevents new
shims tree-wide.

WHAT IT PINS:

Every top-level `def _get_(templates|db|config|secrets)(request)`
outside `web/app.py` + `web/acme_job_state.py` (uses a distinct
no-arg `_get_db()` for the async lease loop) counts. Total must not
exceed `_MAX_SHIMS`.
"""
from __future__ import annotations

import ast

from _pin_harness import SRC_ROOT, iter_files, parse_module, relpath


_MAX_SHIMS = 14  # 2026-07-03 N-248 R24 baseline (post-census R24).
_SSOT_FILES = {"app.py"}  # web/app.py owns the SSOTs.
_ALLOW_FILES = {
    # acme_job_state uses a distinct no-arg `_get_db()` for the async
    # lease loop context — different signature, different concern.
    "web/acme_job_state.py",
}
_SHIM_NAMES = {"_get_templates", "_get_db", "_get_config", "_get_secrets"}


def _count_shims_in_tree(tree: ast.AST) -> int:
    n = 0
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        if node.name not in _SHIM_NAMES:
            continue
        # Must take `request` as first arg — signals the shim shape
        # (`request.app.state.<attr>`), not the acme_job_state no-arg
        # variant.
        args = node.args.args
        if not args or args[0].arg != "request":
            continue
        n += 1
    return n


def test_shim_router_ssot_growth_cap():
    """Tree-wide `_get_(templates|db|config|secrets)(request)` shims
    outside `web/app.py` must not exceed baseline. NEW shims fire —
    route through `web.app.get_<attr>` or `request.app.state.<attr>`."""
    total = 0
    per_file: list[tuple[str, int]] = []
    for path in iter_files(SRC_ROOT):
        rel = relpath(path)
        if rel.split("/")[-1] in _SSOT_FILES:
            continue
        if rel in _ALLOW_FILES:
            continue
        tree = parse_module(path)
        if tree is None:
            continue
        n = _count_shims_in_tree(tree)
        if n > 0:
            total += n
            per_file.append((rel, n))
    assert total <= _MAX_SHIMS, (
        f"N-248 R24 shim-router-SSOT ratchet: `_get_(templates|db|"
        f"config|secrets)(request)` shim count {total} > baseline "
        f"{_MAX_SHIMS}. NEW shims must route through "
        "`web.app.get_<attr>` (import + call) or inline "
        "`request.app.state.<attr>` — a private per-router shim "
        "hides SSOT changes.\n\n"
        + "\n".join(f"{p}: {n}" for p, n in per_file)
    )
