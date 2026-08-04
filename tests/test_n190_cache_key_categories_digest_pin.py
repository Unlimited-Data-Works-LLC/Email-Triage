"""N-190 R20_21 structural pin — cache-key taxonomy-completeness.

Census run20 R20_21: `make_cache_key` (line 510) and `cache_key_for_message`
(line 1054, a thin wrapper) are LEGACY — kept for back-compat with pre-
2026-05-13 tests. Neither includes `_categories_digest` in its payload → any
classification change with new categories doesn't invalidate the cached
entries built by them (structurally taxonomy-blind — stale-classification
recall).

The new SSOT `make_outer_cache_key` DOES include `_categories_digest(...)`
in payload (line 487). This pin asserts: every function named `*cache_key*`
in `cache/classification.py` (outer/inner/aggregate builder) EITHER
references `_categories_digest` OR is on `_LEGACY_ALLOW` with a reason.
A NEW cache-key builder that forgets to fold in `_categories_digest`
fails the pin.

`_LEGACY_ALLOW` currently contains the two legacy functions with a
"legacy pre-taxonomy — tests only" reason. Follow-up N-190b: delete
`make_cache_key` + `cache_key_for_message` and the tests pinning them
(requires porting tests to `make_outer_cache_key`).
"""
from __future__ import annotations

import ast

from _pin_harness import SRC_ROOT, parse_module


_LEGACY_ALLOW: frozenset[str] = frozenset({
    "make_cache_key",           # LEGACY pre-taxonomy — pre-2026-05-13; tests only
    "cache_key_for_message",    # LEGACY wrapper of make_cache_key — tests only
})


def _cache_key_builders(tree: ast.AST) -> list[ast.FunctionDef]:
    """Every `def make_*cache_key*` / `def *_cache_key*` in the module."""
    out = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if "cache_key" in node.name and not node.name.startswith("_"):
                out.append(node)
    return out


def _references_categories_digest(fn: ast.AST) -> bool:
    """True if `fn` folds _categories_digest — either DIRECTLY (a call/name
    reference) OR INTERPROCEDURALLY (delegates to `make_outer_cache_key`,
    which is the canonical builder that folds it)."""
    for sub in ast.walk(fn):
        if isinstance(sub, ast.Call):
            f = sub.func
            called = f.id if isinstance(f, ast.Name) else (
                f.attr if isinstance(f, ast.Attribute) else None)
            if called == "_categories_digest":
                return True
            # Interproc: delegating to make_outer_cache_key (which folds it)
            if called == "make_outer_cache_key":
                return True
        if isinstance(sub, ast.Name) and sub.id == "_categories_digest":
            return True
    return False


def test_every_cache_key_builder_folds_in_categories_digest():
    """N-190 R20_21: every cache-key builder in cache/classification.py MUST
    reference `_categories_digest` in its body — else it's structurally
    taxonomy-blind (stale-classification recall). Legacy builders on
    `_LEGACY_ALLOW` are grandfathered with a documented reason + follow-up
    N-190b for deletion."""
    tree = parse_module(SRC_ROOT / "cache" / "classification.py")
    assert tree is not None
    builders = _cache_key_builders(tree)
    assert len(builders) >= 2, f"too few cache-key builders found ({len(builders)}) — walker mis-wired"
    offenders = []
    for fn in builders:
        if fn.name in _LEGACY_ALLOW:
            continue
        if not _references_categories_digest(fn):
            offenders.append(f"{fn.name}:{fn.lineno}")
    assert not offenders, (
        f"N-190 R20_21: cache-key builder(s) {offenders} do NOT reference "
        "`_categories_digest` — structurally taxonomy-blind. Fold "
        "`_categories_digest(categories)` into the payload (as "
        "`make_outer_cache_key` does at line 487) OR add the name to "
        "`_LEGACY_ALLOW` with a documented follow-up delete horizon."
    )


def test_legacy_allow_entries_still_live():
    """Every `_LEGACY_ALLOW` entry MUST still be a real cache-key builder
    in the module — a stale entry means the legacy function was already
    deleted and the allow-list is out of date (a coverage-lie)."""
    tree = parse_module(SRC_ROOT / "cache" / "classification.py")
    assert tree is not None
    live_builders = {fn.name for fn in _cache_key_builders(tree)}
    stale = _LEGACY_ALLOW - live_builders
    assert not stale, (
        f"N-190 R20_21: `_LEGACY_ALLOW` entries {stale} no longer match a "
        "live cache-key builder — remove them from the allow-list."
    )


def test_pin_has_teeth():
    bad = ast.parse("""
def make_new_cache_key(sender, subject, model):
    payload = f"{sender}|{subject}|{model}"
    return hashlib.sha256(payload.encode()).hexdigest()
""")
    builders = _cache_key_builders(bad)
    assert builders and not _references_categories_digest(builders[0])

    good = ast.parse("""
def make_new_cache_key(sender, subject, model, categories):
    payload = f"{sender}|{subject}|{model}|{_categories_digest(categories)}"
    return hashlib.sha256(payload.encode()).hexdigest()
""")
    builders = _cache_key_builders(good)
    assert builders and _references_categories_digest(builders[0])
