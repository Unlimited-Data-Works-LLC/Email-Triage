"""N-416 Drive-2 close-out #5 — `llm_truncation.py` detect+surface SSOT pin.

`llm_truncation.py:1` declares itself the *"single source of truth for
detecting + surfacing LLM output truncation"*. Every LLM backend
caps generation (`max_tokens` / `num_predict` / `maxOutputTokens`); a cap
hit silently corrupts the output (a cut JSON blob, an unterminated string).
The SSOT concentrates the detect + surface logic so a second detector in
another backend can't drift and mask the truncation.

Two divergence vectors:

  1. **No local twin of the detector** — `is_llm_truncated(body, family)`
     is declared exactly once at `llm_truncation.py:116`. A local
     `def is_llm_truncated(...)` outside the SSOT would silently fork the
     detection logic (a family with the "wrong" schema check would
     under-detect and let a truncated JSON parse to a malformed classify
     verdict).

  2. **No local twin of the surface helper** — `warn_if_llm_truncated`
     at `:125` is the caller-facing wrapper that logs + counts + warns.
     A local twin would fork the surface (a backend that logs but doesn't
     increment `llm_truncated_1h` fools the health signal into steady-
     state while truncation is silently happening).

Reuses `_pin_harness` per PD#6. Rot-guard PD#7 on `_LOCAL_DECL_ALLOW`.
Teeth via planted-fake function decl.
"""

from __future__ import annotations

import ast

from _pin_harness import (
    SRC_ROOT,
    iter_src_files,
    module_declares_function,
    parse_module,
    relpath,
)


_SSOT_MODULE_REL = "llm_truncation.py"
_SSOT_NAMES = ("is_llm_truncated", "warn_if_llm_truncated")


_LOCAL_DECL_ALLOW: dict[str, str] = {}


def _module_declares_function(tree: ast.AST, name: str) -> bool:
    """N-409 Drive-4 refinement: gate on module scope only (db-sme note #3)
    — a nested inner-fn same-name is NOT a competing SSOT twin."""
    return module_declares_function(tree, name, module_scope_only=True)


def test_truncation_detector_declared_only_in_ssot():
    """`is_llm_truncated` + `warn_if_llm_truncated` are each declared
    exactly once at the SSOT. A local twin in another src module silently
    forks the detect/surface logic — a backend with the wrong schema
    check under-detects; a backend that doesn't increment the counter
    fools the health signal into steady-state while truncation is silently
    happening.
    """
    offenders: list[str] = []
    for path in iter_src_files():
        rel = relpath(path)
        if rel == _SSOT_MODULE_REL:
            continue
        if rel in _LOCAL_DECL_ALLOW:
            continue
        tree = parse_module(path)
        if tree is None:
            continue
        for name in _SSOT_NAMES:
            if _module_declares_function(tree, name):
                offenders.append(
                    f"  {rel}  declares `def {name}(...)` — SSOT lives at "
                    "`llm_truncation.py`; local twin forks detect/surface."
                )
    assert not offenders, (
        "N-416 llm_truncation local re-declaration drift — src file(s) "
        "declare a twin of an SSOT function name. Import from "
        "`email_triage.llm_truncation` instead.\n\n" + "\n".join(offenders)
    )


def test_local_decl_allow_list_has_no_stale_entries():
    stale: list[str] = []
    for rel in sorted(_LOCAL_DECL_ALLOW):
        path = SRC_ROOT / rel
        if not path.exists():
            stale.append(f"  {rel}  — file missing")
            continue
        tree = parse_module(path)
        if tree is None:
            stale.append(f"  {rel}  — did not parse")
            continue
        has_twin = any(_module_declares_function(tree, n) for n in _SSOT_NAMES)
        if not has_twin:
            stale.append(f"  {rel}  — no twin declaration on HEAD")
    assert not stale, (
        "N-416 rot-guard: `_LOCAL_DECL_ALLOW` has stale entries (PD#7)."
        "\n\n" + "\n".join(stale)
    )


def test_pin_has_teeth():
    """SSOT still declares both names + synthetic twin flagged."""
    tree = parse_module(SRC_ROOT / _SSOT_MODULE_REL)
    assert tree is not None
    for name in _SSOT_NAMES:
        assert _module_declares_function(tree, name), (
            f"teeth: SSOT no longer declares `{name}` — pin is vacuously silent"
        )
    fake = ast.parse("def is_llm_truncated(body, family):\n    return False\n")
    assert _module_declares_function(fake, "is_llm_truncated"), (
        "teeth: function-declaration detector missed a planted twin"
    )
