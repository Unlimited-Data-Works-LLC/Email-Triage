"""N-415 Drive-2 close-out #4 — `llm_health.py` translate_unreachable SSOT pin.

`llm_health.py:307` declares `translate_unreachable` the *"single source of
truth"* for translating raw HTTP connection errors into
`LLMBackendUnreachableError` — the exception the breaker (`llm_health`'s
own breaker-state helpers) watches for. Before  that translation was
copy-pasted into `OllamaClassifier` twice AND absent from the cloud
backends entirely, so a dead OpenAI / Gemini endpoint never flipped the
breaker. The SSOT is what closes that gap. Reliability-critical: a hand-
rolled twin translator with different error-class detection would silently
divergent recovery behavior across backends.

Pin locks TWO drift classes:

  1. **No local twin of the exception class** — `LLMBackendUnreachableError`
     is declared exactly once (at `llm_health.py:63`). A local
     `class LLMBackendUnreachableError(...)` re-declaration outside the
     SSOT would shadow the SSOT type for that module's `except` clauses —
     the breaker watches the SSOT type; a shadow silently no-op-catches
     it, and the dead endpoint never flips the breaker.

  2. **No local twin of the translator** — `def translate_unreachable(...)`
     (either as a plain function or a `@contextmanager` decorator applied
     to a function of that name) is declared exactly once. A local twin
     with different error-class matching would produce inconsistent
     recovery: some backends flip the breaker, others don't.

Import routing is NOT a check-item here because 22 src consumers reference
either name — an import-routing check would tax every one of them for
little added catch (the two twin-declaration checks above cover the actual
divergence vector). This is a deliberate scope choice per the "pin locks
divergence, not everything" principle in `docs/ssot-and-divergence-
playbook.md`.

Reuses `_pin_harness` per PD#6. Rot-guarded PD#7. Teeth via planted-fake
class + planted-fake function.
"""

from __future__ import annotations

import ast

from _pin_harness import (
    SRC_ROOT,
    iter_src_files,
    parse_module,
    relpath,
)


_SSOT_MODULE_REL = "llm_health.py"


# Empty on HEAD — no src module needs to declare its own copy of either
# name. Rot-guarded PD#7.
_LOCAL_DECL_ALLOW: dict[str, str] = {}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _module_declares_class(tree: ast.AST, name: str) -> bool:
    if not hasattr(tree, "body"):
        return False
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == name:
            return True
    return False


def _module_declares_function(tree: ast.AST, name: str) -> bool:
    """N-409 Drive-4 refinement (db-sme note #3): gate on module scope only
    — a nested inner-fn same-name is NOT a competing SSOT twin."""
    from _pin_harness import module_declares_function
    return module_declares_function(tree, name, module_scope_only=True)


def _module_aliases_name(tree: ast.AST, name: str) -> bool:
    """N-409 Drive-4 refinement (db-sme note #3, extended for N-415): a
    module-scope ``<name> = <Something>`` re-binding would silently divert
    that module's readers to a different symbol. Catches the alias-assign
    evasion (``LLMBackendUnreachableError = SomeOtherException``) that the
    function-def check misses. Only inspects direct children of the module."""
    if not isinstance(tree, ast.Module):
        return False
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for tgt in node.targets:
                if isinstance(tgt, ast.Name) and tgt.id == name:
                    return True
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            if node.target.id == name:
                return True
    return False


# ---------------------------------------------------------------------------
# Pin — no local twin of the exception class
# ---------------------------------------------------------------------------


def test_llm_backend_unreachable_error_declared_only_in_ssot():
    """`LLMBackendUnreachableError` is defined at `llm_health.py:63`. A src
    file that declares its own class of the same name would shadow the
    SSOT type for that module's readers — an `except LLMBackendUnreachable-
    Error` in a shadowed module silently catches the WRONG type and
    lets the dead-endpoint error escape past the breaker.
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
        if _module_declares_class(tree, "LLMBackendUnreachableError"):
            offenders.append(
                f"  {rel}  declares `class LLMBackendUnreachableError(...)` — "
                "the SSOT lives at `llm_health.py:63`; a local shadow "
                "silently no-op-catches the wrong type."
            )
        elif _module_aliases_name(tree, "LLMBackendUnreachableError"):
            # N-409 Drive-4 refinement (db-sme note #3): a module-scope
            # `LLMBackendUnreachableError = SomeOtherException` rebind would
            # silently divert that module's `except LLMBackendUnreachableError`
            # readers to the OTHER exception, letting a dead-endpoint error
            # escape the breaker just as effectively as a shadow class.
            offenders.append(
                f"  {rel}  module-scope-aliases `LLMBackendUnreachableError` — "
                "the SSOT type lives at `llm_health.py:63`; a rebind "
                "silently diverts local `except` handlers to a different type."
            )
    assert not offenders, (
        "N-415 LLMBackendUnreachableError local re-declaration drift — "
        "src file(s) declare a twin exception class of the SSOT name. "
        "Import the SSOT class from `email_triage.llm_health` instead.\n\n"
        + "\n".join(offenders)
    )


# ---------------------------------------------------------------------------
# Pin — no local twin of the translator context manager
# ---------------------------------------------------------------------------


def test_translate_unreachable_declared_only_in_ssot():
    """`translate_unreachable` is declared exactly once at
    `llm_health.py:292`. A local twin with different error-class detection
    would produce inconsistent recovery — some backends flip the breaker
    on a dead endpoint, others don't. The SSOT closes that gap; the pin
    locks it.
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
        if _module_declares_function(tree, "translate_unreachable"):
            offenders.append(
                f"  {rel}  declares `def translate_unreachable(...)` — "
                "the SSOT lives at `llm_health.py:292`; a local twin "
                "silently forks the translator."
            )
    assert not offenders, (
        "N-415 translate_unreachable local re-declaration drift — src "
        "file(s) declare a twin translator function of the SSOT name. "
        "Import the SSOT context manager from `email_triage.llm_health` "
        "instead.\n\n" + "\n".join(offenders)
    )


# ---------------------------------------------------------------------------
# Rot-guard PD#7 + teeth
# ---------------------------------------------------------------------------


def test_local_decl_allow_list_has_no_stale_entries():
    """`_LOCAL_DECL_ALLOW` entries MUST correspond to live src modules
    that STILL declare a twin of one of the SSOT names. Stale entries
    silently exempt a future violation."""
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
        has_class = _module_declares_class(tree, "LLMBackendUnreachableError")
        has_func = _module_declares_function(tree, "translate_unreachable")
        if not (has_class or has_func):
            stale.append(f"  {rel}  — no twin declaration on HEAD")
    assert not stale, (
        "N-415 rot-guard: `_LOCAL_DECL_ALLOW` has stale entries. Keep the "
        "allow-list honest (PD#7).\n\n" + "\n".join(stale)
    )


def test_pin_has_teeth():
    """Three planted-fake probes: (a) SSOT module declares both the class
    and the function at HEAD (else the pin is vacuously silent); (b)
    synthetic AST with a twin class flagged; (c) synthetic AST with a
    twin function flagged.
    """
    tree = parse_module(SRC_ROOT / _SSOT_MODULE_REL)
    assert tree is not None
    assert _module_declares_class(tree, "LLMBackendUnreachableError"), (
        "teeth: SSOT module no longer declares LLMBackendUnreachableError — "
        "pin is vacuously silent"
    )
    assert _module_declares_function(tree, "translate_unreachable"), (
        "teeth: SSOT module no longer declares translate_unreachable — "
        "pin is vacuously silent"
    )

    fake_class = ast.parse(
        "class LLMBackendUnreachableError(Exception):\n    pass\n"
    )
    assert _module_declares_class(fake_class, "LLMBackendUnreachableError"), (
        "teeth: class detector missed a planted twin"
    )

    fake_func = ast.parse(
        "def translate_unreachable(backend, base_url):\n    yield\n"
    )
    assert _module_declares_function(fake_func, "translate_unreachable"), (
        "teeth: function detector missed a planted twin"
    )
