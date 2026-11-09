"""Structural pin — every first-party ``from email_triage… import NAME`` resolves.

Catches the bug class that shipped  Topic Digest dead to prod (2026-06-11):
the back-scan's default fetcher did ``from email_triage.web.triage_runner_bulk
import _create_provider_from_account``, but that name is only a *function-local*
import inside triage_runner_bulk — never a module-level attribute. The statement
raised ``ImportError`` the first time the generator was iterated, and the drain
swallowed it → every real back-scan failed with zero hits. ``py_compile`` and
module-import both PASS for an in-*function* import like that; nothing caught it
until a real run.

This pin is count-agnostic and repo-wide: via the shared ``_pin_harness`` walk
(R5b) it visits every ``src/email_triage`` module's AST, finds every absolute
``from email_triage.<mod> import <name>`` (module-level AND function-local), and
asserts each ``<name>`` resolves as either a module-level attribute of ``<mod>``
or a submodule ``<mod>.<name>``. A name that only exists as a local import
somewhere inside ``<mod>`` does NOT resolve and fails the pin.
"""

from __future__ import annotations

import ast
import importlib

from _pin_harness import relpath, walk_src


def _name_resolves(module_name: str, name: str) -> bool:
    """True iff ``name`` is importable from ``module_name`` — either a
    module-level attribute or a submodule. Importing the target module is
    safe: the whole package is already importable (the suite imports it)."""
    try:
        mod = importlib.import_module(module_name)
    except Exception:
        # The referenced module itself doesn't import — a different defect
        # class (optional-dep / genuine import error). Don't mask it as an
        # unresolved-NAME failure here; let the owning test surface it.
        return True
    try:
        if hasattr(mod, name):
            return True
    except Exception:
        # A module-level __getattr__ (PEP 562) that raises for this name —
        # treat as unresolved and let the submodule check decide.
        pass
    # Maybe it's a submodule not yet imported as an attribute.
    try:
        importlib.import_module(f"{module_name}.{name}")
        return True
    except Exception:
        return False


def _collect_unresolved() -> list[str]:
    failures: list[str] = []
    for _path, rel, tree in walk_src():
        for node in ast.walk(tree):
            if not isinstance(node, ast.ImportFrom):
                continue
            # Absolute first-party imports only. Relative (level>0) and
            # third-party imports are out of scope (optional-dep guards etc.).
            if node.level != 0 or not node.module:
                continue
            if not node.module.startswith("email_triage"):
                continue
            for alias in node.names:
                if alias.name == "*":
                    continue
                if not _name_resolves(node.module, alias.name):
                    failures.append(
                        f"src/email_triage/{rel}:{node.lineno} — 'from "
                        f"{node.module} import {alias.name}' does NOT resolve "
                        f"({alias.name} is not a module-level attribute or "
                        f"submodule of {node.module}). If it is only a "
                        f"function-local import inside {node.module}, import it "
                        f"from the module that actually exports it."
                    )
    return failures


def test_all_first_party_imports_resolve():
    failures = _collect_unresolved()
    assert not failures, (
        "Unresolvable first-party import(s) found — these raise ImportError "
        "the moment the enclosing code runs, even though py_compile passes:\n  "
        + "\n  ".join(failures)
    )


def test_pin_detects_known_bad_import():
    """Teeth check (anti-vacuous, PD#16). The resolver MUST return False for the
    exact pre-fix bad imports that shipped  Topic Digest dead to prod —
    ``_create_provider_from_account`` / ``_build_classifier_from_config`` are
    only function-local imports inside ``triage_runner_bulk``, never module-level
    attributes — and True for the corrected source. If the False assertions ever
    flip, the pin has gone blind and would pass the original bug."""
    # The corrected source resolves.
    assert _name_resolves(
        "email_triage.web.routers.ui", "_create_provider_from_account") is True
    assert _name_resolves(
        "email_triage.web.routers.ui", "_build_classifier_from_config") is True
    # The known-bad pre-fix source does NOT — this is what the pin must catch.
    assert _name_resolves(
        "email_triage.web.triage_runner_bulk",
        "_create_provider_from_account") is False
    assert _name_resolves(
        "email_triage.web.triage_runner_bulk",
        "_build_classifier_from_config") is False
