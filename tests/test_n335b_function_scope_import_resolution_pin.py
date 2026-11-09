"""N-335b R31 tail — function-scope INTERNAL-import module-path resolution.

the backlog . Complementary to
``test_n335b_function_scope_shadow_import_pin.py`` (SHADOW class — the
function-scope name is ALSO imported at module scope) and to
``test_n338c_ast_name_resolution_pin.py`` (Name.Load resolution). This
pin catches a third false-comfort class: a function-scope
``from email_triage.X.Y import Z`` (or ``import email_triage.X.Y``)
where the module path ``email_triage.X.Y`` does NOT exist in the tree.

Motivating incident:
``incident_2026-06-11_topic_digest_dead_in_prod`` — a prod entry-point
did a function-scope import of a submodule that had been renamed /
removed. Top-level ``py_compile`` (N-295) never touches the function
body, so the ImportError only surfaced when the runtime path was
hit; 3 ImportErrors landed in prod before EXECUTION coverage caught
them. N-338c catches unresolved ``Name.Load`` but says nothing about
whether the IMPORTED MODULE PATH itself resolves.

Scope:

* Every function-scope ``ast.Import`` / ``ast.ImportFrom`` under
  ``src/email_triage/`` whose target is an ``email_triage.*`` module
  (absolute) OR a relative import (``level > 0``).
* TYPE_CHECKING-guarded imports are exempt (annotation-only, never
  executed at runtime).
* External imports (``json``, ``os``, ``fastapi``, …) are exempt —
  the incident class is INTERNAL drift, and external-dep breakage is
  caught at install / import time by pytest collection.

Behaviour: fail-CLOSED — baseline at HEAD is EMPTY (zero unresolved
sites verified 2026-07-11). Any function-scope internal import whose
target module path does not resolve against the tree-derived module
set is a FAIL. No allow-list; a new offender is always a bug.

Prime Directive #6 compliance: converges onto the shared
``_pin_harness`` walker (parse_module + iter_src_files + relpath +
SRC_ROOT) — no hand-rolled AST scaffolding.
"""
from __future__ import annotations

import ast

from _pin_harness import SRC_ROOT, iter_src_files, parse_module, relpath


def _legal_modules() -> frozenset[str]:
    """Every ``email_triage.*`` dotted path present in the tree.

    Includes package `__init__` targets (dotted path without the
    ``__init__`` suffix) plus every intermediate parent package.
    Routes the src walk through the shared ``iter_src_files`` per
    Prime Directive #6 (converge on the shared harness walker; the
    meta-pin ``test_pin_harness_adoption`` catches hand-rolled walks).
    """
    names: set[str] = {"email_triage"}
    for p in iter_src_files():
        rel = p.relative_to(SRC_ROOT)
        parts = list(rel.with_suffix("").parts)
        if parts and parts[-1] == "__init__":
            parts = parts[:-1]
        dotted = "email_triage" + ("." + ".".join(parts) if parts else "")
        names.add(dotted)
        for i in range(1, len(parts)):
            names.add("email_triage." + ".".join(parts[:i]))
    return frozenset(names)


def _is_type_checking(test: ast.expr) -> bool:
    if isinstance(test, ast.Name) and test.id == "TYPE_CHECKING":
        return True
    if isinstance(test, ast.Attribute) and test.attr == "TYPE_CHECKING":
        return True
    return False


def _under_type_checking(ancestors: list[ast.AST]) -> bool:
    return any(
        isinstance(a, ast.If) and _is_type_checking(a.test)
        for a in ancestors
    )


def _containing_package(source_relpath: str) -> list[str]:
    """Return the containing package's dotted parts.

    ``actions/foo.py`` → ``["email_triage", "actions"]``
    ``actions/__init__.py`` → ``["email_triage", "actions"]``
    ``__init__.py`` → ``["email_triage"]``
    ``foo.py`` → ``["email_triage"]``
    """
    parts = source_relpath.split("/")
    if parts and parts[-1] == "__init__.py":
        parts = parts[:-1]
    else:
        parts = parts[:-1]
    return ["email_triage", *parts]


def _resolve_import_from(
    node: ast.ImportFrom, source_relpath: str,
) -> str | None:
    """Return the dotted module path the ImportFrom targets, or None
    if it is not an ``email_triage.*`` target (external / stdlib)."""
    if node.level > 0:
        pkg = _containing_package(source_relpath)
        # Ascend (level - 1) segments; level=1 stays in pkg.
        up = node.level - 1
        if up > 0:
            if up >= len(pkg):
                return None
            pkg = pkg[:-up]
        target = ".".join(pkg)
        if node.module:
            target = f"{target}.{node.module}"
        return target
    mod = node.module or ""
    if mod == "email_triage" or mod.startswith("email_triage."):
        return mod
    return None


def _resolve_import(node: ast.Import) -> list[str]:
    """Return ``email_triage.*`` module paths this Import targets."""
    out: list[str] = []
    for alias in node.names:
        name = alias.name
        if name == "email_triage" or name.startswith("email_triage."):
            out.append(name)
    return out


def _walk_unresolved() -> list[tuple[str, int, str]]:
    legal = _legal_modules()
    out: list[tuple[str, int, str]] = []
    for path in iter_src_files():
        tree = parse_module(path)
        if tree is None or not isinstance(tree, ast.Module):
            continue
        rp = relpath(path)

        def visit(node: ast.AST, ancestors: list[ast.AST], in_func: bool) -> None:
            for child in ast.iter_child_nodes(node):
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    visit(child, ancestors + [child], True)
                elif isinstance(child, ast.ImportFrom):
                    if in_func and not _under_type_checking(ancestors):
                        target = _resolve_import_from(child, rp)
                        if target is not None and target not in legal:
                            out.append((rp, child.lineno, target))
                elif isinstance(child, ast.Import):
                    if in_func and not _under_type_checking(ancestors):
                        for target in _resolve_import(child):
                            if target not in legal:
                                out.append((rp, child.lineno, target))
                else:
                    visit(child, ancestors + [child], in_func)

        visit(tree, [], False)
    return out


def test_no_unresolved_function_scope_internal_imports():
    """Every function-scope ``email_triage.*`` import resolves.

    Baseline at N-335b tail landing (2026-07-11): ZERO offenders.
    Fail-CLOSED — no allow-list; any offender is a defect.
    """
    unresolved = _walk_unresolved()
    assert not unresolved, (
        "Function-scope internal imports resolve to a module path that "
        "does NOT exist under ``src/email_triage/``. This is the "
        "class ``incident_2026-06-11_topic_digest_dead_in_prod`` "
        "surfaced in prod: top-level py_compile never touched the "
        "function body, and the import only failed when the runtime "
        "path was hit. Fix: correct the import path (a rename / move / "
        "removal), or move the import to module scope where the "
        "top-level pin will catch it.\n" +
        "\n".join(
            sorted(f"  {rp}:{lineno} -> {target}"
                   for rp, lineno, target in unresolved)
        )
    )


def test_legal_modules_set_is_nonempty():
    """Sanity guard — a walker that computes an EMPTY legal-module set
    would classify every internal import as unresolved (false-fail)
    or, worse, produce an unbounded empty set that turns the pin
    fail-OPEN via zero iterations. Guards against a walker mis-
    implementation on a future refactor of ``SRC_ROOT``.
    """
    legal = _legal_modules()
    assert "email_triage" in legal
    # Sanity — expect ≥ 50 modules at HEAD (231 at 2026-07-11).
    assert len(legal) >= 50, (
        f"_legal_modules() returned only {len(legal)} entries; "
        "expected ≥ 50. Likely SRC_ROOT / walker defect."
    )
