"""N-338c R31 — AST name-resolution walker pin (operator directive).

Trust-repair fix-forward per operator directive 2026-07-05 + the backlog
 (TASK ). Replaces the false-comfort N-295 py_compile pin (which
only catches SyntaxError, not runtime NameError). Walks every function
body in `src/email_triage/*.py`; for each `Name.Load` node, verifies
the name resolves against one of:

  * function-local scope (params + `Name.Store` assigns inside the fn),
  * module-scope names (imports + module-level defs + module-level
    Assign targets),
  * Python builtins,
  * enclosing functions' scopes (closures),
  * names a top-level `globals().update(vars(<sibling>))` injects,
  * PEP 563 lazy annotations (module has the __future__ import).

An unresolved name is a runtime NameError waiting to fire (the class
N-295's py_compile pin was designed to catch but could not, because
py_compile is a syntax-only check that does not execute the module
body).

There is NO allow-list (the file-scope baseline was retired by
allow-list step 2): every file must resolve every Name.Load, and the
teeth tests below pin each scope rule.
"""
from __future__ import annotations

import ast
import builtins
import sys
from pathlib import Path

import pytest

from _pin_harness import SRC_ROOT, iter_files, parse_module, relpath



_BUILTINS: frozenset[str] = frozenset(dir(builtins))


def _module_scope_names(tree: ast.AST) -> set[str]:
    """Collect names bound at module scope: imports, def/class defs,
    top-level Assign targets, top-level AnnAssign targets."""
    names: set[str] = set()
    for node in ast.iter_child_nodes(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                # `import foo.bar` binds `foo` at module scope.
                bound = alias.asname or alias.name.split(".")[0]
                names.add(bound)
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                names.add(alias.asname or alias.name)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(node.name)
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                _collect_names_from_target(target, names)
        elif isinstance(node, ast.AnnAssign):
            _collect_names_from_target(node.target, names)
        elif isinstance(node, ast.If) or isinstance(node, ast.Try):
            # Inside if / try at module scope — walk one level down for
            # imports + assigns (common pattern for conditional imports).
            for sub in ast.walk(node):
                if isinstance(sub, ast.Import):
                    for alias in sub.names:
                        bound = alias.asname or alias.name.split(".")[0]
                        names.add(bound)
                elif isinstance(sub, ast.ImportFrom):
                    for alias in sub.names:
                        names.add(alias.asname or alias.name)
                elif isinstance(sub, ast.Assign):
                    for target in sub.targets:
                        _collect_names_from_target(target, names)
                elif isinstance(sub, ast.AnnAssign):
                    _collect_names_from_target(sub.target, names)
                elif isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    names.add(sub.name)
    return names


def _injected_module_names(tree: ast.AST, path: Path) -> set[str]:
    """Names a module gains from a top-level ``globals().update(...)``
    that snapshots a sibling module: ``from . import X`` followed by
    ``globals().update({n: v for n, v in vars(X).items() if ...})``
    (the ``web/routers/ui`` concern files, which cannot use ``import *``
    because it skips underscore names). The injected names are the
    module-scope names of sibling ``X.py`` (a name bound in X's body),
    minus dunders: resolved statically, so a name ``X`` does NOT bind
    is still reported. Only the exact shape above is honoured; any other
    ``globals()`` write adds nothing (N-338d, allow-list step 2).
    """
    relative_imports: dict[str, str] = {}
    for node in ast.iter_child_nodes(tree):
        if isinstance(node, ast.ImportFrom) and node.level == 1 and not node.module:
            for alias in node.names:
                relative_imports[alias.asname or alias.name] = alias.name
    injected: set[str] = set()
    for node in ast.iter_child_nodes(tree):
        if not (isinstance(node, ast.Expr) and isinstance(node.value, ast.Call)):
            continue
        call = node.value
        fn = call.func
        if not (
            isinstance(fn, ast.Attribute) and fn.attr == "update"
            and isinstance(fn.value, ast.Call)
            and isinstance(fn.value.func, ast.Name)
            and fn.value.func.id == "globals"
        ):
            continue
        for sub in ast.walk(call):
            if (
                isinstance(sub, ast.Call)
                and isinstance(sub.func, ast.Name) and sub.func.id == "vars"
                and len(sub.args) == 1 and isinstance(sub.args[0], ast.Name)
                and sub.args[0].id in relative_imports
            ):
                sibling = path.parent / f"{relative_imports[sub.args[0].id]}.py"
                sibling_tree = parse_module(sibling)
                if sibling_tree is not None:
                    injected |= {
                        n for n in _module_scope_names(sibling_tree)
                        if not n.startswith("__")
                    }
    return injected


def _collect_names_from_target(target: ast.AST, out: set[str]) -> None:
    """Recursively collect Name.Store ids from an assignment target."""
    if isinstance(target, ast.Name):
        out.add(target.id)
    elif isinstance(target, (ast.Tuple, ast.List)):
        for elt in target.elts:
            _collect_names_from_target(elt, out)
    elif isinstance(target, ast.Starred):
        _collect_names_from_target(target.value, out)
    # Attribute / Subscript targets don't BIND a new name.


def _fn_scope_names(fn: ast.AST, module_names: set[str]) -> set[str]:
    """Collect names bound within a function scope: params, local
    assigns, comprehension iter targets, exception-as bindings, walrus
    targets, nested fn/class defs. Includes `global` + `nonlocal`
    declarations (which reference module or enclosing scope).
    """
    names: set[str] = set()
    assert isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda))
    # Parameters.
    if isinstance(fn, ast.Lambda):
        args = fn.args
    else:
        args = fn.args
    for a in args.args + args.posonlyargs + args.kwonlyargs:
        names.add(a.arg)
    if args.vararg:
        names.add(args.vararg.arg)
    if args.kwarg:
        names.add(args.kwarg.arg)
    # Walk body.
    body_iter = fn.body if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)) else [fn.body]
    for stmt in body_iter:
        for sub in ast.walk(stmt):
            if isinstance(sub, ast.Assign):
                for target in sub.targets:
                    _collect_names_from_target(target, names)
            elif isinstance(sub, ast.AnnAssign):
                _collect_names_from_target(sub.target, names)
            elif isinstance(sub, ast.AugAssign):
                if isinstance(sub.target, ast.Name):
                    names.add(sub.target.id)
            elif isinstance(sub, ast.NamedExpr):
                if isinstance(sub.target, ast.Name):
                    names.add(sub.target.id)
            elif isinstance(sub, (ast.For, ast.AsyncFor)):
                _collect_names_from_target(sub.target, names)
            elif isinstance(sub, ast.With):
                for item in sub.items:
                    if item.optional_vars is not None:
                        _collect_names_from_target(item.optional_vars, names)
            elif isinstance(sub, ast.AsyncWith):
                for item in sub.items:
                    if item.optional_vars is not None:
                        _collect_names_from_target(item.optional_vars, names)
            elif isinstance(sub, ast.ExceptHandler):
                if sub.name is not None:
                    names.add(sub.name)
            elif isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                names.add(sub.name)
                # N-338d precision (2026-07-06): also harvest nested-fn
                # parameter names so uses inside the nested fn body don't
                # trip the OUTER fn's recursive body walk. The nested fn
                # is walked separately by the pin's ast.walk(tree) pass;
                # this only prevents the outer's recursion from flagging
                # the inner's params. Slight over-binding at outer scope
                # is per the pin's stated tolerance.
                if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    nested_args = sub.args
                    for a in (nested_args.args + nested_args.posonlyargs
                              + nested_args.kwonlyargs):
                        names.add(a.arg)
                    if nested_args.vararg:
                        names.add(nested_args.vararg.arg)
                    if nested_args.kwarg:
                        names.add(nested_args.kwarg.arg)
            elif isinstance(sub, ast.Lambda):
                # N-338d: same treatment for lambdas — a lambda's params
                # are bound in its own scope; outer's walk sees the body's
                # Name refs and must not flag them.
                for a in (sub.args.args + sub.args.posonlyargs
                          + sub.args.kwonlyargs):
                    names.add(a.arg)
                if sub.args.vararg:
                    names.add(sub.args.vararg.arg)
                if sub.args.kwarg:
                    names.add(sub.args.kwarg.arg)
            elif isinstance(sub, ast.Import):
                for alias in sub.names:
                    names.add(alias.asname or alias.name.split(".")[0])
            elif isinstance(sub, ast.ImportFrom):
                for alias in sub.names:
                    names.add(alias.asname or alias.name)
            elif isinstance(sub, ast.Global) or isinstance(sub, ast.Nonlocal):
                # Declared names are visible in fn scope.
                for n in sub.names:
                    names.add(n)
            elif isinstance(sub, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
                # Comprehension iter targets bind names in the
                # comprehension scope. For simplicity we surface them
                # at fn scope (the pin's false-positive tolerance is
                # OK with slight over-binding).
                for gen in sub.generators:
                    _collect_names_from_target(gen.target, names)
    return names


_NEW_SCOPE_NODES = (
    ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda,
    ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp,
)


def _direct_scope_names(fn: ast.AST) -> set[str]:
    """Names bound in `fn`'s OWN scope only: what a closure nested in `fn`
    can actually see. Unlike `_fn_scope_names` (which over-binds on
    purpose for the per-fn walk), this never descends into a nested
    def / class / lambda / comprehension, so a sibling nested function's
    local or a comprehension variable is not visible to a closure
    (panel r15, db-sme MUST 1: the closure rule fails OPEN otherwise).
    """
    names: set[str] = set()
    a = fn.args
    for arg in a.args + a.posonlyargs + a.kwonlyargs:
        names.add(arg.arg)
    for arg in (a.vararg, a.kwarg):
        if arg is not None:
            names.add(arg.arg)

    def walk(node: ast.AST) -> None:
        for sub in ast.iter_child_nodes(node):
            if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                names.add(sub.name)  # the def binds its name here; its body is its own scope
                continue
            if isinstance(sub, _NEW_SCOPE_NODES):
                continue
            if isinstance(sub, ast.Name) and isinstance(sub.ctx, ast.Store):
                names.add(sub.id)
            elif isinstance(sub, ast.ExceptHandler) and sub.name is not None:
                names.add(sub.name)
            elif isinstance(sub, ast.Import):
                for alias in sub.names:
                    names.add(alias.asname or alias.name.split(".")[0])
            elif isinstance(sub, ast.ImportFrom):
                for alias in sub.names:
                    names.add(alias.asname or alias.name)
            elif isinstance(sub, (ast.Global, ast.Nonlocal)):
                names.update(sub.names)
            walk(sub)

    for stmt in fn.body:
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(stmt.name)
            continue
        walk(ast.Module(body=[stmt], type_ignores=[]))
    return names


_MODULE_DUNDERS: frozenset[str] = frozenset({
    "__file__", "__path__", "__spec__", "__loader__", "__package__",
    "__class__",
})


def _lazy_annotation_name_ids(tree: ast.AST) -> frozenset[int]:
    """ids of Name nodes inside annotations, when the module has
    ``from __future__ import annotations`` (PEP 563: annotations are
    never evaluated, so an annotation-only name cannot raise NameError;
    e.g. ``typing.Any`` named only in a nested def's signature). Without
    the future import annotations ARE evaluated, so none are skipped."""
    lazy = any(
        isinstance(n, ast.ImportFrom) and n.module == "__future__"
        and any(a.name == "annotations" for a in n.names)
        for n in ast.iter_child_nodes(tree)
    )
    if not lazy:
        return frozenset()
    roots: list[ast.AST] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            a = node.args
            for arg in (a.args + a.posonlyargs + a.kwonlyargs
                        + [x for x in (a.vararg, a.kwarg) if x]):
                if arg.annotation is not None:
                    roots.append(arg.annotation)
            if not isinstance(node, ast.Lambda) and node.returns is not None:
                roots.append(node.returns)
        elif isinstance(node, ast.AnnAssign):
            roots.append(node.annotation)
    return frozenset(
        id(n) for r in roots for n in ast.walk(r) if isinstance(n, ast.Name)
    )


def _unresolved_names_in_tree(
    tree: ast.AST,
    module_names: set[str],
) -> list[tuple[str, int]]:
    """Scope-aware walk of a whole module (N-338d, allow-list step 2).

    Python resolves a name in a nested function against the ENCLOSING
    functions' scopes (closures) before the module. The per-fn walker
    below only knew the fn's own scope, so every closure reading an
    enclosing parameter or a function-local import was a false positive
    (the 'WALKER-FP' class that filled `_ALLOWLIST_UNRESOLVED_FILES`).
    This driver carries the union of the enclosing functions' scope
    names down into each nested function. A name no enclosing scope, the
    module or builtins binds is still reported.
    """
    found: list[tuple[str, int]] = []
    skip = _lazy_annotation_name_ids(tree)

    def visit(node: ast.AST, enclosing: frozenset[str]) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                found.extend(
                    _unresolved_names_in_fn(child, module_names, enclosing, skip)
                )
                visit(
                    child,
                    enclosing | frozenset(_direct_scope_names(child)),
                )
            else:
                visit(child, enclosing)

    visit(tree, frozenset())
    return found


def _unresolved_names_in_fn(
    fn: ast.AST,
    module_names: set[str],
    enclosing_names: frozenset[str] = frozenset(),
    skip_node_ids: frozenset[int] = frozenset(),
) -> list[tuple[str, int]]:
    """Return a list of (name, lineno) for every Name.Load in `fn`'s
    body that does NOT resolve against fn_scope | enclosing fn scopes |
    module_names | builtins."""
    fn_names = _fn_scope_names(fn, module_names)
    resolvable = (
        fn_names | enclosing_names | module_names | _BUILTINS | _MODULE_DUNDERS
    )
    unresolved: list[tuple[str, int]] = []
    body_iter = fn.body if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)) else [fn.body]
    for stmt in body_iter:
        for sub in ast.walk(stmt):
            if isinstance(sub, ast.Name) and isinstance(sub.ctx, ast.Load):
                if sub.id not in resolvable and id(sub) not in skip_node_ids:
                    unresolved.append((sub.id, sub.lineno))
    return unresolved


def _scan_source(source: str, path: Path | None = None) -> list[str]:
    """Unresolved names (in source order) the walker reports for `source`."""
    tree = ast.parse(source)
    module_names = _module_scope_names(tree)
    if path is not None:
        module_names |= _injected_module_names(tree, path)
    # De-duplicated: an outer fn's walk also covers nested bodies.
    return list(dict.fromkeys(
        n for n, _ in _unresolved_names_in_tree(tree, module_names)
    ))


def test_no_unresolved_names_in_src():
    """Every `src/email_triage` file resolves every Name.Load in every
    function body. There is no allow-list: the file-scope baseline
    (`_ALLOWLIST_UNRESOLVED_FILES`, 67 files) was retired by allow-list
    step 2 once the walker learned closure scope, `globals().update(
    vars(<sibling>))` injection and PEP 563 lazy annotations, and the two
    real NameErrors it hid were fixed (`log` -> `_log` in
    ``ui/profile.py`` sign-out-all and ``ui/push.py`` stop_watch). A new
    unresolved name is a real NameError, or a new walker false-positive
    shape: fix the code, or teach the walker one general rule with a
    teeth test below. Never re-add a file-scope allow-list.
    """
    violations: list[str] = []
    for path in iter_files(SRC_ROOT):
        rel = relpath(path)
        tree = parse_module(path)
        if tree is None:
            continue
        module_names = _module_scope_names(tree) | _injected_module_names(
            tree, path
        )
        unresolved_in_file = _unresolved_names_in_tree(tree, module_names)
        if unresolved_in_file:
            preview = ", ".join(
                f"{name}@{lineno}" for name, lineno in unresolved_in_file[:5]
            )
            violations.append(
                f"{rel}: {len(unresolved_in_file)} unresolved name(s) — "
                f"first {min(5, len(unresolved_in_file))}: {preview}"
            )
    assert not violations, (
        "N-338c: unresolved Name.Load reference(s). Fix the missing "
        "binding (forgotten import / typo / dead code), or add a general "
        "walker rule with a teeth test.\n\nViolations:\n  "
        + "\n  ".join(violations)
    )


# --- teeth: each walker rule resolves its shape AND still flags a real miss.

def test_teeth_closure_param_resolves_but_typo_is_flagged():
    ok = "def outer(db):\n    def inner():\n        return db\n    return inner\n"
    bad = "def outer(db):\n    def inner():\n        return dbb\n    return inner\n"
    assert _scan_source(ok) == []
    assert _scan_source(bad) == ["dbb"]


def test_teeth_closure_sees_enclosing_local_import_not_sibling_fn_local():
    ok = (
        "def outer():\n    from os import path\n"
        "    def inner():\n        return path\n    return inner\n"
    )
    # A name local to a SIBLING function is not visible: still flagged.
    bad = (
        "def a():\n    secret = 1\n    return secret\n"
        "def b():\n    return secret\n"
    )
    assert _scan_source(ok) == []
    assert _scan_source(bad) == ["secret"]


def test_teeth_closure_does_not_see_a_sibling_nested_fn_local():
    # `x` is local to sibling nested fn `a`; closure `b` cannot see it.
    bad = (
        "def outer():\n"
        "    def a():\n        x = 1\n        return x\n"
        "    def b():\n        return x\n"
        "    return a, b\n"
    )
    assert _scan_source(bad) == ["x"]


def test_teeth_closure_does_not_see_a_comprehension_variable():
    # `item` is bound only inside the comprehension's own scope.
    bad = (
        "def outer(xs):\n"
        "    ys = [item for item in xs]\n"
        "    def inner():\n        return item\n"
        "    return ys, inner\n"
    )
    assert _scan_source(bad) == ["item"]


def test_teeth_globals_update_vars_sibling_injection(tmp_path: Path):
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "_shared.py").write_text(
        "def _render():\n    pass\n_KEY = 1\n", encoding="utf-8"
    )
    mod = pkg / "concern.py"
    src = (
        "from . import _shared\n"
        "globals().update({_n: _v for _n, _v in vars(_shared).items()"
        " if not _n.startswith('__')})\n"
        "def handler():\n    _render()\n    return _KEY\n"
    )
    assert _scan_source(src, mod) == []
    # A name the sibling does NOT bind is still flagged.
    bad = src + "def other():\n    return _not_in_shared\n"
    assert _scan_source(bad, mod) == ["_not_in_shared"]
    # Without the injection statement nothing is injected.
    bare = "from . import _shared\ndef handler():\n    _render()\n"
    assert _scan_source(bare, mod) == ["_render"]


def test_teeth_lazy_annotation_only_under_future_import():
    sig = "def f():\n    def g(x) -> Missing:\n        return x\n    return g\n"
    lazy = "from __future__ import annotations\n" + sig
    ann = (
        "from __future__ import annotations\n"
        "def f():\n    v: Missing = 1\n    return v\n"
    )
    assert _scan_source(lazy) == []
    assert _scan_source(ann) == []
    # No future import: the annotation is evaluated at def time -> real error.
    assert _scan_source(sig) == ["Missing"]
    # A body use of the same name under the future import is still flagged.
    body = "from __future__ import annotations\ndef f():\n    return Missing\n"
    assert _scan_source(body) == ["Missing"]
