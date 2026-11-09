"""Punch 749 (consult #2, db MUST-2 / da MUST-1): no script captures one of the funnel's
exception names. A name may appear only as the type of an `except` handler (alone or in a tuple)
or as the operand of `raise` (`raise offload.X` / `raise offload.X(...)`).

`scripts/_ollama_offload_import.py` binds each exception name (`_ERRORS`) to a placeholder at
import and rebinds it to the loaded module's own class inside `load()`. A name read BEFORE the
first call that loaded the module (a module-level `E = offload.OllamaCallError`, a default
argument, a `from _ollama_offload_import import OllamaCallError`) keeps the placeholder for good,
and an `except E` built on it then matches nothing: the module's exception escapes unhandled.
An `except` expression is evaluated when an exception is already propagating, after the call
that loaded the module; `raise` runs only after a call has loaded it. Those two shapes are safe,
every other read is refused.

Count-agnostic: the name set is read from the funnel's own `_ERRORS` assignment (AST, never a
hard-coded list), the walk is the shared `iter_files` (it skips the retired-scripts directory),
and the funnel itself is the one file left out.
SCOPE CAVEAT: name-keyed on the module alias. A chain such as `mod.offload.OllamaCallError` is not
resolved, and neither is a second alias made by assignment (`o = offload`). Dynamic access is not
seen either: `getattr(offload, "OllamaCallError")` or a module bound through `importlib`. No live
site uses any of these; each would fail closed (the placeholder never matches).
"""
from __future__ import annotations

import ast

from _pin_harness import REPO_ROOT, iter_files, parse_module, parse_source, relpath

_SCRIPTS = REPO_ROOT / "scripts"
_FUNNEL = _SCRIPTS / "_ollama_offload_import.py"
_FUNNEL_MODULE = "_ollama_offload_import"


def _error_names() -> frozenset[str]:
    """The funnel's `_ERRORS`, read from its source (`_ERRORS = frozenset({...})`)."""
    for node in ast.walk(parse_module(_FUNNEL)):
        if (isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "_ERRORS"
                                                 for t in node.targets)):
            return frozenset(ast.literal_eval(node.value.args[0]))
    raise AssertionError("the funnel no longer assigns `_ERRORS = frozenset({...})`")


def _aliases(tree: ast.AST) -> set[str]:
    """Local names bound to the funnel module (`import m as a` / `from pkg import m [as a]`)."""
    out: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            out |= {a.asname or a.name for a in node.names if a.name == _FUNNEL_MODULE}
    return out


def _safe_use(node: ast.Attribute, parents: dict[ast.AST, ast.AST]) -> bool:
    """True if `node` is an except-handler type (alone or in a tuple/list) or a raise operand
    (`raise X` or `raise X(...)`)."""
    parent = parents.get(node)
    if isinstance(parent, (ast.Tuple, ast.List)):
        node, parent = parent, parents.get(parent)
    if isinstance(parent, ast.ExceptHandler):
        return parent.type is node
    if isinstance(parent, ast.Raise):
        return parent.exc is node
    return (isinstance(parent, ast.Call) and parent.func is node
            and isinstance(parents.get(parent), ast.Raise) and parents[parent].exc is parent)


def _captures(tree: ast.AST, names: frozenset[str]) -> list[tuple[int, str]]:
    """(line, what) for every read of an exception name that is not an except type or raise."""
    found: list[tuple[int, str]] = []
    aliases = _aliases(tree)
    parents = {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == _FUNNEL_MODULE:
            found += [(node.lineno, f"from-import of {a.name}") for a in node.names
                      if a.name in names or a.name == "*"]
        elif (isinstance(node, ast.Attribute) and node.attr in names and isinstance(node.ctx, ast.Load)
                and isinstance(node.value, ast.Name) and node.value.id in aliases
                and not _safe_use(node, parents)):
            found.append((node.lineno, f"{node.value.id}.{node.attr} read outside except/raise"))
    return found


def _scan(files) -> tuple[int, int, list[str]]:
    """(files scanned, files that import the funnel, findings)."""
    names = _error_names()
    scanned = importers = 0
    bad: list[str] = []
    for path in files:
        tree = parse_module(path)
        if tree is None:
            continue
        scanned += 1
        importers += bool(_aliases(tree))
        bad += [f"{relpath(path, REPO_ROOT)}:{ln} {what}" for ln, what in _captures(tree, names)]
    return scanned, importers, bad


def test_no_script_captures_a_funnel_exception_name():
    files = [p for p in iter_files(_SCRIPTS) if p != _FUNNEL]
    scanned, importers, bad = _scan(files)
    assert any("hooks" in p.relative_to(_SCRIPTS).parts for p in files), "the walk skipped scripts/hooks/"
    assert importers >= 1, f"{scanned} files scanned, none imports the funnel: the scan is not reaching its callers"
    assert not bad, (
        "a funnel exception name is read outside an `except` type or a `raise`. The name is a "
        "placeholder until the first call loads the module, so a captured copy never matches what "
        "the module raises. Use `except offload.X:` / `raise offload.X(...)` directly:\n  "
        + "\n  ".join(bad)
    )


def test_the_exception_name_set_is_read_from_the_funnel():
    names = _error_names()
    assert names and all(n.startswith("Ollama") for n in names), names


def test_the_capture_detector_has_teeth():
    names = _error_names()
    imp = f"import {_FUNNEL_MODULE} as offload\n"

    def hits(src: str) -> list[tuple[int, str]]:
        return _captures(parse_source(src), names)

    for n in sorted(names):
        assert len(hits(f"from {_FUNNEL_MODULE} import {n}")) == 1, n
        assert len(hits(f"from {_FUNNEL_MODULE} import {n} as E")) == 1, n
        assert len(hits(imp + f"E = offload.{n}")) == 1, n  # module-level capture
        assert len(hits(imp + f"def f():\n    e = offload.{n}\n    return e")) == 1, n  # function-level
        assert len(hits(imp + f"g(offload.{n})")) == 1, n  # passed as an argument
        assert len(hits(imp + f"def f(e=offload.{n}):\n    pass")) == 1, n  # default argument
        assert len(hits(imp + f"T = (offload.{n},)")) == 1, n  # a tuple that is not an except type
        assert len(hits(imp + f"isinstance(x, offload.{n})")) == 1, n
        assert hits(imp + f"try:\n    f()\nexcept offload.{n}:\n    pass") == [], n
        assert hits(imp + f"try:\n    f()\nexcept offload.{n} as e:\n    pass") == [], n
        assert hits(imp + f"try:\n    f()\nexcept (offload.{n}, ValueError):\n    pass") == [], n
        assert hits(imp + f"raise offload.{n}('x')") == [], n
        assert hits(imp + f"raise offload.{n}") == [], n
        assert hits(f"def f(offload):\n    return offload.{n}") == [], n  # not the funnel's alias
    first = sorted(names)[0]
    assert len(hits(f"from {_FUNNEL_MODULE} import *")) == 1
    assert len(hits(f"from scripts import {_FUNNEL_MODULE} as o\nE = o.{first}")) == 1
    assert hits(imp + f"try:\n    f()\nexcept offload.{first}:\n    pass\nE = offload.{first}") == [
        (6, f"offload.{first} read outside except/raise")]
