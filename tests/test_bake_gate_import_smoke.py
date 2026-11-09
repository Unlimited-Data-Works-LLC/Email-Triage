"""Punch 415 — import smoke for the N-432 Path-3 bake-gate step scripts.

``scripts/n432-path3-bake-step*.py`` run INSIDE the freshly built image, against the live PHI
DB, in the middle of a deploy. ``tests/test_deploy_script.py::_run_bake_body`` stubs all of
them as EMPTY files, so a renamed helper (``from email_triage.db._engine import <name>``)
survives every unit test and dies at deploy time with an ImportError. Two such deploy-time
failures already happened on 2026-07-21 (step 3: a stale import, then a wrong symbol).

This pin proves, WITHOUT running any step (so no DB work and no ``sys.exit``), that every
import in every bake step resolves against the real tree:

* ``email_triage.*``: the module file exists under ``src/email_triage`` AND, for
  ``from M import n``, ``n`` is bound at module level in ``M`` (def / class / assignment /
  import) or is a submodule of ``M``. Static (AST), so it needs no optional dependency.
* stdlib: imported for real, ``n`` must be an attribute or a submodule.
* third party: only the reviewed names in ``_THIRD_PARTY``; checked with ``find_spec`` when
  installed (the CI image has it, a bare dev box may not).
* ``import *``, relative imports, an unparseable script: fail CLOSED (cannot be proven).

Count-agnostic: the scripts are discovered by glob, never counted. Residual: a dynamic
``importlib.import_module("...")`` string is invisible to an AST walk (none at HEAD).
"""

from __future__ import annotations

import ast
import importlib
import importlib.util
import sys
from pathlib import Path

import pytest

from _pin_harness import REPO_ROOT, SRC_ROOT, iter_files, parse_module, parse_source

#: Reviewed third-party top-level modules a bake step may import (the image's DB driver).
_THIRD_PARTY: frozenset[str] = frozenset({"sqlcipher3"})
_PKG = "email_triage"
_MAX_STAR_DEPTH = 3


def bake_step_scripts() -> list[Path]:
    return list(iter_files(REPO_ROOT, "n432-path3-bake-step*.py", subdir="scripts"))


def _module_file(src_root: Path, dotted: str) -> Path | None:
    """``email_triage.a.b`` -> ``<src_root>/a/b.py`` or ``<src_root>/a/b/__init__.py``."""
    parts = dotted.split(".")
    if parts[0] != _PKG:
        return None
    base = src_root.joinpath(*parts[1:])
    for cand in (base.with_suffix(".py"), base / "__init__.py"):
        if cand.is_file():
            return cand
    return None


def _bound_names(body, out: set[str], stars: list[str]) -> None:
    """Names bound at MODULE level (descends if/try/with/for/while, never into def/class)."""
    for node in body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            out.add(node.name)
        elif isinstance(node, ast.Assign):
            for t in node.targets:
                out.update(n.id for n in ast.walk(t) if isinstance(n, ast.Name))
        elif isinstance(node, (ast.AnnAssign, ast.AugAssign)):
            if isinstance(node.target, ast.Name):
                out.add(node.target.id)
        elif isinstance(node, ast.Import):
            out.update((a.asname or a.name.split(".")[0]) for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            for a in node.names:
                if a.name == "*":
                    stars.append(("." * node.level) + (node.module or ""))
                else:
                    out.add(a.asname or a.name)
        else:
            for field in ("body", "orelse", "finalbody", "handlers"):
                inner = getattr(node, field, None)
                if isinstance(inner, list):
                    _bound_names(
                        [h for x in inner for h in (x.body if isinstance(x, ast.ExceptHandler) else [x])],
                        out, stars,
                    )


def _module_defines(src_root: Path, dotted: str, name: str, depth: int = 0) -> bool:
    path = _module_file(src_root, dotted)
    if path is None:
        return False
    tree = parse_module(path)
    if tree is None:
        return False
    names: set[str] = set()
    stars: list[str] = []
    _bound_names(tree.body, names, stars)
    if name in names:
        return True
    if path.name == "__init__.py" and _module_file(src_root, f"{dotted}.{name}") is not None:
        return True
    if depth < _MAX_STAR_DEPTH:
        return any(s and not s.startswith(".") and _module_defines(src_root, s, name, depth + 1)
                   for s in stars)
    return False


def _check_stdlib(module: str, name: str | None) -> str | None:
    try:
        mod = importlib.import_module(module)
    except Exception as exc:  # noqa: BLE001 - any import failure is the finding
        return f"stdlib module {module!r} does not import: {exc!r}"
    if name is None or hasattr(mod, name):
        return None
    try:  # find_spec raises (not returns None) when `module` is not a package
        sub = importlib.util.find_spec(f"{module}.{name}")
    except (ImportError, ValueError):
        sub = None
    return None if sub is not None else f"stdlib {module!r} has no attribute or submodule {name!r}"


def _check_third_party(module: str, name: str | None) -> str | None:
    top = module.split(".")[0]
    if top not in _THIRD_PARTY:
        return (f"third-party module {module!r} is not in the reviewed _THIRD_PARTY set "
                f"{sorted(_THIRD_PARTY)}: review it, then add it")
    if importlib.util.find_spec(top) is None:
        return None  # reviewed + not installed on this box: the image/CI is the proof
    try:
        if importlib.util.find_spec(module) is None:
            return f"third-party module {module!r} is not importable"
    except Exception as exc:  # noqa: BLE001
        return f"third-party module {module!r} does not resolve: {exc!r}"
    return None


def import_problems(tree: ast.AST, src_root: Path = SRC_ROOT) -> list[str]:
    """One string per import in ``tree`` that does NOT resolve. Empty list = all resolve."""
    problems: list[str] = []
    for node in ast.walk(tree):
        sites: list[tuple[str, str | None]] = []
        if isinstance(node, ast.Import):
            sites = [(a.name, None) for a in node.names]
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                problems.append(f"line {node.lineno}: relative import cannot be proven (fail closed)")
                continue
            for a in node.names:
                if a.name == "*":
                    problems.append(f"line {node.lineno}: `from {node.module} import *` cannot be proven (fail closed)")
                else:
                    sites.append((node.module or "", a.name))
        for module, name in sites:
            top = module.split(".")[0]
            if top == _PKG:
                parts = module.split(".")
                for i in range(1, len(parts) + 1):
                    if _module_file(src_root, ".".join(parts[:i])) is None:
                        problems.append(f"line {node.lineno}: module {'.'.join(parts[:i])!r} not found under src/")
                        break
                else:
                    if name is not None and not _module_defines(src_root, module, name):
                        problems.append(f"line {node.lineno}: `from {module} import {name}`: {name!r} is not defined in {module}")
            elif top in sys.stdlib_module_names:
                why = _check_stdlib(module, name)
                if why:
                    problems.append(f"line {node.lineno}: {why}")
            else:
                why = _check_third_party(module, name)
                if why:
                    problems.append(f"line {node.lineno}: {why}")
    return problems


def script_problems(path: Path, src_root: Path = SRC_ROOT) -> list[str]:
    tree = parse_module(path)
    if tree is None:
        return ["script does not parse (fail closed)"]
    return import_problems(tree, src_root)


def _pkg_import_sites(path: Path) -> int:
    tree = parse_module(path)
    assert tree is not None, path
    return sum(
        1 for n in ast.walk(tree)
        if (isinstance(n, ast.ImportFrom) and (n.module or "").split(".")[0] == _PKG)
        or (isinstance(n, ast.Import) and any(a.name.split(".")[0] == _PKG for a in n.names))
    )


# --------------------------------------------------------------------------- the pin


def test_the_walk_sees_step_1_and_step_3_and_finds_real_imports_in_them():
    """Vacuity guard: the glob must reach step 1 and step 3, and each must import from the package."""
    names = {p.name for p in bake_step_scripts()}
    assert {"n432-path3-bake-step1.py", "n432-path3-bake-step3.py"} <= names, names
    for p in bake_step_scripts():
        assert _pkg_import_sites(p) >= 1, f"{p.name}: the walk saw no email_triage import (vacuous)"


@pytest.mark.parametrize("script", bake_step_scripts(), ids=lambda p: p.name)
def test_every_import_in_a_bake_step_resolves_against_the_real_tree(script):
    assert script_problems(script) == [], (
        f"{script.name} would die at deploy time with an ImportError; the baked step scripts "
        "import symbols that no unit test exercises (tests stub them as empty files)"
    )


def test_the_reviewed_third_party_set_has_no_stale_entry():
    seen = set()
    for p in bake_step_scripts():
        tree = parse_module(p)
        for n in ast.walk(tree):
            if isinstance(n, ast.Import):
                seen.update(a.name.split(".")[0] for a in n.names)
            elif isinstance(n, ast.ImportFrom) and n.module:
                seen.add(n.module.split(".")[0])
    assert _THIRD_PARTY <= seen, f"stale reviewed third-party entry: {sorted(_THIRD_PARTY - seen)}"


# --------------------------------------------------------------------------- teeth


def _fake_src(tmp_path: Path, files: dict[str, str]) -> Path:
    root = tmp_path / "src" / _PKG
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    return root


def test_teeth_a_stale_name_in_a_copy_of_step_3_fails(tmp_path):
    """RED proof on the REAL step 3 text: swap one real import for a name that does not exist."""
    real = next(p for p in bake_step_scripts() if p.name == "n432-path3-bake-step3.py")
    text = real.read_text(encoding="utf-8")
    needle = "from email_triage.config import load_config"
    assert needle in text
    bad = tmp_path / "n432-path3-bake-step3.py"
    bad.write_text(text.replace(needle, "from email_triage.config import no_such_name"), encoding="utf-8")
    assert script_problems(real) == []
    got = script_problems(bad)
    assert len(got) == 1 and "no_such_name" in got[0], got


def test_teeth_a_renamed_helper_in_the_source_tree_fails(tmp_path):
    """The deploy-time shape: the script is unchanged, the helper it imports was renamed."""
    tree = parse_source("from email_triage.db._engine import assert_cipher_version_floor\n")
    old = _fake_src(tmp_path, {"__init__.py": "", "db/__init__.py": "",
                               "db/_engine.py": "def assert_cipher_version_floor():\n    pass\n"})
    assert import_problems(tree, old) == []
    renamed = _fake_src(tmp_path / "r", {"__init__.py": "", "db/__init__.py": "",
                                         "db/_engine.py": "def assert_cipher_floor():\n    pass\n"})
    got = import_problems(tree, renamed)
    assert len(got) == 1 and "assert_cipher_version_floor" in got[0], got


@pytest.mark.parametrize("source,needle", [
    ("import email_triage.no_such_module\n", "no_such_module"),
    ("from email_triage.no_such_module import x\n", "no_such_module"),
    ("from email_triage.db import _engine, no_such_submodule\n", "no_such_submodule"),
    ("from json import no_such_attr\n", "no_such_attr"),
    ("from sys import no_such_attr\n", "no_such_attr"),  # sys is not a package: find_spec raises
    ("import no_such_stdlib_lookalike_pkg\n", "reviewed _THIRD_PARTY"),
    ("from email_triage.config import *\n", "fail closed"),
    ("from .config import load_config\n", "fail closed"),
    ("def f():\n    from email_triage.config import no_such_name\n", "no_such_name"),
])
def test_teeth_each_unresolvable_import_shape_is_flagged(source, needle):
    got = import_problems(parse_source(source))
    assert got and any(needle in g for g in got), (source, got)


@pytest.mark.parametrize("source", [
    "import json\nfrom pathlib import Path\n",
    "from email_triage.config import load_config\n",
    "from email_triage.db import _engine\n",  # a submodule import
    "import email_triage.db._engine\n",
    "import sqlcipher3.dbapi2 as _d\n",
])
def test_teeth_good_imports_are_not_flagged(source):
    assert import_problems(parse_source(source)) == []


def test_teeth_an_unparseable_script_fails_closed(tmp_path):
    bad = tmp_path / "n432-path3-bake-step9.py"
    bad.write_text("from email_triage.config import (\n", encoding="utf-8")
    assert script_problems(bad) == ["script does not parse (fail closed)"]
