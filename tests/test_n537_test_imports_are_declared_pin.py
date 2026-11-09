"""Punch 537 pin: every third-party module a test imports is a DECLARED dependency.

On 2026-09-23 the N-495 render pin shipped importing ``markdown_it`` with nothing in
``pyproject.toml`` declaring it, and CI broke. That one import was then declared, but
nothing enforced the class, and the adversary pass on punch 537 found a second
instance: ``tests/conftest.py`` imported ``filelock`` (on every xdist worker) while
only ``torch`` happened to provide it. That kind of dependency holds by accident and
fails as a partial red that reads like a flake.

INVARIANT: every ``import X`` / ``from X import ...`` under ``tests/`` AND ``src/``
whose top-level module is neither stdlib nor first-party (top-level importable from an
import root in this repo) is NAMED in ``pyproject.toml`` (``[project] dependencies`` or
any optional extra) -- either under its own spelling, or as an installed distribution
that provides it.

Exempt by structure, not by list: an import inside a ``try`` whose handler catches
``ImportError`` / ``ModuleNotFoundError`` (or broader) and does something other than
re-raise, and an import under ``if TYPE_CHECKING:``. Those are written to survive the
module's absence. Both tests are STRUCTURAL (punch 537 panel 3, DA-A5): the
``TYPE_CHECKING`` test must BE that name, not merely contain it, so ``if not
TYPE_CHECKING:`` is not a guard; and a handler whose whole body is a ``raise`` does not
survive absence, so it is not a guard either.

SCOPE CAVEAT -- what a green run here does NOT prove (punch 537 panel 3):

* ``tests/`` AND ``src/`` are walked. ``src/`` was added by the punch-537 panel-3 fold
  on the operator's scope ruling (DA-A3 / DB-P3-6): CI runs ``src/`` THROUGH the tests,
  so a missing runtime declaration there costs a 500 or a broken fresh install rather
  than a red check -- the class was closed on the surface where the accident is least
  consequential and left open on the one where it is most. The 8 unguarded
  transitive-only imports that ruling exposed (``markupsafe`` x5 via ``jinja2``,
  ``pydantic`` x2 via ``fastapi``, ``requests`` x1 via ``acme`` -- provided by ``acme``, imported only by the ``_egress.py``
  SSOT from punch 547 on and by ``web/acme_renewer.py`` before it) are now declared in
  ``[project.dependencies]`` at their providers' own floors, which is why
  ``requirements.lock`` stayed byte-identical.
* ``scripts/`` is still OUT, and the reason is stated rather than assumed: it holds
  operator tools and spikes whose imports CI never executes. Measured at this fold, the
  same predicate over ``scripts/`` reports 3 (``PIL`` in ``gen-pwa-icons.py``, ``apsw``
  x2 in ``spike_apsw_compat_perf.py``) -- both genuinely optional operator tooling.
* Declared-ness is read from the declaration FIRST and from the installed environment
  only as a fallback, so the verdict no longer depends on what a previous CI job left
  behind (panel 3, DB-P3-1: ``playwright`` is declared in the ``e2e`` extra, absent from
  ``requirements.lock``, and not installed by the ``[dev,encryption]`` install
  ``tests.yml`` runs -- it produced 47 offenders against the declared install steps and
  0 here only because this workstation happens to have it). The fallback is
  NAME-EQUALITY: a distribution whose import name differs from its project name
  (``dnspython``->``dns``, ``PyYAML``->``yaml``, ``PyJWT``->``jwt``,
  ``markdown-it-py``->``markdown_it``) is still resolved only through the installed
  environment. Measured at 8b9cfcef: those four are the only such cases in this tree
  (21 import sites at that sha), all four are declared, and all four are installed by
  the commands CI runs.
* A declaration in ANY optional extra satisfies this pin, and that is CORRECT rather
  than a gap -- recorded here because the fold's first draft wrote it up as a gap on a
  reading that both seats then refuted. The objection was "a dev-extra declaration
  satisfies the pin while a mirror install would not carry the module". It proves too
  much: ``pytest`` is itself dev-only (in the ``dev`` extra, absent from
  ``[project.dependencies]``) and is imported by **433 of the 791** shipped test files,
  or **462 of the 843** tracked ones -- two units over two populations, neither to be
  quoted as a rate. If any-extra acceptance were too permissive, ``pytest`` would be its
  flagship instance across most of the suite. It is not: the dev extra is the correct
  home for a test-only dependency, and ``pyproject.toml`` says the image build excludes
  it precisely because the image does not run the tests. (hipaa A-4 leg (ii), refuted by
  its own later measurement and re-measured independently as db DB-P3-11; A-4 stands at
  LOW, matching DB-P3-10.) The pin's invariant is "named somewhere in pyproject", it
  cannot distinguish which extra a given installer uses, and no consumer needs it to.
* Dynamic imports are invisible -- ``importlib.import_module("x")`` and ``__import__``
  are not ``ast.Import`` nodes. 23 occurred under ``tests/`` at 8b9cfcef; every one
  resolved a first-party ``email_triage.*`` or ``scripts/`` name, so there was no live
  gap at that sha. (``pytest.importorskip`` is absence-tolerant, so it is not a
  declaration gap here; whether its package is one CI installs, so the arm runs rather
  than skips, is ``test_importorskip_names_a_dev_lock_distribution_pin``.) These are counts at a sha, not live properties: re-measure, do not cite.
* ``_first_party()`` walks the FILESYSTEM, not the git index, so an untracked ``.py``
  file could in principle contribute an exemption name a clean CI checkout lacks.
  Measured in this worktree at 8b9cfcef: 1,178 ``.py`` files walked, 0 untracked, and a
  tracked-only walk yields the identical 591 names. The direction if it ever diverges is
  fail-CLOSED on CI (a clean checkout exempts FEWER names, so it reports more, not less).
* ``sys.stdlib_module_names`` is interpreter-version dependent and
  ``requires-python = ">=3.11"``, so a module that is stdlib on 3.11 and removed later
  is exempt on an older runner and undeclared on a newer one.
* The first-party exemption is resolution-based but still keyed on a NAME at an import
  root, so a future top-level ``scripts/spikes/click.py`` would exempt ``click``.
  ``test_the_first_party_set_shadows_no_installed_distribution`` is the census over
  that (PD#7); it bounds the set, it does not eliminate the shape.
"""
from __future__ import annotations

import ast
import importlib.metadata as md
import re
import sys
import tomllib

from _pin_harness import REPO_ROOT, iter_files, parse_module, parse_source, relpath
from _pin_harness import _FULL_DEV_TREE  # the one dev-tree detector (PD-5)

_GUARD_EXC = {"ImportError", "ModuleNotFoundError", "Exception", "BaseException"}

# Never an import root, and never walked looking for one.
_SKIP_DIR = {".git", "__pycache__", ".venv", "venv", "node_modules", ".pytest_cache",
             ".mypy_cache", ".ruff_cache", "htmlcov", ".tox", ".ci-shepherd"}


def _venv_roots() -> set:
    """Every virtual environment inside the checkout, whatever its name: a directory
    holding ``pyvenv.cfg``. punch 454's ``.venv-lock/`` made every distribution it
    installs a "first-party" name until this skipped it (panel B2, db-sme F9: skip by
    the marker, not by a list of names)."""
    return {p.parent for p in iter_files(REPO_ROOT, "pyvenv.cfg")}


def _norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _pyproject() -> dict:
    return tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))


def _declared() -> set[str]:
    data = _pyproject()
    reqs = list(data["project"].get("dependencies", []))
    for extra in data["project"].get("optional-dependencies", {}).values():
        reqs += extra
    return {_norm(re.split(r"[<>=!~\[;\s]", r.strip(), maxsplit=1)[0]) for r in reqs}


def _pythonpath_roots() -> set:
    """The ``[tool.pytest.ini_options] pythonpath`` entries. pytest puts these on
    ``sys.path`` verbatim whether or not they are packages -- ``tests/`` is BOTH a
    package and a pythonpath entry, which is how ``_pin_harness`` is importable as a
    bare top-level name. DERIVED from config, never hardcoded (R7b)."""
    ini = _pyproject().get("tool", {}).get("pytest", {}).get("ini_options", {})
    return {(REPO_ROOT / e).resolve() for e in ini.get("pythonpath", [])}


def _first_party() -> set[str]:
    """Top-level names this repo itself provides. Exemption is by RESOLUTION, not by
    spelling: a name counts only if a module or package of that name sits AT an import
    root. A directory inside a package is reachable only as ``pkg.sub``, which is why
    ``src/email_triage/classify/ollama.py`` does NOT make ``ollama`` a top-level name.
    The former stem-and-every-parent-part set held 1,135 names and silently exempted
    any third-party top-level colliding with one -- ``ollama`` (a real PyPI
    distribution and this project's own LLM backend) among them (panel 3, A-4).

    The walk routes through the shared harness (``iter_files``), per PD#6: deriving
    roots with a hand-rolled ``iterdir``/``rglob`` is the drift
    ``test_pin_harness_adoption`` exists to stop, and it caught exactly that here."""
    pythonpath = _pythonpath_roots()
    venvs = _venv_roots()
    files = [p for p in iter_files(REPO_ROOT, "*.py")
             if not (set(p.relative_to(REPO_ROOT).parts) & _SKIP_DIR)
             and not (venvs & set(p.parents))]
    packages = {p.parent for p in files if p.name == "__init__.py"}

    def is_root(d) -> bool:
        """A directory a bare import can resolve from: an explicit pythonpath entry,
        or a directory no part of whose chain below the repo root is a package."""
        if d in pythonpath or d == REPO_ROOT:
            return True
        cur = d
        while cur != REPO_ROOT:
            if cur in packages:
                return False
            cur = cur.parent
        return True

    names: set[str] = set()
    for p in files:
        if is_root(p.parent):
            names.add(p.stem)
            if p.name == "__init__.py":
                names.discard("__init__")
        if p.name == "__init__.py" and is_root(p.parent.parent):
            names.add(p.parent.name)      # a top-level PACKAGE
    return names


def _is_absence_guard(handler: ast.ExceptHandler) -> bool:
    """A handler guards against the module's absence only if it catches an absence
    exception AND does something other than re-raise. ``except ImportError: raise``
    does not survive absence (panel 3, DA-A5)."""
    types = handler.type.elts if isinstance(handler.type, ast.Tuple) else [handler.type]
    catches = handler.type is None or any(
        isinstance(t, ast.Name) and t.id in _GUARD_EXC for t in types)
    if not catches:
        return False
    return not all(isinstance(stmt, ast.Raise) for stmt in handler.body)


def _is_type_checking_test(test: ast.AST) -> bool:
    """``TYPE_CHECKING`` or ``typing.TYPE_CHECKING`` ITSELF -- not any expression
    mentioning it, so ``if not TYPE_CHECKING:`` and ``if 'TYPE_CHECKING' == x:`` are
    not guards (panel 3, DA-A5)."""
    return (isinstance(test, ast.Name) and test.id == "TYPE_CHECKING"
            or isinstance(test, ast.Attribute) and test.attr == "TYPE_CHECKING")


def _guarded(tree: ast.AST) -> set[int]:
    """id()s of import nodes written to survive the module's absence."""
    ids: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Try):
            body = node.body if any(_is_absence_guard(h) for h in node.handlers) else []
        elif isinstance(node, ast.If) and _is_type_checking_test(node.test):
            body = node.body
        else:
            continue
        for stmt in body:
            for sub in ast.walk(stmt):
                if isinstance(sub, (ast.Import, ast.ImportFrom)):
                    ids.add(id(sub))
    return ids


def undeclared_imports(tree: ast.AST, first_party: set[str], declared: set[str],
                       dists: dict[str, list[str]]) -> list[tuple[int, str, list[str]]]:
    """(lineno, module, providing distributions) for each unguarded third-party
    import that pyproject does not name, directly or through an installed provider.

    The declaration is consulted BEFORE the environment, so a declared-but-not-
    installed module is not an offender (DB-P3-1)."""
    guarded = _guarded(tree)
    out = []
    for node in ast.walk(tree):
        if id(node) in guarded:
            continue
        if isinstance(node, ast.Import):
            mods = [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            mods = [node.module]
        else:
            continue
        for mod in mods:
            top = mod.split(".")[0]
            if top in sys.stdlib_module_names or top in first_party:
                continue
            if _norm(top) in declared:
                continue
            providers = [_norm(d) for d in dists.get(top, [])]
            if not any(d in declared for d in providers):
                out.append((node.lineno, top, providers))
    return out


# Walked trees. `tests/` is what CI runs directly; `src/` is what CI runs THROUGH the
# tests and what a fresh install executes (punch 537 panel 3, DA-A3 / DB-P3-6).
_WALKED = ("tests", "src")

# Distributions whose IMPORT name differs from their project name. The
# declaration-first resolution below matches by name, so these four are the only
# modules that still need the installed environment to resolve -- which is exactly
# what `test_the_verdict_rests_on_declarations_not_on_the_environment` bounds.
# Every value must be a declared distribution; the pin asserts that, so this table
# cannot drift into an exemption list.
_IMPORT_NAME_ALIASES = {
    "dns": "dnspython",
    "yaml": "pyyaml",
    "jwt": "pyjwt",
    "markdown_it": "markdown-it-py",
}


def _walk_offenders(dists: dict[str, list[str]]) -> tuple[list[str], set[str], int]:
    """(rendered offenders, offending top-level names, files scanned) over every
    walked tree, resolving declared-ness against `dists`."""
    first_party, declared = _first_party(), _declared()
    offenders: list[str] = []
    tops: set[str] = set()
    scanned = 0
    for sub in _WALKED:
        for path in iter_files(REPO_ROOT, "*.py", sub):
            tree = parse_module(path)
            if tree is None:
                continue
            scanned += 1
            for ln, top, providers in undeclared_imports(tree, first_party, declared, dists):
                offenders.append(f"{relpath(path, REPO_ROOT)}:{ln} imports {top!r} "
                                 f"(provided by {providers or 'NOTHING INSTALLED'})")
                tops.add(top)
    return offenders, tops, scanned


def test_every_test_import_is_a_declared_dependency():
    offenders, _tops, scanned = _walk_offenders(md.packages_distributions())
    assert scanned > 100, f"scanned only {scanned} test files: the walk is broken, not clean"
    assert not offenders, (
        "a test imports a third-party module that pyproject.toml does not declare. It works "
        "here only because something else installed it; declare it (the `dev` extra for "
        "test-only use) or guard the import:\n  " + "\n  ".join(sorted(offenders))
    )


def test_the_verdict_rests_on_declarations_not_on_the_environment():
    """DB-P3-1 (HIGH) as a PIN rather than a probe: the pin must give the same answer
    on a runner with extra packages installed and on one carrying only the declared
    extras. Before the fix it did not -- `playwright` is declared in the `e2e` extra,
    absent from `requirements.lock`, and not installed by the `[dev,encryption]`
    install `tests.yml` runs, so the walk reported 47 offenders against a clean
    execution of its own declared install steps and 0 only where an earlier e2e job
    had left the package behind on the persistent runner. A verdict decided by what a
    previous job installed is the defect, and the GREEN branch was the worse one.

    Simulated by the harshest environment there is -- NOTHING installed. Everything
    still reported there must be an import-name/project-name mismatch, never a missing
    declaration. That makes the `playwright` class impossible by construction: its
    import name equals its distribution name, so declaration-first resolves it with no
    environment at all."""
    declared = _declared()
    for mod, dist in sorted(_IMPORT_NAME_ALIASES.items()):
        assert _norm(dist) in declared, (
            f"the alias table claims {mod!r} comes from {dist!r}, which pyproject does "
            "not declare — the table must never become an exemption list"
        )
    live_offenders, _live_tops, _n = _walk_offenders(md.packages_distributions())
    assert not live_offenders, "the live-environment walk is not clean; fix that first"

    _bare_offenders, bare_tops, scanned = _walk_offenders({})
    assert scanned > 100, f"scanned only {scanned} files: the walk is broken, not clean"
    unexplained = sorted(bare_tops - set(_IMPORT_NAME_ALIASES))
    assert not unexplained, (
        "with NOTHING installed these imports are still reported, so the pin's verdict "
        "depends on the environment rather than on the repo's declarations — the "
        "punch-537 DB-P3-1 defect. Each must either be declared under its own spelling "
        "or be added to _IMPORT_NAME_ALIASES with its real distribution name:\n  "
        + "\n  ".join(unexplained)
    )


def test_the_first_party_set_resolves_names_rather_than_matching_spellings():
    """A-4 / DB-P3-10 as a pin over the REAL `_first_party()`. The teeth arm below
    uses a hand-built first-party set, so it cannot see this function regress -- a
    mutation check found exactly that escape. The property: a module that exists only
    INSIDE a package is not a top-level name, however its file is spelled."""
    fp = _first_party()
    assert fp, "the first-party set is empty: the root derivation is broken"
    # `src/email_triage/classify/ollama.py` exists, so the old stem-based set held
    # `ollama` -- a real PyPI distribution and this project's own LLM backend.
    inside_a_package = {"ollama": "src/email_triage/classify/ollama.py"}
    for name, where in inside_a_package.items():
        assert (REPO_ROOT / where).exists(), f"{where} moved; pick another in-package module"
        assert name not in fp, (
            f"{name!r} is exempt because a file is SPELLED that way ({where}), not "
            "because it resolves first-party -- it is importable only as "
            "email_triage.classify.ollama, so an `import ollama` in a test would be "
            "silently exempted (punch 537, A-4 / DB-P3-10)"
        )
    # ...and the genuinely top-level names must survive, or the narrowing went too far.
    # The shipped four hold on every tree. The operator-internal two do not ship (scripts/**
    # is default-deny in the publish ship-set), so they are top-level on the full dev tree only.
    for name in ("email_triage", "tests", "conftest", "_pin_harness"):
        assert name in fp, f"{name!r} IS top-level importable here and must stay exempt"
    for name in ("publish_shipset", "defer_gate"):
        if _FULL_DEV_TREE:
            assert name in fp, f"{name!r} IS top-level importable here and must stay exempt"


def test_the_walk_covers_every_declared_tree():
    """DA-A3 / DB-P3-6: `src/` is in scope by the operator's ruling, and a mutation
    check showed nothing noticed when it was removed from `_WALKED`."""
    assert set(_WALKED) >= {"tests", "src"}, (
        f"the walk no longer covers both declared trees: {_WALKED!r}. `src/` is what a "
        "fresh install executes; dropping it reopens the class DB-P3-6 filed."
    )
    for sub in _WALKED:
        found = [p for p in iter_files(REPO_ROOT, "*.py", sub)]
        assert len(found) > 50, f"the {sub}/ walk yielded only {len(found)} files"


def test_the_first_party_set_shadows_no_installed_distribution():
    """PD#7, census the censusers. ``_first_party()`` is a derived exemption set, so
    the shape that bit us -- a real distribution silently exempted by a name collision
    -- needs its own assertion. Only names this repo genuinely owns may appear in both
    the exemption set and the installed distributions."""
    first_party = _first_party()
    assert first_party, "the first-party set is empty: the root derivation is broken"
    repo_owned = {"email_triage", "tests", "scripts", "conftest"}
    shadowed = sorted((first_party & set(md.packages_distributions())) - repo_owned)
    assert not shadowed, (
        "a first-party name collides with an INSTALLED third-party top-level module, so "
        "this pin would exempt that module's imports by spelling rather than resolve "
        "them. Rename the repo module or narrow _first_party():\n  " + "\n  ".join(shadowed)
    )


def test_the_undeclared_import_detector_has_teeth():
    dists = {"filelock": ["filelock"], "yaml": ["PyYAML"]}
    declared = {"pyyaml"}
    first = {"_pin_harness"}

    def det(src: str, d=dists, dec=declared):
        return undeclared_imports(parse_source(src), first, dec, d)

    assert [t[1] for t in det("from filelock import FileLock\n")] == ["filelock"], (
        "missed an import whose only provider is undeclared"
    )
    assert [t[1] for t in det("import totally_absent_mod\n")] == ["totally_absent_mod"], (
        "missed an import that nothing provides"
    )
    assert [t[1] for t in det("def f():\n    import filelock\n")] == ["filelock"], (
        "missed a function-local import"
    )
    clean = ("import os, json\nimport yaml\nfrom _pin_harness import REPO_ROOT\n"
             "try:\n    import filelock\nexcept ImportError:\n    filelock = None\n"
             "from typing import TYPE_CHECKING\nif TYPE_CHECKING:\n    import filelock\n"
             "from . import sibling\n")
    assert not det(clean), f"flagged stdlib, declared, first-party or guarded imports: {det(clean)!r}"
    assert [t[1] for t in det("try:\n    import filelock\nexcept KeyError:\n    pass\n")] == ["filelock"], (
        "a try that does not catch ImportError is not a guard"
    )
    # DB-P3-1: a DECLARED module that is simply not installed is not an offender, and
    # the verdict must not flip with the runner's leftovers. `playwright` is declared in
    # the `e2e` extra and absent from the `[dev,encryption]` install CI runs.
    assert not det("import playwright\n", d={}, dec={"playwright"}), (
        "a declared module reported as undeclared because it is not INSTALLED: the pin "
        "is reading the environment instead of the declaration"
    )
    assert not det("from playwright.sync_api import Page\n", d={}, dec={"playwright"}), (
        "same, through a submodule import"
    )
    assert [t[1] for t in det("import ollama\n", d={})] == ["ollama"], (
        "an undeclared module is exempt: the first-party set is matching a spelling "
        "(src/email_triage/classify/ollama.py) rather than resolving an import root"
    )
    # DA-A5: both guard tests must be structural, not substring.
    for src, why in (
        ("from typing import TYPE_CHECKING\nif not TYPE_CHECKING:\n    import filelock\n",
         "`if not TYPE_CHECKING:` runs at runtime and is not a guard"),
        ("if 'TYPE_CHECKING' == x:\n    import filelock\n",
         "a test merely MENTIONING TYPE_CHECKING is not a guard"),
        ("try:\n    import filelock\nexcept ImportError:\n    raise\n",
         "a handler that re-raises does not survive the module's absence"),
        ("try:\n    import filelock\nexcept ImportError:\n    raise RuntimeError('no')\n",
         "a handler that raises something else does not survive absence either"),
    ):
        assert [t[1] for t in det(src)] == ["filelock"], f"{why}: {det(src)!r}"
