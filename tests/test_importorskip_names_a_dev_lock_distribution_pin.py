"""Pin: every ``pytest.importorskip("<name>")`` under ``tests/`` names a distribution
that ``requirements-dev.lock`` installs, so CI RUNS the arm instead of skipping it.

Origin (CVE-2026-59951, mcp removal): the N-433 retired-key arm did
``pytest.importorskip("jsonschema")``. ``jsonschema`` reached the dev lock only as a
transitive dependency of ``mcp``; dropping ``mcp`` removed it, and the arm would have
become a SKIP on the CI runner while the suite still printed green. An
``importorskip`` of a package CI never installs is a control that cannot run where it
is checked (style guide: never a bare skip that hides a control). This pin makes that
state a RED instead of a quiet ``s`` in ``-r sfE`` output.

INVARIANT: for every call to ``importorskip`` in every ``tests/**/*.py`` -- spelled
``pytest.importorskip(...)`` (any receiver), a bare ``importorskip(...)``, or a
``from pytest import importorskip as X`` alias, with the module positional or as
``modname=`` -- the module name is a string literal whose TOP-LEVEL segment
(``sqlcipher3.dbapi2`` -> ``sqlcipher3``), canonicalised per PEP 503, is a
distribution in ``requirements-dev.lock`` (read through ``scripts/lock_reader.py``,
the one lock reader, PD-5), directly or through ``_IMPORT_NAME_TO_DIST`` when the
import name differs from the distribution name; OR it is in ``_ALLOW`` with a
reason.

Fail CLOSED: a module name that is not a string literal (a variable, an f-string)
is an offender, not skipped, because the pin cannot tell what CI would install for
it. A test file that does not parse is an offender too.

Presence is read across ALL lock entries (``pins`` + ``not_applicable`` +
``unevaluated`` with no marker environment): the question is "does the dev lock
carry this distribution at all", not "on which platform". SCOPE CAVEAT: a
distribution whose marker is false on the Linux CI runner (none today) would pass
here and still skip there; and a skip for a reason other than absence (a platform
``skipif``, a missing binary) is not this pin's subject.

Count-agnostic: the walk is ``iter_files`` over the tests tree from the shared
harness, never a list of expected files or a site count.
"""
from __future__ import annotations

import ast

from _pin_harness import (
    REPO_ROOT,
    assert_pin_has_teeth,
    iter_files,
    load_repo_script,
    parse_module,
    relpath,
)

_lock_reader = load_repo_script("scripts/lock_reader.py", "_et_lock_reader")

_TESTS_ROOT = REPO_ROOT / "tests"
_DEV_LOCK = REPO_ROOT / "requirements-dev.lock"

# Import name -> distribution name, for the in-lock packages whose import name
# differs from the project name (the same four-way split test_n537 documents;
# ``PyJWT`` is omitted because the dev lock does not carry it). A mapping, not an
# exemption: the mapped distribution must still be in the lock.
_IMPORT_NAME_TO_DIST: dict[str, str] = {
    "dns": "dnspython",
    "yaml": "pyyaml",
    "markdown_it": "markdown-it-py",
}

# Canonical top-level module name -> reason it may be importorskip'd although the
# dev lock does not install it. Keep this SHORT: an entry is a conscious decision
# that an arm does not run in CI. Empty at creation (2026-10-16): every site named
# a locked distribution once the N-433 arm went structural.
_ALLOW: dict[str, str] = {}


def _dev_lock_distributions() -> frozenset[str]:
    locked = _lock_reader.parse_lock(_DEV_LOCK.read_text(encoding="utf-8"), None)
    names = set(locked.pins) | set(locked.not_applicable) | set(locked.unevaluated)
    return frozenset(_lock_reader.canonical(n) for n in names)


def _importorskip_aliases(tree: ast.AST) -> set[str]:
    """Local names bound to ``pytest.importorskip``: the bare name plus any
    ``from pytest import importorskip as X`` alias (same shape as
    ``test_n560_dbapi_error_funnel_ssot_pin._importorskip_names``)."""
    names = {"importorskip"}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == "pytest":
            for alias in node.names:
                if alias.name == "importorskip" and alias.asname:
                    names.add(alias.asname)
    return names


def _importorskip_sites(tree: ast.AST) -> list[tuple[int, str | None]]:
    """``(lineno, module name or None)`` for every importorskip call; ``None`` when
    the module argument is missing or not a string literal."""
    aliases = _importorskip_aliases(tree)
    sites: list[tuple[int, str | None]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Attribute):
            hit = func.attr == "importorskip"
        else:
            hit = getattr(func, "id", None) in aliases
        if not hit:
            continue
        args = list(node.args[:1]) + [k.value for k in node.keywords if k.arg == "modname"]
        arg = args[0] if args else None
        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
            sites.append((node.lineno, arg.value))
        else:
            sites.append((node.lineno, None))
    return sites


def _offenders_in_tree(tree: ast.AST, locked: frozenset[str]) -> list[tuple[int, str]]:
    out: list[tuple[int, str]] = []
    for lineno, modname in _importorskip_sites(tree):
        if modname is None:
            out.append((lineno, "<non-literal module name>"))
            continue
        top = modname.split(".", 1)[0]
        dist = _lock_reader.canonical(_IMPORT_NAME_TO_DIST.get(top, top))
        if dist in locked or _lock_reader.canonical(top) in _ALLOW:
            continue
        out.append((lineno, modname))
    return out


def test_every_importorskip_names_a_dev_lock_distribution():
    locked = _dev_lock_distributions()
    assert locked, "requirements-dev.lock parsed to zero distributions; the pin would prove nothing"
    offenders: list[str] = []
    for path in iter_files(_TESTS_ROOT, "*.py"):
        tree = parse_module(path)
        rel = relpath(path, REPO_ROOT)
        if tree is None:
            offenders.append(f"{rel}: does not parse")
            continue
        offenders.extend(f"{rel}:{ln}: importorskip({name!r})" for ln, name in _offenders_in_tree(tree, locked))
    assert not offenders, (
        "These importorskip calls name a package requirements-dev.lock does not install, so "
        "the arm SKIPS on the CI runner and the control it guards never runs there. Either "
        "declare the package so the dev lock carries it, rewrite the arm so it needs no "
        "third-party package, or add the top-level name to _ALLOW with the reason:\n  "
        + "\n  ".join(offenders)
    )


def test_allow_entries_are_used_and_justified():
    """A dead ``_ALLOW`` entry silently pre-approves a future skip; drop it."""
    seen: set[str] = set()
    for path in iter_files(_TESTS_ROOT, "*.py"):
        tree = parse_module(path)
        if tree is None:
            continue
        for _, name in _importorskip_sites(tree):
            if name is not None:
                seen.add(_lock_reader.canonical(name.split(".", 1)[0]))
    dead = sorted(set(_ALLOW) - seen)
    assert not dead, f"_ALLOW entries no test importorskips any more: {dead}"
    blank = sorted(k for k, why in _ALLOW.items() if not why.strip())
    assert not blank, f"_ALLOW entries without a reason: {blank}"


def test_pin_has_teeth():
    locked = _dev_lock_distributions()

    def detector(tree):
        return _offenders_in_tree(tree, locked)

    # A distribution the dev lock does not carry: positional, keyword, aliased, dotted.
    assert_pin_has_teeth(
        detector,
        'import pytest\nx = pytest.importorskip("et_absent_dist_zz")\n',
        'import pytest\nx = pytest.importorskip("aioimaplib")\n',
    )
    assert_pin_has_teeth(detector, 'import pytest\npytest.importorskip(modname="et_absent_dist_zz")\n')
    assert_pin_has_teeth(detector, 'from pytest import importorskip as ios\nios("et_absent_dist_zz.sub")\n')
    # Fail closed on a module name the pin cannot read.
    assert_pin_has_teeth(detector, 'import pytest\nname = "aioimaplib"\npytest.importorskip(name)\n')
    # A dotted submodule of a locked distribution is not an offender.
    assert_pin_has_teeth(
        detector,
        'import pytest\npytest.importorskip("et_absent_dist_zz")\n',
        'import pytest\npytest.importorskip("sqlcipher3.dbapi2")\n',
    )
