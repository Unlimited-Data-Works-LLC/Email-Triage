"""N-560 / punch 560 — every DB-error matcher routes through ``_dbapi_errors``.

sqlcipher3 roots its exception hierarchy at ``Exception`` (0.6.2
``src/module.c:481``), so a stdlib ``sqlite3.*`` class never matches an error
raised on an encrypted connection. A matcher spelled with the stdlib class
alone is dead on every encrypted install. The funnel
``email_triage._dbapi_errors`` carries both drivers' class of the same name.

Invariant (count-agnostic, every ``src/email_triage`` module): no stdlib
``sqlite3`` exception class is used as an exception MATCHER — an ``except``
clause, a ``contextlib.suppress(...)`` argument, or the class argument of
``isinstance`` / ``issubclass`` — outside the repo-relative allow-list below.
The module-alias (``import sqlite3 as s``) and the class-import (``from sqlite3
import OperationalError as OE``) spellings are both resolved.

Second invariant (punch 560 panel, db-sme F1): no funnel tuple is an ELEMENT of
an ``except`` tuple. ``except (DB_ERRORS, Exception)`` nests a tuple inside the
except tuple; CPython does not recurse into it and raises ``TypeError`` the
moment an exception reaches the clause, so the handler crashes instead of
catching. Splat it (``except (*DB_ERRORS, X)``) or catch the tuple alone.
``contextlib.suppress`` / ``isinstance`` / ``issubclass`` accept nested tuples
and are out of scope for this arm. Every src module is scanned, whether or not
it imports ``sqlite3``.

Third invariant (punch 560 panel, devils-advocate F2): the "table absent"
test is one predicate, ``_dbapi_errors.is_missing_table``. No other src module
carries a ``"no such table"`` string in code (docstrings and comments may name
it), so a handler cannot hand-roll its own, possibly wider, absent-table check.

SCOPE CAVEAT (what a green run does NOT prove):
* It does not prove a routed site picked the RIGHT tuple. The rewrite mapped
  each class to the tuple of the same name (no widening); the pin cannot see
  the pre-rewrite class. ``test_funnel_holds_the_needles`` proves each tuple
  holds only classes of its own name.
* A matcher built at runtime (a tuple assembled in a variable, a class read
  through ``getattr``) is not followed.
* A handler that catches ``Exception`` swallows both drivers already and is
  out of scope; whether it SHOULD is a per-site question.
"""

from __future__ import annotations

import ast
import re
import sqlite3

import pytest

from tests._pin_harness import (
    REPO_ROOT,
    assert_pin_has_teeth,
    docstring_constant_ids,
    enclosing_fn,
    iter_files,
    iter_src_files,
    module_ssot_imports,
    parse_module,
    relpath,
)

# Every exception class the stdlib module exports — derived, never listed, so a
# class added to ``sqlite3`` is covered without editing this pin.
_SQLITE3_EXC_NAMES = frozenset(
    name for name in dir(sqlite3)
    if isinstance(getattr(sqlite3, name), type)
    and issubclass(getattr(sqlite3, name), BaseException)
)

# (repo-relative path, enclosing function) -> why it may keep the stdlib class.
# Keyed line-stable (R38). Each entry must match a live site (is_not_stale).
_ALLOWED: dict[tuple[str, str], str] = {
    ("db/_migrate.py", "_is_plaintext_sqlite"): (
        "probes a PLAINTEXT file with a raw stdlib sqlite3.connect; the "
        "DatabaseError it catches is the stdlib one by construction"
    ),
    ("db/_migrate.py", "_checkpoint_plaintext"): (
        "quiesces the PLAINTEXT source DB before migration through a raw "
        "stdlib sqlite3.connect; never a SQLCipher conn"
    ),
}


def _sqlite3_aliases(tree) -> tuple[set[str], set[str]]:
    """(names bound to the sqlite3 module, names bound to a sqlite3 exc class)."""
    modules: set[str] = set()
    classes: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name == "sqlite3":
                    modules.add(a.asname or "sqlite3")
        elif isinstance(node, ast.ImportFrom) and node.module == "sqlite3":
            for a in node.names:
                if a.name in _SQLITE3_EXC_NAMES:
                    classes.add(a.asname or a.name)
    return modules, classes


def _matcher_exprs(tree):
    """Yield every expression used as an exception matcher."""
    for node in ast.walk(tree):
        if isinstance(node, ast.ExceptHandler) and node.type is not None:
            yield node, node.type
        elif isinstance(node, ast.Call):
            fn = node.func
            name = fn.attr if isinstance(fn, ast.Attribute) else getattr(fn, "id", None)
            if name == "suppress":
                for arg in node.args:
                    yield node, arg
            elif name in ("isinstance", "issubclass") and len(node.args) == 2:
                yield node, node.args[1]


def _stdlib_classes_in(expr, modules: set[str], classes: set[str]) -> list[str]:
    elts = expr.elts if isinstance(expr, ast.Tuple) else [expr]
    hits: list[str] = []
    for e in elts:
        if (
            isinstance(e, ast.Attribute)
            and isinstance(e.value, ast.Name)
            and e.value.id in modules
            and e.attr in _SQLITE3_EXC_NAMES
        ):
            hits.append(f"{e.value.id}.{e.attr}")
        elif isinstance(e, ast.Name) and e.id in classes:
            hits.append(e.id)
    return hits


def _violations(tree) -> list[tuple[str, int, str]]:
    """(enclosing fn, line, spelled class) for every stdlib-only matcher."""
    modules, classes = _sqlite3_aliases(tree)
    if not modules and not classes:
        return []
    out: list[tuple[str, int, str]] = []
    for site, expr in _matcher_exprs(tree):
        for spelled in _stdlib_classes_in(expr, modules, classes):
            out.append((enclosing_fn(site), site.lineno, spelled))
    return out


def _scan() -> dict[tuple[str, str], list[tuple[int, str]]]:
    found: dict[tuple[str, str], list[tuple[int, str]]] = {}
    for path in iter_src_files():
        tree = parse_module(path)
        if tree is None:
            continue
        rel = relpath(path)
        for fn, line, spelled in _violations(tree):
            found.setdefault((rel, fn), []).append((line, spelled))
    return found


def test_no_stdlib_only_sqlite_error_matcher():
    bad = {k: v for k, v in _scan().items() if k not in _ALLOWED}
    assert not bad, (
        "A stdlib sqlite3 exception class is used as a matcher. On an "
        "encrypted install the connection is sqlcipher3, whose classes do NOT "
        "inherit from sqlite3's, so this handler never fires. Catch the "
        "same-named tuple from email_triage._dbapi_errors instead "
        "(sqlite3.OperationalError -> DB_OPERATIONAL_ERRORS, etc.; never a "
        "wider class). If the connection is provably a raw stdlib plaintext "
        "conn, add a justified (path, function) entry to _ALLOWED.\n"
        + "\n".join(
            f"  {path}::{fn} line {line}: {spelled}"
            for (path, fn), sites in sorted(bad.items())
            for line, spelled in sites
        )
    )


def test_allowlist_is_not_stale():
    found = _scan()
    stale = [k for k in _ALLOWED if k not in found]
    assert not stale, (
        f"_ALLOWED entries match no live stdlib-sqlite3 matcher: {stale}. "
        "Remove them."
    )


@pytest.mark.parametrize("bad_source", [
    "import sqlite3\ntry:\n    pass\nexcept sqlite3.OperationalError:\n    pass\n",
    "import sqlite3 as s\ntry:\n    pass\nexcept (ValueError, s.Error):\n    pass\n",
    "from sqlite3 import IntegrityError as IE\ntry:\n    pass\nexcept IE:\n    pass\n",
    "import contextlib, sqlite3\nwith contextlib.suppress(sqlite3.Error):\n    pass\n",
    "import sqlite3\nok = isinstance(exc, sqlite3.DatabaseError)\n",
    "import sqlite3\nok = issubclass(t, (KeyError, sqlite3.ProgrammingError))\n",
], ids=["except", "module-alias", "class-alias", "suppress", "isinstance", "issubclass"])
def test_pin_has_teeth(bad_source):
    assert_pin_has_teeth(
        _violations,
        bad_source,
        good_source=(
            "import sqlite3\n"
            "from email_triage._dbapi_errors import DB_OPERATIONAL_ERRORS\n"
            "conn = sqlite3.connect(':memory:')\n"
            "try:\n    pass\nexcept DB_OPERATIONAL_ERRORS:\n    pass\n"
        ),
    )


def test_funnel_holds_the_needles():
    """Each tuple holds the stdlib class and nothing of another name, and the
    exported name map points at the same tuple objects."""
    import email_triage._dbapi_errors as funnel

    assert set(funnel.FUNNEL_BY_CLASS) == set(funnel.FUNNEL_NAME_BY_CLASS)
    for cls_name, tup in funnel.FUNNEL_BY_CLASS.items():
        assert getattr(sqlite3, cls_name) in tup, cls_name
        assert {c.__name__ for c in tup} == {cls_name}, (cls_name, tup)
        assert getattr(funnel, funnel.FUNNEL_NAME_BY_CLASS[cls_name]) is tup


def test_funnel_carries_the_sqlcipher_classes():
    """Runs where the driver is installed (CI installs sqlcipher3==0.6.2 via the
    ``encryption`` extra). Deleting the driver arm turns this red.

    Spelled ``importorskip("sqlcipher3")`` so tests.yml's "sqlcipher-gated"
    step discovers this file and FAILS the job if this arm skips (punch 560
    panel: db-sme F2 / devils-advocate F1 / hipaa-sme H2). The discovery guard
    below keeps that true for every gated file."""
    pytest.importorskip("sqlcipher3")
    import sqlcipher3.dbapi2 as sqlcipher_dbapi

    import email_triage._dbapi_errors as funnel

    for cls_name, tup in funnel.FUNNEL_BY_CLASS.items():
        assert getattr(sqlcipher_dbapi, cls_name) in tup, cls_name


# ---------------------------------------------------------------------------
# Second invariant: no funnel tuple nested inside an ``except`` tuple.
# ---------------------------------------------------------------------------

_FUNNEL_MODULE = "email_triage._dbapi_errors"


def _funnel_tuple_names() -> frozenset[str]:
    import email_triage._dbapi_errors as funnel

    return frozenset(funnel.FUNNEL_NAME_BY_CLASS.values())


def _nested_funnel_tuples(tree) -> list[tuple[str, int, str]]:
    """(enclosing fn, line, element) for every unstarred ``except``-tuple
    element that is a funnel tuple: a name bound from the funnel module
    (aliases included), or any Name / Attribute spelled with a funnel tuple's
    name (so a re-export or ``module.DB_ERRORS`` is caught too)."""
    bound = module_ssot_imports(tree, _FUNNEL_MODULE) - {"*"}
    tuple_names = _funnel_tuple_names()
    out: list[tuple[str, int, str]] = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.ExceptHandler) and isinstance(node.type, ast.Tuple)):
            continue
        for e in node.type.elts:
            if isinstance(e, ast.Name) and (e.id in bound or e.id in tuple_names):
                out.append((enclosing_fn(node), node.lineno, e.id))
            elif isinstance(e, ast.Attribute) and e.attr in tuple_names:
                out.append((enclosing_fn(node), node.lineno, ast.unparse(e)))
    return out


def test_no_funnel_tuple_nested_in_an_except_tuple():
    bad = []
    for path in iter_src_files():
        tree = parse_module(path)
        if tree is None:
            continue
        rel = relpath(path)
        bad.extend(f"  {rel}::{fn} line {line}: {elt}"
                   for fn, line, elt in _nested_funnel_tuples(tree))
    assert not bad, (
        "A _dbapi_errors tuple is an element of an except tuple. Python raises "
        "TypeError ('catching classes that do not inherit from BaseException') "
        "when an exception reaches that clause, so the handler crashes instead "
        "of catching. Splat it (except (*DB_ERRORS, X)) or catch it alone.\n"
        + "\n".join(bad)
    )


def test_nested_tuple_premise_raises_type_error():
    """The premise of the arm above, on the running interpreter."""
    with pytest.raises(TypeError):
        try:
            raise ValueError("x")
        except ((KeyError,), Exception):  # the shape under test
            pass


@pytest.mark.parametrize("bad_source", [
    "from email_triage._dbapi_errors import DB_ERRORS\n"
    "try:\n    pass\nexcept (DB_ERRORS, Exception):\n    pass\n",
    "from email_triage._dbapi_errors import DB_OPERATIONAL_ERRORS as OPS\n"
    "try:\n    pass\nexcept (ValueError, OPS):\n    pass\n",
    "import email_triage._dbapi_errors as dbe\n"
    "try:\n    pass\nexcept (dbe.DB_INTEGRITY_ERRORS, KeyError):\n    pass\n",
    "from email_triage import _dbapi_errors\n"
    "try:\n    pass\nexcept (_dbapi_errors.DB_ERRORS, OSError):\n    pass\n",
    "from email_triage.db import DB_PROGRAMMING_ERRORS\n"
    "try:\n    pass\nexcept (DB_PROGRAMMING_ERRORS, TypeError):\n    pass\n",
], ids=["plain", "class-alias", "module-alias-attr", "parent-import-attr", "re-export"])
def test_nested_tuple_arm_has_teeth(bad_source):
    assert_pin_has_teeth(
        _nested_funnel_tuples,
        bad_source,
        good_source=(
            "import contextlib\n"
            "from email_triage._dbapi_errors import DB_ERRORS\n"
            "try:\n    pass\nexcept (*DB_ERRORS, Exception):\n    pass\n"
            "try:\n    pass\nexcept DB_ERRORS:\n    pass\n"
            "ok = isinstance(exc, (DB_ERRORS, KeyError))\n"
            "with contextlib.suppress(DB_ERRORS):\n    pass\n"
        ),
    )


# ---------------------------------------------------------------------------
# The driver arms are only proof if CI's fail-on-skip step runs them.
# ---------------------------------------------------------------------------

_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "tests.yml"


def _importorskip_names(tree: ast.AST) -> set[str]:
    """Local names bound to ``pytest.importorskip``: the bare name plus any
    ``from pytest import importorskip as X`` alias (devils-advocate r2)."""
    names = {"importorskip"}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == "pytest":
            for alias in node.names:
                if alias.name == "importorskip" and alias.asname:
                    names.add(alias.asname)
    return names


def _importorskips_sqlcipher(text: str) -> bool:
    """True when the file calls ``importorskip`` on ``sqlcipher3`` or a
    submodule, in any call shape: positional or ``modname=``, attribute, bare
    or aliased name, whether or not the call is split across lines. Read from
    the AST, so the guard's notion of "this file importorskips sqlcipher3"
    cannot be narrower than Python's (devils-advocate fold-check N1: a regex
    over the text missed the ``modname=`` form).

    SCOPE CAVEAT: a module name built at runtime (a variable, an f-string) is
    not followed; only a string literal is recognised."""
    tree = ast.parse(text)
    names = _importorskip_names(tree)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Attribute):
            hit = func.attr == "importorskip"
        else:
            hit = getattr(func, "id", None) in names
        if not hit:
            continue
        args = list(node.args[:1]) + [k.value for k in node.keywords if k.arg == "modname"]
        for arg in args:
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str) and (
                arg.value == "sqlcipher3" or arg.value.startswith("sqlcipher3.")
            ):
                return True
    return False


def _ci_discovers(pattern: re.Pattern, text: str) -> bool:
    """Whether tests.yml's ``grep -rlE`` selects the file. grep matches per
    line, so ``\\s*`` never crosses a newline there; a whole-text
    ``re.search`` would let a split call pass here while CI misses it
    (devils-advocate fold-check N1)."""
    return any(pattern.search(line) for line in text.splitlines())


def _classify(pattern: re.Pattern, files) -> tuple[list[str], list[str]]:
    """Split ``(name, text)`` pairs that importorskip sqlcipher3 into those
    CI's gated step discovers and those it misses. The guard and its teeth
    both call this, so the teeth exercise the guard's own classification
    (devils-advocate r2: teeth on the helpers alone left the guard's wiring
    untested)."""
    gated, missed = [], []
    for name, text in files:
        if not _importorskips_sqlcipher(text):
            continue
        (gated if _ci_discovers(pattern, text) else missed).append(name)
    return gated, missed


def _ci_gated_discovery_pattern() -> re.Pattern:
    """The ``grep -rlE`` pattern the tests.yml gated step discovers files with,
    read from the workflow (bash-escaped quotes undone)."""
    for line in _WORKFLOW.read_text(encoding="utf-8").splitlines():
        if "grep -rlE" in line and "importorskip" in line:
            m = re.search(r'"(importorskip.*?[^\\])" tests/', line)
            assert m, line
            return re.compile(m.group(1).replace('\\"', '"'))
    raise AssertionError("tests.yml has no sqlcipher-gated discovery grep")


def test_every_sqlcipher_importorskip_file_is_ci_gated():
    """Every test file that importorskips sqlcipher3 (any spelling, including
    ``sqlcipher3.dbapi2``) is discovered by the tests.yml step that fails on a
    skip. A file outside that set can skip its driver arm in CI and stay green
    (punch 560 panel: the n560 pin's driver arm was outside it)."""
    gated, missed = _classify(
        _ci_gated_discovery_pattern(),
        ((p.name, p.read_text(encoding="utf-8"))
         for p in iter_files(REPO_ROOT / "tests", "*.py")),
    )
    assert gated, "no sqlcipher-gated test file found; the guard proves nothing"
    assert "test_n560_dbapi_error_funnel_ssot_pin.py" in gated, gated
    assert not missed, (
        f"importorskip sqlcipher3 but NOT discovered by tests.yml's gated step "
        f"(a skip there would not fail CI): {missed}"
    )


@pytest.mark.parametrize("source", [
    'import pytest\nsqlcipher3 = pytest.importorskip(\n    "sqlcipher3"\n)\n',
    'import pytest\nsqlcipher3 = pytest.importorskip(modname="sqlcipher3")\n',
    'from pytest import importorskip\nd = importorskip(\n    "sqlcipher3.dbapi2",\n)\n',
    'from pytest import importorskip as ios\nd = ios("sqlcipher3")\n',
], ids=["split-call", "modname-keyword", "bare-name-split-submodule", "aliased-name"])
def test_ci_gate_guard_catches_shapes_ci_cannot_discover(source):
    """Teeth for the guard above (devils-advocate fold-check N1 and r2): each
    shape importorskips sqlcipher3 but is invisible to CI's per-line grep, so
    the guard's own classification must put it in MISSED. A regression to
    whole-text matching, to a text regex, or to a name match that ignores
    aliases turns this red."""
    assert _classify(_ci_gated_discovery_pattern(), [("plant.py", source)]) == (
        [], ["plant.py"]
    ), source


def test_ci_gate_guard_passes_the_single_line_form():
    """The control: the single-line spelling every gated file uses today is
    classified as GATED, so the teeth above are not a broad refusal."""
    source = 'import pytest\nsqlcipher3 = pytest.importorskip("sqlcipher3")\n'
    assert _classify(_ci_gated_discovery_pattern(), [("ok.py", source)]) == (
        ["ok.py"], []
    )


# ---------------------------------------------------------------------------
# Third invariant: one "table absent" predicate.
# ---------------------------------------------------------------------------

_MISSING_TABLE_NEEDLE = "no such table"
_MISSING_TABLE_HOME = "_dbapi_errors.py"


def _missing_table_needles(tree) -> list[int]:
    """Lines of every code string (not a docstring) carrying the needle."""
    docs = docstring_constant_ids(tree)
    return [
        node.lineno for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
        and id(node) not in docs
        and _MISSING_TABLE_NEEDLE in node.value.lower()
    ]


def test_missing_table_needle_only_in_the_funnel():
    bad, home_hits = [], []
    for path in iter_src_files():
        tree = parse_module(path)
        if tree is None:
            continue
        rel = relpath(path)
        lines = _missing_table_needles(tree)
        if rel == _MISSING_TABLE_HOME:
            home_hits.extend(lines)
        else:
            bad.extend(f"  {rel} line {line}" for line in lines)
    assert home_hits, (
        f"{_MISSING_TABLE_HOME} no longer holds the {_MISSING_TABLE_NEEDLE!r} "
        "needle; the predicate moved and this pin is stale"
    )
    assert not bad, (
        "A 'no such table' check outside _dbapi_errors.is_missing_table. Call "
        "the predicate, so every absent-table skip treats a locked, busy or "
        "I/O error the same way (not as 'absent'):\n" + "\n".join(bad)
    )


def test_missing_table_arm_has_teeth():
    assert_pin_has_teeth(
        _missing_table_needles,
        'try:\n    pass\nexcept Exception as e:\n'
        '    if "No such table" in str(e):\n        pass\n',
        good_source=(
            'def f(e):\n    """Skips a "no such table" error only."""\n'
            '    return is_missing_table(e)\n'
        ),
    )
