"""Pin for ``tests/_network_guard.py`` (t20): the guard is wired for every test process, and
every opt-out says why.

* The root ``tests/conftest.py`` calls ``_network_guard.register(config)`` from
  ``pytest_configure``. That is what installs the guard before collection, so the pin is on
  the wiring, not on a fixture a directory could shadow.
* Every use of the ``allow_outbound_network`` marker under ``tests/`` is a call with a
  non-empty string ``reason=``. A bare marker, a marker without a reason, or the marker name
  as a string (``request.node.add_marker("allow_outbound_network")``) is flagged. The
  property holds over every file the harness walks, so a new opt-out is reviewed by its
  reason, whatever the count.

SCOPE CAVEAT: a green run proves the wiring and the reasons. That the guard refuses is
``tests/test_network_guard.py``; what it cannot see (subprocesses, C extensions that resolve or
open their own sockets, ``socket.sendmsg``, the proactor loop's datagram sends) is in the module
docstring.
"""

from __future__ import annotations

import ast

from _pin_harness import (
    REPO_ROOT, assert_pin_has_teeth, iter_files, parse_module, parse_source, relpath,
)

import _network_guard

TESTS_ROOT = REPO_ROOT / "tests"
_MARKER = _network_guard.MARKER
_GUARD_HOME = "_network_guard.py"


def _reason_ok(call: ast.Call) -> bool:
    return any(kw.arg == "reason" and isinstance(kw.value, ast.Constant)
               and isinstance(kw.value.value, str) and kw.value.value.strip()
               for kw in call.keywords)


def unjustified_opt_outs(tree: ast.AST) -> list[int]:
    """Line numbers of every marker use without a non-empty ``reason=``."""
    bad: list[int] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and node.attr == _MARKER:
            parent = getattr(node, "_ph_parent", None)
            if not (isinstance(parent, ast.Call) and parent.func is node and _reason_ok(parent)):
                bad.append(node.lineno)
        elif isinstance(node, ast.Constant) and node.value == _MARKER:
            bad.append(node.lineno)
    return bad


def test_every_opt_out_states_its_reason():
    offenders = []
    for path in iter_files(TESTS_ROOT):
        # Only a file that names the marker can use it; parse just those.
        if path.name == _GUARD_HOME or _MARKER not in path.read_text(encoding="utf-8", errors="replace"):
            continue
        tree = parse_module(path)
        if tree is None:
            continue
        offenders += [f"{relpath(path, REPO_ROOT)}:{line}" for line in unjustified_opt_outs(tree)]
    assert not offenders, (
        f"`{_MARKER}` without a non-empty reason= (tests/_network_guard.py). A test that "
        "reaches a non-loopback host says why, in the marker:\n  " + "\n  ".join(offenders))


def test_opt_out_detector_has_teeth():
    assert_pin_has_teeth(
        lambda tree: unjustified_opt_outs(tree),
        bad_source=(
            "import pytest\n"
            f"@pytest.mark.{_MARKER}\n"
            "def test_a(): pass\n"
            f"@pytest.mark.{_MARKER}(reason='')\n"
            "def test_b(): pass\n"
            "def test_c(request):\n"
            f"    request.node.add_marker('{_MARKER}')\n"
        ),
        good_source=(
            "import pytest\n"
            f"@pytest.mark.{_MARKER}(reason='talks to a public test server on purpose')\n"
            "def test_a(): pass\n"
        ),
    )
    bad = parse_source(f"import pytest\n@pytest.mark.{_MARKER}\ndef test_a(): pass\n")
    assert unjustified_opt_outs(bad) == [2]


def registers_the_guard(tree: ast.AST) -> bool:
    """True when a module-level ``pytest_configure`` calls ``_network_guard.register(...)``."""
    for fn in getattr(tree, "body", []):
        if isinstance(fn, ast.FunctionDef) and fn.name == "pytest_configure":
            for node in ast.walk(fn):
                if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                        and node.func.attr == "register"
                        and isinstance(node.func.value, ast.Name)
                        and node.func.value.id == "_network_guard"):
                    return True
    return False


def test_the_root_conftest_registers_the_guard():
    tree = parse_module(TESTS_ROOT / "conftest.py")
    assert tree is not None and registers_the_guard(tree), (
        "tests/conftest.py pytest_configure must call _network_guard.register(config): "
        "without it no test is guarded")


def test_registration_detector_has_teeth():
    assert_pin_has_teeth(
        lambda tree: not registers_the_guard(tree),
        bad_source=(
            "import _network_guard\n"
            "def pytest_configure(config):\n"
            "    pass\n"
            "def helper(config):\n"
            "    _network_guard.register(config)\n"
        ),
        good_source=(
            "import _network_guard\n"
            "def pytest_configure(config):\n"
            "    _network_guard.register(config)\n"
        ),
    )
