"""Pin: the installed pytest keeps a nested conftest's fixtures on interleaved file args (punch 629, N-614).

Why this exists. pytest 9.1.0 and 9.1.1 regressed (pytest-dev/pytest#14964, from
#14004): when the file arguments leave a nested package for a file in its parent
directory and then come back (``nested/test_a.py test_top.py nested/test_b.py``),
the later nested file is collected under a node that never receives the nested
conftest's fixtures. A requested fixture then ERRORS ("fixture not found"), and an
AUTOUSE fixture is dropped SILENTLY, so a test can PASS without the isolation its
conftest supplies: a false PASS, fail-OPEN on test evidence. On the 9.1.1 lock the
curated 20-file run showed 21 such errors (builder F2a section 7).

``pyproject.toml`` caps the dev extra below 9.1 and the N-542 pin holds the dev lock
inside that cap, so 9.1.x cannot be locked by accident. This pin is for the moment the
cap is raised: it checks the PROPERTY on whatever pytest is installed, in a child
process over a planted tree, whatever the version number says.

The planted tree is the upstream trigger: a nested PACKAGE with its own conftest (a
requested fixture and an autouse one), and the parent-dir file passed between the two
nested files. It runs in ``tmp_path`` with its own ``pytest.ini`` and rootdir, plugin
autoload off and xdist and the cache provider disabled, so neither the project's
conftest nor its addopts reach it. A control run with the nested files adjacent comes
first: the rig must PASS before its interleaved RED means anything.

Seen RED once, as the DA required (panel F2a): this file under pytest 9.1.1 in a
scratch the deploy host container failed the interleaved run and passed the control; the same
container on 9.0.3 passed both (fold report, batchF2a-fold.md).
"""

from __future__ import annotations

import os
import re
import subprocess
import sys

import pytest

_CONFTEST = '''import pytest


@pytest.fixture
def nested_fixture():
    return "nested"


@pytest.fixture(autouse=True)
def nested_autouse(request):
    request.node.nested_autouse_ran = True
'''

_NESTED_TEST = '''def test_requested_fixture(nested_fixture):
    assert nested_fixture == "nested"


def test_autouse_fixture_ran(request):
    assert getattr(request.node, "nested_autouse_ran", False), "the nested autouse fixture did not run"
'''

_FILES = {
    "pytest.ini": "[pytest]\n",
    "nested/__init__.py": "",
    "nested/conftest.py": _CONFTEST,
    "nested/test_a.py": _NESTED_TEST,
    "nested/test_b.py": _NESTED_TEST,
    "test_top.py": "def test_top():\n    pass\n",
}
_EXPECTED_PASSED = 5  # 2 nested tests in each nested file, plus test_top


def _run(root, order: list[str]) -> tuple[int, str]:
    env = {k: v for k, v in os.environ.items() if k not in ("PYTEST_ADDOPTS", "PYTEST_PLUGINS")}
    env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "-p", "no:cacheprovider", "-p", "no:xdist",
         "-c", str(root / "pytest.ini"), "--rootdir", str(root), "-q", *order],
        cwd=root, env=env, capture_output=True, text=True, timeout=120,
    )
    return proc.returncode, proc.stdout + proc.stderr


def _summary_ok(out: str) -> bool:
    last = [ln for ln in out.splitlines() if ln.strip()][-1:] or [""]
    return (re.search(rf"\b{_EXPECTED_PASSED} passed\b", last[0]) is not None
            and not re.search(r"\b(failed|errors?)\b", last[0]))


def test_nested_conftest_fixtures_reach_both_nested_files_on_interleaved_args(tmp_path) -> None:
    for rel, text in _FILES.items():
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    adjacent = ["nested/test_a.py", "nested/test_b.py", "test_top.py"]
    rc, out = _run(tmp_path, adjacent)
    assert rc == 0 and _summary_ok(out), (
        f"control run (nested files adjacent) did not pass {_EXPECTED_PASSED} tests on pytest "
        f"{pytest.__version__}: the rig is broken, not the property\n{out[-3000:]}")

    interleaved = ["nested/test_a.py", "test_top.py", "nested/test_b.py"]
    rc, out = _run(tmp_path, interleaved)
    assert rc == 0 and _summary_ok(out), (
        f"pytest {pytest.__version__} loses the nested conftest's fixtures for nested/test_b.py "
        "when a parent-dir file sits between the nested files (pytest-dev/pytest#14964). A "
        "requested fixture errors and an autouse one is dropped silently (a false PASS). Keep "
        f"the pyproject cap below this version.\n{out[-3000:]}")
