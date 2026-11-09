"""Pin: the Playwright e2e tier never shares a pytest process with other tests, and no test
leaves an asyncio loop registered as running (flk, 2026-10-23).

Why this exists. pytest-playwright's session-scoped SYNC ``playwright`` fixture leaves its
dispatcher loop registered as the running loop of the worker thread for the rest of the
session (see ``tests/_e2e_isolation_guard.py`` for the mechanism and the measurements), so
every ``asyncio.run()`` / pytest-asyncio test that follows on that worker fails with
``cannot be called from a running event loop``. A sweep list that NAMES an e2e file defeats
``addopts = --ignore=tests/e2e`` and pulled 30 unrelated tests red; the symptom pointed at the
victims, never at the cause. ``tests/conftest.py`` now registers the guard, which refuses a
mixed run at collection and fails a leaking test under its own node id.

These are the teeth. Each case runs the SAME ``register()`` the repo conftest calls, in a child
pytest over a planted tree (own ``pytest.ini``, plugin autoload off, xdist and cache provider
off, so neither the project's conftest nor its addopts reach it). The rig must PASS before its
RED means anything: the unit-only, e2e-only, deselected and collect-only runs are the controls,
and the leaker-without-guard run shows the victim really fails when nothing guards.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

_TESTS_DIR = Path(__file__).resolve().parent

_CONFTEST = '''
import os
from pathlib import Path

import _e2e_isolation_guard as guard


def pytest_configure(config):
    if os.environ.get("PLANTED_GUARD") == "1":
        guard.register(config, e2e_dir=Path(__file__).parent / "e2e")
'''

_LEAK = '''
import asyncio


def {name}():
    asyncio.events._set_running_loop(asyncio.new_event_loop())
'''

_FILES = {
    "pytest.ini": "[pytest]\n",
    "conftest.py": _CONFTEST,
    "e2e/test_spec.py": "def test_spec():\n    pass\n",
    "e2e/test_leaky_spec.py": _LEAK.format(name="test_leaky_spec"),
    "test_unit.py": "def test_unit():\n    pass\n",
    "test_leaker.py": _LEAK.format(name="test_leaker"),
    "test_victim.py": (
        "import asyncio\n\n\ndef test_victim():\n"
        "    assert asyncio.events._get_running_loop() is None\n"
    ),
}


@pytest.fixture(scope="module")
def tree(tmp_path_factory) -> Path:
    root = tmp_path_factory.mktemp("e2e_guard_tree")
    for rel, text in _FILES.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


def _run(root: Path, *args: str, guard: bool = True, xdist: bool = False) -> tuple[int, str]:
    env = {k: v for k, v in os.environ.items() if k not in ("PYTEST_ADDOPTS", "PYTEST_PLUGINS")}
    env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
    env["PYTHONPATH"] = str(_TESTS_DIR)
    env["PLANTED_GUARD"] = "1" if guard else "0"
    xdist_args = ["-p", "xdist.plugin", "-n", "2"] if xdist else ["-p", "no:xdist"]
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "-p", "no:cacheprovider", *xdist_args,
         "-c", str(root / "pytest.ini"), "--rootdir", str(root), "-q", *args],
        # 300 s, not 120: the xdist leg starts a controller plus two workers, and under a
        # parallel full sweep that took over 120 s (1 failed in 15084, 2026-10-31). The
        # timeout catches a hang, not a slow start.
        cwd=root, env=env, capture_output=True, text=True, timeout=300,
    )
    return proc.returncode, proc.stdout + proc.stderr


def _summary(out: str) -> str:
    return ([ln for ln in out.splitlines() if ln.strip()] or [""])[-1]


def test_the_repo_conftest_registers_the_guard_in_this_session(request) -> None:
    import _e2e_isolation_guard as guard

    assert request.config.pluginmanager.has_plugin(guard.PLUGIN_NAME), (
        "tests/conftest.py pytest_configure no longer registers the e2e isolation guard: a run "
        "that mixes tests/e2e with other tests is no longer refused, and a test that leaves a "
        "running asyncio loop is no longer failed at the leaker")


def test_controls_unit_only_and_e2e_only_runs_pass(tree) -> None:
    rc, out = _run(tree, "test_unit.py")
    assert rc == 0 and re.search(r"\b1 passed\b", _summary(out)), f"unit-only control failed\n{out}"
    rc, out = _run(tree, "e2e/test_spec.py")
    assert rc == 0 and re.search(r"\b1 passed\b", _summary(out)), f"e2e-only control failed\n{out}"


@pytest.mark.parametrize("xdist", [False, True], ids=["serial", "xdist-n2"])
def test_a_run_that_mixes_e2e_with_other_tests_is_refused_at_collection(tree, xdist) -> None:
    # Under xdist the CONTROLLER refuses: a worker that exits during collection surfaces only as
    # an anonymous crash (INTERNALERROR on a crashed item) with the cause lost.
    rc, out = _run(tree, "e2e/test_spec.py", "test_unit.py", xdist=xdist)
    assert rc == 4, f"a mixed e2e + non-e2e run was NOT refused with the usage-error code\n{out}"
    assert "cannot share a pytest process" in out and "e2e/test_spec.py::test_spec" in out, (
        f"the refusal must name the cause and the e2e item\n{out}")
    assert "INTERNALERROR" not in out and " passed" not in out, f"the refusal must be clean and run nothing\n{out}"
    # The refusal is a property of the SELECTED items: deselecting one side, or only listing
    # them, is not a mixed run.
    rc, out = _run(tree, "e2e/test_spec.py", "test_unit.py", "-k", "test_unit")
    assert rc == 0 and re.search(r"\b1 passed\b", _summary(out)), f"deselected-e2e control failed\n{out}"
    rc, out = _run(tree, "e2e/test_spec.py", "test_unit.py", "--collect-only")
    assert rc == 0, f"a collect-only listing must not be refused\n{out}"


def test_the_refusal_is_the_guard_and_not_the_rig(tree) -> None:
    rc, out = _run(tree, "e2e/test_spec.py", "test_unit.py", guard=False)
    assert rc == 0 and re.search(r"\b2 passed\b", _summary(out)), (
        f"without the guard the same mixed run must pass, or the refusal proves nothing\n{out}")


def test_a_leaked_running_loop_fails_the_leaker_and_not_the_next_test(tree) -> None:
    rc, out = _run(tree, "test_leaker.py", "test_victim.py", guard=False)
    assert rc != 0 and "test_victim.py::test_victim" in out and "test_leaker.py::test_leaker" not in out.split("short test summary")[-1], (
        f"without the guard the VICTIM must be the red one (the bug being guarded)\n{out}")
    rc, out = _run(tree, "test_leaker.py", "test_victim.py")
    tail = out.split("short test summary")[-1] if "short test summary" in out else out
    assert rc != 0, f"the guard did not fail the leaking test\n{out}"
    assert "test_leaker.py::test_leaker" in out and "left an asyncio loop registered as RUNNING" in out, (
        f"the failure must carry the LEAKER's node id and the cause\n{out}")
    assert "test_victim.py::test_victim" not in tail, f"the victim failed too; the leak was not cleared\n{out}"
    # The leaker's body passes and its TEARDOWN errors; the victim passes: 2 passed, 1 error.
    assert re.search(r"\b2 passed\b.*\b1 error\b", _summary(out)) and "failed" not in _summary(out), (
        f"expected the leaker errored at teardown and the victim passed\n{out}")


def test_an_e2e_only_session_is_exempt_from_the_leak_check(tree) -> None:
    # Sync Playwright legitimately holds its loop for the session; the collection check is what
    # keeps that holder out of every other session.
    rc, out = _run(tree, "e2e/test_leaky_spec.py")
    assert rc == 0 and re.search(r"\b1 passed\b", _summary(out)), f"e2e-only leaky spec was failed\n{out}"
