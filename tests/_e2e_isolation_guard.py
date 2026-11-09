"""Guard: the Playwright e2e tier never shares a pytest process with the asyncio tests.

Why this exists (flk, 2026-10-23). The sync Playwright fixture that pytest-playwright
starts once per session (``playwright/sync_api/_context_manager.py``, ``greenlet_main``)
runs its dispatcher loop with ``loop.run_until_complete(...)`` inside a greenlet and then
switches back to the test. ``run_until_complete`` has registered that loop as THE running
loop of the thread (``events._set_running_loop``) and its reset never runs, because the
greenlet is parked inside it. So from the first e2e spec until the worker exits, every
``asyncio.run()`` and every pytest-asyncio runner on that thread raises
``Runner.run() cannot be called from a running event loop`` (or ``Cannot run the event
loop while another loop is running`` at runner teardown). The victims are unrelated tests
that pass alone: measured on the 668 sweep, chunk 0, ``-n 2``, 43 failures and errors in
four to five files, all on the one worker that drew an e2e spec first. A full-tree run that
included ``tests/e2e`` failed 270 tests the same way (``582-b7-sweep-run1-e2e-polluted``)
and was papered over by re-running without e2e.

``addopts = --ignore=tests/e2e`` keeps the tier out of a default run, but pytest does not
apply ``--ignore`` to a path NAMED on the command line, so a sweep list that names an e2e
file pulls the whole tier into the process. e2e is its own tier (``scripts/test-e2e.sh``,
``.github/workflows/e2e.yml``, the pre-push hook: ``pytest tests/e2e ... -o addopts=``).

Two checks, each fails at the cause and names it:

* **Collection** (``refuse_mixed_session``): a run that selects any item under
  ``tests/e2e`` together with any item outside it is refused before a test starts, with the
  cause and the first e2e and non-e2e node ids. The rule is a property of the selected items,
  not a count or a file list. Under xdist the CONTROLLER refuses (a worker that exits during
  collection only shows up as an anonymous crash); without xdist, the collecting process does.
* **Teardown** (``_Guard.pytest_runtest_teardown``): in a session with no e2e item, a test
  that leaves an asyncio loop registered as running on its thread fails (an ERROR at ITS
  teardown, under its own node id), and the registration is cleared so the leak is reported
  once, at the leaker, instead of on every later async test. An e2e-only session is exempt by
  construction (sync Playwright legitimately holds its loop for the whole session); that is
  the one known holder and the collection check keeps it out of every other session.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

E2E_DIR = Path(__file__).resolve().parent / "e2e"
PLUGIN_NAME = "e2e-isolation-guard"

_MIXED_MSG = (
    "tests/e2e (sync Playwright) cannot share a pytest process with other tests: the sync "
    "Playwright fixture leaves its event loop registered as running on the worker thread for "
    "the rest of the session, so every later asyncio.run() / pytest-asyncio test on that "
    "worker fails with 'cannot be called from a running event loop'. Run the e2e tier in its "
    "own process (scripts/test-e2e.sh, or `pytest tests/e2e --browser chromium -o addopts=`) "
    "and keep it out of every other test list. Selected e2e items: {n_e2e} (first: {first_e2e}); "
    "selected non-e2e items: {n_other} (first: {first_other})."
)


def split_e2e(nodeids, rootpath: Path, e2e_dir: Path = E2E_DIR) -> tuple[list[str], list[str]]:
    """``(e2e_ids, other_ids)`` for the selected node ids (relative to ``rootpath``)."""
    e2e_root = e2e_dir.resolve()
    verdict: dict[str, bool] = {}
    e2e: list[str] = []
    other: list[str] = []
    for nodeid in nodeids:
        file_part = nodeid.split("::", 1)[0]
        if file_part not in verdict:
            try:
                verdict[file_part] = (Path(rootpath) / file_part).resolve().is_relative_to(e2e_root)
            except (OSError, ValueError):
                verdict[file_part] = False
        (e2e if verdict[file_part] else other).append(nodeid)
    return e2e, other


def refuse_mixed_session(nodeids, rootpath: Path, e2e_dir: Path = E2E_DIR) -> None:
    """End the session (``pytest.exit``, code 4) when ``nodeids`` mixes e2e and non-e2e items."""
    e2e, other = split_e2e(nodeids, rootpath, e2e_dir)
    if e2e and other:
        pytest.exit(
            _MIXED_MSG.format(
                n_e2e=len(e2e), first_e2e=e2e[0], n_other=len(other), first_other=other[0]),
            returncode=4,
        )


_BEFORE = pytest.StashKey[object]()


class _Guard:
    """Registered by ``register`` (called from ``tests/conftest.py`` ``pytest_configure``)."""

    def __init__(self, e2e_dir: Path = E2E_DIR) -> None:
        self.e2e_dir = e2e_dir
        self.strict = True  # no e2e item selected => any leaked running loop is a leak

    @pytest.hookimpl(trylast=True)
    def pytest_collection_modifyitems(self, config, items):
        # trylast: ``-k`` / ``-m`` deselection has already run, so ``items`` is what will run.
        if config.getoption("collectonly", default=False):
            return  # nothing runs, so nothing can leak a loop
        ids = [item.nodeid for item in items]
        self.strict = not split_e2e(ids, config.rootpath, self.e2e_dir)[0]
        if not hasattr(config, "workerinput"):  # an xdist worker leaves the refusal to its controller
            refuse_mixed_session(ids, config.rootpath, self.e2e_dir)

    @pytest.hookimpl(optionalhook=True)
    def pytest_xdist_node_collection_finished(self, node, ids):
        # The xdist controller never collects; it receives each worker's selected ids here.
        refuse_mixed_session(ids, node.config.rootpath, self.e2e_dir)

    @pytest.hookimpl(wrapper=True)
    def pytest_runtest_setup(self, item):
        item.stash[_BEFORE] = asyncio.events._get_running_loop()
        return (yield)

    @pytest.hookimpl(wrapper=True)
    def pytest_runtest_teardown(self, item, nextitem):
        try:
            return (yield)
        finally:
            self._check(item)

    def _check(self, item) -> None:
        # ``finally`` of the teardown wrapper: every function-scoped finalizer (the
        # pytest-asyncio runner, async fixtures) has already run.
        if not self.strict or item.stash.get(_BEFORE, None) is not None:
            return
        leaked = asyncio.events._get_running_loop()
        if leaked is None:
            return
        asyncio.events._set_running_loop(None)
        pytest.fail(
            f"{item.nodeid} left an asyncio loop registered as RUNNING on its thread "
            f"({leaked!r}). Every later asyncio.run() / pytest-asyncio test on this worker "
            "would fail with 'cannot be called from a running event loop'; the registration "
            "was cleared so the failure lands here, at the test that leaked it.",
            pytrace=False,
        )


def register(config: pytest.Config, e2e_dir: Path = E2E_DIR) -> None:
    """Idempotent: register the guard plugin on ``config`` (called from ``pytest_configure``)."""
    if not config.pluginmanager.has_plugin(PLUGIN_NAME):
        config.pluginmanager.register(_Guard(e2e_dir), PLUGIN_NAME)
