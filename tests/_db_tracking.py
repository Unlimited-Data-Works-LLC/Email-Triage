"""SSOT funnel for test-opened SQLite connections (ResourceWarning bucket 1).

``internal documentation`` bucket 1: dozens of test fixtures and plain
``_make_db`` / ``_fresh_db`` helpers opened a SQLite/SQLCipher connection via
``init_db()`` (or a ``FlowStore``) and never ``.close()``-d it, so the garbage
collector closed it late and emitted ``ResourceWarning: unclosed database in
<sqlite3.Connection ...>`` — by far the largest bucket once ``-W default`` is on.

PRODUCT code is NOT a leaker: every ``open_dedicated_conn`` site in
``src/email_triage`` (backup.py, single_flight.py, web/acme_job_state.py,
engine/store.py) closes via ``try/finally`` (audited 2026-06-13). This bucket is
test-fixture hygiene only.

Rather than repeat a ``yield``/``close()`` body in ~20 fixtures AND add a
``.close()`` at ~50 plain-helper call sites — both of which drift — every
test-side DB opener funnels through ``tracked_db()`` / ``track()`` here, and the
autouse ``_close_tracked_test_conns`` fixture in ``conftest.py`` closes the
registered objects after each test. ONE funnel, one teardown — the SSOT/no-
duplicate discipline (project_style_guide directive 5) applied to test infra.

Importable from any subdir test as ``from _db_tracking import tracked_db`` —
``tests`` is on ``pythonpath`` (pyproject ``[tool.pytest.ini_options]``), the
same mechanism the structural-drift pins use for ``from _pin_harness import``.
"""

from __future__ import annotations

from typing import TypeVar

#: Connections / stores opened during the CURRENT test, awaiting teardown-close.
#: Cleared after every test by the autouse fixture; a module global is correct
#: because pytest-xdist gives each worker its own import of this module.
_OPEN: list = []

_T = TypeVar("_T")


def track(closeable: _T) -> _T:
    """Register an already-opened ``.close()``-able (sqlite3 conn, FlowStore, …)
    for autouse teardown-close, and return it unchanged so callers can inline:
    ``conn = track(open_something())``."""
    _OPEN.append(closeable)
    return closeable


def tracked_db(path: str = ":memory:"):
    """``init_db(path)`` + register for autouse teardown-close.

    Drop-in for the leaking ``return init_db(...)`` fixtures/helpers: swap
    ``init_db`` → ``tracked_db`` (default ``":memory:"``; pass a file path for
    the ``tmp_path`` fixtures)."""
    from email_triage.web.db import init_db

    return track(init_db(path))


def _close_all() -> None:
    """Close every registered object, swallowing per-object close errors.

    Idempotent / double-close-safe: ``sqlite3.Connection.close()`` and
    ``FlowStore.close()`` tolerate being called on an already-closed object, so
    a test that closes its own connection is harmless here."""
    while _OPEN:
        obj = _OPEN.pop()
        try:
            obj.close()
        except Exception:
            pass
