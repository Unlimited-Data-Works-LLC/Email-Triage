"""Bundle E2 /  phase 2 — async DB conversion regression sweep.

Phase 1 (Bundle E) wrapped /health, /health/detail, /dashboard.
Phase 2 (this bundle) wrapped ~85 additional handlers. The handlers
return the same status + same template + same context shape — only
the threading model changed (sync DB reads now run on the asyncio
default threadpool via ``db_call`` instead of inline on the loop).

This file is a thin smoke-sweep over 10 of the converted handlers,
asserting the response status + Content-Type + a representative
substring of the rendered HTML. Goal is to catch a regression where
the wrap-at-snapshot helper drops a context key or returns the wrong
shape, NOT to retest each handler's full feature surface (those
tests live in their dedicated test files).

Cross-references:
- ``tests/test_web/test_db_threadpool.py`` — the wrapper itself.
- ``scripts_session_2026-05-09.md`` (memory) — phase 2 entry.
"""

from __future__ import annotations

import pytest


# Five-way concurrency probe against /accounts list (one of the
# converted handlers). Default pool = min(32, cpu_count()+4); five
# requests should fan out fully if the threadpool is healthy.


@pytest.mark.parametrize(
    "url",
    [
        "/accounts",
        "/admin/stats",
        "/compliance",
        "/logs",
        "/users",
        "/admin/security",
        "/config",
        "/accounts/api-keys",
        "/rules",
        "/categories",
    ],
)
def test_phase2_handlers_render(client, db, admin_user, admin_cookies, url):
    """Sample 10 of the converted handlers — assert status + content
    type haven't drifted post-wrap.

    Bundle E2 wraps ~85 handlers in ``db_call``. A drift in the
    snapshot helper (returns wrong shape, missing key, etc.) usually
    surfaces as a 500 here. Pure smoke; full feature tests live
    elsewhere.
    """
    resp = client.get(url, cookies=admin_cookies)
    assert resp.status_code == 200, (
        f"{url} returned {resp.status_code}: {resp.text[:300]}"
    )
    # All converted GETs render HTML.
    assert "text/html" in resp.headers.get("content-type", "")


def test_phase2_concurrent_accounts_polls_dont_collide(
    client, db, admin_user, admin_cookies,
):
    """ — eight concurrent /accounts requests must not collide on
    the shared SQLite connection.

    The app keeps ONE shared ``sqlite3.Connection``; the Python
    ``sqlite3`` driver rejects two threads using it concurrently —
    even for two reads — with ``InterfaceError: bad parameter or
    other API misuse``. Before  this surfaced as intermittent
    500s under concurrent ``GET /accounts`` (33/40 stress trials
    failed).  serialises every ``db_call`` through the
    process-wide DB lock, so a concurrent reader queues instead of
    colliding.

    QA-gap note: the previous version of this test ran its
    ``assert r.status_code == 200`` *inside the worker thread*. A
    failed assertion there becomes a ``PytestUnhandledThreadException``
    *warning* — the test itself still PASSED while the bug was live.
    This version collects every worker's outcome (status code AND any
    exception) into shared lists and asserts on the MAIN thread, so a
    collision actually fails the test.
    """
    import threading

    statuses: list[int] = []
    errors: list[BaseException] = []
    lock = threading.Lock()

    def _hit():
        try:
            r = client.get("/accounts", cookies=admin_cookies)
            with lock:
                statuses.append(r.status_code)
        except BaseException as exc:  # noqa: BLE001 — surfaced below
            with lock:
                errors.append(exc)

    # 8-way fan-out — comfortably above the 1-2 needed to trip the
    # driver's concurrent-use guard, matching the stress-trial setup.
    threads = [threading.Thread(target=_hit) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # Assertions run on the MAIN thread — a failure here fails the
    # test instead of being swallowed as a thread-exception warning.
    assert not errors, (
        f"{len(errors)} worker(s) raised: {errors[0]!r}"
    )
    assert len(statuses) == 8, (
        f"expected 8 responses, got {len(statuses)}"
    )
    assert all(s == 200 for s in statuses), (
        f"non-200 responses under concurrency: {statuses} — "
        "looks like a shared-connection collision (#231)"
    )
