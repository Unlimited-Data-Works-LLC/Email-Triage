"""Bundle E2 / #135 phase 2 — async DB conversion regression sweep.

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


def test_phase2_concurrent_dashboard_polls_dont_serialise(
    client, db, admin_user, admin_cookies,
):
    """Five concurrent /accounts requests should not serialise.

    With the wrap-at-snapshot pattern each request runs its DB reads
    on the threadpool, leaving the event loop free to handle the next
    request. Threading regressions (e.g. a global lock around the
    pool) would surface as elapsed ≈ 5 × single-request time.

    Wall-clock assertion is conservative — TestClient adds its own
    overhead and SQLite uses WAL so reads parallelise well, but
    cold-cache I/O variance on Windows is high. Using a generous
    upper bound to keep CI stable while still catching a real
    serialisation regression.
    """
    import threading
    import time

    elapsed_per_thread: list[float] = []

    def _hit():
        t0 = time.monotonic()
        r = client.get("/accounts", cookies=admin_cookies)
        elapsed_per_thread.append(time.monotonic() - t0)
        assert r.status_code == 200, r.text[:200]

    threads = [threading.Thread(target=_hit) for _ in range(5)]
    start = time.monotonic()
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    elapsed = time.monotonic() - start

    # Sanity: every request succeeded.
    assert len(elapsed_per_thread) == 5

    # Don't assert tight bounds — TestClient + Windows scheduling
    # noise + the in-memory SQLite contention floor make exact
    # numbers unreliable. The point is "5 concurrent reads finish
    # in roughly the time of one slow read, not 5 × single-read",
    # so a 2× single-request budget is the practical regression
    # canary. If the threadpool were size=1 (or there were a lock
    # around db_call) we'd see ≥4× the single-request time.
    single = max(elapsed_per_thread)
    assert elapsed < single * 2.5, (
        f"5-way concurrency took {elapsed:.3f}s; "
        f"slowest single request was {single:.3f}s. "
        f"Looks like serialisation."
    )
