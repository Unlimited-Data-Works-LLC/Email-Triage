"""Shared helpers for the retrofit Playwright walks.

Per ``feedback_code_reuse_directive`` — every helper in here is used by
at least TWO walk files; a helper needed by only one walk stays inline in
that walk (< 5 LOC or single-use = no lift). The conftest fixtures
(``authed_page``, ``base_url``, ``e2e_server``, ``page``) already do all
the heavy lifting (session-cookie mint, uvicorn socket, seeded admin +
inert accounts), so this module only carries the small shape utilities
the sketches reference by name.
"""

from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Awaitable, Callable, TypeVar

import pytest

_T = TypeVar("_T")


def goto_or_fail(
    page: Any,
    url: str,
    *,
    ok_range: tuple[int, int] = (200, 399),
) -> Any:
    """``page.goto(url)`` + LOUD status guard (Drive-7 defensive-xfail SSOT).

    Drive-7 fold class (DA-batch3 HIGH, Drive-6 close-out): a walk that does
    ``authed_page.goto(url)`` and then ``if x.count() == 0: pytest.xfail(...)``
    silently converts a 5xx (or a wrong-auth 4xx) REGRESSION into an xfail
    SKIPPED, voiding the walk's coverage claim. The HIPAA-critical instance
    was folded in Drive-6 (``test_provider_labels_apply.py:225-242``); this
    helper is the SSOT so the 5 non-HIPAA sites can adopt the same guard
    without hand-rolling the ``resp.status`` check.

    The guard asserts the response status falls in ``ok_range`` (default
    200-399; Playwright follows 3xx transparently, so 200-399 covers the
    landed-page shape). Any 4xx/5xx = regression → ``pytest.fail()`` LOUD
    (never xfail; a route regression MUST surface as CI-red, not a silent
    skip). The subsequent ``.count() == 0`` xfails on the SAME walk are
    then honest "feature-work missing" xfails (the page LOADED but the
    element isn't shipped yet), NOT "the route 500'd and every locator
    returned 0".

    Returns the ``Response`` from ``page.goto`` so callers can inspect
    body/headers if needed. ``None`` returns are passed through unchanged
    (Playwright returns ``None`` when the URL is a fragment-only nav on
    the same document — not a case any of our walks hits).
    """
    response = page.goto(url)
    if response is None:
        return response
    lo, hi = ok_range
    if not (lo <= response.status <= hi):
        # db-sme Drive-7 NTH#1: bounded body read — response.text() would
        # materialize a giant 5xx body before slicing; response.body() is
        # bytes so [:200] slices BEFORE decode. Bounded read is
        # determinism-preserving on huge error pages.
        body_head = "<body-not-readable>"
        try:
            body_head = response.body()[:200].decode("utf-8", errors="replace")
        except Exception:
            pass
        pytest.fail(
            f"Regression: GET {url} returned {response.status} "
            f"(expected {lo}-{hi}). This is a route regression, NOT "
            f"missing-feature. Fail LOUD (do not xfail). "
            f"body_head={body_head!r}"
        )
    return response


def start_5xx_watch(page: Any) -> list[tuple[str, int]]:
    """Attach a 5xx response listener; return the mutable capture list.

    Companion to :func:`assert_no_regression_or_xfail`. Attach BEFORE the
    click that triggers HTMX; the returned list accumulates every
    ``(url, status)`` tuple whose status >= 500 during the walk. On a
    subsequent ``wait_for(state="visible")`` timeout, pass the list to
    :func:`assert_no_regression_or_xfail` — a captured 5xx forces LOUD
    ``pytest.fail`` (regression), an empty list falls through to xfail
    (honest missing signal).

    Rationale: an HTMX POST that 5xxs leaves the swap target unchanged →
    ``wait_for(state="visible")`` times out → the walk xfails silently.
    That's the DA-batch3 HIGH anti-pattern in its HTMX-swap flavor.

    Cleanup contract (db-sme Drive-7 NTH#3): the listener is intentionally
    NOT ``page.off``'d — safe because ``pytest-playwright``'s ``page``
    fixture is function-scoped and its Playwright context is torn down
    at test end, dropping the callback along with the page. If a caller
    ever widens the ``page`` fixture to module- or session-scope, this
    helper MUST grow a ``finalizer`` (``page.off("response", cb)``) or
    the capture list will leak across tests.

    Race contract (DA Drive-7 NTH): Playwright's sync API dispatches
    ``page.on("response", ...)`` callbacks synchronously during any
    Playwright driver call (including ``wait_for``'s own pump), so a
    5xx that arrives during the ``wait_for(8s)`` window drains into
    ``recorded_5xx`` before the timeout returns. A theoretical
    sub-millisecond race exists between the timeout return and
    :func:`assert_no_regression_or_xfail` reading the list; do NOT
    add ``time.sleep(0)`` to "fix" it — Playwright's internal pump
    already resolved any in-flight event before wait_for raised.
    """
    recorded: list[tuple[str, int]] = []

    def _on_response(resp: Any) -> None:
        try:
            status = int(resp.status)
        except Exception:
            return
        if status >= 500:
            recorded.append((resp.url, status))

    page.on("response", _on_response)
    return recorded


def assert_no_regression_or_xfail(
    recorded_5xx: list[tuple[str, int]],
    xfail_msg: str,
) -> None:
    """Post-``wait_for``-timeout dispatch: LOUD fail on 5xx, else xfail.

    If :func:`start_5xx_watch` captured any 5xx response during the swap
    window, that is a route regression — surface it via ``pytest.fail``
    so CI goes RED (never xfail; the walk's coverage claim MUST NOT be
    silently voided by a 500 the operator won't see). Otherwise the
    signal-never-visible really is honest missing-feature → ``pytest.xfail``.
    """
    if recorded_5xx:
        first_url, first_status = recorded_5xx[0]
        pytest.fail(
            f"Regression: {first_status} response captured during walk — "
            f"{first_url!r}. This is a route regression, NOT missing-"
            f"feature. Fail LOUD (do not xfail). "
            f"all_5xx={recorded_5xx}"
        )
    pytest.xfail(xfail_msg)


def sync_run_in_thread(coro: Awaitable[_T]) -> _T:
    """Run *coro* in a fresh thread with a fresh event loop, return its result.

    Use this from SYNC ``def test_...`` bodies that need to await an
    ``async def`` product function (``push_provider_labels``,
    ``match_topics_for_message``, ``run_topic_backscan_job``,
    ``RegulatoryClockAction.execute``) instead of ``asyncio.run(coro)``.

    Why: the e2e session fixture stack (uvicorn thread, pytest-asyncio
    auto-mode, pytest-playwright's browser session) leaves an outer event
    loop reachable on the main thread once several walks have executed.
    A subsequent ``asyncio.run(coro)`` sees it and raises
    ``RuntimeError: asyncio.run() cannot be called from a running event
    loop``. Converting the test to ``async def`` doesn't help either —
    pytest-asyncio's Runner then hits the same outer loop and raises
    ``Runner.run() cannot be called from a running event loop``.

    A fresh thread has NO event loop of its own, so a private loop we
    build inside it is free of the outer conflict. The coroutine runs to
    completion or raises, and its result / exception is surfaced back to
    the caller synchronously via the ThreadPoolExecutor future.
    """
    def _in_thread() -> _T:
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(coro)
        finally:
            loop.close()

    with ThreadPoolExecutor(max_workers=1) as ex:
        return ex.submit(_in_thread).result()


def seed_backfill_capped(
    conn: Any,
    account_id: int,
    *,
    kind: str = "gmail_history",
    window: str = "last 7 days",
    recovered: int = 200,
) -> None:
    """Seed a backfill-capped chip for ``account_id``.

    Thin wrapper around ``email_triage.web._backfill_chip.mark_backfill_capped``.
    Kept in helpers because a walk that wants to prove PER-ACCOUNT isolation
    seeds two rows (N-211 R23 D2-shape) and the two-line arrange stays
    readable inside the flow.
    """
    from email_triage.web._backfill_chip import mark_backfill_capped

    mark_backfill_capped(
        conn,
        account_id=account_id,
        kind=kind,
        window=window,
        recovered=recovered,
    )


def force_llm_unhealthy(
    backend: str = "ollama",
    *,
    ttl_seconds: int = 300,
    reason: str = "e2e-no-backend",
) -> None:
    """Force the LLM fail-soft branch so guidance renders deterministically.

    Used by ``test_help_me.py`` and ``test_help_me_ask.py`` — both call
    it as their first line (no real Ollama in e2e). Mirrors the pattern
    already established in ``tests/e2e/test_help_me.py``.
    """
    from email_triage.llm_health import set_unhealthy

    set_unhealthy(backend, ttl_seconds=ttl_seconds, reason=reason)


def seed_running_regulatory_clock(
    e2e_server: dict,
    *,
    case_ref: str = "E2E-SECRET-CASE-REF",
    responsibility: str = "i_submit",
) -> int:
    """Seed one ``regulatory_clock_instance`` in state='running'.

    Shared by ``test_regulatory_clocks_dashboard.py`` and
    ``test_clock_disposition_actions.py`` — both need the SAME pattern
    already used by the reference spec ``tests/e2e/test_regulatory_clocks.py``
    (``create_clock_candidate`` on the ``IRB_AWARENESS`` def + UPDATE
    state='running'). Returns the new instance id.

    ``case_ref`` is retained as a PHI redaction anchor — the dashboard
    walk asserts it is NEVER rendered to the user; the disposition walk
    reuses the same value for the same PHI-hide invariant.
    """
    from email_triage.db.regulatory_clock import create_clock_candidate

    conn = e2e_server["conn"]
    acct_id = e2e_server.get("research_account_id") or e2e_server.get(
        "clinic_account_id"
    )
    def_id = conn.execute(
        "SELECT id FROM regulatory_clock_def WHERE code='IRB_AWARENESS'"
    ).fetchone()[0]
    iid = create_clock_candidate(
        conn,
        def_id=def_id,
        account_id=acct_id,
        case_ref=case_ref,
        responsibility=responsibility,
    )
    conn.execute(
        "UPDATE regulatory_clock_instance SET state='running' WHERE id=?",
        (iid,),
    )
    conn.commit()
    return int(iid)


def app_from_e2e_server(e2e_server: dict) -> Any:
    """Return the running FastAPI app from the ``e2e_server`` yield dict.

    ``ops-db-backup`` (sketch ) needs the live ``app.state.config`` to
    flip ``backup.enabled`` / ``backup.format`` before triggering the
    endpoint. The conftest exposes the app under key ``app``. If a caller
    holds only the ``conn``/``base_url`` handle, this raises a KeyError
    with a hint pointing at the conftest change.
    """
    try:
        return e2e_server["app"]
    except KeyError as exc:
        raise KeyError(
            "e2e_server does not expose 'app'; add it to the yield dict in "
            "tests/e2e/conftest.py so walk specs can reach app.state.config."
        ) from exc
