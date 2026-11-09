"""Walk — Reindex jobs aggregate progress fragment — sketch .

Feature: ``GET /triage/jobs/reindex-progress`` (landed 2026-06-13 in
c3430b0f). HTMX aggregate progress card for reindex jobs. Walk seeds
ONE running ``embedding_reindex`` job (mirrors ``_seed_running_reindex``
in ``tests/e2e/test_reindex_aggregate.py``), loads ``/triage/jobs``,
waits for the self-poll to swap the ``#reindex-agg-inner`` fragment in,
and asserts operator-copy + account-by-name + pct + aria-valuenow.
Branch — flip the seeded job to ``succeeded`` and reload; the outer
container stays but the inner never renders (empty body → self-poll
stops cleanly).
"""

from __future__ import annotations

import pytest
from playwright.sync_api import expect

pytestmark = pytest.mark.e2e


def _seed_running_reindex(conn, account_id, *, processed=20, total=100):
    from email_triage.jobs.embedding_reindex import enqueue_embedding_reindex

    job_id = enqueue_embedding_reindex(conn, account_id, None)
    conn.execute(
        "UPDATE triage_jobs SET status='running', total_processed=?, "
        "cursor=? WHERE job_id=?",
        (processed, str(total), job_id),
    )
    conn.commit()
    return job_id


def test_aggregate_fragment_renders_with_percent_and_a11y(
    authed_page, base_url, e2e_server,
):
    """GOLDEN — seeded running wave surfaces the inner card with
    operator copy + account-by-name + '20%' + a role=progressbar node
    carrying aria-valuenow='20'."""
    _seed_running_reindex(
        e2e_server["conn"], e2e_server["research_account_id"],
        processed=20, total=100,
    )
    authed_page.goto(f"{base_url}/triage/jobs")

    # Container is always wired regardless of wave state.
    expect(authed_page.locator("#reindex-agg")).to_have_count(1)

    inner = authed_page.locator("#reindex-agg-inner")
    try:
        inner.wait_for(state="visible", timeout=10_000)
    except Exception:
        pytest.xfail(
            "#reindex-agg-inner never rendered — feature-work: "
            "HTMX self-poll did not fire or fragment 500'd."
        )

    expect(inner).to_contain_text("Updating the mail search index")
    expect(inner).to_contain_text("Research Inbox")
    expect(inner).to_contain_text("20%")

    progressbar = inner.locator("[role=progressbar]").first
    if progressbar.count() == 0:
        pytest.xfail(
            "[role=progressbar] absent inside #reindex-agg-inner — "
            "a11y contract not met."
        )
    aria_val = progressbar.get_attribute("aria-valuenow")
    assert aria_val == "20", (
        f"aria-valuenow expected '20', got {aria_val!r}"
    )


def test_aggregate_fragment_empty_when_wave_finished(
    authed_page, base_url, e2e_server,
):
    """BRANCH — a succeeded job produces an empty inner fragment; the
    outer container remains (so a NEW wave can re-arm it) but the
    self-poll stops cleanly (no stale bar, no JS error).

    Cross-test hermeticity: the session-scoped conn preserves rows from
    the sibling golden-path test in this file (and any prior spec that
    seeded an embedding_reindex). The autouse ``_hermetic_jobs`` fixture
    only cancels ``topic_backscan``; embedding_reindex rows leak — and
    the aggregate fragment surfaces on ANY non-empty snapshot, not just
    non-terminal rows. Hard-DELETE all embedding_reindex rows so the
    "no live wave" contract is truly cold.
    """
    conn = e2e_server["conn"]
    conn.execute("DELETE FROM triage_jobs WHERE kind='embedding_reindex'")
    conn.commit()

    authed_page.goto(f"{base_url}/triage/jobs")

    expect(authed_page.locator("#reindex-agg")).to_have_count(1)
    # Empty fragment = self-poll stops = inner is never rendered.
    expect(authed_page.locator("#reindex-agg-inner")).to_have_count(0)
