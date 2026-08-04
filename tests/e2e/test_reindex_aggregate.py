"""E2E —  cross-account reindex aggregate on the Bulk runs page.

Proves the self-polling HTMX fragment end to end in a real browser: with a live
reindex wave seeded into the server's DB, the rolled-up bar renders on
/triage/jobs with the account by name and a percentage; with no wave the
container stays empty (no stale bar, no JS error).
"""

from __future__ import annotations

import pytest
from playwright.sync_api import expect

pytestmark = pytest.mark.e2e


def _seed_running_reindex(conn, account_id, *, processed=20, total=100):
    from email_triage.jobs.embedding_reindex import enqueue_embedding_reindex
    job_id = enqueue_embedding_reindex(conn, account_id, None)
    conn.execute(
        "UPDATE triage_jobs SET status='running', total_processed=?, cursor=? "
        "WHERE job_id=?",
        (processed, str(total), job_id),
    )
    conn.commit()
    return job_id


def test_jobs_page_empty_when_no_wave(authed_page, base_url):
    """No reindex jobs seeded by default → the aggregate container loads but
    renders empty (no bar)."""
    authed_page.goto(f"{base_url}/triage/jobs")
    # The container exists (wired into the page)…
    expect(authed_page.locator("#reindex-agg")).to_have_count(1)
    # …but with no active wave it carries no rolled-up bar.
    expect(authed_page.locator("#reindex-agg-inner")).to_have_count(0)


def test_jobs_page_shows_reindex_aggregate(authed_page, base_url, e2e_server):
    """Seed a running reindex job; the rolled-up bar renders on the Bulk runs
    page with the account by NAME + a percentage."""
    _seed_running_reindex(
        e2e_server["conn"], e2e_server["research_account_id"],
        processed=20, total=100,
    )
    authed_page.goto(f"{base_url}/triage/jobs")
    bar = authed_page.locator("#reindex-agg-inner")
    expect(bar).to_be_visible()
    expect(bar).to_contain_text("Updating the mail search index")
    # Account surfaced by name (feedback_no_account_id_alone), not bare number.
    expect(bar).to_contain_text("Research Inbox")
    # The wave is 20/100 → 20%.
    expect(bar).to_contain_text("20%")
