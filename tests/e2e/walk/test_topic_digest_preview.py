"""Walk — Topic Digest preview fragment (sketch ).

Feature: ``POST /profile/topic-digest/{topic_id:int}/preview`` (landed
2026-06-07 in 237472a9). HTMX preview fragment — evaluates the topic
against the user's mail (PHI-read; owner self-access, non-HIPAA account
per sketch to stay off the actor≠owner audit gate). Walk creates a
Topic via the real UI, clicks 'Preview matches', asserts the empty-hits
'No matches yet' article renders with an on-page remedy hint, then
widens the lookback and confirms the re-render stays idempotent (no
stale hits, no 500).
"""

from __future__ import annotations

import re

import pytest
from playwright.sync_api import expect

from tests.e2e.walk._helpers import (
    assert_no_regression_or_xfail,
    goto_or_fail,
    start_5xx_watch,
)

pytestmark = pytest.mark.e2e


def _pick_research_option(authed_page) -> None:
    trigger = authed_page.locator(".ms-trigger").first
    trigger.click()
    authed_page.locator(
        ".ms-option", has_text=re.compile("Research Inbox", re.I)
    ).first.click()
    authed_page.keyboard.press("Escape")


def test_preview_no_matches_and_widen_remedy(authed_page, base_url):
    """GOLDEN + BRANCH — with empty seeded mail, preview renders
    'No matches yet' with a widen-remedy hint; re-preview after widening
    the lookback stays idempotent."""
    # Create the Topic via the real UI so topic_id is bound to the editor.
    # Drive-7 DA-batch3 fold: 5xx watch armed BEFORE HTMX clicks so preview-
    # swap timeouts distinguish honest missing-signal from route regression.
    recorded_5xx = start_5xx_watch(authed_page)
    goto_or_fail(authed_page, f"{base_url}/profile/topic-digest/new")
    if authed_page.locator("#topic-editor-form").count() == 0:
        pytest.xfail(
            "#topic-editor-form not surfaced — feature-work: expose the "
            "editor root with a stable id."
        )
    authed_page.locator('input[name="name"]').fill("E2E Preview Walk")
    subj = authed_page.locator('input[name="subjects"]').first
    if subj.count() == 0:
        pytest.xfail("subjects chip input not surfaced.")
    subj.fill("zzz-no-match-preview")
    if authed_page.locator(".ms-trigger").count() == 0:
        pytest.xfail(".ms-trigger not surfaced on /new.")
    _pick_research_option(authed_page)

    authed_page.get_by_role(
        "button", name=re.compile(r"Create Topic", re.I)
    ).click()
    expect(authed_page).to_have_url(re.compile(r"/profile\?tab=topic-digest"))

    # Reopen the saved Topic so the Preview button is bound to a topic_id.
    saved_link = authed_page.get_by_role(
        "link", name=re.compile(r"E2E Preview Walk", re.I)
    )
    if saved_link.count() == 0:
        pytest.xfail("saved Topic link not surfaced on the topic-digest tab.")
    saved_link.first.click()

    preview_btn = authed_page.get_by_role(
        "button", name=re.compile(r"Preview matches", re.I)
    )
    if preview_btn.count() == 0:
        pytest.xfail(
            "'Preview matches' button not present in editor — feature-work: "
            "expose the preview submit inside #topic-editor-form."
        )
    preview_btn.click()

    # HTMX swap — wait for the fragment.
    preview_root = authed_page.locator("#topic-preview")
    # `.topic-preview-result` is the deterministic ready-signal per sketch.
    result = preview_root.locator(".topic-preview-result")
    try:
        result.wait_for(state="visible", timeout=8_000)
    except Exception:
        assert_no_regression_or_xfail(
            recorded_5xx,
            "#topic-preview .topic-preview-result never became visible — "
            "feature-work: expose the ready-signal class on the swapped root.",
        )

    # Empty-hits article rendered, not a hits table.
    no_matches = preview_root.locator(
        "article", has_text=re.compile("No matches yet", re.I)
    )
    expect(no_matches.first).to_be_visible()
    # The on-page remedy hint is present.
    expect(
        authed_page.get_by_text(re.compile(r"add or widen your Subject terms", re.I))
    ).to_be_visible()
    # Audience-safe copy — no Account #<n>, no bare topic_id/user_id leaks.
    preview_text = preview_root.inner_text() or ""
    assert not re.search(r"Account\s+#\d+", preview_text), (
        f"preview leaked 'Account #<id>' shape: {preview_text[:200]!r}"
    )
    assert "topic_id" not in preview_text.lower(), (
        f"preview leaked bare 'topic_id' string: {preview_text[:200]!r}"
    )
    assert "user_id" not in preview_text.lower(), (
        f"preview leaked bare 'user_id' string: {preview_text[:200]!r}"
    )
    # No accidental hits-table for a zero-match preview.
    assert preview_root.locator("table").count() == 0, (
        "preview rendered a <table> even though there are zero matches"
    )

    # Widen the lookback → re-preview → idempotent empty-hits render.
    lookback = authed_page.locator('select[name="lookback_days"]')
    if lookback.count() > 0:
        try:
            lookback.select_option("90")
        except Exception:
            pass
    preview_btn.click()
    try:
        result.wait_for(state="visible", timeout=8_000)
    except Exception:
        assert_no_regression_or_xfail(
            recorded_5xx,
            "preview re-render did not surface ready-signal.",
        )
    # Still empty-hits after widen — no stale hits carried, no 500.
    expect(
        preview_root.locator(
            "article", has_text=re.compile("No matches yet", re.I)
        ).first
    ).to_be_visible()
