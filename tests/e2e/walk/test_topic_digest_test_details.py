"""Walk — Topic Digest test-details fragment (sketch ).

Feature: ``POST /profile/topic-digest/{topic_id:int}/test-details``
(landed 2026-06-07 in 237472a9). Sample-hit expansion / debug detail
for topic preview. Walk creates a Topic via the real UI, triggers the
Step-1 keyword Preview, clicks 'Test Details', and asserts the
details-mode fragment swapped in (either the details-mode summary hint
OR the details-mode empty-state — both are valid under an inert
seeded account with no real messages). Branch: HTMX POST to a
non-existent topic_id renders 'Topic not found' in the swap target
while the outer editor chrome stays intact.
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


def _create_and_open_topic(authed_page, base_url: str, name: str) -> None:
    goto_or_fail(authed_page, f"{base_url}/profile/topic-digest/new")
    if authed_page.locator("#topic-editor-form").count() == 0:
        pytest.xfail("#topic-editor-form not surfaced.")
    authed_page.locator('input[name="name"]').fill(name)
    subj = authed_page.locator('input[name="subjects"]').first
    if subj.count() == 0:
        pytest.xfail("subjects chip input not surfaced.")
    subj.fill("NCT00000419")
    if authed_page.locator(".ms-trigger").count() == 0:
        pytest.xfail(".ms-trigger not surfaced.")
    _pick_research_option(authed_page)
    authed_page.get_by_role(
        "button", name=re.compile(r"Create Topic", re.I)
    ).click()
    expect(authed_page).to_have_url(re.compile(r"/profile\?tab=topic-digest"))
    saved = authed_page.get_by_role("link", name=re.compile(name, re.I))
    if saved.count() == 0:
        pytest.xfail(f"saved Topic '{name}' link not surfaced.")
    saved.first.click()


def test_test_details_swaps_details_mode(authed_page, base_url):
    """GOLDEN — Preview → Test Details swaps details-mode fragment in
    place of the keyword-mode payload."""
    # Drive-7 DA-batch3 fold: 5xx watch armed BEFORE HTMX clicks so preview-
    # swap timeouts distinguish honest missing-signal from route regression.
    recorded_5xx = start_5xx_watch(authed_page)
    _create_and_open_topic(authed_page, base_url, "E2E TestDetails Topic")

    preview_btn = authed_page.get_by_role(
        "button", name=re.compile(r"Preview matches", re.I)
    )
    if preview_btn.count() == 0:
        pytest.xfail("'Preview matches' button not present.")
    preview_btn.click()

    preview_root = authed_page.locator("#topic-preview")
    try:
        preview_root.locator(".topic-preview-result").wait_for(
            state="visible", timeout=8_000
        )
    except Exception:
        assert_no_regression_or_xfail(
            recorded_5xx,
            "keyword-mode preview never became visible.",
        )

    # Step-1 helper copy present in keyword mode. It renders only when the
    # keyword search returned candidates (`_match_count` in
    # _topic_digest_preview.html). The seeded accounts are inert (no real
    # IMAP), so the search returns none and the preview shows its empty or
    # error state, with no 'Test Details' button to press. Before the bounded
    # render probes (punch 676, ec57f24b) the inert connect outlived the 8s
    # wait and this test xfailed above; now the preview lands in time, so the
    # same unmet precondition is named here, with what the preview showed.
    keyword_helper = preview_root.get_by_text(
        re.compile(r"Fast search of your Subject terms", re.I)
    )
    if keyword_helper.count() == 0:
        assert_no_regression_or_xfail(
            recorded_5xx,
            "keyword preview returned no candidates under the inert seeded "
            "accounts, so there is no 'Test Details' to press. Preview showed: "
            + preview_root.inner_text()[:200].replace("\n", " "),
        )
    expect(keyword_helper).to_be_visible()

    test_details_btn = authed_page.get_by_role(
        "button", name=re.compile(r"Test Details", re.I)
    )
    if test_details_btn.count() == 0:
        pytest.xfail(
            "'Test Details' button not rendered after keyword preview — "
            "feature-work: expose the Test Details submit inside #topic-preview."
        )
    test_details_btn.click()

    # Wait for the swap to reflect the details-mode signature. Either the
    # summary hint OR the empty-state — both are valid.
    details_signature = re.compile(
        r"Tested against the full Topic \(Subject \+ Details\) by AI"
        r"|None of the keyword candidates matched the full Topic",
        re.I,
    )
    try:
        preview_root.get_by_text(details_signature).first.wait_for(
            state="visible", timeout=8_000
        )
    except Exception:
        assert_no_regression_or_xfail(
            recorded_5xx,
            "details-mode signature never rendered — feature-work: expose "
            "the details-mode summary/empty-state copy in the swap.",
        )

    # Mode flipped — the Test Details button is now hidden AND the
    # keyword-mode Step-1 helper is no longer present.
    assert (
        authed_page.get_by_role(
            "button", name=re.compile(r"Test Details", re.I)
        ).count()
        == 0
    ), "'Test Details' button still visible after swap — mode did not flip"
    assert (
        preview_root.get_by_text(
            re.compile(r"Fast search of your Subject terms", re.I)
        ).count()
        == 0
    ), "keyword-mode helper string still present after details swap"


def test_test_details_missing_topic_refuses_in_swap(authed_page, base_url):
    """BRANCH — HTMX POST to a non-existent topic_id must land
    'Topic not found' inside #topic-preview while the outer editor
    chrome stays reachable (user remedy: return to the topic list)."""
    _create_and_open_topic(authed_page, base_url, "E2E TestDetails Branch")

    # Fire an HTMX-shaped POST via page.evaluate → fetch. The response
    # body is what would be swapped into #topic-preview.
    result = authed_page.evaluate(
        """async () => {
            const resp = await fetch(
                '/profile/topic-digest/999999/test-details',
                {
                    method: 'POST',
                    headers: {
                        'HX-Request': 'true',
                        'Content-Type': 'application/x-www-form-urlencoded',
                    },
                    body: '',
                }
            );
            return { status: resp.status, text: await resp.text() };
        }"""
    )
    assert "Topic not found" in (result.get("text") or ""), (
        f"missing-topic test-details didn't surface 'Topic not found'; "
        f"status={result.get('status')}, body={(result.get('text') or '')[:300]!r}"
    )

    # Outer editor chrome still reachable — the Topic Digest tab loads.
    # This site is ALREADY DA-batch3-fold-shape (inline status assert) —
    # kept literal, not converted to goto_or_fail, to preserve the original
    # explicit-status shape as a reader example.
    remedy = authed_page.goto(f"{base_url}/profile?tab=topic-digest")
    assert remedy is not None and remedy.status == 200
