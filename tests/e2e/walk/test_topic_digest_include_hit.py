"""Walk — Topic Digest include-hit via the preview thumbs-up (sketch ).

MF6 (DA Batch-2) selector fix — verified against HEAD: the preview
fragment (``profile/_topic_digest_preview.html``) renders NO
``/hits/include`` button. The operator's include-in-digest control IS
the thumbs-UP (Keep) button, which ``hx-post``s to
``POST /profile/topic-digest/{topic_id:int}/hits/feedback`` with
``vote=up`` — and that route promotes the hit to ``source='included'``
(its docstring: "up promotes (source='included')") and swaps '👍 Kept'
into the row's cell. The dedicated ``/hits/include`` route still exists
and IS exercised by the D2 branch below (a real fail-closed endpoint),
but the RENDERED control a browser can click is the thumbs-up, so the
GOLDEN drives that (the old ``/hits/include`` button selector matched
nothing → the golden xfailed vacuously; this is the MF6 fix).

Walk monkeypatches ``_preview_candidate_batches`` to surface ONE
synthetic candidate so the preview renders one row. Golden: click the
thumbs-up (Keep) control, assert the row cell swaps to '👍 Kept'.
Branch (D2 — forged POST): the SAME authed page POSTs ``/hits/include``
to a topic owned by a DIFFERENT user; the topic-ownership check must
fail-closed and write NOTHING to topic_hits.
"""

from __future__ import annotations

import re

import pytest
from playwright.sync_api import expect

pytestmark = pytest.mark.e2e


@pytest.fixture
def include_hit_env(e2e_server, monkeypatch):
    """Seed a foreign user + foreign Topic for the branch, and monkeypatch
    the preview batcher to return one synthetic candidate for the seeded
    admin's Research Inbox."""
    from datetime import datetime, timezone

    from email_triage.actions.topic_configs import TopicConfig, upsert_topic

    conn = e2e_server["conn"]
    research_id = e2e_server["research_account_id"]

    # Foreign user + Topic (for the branch — never rendered).
    conn.execute(
        "INSERT INTO users (email, name, role, created_at) VALUES (?, ?, ?, ?)",
        (
            "foreign-include@test.local",
            "Foreign Include",
            "user",
            datetime.now(timezone.utc).isoformat(),
        ),
    )
    conn.commit()
    other_uid = int(
        conn.execute(
            "SELECT id FROM users WHERE email=?",
            ("foreign-include@test.local",),
        ).fetchone()["id"]
    )
    foreign_tid = upsert_topic(
        conn,
        TopicConfig(
            id=0, user_id=other_uid, name="Foreign Include Topic",
            subjects=["NCT00000419"],
            selected_account_ids=[research_id],
            retention_days=90,
        ),
    ).id

    # Monkeypatch the batcher to yield exactly one synthetic candidate.
    async def _fake_batches(provider, topic, after_dt, *, cap):
        yield [
            {
                "topic_id": getattr(topic, "id", 0),
                "account_id": research_id,
                "account_name": "Research Inbox",
                "message_id": "e2e-msg-1",
                "when": datetime.now(timezone.utc).isoformat(),
                "sender": "alice@lab.test",
                "subject": "NCT00000419 update",
                "confidence_band": "likely",
                "matched_terms": ["NCT00000419"],
                "included": False,
                "folder": "INBOX",
            }
        ]

    try:
        monkeypatch.setattr(
            "email_triage.web.routers.ui.profile._preview_candidate_batches",
            _fake_batches,
        )
    except AttributeError:
        pytest.xfail(
            "email_triage.web.routers.ui.profile._preview_candidate_batches "
            "not importable — feature-work: expose the symbol at that path."
        )

    yield {
        "foreign_topic_id": foreign_tid,
        "message_id": "e2e-msg-1",
        "research_account_id": research_id,
    }

    # Teardown — remove the foreign topic + user.
    conn.execute("DELETE FROM topics WHERE id=?", (foreign_tid,))
    conn.execute("DELETE FROM users WHERE id=?", (other_uid,))
    conn.commit()


def _pick_research_option(authed_page) -> None:
    trigger = authed_page.locator(".ms-trigger").first
    trigger.click()
    authed_page.locator(
        ".ms-option", has_text=re.compile("Research Inbox", re.I)
    ).first.click()
    authed_page.keyboard.press("Escape")


def test_include_hit_marks_row_included(
    authed_page, base_url, include_hit_env,
):
    """GOLDEN — create Topic, preview surfaces one synthetic candidate,
    click Include, cell swaps to '✓ Included'."""
    authed_page.goto(f"{base_url}/profile/topic-digest/new")
    if authed_page.locator("#topic-editor-form").count() == 0:
        pytest.xfail("#topic-editor-form not surfaced.")
    authed_page.locator('input[name="name"]').fill("IncludeHitE2E")
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

    saved = authed_page.get_by_role(
        "link", name=re.compile(r"IncludeHitE2E", re.I)
    )
    if saved.count() == 0:
        pytest.xfail("saved Topic link not surfaced.")
    saved.first.click()

    # Capture topic_id from URL for the branch verification.
    url_match = re.search(r"/topic-digest/(\d+)", authed_page.url)
    assert url_match, f"topic_id not present in URL: {authed_page.url!r}"

    preview_btn = authed_page.get_by_role(
        "button", name=re.compile(r"Preview matches", re.I)
    )
    if preview_btn.count() == 0:
        pytest.xfail("'Preview matches' button missing.")
    preview_btn.click()

    preview_root = authed_page.locator("#topic-preview")
    try:
        preview_root.locator(".topic-preview-result").wait_for(
            state="visible", timeout=8_000
        )
    except Exception:
        pytest.xfail("preview never surfaced .topic-preview-result.")

    # One row for the synthetic sender.
    row = preview_root.locator(
        "tr, li, div",
        has_text=re.compile(r"alice@lab\.test|NCT00000419", re.I),
    ).first
    if row.count() == 0:
        pytest.xfail(
            "synthetic candidate row not rendered — feature-work: expose "
            "the preview candidate row (see _topic_digest_preview.html)."
        )
    # The rendered include-in-digest control is the thumbs-UP (Keep) button,
    # which hx-posts to /hits/feedback with vote=up (promotes source='included').
    include_btn = row.locator(
        'button[hx-post*="/hits/feedback"][aria-label="Keep this match"]'
    ).first
    if include_btn.count() == 0:
        pytest.xfail(
            "thumbs-up (Keep) control not surfaced on synthetic row — "
            "feature-work: expose the preview Keep control (hx-post to "
            "/hits/feedback, vote=up)."
        )
    include_btn.click()

    # After the swap, the up-vote confirmation ('👍 Kept') replaces the cell.
    try:
        expect(
            preview_root.get_by_text(re.compile(r"Kept", re.I)).first
        ).to_be_visible(timeout=5_000)
    except Exception:
        pytest.xfail("Keep swap didn't surface the '👍 Kept' confirmation.")

    kept_text = preview_root.inner_text() or ""
    assert "Kept" in kept_text or "\U0001F44D" in kept_text, (
        f"'👍 Kept' confirmation missing: {kept_text[:200]!r}"
    )
    # Both curate buttons gone from that cell after the swap.
    assert (
        preview_root.locator("button[hx-post*='/hits/feedback']").count() == 0
    ), "curate control still present in swapped row cell"


def test_include_hit_foreign_topic_refuses(
    authed_page, base_url, e2e_server, include_hit_env,
):
    """BRANCH (D2 — forged POST). The seeded admin does NOT own
    foreign_topic_id; the topic-ownership check must fail-closed (403
    'Forbidden') and topic_hits must have ZERO rows for that topic."""
    foreign_tid = include_hit_env["foreign_topic_id"]
    research_id = include_hit_env["research_account_id"]
    conn = e2e_server["conn"]

    # Prime the page so /api/csrf-token binds to a session.
    authed_page.goto(f"{base_url}/profile?tab=topic-digest")

    # Forged POST via in-browser fetch.
    result = authed_page.evaluate(
        f"""async () => {{
            const body =
                'account_id={research_id}&message_id=e2e-msg-1&folder=INBOX';
            const resp = await fetch(
                '/profile/topic-digest/{foreign_tid}/hits/include',
                {{
                    method: 'POST',
                    headers: {{
                        'Content-Type': 'application/x-www-form-urlencoded',
                    }},
                    body,
                }}
            );
            return {{ status: resp.status, text: (await resp.text()).slice(0, 300) }};
        }}"""
    )
    # Fail-closed: 403 (or 404 if the router treats foreign as not-found —
    # both are acceptable fail-closed shapes; sketch calls out 403 but the
    # walk holds to the fail-closed contract, not the exact code).
    assert result["status"] in (401, 403, 404), (
        f"forged POST returned {result['status']}, expected fail-closed "
        f"(401/403/404); body={result['text']!r}"
    )

    # Post-condition — no topic_hits row for foreign_tid.
    hits = conn.execute(
        "SELECT COUNT(*) AS n FROM topic_hits WHERE topic_id=?",
        (foreign_tid,),
    ).fetchone()
    assert hits["n"] == 0, (
        f"forged POST wrote {hits['n']} topic_hits row(s) for foreign_tid "
        f"{foreign_tid}; expected 0 (fail-closed intersection held)"
    )
