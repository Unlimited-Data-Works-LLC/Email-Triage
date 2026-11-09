"""Walk — POST /config/ai-backends/embedding-remove (route).

Feature: ``POST /config/ai-backends/embedding-remove`` (punch 541,
2026-09-29). The admin half of the ONE removal funnel for the embedding
runtime: it deletes the runtime prefix on the data volume and resets the
install-state row in one step, audited through the audit-emitter SSOT.

GOLDEN — with a runtime prefix present on disk, the AI-backends tab offers
"Remove the installed runtime"; an admin opens it, confirms the dialog, and the
prefix is gone (renamed to a sibling tombstone in the request, then deleted
by a background purge the walk waits for), the card shows no refusal and
no longer offers Remove, and an
``embedding_install_remove`` INTENT row (written before the delete, N-543) and
OUTCOME row exist. The prefix is a temp directory installed by patching
``embedding_bits.DEFAULT_RUNTIME_DEPS`` (the e2e server runs in-process, so the
patch reaches it; the env var is RETIRED since punch 547), so nothing real is
deleted. It holds the installer's
``INSTALLED.json`` marker because the removal funnel only deletes a target it
can positively identify as a runtime prefix (N-549).

BRANCH (server refuses -> user remedy) — a POST without the CSRF token is
refused and the prefix survives; the remedy is to use the form, which carries
the token.
"""

from __future__ import annotations

import time

import pytest
from playwright.sync_api import expect

from tests.e2e.walk._helpers import goto_or_fail

pytestmark = pytest.mark.e2e


@pytest.fixture
def planted_runtime_prefix(tmp_path, monkeypatch):
    """A runtime prefix the N-549 guard identifies POSITIVELY, built by the
    shared builder: site-packages, a manifest naming exactly its packages, and
    the marker written by the REAL ``write_installed_marker``. A hand-written
    ``{}`` marker is refused since the guard requires one that parses with a
    known schema (539 round 4), and that refusal is what this walk used to hit."""
    from tests._embedding_runtime_fixture import make_verified_prefix

    prefix, _site, _manifest = make_verified_prefix(tmp_path, monkeypatch)
    return prefix


def _remove_audit_rows(conn, outcome: str) -> int:
    return conn.execute(
        "SELECT COUNT(*) FROM auth_events WHERE event_type = ? AND outcome = ?",
        ("embedding_install_remove", outcome),
    ).fetchone()[0]


def test_embedding_remove_deletes_the_prefix_and_audits(
    authed_page, base_url, e2e_server, planted_runtime_prefix,
):
    """GOLDEN — Remove from the AI-backends tab deletes the planted prefix."""
    conn = e2e_server["conn"]
    intents = _remove_audit_rows(conn, "attempt")
    outcomes = _remove_audit_rows(conn, "success")

    goto_or_fail(authed_page, f"{base_url}/config?tab=ai_backends")
    card = authed_page.locator("#embedding-install-card")
    expect(card).to_be_visible()
    summary = card.get_by_text("Remove the installed runtime")
    expect(summary).to_be_visible()
    summary.click()

    authed_page.once("dialog", lambda dialog: dialog.accept())
    with authed_page.expect_response(
        lambda r: r.url.endswith("/config/ai-backends/embedding-remove")
    ) as resp_info:
        card.get_by_role("button", name="Remove").click()
    assert resp_info.value.status == 200, resp_info.value.status

    card = authed_page.locator("#embedding-install-card")
    expect(card.get_by_text("Nothing was removed")).to_have_count(0)
    # The card offers Remove only while the prefix exists; the request RENAMES
    # it to a sibling tombstone inside the writer call, so it is gone now.
    expect(card.get_by_text("Remove the installed runtime")).to_have_count(0)
    assert not planted_runtime_prefix.exists(), (
        f"the runtime prefix survived the removal: {planted_runtime_prefix}"
    )
    # The bytes are deleted AFTER the response, by a background purge off the
    # DB writer (N-543), so the walk waits for the tombstone to go rather than
    # assuming a synchronous delete.
    from email_triage.embedding_bits import REMOVAL_TOMBSTONE_INFIX

    def _tombstones():
        stem = planted_runtime_prefix.name + REMOVAL_TOMBSTONE_INFIX
        return [p for p in planted_runtime_prefix.parent.iterdir() if p.name.startswith(stem)]

    deadline = time.monotonic() + 15
    while _tombstones() and time.monotonic() < deadline:
        time.sleep(0.2)
    assert not _tombstones(), (
        f"the background purge did not delete the tombstone: {_tombstones()}"
    )
    assert _remove_audit_rows(conn, "attempt") == intents + 1, (
        "the removal wrote no embedding_install_remove INTENT row"
    )
    assert _remove_audit_rows(conn, "success") == outcomes + 1, (
        "the removal wrote no embedding_install_remove OUTCOME row"
    )


def test_embedding_remove_without_csrf_is_refused(
    authed_page, base_url, planted_runtime_prefix,
):
    """BRANCH — no CSRF token: refused, and the prefix is untouched."""
    response = authed_page.request.post(
        f"{base_url}/config/ai-backends/embedding-remove", max_redirects=0,
    )
    assert response.status in (400, 403), (
        f"a POST without the CSRF token must be refused, got {response.status}: "
        f"{response.text()[:200]!r}"
    )
    assert planted_runtime_prefix.exists(), (
        "the runtime prefix was deleted by a request without a CSRF token"
    )
