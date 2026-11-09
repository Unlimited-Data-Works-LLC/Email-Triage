"""E2E — a refused API-key create or revoke is SHOWN to the operator (panel AA MUST-A4).

Punch 689 and  made the UI revoke and create routes fail closed with a 503
when the change or its chained audit record cannot be written. HTMX does not swap
a 4xx/5xx response, so before MUST-A4 the page showed nothing: after a failed
revoke the row simply stayed listed. A TestClient 503 assertion cannot see that
(PD-17), so these specs drive a real browser against the real routes, with the
audit witness failing in-process, and assert what the page shows.
"""

from __future__ import annotations

import pytest
from playwright.sync_api import expect

import email_triage.db.audit as audit_mod

pytestmark = pytest.mark.e2e


def _boom(*_a, **_kw):
    raise RuntimeError("audit storage exploded (e2e)")


def _mint(e2e_server, name: str) -> int:
    from email_triage.web.auth import generate_api_key, hash_api_key, store_api_key
    return store_api_key(
        e2e_server["conn"], hash_api_key(generate_api_key()), name,
        e2e_server["user_id"], actor_user_id=e2e_server["user_id"],
        actor_email="e2e-admin@test.local", source="ui",
    )


def _key_exists(e2e_server, key_id: int) -> bool:
    return e2e_server["conn"].execute(
        "SELECT 1 FROM api_keys WHERE id = ?", (key_id,)).fetchone() is not None


def test_a_refused_revoke_shows_why_and_how_to_contain_it(
        authed_page, base_url, e2e_server, monkeypatch):
    page = authed_page
    key_id = _mint(e2e_server, "e2e-revoke-refused")
    page.goto(f"{base_url}/profile/security")
    alert = page.locator("#api-keys-error")
    expect(alert).to_be_hidden()

    monkeypatch.setattr(audit_mod, "record_api_key_event_txn", _boom)
    page.once("dialog", lambda d: d.accept())
    page.locator(f"#api-key-row-{key_id} button", has_text="Revoke").click()

    expect(alert).to_be_visible()
    expect(alert).to_contain_text("not revoked")
    expect(alert).to_contain_text("disable the owning user")
    expect(alert).to_contain_text("stop the service")
    expect(page.locator(f"#api-key-row-{key_id}")).to_be_visible()
    assert _key_exists(e2e_server, key_id)

    # PD-18: the next successful request in the section clears the alert.
    monkeypatch.undo()
    page.once("dialog", lambda d: d.accept())
    page.locator(f"#api-key-row-{key_id} button", has_text="Revoke").click()
    expect(page.locator(f"#api-key-row-{key_id}")).to_have_count(0)
    expect(alert).to_be_hidden()
    assert not _key_exists(e2e_server, key_id)


def test_a_refused_create_shows_why_and_no_token(
        authed_page, base_url, e2e_server, monkeypatch):
    page = authed_page
    page.goto(f"{base_url}/profile/security")
    alert = page.locator("#api-keys-error")
    monkeypatch.setattr(audit_mod, "record_api_key_event_txn", _boom)

    page.get_by_role("button", name="Create a token").click()
    form = page.locator('form[hx-post="/accounts/api-keys"]')
    form.locator('input[name="name"]').fill("e2e-create-refused")
    form.get_by_role("button", name="Create token").click()

    expect(alert).to_be_visible()
    expect(alert).to_contain_text("nothing was granted")
    expect(page.locator("#new-key-result")).not_to_contain_text("Token created")
    assert "et_" not in (page.locator("#new-key-result").inner_text() or "")
    assert e2e_server["conn"].execute(
        "SELECT COUNT(*) FROM api_keys WHERE name = 'e2e-create-refused'",
    ).fetchone()[0] == 0
