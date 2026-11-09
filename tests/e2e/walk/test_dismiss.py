"""Walk — route POST /admin/disclosures/dismiss (punch 553, N-556).

Golden: the admin's dismiss click reaches the route and the dismissal is
stored for THAT admin. Refusal: an id that is not a live disclosure (the
security banner's, or a made-up host) is refused with 400 and stores nothing,
so the non-dismissable security banner cannot be dismissed.
"""

from __future__ import annotations

import pytest
from playwright.sync_api import expect

from tests.e2e.walk._helpers import goto_or_fail

pytestmark = pytest.mark.e2e


def _admin_dismissals(e2e_server):
    from email_triage.web.db import (
        DISMISSAL_NS_EGRESS_DISCLOSURES, get_user_dismissals,
        set_user_dismissals,
    )
    conn = e2e_server["conn"]
    uid = conn.execute(
        "SELECT id FROM users WHERE role = 'admin' ORDER BY id LIMIT 1"
    ).fetchone()[0]
    return (
        lambda: get_user_dismissals(conn, uid, DISMISSAL_NS_EGRESS_DISCLOSURES),
        lambda: set_user_dismissals(conn, uid, DISMISSAL_NS_EGRESS_DISCLOSURES, []),
    )


def test_golden(authed_page, base_url, e2e_server):
    """GOLDEN — the click POSTs the disclosure id; the store records it."""
    read, reset = _admin_dismissals(e2e_server)
    reset()
    try:
        goto_or_fail(authed_page, f"{base_url}/dashboard")
        with authed_page.expect_response(
            lambda r: r.url.endswith("/admin/disclosures/dismiss")
        ) as resp_info:
            authed_page.get_by_role("button", name="Got it, hide this").click()
        assert resp_info.value.status == 200
        assert read() == ["egress:update_check:api.github.com"]
    finally:
        reset()


def test_server_refuses_remedy(authed_page, base_url, e2e_server):
    """BRANCH — a non-disclosure id is refused (400) and nothing is stored."""
    read, reset = _admin_dismissals(e2e_server)
    reset()
    try:
        goto_or_fail(authed_page, f"{base_url}/dashboard")
        status = authed_page.evaluate(
            # No X-CSRF-Token of our own: static/csrf.js wraps fetch() and
            # adds the real token only when the header is absent.
            """async () => {
                const r = await fetch('/admin/disclosures/dismiss', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/x-www-form-urlencoded'},
                    body: 'disclosure_id=security',
                });
                return r.status;
            }"""
        )
        # 400 = the ROUTE refused it (the csrf.js fetch shim supplies the
        # token, so a 403 here would mean the probe never reached the route).
        assert status == 400, status
        assert read() == []
    finally:
        reset()
