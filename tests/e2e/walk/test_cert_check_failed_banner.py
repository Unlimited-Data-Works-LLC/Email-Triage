"""Walk — src/email_triage/web/templates/admin/_cert_check_failed_banner.html (template).

Panel M M-DA-10 (2026-10-22): a recent ``tls_cert_check_failed`` event whose
connection went ahead unverified (enforcement off) shows a warning banner on the
admin pages; a REFUSED event (enforcement on) does not, because nothing
connected. The banner reads the application log (``log_entries``).

Shared-DB safety: the seeded rows are UNCHAINED (empty ``row_hash``), which
``verify_log_chain`` skips (counted as ``prechain``), and the chain writer
takes its ``prev_hash`` from its own in-memory last hash, never from the
table. Each test still deletes its row in a ``finally`` so no other test (the
compliance audit-chain walk included) ever sees it.
"""
from __future__ import annotations

import json

import pytest
from playwright.sync_api import expect

from tests.e2e.walk._helpers import goto_or_fail

pytestmark = pytest.mark.e2e


def _seed(conn, host: str, port: int, action: str) -> int:
    from datetime import datetime, timezone

    from email_triage._isotime import to_utc_iso
    from email_triage.tls import CERT_FAIL_LOGGER, CERT_FAIL_MESSAGE

    ts = to_utc_iso(datetime.now(timezone.utc))
    cur = conn.execute(
        "INSERT INTO log_entries (ts, level, logger, message, extra_json, created_at) "
        "VALUES (?, 'WARNING', ?, ?, ?, ?)",
        (ts, CERT_FAIL_LOGGER, CERT_FAIL_MESSAGE,
         json.dumps({"event": "tls_cert_check_failed", "host": host, "port": port,
                     "protocol": "imap", "action": action}), ts),
    )
    conn.commit()
    return cur.lastrowid


def _drop(conn, row_id: int) -> None:
    conn.execute("DELETE FROM log_entries WHERE id = ?", (row_id,))
    conn.commit()


def test_golden(authed_page, base_url, e2e_server):
    # GOLDEN: a failed check that connected anyway is shown to the admin.
    conn = e2e_server["conn"]
    row = _seed(conn, "imap.walk-golden.invalid", 993, "connected_unverified")
    try:
        goto_or_fail(authed_page, base_url + "/config")
        banner = authed_page.locator('[data-banner="cert-check-failed"]')
        expect(banner).to_be_visible()
        expect(banner.get_by_text("Certificate check failed for", exact=False)).to_be_visible()
        expect(banner.get_by_text("imap.walk-golden.invalid:993", exact=False)).to_be_visible()
        expect(banner.get_by_text("enforcement is off", exact=False)).to_be_visible()
    finally:
        _drop(conn, row)


def test_server_refuses_remedy(authed_page, base_url, e2e_server):
    # BRANCH: enforcement on refused the connection, so there is nothing to
    # warn about: no banner.
    conn = e2e_server["conn"]
    row = _seed(conn, "imap.walk-refused.invalid", 993, "refused")
    try:
        goto_or_fail(authed_page, base_url + "/config")
        expect(authed_page.locator('[data-banner="cert-check-failed"]')).to_have_count(0)
        expect(authed_page.get_by_text("imap.walk-refused.invalid", exact=False)).to_have_count(0)
    finally:
        _drop(conn, row)
