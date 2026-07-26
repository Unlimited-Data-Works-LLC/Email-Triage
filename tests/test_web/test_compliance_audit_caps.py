""" — the /compliance page caps each audit table with a hard LIMIT
(100 access / 100 api-key / 100 discover / 100 generic / 50 boundary).
Before this fix the capped subset rendered with no indication, so an
operator read 100 rows as the whole audit trail — a HIPAA compliance-
visibility gap (silent-truncation audit, row ).

These tests prove:
  * the COUNT(*) helpers return the true table totals, and
  * the snapshot pairs each list_* with its total in ``audit_totals``, and
  * the rendered /compliance page surfaces a "showing N of M" banner the
    moment a table exceeds its cap (test the VIEW, not just the machinery).
"""

import pytest

from email_triage.db.audit import (
    record_hipaa_boundary,
    count_hipaa_boundary_events,
    count_hipaa_access_events,
    count_api_key_events,
    count_discover_runs,
    count_access_events,
)
from email_triage.web.routers.ui._shared import _compliance_page_snapshot


def _seed_boundary_events(db, n):
    for i in range(n):
        # alternate on/off so the rows are realistic; scope unique-ish
        record_hipaa_boundary(
            db, scope=f"account:{i}", direction="on" if i % 2 else "off",
            actor_id=None, reason=f"seed {i}",
        )


class TestCountHelpers:
    def test_boundary_count_matches_inserts(self, db):
        assert count_hipaa_boundary_events(db) == 0
        _seed_boundary_events(db, 7)
        assert count_hipaa_boundary_events(db) == 7

    def test_empty_tables_count_zero(self, db):
        # Fresh DB — every audit table is empty, count is 0 (not an error).
        assert count_hipaa_access_events(db) == 0
        assert count_api_key_events(db) == 0
        assert count_discover_runs(db) == 0
        assert count_access_events(db) == 0
        assert count_hipaa_boundary_events(db) == 0


class TestSnapshotPages:
    def test_snapshot_exposes_audit_pages(self, db, app):
        """_compliance_page_snapshot pairs every capped list with a
        PageWindow under audit_pages[name] (total/offset/limit/shown)."""
        snap = _compliance_page_snapshot(db, app.state)
        assert "audit_pages" in snap
        ap = snap["audit_pages"]
        for key in (
            "access_events", "api_key_events", "discover_runs",
            "generic_access_events", "recent_events",
        ):
            assert key in ap, f"missing page window for {key}"
            win = ap[key]
            # PageWindow protocol used by the pager macro.
            for attr in ("total", "offset", "limit", "shown",
                         "has_older", "has_newer", "truncated"):
                assert hasattr(win, attr), f"{key} window missing {attr}"

    def test_over_cap_window_has_older(self, db, app):
        """Seed past the 50-row boundary cap → the PageWindow reports the
        true total + has_older (so the pager renders 'load older')."""
        _seed_boundary_events(db, 55)
        snap = _compliance_page_snapshot(db, app.state)
        be = snap["audit_pages"]["recent_events"]
        assert be.limit == 50
        assert be.shown == 50          # capped page
        assert be.total == 55          # honest denominator
        assert be.has_older            # → "load older" link
        assert not be.has_newer        # first page

    def test_offset_reaches_older_page(self, db, app):
        """Paging by boundary_offset=50 reaches the older 5 rows — the
        full trail is REACHABLE, not just counted."""
        _seed_boundary_events(db, 55)
        snap = _compliance_page_snapshot(
            db, app.state, {"recent_events": "50"},
        )
        be = snap["audit_pages"]["recent_events"]
        assert be.offset == 50
        assert be.shown == 5           # the older tail
        assert be.total == 55
        assert be.has_newer            # a newer page exists
        assert not be.has_older        # last page
        assert len(snap["recent_events"]) == 5


class TestRenderedPager:
    def test_compliance_page_shows_pager_with_load_older(
        self, client, admin_cookies, db,
    ):
        """Route-level VIEW test: seed >cap boundary events and assert the
        rendered /compliance HTML carries the 'showing N–M of T' pager AND
        a reachable 'load older' link (full trail, not just a count)."""
        _seed_boundary_events(db, 55)
        resp = client.get("/compliance", cookies=admin_cookies)
        assert resp.status_code == 200
        body = resp.text
        assert "of 55" in body          # honest total
        assert "load older" in body     # reachable, not just labeled
        assert "boundary_offset=50" in body  # the older-page link

    def test_under_cap_no_pager(self, client, admin_cookies, db):
        """A table under its cap renders NO pager — no false 'load older'."""
        _seed_boundary_events(db, 3)
        resp = client.get("/compliance", cookies=admin_cookies)
        assert resp.status_code == 200
        assert "load older" not in resp.text

    def test_older_page_renders_via_query_param(
        self, client, admin_cookies, db,
    ):
        """GET /compliance?boundary_offset=50 renders the older page and a
        'newer' link back — round-trip reachability through the route."""
        _seed_boundary_events(db, 55)
        resp = client.get(
            "/compliance?boundary_offset=50", cookies=admin_cookies,
        )
        assert resp.status_code == 200
        body = resp.text
        assert "51–55" in body or "of 55" in body
        assert "newer" in body          # a way back to the newest page
