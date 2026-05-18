"""Universal admin BAA-expiry banner coverage (#171-D).

W2-α (#169 I7) shipped the BAA-expiry tracking + banner partial, wired
into ``/config`` and ``/config/ai-backends`` only. #171-D extends that
to every admin page via ctx auto-injection in ``_shared._render``
plus an include in ``base.html``.

Tests pin:

* The banner partial renders on every admin page (the touched URL
  surface in the task spec) when an HIPAA account exists AND a row
  is in scope.
* The banner does NOT render on user-facing pages (no-admin-path-in-
  user-copy rule).
* The banner does NOT render on a non-admin owner's account-edit
  view (same rule, different surface).
* First-boot empty ``app.state.baa_expiry_status`` does not crash —
  the helper falls back to a live ``build_banner_context`` call.
* An HIPAA-disabled install (no system HIPAA + no HIPAA-flagged
  account) renders no banner even with expired backends in the DB.
* Stale-sweep handling: silent fail — the LAST successful cache
  summary keeps surfacing until the next tick (see drawer note in
  ``_inject_baa_banner_ctx``).
"""

from __future__ import annotations

from datetime import date, timedelta

import pytest

from email_triage.web.auth import SESSION_COOKIE_NAME
from email_triage.web.db import (
    create_ai_backend,
    create_email_account,
    set_account_style_learning_backend,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

#: A copy-paste fingerprint pulled from the partial template. If this
#: string changes there, update here to keep the assertion meaningful.
BANNER_HEADER_FRAGMENT = "AI backend vendor agreement"


def _iso_today_plus(days: int) -> str:
    return (date.today() + timedelta(days=days)).isoformat()


def _expired_backend(db, *, admin_user) -> int:
    """Insert one already-expired BAA backend so the banner is loud."""
    return create_ai_backend(
        db,
        name="ExpiredAzure",
        type_="azure_openai",
        endpoint="https://example.com/v1",
        api_key_secret_ref=None,
        model="gpt-4o-mini",
        baa_certified=True,
        baa_expires_at=_iso_today_plus(-7),
        enabled=True,
        created_by=admin_user["id"],
    )


def _seed_hipaa_account(db, *, owner_id: int) -> int:
    """Create one HIPAA-flagged account so the HIPAA gate opens."""
    return create_email_account(
        db, owner_id, "HIPAA Account", "imap", {}, hipaa=True,
    )


def _seed_plain_account(db, *, owner_id: int) -> int:
    return create_email_account(
        db, owner_id, "Plain Account", "imap", {},
    )


def _reset_system_hipaa() -> None:
    """Force system HIPAA mode off + clear any per-process leak from
    a prior test. Mirrors the discipline in test_accounts.TestHIPAA.
    """
    from email_triage import triage_logging
    triage_logging._hipaa_mode = False


# ---------------------------------------------------------------------------
# Banner renders on every admin page
# ---------------------------------------------------------------------------

ADMIN_PAGES = [
    "/config",
    "/config/ai-backends",
    "/admin/security",
    "/admin/integrations",
    "/admin/stats",
    "/logs",
    "/users",
    "/compliance",
]


class TestBannerOnAdminPages:
    """When an admin loads an admin page on a HIPAA-bearing install
    with an expired BAA in scope, the banner partial appears in the
    HTML. One test per touched URL so a missing surface is loud.
    """

    @pytest.fixture(autouse=True)
    def _setup(self, db, admin_user):
        _reset_system_hipaa()
        _seed_hipaa_account(db, owner_id=admin_user["id"])
        _expired_backend(db, admin_user=admin_user)
        yield
        _reset_system_hipaa()

    @pytest.mark.parametrize("path", ADMIN_PAGES)
    def test_banner_renders(self, client, admin_cookies, path):
        client.cookies.set(
            SESSION_COOKIE_NAME, admin_cookies[SESSION_COOKIE_NAME],
        )
        resp = client.get(path, follow_redirects=False)
        # Some admin URLs 303-redirect to /config?tab=... — pick those up
        # too so we follow into the actual rendered surface.
        if resp.status_code in (302, 303):
            loc = resp.headers.get("location", "")
            if loc:
                resp = client.get(loc)
        assert resp.status_code == 200, (
            f"{path}: status={resp.status_code} body[:200]={resp.text[:200]!r}"
        )
        assert BANNER_HEADER_FRAGMENT in resp.text, (
            f"{path}: missing banner header fragment "
            f"{BANNER_HEADER_FRAGMENT!r}"
        )


# ---------------------------------------------------------------------------
# Banner does NOT render on user-facing pages (no-admin-path-in-user-copy)
# ---------------------------------------------------------------------------

class TestBannerSuppressedOnUserFacingPages:
    """A non-admin owner viewing their own account-edit / dashboard
    must not see the admin-only banner. The partial guards on
    ``baa_banner is defined and baa_banner and severity != silent``;
    ``_inject_baa_banner_ctx`` returns ``None`` for non-admin users
    so the include emits zero markup.
    """

    @pytest.fixture(autouse=True)
    def _setup(self, db, admin_user):
        _reset_system_hipaa()
        # Seed HIPAA + expired backend so the only thing keeping the
        # banner off is the role gate.
        _seed_hipaa_account(db, owner_id=admin_user["id"])
        _expired_backend(db, admin_user=admin_user)
        yield
        _reset_system_hipaa()

    def test_no_banner_on_dashboard_for_regular_user(
        self, client, user_cookies,
    ):
        client.cookies.set(
            SESSION_COOKIE_NAME, user_cookies[SESSION_COOKIE_NAME],
        )
        resp = client.get("/dashboard")
        assert resp.status_code == 200
        assert BANNER_HEADER_FRAGMENT not in resp.text

    def test_no_banner_on_accounts_for_regular_user(
        self, client, user_cookies,
    ):
        client.cookies.set(
            SESSION_COOKIE_NAME, user_cookies[SESSION_COOKIE_NAME],
        )
        resp = client.get("/accounts")
        # Non-admin owner may legitimately reach /accounts.
        assert resp.status_code == 200
        assert BANNER_HEADER_FRAGMENT not in resp.text

    def test_no_banner_for_anonymous(self, client):
        """Login page renders for anonymous users — must not carry
        admin-only copy."""
        resp = client.get("/login")
        assert resp.status_code == 200
        assert BANNER_HEADER_FRAGMENT not in resp.text


# ---------------------------------------------------------------------------
# Edge case: empty app.state.baa_expiry_status (first boot)
# ---------------------------------------------------------------------------

class TestFirstBootEmptyCache:
    """Before the hourly sweeper's first tick, ``app.state
    .baa_expiry_status`` is ``None``. The helper falls back to a live
    ``build_banner_context(db)`` call so the banner still surfaces.
    """

    def test_no_crash_no_banner_clean_db(
        self, app, client, db, admin_user, admin_cookies,
    ):
        _reset_system_hipaa()
        _seed_hipaa_account(db, owner_id=admin_user["id"])
        # Defensive: ensure the attribute is missing on first boot.
        if hasattr(app.state, "baa_expiry_status"):
            delattr(app.state, "baa_expiry_status")
        client.cookies.set(
            SESSION_COOKIE_NAME, admin_cookies[SESSION_COOKIE_NAME],
        )
        # No expired backend, no cache; banner partial must short-
        # circuit to silent without raising.
        resp = client.get("/config")
        assert resp.status_code == 200
        assert BANNER_HEADER_FRAGMENT not in resp.text

    def test_live_fallback_when_cache_missing(
        self, app, client, db, admin_user, admin_cookies,
    ):
        _reset_system_hipaa()
        _seed_hipaa_account(db, owner_id=admin_user["id"])
        _expired_backend(db, admin_user=admin_user)
        if hasattr(app.state, "baa_expiry_status"):
            delattr(app.state, "baa_expiry_status")
        client.cookies.set(
            SESSION_COOKIE_NAME, admin_cookies[SESSION_COOKIE_NAME],
        )
        # Cache cold; live build_banner_context fires + banner renders.
        resp = client.get("/config")
        assert resp.status_code == 200
        assert BANNER_HEADER_FRAGMENT in resp.text


# ---------------------------------------------------------------------------
# Edge case: HIPAA-disabled install (no system HIPAA + no HIPAA accounts)
# ---------------------------------------------------------------------------

class TestHipaaDisabledInstallSilent:
    """On an install with system HIPAA off + zero HIPAA-flagged
    accounts, the BAA gate is irrelevant — surface no banner even
    when an expired-BAA backend sits in the catalog. Avoids alert
    fatigue + scares users on plain-mail installs.
    """

    @pytest.fixture(autouse=True)
    def _setup(self):
        _reset_system_hipaa()
        yield
        _reset_system_hipaa()

    def test_no_banner_when_no_hipaa_anywhere(
        self, client, db, admin_user, admin_cookies,
    ):
        # No HIPAA account; expired backend exists.
        _seed_plain_account(db, owner_id=admin_user["id"])
        _expired_backend(db, admin_user=admin_user)
        client.cookies.set(
            SESSION_COOKIE_NAME, admin_cookies[SESSION_COOKIE_NAME],
        )
        resp = client.get("/config")
        assert resp.status_code == 200
        assert BANNER_HEADER_FRAGMENT not in resp.text

    def test_system_hipaa_opens_the_gate(
        self, client, db, admin_user, admin_cookies,
    ):
        """System HIPAA on + zero per-account flags → banner DOES
        render (system-wide HIPAA mode is the override per
        ``is_account_hipaa``)."""
        _seed_plain_account(db, owner_id=admin_user["id"])
        _expired_backend(db, admin_user=admin_user)
        from email_triage import triage_logging
        triage_logging._hipaa_mode = True
        try:
            client.cookies.set(
                SESSION_COOKIE_NAME, admin_cookies[SESSION_COOKIE_NAME],
            )
            resp = client.get("/config")
            assert resp.status_code == 200
            assert BANNER_HEADER_FRAGMENT in resp.text
        finally:
            triage_logging._hipaa_mode = False


# ---------------------------------------------------------------------------
# Edge case: stale sweep (cache is set but the last sweep was hours ago)
# ---------------------------------------------------------------------------

class TestStaleCachedSummary:
    """Stale-sweep policy: silent fail. The helper just reads the
    cache and renders whatever buckets are in there; the bucket math
    is day-resolution so 1-25 hours of staleness is invisible.

    /health/detail surfaces a Nagios-pollable freshness signal
    separately — the banner doesn't try to second-guess.
    """

    def test_stale_cache_still_renders(
        self, app, client, db, admin_user, admin_cookies,
    ):
        _reset_system_hipaa()
        _seed_hipaa_account(db, owner_id=admin_user["id"])
        # Hand-build a cached summary that mimics a sweeper that ran
        # 25 hours ago. Bucket shape per
        # ``baa_expiry_daily_sweep``. We don't mock the timestamp; the
        # helper doesn't gate on it.
        from email_triage.baa_expiry import BackendBucketRow

        app.state.baa_expiry_status = {
            "expiring_soon": 0,
            "expiring_urgent": 0,
            "expired": 1,
            "auto_disabled": [],
            "buckets": {
                "fresh": [],
                "expiring_soon": [],
                "expiring_urgent": [],
                "expired": [
                    BackendBucketRow(
                        id=99,
                        name="StaleVendor",
                        type="azure_openai",
                        baa_certified=True,
                        baa_expires_at="2026-01-01",
                        days_until_expiry=-30,
                        bucket="expired",
                    ),
                ],
            },
            "swept_at": "2024-01-01T00:00:00+00:00",
        }
        client.cookies.set(
            SESSION_COOKIE_NAME, admin_cookies[SESSION_COOKIE_NAME],
        )
        resp = client.get("/config")
        assert resp.status_code == 200
        # Banner still appears using the stale cache + names StaleVendor.
        assert BANNER_HEADER_FRAGMENT in resp.text
        assert "StaleVendor" in resp.text

    def test_malformed_cache_falls_through_to_live(
        self, app, client, db, admin_user, admin_cookies,
    ):
        """Defence-in-depth: a malformed cache (e.g. ``buckets`` missing
        or wrong type) falls through ``banner_from_cached_status`` →
        live ``build_banner_context`` so the banner still surfaces
        based on current DB state."""
        _reset_system_hipaa()
        _seed_hipaa_account(db, owner_id=admin_user["id"])
        _expired_backend(db, admin_user=admin_user)
        # Cache shape is broken (no ``buckets`` key).
        app.state.baa_expiry_status = {"unexpected": "shape"}
        client.cookies.set(
            SESSION_COOKIE_NAME, admin_cookies[SESSION_COOKIE_NAME],
        )
        resp = client.get("/config")
        assert resp.status_code == 200
        assert BANNER_HEADER_FRAGMENT in resp.text


# ---------------------------------------------------------------------------
# No double-render: the partial appears AT MOST once on a single page
# ---------------------------------------------------------------------------

class TestNoDoubleRender:
    """Pre-#171-D, /config and /config/ai-backends each included the
    partial directly. After the refactor, base.html owns the include
    and the page-level ones are removed — so the partial must appear
    at most once per page.
    """

    @pytest.fixture(autouse=True)
    def _setup(self, db, admin_user):
        _reset_system_hipaa()
        _seed_hipaa_account(db, owner_id=admin_user["id"])
        _expired_backend(db, admin_user=admin_user)
        yield
        _reset_system_hipaa()

    def test_config_renders_banner_once(self, client, admin_cookies):
        client.cookies.set(
            SESSION_COOKIE_NAME, admin_cookies[SESSION_COOKIE_NAME],
        )
        resp = client.get("/config")
        assert resp.status_code == 200
        assert resp.text.count(BANNER_HEADER_FRAGMENT) == 1

    def test_ai_backends_renders_banner_once(self, client, admin_cookies):
        client.cookies.set(
            SESSION_COOKIE_NAME, admin_cookies[SESSION_COOKIE_NAME],
        )
        resp = client.get("/config/ai-backends")
        assert resp.status_code == 200
        assert resp.text.count(BANNER_HEADER_FRAGMENT) == 1
