"""Punch 607 (PD-17) — every BAA expiry site renders the calendar date, through the real view.

Before the fix the 7 BAA expiry sites (`admin/_baa_expiry_banner.html` x3,
`admin/ai_backends/_index.html` x4) piped the ``YYYY-MM-DD`` value through
``us_datetime``: it was read as UTC midnight and shifted to server-local
time, so a BAA expiring 2026-12-31 showed as ``12/30/2026 7:00 PM EST``
(server text) and again in the browser walker. In a UTC zone it showed
``12/31/2026 12:00:00 AM UTC`` — the right day with an invented time.

These tests seed one BAA-certified backend per bucket (expired, expiring
within a week, expiring within 30 days, fresh), then:

* GET ``/config/ai-backends`` as an admin (the real handler + base.html)
  and check all four ``_index.html`` sites;
* render ``admin/_baa_expiry_banner.html`` with ``StrictUndefined`` from the
  real ``baa_expiry.build_banner_context`` over the same rows and check
  its three sites.

Each site must be ``<time datetime="YYYY-MM-DD" data-us-date>M/D/YYYY</time>``:
the date path, the exact day the BAA gate reads, and no time or zone.
The gate itself (``classify_bucket``) is not touched.
"""
from __future__ import annotations

import re
from datetime import date, timedelta

import jinja2

from email_triage.baa_expiry import build_banner_context
from email_triage.web.auth import SESSION_COOKIE_NAME
from email_triage.web.db import create_ai_backend

from _pin_harness import TEMPLATES_ROOT


def _us(d: date) -> str:
    return f"{d.month}/{d.day}/{d.year}"


def _seed(db, admin_user) -> dict[str, date]:
    today = date.today()
    expiries = {
        "expired": today - timedelta(days=2),
        "urgent": today + timedelta(days=3),
        "soon": today + timedelta(days=20),
        "fresh": today + timedelta(days=200),
    }
    for label, d in expiries.items():
        create_ai_backend(
            db, name=f"BAA {label}", type_="ollama",
            endpoint="http://localhost:11434",
            api_key_secret_ref=None, model=None,
            baa_certified=True, baa_expires_at=d.isoformat(),
            enabled=True, created_by=admin_user["id"],
        )
    return expiries


def _assert_rendered_as_date(body: str, d: date) -> int:
    """Every <time> carrying ``d`` is a date-path element showing ``M/D/YYYY``.
    Returns how many such elements were found."""
    tags = re.findall(
        r'<time datetime="' + re.escape(d.isoformat()) + r'"([^>]*)>([^<]*)</time>', body,
    )
    for attrs, text in tags:
        assert text.strip() == _us(d), (
            f"{d}: rendered {text.strip()!r}, expected {_us(d)!r} (no time, no zone shift)"
        )
        assert "data-us-date" in attrs.split(), f"{d}: not a date-path element: {attrs!r}"
    return len(tags)


def test_ai_backends_index_renders_every_baa_expiry_as_a_date(
    client, db, admin_user, admin_cookies,
):
    expiries = _seed(db, admin_user)
    client.cookies.set(SESSION_COOKIE_NAME, admin_cookies[SESSION_COOKIE_NAME])
    resp = client.get("/config/ai-backends")
    assert resp.status_code == 200
    for label, d in expiries.items():
        assert _assert_rendered_as_date(resp.text, d) >= 1, f"{label} expiry not rendered"


def test_baa_expiry_banner_renders_every_bucket_as_a_date(db, admin_user):
    expiries = _seed(db, admin_user)
    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(str(TEMPLATES_ROOT)),
        autoescape=jinja2.select_autoescape(["html"]),
        undefined=jinja2.StrictUndefined,
    )
    from email_triage._us_datetime import install_filter
    install_filter(env)
    banner = build_banner_context(db)
    assert banner["severity"] == "loud"
    body = env.get_template("admin/_baa_expiry_banner.html").render(baa_banner=banner)
    for label in ("expired", "urgent", "soon"):
        assert _assert_rendered_as_date(body, expiries[label]) == 1, f"{label} not in banner"
    # A fresh backend is not a banner row.
    assert _assert_rendered_as_date(body, expiries["fresh"]) == 0
