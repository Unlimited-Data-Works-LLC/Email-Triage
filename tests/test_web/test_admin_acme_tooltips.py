"""Tests for /admin/acme-status per-field tooltip coverage (#80).

The form has many small fields that map to ACME / DNS-01 protocol
concepts. Operators shouldn't have to read source to understand each
one. Every visible form field carries an ``m.help(...)`` tooltip with
a concrete example.

Coverage:
* Page renders for an admin (sanity).
* At least 20 ``data-tooltip=`` attributes (each ``m.help`` emits one)
  -- the macro is the single source of truth so counting attribute
  occurrences gives a stable lower-bound check for tooltip
  regressions.
* Forbidden phrasing: the audit-flagged "Ask your administrator"
  phrase MUST NOT leak into an admin-tier page (admins ARE the
  administrator). See feedback_no_admin_path_in_user_copy.md.
* TLS-posture overview block exists -- operators land on this page
  before they know which fields apply to their install.
"""

from __future__ import annotations

import pytest


def test_admin_acme_status_page_loads_for_admin(client, admin_cookies):
    resp = client.get("/admin/acme-status", cookies=admin_cookies)
    assert resp.status_code == 200
    assert "ACME / Let&#39;s Encrypt status" in resp.text \
        or "ACME / Let's Encrypt status" in resp.text


def test_acme_status_has_tooltip_per_field(client, admin_cookies):
    """Every ``m.help(...)`` macro emits a ``data-tooltip="..."``
    attribute on its trigger span. Count those: a regression that
    drops a tooltip drops the count. 20 is a generous floor; the
    template currently emits ~27. Anything below 20 means tooltips
    were removed without the macro being audited."""
    resp = client.get("/admin/acme-status", cookies=admin_cookies)
    assert resp.status_code == 200
    tooltip_count = resp.text.count('data-tooltip="')
    assert tooltip_count >= 20, (
        f"Expected >= 20 tooltip triggers on /admin/acme-status; "
        f"got {tooltip_count}. Removed an m.help() call?"
    )


def test_acme_status_no_ask_your_administrator_phrase(client, admin_cookies):
    """The 'Ask your administrator' phrase is banned on every page
    (user-facing and admin-facing) per
    feedback_no_admin_path_in_user_copy.md. Admins ARE the
    administrator -- the phrase is meaningless on /admin/* pages."""
    resp = client.get("/admin/acme-status", cookies=admin_cookies)
    assert resp.status_code == 200
    assert "Ask your administrator" not in resp.text
    assert "ask your administrator" not in resp.text


def test_acme_status_has_tls_posture_intro(client, admin_cookies):
    """The intro block lists which fields apply to which posture.
    Without it, an operator on a Tailscale-issued LE install will
    waste time filling in DNS-01 fields that get ignored."""
    resp = client.get("/admin/acme-status", cookies=admin_cookies)
    assert resp.status_code == 200
    text = resp.text
    # The four supported postures must each appear by name in the
    # intro block.
    assert "Built-in ACME automation" in text
    assert "External ACME pipeline" in text
    assert "Tailscale-issued LE" in text
    assert "Self-signed" in text
    # And the block should call out cert_dir as the shared field
    # operators on external / Tailscale / self-signed installs touch.
    assert "cert_dir" in text


def test_acme_status_audience_header_present(client, admin_cookies):
    """The audience header is a comment block in the template; not
    rendered to the response. This test is a smoke check that the
    page itself still renders -- the actual audience-comment
    presence is enforced via grep in CI per
    feedback_audience_per_page.md."""
    # Comment blocks are stripped by Jinja; we just confirm the
    # page builds (not 500). The grep audit lives in CI / pre-commit
    # rather than runtime.
    resp = client.get("/admin/acme-status", cookies=admin_cookies)
    assert resp.status_code == 200


def test_acme_status_tooltips_have_concrete_examples(client, admin_cookies):
    """Sample-check: a few key tooltips must include concrete
    example values so the operator doesn't have to invent them.
    These three were the original audit-flagged fields."""
    resp = client.get("/admin/acme-status", cookies=admin_cookies)
    assert resp.status_code == 200
    text = resp.text
    # Account email tooltip references a concrete monitored-mailbox
    # example.
    assert "ops@example.com" in text or "tls-admin@example.com" in text
    # Public resolvers tooltip references the canonical 8.8.8.8 / 1.1.1.1.
    assert "8.8.8.8" in text
    # Update zone example pattern.
    assert "acme.example.com" in text or "acme.&lt;domain&gt;" in text \
        or "acme.<domain>" in text
