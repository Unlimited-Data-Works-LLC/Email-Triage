"""E2E — the /compliance "Audit-event chains" tamper-evidence panel.

Real-browser confirmation that the audit-chain verify surface (seam 6) renders
correctly in chromium for an authed admin — not just a TestClient string-assert.
The unit-level view test (tests/test_web/test_audit_chain_verify_surface.py)
covers the tamper-break rendering; this spec is the live-render regression net
that catches a StrictUndefined break, a template/CSS error, or an escaping issue
the TestClient path would miss (the topic-digest-dead / preview-metadata lesson).
"""
from __future__ import annotations

import re

import pytest
from playwright.sync_api import expect

pytestmark = pytest.mark.e2e


def test_compliance_renders_the_audit_chain_panel(authed_page, base_url):
    page = authed_page
    page.goto(f"{base_url}/compliance")

    # The new tamper-evidence section heading renders.
    expect(
        page.get_by_role("heading", name=re.compile("Audit-event chains", re.I))
    ).to_be_visible()

    # On the seeded/clean DB every chain is intact (written via the chained
    # SSOT), so the panel shows the intact summary — not a break warning.
    expect(
        page.get_by_text(re.compile(r"audit chains intact", re.I))
    ).to_be_visible()
    expect(
        page.get_by_text(re.compile(r"audit chain\(s\) show a break", re.I))
    ).to_have_count(0)


def test_compliance_audit_chain_panel_requires_auth(page, base_url):
    """Unauthenticated request must not expose the audit-chain panel."""
    page.goto(f"{base_url}/compliance")
    expect(
        page.get_by_role("heading", name=re.compile("Audit-event chains", re.I))
    ).to_have_count(0)
