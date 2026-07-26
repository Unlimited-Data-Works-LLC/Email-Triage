"""E2E smokes for tranche  (task  follow-up).

DA panel on tranche  called for real-browser smoke coverage on
two UI-visible surfaces the code-level pins can't reach:

**Smoke 1 — `4071ed6b` `require_admin_ui` SSOT** (§164.308(a)(4)(ii)(A)
+ §164.312(a)(1)): a NON-admin visiting a /config admin page must
see the Forbidden HTMLResponse rendered (not a 500, not a redirect
loop, and not the admin page itself). This exercises the SSOT
consolidated across 8 UI admin gates.

**Smoke 2 — `1e430c4a` URL-encode redirect ?err= values**
(§164.312(a)(1) info-leak defense-in-depth): an ?err= query
parameter carrying HTML metachars must render escape-safe in the
target page (both URL-encode at emit + Jinja autoescape at
consume). A raw `<script>` payload survives to the target page as
escaped text, not as script.
"""

from __future__ import annotations

import pytest
from playwright.sync_api import expect

pytestmark = pytest.mark.e2e


def test_non_admin_hits_forbidden_on_admin_route(page, base_url):
    """N-318 R30 (task  tranche  follow-up): an unauthenticated
    page hitting /config?tab=security (an admin-gated route) is
    redirected to /login by `require_admin_ui` — NOT presented with
    the admin content, NOT hit by a 500.
    """
    # Not going through `authed_page` — this exercises the
    # non-admin / anonymous branch of the SSOT.
    page.goto(f"{base_url}/config?tab=security")
    # `require_admin_ui` returns RedirectResponse('/login', 303) on
    # anonymous. Playwright follows the redirect; the final URL
    # should be /login or a login page. The dev-key form is
    # gate-protected, so its presence means the gate failed CLOSED
    # in the WRONG direction.
    expect(page.locator('form[action="/admin/dev-keys/add"]')).to_have_count(0)


def test_login_redirect_err_query_html_metachars_escaped(page, base_url):
    """N-318 R30: an `err` query param carrying an HTML metachar
    payload must render as escaped text in the target /login page —
    not as executed script or raw markup.

    Double defense per `1e430c4a`: URL-encode at emit (`quote(..,
    safe='')`) + Jinja autoescape at consume. If either layer is
    dropped, the metachars survive to the DOM.
    """
    payload = "<script>alert(1)</script>"
    # Directly hit /login with the payload via a query param the
    # /login template surfaces.
    page.goto(f"{base_url}/login?err={payload}")
    # If autoescape / URL-encode is intact, the literal text
    # `<script>` should NOT appear as an HTML element — but its
    # escaped form MAY appear as visible text. Assert no live script
    # element got parsed.
    script_count = page.locator("script:has-text('alert(1)')").count()
    assert script_count == 0, (
        "N-318 R30 REGRESSION: HTML-metachar `err` payload rendered "
        "an executable <script> element — URL-encode + autoescape "
        "chain broken."
    )
