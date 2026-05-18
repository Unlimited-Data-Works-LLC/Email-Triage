"""Tests for PWA install-prompt surface (#124).

Covers the second layer of PWA support shipped on top of the existing
manifest + service worker plumbing:

  * Manifest is served with the spec-compliant
    ``application/manifest+json`` content-type and contains every
    field the install heuristic looks at.
  * The install-prompt JS is reachable at ``/static/pwa-install.js``
    so the dashboard install card can wire up the
    ``beforeinstallprompt`` listener + iOS fallback copy.
  * The dashboard renders the install card with the audience-correct
    descriptive caption + the ``m.help()`` tooltip + the iOS fallback
    block + the "already installed" block.
  * ``/offline`` serves the branded offline shell with no PHI in the
    page (audience-comment header verifies the template is end-user
    facing).

The tests do NOT exercise the JS runtime — that's covered by the
file-content checks (markup contract is documented in pwa-install.js).
"""

from __future__ import annotations

import json


# ---------------------------------------------------------------------------
# Manifest content-type + required PWA fields
# ---------------------------------------------------------------------------

def test_manifest_served_with_spec_content_type(client):
    """The PWA spec content-type is ``application/manifest+json``.

    Python stdlib's mimetypes module maps .webmanifest -> that type,
    and StaticFiles uses mimetypes — so this should hold without
    any custom routing. Pinned here so a future content-type mishap
    surfaces immediately instead of via "the install prompt
    stopped working on Android".
    """
    resp = client.get("/static/manifest.webmanifest")
    assert resp.status_code == 200
    ctype = resp.headers.get("content-type", "").lower()
    assert "application/manifest+json" in ctype, ctype


def test_manifest_contains_required_pwa_fields(client):
    """Every field the Chrome / Edge install heuristic checks for."""
    resp = client.get("/static/manifest.webmanifest")
    data = json.loads(resp.text)

    # Identity
    assert data["name"]
    assert data["short_name"]

    # Launch behaviour
    assert data["start_url"]
    assert data["display"] == "standalone", data.get("display")

    # Theming (Chrome uses theme_color for the title bar of the
    # standalone window, background_color for the splash screen).
    assert data["theme_color"]
    assert data["background_color"]

    # Icons: 192 + 512 + at least one maskable per Android adaptive-
    # icon requirements.
    icons = data["icons"]
    assert isinstance(icons, list) and len(icons) >= 3
    sizes = {icon["sizes"] for icon in icons}
    assert "192x192" in sizes
    assert "512x512" in sizes
    purposes = {icon.get("purpose") for icon in icons}
    assert "maskable" in purposes


# ---------------------------------------------------------------------------
# pwa-install.js is reachable
# ---------------------------------------------------------------------------

def test_pwa_install_js_served(client):
    """The install-prompt script must be reachable so the dashboard
    install card can wire up the listener."""
    resp = client.get("/static/pwa-install.js")
    assert resp.status_code == 200
    ctype = resp.headers.get("content-type", "").lower()
    assert "javascript" in ctype, ctype


def test_pwa_install_js_handles_beforeinstallprompt(client):
    """Anti-regression: confirm the file actually implements the
    install protocol (event listener + prompt() + persistence).
    String-based check; if a refactor renames the symbols the test
    needs updating in lockstep."""
    resp = client.get("/static/pwa-install.js")
    body = resp.text
    assert "beforeinstallprompt" in body
    assert "appinstalled" in body
    assert "prompt(" in body
    assert "localStorage" in body


def test_pwa_install_js_has_ios_fallback(client):
    """iOS Safari has no programmatic install API. The script must
    fall back to the Share-sheet hint via UA detection."""
    resp = client.get("/static/pwa-install.js")
    body = resp.text
    # Either UA token covers the iOS family (iPhone / iPad / iPod).
    assert "iPhone" in body
    assert "navigator.userAgent" in body or "userAgent" in body


# ---------------------------------------------------------------------------
# Dashboard install card markup
# ---------------------------------------------------------------------------

def test_dashboard_includes_install_card_markup(client, regular_user, user_cookies):
    """Dashboard renders the install card scaffolding (hidden by
    default; revealed by pwa-install.js based on platform)."""
    resp = client.get("/dashboard", cookies=user_cookies)
    assert resp.status_code == 200
    body = resp.text

    # Host wrapper is the JS contract.
    assert "data-pwa-install" in body
    # Trigger button (desktop / Android Chrome).
    assert "data-pwa-install-trigger" in body
    # iOS fallback block.
    assert "data-pwa-install-ios" in body
    # Already-installed block.
    assert "data-pwa-install-installed" in body


def test_dashboard_install_card_has_descriptive_caption(client, regular_user, user_cookies):
    """Per the no-bare-button rule: caption explains what the button
    does without forcing the user to read the tooltip."""
    resp = client.get("/dashboard", cookies=user_cookies)
    body = resp.text
    # Caption text — exact phrasing pinned so a copy edit reviewer
    # sees the test fail and either updates the test or restores
    # the caption.
    assert "Install as an app for desktop and mobile" in body


def test_dashboard_install_card_has_help_tooltip(client, regular_user, user_cookies):
    """The m.help() macro emits a [data-tooltip] span. Confirm the
    install card uses it (and not a bare label)."""
    resp = client.get("/dashboard", cookies=user_cookies)
    body = resp.text
    # The macro renders the explanatory text inside data-tooltip.
    # Match the leading phrase so we know the tooltip is wired to
    # the install card, not just present somewhere on the page.
    assert "Install Email Triage as an app on this device" in body


def test_dashboard_loads_pwa_install_script(client, regular_user, user_cookies):
    """The script is loaded from base.html only when a user is
    logged in (the install card lives on /dashboard, so loading it
    on /login would be inert)."""
    resp = client.get("/dashboard", cookies=user_cookies)
    body = resp.text
    assert "/static/pwa-install.js" in body


def test_login_page_does_not_load_pwa_install_script(client):
    """Conversely: /login has no install card, so the JS shouldn't
    load there. Saves a request on the unauth surface."""
    resp = client.get("/login")
    body = resp.text
    assert "/static/pwa-install.js" not in body


# ---------------------------------------------------------------------------
# Offline shell (/offline)
# ---------------------------------------------------------------------------

def test_offline_route_reachable_unauthenticated(client):
    """/offline is the PWA fallback shell. Must be reachable without
    a session cookie (the user might be offline + logged out)."""
    resp = client.get("/offline")
    assert resp.status_code == 200


def _extract_main(html: str) -> str:
    """Return the content of the <main> tag (the bit users actually
    read). Strips out base.html's inline script comments + nav copy
    so anti-jargon assertions stay scoped to the page body."""
    lower = html.lower()
    start = lower.find("<main")
    end = lower.find("</main>")
    if start == -1 or end == -1:
        return html
    return html[start:end]


def test_offline_page_has_user_facing_copy(client):
    """End-user audience: speak in plain English, not protocol terms."""
    resp = client.get("/offline")
    main = _extract_main(resp.text).lower()
    assert "offline" in main
    # Pinned plain-English copy. Not strict — leeway for paraphrase.
    assert "internet" in main or "connection" in main
    # Anti-jargon guard: developer / protocol terms must not surface
    # in the page body the user actually reads. (Scoped to <main> so
    # base.html's inline script comments don't trip the check.)
    forbidden = (
        "service worker", "503", "tcp", "dns lookup", "http error",
    )
    for needle in forbidden:
        assert needle not in main, f"jargon {needle!r} on /offline"


def test_offline_page_links_back_to_dashboard(client):
    """Reload entry point: when the connection comes back the user
    needs an obvious way to retry."""
    resp = client.get("/offline")
    assert "/dashboard" in resp.text


def test_offline_page_has_no_admin_path_references(client):
    """End-user template — must not point at /admin/* or /config etc.
    (The user is offline; even if we showed the link, they couldn't
    reach it.)

    Scoped to <main> because base.html's keyboard-shortcut JS map +
    the nav-comment block reference admin paths inside <head> /
    <script>; those don't render as user-clickable copy. The rule
    targets visible page content."""
    resp = client.get("/offline")
    main = _extract_main(resp.text)
    forbidden = ("/admin/", "/config", "/users", "/logs")
    for needle in forbidden:
        assert needle not in main, f"admin path {needle!r} in /offline body"
