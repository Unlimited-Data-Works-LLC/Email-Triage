"""Tests for PWA install plumbing (#94).

Browsers fire the "Install" prompt on the URL bar when:

  * The site is HTTPS (or localhost — TestClient is fine).
  * A web app manifest is reachable.
  * A service worker is registered at root scope (the
    ``Service-Worker-Allowed: /`` header on /sw.js makes that work
    even though the JS source lives at /static/sw.js for delivery).
  * 192 + 512 PNG icons are declared in the manifest and reachable.

These tests verify each of those requirements is satisfied so a
regression on any one of them surfaces in CI rather than via "the
install prompt stopped showing up". They do NOT exercise the SW's
runtime behaviour — that file is intentionally near-empty (no
caching) for PHI-safety reasons documented at the top of sw.js.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest


# ---------------------------------------------------------------------------
# /sw.js route (custom handler in routers/ui.py)
# ---------------------------------------------------------------------------

def test_sw_js_served_from_root(client):
    """SW must be reachable at /sw.js for root-scope registration."""
    resp = client.get("/sw.js")
    assert resp.status_code == 200


def test_sw_js_javascript_content_type(client):
    resp = client.get("/sw.js")
    ctype = resp.headers.get("content-type", "")
    assert "javascript" in ctype.lower()


def test_sw_js_service_worker_allowed_header(client):
    """``Service-Worker-Allowed: /`` is what makes a /sw.js worker
    legal at root scope. Without it the registration in base.html
    would error in the browser console."""
    resp = client.get("/sw.js")
    assert resp.headers.get("Service-Worker-Allowed") == "/"


def test_sw_js_no_caching_logic(client):
    """Anti-regression: keep the SW pass-through. Caching introduces
    PHI-leak surface (browser SW cache is persistent + tab-shared).
    The check is intentionally string-based — anything that imports
    a cache API must be flagged on first sight."""
    resp = client.get("/sw.js")
    body = resp.text
    forbidden = ("caches.open", "cache.put", "cache.add", "cache.match")
    for needle in forbidden:
        assert needle not in body, (
            f"sw.js must remain pass-through; found {needle!r} — see "
            "the comment block at the top of sw.js"
        )


# ---------------------------------------------------------------------------
# Manifest (served via StaticFiles)
# ---------------------------------------------------------------------------

def test_manifest_reachable(client):
    resp = client.get("/static/manifest.webmanifest")
    assert resp.status_code == 200


def test_manifest_content_type_is_manifest_or_json(client):
    """Spec content-type is application/manifest+json. Some setups
    fall back to application/json — accept either; the body must
    parse as JSON regardless."""
    resp = client.get("/static/manifest.webmanifest")
    ctype = resp.headers.get("content-type", "").lower()
    assert "manifest+json" in ctype or "json" in ctype, ctype


def test_manifest_body_parses_as_json(client):
    resp = client.get("/static/manifest.webmanifest")
    data = json.loads(resp.text)
    assert data["name"]
    assert data["short_name"]
    assert data["start_url"]
    assert isinstance(data["icons"], list)
    assert len(data["icons"]) >= 2


def test_manifest_declares_192_and_512_icons(client):
    resp = client.get("/static/manifest.webmanifest")
    data = json.loads(resp.text)
    sizes = {icon["sizes"] for icon in data["icons"]}
    assert "192x192" in sizes
    assert "512x512" in sizes


def test_manifest_has_maskable_icon(client):
    """Android adaptive-icon launchers crop standard icons through
    the safe zone. A maskable variant is required so the launcher
    has something to crop without chopping the logo."""
    resp = client.get("/static/manifest.webmanifest")
    data = json.loads(resp.text)
    purposes = {icon.get("purpose") for icon in data["icons"]}
    assert "maskable" in purposes


# ---------------------------------------------------------------------------
# Icon derivatives (served via StaticFiles)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "path",
    [
        "/static/icon-192.png",
        "/static/icon-512.png",
        "/static/icon-512-maskable.png",
        "/static/apple-touch-icon.png",
    ],
)
def test_icon_derivatives_served(client, path):
    resp = client.get(path)
    assert resp.status_code == 200, path
    assert resp.headers.get("content-type", "").startswith("image/png"), path


def test_manifest_icon_paths_exist_on_disk(client):
    """Cross-check: every icon path the manifest declares must exist
    in the static dir. Catches typos in the manifest before they ship."""
    from email_triage.web.app import _STATIC_DIR

    resp = client.get("/static/manifest.webmanifest")
    data = json.loads(resp.text)
    for icon in data["icons"]:
        # Strip the /static/ prefix to land on a filesystem path.
        rel = icon["src"].removeprefix("/static/")
        on_disk = _STATIC_DIR / rel
        assert on_disk.is_file(), f"manifest references missing {on_disk}"


# ---------------------------------------------------------------------------
# Base template wiring
# ---------------------------------------------------------------------------

def test_login_page_advertises_manifest_and_theme(client):
    """The install prompt must work for first-time users on /login,
    so the manifest link + theme-color tag have to render even when
    no session cookie is present."""
    resp = client.get("/login")
    assert resp.status_code == 200
    body = resp.text
    assert 'rel="manifest"' in body
    assert "/static/manifest.webmanifest" in body
    assert 'name="theme-color"' in body
    assert 'rel="apple-touch-icon"' in body
    assert "/static/apple-touch-icon.png" in body


def test_login_page_registers_service_worker(client):
    resp = client.get("/login")
    assert resp.status_code == 200
    body = resp.text
    assert "serviceWorker" in body
    assert "/sw.js" in body
