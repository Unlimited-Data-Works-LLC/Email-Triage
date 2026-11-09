"""Walk — GET /health/runtime-deps (route).

Feature: ``GET /health/runtime-deps`` (punch 542, 2026-09-29). An admin-only
inventory of the embedding runtime-deps volume: the baked build sha, the Python
version, whether a runtime prefix exists, the distributions on disk, the image
and installed manifest hashes, and whether the runtime is on ``sys.path``.

GOLDEN — an authenticated admin gets 200 and a JSON object whose key set is
EXACTLY the route's closed contract (a new key must be argued for, not arrive
by drift), with ``build_sha`` either a full commit sha or ``""`` (the e2e
server has no baked ``/app/VERSION``, so ``""`` is the honest answer).

BRANCH (server refuses -> user remedy) — an unauthenticated caller is refused:
a Bearer caller gets 401, a browser gets a redirect to the login page. Never a
200 with the inventory.
"""

from __future__ import annotations

import re

import pytest

pytestmark = pytest.mark.e2e

_CONTRACT_KEYS = {
    "build_sha",
    "python",
    "runtime_deps_present",
    "distributions",
    "image_manifest_sha256",
    "installed_manifest_sha256",
    "runtime_on_sys_path",
    # Punch 552 / N-555: the drift gate's bool, the field the warn-only
    # the monitoring system check alarms on (mirrors N-524's _PROMISED_KEYS).
    "runtime_verified",
    # Punch 647 / 734 (drive 647): what the image carries beyond the installed
    # distributions, the vendored libraries and the Debian packages (mirrors
    # N-524's _PROMISED_KEYS).
    "vendored",
    "vendored_error",
    "os_release",
    "os_packages",
    "os_packages_unstateable",
    "os_packages_error",
    # Punch 848: what a wheel bundles beyond Python (dist-info SBOMs, auditwheel
    # .libs), mirrors N-524's _PROMISED_KEYS.
    "bundled",
    "bundled_error",
}


def test_runtime_deps_admin_gets_the_closed_contract(authed_page, base_url):
    """GOLDEN — admin session, 200, exactly the contracted keys."""
    response = authed_page.request.get(f"{base_url}/health/runtime-deps")
    assert response.status == 200, (
        f"GET /health/runtime-deps as admin returned {response.status}: "
        f"{response.text()[:200]!r}"
    )
    body = response.json()
    assert set(body) == _CONTRACT_KEYS, (
        f"payload keys drifted from the closed contract: "
        f"extra={sorted(set(body) - _CONTRACT_KEYS)} "
        f"missing={sorted(_CONTRACT_KEYS - set(body))}"
    )
    assert body["build_sha"] == "" or re.fullmatch(r"[0-9a-f]{40}", body["build_sha"]), (
        f"build_sha must be a full commit sha or empty, got {body['build_sha']!r}"
    )
    assert isinstance(body["runtime_deps_present"], bool)
    assert isinstance(body["runtime_on_sys_path"], bool)
    assert isinstance(body["runtime_verified"], bool)
    # Punch 848: a scan failure is bundled None plus a non-empty bundled_error,
    # never an empty list read as "nothing bundled".
    assert body["bundled"] is None or isinstance(body["bundled"], list)
    assert isinstance(body["bundled_error"], list)
    assert body["bundled"] is not None or body["bundled_error"]


def test_runtime_deps_refuses_an_unauthenticated_caller(page, base_url):
    """BRANCH — no session: Bearer caller 401, browser redirected to login.
    Fail-closed; the inventory is never served."""
    bearer = page.request.get(
        f"{base_url}/health/runtime-deps",
        headers={"Authorization": "Bearer not-a-real-key"},
    )
    assert bearer.status == 401, (
        f"expected 401 for an invalid Bearer caller, got {bearer.status}: "
        f"{bearer.text()[:200]!r}"
    )
    browser = page.request.get(f"{base_url}/health/runtime-deps", max_redirects=0)
    assert browser.status in (303, 307, 401, 403), (
        f"expected a refusal for an anonymous browser, got {browser.status}: "
        f"{browser.text()[:200]!r}"
    )
    if browser.status in (303, 307):
        assert "/login" in browser.headers.get("location", ""), browser.headers
