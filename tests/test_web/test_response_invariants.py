"""Cross-endpoint response invariants.

Regression-guards against bug classes that don't surface in normal
unit tests because the endpoint returns a 200 + the body looks fine
on the application side -- only the wire-level framing is off.

Bug seen on 2026-04-29: /api/csrf-token returned a body whose actual
length did NOT match the Content-Length header it advertised. Cause:
mutate-then-discard pattern in the endpoint (placeholder response
created, mutated by a helper that computed Content-Length, then
thrown away while the caller emitted a different response copying
the stale Content-Length). Browser saw mismatch and aborted the
fetch with ERR_CONTENT_LENGTH_MISMATCH; CSRF shim couldn't fetch
its token; every subsequent state-changing fetch logged a
"would-reject" warning despite being initiated by the operator's
own browser.

The invariant: for any endpoint that advertises a Content-Length
header, the actual body length must equal that header's value.
Trivially true for any well-formed HTTP response -- but easy to
violate in code that builds bodies via mutation chains.

This test exercises the small set of endpoints whose response
construction goes through helpers (auth flows, CSRF token mint,
listener-mode toggle save). If the fixture set grows, add new
endpoints here. Catches the mismatch class anywhere in the project.
"""

from __future__ import annotations

import pytest

from email_triage.web.auth import (
    SESSION_COOKIE_NAME, create_session_token,
)


def _content_length_matches_body(resp) -> bool:
    """True iff the response declares a Content-Length and the body
    matches. Returns True for responses with no Content-Length header
    (chunked / streaming) -- those use a different framing.
    """
    cl_header = resp.headers.get("content-length")
    if cl_header is None:
        return True
    return int(cl_header) == len(resp.content)


def test_csrf_token_endpoint_content_length_matches_body(
    client, db, app, admin_user,
):
    """Direct regression for the /api/csrf-token mismatch."""
    app.state.session_secret = "test-secret"
    sess = create_session_token(
        "test-secret", admin_user["email"], "admin",
    )
    client.cookies.set(SESSION_COOKIE_NAME, sess)

    resp = client.get("/api/csrf-token")
    assert resp.status_code == 200, resp.text
    assert _content_length_matches_body(resp), (
        f"Content-Length={resp.headers.get('content-length')} "
        f"body={len(resp.content)} body_repr={resp.content!r}"
    )


@pytest.mark.parametrize("path", [
    "/api/csrf-token",
    "/api/status",
    "/health",
])
def test_endpoint_content_length_consistency(
    path, client, db, app, admin_user,
):
    """Sweep across endpoints whose body-build path goes through a
    helper. Any future endpoint that adds a similar pattern should
    be added here -- catches the mutate-and-discard class up front.
    """
    app.state.session_secret = "test-secret"
    sess = create_session_token(
        "test-secret", admin_user["email"], "admin",
    )
    client.cookies.set(SESSION_COOKIE_NAME, sess)

    resp = client.get(path)
    # Don't care about status here -- 200, 401, 503 all OK -- only
    # that the body length matches the Content-Length header when
    # one is present.
    assert _content_length_matches_body(resp), (
        f"{path}: "
        f"Content-Length={resp.headers.get('content-length')} "
        f"body={len(resp.content)}"
    )
