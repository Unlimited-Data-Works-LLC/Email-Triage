"""Tests for the server-side csrf_input() Jinja helper (2026-05-11).

Backstop for the watch-editor "would-reject" finding: every plain
HTML POST form must render a `csrf_token` hidden input from the
server, not rely on the JS shim's `/api/csrf-token` fetch. The
shim is fallback only now.
"""

from __future__ import annotations

import re
import types
from pathlib import Path

from email_triage.web.auth import SESSION_COOKIE_NAME
from email_triage.web.csrf import csrf_input, verify_csrf_token


# ---------------------------------------------------------------------------
# Helper behaviour
# ---------------------------------------------------------------------------


def test_csrf_input_helper_renders_signed_hidden_input():
    """Authenticated request shape → hidden input with a valid token."""
    request = types.SimpleNamespace()
    request.app = types.SimpleNamespace()
    request.app.state = types.SimpleNamespace(session_secret="shh")
    request.cookies = {SESSION_COOKIE_NAME: "session-abc"}

    html = str(csrf_input(request))
    assert html.startswith('<input type="hidden" name="csrf_token" value="')
    assert html.endswith('">')

    token = html.split('value="', 1)[1].rstrip('">')
    assert token
    assert verify_csrf_token("shh", token, "session-abc") is True


def test_csrf_input_helper_empty_when_anonymous():
    """No session cookie → empty-value field. Still renders so the JS
    shim's submit listener skips its own injection path."""
    request = types.SimpleNamespace()
    request.app = types.SimpleNamespace()
    request.app.state = types.SimpleNamespace(session_secret="shh")
    request.cookies = {}

    html = str(csrf_input(request))
    assert 'name="csrf_token"' in html
    assert 'value=""' in html


def test_csrf_input_helper_empty_when_no_session_secret():
    """Misconfigured install (lifespan didn't set session_secret)
    falls back to empty rather than raising."""
    request = types.SimpleNamespace()
    request.app = types.SimpleNamespace()
    request.app.state = types.SimpleNamespace()
    request.cookies = {SESSION_COOKIE_NAME: "session-abc"}

    html = str(csrf_input(request))
    assert 'value=""' in html


# ---------------------------------------------------------------------------
# Template-coverage regression
# ---------------------------------------------------------------------------


def test_every_post_form_template_carries_csrf_token_field():
    """Regression: every plain POST form template must include a
    csrf_token hidden input server-side. Pre-2026-05-11 several
    templates relied on csrf.js JS injection, which raced with the
    /api/csrf-token fetch + intermittently submitted without a
    token (logged as `CSRF token would-reject (soft-launch)`).

    Acceptable shapes:
      * `csrf_input(` invocation (preferred, post-helper)
      * literal `name="csrf_token"` hidden input (a few templates
        had this pre-helper and don't need a refactor)
    """
    template_root = (
        Path(__file__).resolve().parents[2]
        / "src" / "email_triage" / "web" / "templates"
    )
    assert template_root.is_dir(), template_root

    # Forms whose action lives on a CSRF-exempt path prefix never
    # hit the middleware. Mirror web/csrf.py:_EXEMPT_PREFIXES at
    # the template level.
    EXEMPT_FILENAMES = {"login.html", "login_dev_keypair.html"}

    # Multi-line aware — some templates split <form ...> across
    # several lines (action= on a continuation line). re.DOTALL so
    # the regex doesn't stop at the first newline inside the tag.
    form_open_re = re.compile(
        r"""<form\b[^>]*?method=["']?[Pp][Oo][Ss][Tt]["']?[^>]*?>""",
        re.DOTALL,
    )

    missing: list[str] = []
    for tpl in template_root.rglob("*.html"):
        if tpl.name in EXEMPT_FILENAMES:
            continue
        text = tpl.read_text(encoding="utf-8")
        if not form_open_re.search(text):
            continue
        ok = (
            "csrf_input(" in text
            or 'name="csrf_token"' in text
        )
        if not ok:
            missing.append(str(tpl.relative_to(template_root)))

    assert not missing, (
        "POST form template(s) missing csrf_input() / csrf_token "
        "field:\n  " + "\n  ".join(missing)
    )
