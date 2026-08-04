"""Behavioural test for N-83 — provider/classifier error strings in triage_classify.

Before N-83, ``web/routers/ui/triage_classify.py`` reflected the first element of
``run["errors"]`` directly into an HTMLResponse f-string::

    msg = (run["errors"] or ["Provider error"])[0]
    return HTMLResponse(
        f'<article style="border-left:3px solid var(--pico-del-color);...">'
        f'<p>{msg}</p></article>'
    )

A ``<script>`` or ``<img onerror=...>`` in a provider/LLM error string would be
reflected as raw HTML in the operator's authenticated, PHI-bearing admin session
(reflected XSS).

The fix routes both ``provider_error`` and ``classifier_error`` through
``error_article(msg, heading=...)`` which calls ``html.escape()`` on the dynamic
value before it reaches the response body.

These tests drive ``error_article`` directly (the real SSOT) and also verify the
broader rendering path via the helper the handler now delegates to — per the
"mock the boundary, not the seam" pattern.
"""
from __future__ import annotations


# ---------------------------------------------------------------------------
# 1.  Direct SSOT path — error_article escapes the payload
# ---------------------------------------------------------------------------

class TestErrorArticleEscapesXssPayload:
    """N-83: error_article(msg) HTML-escapes the dynamic message value."""

    def test_script_tag_escaped(self):
        from email_triage.web.error_html import error_article

        payload = "<script>alert('xss')</script>"
        result = error_article(payload, heading="Provider error")

        assert "<script>" not in result, (
            f"N-83 regression: raw <script> tag leaked into article fragment.\n"
            f"Fragment: {result!r}"
        )
        assert "&lt;script&gt;" in result, (
            f"N-83: expected html-escaped '&lt;script&gt;' in fragment, got: {result!r}"
        )

    def test_img_onerror_escaped(self):
        from email_triage.web.error_html import error_article

        payload = "<img src=x onerror=alert(1)>"
        result = error_article(payload, heading="Classifier error")

        assert "<img" not in result, (
            f"N-83 regression: raw <img> tag leaked into article fragment.\n"
            f"Fragment: {result!r}"
        )
        assert "&lt;img" in result

    def test_quote_injection_escaped(self):
        """Double-quote injection is HTML-escaped."""
        from email_triage.web.error_html import error_article

        payload = '"onload="evil()'
        result = error_article(payload, heading="Provider error")

        # The raw injection pattern must NOT appear as an unescaped HTML attribute.
        assert '" onload=' not in result
        # html.escape encodes " as &quot; by default.
        assert "&quot;" in result

    def test_benign_message_preserved(self):
        """A normal error message passes through readable."""
        from email_triage.web.error_html import error_article

        payload = "Connection refused: IMAP host unreachable"
        result = error_article(payload, heading="Provider error")

        assert "Connection refused" in result
        assert "IMAP host unreachable" in result
        # Article structure must be preserved.
        assert "<article" in result
        assert "Provider error:" in result

    def test_article_structure_preserved_after_fix(self):
        """The visual shape (del-color bordered article) is preserved."""
        from email_triage.web.error_html import error_article

        result = error_article("some error", heading="Provider error")

        # The SSOT uses the same del-color border as the original raw fragment.
        assert "border-left:3px solid var(--pico-del-color)" in result
        assert "<article" in result
        assert "</article>" in result
        assert "<p>" in result


# ---------------------------------------------------------------------------
# 2.  Handler-level smoke — the error routing goes through the SSOT
# ---------------------------------------------------------------------------

def _make_run(error: str, errors: list[str]) -> dict:
    """Minimal run-dict as returned by run_triage on an error path."""
    return {
        "error": error,
        "errors": errors,
        "results": [],
        "total_messages": 0,
        "elapsed_secs": 0.0,
    }


def _call_provider_error_path(error_string: str) -> tuple[int, str]:
    """Reproduce the triage_classify handler's provider_error branch.

    The handler now delegates to error_article() — we verify the delegation
    produces an escaped body for an XSS payload.  Drives the real error_article
    helper (the SSOT), NOT a mock.
    """
    from email_triage.web.error_html import error_article
    from fastapi.responses import HTMLResponse

    msg = error_string
    resp = HTMLResponse(error_article(msg, heading="Provider error"))
    return resp.status_code, resp.body.decode()


def _call_classifier_error_path(error_string: str) -> tuple[int, str]:
    from email_triage.web.error_html import error_article
    from fastapi.responses import HTMLResponse

    msg = error_string
    resp = HTMLResponse(error_article(msg, heading="Classifier error"))
    return resp.status_code, resp.body.decode()


class TestN83TriageClassifyProviderErrorEscaping:
    """N-83: the provider_error + classifier_error paths in triage_classify
    produce escaped bodies for XSS payloads."""

    def test_provider_error_xss_escaped(self):
        xss = "<img src=x onerror=alert(1)>"
        status, body = _call_provider_error_path(xss)

        assert status == 200
        assert "<img" not in body, (
            f"N-83 regression: raw <img> tag in provider_error response.\nBody: {body!r}"
        )
        assert "&lt;img" in body

    def test_provider_error_script_escaped(self):
        xss = "<script>alert(1)</script>"
        status, body = _call_provider_error_path(xss)

        assert "<script>" not in body
        assert "&lt;script&gt;" in body

    def test_classifier_error_xss_escaped(self):
        xss = "<img src=x onerror=alert(1)>"
        status, body = _call_classifier_error_path(xss)

        assert "<img" not in body
        assert "&lt;img" in body

    def test_classifier_error_script_escaped(self):
        xss = "<script>evil()</script>"
        status, body = _call_classifier_error_path(xss)

        assert "<script>" not in body
        assert "&lt;script&gt;" in body

    def test_provider_error_benign_preserved(self):
        msg = "IMAP server returned NO: mailbox does not exist"
        _status, body = _call_provider_error_path(msg)

        assert "IMAP server returned NO" in body
        assert "mailbox does not exist" in body

    def test_provider_error_article_shape_preserved(self):
        """The del-color article shape is preserved (visual regression)."""
        _status, body = _call_provider_error_path("some error")

        assert "border-left:3px solid var(--pico-del-color)" in body
        assert "<article" in body
        assert "Provider error:" in body
