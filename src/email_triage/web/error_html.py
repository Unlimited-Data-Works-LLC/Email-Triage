"""Escaped error-surface HTML — the error-rendering SSOT (A8, census 2026-06-09).

The HTMX handlers return small HTML fragments to report failures. The
divergence census found 22+ of them interpolating an exception message
(``{e}`` / ``fmt_exc(e)`` / a provider error string / the Google OAuth
``error`` query param) straight into an ``<small>`` / ``<article>`` /
``<span>`` fragment with NO ``html.escape``. Those messages routinely echo
attacker-influenceable text — an IMAP folder name, an SMTP/SSL server
banner, a provider OAuth error, a pasted message — so a crafted value
could reflect script into the operator's authenticated, PHI-bearing admin
session (reflected XSS).

These two helpers are the single escaped surface. Every dynamic value is
``html.escape``-d. ``tests/test_error_html_escape_pin_a8.py`` is the
count-agnostic AST pin that keeps handlers from re-rolling an unescaped
error fragment.
"""

from __future__ import annotations

import html
from typing import Any

_DEL = "color:var(--pico-del-color);"
_ARTICLE_STYLE = (
    "border-left:3px solid var(--pico-del-color);padding:0.5rem 1rem;"
)


def _resolve_message(message: Any, purpose: str) -> str:
    """N-179 R20_1 sub-2 compose: when message IS an Exception, route through
    scrub_exc (from web/_flash.py) for the PHI/secret scrubber layer BEFORE the
    A8 html.escape. Existing callers passing a pre-formatted string bypass
    scrub (they already scrubbed / it's a static label / etc.). Keeps
    error_html.py the single ESCAPE seam and adds a scrub seam via composition
    with the flash SSOT — no duplicate scrub logic."""
    if isinstance(message, BaseException):
        # Local import to avoid a circular _flash <-> error_html import at module load.
        from email_triage.web._flash import scrub_exc
        return scrub_exc(message, purpose=purpose)
    return str(message)


def error_chip(message: Any, *, prefix: str = "", purpose: str = "misc") -> str:
    """A one-line error chip: ``<small …>{prefix}{message}</small>``.

    Both ``prefix`` (a static label like ``"Save failed: "``) and the
    dynamic ``message`` are HTML-escaped (A8), so an exception string
    carrying ``<`` / ``>`` / ``&`` / quotes can never break out of the
    fragment. ``purpose`` (N-179) routes an Exception-typed ``message``
    through the flash scrubber for PHI/secret shape removal.
    """
    resolved = _resolve_message(message, purpose)
    return f'<small style="{_DEL}">{html.escape(prefix + resolved)}</small>'


def error_article(message: Any, *, heading: str = "Error", purpose: str = "misc") -> str:
    """A larger error block: ``<article …><p><strong>{heading}:</strong>
    {message}</p></article>``. Heading + message both escaped; Exception
    message routes through the flash scrubber under ``purpose``."""
    resolved = _resolve_message(message, purpose)
    return (
        f'<article style="{_ARTICLE_STYLE}">'
        f"<p><strong>{html.escape(heading)}:</strong> "
        f"{html.escape(resolved)}</p></article>"
    )
