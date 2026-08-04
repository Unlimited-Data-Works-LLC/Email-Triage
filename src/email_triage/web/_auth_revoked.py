"""SSOT for "is this exception an auth-revoked / re-authentication-required
signal?" — the needle predicate behind the per-account ``auth_stale`` flag.

Before 2026-06-09 this needle list lived in **two** places that were meant to
"mirror" each other but had already drifted:

  * ``web/app.py::_maybe_mark_auth_stale`` — 8 needles, scanned ``str(exc)``
    only. This is the SET side (flips an account to ``auth_stale`` → the
    "Re-authenticate required" chip + the daily-health email call-out).
  * ``web/watcher_retry.py::_AUTH_REVOKED_NEEDLES`` — 10 needles (the SET
    list **plus** ``OAuthRefreshFailed`` / ``IMAPAuthError``), scanned the
    exception **class name** as well as the message. This is the
    never-retry short-circuit for the durable retry queue.

The drift meant an ``OAuthRefreshFailed`` / ``IMAPAuthError`` (raised by class,
no matching substring in ``str(exc)``) would correctly short-circuit retries
but would **not** flip the UI chip — the operator saw a silently-failing
account with no "re-authenticate" cue. The divergence census (2026-06-09,
finding #1) surfaced this as a "convergent intent, divergent implementation"
class; this module is the single source of truth both callers now share.

The list is the **union** (the superset the retry path already carried), and
matching scans **both** the class name and the message (the stronger of the
two behaviours) so the SET side no longer misses a class-only signal.
"""

from __future__ import annotations

# String-match needle list for auth-revoked detection. A match means
# "re-authentication is required; auto-refresh cannot recover" — so there is
# no point retrying, AND the account should surface the re-auth chip.
#
# Keep SET (``_maybe_mark_auth_stale``) and never-retry (``watcher_retry``) in
# agreement by routing BOTH through ``is_auth_revoked`` below — do not re-inline
# a private copy of these needles (the structural pin
# ``tests/test_auth_stale_lifecycle_pin.py`` fails CI on a re-inlined list).
AUTH_REVOKED_NEEDLES: tuple[str, ...] = (
    # Google OAuth refresh-token death (HTTP 400 invalid_grant family).
    "Token has been expired or revoked",
    "invalid_grant",
    # IMAP / Microsoft Graph auth failure signatures.
    "AUTHENTICATIONFAILED",
    "InvalidAuthenticationToken",
    "Invalid Credentials",
    # Google's LONG-FORM data-API 401 for a dead token: the body message is
    # "Request had invalid authentication credentials. Expected OAuth 2 access
    # token..." (status UNAUTHENTICATED). This is the double-401-after-refresh
    # shape (refresh succeeded but the data call still 401s) — the common
    # revoked-refresh-token case raises ``invalid_grant`` from the refresh
    # itself (caught above), but this narrower shape would otherwise slip past
    # every other needle. (Added 2026-06-09 from the census #1 SME review.)
    "invalid authentication credentials",
    # The oauth_request double-401 sentinel (providers/_oauth_http.py) — an
    # unambiguous, prose-independent marker that both attempts 401'd, i.e.
    # genuine credential death (a transient/stale-token 401 is recovered by the
    # refresh+retry). Belt-and-suspenders alongside the message needles above.
    "Auth failed after refresh",
    # Our own wrapped auth-failure exception class names (caught by scanning
    # the class name, not just str(exc) — the drift the census found).
    "OAuthRefreshFailed",
    "IMAPAuthError",
    # OAuth CLIENT-credential rejection (client_id/secret wrong or rotated):
    # the token endpoint answers the refresh with HTTP 401 invalid_client.
    # Every account sharing the client fails at once and auto-refresh CANNOT
    # recover — re-auth (or a client fix) is required. (Added 2026-06-08.)
    "invalid_client",
    "unauthorized_client",
    "401: Unauthorized",
)


def is_auth_revoked(error_class: str, error_msg: str) -> bool:
    """Return True when the error is auth-revoked (re-auth required, never-retry).

    Both ``error_class`` (the exception class name) and ``error_msg``
    (``str(exc)`` text) are scanned, on substrings, to catch the bare
    exception class name AND the wrapped/formatted error string that bubbles
    out of Google / Microsoft / Dovecot.
    """
    for needle in AUTH_REVOKED_NEEDLES:
        if needle in error_class or needle in error_msg:
            return True
    return False


def is_auth_revoked_exc(exc: BaseException) -> bool:
    """Convenience wrapper: classify an exception object directly."""
    try:
        return is_auth_revoked(type(exc).__name__, str(exc) or "")
    except Exception:  # pragma: no cover - defensive; classification is best-effort
        return False
