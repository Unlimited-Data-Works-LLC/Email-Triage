"""Secret-token scrub SSOT for persisted error text (divergence census #6).

Provider/client exception text can incidentally carry a secret token — an
``OAuthError: {'access_token': '...'}``, a ``refresh_token='abc'`` kwarg, a
urlencoded ``client_secret=...``. When that text is **persisted** to a DB column
(``triage_jobs.error_text``, ``office365_subscriptions.error_last``, the
embedding-install ``last_error_msg``) or surfaced in the admin UI, the token
leaks at rest / on-screen.

Before this SSOT the redaction logic + the token-key list were **duplicated**
(``web/db.py::_scrub_watcher_retry_error_msg`` / ``_WATCHER_RETRY_TOKEN_KEYS``,
mirrored again in ``triage_logging``) and **several writers scrubbed nothing**
(``finish_triage_job``, ``record_o365_subscription_error``, and the embedding
``_scrub_error`` which only TRIMMED — no token redaction at all). This module is
the single source: one ``SECRET_TOKEN_KEYS`` set + one ``scrub_secrets_from_text``.

Deliberately **leaf / dependency-free** (only stdlib ``re``) so ``web/db.py`` and
``triage_logging`` can both import it without an import cycle (the reason the
``_WATCHER_RETRY_TOKEN_KEYS`` copy was kept inline originally).

The scrub is a best-effort token-SHAPE strip, not an exception parser (a losing
game): it redacts ``<key>: "value"`` / ``"<key>": value`` / ``<key>='value'`` /
``<key>=bareword`` for each known key, then truncates. It is applied at the
PERSISTENCE BOUNDARY regardless of the account HIPAA flag.
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit

#: Maximum length of a persisted error string before truncation. 500 chars is
#: enough to identify the error shape but small enough that a provider-side
#: stacktrace can't bloat the row.
SECRET_SCRUB_MAX_LEN = 500

#: Token-shaped keys to strip from any embedded value in error text.
#: ``secret`` (bare) covers the ACME TSIG/EAB ``secret='base64=='`` shape — the
#: ``\bsecret\b=`` boundary does NOT match inside ``client_secret`` (no word
#: boundary at ``_secret``), so it adds coverage without double-matching.
SECRET_TOKEN_KEYS: frozenset[str] = frozenset({
    "authorization", "access_token", "refresh_token", "id_token",
    "code", "auth_code", "client_secret", "bearer_token",
    "api_key", "password", "smtp_password", "imap_password",
    "session_token", "secret",
})


#: Punch 606: words that may make a bare ``code=`` a diagnostic, not a secret.
#: ``status code=503`` / ``exit code=2`` / ``error code=AADSTS50076`` name a
#: protocol or process result. ``status_code=500`` needs no entry: ``\bcode``
#: does not match after ``_``. Applies to the bare-key shapes only; a quoted
#: ``"code": "..."`` key is always redacted.
_CODE_DIAGNOSTIC_WORDS = ("status", "exit", "return", "error", "http", "response")

#: Panel B3 hipaa-sme F2: the word alone is not enough. ``OTP error code=482913``
#: and ``error code=4/0AX4XfWh-abc`` carry a plausible secret after ``error``.
#: The value is kept only when it is ALSO a diagnostic shape that ends at a
#: delimiter: a signed 1-3 digit status (``503``, ``2``, ``-15``) or an
#: uppercase vendor code (``AADSTS50076``; ``(?-i:)`` keeps it case-sensitive
#: under the scrub's IGNORECASE).
_CODE_DIAGNOSTIC_VALUE = r"""(?:-?\d{1,3}|(?-i:[A-Z]{2,}\d+))(?=['"\s,;&)}\]]|$)"""

#: Per-key prefix guard: a negative lookahead at the key's position that skips
#: the match only when a diagnostic word precedes the key AND a diagnostic
#: value follows it. Python lookbehinds are fixed-width, so each word is its
#: own lookbehind (case-insensitive under the scrub's flag).
_KEY_GUARDS: dict[str, str] = {
    "code": (
        "(?!(?:" + "|".join(f"(?<={w} )" for w in _CODE_DIAGNOSTIC_WORDS) + ")"
        + r"""code\s*=\s*['"]?""" + _CODE_DIAGNOSTIC_VALUE + ")"
    ),
}

#: Punch 606: an ``Authorization=Bearer <token>`` value is two words; the
#: bareword shape stopped at the space and kept the token.
_KEY_VALUE_PREFIX: dict[str, str] = {
    "authorization": r"(?:(?:Bearer|Basic)\s+)?",
}


def _compile_key_shapes(key: str) -> tuple[re.Pattern[str], re.Pattern[str], re.Pattern[str]]:
    """The three value shapes for one key, compiled (quoted-key, quoted-value,
    bareword)."""
    ek = re.escape(key)
    guard = _KEY_GUARDS.get(key, "")
    return (
        # Shape 1: quoted key + colon + quoted value ("key": "value").
        re.compile(r"(['\"]" + ek + r"['\"]\s*:\s*['\"])[^'\"]*(['\"])", re.IGNORECASE),
        # Shape 2: bare key + = + quoted value (key='value').
        re.compile(guard + r"(\b" + ek + r"\s*=\s*['\"])[^'\"]*(['\"])", re.IGNORECASE),
        # Shape 3: bare key + = + bareword value, bounded at a delimiter.
        # The lookahead skips a value shape 2 (or an upstream scrub) already
        # redacted; an UNTERMINATED quoted value (``password='hunter2``,
        # which shape 2 cannot match) is still taken, quote and all.
        re.compile(
            guard + r"(\b" + ek + r"\s*=\s*)(?!['\"]?\[REDACTED\])"
            + _KEY_VALUE_PREFIX.get(key, "") + r"[^\s,;&)}\]]+",
            re.IGNORECASE,
        ),
    )


#: Panel B3 db-sme F2: compiled once at import. The scrub runs on the logging
#: caller's thread (the event loop for async code) for the message and every
#: extra, and rebuilding 42 pattern strings per call cost 0.1-0.75 ms each.
_KEY_SHAPES = tuple(_compile_key_shapes(key) for key in SECRET_TOKEN_KEYS)


def redact_secret_tokens(text: str) -> str:
    """The token-SHAPE redaction itself: no whitespace collapse, no cap.

    For each :data:`SECRET_TOKEN_KEYS` key, the three common shapes
    (quoted-key dict-repr/JSON, ``key='quoted'`` kwarg, ``key=bareword``) have
    their value replaced with ``[REDACTED]``. Idempotent: an already-redacted
    value is left alone, so text scrubbed upstream and scrubbed again at a
    sink is unchanged (before punch 606 the bareword shape re-matched
    ``'[REDACTED`` and wrote ``[REDACTED]]``).

    :func:`scrub_secrets_from_text` (the persisted error-column funnel) wraps
    this with collapse + truncation; the ``log_entries`` sink calls it bare
    (``triage_logging.scrub_persisted_log_text``), so a log row changes only
    where a secret shape was found.
    """
    out = str(text)
    # Panel B3 db-sme F2: exact short-circuit. Shape 1 needs a ":", and shapes 2
    # and 3 need an "=", so text with neither cannot match any pattern.
    if "=" not in out and ":" not in out:
        return out
    for quoted_key, quoted_value, bareword in _KEY_SHAPES:
        out = quoted_key.sub(r"\1[REDACTED]\2", out)
        out = quoted_value.sub(r"\1[REDACTED]\2", out)
        out = bareword.sub(r"\1[REDACTED]", out)
    return out


def scrub_secrets_from_text(
    text: str | None, *, max_len: int = SECRET_SCRUB_MAX_LEN,
) -> str | None:
    """Return a token-redacted + whitespace-collapsed + truncated copy.

    ``None`` / empty in → ``None`` out. The redaction is
    :func:`redact_secret_tokens`. The result is collapsed (CR/LF runs →
    single spaces, so a multi-line stderr renders in a one-line banner) and
    truncated to ``max_len``.
    """
    if not text:
        return None
    out = redact_secret_tokens(" ".join(str(text).split()))
    if len(out) > max_len:
        # N-254 R25: route through truncate SSOT.
        from email_triage._textfmt import truncate
        out = truncate(out, max_len, ellipsis="...")
    return out


#: URL query-parameter keys whose value is a plaintext credential when carried
#: in a request URL (census run23 discovered class #3, HIGH sev).
#:
#: Gemini's auth IS ``?key=<PLAINTEXT>`` so scrubbing this shape from any URL
#: string rendered into an exception message / log line / persisted error row
#: is the ONE guard against a real plaintext-API-key leak. Azure & OpenAI put
#: the key in a header today (belt-and-suspenders here), but a future refactor
#: copy-pasting a ``?api-key=...`` sample would introduce the same leak.
#:
#: NOTE: distinct from :data:`SECRET_TOKEN_KEYS` — those match token-shaped
#: values embedded in FREE-FORM text (dict repr, kwargs, JSON body). This set
#: matches URL query-parameter NAMES for the parsed-URL rewrite path.
URL_QUERY_SECRET_KEYS: frozenset[str] = frozenset({
    "api-key", "key", "token", "access_token", "code",
})


def strip_url_query_secrets(url: str | None) -> str | None:
    """Return ``url`` with each :data:`URL_QUERY_SECRET_KEYS` query value
    rewritten to ``<key>=REDACTED``.

    Passes ``None``, empty, and query-less URLs through unchanged. On any
    parse failure returns the input verbatim (fail-open so an unparseable URL
    still surfaces its shape to the operator — the leak surface is the value,
    not the key, and we never emit MORE than the caller passed in).
    """
    if not url or "?" not in url:
        return url
    try:
        parts = urlsplit(url)
    except Exception:
        return url
    pairs = []
    for raw in parts.query.split("&"):
        if not raw:
            continue
        k, _, _v = raw.partition("=")
        if k.lower() in URL_QUERY_SECRET_KEYS:
            pairs.append(f"{k}=REDACTED")
        else:
            pairs.append(raw)
    new_query = "&".join(pairs)
    return f"{parts.scheme}://{parts.netloc}{parts.path}" + (
        f"?{new_query}" if new_query else ""
    )
