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


def scrub_secrets_from_text(
    text: str | None, *, max_len: int = SECRET_SCRUB_MAX_LEN,
) -> str | None:
    """Return a token-redacted + whitespace-collapsed + truncated copy.

    ``None`` / empty in → ``None`` out. For each :data:`SECRET_TOKEN_KEYS` key,
    the three common shapes (quoted-key dict-repr/JSON, ``key='quoted'`` kwarg,
    ``key=bareword``) have their value replaced with ``[REDACTED]``. The result
    is collapsed (CR/LF runs → single spaces, so a multi-line stderr renders in
    a one-line banner) and truncated to ``max_len``.
    """
    if not text:
        return None
    out = " ".join(str(text).split())
    for key in SECRET_TOKEN_KEYS:
        ek = re.escape(key)
        # Shape 1: quoted key + colon + quoted value ("key": "value").
        out = re.sub(
            r"(['\"]" + ek + r"['\"]\s*:\s*['\"])[^'\"]*(['\"])",
            r"\1[REDACTED]\2", out, flags=re.IGNORECASE,
        )
        # Shape 2: bare key + = + quoted value (key='value').
        out = re.sub(
            r"(\b" + ek + r"\s*=\s*['\"])[^'\"]*(['\"])",
            r"\1[REDACTED]\2", out, flags=re.IGNORECASE,
        )
        # Shape 3: bare key + = + bareword value, bounded at a delimiter.
        out = re.sub(
            r"(\b" + ek + r"\s*=\s*)[^\s,;&)}\]]+",
            r"\1[REDACTED]", out, flags=re.IGNORECASE,
        )
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
