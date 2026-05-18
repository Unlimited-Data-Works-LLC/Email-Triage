"""Outbound mail stamping + inbound loop-prevention helpers.

Every outbound mail codepath (digest delivery, draft replies, OTP,
daily health) stamps an ``X-Email-Triage:`` header so that when that
mail lands back in a watched inbox we can short-circuit the triage
pipeline and avoid cascading re-classification.

Header format::

    X-Email-Triage: <source>[; key=value]...

``<source>`` is the mandatory first token — one of ``digest``,
``draft-reply``, ``otp``, ``health-email``. Optional fields:

* ``category=``  — when applicable (digest + draft-reply)
* ``account=``   — non-HIPAA only (account identifier); dropped when
  the message is on a HIPAA account / system HIPAA is on
* ``version=``   — commit SHA, matching whatever ``/health`` reports
* ``generated=`` — ISO timestamp in the container's local tz

The helper is deliberately tiny + stringly-typed; every site adds
just one line: ``msg["X-Email-Triage"] = build_triage_header("digest",
category=...)``.

This module also hosts two related self-loop helpers used by every
triage entry point:

* :func:`build_self_skip_query` rewrites a provider-specific search
  query so the install's own outbound from-address is excluded at
  the SEARCH stage. Saves a fetch + classifier call per self-mail
  on every poll cycle (#117).
* :func:`is_self_origin` is the defense-in-depth secondary check on
  ``message.sender`` matching ``smtp.from_addr`` — fires even when
  a downstream MTA stripped the ``X-Email-Triage`` header (custom
  inbound-rewrite rules, Gmail "Forward" with stripping etc.).
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any

# The literal header name. Kept as a module constant so every
# producer + consumer uses the exact same string (case normalisation
# aside — RFC 5322 headers are case-insensitive, but MTAs routinely
# preserve whatever case the sender used, so we pick one canonical
# form and stick to it).
X_EMAIL_TRIAGE_HEADER = "X-Email-Triage"

# M-6 edit-feedback capture loop: companion header carrying the
# original AI-drafted body as a base64-encoded snapshot. When the
# user edits + sends the draft, the M-6 scanner reads this header
# off the sent message to compare draft vs sent and persist the
# captured pair into the M-4 RAG index with a higher ranking weight.
# Old messages without this header (drafted before M-6 shipped) are
# skipped silently by the scanner.
X_EMAIL_TRIAGE_DRAFT_BODY_HEADER = "X-Email-Triage-Draft-Body"


def _resolve_version() -> str:
    """Return the short version identifier that ``/health`` exposes.

    Lazy-imported so ``mail_headers`` doesn't pull in the whole
    FastAPI web module for non-web callers (CLI, background scripts).
    """
    try:
        from email_triage.web.app import _resolve_version as _rv
        return _rv()
    except Exception:
        return "unknown"


def _now_iso() -> str:
    """Local-tz ISO timestamp; matches the ``last_triage`` render style."""
    return datetime.now().astimezone().isoformat()


def build_triage_header(
    source: str,
    *,
    category: str = "",
    account: str = "",
    hipaa: bool = False,
    version: str | None = None,
    generated: str | None = None,
) -> str:
    """Assemble the ``X-Email-Triage:`` header value.

    ``source`` must be one of ``digest`` / ``draft-reply`` / ``otp`` /
    ``health-email``. ``category`` + ``account`` are optional; pass
    empty strings to skip them. When ``hipaa=True`` the ``account=``
    field is dropped regardless of what was passed in — the header
    itself is still emitted so the loop-prevention check still fires.

    ``version`` + ``generated`` default to ``_resolve_version()`` and
    ``datetime.now().astimezone().isoformat()`` respectively; tests
    pin them for deterministic output.
    """
    parts: list[str] = [source]
    if category:
        parts.append(f"category={category}")
    if account and not hipaa:
        parts.append(f"account={account}")
    parts.append(f"version={version if version is not None else _resolve_version()}")
    parts.append(f"generated={generated if generated is not None else _now_iso()}")
    return "; ".join(parts)


def get_rfc_message_id(headers: Any) -> str:
    """Return the RFC-5322 ``Message-Id:`` header value.

    Used by the cross-folder loop-prevention dedup: the IMAP UID
    changes when a message is COPY+DELETE'd into a watched
    destination folder, but the RFC ``Message-Id:`` is stable. Same
    case-insensitive scan as ``get_triage_header`` because providers
    aren't consistent (Gmail returns ``Message-ID``, IMAP parsed
    headers vary, Graph normalises).

    Returns the bare value (still angle-bracketed if the wire format
    used them — we don't strip), or empty string if absent.
    """
    if not headers:
        return ""
    val = headers.get("Message-ID") if hasattr(headers, "get") else None
    if val:
        return str(val).strip()
    val = headers.get("Message-Id") if hasattr(headers, "get") else None
    if val:
        return str(val).strip()
    try:
        items = headers.items()
    except AttributeError:
        return ""
    for key, value in items:
        if isinstance(key, str) and key.lower() == "message-id" and value:
            return str(value).strip()
    return ""


def _extract_addr(addr: str) -> str:
    """Pull the bare ``user@host`` out of an RFC-5322 address string.

    Tolerates the four shapes we routinely see on the wire: bare
    ``a@b``, angle-bracketed ``<a@b>``, display-name ``Name <a@b>``,
    and group syntax ``"Name" <a@b>``. Lower-cased so equality
    comparisons survive provider casing drift.
    """
    if not addr:
        return ""
    s = str(addr).strip()
    m = re.search(r"<([^>]+)>", s)
    if m:
        return m.group(1).strip().lower()
    return s.lower()


def build_self_skip_query(
    base_query: str,
    self_from_addr: str,
    *,
    provider_type: str,
) -> str:
    """Rewrite ``base_query`` so the SEARCH stage excludes self-from mail.

    Self-mail (digests, draft replies, OTP, health email) carries the
    ``X-Email-Triage`` header and is short-circuited in every triage
    entry point — but every poll still pays the per-message FETCH +
    HEADER-parse cost just to find that out. Pushing the exclusion
    up to the provider's SEARCH means the install's own outbound
    never enters the result set in the first place.

    ``provider_type`` is the ``email_accounts.provider_type`` value:
    ``gmail_api``, ``imap``, ``office365``. Empty / unknown providers
    return ``base_query`` unchanged so the caller falls back to the
    fetch-stage X-Email-Triage check.

    ``self_from_addr`` should be the install's ``smtp.from_addr``.
    Empty value returns ``base_query`` unchanged — no install-wide
    self-from configured means there's no install-wide self-mail to
    skip at the SEARCH stage.
    """
    addr = _extract_addr(self_from_addr)
    if not addr:
        return base_query or ""
    base = (base_query or "").strip()
    pt = (provider_type or "").lower()

    if pt in ("gmail_api", "gmail"):
        # Gmail's q= syntax: ``-from:foo@bar`` excludes that sender.
        # AND-combined with the rest of the query.
        clause = f"-from:{addr}"
        return f"{base} {clause}".strip() if base else clause

    if pt in ("imap", "imap_oauth"):
        # IMAP SEARCH: ``NOT FROM "foo@bar"`` — RFC 3501 SEARCH
        # criterion. Quoted because addresses can contain dots and
        # IMAP servers are picky about unquoted atom syntax.
        clause = f'NOT FROM "{addr}"'
        # IMAP SEARCH AND-combines space-separated criteria. If the
        # base is empty we still want SEARCH to succeed — emit
        # ``ALL NOT FROM ...`` so the parser sees a complete criterion.
        if not base:
            return f"ALL {clause}"
        return f"{base} {clause}"

    if pt in ("office365", "graph", "msgraph"):
        # Microsoft Graph $filter: ``from/emailAddress/address ne 'foo@bar'``.
        # When base is non-empty we treat it as a $filter clause and
        # ``and`` with our exclusion. When base is empty, just emit
        # the exclusion. The provider's _translate_filter / search()
        # dispatch decides whether to use $filter or $search; this
        # helper handles only the $filter shape because that's the
        # OData logical operators codepath.
        clause = f"from/emailAddress/address ne '{addr}'"
        if not base:
            return clause
        return f"({base}) and {clause}"

    return base


def is_self_origin(sender: str, self_from_addr: str) -> bool:
    """Defense-in-depth check: does ``sender`` match the install's
    own outbound from-address?

    Used by every triage entry point as a secondary skip after the
    primary ``X-Email-Triage`` header check. Catches the case where
    a downstream MTA (forwarder, list explosion, custom inbound
    re-write rule) stripped the ``X-Email-Triage`` header before
    delivery — the install would otherwise re-classify its own
    outbound digest as fyi.

    Empty arguments return ``False`` (no install-wide self-from
    configured ⇒ no self-loop to detect). Address-only comparison
    after :func:`_extract_addr` normalisation; a display-name change
    (``Email Triage <a@b>`` → ``a@b``) won't break the match.
    """
    a = _extract_addr(sender)
    b = _extract_addr(self_from_addr)
    if not a or not b:
        return False
    return a == b


def encode_draft_body_header(body: str) -> str:
    """Encode an AI-drafted body for the ``X-Email-Triage-Draft-Body`` header.

    Returns a base64-encoded UTF-8 string with no embedded newlines
    (RFC 5322 headers can fold but the consumer is happiest with a
    single line). Empty input returns the empty string -- the caller
    decides whether to drop the header entirely in that case.

    Inverse of :func:`decode_draft_body_header`.
    """
    import base64
    if not body:
        return ""
    raw = body.encode("utf-8", errors="replace")
    encoded = base64.b64encode(raw).decode("ascii")
    # Strip any embedded whitespace just in case the encoder split
    # at width-76 (Python 3.13 doesn't, but defence in depth).
    return "".join(encoded.split())


def decode_draft_body_header(value: str | None) -> str:
    """Decode a base64-encoded draft body back to plaintext.

    Tolerant of whitespace embedded in the header value (some MTAs
    fold long header lines) and of malformed input -- returns the
    empty string on any decode failure rather than raising. The
    caller treats empty as "no usable draft body" and skips the
    captured-pair indexing for that message.

    Inverse of :func:`encode_draft_body_header`.
    """
    import base64
    if not value:
        return ""
    cleaned = "".join(str(value).split())
    if not cleaned:
        return ""
    try:
        raw = base64.b64decode(cleaned, validate=False)
    except Exception:
        return ""
    try:
        return raw.decode("utf-8", errors="replace")
    except Exception:
        return ""


def get_draft_body_header(headers: Any) -> str | None:
    """Case-insensitive lookup of the ``X-Email-Triage-Draft-Body`` header.

    Mirrors :func:`get_triage_header` -- providers can normalise to
    different casing, so we walk the headers map case-insensitively.
    Returns the raw (still-base64) header value on a hit, or ``None``
    when absent. The caller pipes it through :func:`decode_draft_body_header`
    to get plaintext.
    """
    if not headers:
        return None
    val = headers.get(X_EMAIL_TRIAGE_DRAFT_BODY_HEADER) if hasattr(
        headers, "get",
    ) else None
    if val:
        return val
    try:
        items = headers.items()
    except AttributeError:
        return None
    target = X_EMAIL_TRIAGE_DRAFT_BODY_HEADER.lower()
    for key, value in items:
        if isinstance(key, str) and key.lower() == target and value:
            return value
    return None


def get_triage_header(headers: Any) -> str | None:
    """Case-insensitive lookup of the ``X-Email-Triage`` header.

    ``EmailMessage.headers`` is a plain dict populated by each
    provider in whatever case the wire format reported; Gmail's API
    typically preserves the sender's casing, IMAP's parsed headers
    can go either way, and Graph normalises to title case. So we
    check every key instead of trusting the mapping's case policy.
    Returns the header value on a hit, ``None`` otherwise.
    """
    if not headers:
        return None
    # Fast path: exact canonical.
    val = headers.get(X_EMAIL_TRIAGE_HEADER) if hasattr(headers, "get") else None
    if val:
        return val
    # Slow path: case-insensitive scan. Providers aren't consistent.
    try:
        items = headers.items()
    except AttributeError:
        return None
    target = X_EMAIL_TRIAGE_HEADER.lower()
    for key, value in items:
        if isinstance(key, str) and key.lower() == target and value:
            return value
    return None
