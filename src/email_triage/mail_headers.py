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
  on every poll cycle.
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


def _now_local_iso() -> str:
    """Local-tz ISO timestamp for the human-facing ``generated=`` header
    stamp (matches the ``last_triage`` render style). A10 (census
    2026-06-09): renamed from the confusable ``_now_iso`` + delegates to
    the SSOT, so the LOCAL display helper can never be crossed with the
    UTC stored-timestamp ``_now_iso`` of the (previously) same name."""
    from email_triage._isotime import now_local_iso
    return now_local_iso()


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
    parts.append(f"generated={generated if generated is not None else _now_local_iso()}")
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


def get_message_rfc_id(message: Any) -> str:
    """Durable RFC-5322 Message-ID for a parsed *message*, with provider
    fallback — the message-level SSOT (A6, divergence census 2026-06-09).

    Resolution order, single casing authority:
      1. The ``Message-Id:`` header in ANY casing — via
         :func:`get_rfc_message_id` (the one place that knows providers
         emit ``Message-ID`` / ``Message-Id`` / ``message-id``).
      2. An explicit ``rfc822_message_id`` attribute/key, if present.
      3. The provider-normalised ``message_id`` attribute/key.
    Returns the stripped value, or ``""`` when none is present.

    ``message`` may be an ``EmailMessage``-like object OR a plain dict
    (the topic-backscan hit path passes dicts). Both header-as-attr and
    header-as-key shapes are tolerated.

    This collapses 4 hand-rolled extractors that each checked a DIFFERENT
    subset of header casings — most consequentially ``SentMailIndex``,
    which checked only ``Message-ID``/``message-id`` (missing the IMAP
    ``Message-Id``) and had NO provider-id fallback, so an IMAP-cased sent
    message resolved to ``""`` → the dedup lookup was skipped → a fresh
    row was inserted on every re-scan (the census "double-count").
    """
    if isinstance(message, dict):
        headers = message.get("headers")
    else:
        headers = getattr(message, "headers", None)
    rfc = get_rfc_message_id(headers or {})
    if rfc:
        return rfc
    for attr in ("rfc822_message_id", "message_id"):
        if isinstance(message, dict):
            val = message.get(attr)
        else:
            val = getattr(message, attr, None)
        if val:
            return str(val).strip()
    return ""


def extract_bare_address(addr: str) -> str:
    """Pull the bare ``user@host`` out of an RFC-5322 address string —
    the bare-address extraction SSOT (A7, divergence census 2026-06-09).

    Tolerates the four shapes we routinely see on the wire: bare
    ``a@b``, angle-bracketed ``<a@b>``, display-name ``Name <a@b>``,
    and group syntax ``"Name" <a@b>``. Lower-cased so equality
    comparisons survive provider casing drift.

    Robust where the hand-rolled variants weren't: the ``<([^>]+)>``
    regex correctly skips a display name that itself contains ``>`` (the
    ``s[s.index("<"):s.index(">")]`` first-bracket slice broke there) and
    the unbracketed ``"CTOx" <news@email.ctox.com>`` case (a naive
    ``rsplit("@")`` left the trailing ``>`` so every sender match
    silently missed). Do NOT change this function's output without
    re-hashing the per-contact HIPAA recipient store — it feeds
    ``style_learning.per_contact_hipaa`` (salted recipient hash).
    """
    if not addr:
        return ""
    s = str(addr).strip()
    m = re.search(r"<([^>]+)>", s)
    if m:
        return m.group(1).strip().lower()
    return s.lower()


# Back-compat alias — the SSOT was historically the module-private
# ``_extract_addr`` (cross-imported by per_contact_hipaa / draft_reply).
_extract_addr = extract_bare_address


def canonical_email(raw: str | None) -> str:
    """N-253 R25 — canonical email-address SSOT for allow-list gates.

    Produces the STABLE case-folded bare-address form used across every
    recipient-allow-list gate (§164.312(a)(1) unauthorized-recipient
    enforcement). Semantics:

    * ``None`` / ``""`` → ``""`` (fail-closed callers can distinguish).
    * A display-name-wrapped shape ``"Name <a@b>"`` → ``"a@b"`` (via
      :func:`extract_bare_address`).
    * A bare ``"a@b"`` → ``"a@b"`` (already canonical).
    * Whitespace on either side → stripped.
    * Case → lower.

    Callers that used ``(x or "").strip().lower()`` on an
    address-shaped variable MUST route through this helper — a raw
    strip/lower left ``"Alice <a@b>"`` split from ``"a@b"``, so the
    SAME sender's two envelope shapes DIVERGED in the allow-list gate
    → §164.312(a)(1) drift.

    Wraps :func:`extract_bare_address` which already handles the four
    wire shapes (bare / ``<a@b>`` / ``Name <a@b>`` / ``"Name" <a@b>``)
    and lower-cases the output.

    **N-317 R30 (tranche  follow-up from DA panel)**: additionally
    IDNA-normalize the domain part so ``alice@münchen.de`` (U-label /
    unicode) and ``alice@xn--mnchen-3ya.de`` (A-label / punycode) map
    to the SAME canonical key. Without this, the allow-list gate at
    §164.312(a)(1) treated the two shapes as distinct → an authorized
    recipient's IDN-encoded envelope variant BYPASSED the gate. Fix:
    encode the domain via the stdlib ``idna`` codec (**RFC 3490 /
    IDNA-2003** — that is what Python's stdlib actually implements,
    NOT IDNA-2008/UTS-46 as the original N-317 R30 docstring cited).

    **N-358 R31 accuracy fix (2026-07-05 trust-repair fix-forward per
    PHASE2 tranche  db-sme + the backlog  = TASK ):** the
    original docstring cited RFC 5890 / 6531 (IDNA-2008 / UTS-46 —
    what the ``idna`` PyPI package implements). Python's stdlib
    ``.encode("idna")`` is IDNA-2003 (RFC 3490) which is a strict
    subset. The two agree on the common Unicode/punycode cases the
    N-317 gate protects (Latin-1 diacritics, common CJK), but differ
    on some edge cases (TR-46 mappings, some emoji/ZWJ shapes). The
    full migration to the ``idna`` PyPI package (IDNA-2008 / UTS-46
    semantics) is tracked as N-317, an OPEN v0.2.0 work item awaiting
    a proper drive (corrected 2026-07-06 from a false "v0.3.0 scope
    item" attribution per operator directive — v0.3.0 is enterprise-
    scaling scope only per internal documentation; IDNA
    semantics work is v0.2.0). Until then this docstring accurately
    reflects the stdlib IDNA-2003 shape.

    **N-346c R31 (2026-07-08 trust-repair drive HIGH  close):** the
    persisted-hash backfill/dual-lookup decision that WAS "operator-
    parked" per an earlier revision of this docstring is LANDED. The
    dual-lookup shim (`hash_recipient_for_install(shape=)` +
    `hash_recipient_for_install_all_shapes()`) preserves persisted-row
    integrity while enabling canonical-shape reads without a downtime
    backfill window; existing rows stay legacy-shape + are still
    addressable via the dual-lookup probe. See §4.9 register-row
    N-346c + `tests/test_n346c_dual_lookup_shim.py`. N-317 stays open
    as an independent work item (extending `_HASH_SHAPES` with a
    UTS-46 variant is forward-compatible with the shim; no re-scope
    of N-317 needed). SME panel MUST-FIX F2 fold — the register-row
    landing is the source of truth on N-346c status; this docstring
    no longer holds that scope.

    Fail-CLOSED on encode error — return the extracted bare address
    unchanged so any bad-domain caller matches against a shape the
    allow-list won't accept.
    """
    bare = extract_bare_address(raw or "")
    if not bare or "@" not in bare:
        return bare
    local, _, domain = bare.rpartition("@")
    if not domain:
        return bare
    try:
        # `idna` codec produces the A-label form (punycode-prefixed
        # for non-ASCII labels; identity for pure-ASCII). Case is
        # already lowered by extract_bare_address.
        ascii_domain = domain.encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        # Malformed domain — fail closed. Return the raw extraction
        # so the caller's allow-list gate rejects (no authorized
        # entry will match a malformed domain).
        return bare
    return f"{local}@{ascii_domain}"


#: SSOT for the subject reply-prefix matcher (census run13 ). ``fwd?`` matches
#: both ``fw`` and ``fwd``; ``re``/``fw``/``fwd`` are the recognised tokens. Two
#: copies had drifted (one ``(?:re|fwd?|fw)``, one ``(?:re|fwd|fw)`` — equivalent
#: today, but a future prefix added to ONE would fragment the other's dedup key).
SUBJECT_REPLY_PREFIX_RE = re.compile(r"^\s*(?:re|fwd?|fw)\s*:\s*", re.IGNORECASE)


def strip_reply_prefix(subject: str) -> str:
    """Strip chained leading ``Re:`` / ``Fwd:`` / ``Fw:`` reply-prefix tokens
    (any case) from a subject (``Re: Fwd: Re: Lunch`` -> ``Lunch``) — the SSOT
    for subject reply-prefix normalization (census run13 ). ``None``/empty ->
    ``""``. Returns the prefix-stripped subject WITHOUT further normalization;
    the caller applies its own (a trailing ``.strip()`` / a cache ``_norm``), so
    converging onto this is behaviour-preserving for both consumers."""
    if not subject:
        return ""
    out = subject
    while True:
        new = SUBJECT_REPLY_PREFIX_RE.sub("", out, count=1)
        if new == out:
            break
        out = new
    return out


def extract_display_name(sender: str) -> str:
    """The DISPLAY-NAME portion of a From header (``"Alice" <a@b>`` -> ``Alice``)
    — the SSOT (census run13 ). Strips surrounding single AND double quotes.
    Returns ``""`` when there is no ``<…>`` bracket (a bare address) — the CALLER
    chooses its own no-display-name fallback (digest title-cases the local-part,
    escalate uses it raw, the watch first-name extractors take the first word),
    because that fallback is a per-surface UX choice, not a parse. Complements
    :func:`extract_bare_address` (which pulls the ADDRESS out of the same header)."""
    if not sender or "<" not in sender:
        return ""
    return sender.split("<")[0].strip().strip('"').strip("'")


def extract_domain(sender: str) -> str:
    """Return the lowercased domain portion of an RFC-5322 sender value.

    The SSOT for sender-domain extraction (N-71, divergence census
    2026-06-09): before this, ``_extract_domain`` in ``classify/hints.py``
    and ``_domain_of`` in ``web/email_watches.py`` each extracted the
    domain independently via ``rsplit("@", 1)[-1]`` / ``split("@", 1)[1]``
    on a bare address.  While both happened to call ``extract_bare_address``
    first (so the display-name issue was resolved), they diverge on the
    security-critical double-@ spoof case:

      * ``addr.split("@", 1)[1]``   → for ``a@b@evil.com`` after bare-addr
        extraction returns ``b`` (the first part after the first @).
      * ``addr.rsplit("@", 1)[-1]`` → returns ``evil.com`` (the last part).

    Per RFC 5321 §4.1.2 the domain is the LAST @-separated token in the
    addr-spec.  ``extract_bare_address`` already handles display-name
    stripping; here we just split on the rightmost ``@`` so that a
    double-@ spoof consistently resolves to the real (last) domain rather
    than the decoy local-part.

    Composed on ``extract_bare_address`` (frozen SSOT) so:
    - display-name form ``"Name" <a@b>`` → ``b``
    - bare address ``a@b`` → ``b``
    - double-@ ``a@b@evil.com`` → ``evil.com`` (the rightmost = real domain)
    - no ``@`` → ``""`` (not a valid address; caller gates on empty)

    The ``classify/hints.py::_extract_domain`` and
    ``web/email_watches.py::_domain_of`` helpers delegate here; the pin
    ``tests/test_n71_sender_domain_ssot_pin.py`` enforces that no new
    module hand-rolls the split.
    """
    addr = extract_bare_address(sender)
    if "@" not in addr:
        return ""
    return addr.rsplit("@", 1)[-1]


def format_from_header(from_addr: str, from_name: str | None = "") -> str:
    """Build an RFC-5322 ``From`` value — ``"Display Name" <addr@host>``, or the
    bare address when there is no display name.

    SSOT for the ~5 hand-rolled copies (``web/auth``, ``web/smtp_send``,
    ``providers/gmail_api``, ``providers/imap`` ×2) that each quoted the display
    name WITHOUT stripping CR/LF (divergence census 2026-06-09 #5). It lives here
    in ``mail_headers`` (not ``web/``) because the providers must call it too and
    a provider must not import from ``web``.

    STRIPS CR/LF (and other control characters) from the display name — a name
    containing a bare ``\\r``/``\\n`` could otherwise inject extra mail headers —
    then escapes backslash + quote. The display name is operator/account-owner
    config in the current senders (not attacker-controlled), so this is
    defense-in-depth; but the weakest-variant rule applies (no copy stripped
    CR/LF, so the system had no CR/LF defense at all). For a name with no control
    characters the output is byte-identical to the old copies.

    Distinct from ``extract_bare_address`` (extraction for the §164.514(b) hash,
    byte-FROZEN) — this is header BUILDING.
    """
    name = (from_name or "").strip()
    if not name:
        return from_addr
    # Header-injection defense: collapse any CR/LF/control run to a single space
    # BEFORE quoting, so the quoted-string can't carry a header break.
    cleaned = re.sub(r"[\r\n\t\x00-\x1f]+", " ", name).strip()
    if not cleaned:
        return from_addr
    safe = cleaned.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{safe}" <{from_addr}>'


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
        #  tail — RFC 2047 encoded-word body; some MUAs strip
        # padding. Route through the SSOT so a length-not-multiple-of-4
        # input decodes correctly instead of returning empty string.
        # Post-#123 CI regression fix (2026-07-11): the pre-fix behavior
        # `base64.b64decode(cleaned, validate=False)` RAISED on non-4-
        # multiple garbage input (length mismatch) — the SSOT pads first
        # so length-mismatch no longer raises. Use `validate=True` to
        # reject non-alphabet chars (garbage) so the caller's
        # `except: return ""` semantics are preserved for garbage input.
        # The `test_decode_garbage_returns_empty` test pins this contract.
        from email_triage._base64url import b64decode_permissive
        raw = b64decode_permissive(cleaned, urlsafe=False, validate=True)
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
