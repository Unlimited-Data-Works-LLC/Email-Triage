"""US cell-carrier email-to-SMS gateway helpers (#73).

Operator picks a carrier from a dropdown on ``/profile`` and types a
cell number; the system computes the matching gateway address (e.g.
``5551234567@vtext.com``) and writes it to ``users.notify_email``
where the existing ``EscalateAction`` reads it.

Carriers + gateway domains are best-effort, US-only, and do change
without notice — verify the list against the carrier's published
docs before any deploy. International users + non-listed carriers
fall back to the free-text "Advanced — custom address" path on
``/profile``.

Privacy note: SMS over a carrier email-to-SMS gateway is plaintext
on the wire and is NOT a HIPAA-encrypted channel. The escalation
notification text is metadata-only (category + timestamp,
optionally first name + subject in non-HIPAA mode) — see
``actions/escalate.py:_build_notification``. No mail body content
ever reaches the gateway regardless of mode.
"""

from __future__ import annotations

import re

# (slug, display_name, gateway_domain). Slug is the form-field
# value the dropdown POSTs back. Order = display order in the UI.
US_CELL_CARRIERS: list[tuple[str, str, str]] = [
    ("verizon",     "Verizon",            "@vtext.com"),
    ("att",         "AT&T",               "@txt.att.net"),
    ("tmobile",     "T-Mobile / Sprint",  "@tmomail.net"),
    ("uscellular",  "US Cellular",        "@email.uscc.net"),
    ("boost",       "Boost",              "@sms.myboostmobile.com"),
    ("cricket",     "Cricket",            "@sms.cricketwireless.net"),
    ("metropcs",    "MetroPCS",           "@mymetropcs.com"),
    ("googlefi",    "Google Fi",          "@msg.fi.google.com"),
]


def carrier_gateway(slug: str) -> str | None:
    """Return the gateway domain (with leading ``@``) for a carrier
    slug, or ``None`` if the slug isn't recognized."""
    for c_slug, _name, domain in US_CELL_CARRIERS:
        if c_slug == slug:
            return domain
    return None


def normalize_us_cell_number(raw: str) -> str | None:
    """Accept a loosely-formatted US cell number, return canonical
    10-digit string or ``None`` if the input can't be normalized.

    Accepted shapes (after stripping spaces / dashes / dots / parens
    / leading ``+``):

    - ``5551234567``         (10 digits)
    - ``15551234567``        (11 digits with US country code)

    Anything else — fewer than 10 digits, more than 11, or 11 digits
    that don't start with 1 — fails.
    """
    if not raw:
        return None
    digits = re.sub(r"\D", "", raw)
    if len(digits) == 10:
        return digits
    if len(digits) == 11 and digits.startswith("1"):
        return digits[1:]
    return None


def build_sms_address(number: str, carrier_slug: str) -> str | None:
    """Combine a normalized 10-digit number + carrier slug into the
    gateway email address. Returns ``None`` if the slug is unknown
    or the number isn't already in canonical form (caller should
    normalize first)."""
    if not number or not number.isdigit() or len(number) != 10:
        return None
    gateway = carrier_gateway(carrier_slug)
    if gateway is None:
        return None
    return f"{number}{gateway}"


def carrier_display_name(slug: str) -> str | None:
    """Return the human-readable carrier name for a slug, or None."""
    for c_slug, name, _domain in US_CELL_CARRIERS:
        if c_slug == slug:
            return name
    return None
