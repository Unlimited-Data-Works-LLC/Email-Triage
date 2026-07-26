"""N-272 R28 — MIME envelope builder SSOT (2026-07-03).

Census R28 discovered MED #5 (Outbound MIME envelope builder, 7 forks):
`MIMEMultipart("alternative")` construction is spread across 4+ sites
(recipient_digest.py, imap.py :1475/:1669, auth.py:424) plus 3 sites
using the modern `EmailMessage.set_content + add_alternative` API.
Each differs on:
  - `Date` header: `formatdate(localtime=True)` (tz-leak) vs
    `formatdate(usegmt=True)`.
  - Missing `Message-Id` header on some.
  - X-Email-Triage stamp inline vs `extra_headers`.
  - 7 different plain-fallback derivations (`strip_tags` vs
    `_html_to_text_fallback` vs `render_plain` vs `_render_text` vs
    hand-composed — 7 forks of the fallback).

Any HIPAA-relevant loop-prevention added to `build_triage_header`
silently skips 6 of 7 envelopes.

N-272 lands the SSOT: `build_alternative_message(...)` — single home
for the alternative-multipart shape with correct Date/Message-Id
handling + the X-Email-Triage stamp routed through the
`build_triage_header` SSOT.

The transport SSOT (`web.smtp_send.send_smtp_message`) already exists
and is unchanged; this module only covers the ENVELOPE construction.
"""
from __future__ import annotations

import email.utils
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any


def build_alternative_message(
    *,
    subject: str,
    from_addr: str,
    from_name: str = "",
    to: str,
    plain_body: str,
    html_body: str,
    source_tag: str,
    date_gmt: bool = True,
    extra_headers: dict[str, str] | None = None,
) -> MIMEMultipart:
    """N-272 R28 SSOT — build an alternative-multipart MIME envelope.

    Contract:
      - Subject / From / To set via the canonical SSOTs
        (`format_from_header` for From).
      - `Date` header: GMT/UTC by default (`formatdate(usegmt=True)`)
        — set `date_gmt=False` if the send flow specifically needs a
        localtime date. Default matches the RFC-preferred form
        + avoids leaking the sender's timezone.
      - `Message-Id`: minted via `email.utils.make_msgid` for every
        outgoing message. Previously 6 of 7 sites omitted it, which
        broke MUA threading + inbox-provider dedup.
      - `X-Email-Triage`: stamp via `build_triage_header(source_tag)`
        — the loop-prevention SSOT. Passing a string here forces the
        SSOT-routed stamp instead of an inline hand-roll.
      - `extra_headers`: caller-specified additional headers (e.g.
        `In-Reply-To`, `References` for a threaded reply).

    Plain-then-HTML attach order per RFC 2046 (MUA picks the best it
    can render; falls back to plain).
    """
    from email_triage.mail_headers import (
        X_EMAIL_TRIAGE_HEADER,
        build_triage_header,
        format_from_header,
    )

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = format_from_header(from_addr, from_name)
    msg["To"] = to
    msg["Date"] = email.utils.formatdate(usegmt=date_gmt)
    msg["Message-Id"] = email.utils.make_msgid()
    msg[X_EMAIL_TRIAGE_HEADER] = build_triage_header(source_tag)
    if extra_headers:
        for k, v in extra_headers.items():
            # N-313 R30 (CI-red fix-forward on N-272): `email.message.
            # Message.__setitem__` APPENDS rather than replaces — so
            # `extra_headers["X-Email-Triage"] = "digest"` on top of
            # the SSOT-stamped default emitted TWO `X-Email-Triage`
            # headers, breaking downstream consumers that read the
            # first via `msg["X-Email-Triage"]` (they got the SSOT-
            # stamped default instead of the caller's override).
            # Del-then-set makes `extra_headers` the authoritative
            # last-writer for any header it names.
            del msg[k]
            msg[k] = v
    # RFC 2046 plain-then-HTML attach order.
    msg.attach(MIMEText(plain_body, "plain", "utf-8"))
    msg.attach(MIMEText(html_body, "html", "utf-8"))
    return msg
