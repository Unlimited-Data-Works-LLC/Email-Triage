"""Shared EmailMessage assembly helper for provider ``_normalise`` paths
(#145.8).

All three providers (Gmail, O365, IMAP) ended their ``_normalise``
methods with the same final-assembly shape: extract dialect-specific
fields, run ``extract_links(body_html)``, hand the kwargs to
``EmailMessage(...)``. The link-extraction step in particular was
copied three times.

This module hosts :func:`build_email_message` — providers extract
dialect-specific fields, hand the kwargs in, get the assembled
EmailMessage back. The helper centralises:

* the ``extract_links(body_html)`` post-step;
* the ``links=[]`` fallback for HTML-less messages;
* a single import path for ``extract_links`` (was three sites).

Providers' ``_normalise`` methods become "extract dialect-specific
fields, hand off to this helper". Existing tests against
``_normalise`` stay green because the assembly shape is preserved.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from email_triage.engine.models import Attachment, EmailMessage


def build_email_message(
    *,
    message_id: str,
    provider: str,
    sender: str,
    recipients: list[str],
    subject: str,
    body_text: str,
    body_html: str,
    date: datetime,
    thread_id: str | None = None,
    labels: list[str] | None = None,
    headers: dict[str, str] | None = None,
    raw_metadata: dict[str, Any] | None = None,
    attachments: list[Attachment] | None = None,
) -> EmailMessage:
    """Assemble an EmailMessage with link extraction baked in.

    ``links`` is ALWAYS computed from ``body_html`` here — provider
    ``_normalise`` methods used to do this themselves, three sites,
    same import each time. Pass an empty string for ``body_html``
    on plain-text messages; ``links`` will be ``[]``.

    ``body_text`` falls back to a stripped-HTML rendering of
    ``body_html`` when the caller supplies an empty string. Modern
    Outlook / web Outlook / Apple Mail composes often produce
    HTML-only ``multipart/alternative`` sent items (no real
    ``text/plain`` part — or only a placeholder). Without this
    fallback the IMAP + Gmail ``_extract_body`` paths return an
    empty string and downstream style-mining + RAG indexing +
    body-based list rules silently see nothing — was the symptom
    operator hit on ``/profile/style-data/mine-now`` (IMAP account,
    "No usable sent messages" with non-zero IDs returned by SEARCH).
    O365's ``_normalise`` already does the same strip itself before
    calling here; the conditional guard below makes a double-strip
    a no-op.
    """
    from email_triage.engine.html_text import (
        extract_links, html_to_text_with_links,
    )

    links = extract_links(body_html) if body_html else []
    if not body_text and body_html:
        body_text = html_to_text_with_links(body_html)

    return EmailMessage(
        message_id=message_id,
        provider=provider,
        sender=sender,
        recipients=recipients,
        subject=subject,
        body_text=body_text,
        body_html=body_html,
        links=links,
        date=date,
        thread_id=thread_id,
        labels=list(labels or []),
        headers=dict(headers or {}),
        raw_metadata=dict(raw_metadata or {}),
        attachments=list(attachments or []),
    )
