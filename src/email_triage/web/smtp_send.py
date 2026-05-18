"""Generic SMTP send helper, shared between OTP login and escalation
notifications (#73).

Extracted from ``email_triage.web.auth.send_otp_email`` so the
``EscalateAction`` can reuse the same auth envelope + From-quoting +
loop-prevention stamp without duplicating the smtplib dance. OTP-
specific shaping (subject + body) stays in ``send_otp_email`` as a
thin wrapper around this primitive.

Loop-prevention: every send via this helper stamps the
``X-Email-Triage`` header with the supplied ``triage_source``. The
ingestion pipelines short-circuit on that header so a notification
mail that lands in a watched inbox doesn't re-classify into a loop.
Caller picks ``triage_source`` per use-case (``"otp"`` for login
codes, ``"escalation"`` for the escalate action, etc.).
"""

from __future__ import annotations

import smtplib
from email.message import EmailMessage

from email_triage.mail_headers import (
    X_EMAIL_TRIAGE_HEADER,
    build_triage_header,
)


def format_from_header(from_addr: str, from_name: str) -> str:
    """Quote a display name into ``"Name" <addr@host>`` form, or
    return the bare address if no name is provided."""
    if not from_name:
        return from_addr
    safe_name = from_name.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{safe_name}" <{from_addr}>'


def send_simple_smtp_email(
    *,
    smtp_host: str,
    smtp_port: int,
    smtp_user: str,
    smtp_password: str,
    from_addr: str,
    to_addr: str,
    subject: str,
    body: str,
    use_tls: bool = True,
    from_name: str = "",
    triage_source: str = "system",
) -> None:
    """Send a plain-text single-recipient email via SMTP.

    Synchronous; caller wraps in ``asyncio.to_thread`` if used from
    an async path. Raises ``smtplib`` exceptions on failure for the
    caller to log + decide on retry behavior.

    Loop-prevention: stamps ``X-Email-Triage: <triage_source>; ...``
    so if this message ever ends up in a watched mailbox the
    ingestion pipeline drops it instead of re-triaging.
    """
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = format_from_header(from_addr, from_name)
    msg["To"] = to_addr
    msg[X_EMAIL_TRIAGE_HEADER] = build_triage_header(triage_source)
    msg.set_content(body)

    with smtplib.SMTP(smtp_host, smtp_port) as server:
        if use_tls:
            server.starttls()
        if smtp_user:
            server.login(smtp_user, smtp_password)
        server.send_message(msg)
