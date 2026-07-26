"""Generic SMTP send helper, shared between OTP login and escalation
notifications.

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

import email.utils
import smtplib
from email.message import EmailMessage

from email_triage.mail_headers import (
    X_EMAIL_TRIAGE_HEADER,
    build_triage_header,
)


def stamp_default_message_headers(msg) -> None:
    """N-272b R28 SSOT — stamp RFC-preferred GMT ``Date`` + ``Message-Id``
    on an ``EmailMessage`` at build time.

    Rationale: ``send_smtp_message`` is pure transport (calls
    ``server.send_message`` — smtplib does NOT auto-add these headers).
    Missing ``Date`` degrades MUA threading + inbox-provider dedup;
    missing ``Message-Id`` breaks reply-threading + downstream de-dup.
    Every ``EmailMessage()`` construct on a send path must route through
    this helper (mirrors the ``build_alternative_message`` legacy-API
    SSOT's Date/Message-Id contract). Gmail RAW builds (``_build_raw_message``)
    are exempt — the Gmail send endpoint sets both server-side.
    """
    msg["Date"] = email.utils.formatdate(usegmt=True)
    msg["Message-Id"] = email.utils.make_msgid()


def format_from_header(from_addr: str, from_name: str = "") -> str:
    """Quote a display name into ``"Name" <addr@host>`` form — delegates to the
    mail_headers SSOT (census 2026-06-09 #5), which strips CR/LF. Re-exported so
    existing importers are unchanged."""
    from email_triage.mail_headers import format_from_header as _ssot
    return _ssot(from_addr, from_name)


def send_smtp_message(
    msg,
    *,
    smtp_host: str,
    smtp_port: int,
    smtp_user: str = "",
    smtp_password: str = "",
    use_tls: bool = True,
    smtp_timeout_secs: float | None = None,
) -> None:
    """SSOT for the smtplib transport dance — connect, optional STARTTLS, optional
    login, send a PRE-BUILT ``email.message.Message`` (plain OR multipart).

    The single place ``smtplib.SMTP(...)`` is constructed (divergence census
    2026-06-09 #2): the recipient-digest, escalate-digest, and daily-health
    senders previously each re-rolled this exact ``with smtplib.SMTP(...):
    starttls / login / send_message`` block. Sync (smtplib blocks); callers wrap
    in ``asyncio.to_thread``. Raises ``smtplib`` exceptions for the caller to
    handle. Destination-locality / egress gating is the CALLER's concern (the
    recipient is already resolved); this is transport only.
    """
    # : bounded timeout on connect + handshake. `smtplib.SMTP()`
    # defaults to the global socket timeout, which is None -> the
    # connect can block forever on an unresponsive relay (llm-host audit
    # `wf_80d5be60-ae1` finding: highest-severity of the pool-sizing
    # class). Timeout is a CONFIG item (`smtp_timeout_secs` kwarg) per
    # feedback_dynamic_over_hardcoding -- caller passes the value from
    # its own settings (env / DB / YAML); the 30s here is the SANE
    # DEFAULT that fires only when the caller passes None. Callers
    # should route through the operator-facing smtp config to keep
    # the value tunable at runtime.
    _timeout = smtp_timeout_secs if smtp_timeout_secs is not None else 30.0
    with smtplib.SMTP(smtp_host, smtp_port, timeout=_timeout) as server:
        if use_tls:
            server.starttls()
        if smtp_user:
            server.login(smtp_user, smtp_password)
        server.send_message(msg)


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
    # N-272b R28 SSOT — RFC-preferred GMT Date + Message-Id at build time.
    stamp_default_message_headers(msg)
    msg[X_EMAIL_TRIAGE_HEADER] = build_triage_header(triage_source)
    msg.set_content(body)

    send_smtp_message(
        msg, smtp_host=smtp_host, smtp_port=smtp_port,
        smtp_user=smtp_user, smtp_password=smtp_password, use_tls=use_tls,
    )
