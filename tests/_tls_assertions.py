"""Shared test assertion for punch 651 (N-119): a client TLS context must
verify the peer. One copy, imported by the pin and the imap_blocking tests
(panel K db-sme F11)."""

from __future__ import annotations

import ssl


def assert_verifying_context(ctx) -> None:
    """``ctx`` is an ``ssl.SSLContext`` with CERT_REQUIRED and the hostname
    check on. With no context, imaplib/smtplib fall back to CERT_NONE."""
    assert isinstance(ctx, ssl.SSLContext), (
        "no SSLContext was passed: the stdlib default is CERT_NONE (punch 651, N-119)"
    )
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    assert ctx.check_hostname is True
