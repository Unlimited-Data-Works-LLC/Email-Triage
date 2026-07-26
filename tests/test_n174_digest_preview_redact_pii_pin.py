"""N-174 — digest PREVIEW render leak (3rd site of the display-min class).

Sibling of N-162 (triage discover-results) and N-172 (digest candidates
"Show matches" table). The full-digest-BODY render
(``recipient_digest.render_html`` / ``render_plain``, reached by the
``digest_preview`` handler through ``_render_digest_payload``) rendered
``sender`` + ``subject`` VERBATIM even for a HIPAA account. The preview
route is gated by ``OwnedAccount`` → ``can_manage_account`` = reachable by
a MANAGING NON-OWNER (site-admin / delegate), so verbatim sender + subject
there is a §164.502(b) min-necessary / §164.514(d)(1) leak.

The fix adds an orthogonal ``redact_pii`` flag (default ``False`` =
delivered-path verbatim) that the PREVIEW passes as ``effective_hipaa``
(viewer-independent display-min — even the owner sees ``[redacted]`` in
HIPAA-mode preview). ``hipaa`` (the classifier-reason gate) is unchanged.

CRITICAL CONSTRAINT pinned here: the DELIVERED digest
(``_fire_one_digest`` → ``_render_digest_payload`` with ``redact_pii``
omitted/``False``) is BYTE-UNCHANGED — the recipient is the account's own
authorized mailbox and still gets verbatim sender + subject.

Teeth: pre-fix ``render_html`` had no ``redact_pii`` parameter and the
preview rendered sender + subject verbatim — the redaction assertions
below RED against HEAD~1.
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import patch

import pytest

from email_triage.actions.recipient_digest import render_html, render_plain

_SENDER = "alice@clinic.example.com"
_SUBJECT = "Lab results: glucose panel"
_REASON = "Patient confirmed Tuesday appointment"  # the new-PHI surface


def _row(*, sender=_SENDER, subject=_SUBJECT, category="newsletter"):
    return {
        "message_id": "m1",
        "sender": sender,
        "subject": subject,
        "category": category,
        "reason": _REASON,
        "source": "llm",
        "status": "ok",
        "date": "2026-05-02T08:14:00+00:00",
    }


# ---------------------------------------------------------------------------
# render_html — the surface the preview reaches
# ---------------------------------------------------------------------------


class TestRenderHtmlRedactPii:
    def test_preview_redacts_sender_and_subject(self):
        """redact_pii=True (the preview path) → sender + subject gone."""
        out = render_html(
            rows=[_row()], account_name="Clinic", account_email="x@y.com",
            hipaa=True, redact_pii=True,
        )
        assert _SENDER not in out
        assert _SUBJECT not in out
        assert "[redacted]" in out

    def test_delivered_keeps_sender_and_subject_verbatim(self):
        """redact_pii=False (delivered) → verbatim to the OWN mailbox."""
        out = render_html(
            rows=[_row()], account_name="Clinic", account_email="x@y.com",
            hipaa=True, redact_pii=False,
        )
        assert _SENDER in out
        assert _SUBJECT in out

    def test_default_is_delivered_verbatim(self):
        """Omitting redact_pii defaults to the delivered (verbatim)
        behavior — a caller that does NOT opt in must not redact."""
        out = render_html(
            rows=[_row()], account_name="Clinic", account_email="x@y.com",
            hipaa=True,
        )
        assert _SENDER in out
        assert _SUBJECT in out

    def test_delivered_byte_unchanged_default_vs_explicit_false(self):
        """The DELIVERED digest is byte-identical whether the caller
        omits redact_pii or passes redact_pii=False — proves the send
        path is untouched by the N-174 plumbing."""
        kwargs = dict(
            rows=[_row()], account_name="Clinic",
            account_email="x@y.com", hipaa=True,
        )
        assert render_html(**kwargs) == render_html(**kwargs, redact_pii=False)

    def test_reason_still_redacted_under_hipaa_regardless(self):
        """redact_pii is orthogonal to the classifier-reason gate:
        the new-PHI ``reason`` surface stays redacted under hipaa in
        BOTH preview and delivered renders."""
        for redact_pii in (True, False):
            out = render_html(
                rows=[_row()], account_name="Clinic",
                account_email="x@y.com", hipaa=True, redact_pii=redact_pii,
            )
            assert _REASON not in out

    def test_banner_distinguishes_preview_from_delivered(self):
        preview = render_html(
            rows=[_row()], account_name="C", account_email="x@y.com",
            hipaa=True, redact_pii=True,
        )
        delivered = render_html(
            rows=[_row()], account_name="C", account_email="x@y.com",
            hipaa=True, redact_pii=False,
        )
        assert "redacted" in preview.lower()
        # Delivered banner asserts verbatim; preview banner must NOT.
        assert "verbatim" in delivered.lower()
        assert "verbatim because" not in preview.lower()


class TestRenderPlainRedactPii:
    def test_preview_plain_redacts(self):
        out = render_plain(
            rows=[_row()], account_name="C", account_email="x@y.com",
            hipaa=True, redact_pii=True,
        )
        assert _SENDER not in out
        assert _SUBJECT not in out
        assert "[redacted]" in out

    def test_delivered_plain_verbatim(self):
        out = render_plain(
            rows=[_row()], account_name="C", account_email="x@y.com",
            hipaa=True, redact_pii=False,
        )
        assert _SENDER in out
        assert _SUBJECT in out


# ---------------------------------------------------------------------------
# Seam test — the preview's real plumbing: digest_preview passes
# redact_pii through _render_digest_payload (preset branch) down to
# render_html. _fire_one_digest omits it → delivered verbatim.
# ---------------------------------------------------------------------------


@pytest.fixture
def acct_imap():
    return {
        "id": 42, "name": "Clinic", "user_id": 1,
        "provider_type": "imap",
        "config": {"host": "x.test", "port": 993, "username": "u@test"},
        "email_address": "u@test", "is_active": True, "hipaa": True,
    }


@pytest.fixture
def dcfg_preset():
    from email_triage.actions.digest_configs import (
        DigestConfig, DigestFormat, PRESET_ID,
    )
    return DigestConfig(
        id=PRESET_ID, kind="custom", name="", enabled=True,
        format=DigestFormat(render_as="table"),
    )


@pytest.mark.asyncio
async def test_preview_seam_redacts_delivered_seam_verbatim(
    acct_imap, dcfg_preset,
):
    """The preset preview seam (redact_pii=True) redacts the digest
    body; the delivered seam (redact_pii omitted) keeps it verbatim —
    same shared SSOT, one flag apart."""
    from email_triage.web.app import _render_digest_payload

    secrets = type("S", (), {"get": lambda *a, **k: ""})()
    rows_in = [_row()]
    with patch(
        "email_triage.actions.recipient_digest.gather_digest_rows",
        return_value=rows_in,
    ):
        # PREVIEW: digest_preview passes redact_pii=effective_hipaa.
        _s, prev_html, prev_plain, _r, _t = await _render_digest_payload(
            db=object(), secrets=secrets, acct=acct_imap, dcfg=dcfg_preset,
            hipaa=True, now_utc=datetime.now(timezone.utc), last_sent=None,
            redact_pii=True,
        )
        # DELIVERED: _fire_one_digest omits redact_pii (default False).
        _s2, deliv_html, deliv_plain, _r2, _t2 = await _render_digest_payload(
            db=object(), secrets=secrets, acct=acct_imap, dcfg=dcfg_preset,
            hipaa=True, now_utc=datetime.now(timezone.utc), last_sent=None,
        )

    # Preview body is display-min redacted.
    assert _SENDER not in prev_html and _SUBJECT not in prev_html
    assert "[redacted]" in prev_html
    assert _SENDER not in prev_plain and _SUBJECT not in prev_plain

    # Delivered body still carries verbatim sender + subject to the
    # account's own authorized mailbox (the N-174 must-not-break).
    assert _SENDER in deliv_html and _SUBJECT in deliv_html
    assert _SENDER in deliv_plain and _SUBJECT in deliv_plain
