"""Tests for the per-digest sender's recipient-mismatch guard.

The digest sender enforces a defense-in-depth assertion that the
``to_addr`` it's about to send to MATCHES the account's resolved
``email_address`` field. Locks delivery to "the same mailbox the
mail came from" per the design contract. HIPAA-flagged accounts
benefit most (PHI never leaks via a redirected-recipient leak)
but the check fires in standard mode too — a misrouted send is
a bug regardless of HIPAA posture.

Coverage:
- Matching to_addr → send proceeds (delegates to the rest of
  the pipeline; mocked here so we just observe the SMTP call
  was attempted).
- Mismatched to_addr (caller passed a different address than
  acct.email_address resolves to) → refuse + log; SMTP NOT
  called.
- Empty expected_to (account has no email_address) → refuse;
  SMTP NOT called.
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


@pytest.fixture
def acct_imap():
    return {
        "id": 42,
        "name": "test-acct",
        "user_id": 1,
        "provider_type": "imap",
        "config": {
            "host": "x.test", "port": 993, "username": "u@test",
        },
        "email_address": "u@test",
        "is_active": True,
        "hipaa": False,
    }


@pytest.fixture
def dcfg_custom():
    from email_triage.actions.digest_configs import (
        DigestConfig, DigestFormat,
    )
    return DigestConfig(
        id="digest_x", kind="custom", name="x",
        enabled=True,
        format=DigestFormat(render_as="grouped_list"),
    )


class _FakeSmtp:
    host = "smtp.test"
    port = 587
    username = "smtp_user"
    from_addr = "noreply@test"
    from_name = "Triage"
    use_tls = True


@pytest.mark.asyncio
async def test_send_proceeds_when_to_addr_matches(
    acct_imap, dcfg_custom,
):
    """to_addr == acct.email_address → render+send pipeline runs."""
    from email_triage.web.app import _fire_one_digest

    # send_recipient_digest is sync; the production sender wraps
    # it in asyncio.to_thread. MagicMock (NOT AsyncMock) reflects
    # the sync signature.
    sent = MagicMock(return_value=None)
    rows_returned = [{
        "category": "newsletter", "sender": "x@y", "subject": "s",
        "date": "2026-05-05T08:00:00+00:00",
        "labels": [], "actions": [], "attachments": [], "headers": {},
        "source": "llm", "reason": "rrr",
    }]
    with patch(
        "email_triage.actions.recipient_digest.send_recipient_digest",
        sent,
    ), patch(
        "email_triage.actions.recipient_digest.gather_digest_rows",
        return_value=rows_returned,
    ):
        await _fire_one_digest(
            db=object(),
            secrets=type("S", (), {"get": lambda *a, **k: ""})(),
            smtp=_FakeSmtp(),
            acct=acct_imap, dcfg=dcfg_custom, hipaa=False,
            now_utc=datetime.now(timezone.utc),
            last_sent=None,
            to_addr="u@test",  # matches acct["email_address"]
        )
    sent.assert_called_once()


@pytest.mark.asyncio
async def test_send_refused_on_recipient_mismatch_standard_mode(
    acct_imap, dcfg_custom,
):
    """to_addr != acct.email_address → raise, no SMTP call.

    Refactored to raise (was return-silent) so the test-send route
    + scheduler can both surface the misroute. SMTP must NOT be
    called regardless of how the refusal is signalled.
    """
    from email_triage.web.app import _fire_one_digest

    sent = MagicMock(return_value=None)
    with patch(
        "email_triage.actions.recipient_digest.send_recipient_digest",
        sent,
    ), patch(
        "email_triage.actions.recipient_digest.gather_digest_rows",
        return_value=[],
    ):
        with pytest.raises(RuntimeError, match="recipient mismatch"):
            await _fire_one_digest(
                db=object(),
                secrets=type("S", (), {"get": lambda *a, **k: ""})(),
                smtp=_FakeSmtp(),
                acct=acct_imap, dcfg=dcfg_custom, hipaa=False,
                now_utc=datetime.now(timezone.utc),
                last_sent=None,
                to_addr="attacker@elsewhere",
            )
    sent.assert_not_called()


@pytest.mark.asyncio
async def test_send_refused_on_recipient_mismatch_hipaa_mode(
    acct_imap, dcfg_custom,
):
    """Same refusal under HIPAA — the assertion fires regardless of
    flag, but the HIPAA path is the high-stakes guarantee."""
    from email_triage.web.app import _fire_one_digest

    sent = MagicMock(return_value=None)
    acct_imap["hipaa"] = True
    with patch(
        "email_triage.actions.recipient_digest.send_recipient_digest",
        sent,
    ):
        with pytest.raises(RuntimeError, match="recipient mismatch"):
            await _fire_one_digest(
                db=object(),
                secrets=type("S", (), {"get": lambda *a, **k: ""})(),
                smtp=_FakeSmtp(),
                acct=acct_imap, dcfg=dcfg_custom, hipaa=True,
                now_utc=datetime.now(timezone.utc),
                last_sent=None,
                to_addr="leak@elsewhere",
            )
    sent.assert_not_called()


@pytest.mark.asyncio
async def test_send_refused_when_account_has_no_email_address(
    acct_imap, dcfg_custom,
):
    """Empty expected_to (account row missing email_address) → also
    refuse. Otherwise a misconfigured account could fire a digest
    against an empty string, which most SMTP libraries handle in
    surprising ways."""
    from email_triage.web.app import _fire_one_digest

    sent = MagicMock(return_value=None)
    acct_imap["email_address"] = ""
    with patch(
        "email_triage.actions.recipient_digest.send_recipient_digest",
        sent,
    ):
        with pytest.raises(RuntimeError, match="recipient mismatch"):
            await _fire_one_digest(
                db=object(),
                secrets=type("S", (), {"get": lambda *a, **k: ""})(),
                smtp=_FakeSmtp(),
                acct=acct_imap, dcfg=dcfg_custom, hipaa=False,
                now_utc=datetime.now(timezone.utc),
                last_sent=None,
                to_addr="",
            )
    sent.assert_not_called()


@pytest.mark.asyncio
async def test_empty_window_returns_zero_no_send(
    acct_imap, dcfg_custom,
):
    """0 matching rows → return 0, no SMTP call. The test-send route
    branches on this to render an honest "nothing matched" message
    instead of falsely claiming "✓ Sent". """
    from email_triage.web.app import _fire_one_digest

    sent = MagicMock(return_value=None)
    with patch(
        "email_triage.actions.recipient_digest.send_recipient_digest",
        sent,
    ), patch(
        "email_triage.actions.recipient_digest.gather_digest_rows",
        return_value=[],  # empty window
    ):
        rv = await _fire_one_digest(
            db=object(),
            secrets=type("S", (), {"get": lambda *a, **k: ""})(),
            smtp=_FakeSmtp(),
            acct=acct_imap, dcfg=dcfg_custom, hipaa=False,
            now_utc=datetime.now(timezone.utc),
            last_sent=None,
            to_addr="u@test",
            is_test_send=True,  # skip mark_sent
        )
    assert rv == 0
    sent.assert_not_called()


# ---------------------------------------------------------------------------
# _filter_digest_candidates — cheap dry-run for the Show-matches button
# ---------------------------------------------------------------------------


def _row(category="newsletter", sender="x@y", subject="s",
         date="2026-05-07T08:00:00+00:00"):
    return {
        "category": category, "sender": sender, "subject": subject,
        "date": date, "labels": [], "actions": [],
        "attachments": [], "headers": {},
        "source": "llm", "reason": "rrr",
    }


def test_candidates_returns_filtered_rows(acct_imap, dcfg_custom):
    """Cheap path: gather rows + apply filter. Returns a list."""
    from email_triage.web.app import _filter_digest_candidates

    rows_in = [_row(subject=f"s{i}") for i in range(3)]
    with patch(
        "email_triage.actions.recipient_digest.gather_digest_rows",
        return_value=rows_in,
    ):
        rows_out = _filter_digest_candidates(
            db=object(), acct=acct_imap, dcfg=dcfg_custom,
            now_utc=datetime.now(timezone.utc), last_sent=None,
        )
    assert len(rows_out) == 3
    assert all(r["category"] == "newsletter" for r in rows_out)


def test_candidates_empty_window_returns_empty_list(
    acct_imap, dcfg_custom,
):
    """Empty gather → empty candidate list. UI renders the
    'no matching messages' muted message."""
    from email_triage.web.app import _filter_digest_candidates

    with patch(
        "email_triage.actions.recipient_digest.gather_digest_rows",
        return_value=[],
    ):
        rows_out = _filter_digest_candidates(
            db=object(), acct=acct_imap, dcfg=dcfg_custom,
            now_utc=datetime.now(timezone.utc), last_sent=None,
        )
    assert rows_out == []


# ---------------------------------------------------------------------------
# _render_digest_payload — render-without-send for the Preview button
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_render_payload_returns_tuple_for_grouped_list(
    acct_imap, dcfg_custom,
):
    """grouped_list → sync render path. Returns
    (subject, html_body, plain_body, rows). No SMTP, no LLM."""
    from email_triage.web.app import _render_digest_payload

    rows_in = [_row(subject="A"), _row(subject="B")]
    with patch(
        "email_triage.actions.recipient_digest.gather_digest_rows",
        return_value=rows_in,
    ):
        subject, html_body, plain_body, rows_out = (
            await _render_digest_payload(
                db=object(),
                secrets=type("S", (), {"get": lambda *a, **k: ""})(),
                acct=acct_imap, dcfg=dcfg_custom, hipaa=False,
                now_utc=datetime.now(timezone.utc),
                last_sent=None,
            )
        )
    # Custom digest → cadence-aware subject (not legacy preset).
    assert "Digest" in subject
    assert html_body  # rendered HTML
    assert plain_body  # plain fallback
    assert len(rows_out) == 2


@pytest.mark.asyncio
async def test_render_payload_empty_window_returns_blanks(
    acct_imap, dcfg_custom,
):
    """0 rows → all four return values blank/empty.

    Caller (_fire_one_digest, /preview, /candidates) branches on
    rows being empty to render a 'nothing matched' message."""
    from email_triage.web.app import _render_digest_payload

    with patch(
        "email_triage.actions.recipient_digest.gather_digest_rows",
        return_value=[],
    ):
        subject, html_body, plain_body, rows_out = (
            await _render_digest_payload(
                db=object(),
                secrets=type("S", (), {"get": lambda *a, **k: ""})(),
                acct=acct_imap, dcfg=dcfg_custom, hipaa=False,
                now_utc=datetime.now(timezone.utc),
                last_sent=None,
            )
        )
    assert subject == ""
    assert html_body == ""
    assert plain_body == ""
    assert rows_out == []
