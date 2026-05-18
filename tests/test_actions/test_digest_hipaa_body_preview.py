"""HIPAA verification for digest body-preview rendering (#110).

Two render surfaces touch message body content:

1. Sync renderers in ``actions.digest_render`` (table /
   grouped_list / plain_list) — read body_text + body_html out of
   the row dict gathered from ``triage_runs.results_json``. The
   data layer happens not to persist body fields, so the row
   dict's body_* keys are empty by construction. Even so, both
   ``_preview`` and ``_cheap_preview`` carry an explicit HIPAA
   gate that returns ``"[redacted]"`` / empty for HIPAA-flagged
   accounts. We assert the gate fires when body fields ARE
   present (defending against a future schema change that adds
   body_text to the persisted row).

2. Async newsletter render (``digest.extract_articles`` via
   ``digest_render.render_newsletter_async``) — re-fetches
   each row's source message via the provider so the LLM
   article extractor has body_html. The HIPAA fail-closed gate
   on ``extract_articles`` checks ``message.hipaa`` — which is
   only true if the caller stamped the flag on the fetched
   message object. The per-digest send path (audit #110) was
   missing that stamp, leaving the gate dead. This module
   exercises the full ``_render_digest_payload`` path with a
   HIPAA-flagged account + a mocked provider returning a
   sentinel-string body, and asserts the sentinel never appears
   in the rendered HTML.

Compliance angle: HIPAA §164.502(a)(1) — digests are an
outbound disclosure of PHI to the operator's mailbox. Body
preview that bypasses HIPAA mode is a §164.502 issue even when
recipient = data subject (digest travels via SMTP + sits at
rest in the recipient's mailbox).
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import patch

import pytest


# Sentinel string the test asserts never appears in any rendered
# digest HTML / plain output. Long enough to be visually distinct
# in failure messages; not token-shaped so the static-grep guard
# in test_security_token_logging doesn't false-positive.
SENTINEL = "UNIQUE_BODY_SENTINEL_77"


# ---------------------------------------------------------------------------
# Sync renderer gate — exercise _cheap_preview / _preview directly
# ---------------------------------------------------------------------------


def test_cheap_preview_hipaa_redacts_lede_and_headings():
    """Direct unit on the renderer helper. body_text + body_html
    populated; HIPAA mode returns ``("[redacted]", [])`` instead
    of mining the lede + H1/H2."""
    from email_triage.actions.digest_render import _cheap_preview
    entry = {
        "body_text": f"{SENTINEL} Top stories this week.\nMore below.",
        "body_html": f"<h1>{SENTINEL}-headline</h1><p>filler</p>",
    }
    lede, headings = _cheap_preview(entry, hipaa=True)
    assert lede == "[redacted]"
    assert headings == []
    # Sanity: SENTINEL is in the input but redaction rejected it.
    assert SENTINEL not in lede
    assert all(SENTINEL not in h for h in headings)


def test_legacy_preview_hipaa_redacts():
    """Same gate on the legacy preset preview helper."""
    from email_triage.actions.digest_render import _preview
    entry = {"body_text": f"{SENTINEL} verbatim message body"}
    out = _preview(entry, hipaa=True)
    assert out == "[redacted]"
    assert SENTINEL not in out


def test_grouped_list_hipaa_does_not_leak_body_sentinel():
    """End-to-end on the sync grouped_list path: even when a row
    DOES carry body_text + body_html (defending against a future
    schema that persists them), the rendered HTML must not
    contain the sentinel under HIPAA mode."""
    from email_triage.actions.digest_configs import DigestConfig, DigestFormat
    from email_triage.actions.digest_render import render_grouped_list

    cfg = DigestConfig(
        kind="custom",
        name="Test",
        format=DigestFormat(
            render_as="grouped_list", group_by="category",
            include_body_preview=True, max_rows=10,
        ),
    )
    rows = [{
        "category": "newsletter",
        "sender": "alice@example.com",
        "subject": "Update",
        "body_text": f"{SENTINEL} full message body that must not leak",
        "body_html": f"<h1>{SENTINEL}-headline</h1>",
        "reason": "n/a",
        "source": "llm",
        "date": "2026-05-08T08:00:00+00:00",
    }]
    out = render_grouped_list(
        cfg=cfg, rows=rows,
        account_name="acct", account_email="me@here",
        hipaa=True,
    )
    assert SENTINEL not in out, (
        "HIPAA digest rendered body content despite the redact "
        "gate — first 200 chars of body must not appear in "
        "rendered HTML."
    )
    # Sanity: the redacted-marker IS present.
    assert "[redacted]" in out


def test_table_render_hipaa_does_not_leak_body_sentinel():
    """Same guarantee on the table format (preview column)."""
    from email_triage.actions.digest_configs import (
        DigestColumn, DigestConfig, DigestFormat,
    )
    from email_triage.actions.digest_render import render_table_generic

    cfg = DigestConfig(
        kind="custom",
        name="Test",
        format=DigestFormat(
            render_as="table", include_body_preview=True, max_rows=10,
            columns=[
                DigestColumn(key="datetime", label="When"),
                DigestColumn(key="sender", label="Sender"),
                DigestColumn(key="subject", label="Subject"),
                DigestColumn(key="preview", label="Preview"),
            ],
        ),
    )
    rows = [{
        "category": "newsletter",
        "sender": "alice@example.com",
        "subject": "Update",
        "body_text": f"{SENTINEL} verbatim body that must not leak",
        "reason": "n/a",
        "source": "llm",
        "date": "2026-05-08T08:00:00+00:00",
    }]
    out = render_table_generic(
        cfg=cfg, rows=rows,
        account_name="acct", account_email="me@here",
        hipaa=True,
    )
    assert SENTINEL not in out
    assert "[redacted]" in out


# ---------------------------------------------------------------------------
# Async newsletter path — full _render_digest_payload integration
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_extract_articles_hipaa_skips_body_with_remote_classifier():
    """``extract_articles`` HIPAA fail-closed gate: when
    ``message.hipaa=True`` AND the classifier is non-local, the
    function must NOT call classifier.complete() and must return
    a subject-only article. The body sentinel must not appear in
    the returned article's summary or be passed to the LLM."""
    from email_triage.actions.digest import extract_articles
    from email_triage.engine.models import EmailMessage

    msg = EmailMessage(
        message_id="m1", provider="imap", sender="boss@hospital.org",
        recipients=["doctor@hospital.org"], subject="Patient update",
        body_text=f"{SENTINEL} patient X labs results enclosed",
        body_html=f"<p>{SENTINEL} PHI body content</p>",
        date=datetime.now(timezone.utc),
        links=[],
    )
    msg.hipaa = True

    class _RemoteClassifier:
        is_local = False
        async def complete(self, prompt):  # pragma: no cover
            raise AssertionError(
                "complete() must NOT be called for HIPAA + non-local"
            )

    articles = await extract_articles(_RemoteClassifier(), msg)
    assert len(articles) == 1
    assert SENTINEL not in articles[0].summary
    assert SENTINEL not in (articles[0].headline or "")
    # Affirmative content check: the placeholder stays factual.
    assert "HIPAA" in articles[0].summary


@pytest.mark.asyncio
async def test_extract_articles_fallback_hipaa_does_not_leak_body():
    """When the LLM call raises (parse error, network blip, etc.)
    AND the message is HIPAA-flagged, the fallback article must
    NOT include the first 200 chars of body_text. Defense in
    depth: the gate at the top of extract_articles only fires
    when the classifier is non-local; with a local classifier we
    proceed into the LLM call, and a parser failure used to drop
    body_text into the article summary regardless of HIPAA flag.
    Punch-list #110 (2026-05-08) closed that fallback hole."""
    from email_triage.actions.digest import extract_articles
    from email_triage.engine.models import EmailMessage

    msg = EmailMessage(
        message_id="m1", provider="imap", sender="boss@hospital.org",
        recipients=["doctor@hospital.org"], subject="Patient update",
        body_text=f"{SENTINEL} patient X labs results enclosed",
        body_html="",
        date=datetime.now(timezone.utc),
        links=[],
    )
    msg.hipaa = True

    class _LocalBuggyClassifier:
        is_local = True
        async def complete(self, prompt):
            # Simulate LLM-side / parser-side failure mid-extraction.
            raise RuntimeError("simulated parser failure")

    articles = await extract_articles(_LocalBuggyClassifier(), msg)
    assert len(articles) == 1
    assert SENTINEL not in articles[0].summary
    assert "HIPAA" in articles[0].summary


@pytest.mark.asyncio
async def test_render_digest_payload_stamps_hipaa_on_fetched_messages(
    monkeypatch,
):
    """End-to-end on the per-digest send path's newsletter branch:
    a HIPAA-flagged account dispatches through
    ``_render_digest_payload`` → fetched messages → newsletter
    render → ``extract_articles`` gate. The fix at audit #110 is
    that ``msg.hipaa = hipaa`` is stamped on every fetched
    message; without the stamp the gate is dead. This test
    verifies the stamp survives the ``provider.fetch_message``
    boundary by inspecting the ``messages`` list passed into the
    article extractor.
    """
    from email_triage.actions.digest_configs import (
        DigestConfig, DigestFilter, DigestFormat,
    )
    from email_triage.engine.models import EmailMessage
    from email_triage.web import app as app_mod

    captured_messages: list = []

    async def _fake_extract(classifier, message):
        # Every message reaching here must be HIPAA-stamped.
        captured_messages.append(message)
        from email_triage.actions.digest import Article
        return [Article(headline=message.subject, summary="ok", url=None)]

    class _FakeProvider:
        async def fetch_message(self, mid):
            return EmailMessage(
                message_id=mid, provider="imap",
                sender="boss@hospital.org",
                recipients=["doctor@hospital.org"],
                subject="Patient update",
                body_text=f"{SENTINEL} PHI body",
                body_html="",
                date=datetime.now(timezone.utc),
                links=[],
                # NB: provider returns hipaa=False by default; the
                # caller is responsible for stamping the per-account
                # hipaa flag onto the fetched message.
            )

        async def close(self):
            pass

    class _LocalClassifier:
        is_local = True

    # Patch the renderer dependencies used by _render_digest_payload.
    monkeypatch.setattr(
        "email_triage.actions.digest.extract_articles", _fake_extract,
    )
    monkeypatch.setattr(
        "email_triage.web.routers.ui._create_provider_from_account",
        lambda acct, secrets: _FakeProvider(),
    )
    monkeypatch.setattr(
        "email_triage.web.routers.ui._build_classifier_from_config",
        lambda cfg: _LocalClassifier(),
    )

    # The filter step reads a row out of triage_runs.results_json;
    # short-circuit it to return a single row referencing message_id "m1".
    def _fake_filter(*, db, acct, dcfg, now_utc, last_sent):
        return [{
            "message_id": "m1",
            "category": "newsletters",
            "sender": "boss@hospital.org",
            "subject": "Patient update",
            "source": "llm",
            "date": "2026-05-08T08:00:00+00:00",
        }]

    monkeypatch.setattr(app_mod, "_filter_digest_candidates", _fake_filter)

    dcfg = DigestConfig(
        id="d1", kind="custom", name="Newsletters",
        filter=DigestFilter(categories=["newsletters"]),
        format=DigestFormat(render_as="newsletter", max_rows=10),
    )

    # Minimal stub config carrying summary_email.signature attr.
    class _S:
        signature = ""

    class _Cfg:
        summary_email = _S()

    acct = {
        "id": 1, "name": "Hospital Inbox",
        "email_address": "doctor@hospital.org",
    }

    subject, html_body, plain_body, rows = await app_mod._render_digest_payload(
        db=None, secrets={}, acct=acct, dcfg=dcfg, hipaa=True,
        now_utc=datetime.now(timezone.utc), last_sent=None, config=_Cfg(),
    )

    # Affirmative: the fetch happened.
    assert len(captured_messages) == 1
    # Critical: the HIPAA flag was stamped onto the fetched message
    # before it reached the article extractor. Without the stamp
    # the extract_articles gate is dead — this assertion is the
    # punch-list #110 regression guard.
    assert captured_messages[0].hipaa is True
    # Sanity: nothing leaked the sentinel through the rendered
    # body. The stub extractor returned summary="ok" so the
    # rendered HTML is sentinel-free by construction; the test's
    # value is in the hipaa-stamp assertion above.
    assert SENTINEL not in html_body
    assert SENTINEL not in plain_body
