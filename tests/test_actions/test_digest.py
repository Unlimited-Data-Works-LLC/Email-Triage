"""Tests for the newsletter digest generator."""

from _db_tracking import track
import json
from datetime import datetime, timezone

import pytest

from email_triage.actions.digest import (
    Article,
    DEFAULT_FORMAT_PROMPT,
    SenderGroup,
    _extract_sender_name,
    _parse_json_array,
    build_digest_html,
    extract_articles,
    generate_digest,
)
from email_triage.engine.models import EmailMessage


def _make_message(
    sender="Techpresso <news@techpresso.com>",
    subject="Daily Tech News",
    body="Article 1: AI breakthrough. Article 2: New chip released.",
    uid="100",
    links=None,
) -> EmailMessage:
    if links is None:
        links = [
            ("AI Breakthrough", "https://example.com/ai"),
            ("New Chip", "https://example.com/chip"),
        ]
    return EmailMessage(
        message_id=uid,
        provider="imap",
        sender=sender,
        recipients=["user@test.com"],
        subject=subject,
        body_text=body,
        date=datetime.now(timezone.utc),
        links=links,
    )


class TestSenderNameExtraction:
    def test_display_name(self):
        assert _extract_sender_name("Techpresso <news@techpresso.com>") == "Techpresso"

    def test_quoted_name(self):
        assert _extract_sender_name('"The Morning Brew" <team@morningbrew.com>') == "The Morning Brew"

    def test_email_only_generic_local(self):
        # Generic local part → use domain name.
        assert _extract_sender_name("newsletter@techcrunch.com") == "Techcrunch"

    def test_email_only_specific_local(self):
        assert _extract_sender_name("ben.thompson@stratechery.com") == "Ben Thompson"

    def test_noreply(self):
        assert _extract_sender_name("noreply@substack.com") == "Substack"

    def test_plain_string(self):
        assert _extract_sender_name("Some Sender") == "Some Sender"


class TestParseJsonArray:
    def test_simple_array(self):
        result = _parse_json_array('[{"headline": "Test", "summary": "Desc"}]')
        assert len(result) == 1
        assert result[0]["headline"] == "Test"

    def test_with_code_fences(self):
        text = '```json\n[{"headline": "Test", "summary": "Desc"}]\n```'
        result = _parse_json_array(text)
        assert len(result) == 1

    def test_single_object(self):
        result = _parse_json_array('{"headline": "Test", "summary": "Desc"}')
        assert len(result) == 1

    def test_empty_array(self):
        assert _parse_json_array("[]") == []

    def test_no_json(self):
        assert _parse_json_array("no json here") == []


class TestExtractArticles:
    @pytest.mark.asyncio
    async def test_successful_extraction(self):
        """Mock classifier returns valid JSON articles."""
        from unittest.mock import AsyncMock

        classifier = AsyncMock()
        classifier.complete.return_value = json.dumps([
            {"headline": "AI Breakthrough", "summary": "Major advance in LLMs.", "url": "https://example.com/ai"},
            {"headline": "New Chip", "summary": "Intel releases new chip.", "url": None},
        ])

        msg = _make_message()
        articles = await extract_articles(classifier, msg)

        assert len(articles) == 2
        assert articles[0].headline == "AI Breakthrough"
        assert articles[0].url == "https://example.com/ai"
        assert articles[1].headline == "New Chip"
        assert articles[1].url is None

    @pytest.mark.asyncio
    async def test_extraction_with_fences(self):
        """Classifier wraps JSON in markdown fences."""
        from unittest.mock import AsyncMock

        classifier = AsyncMock()
        classifier.complete.return_value = (
            '```json\n[{"headline": "Test", "summary": "A test.", "url": null}]\n```'
        )

        msg = _make_message()
        articles = await extract_articles(classifier, msg)
        assert len(articles) == 1
        assert articles[0].headline == "Test"

    @pytest.mark.asyncio
    async def test_extraction_failure_fallback(self):
        """On failure, falls back to treating email as one article."""
        from unittest.mock import AsyncMock

        classifier = AsyncMock()
        classifier.complete.side_effect = RuntimeError("LLM down")

        msg = _make_message(subject="Newsletter", body="Some content here.")
        articles = await extract_articles(classifier, msg)

        assert len(articles) == 1
        assert articles[0].headline == "Newsletter"
        assert "Some content" in articles[0].summary

    @pytest.mark.asyncio
    async def test_extraction_empty_array(self):
        """Classifier returns empty array."""
        from unittest.mock import AsyncMock

        classifier = AsyncMock()
        classifier.complete.return_value = "[]"

        msg = _make_message()
        articles = await extract_articles(classifier, msg)
        assert articles == []

    @pytest.mark.asyncio
    async def test_url_constrained_to_known_links(self):
        """LLM-returned URL not in the message's links set is dropped."""
        import json
        from unittest.mock import AsyncMock

        classifier = AsyncMock()
        classifier.complete.return_value = json.dumps([
            {"headline": "Fake", "summary": "x",
             "url": "https://evil.com/hallucinated"},
        ])
        msg = _make_message(
            links=[("Real Link", "https://real.com/a")],
        )
        articles = await extract_articles(classifier, msg)
        assert len(articles) == 1
        assert articles[0].url is None  # hallucinated URL dropped

    @pytest.mark.asyncio
    async def test_hipaa_msg_skips_external_classifier(self):
        """HIPAA-flagged msg + non-local classifier -> subject-only fallback,
        classifier.complete never called."""
        from unittest.mock import AsyncMock

        classifier = AsyncMock()
        classifier.is_local = False
        classifier.complete = AsyncMock()

        msg = _make_message(subject="PHI Subject")
        msg.hipaa = True
        articles = await extract_articles(classifier, msg)

        assert len(articles) == 1
        assert articles[0].headline == "PHI Subject"
        assert articles[0].url is None
        classifier.complete.assert_not_called()

    @pytest.mark.asyncio
    async def test_hipaa_msg_allowed_on_local_classifier(self):
        """HIPAA-flagged msg + local classifier -> normal extraction runs."""
        import json
        from unittest.mock import AsyncMock

        classifier = AsyncMock()
        classifier.is_local = True
        classifier.complete.return_value = json.dumps([
            {"headline": "H", "summary": "S", "url": None},
        ])
        msg = _make_message()
        msg.hipaa = True
        articles = await extract_articles(classifier, msg)
        classifier.complete.assert_called_once()
        assert articles[0].headline == "H"


class TestBuildDigestHtml:
    def test_basic_digest(self):
        groups = {
            "news@techpresso.com": SenderGroup(
                sender_name="Techpresso",
                sender_email="news@techpresso.com",
                articles=[
                    Article("AI Update", "Big news in AI.", "https://example.com/ai"),
                    Article("Chip News", "New chip released.", None),
                ],
            ),
        }
        html = build_digest_html(groups, "Tuesday, April 15, 2026")

        # Minimal template — intro line + bold group name + <ul>.
        # Big <h2>Newsletter Digest</h2> header is gone.
        assert "Here is your daily digest" in html
        assert "newsletters" in html
        assert "<strong>Techpresso</strong>" in html
        assert "AI Update" in html
        assert "Chip News" in html
        assert "https://example.com/ai" in html
        assert "Read more" in html

    def test_multiple_senders(self):
        groups = {
            "a@test.com": SenderGroup(
                sender_name="Alpha",
                sender_email="a@test.com",
                articles=[Article("Art1", "Sum1", None)],
            ),
            "b@test.com": SenderGroup(
                sender_name="Beta",
                sender_email="b@test.com",
                articles=[Article("Art2", "Sum2", None)],
            ),
        }
        html = build_digest_html(groups, "Today")
        assert "<strong>Alpha</strong>" in html
        assert "<strong>Beta</strong>" in html

    def test_empty_groups(self):
        html = build_digest_html({}, "Today")
        assert "No newsletters found" in html

    def test_html_escaping(self):
        groups = {
            "x@test.com": SenderGroup(
                sender_name="Test <Script>",
                sender_email="x@test.com",
                articles=[Article("Headline & More", "Summary <b>bold</b>", None)],
            ),
        }
        html = build_digest_html(groups, "Today")
        assert "&lt;Script&gt;" in html
        assert "&amp; More" in html
        assert "&lt;b&gt;" in html


class TestGenerateDigest:
    @pytest.mark.asyncio
    async def test_generate_basic(self):
        from unittest.mock import AsyncMock

        classifier = AsyncMock()
        classifier.complete.return_value = json.dumps([
            {"headline": "Article 1", "summary": "Summary 1.", "url": "https://ex.com/1"},
        ])

        provider = AsyncMock()
        messages = [_make_message(), _make_message(sender="Other <other@test.com>", uid="101")]

        html, article_count, source_count = await generate_digest(
            provider, classifier, messages,
        )

        assert article_count == 2  # 1 per message.
        assert source_count == 2
        assert "Article 1" in html
        assert "Here is your daily digest" in html

    @pytest.mark.asyncio
    async def test_generate_with_delete(self):
        from unittest.mock import AsyncMock

        classifier = AsyncMock()
        classifier.complete.return_value = json.dumps([
            {"headline": "X", "summary": "Y", "url": None},
        ])

        provider = AsyncMock()
        messages = [_make_message()]

        await generate_digest(provider, classifier, messages, delete_originals=True)

        provider.archive.assert_called_once_with("100")

    @pytest.mark.asyncio
    async def test_generate_empty_messages(self):

        from unittest.mock import AsyncMock

        classifier = AsyncMock()
        provider = AsyncMock()

        html, article_count, source_count = await generate_digest(
            provider, classifier, [],
        )

        assert article_count == 0
        assert "No newsletters found" in html


class TestDefaultFormatPrompt:
    def test_default_prompt_exists(self):
        assert "Group articles" in DEFAULT_FORMAT_PROMPT
        assert "sender" in DEFAULT_FORMAT_PROMPT
        assert "Read more" in DEFAULT_FORMAT_PROMPT


# ---------------------------------------------------------------------------
# Signature ( scope correction — signature lives on newsletter digest,
# not on the daily admin health email).
# ---------------------------------------------------------------------------

class TestDigestSignature:
    def _groups_with_one_article(self) -> dict:
        from email_triage.actions.digest import SenderGroup, Article
        return {
            "news@techpresso.com": SenderGroup(
                sender_name="Techpresso",
                sender_email="news@techpresso.com",
                articles=[Article(headline="AI news", summary="Stuff happened.")],
            ),
        }

    def test_digest_renders_default_signature_with_category_substituted(self):
        from email_triage.config import TriageConfig
        from email_triage.actions.digest import (
            build_digest_html, build_digest_text, render_signature,
        )
        cfg = TriageConfig()
        signature = render_signature(
            cfg.summary_email.signature, category="Tech",
        )
        assert signature == "Sent by your email-triage Tech Digest 🗞️"

        html_out = build_digest_html(
            self._groups_with_one_article(), "Monday, April 22, 2026",
            signature=signature,
        )
        text_out = build_digest_text(
            self._groups_with_one_article(), "Monday, April 22, 2026",
            signature=signature,
        )
        assert "Sent by your email-triage Tech Digest" in html_out
        assert "Sent by your email-triage Tech Digest" in text_out

    def test_digest_signature_respects_config_override(self):
        from email_triage.actions.digest import (
            build_digest_html, render_signature,
        )
        override = "— curated by {category} bot"
        rendered = render_signature(override, category="Newsletters")
        html_out = build_digest_html(
            self._groups_with_one_article(), "today", signature=rendered,
        )
        assert "curated by Newsletters bot" in html_out

    def test_digest_signature_category_placeholder_tolerant_of_missing_values(self):
        from email_triage.actions.digest import render_signature
        # Reserved-for-later placeholders must pass through unchanged.
        out = render_signature(
            "{category} · {account} · {date} · {unknown}",
            category="Tech",
        )
        assert out == "Tech ·  ·  · {unknown}"

    def test_digest_signature_appears_in_both_html_and_text(self):
        from email_triage.actions.digest import (
            build_digest_html, build_digest_text,
        )
        sig = "Sent by your email-triage Newsletters Digest"
        groups = self._groups_with_one_article()
        html_out = build_digest_html(groups, "today", signature=sig)
        text_out = build_digest_text(groups, "today", signature=sig)
        assert sig in html_out
        assert sig in text_out
        # Text version uses the standard sig-separator convention.
        assert "--" in text_out

    def test_digest_signature_absent_when_template_blank(self):
        from email_triage.actions.digest import (
            build_digest_html, build_digest_text,
        )
        groups = self._groups_with_one_article()
        html_out = build_digest_html(groups, "today", signature="")
        text_out = build_digest_text(groups, "today", signature="")
        assert "email-triage" not in html_out
        assert "email-triage" not in text_out

    @pytest.mark.asyncio
    async def test_generate_digest_applies_signature_template(self):
        from unittest.mock import AsyncMock

        classifier = AsyncMock()
        classifier.complete.return_value = json.dumps([
            {"headline": "H", "summary": "S", "url": None},
        ])
        provider = AsyncMock()

        msg = _make_message()
        html_out, articles, sources = await generate_digest(
            provider, classifier, [msg], delete_originals=False,
            signature_template="Sent by your email-triage {category} Digest",
            category="Tech",
        )
        assert articles == 1
        assert "Sent by your email-triage Tech Digest" in html_out

    def test_digest_name_surfaces_in_compact_template(self):
        """Operator-typed DigestConfig.name renders at the top of
        the compact / default newsletter template so the recipient
        knows which digest sent the email when an account has
        multiple custom digests against different filters."""
        from email_triage.actions.digest import build_digest_html
        groups = self._groups_with_one_article()
        html_out = build_digest_html(
            groups, "today", signature="",
            digest_name="AI Newsletters",
        )
        assert "AI Newsletters" in html_out

    def test_digest_name_blank_omits_heading_compact(self):
        """No name → no h2 prefix (back-compat for callers that
        don't thread digest_name)."""
        from email_triage.actions.digest import build_digest_html
        groups = self._groups_with_one_article()
        html_out = build_digest_html(
            groups, "today", signature="", digest_name="",
        )
        # default DEFAULT_DIGEST_TEMPLATE only renders the h2 when
        # digest_name is truthy
        assert "<h2" not in html_out

    @pytest.mark.asyncio
    async def test_generate_digest_without_signature_template(self):
        from unittest.mock import AsyncMock

        classifier = AsyncMock()
        classifier.complete.return_value = json.dumps([
            {"headline": "H", "summary": "S", "url": None},
        ])
        provider = AsyncMock()

        msg = _make_message()
        html_out, _, _ = await generate_digest(
            provider, classifier, [msg], delete_originals=False,
        )
        assert "Sent by your email-triage" not in html_out


# ---------------------------------------------------------------------------
# H-06 (Cycle 6, 2026-05-23) — digest archive-failure state-divergence
# visibility per §164.308(a)(7) Contingency Plan. When delete_originals=True
# and an archive call fails on a HIPAA-flagged message, the install ends up
# with PHI in BOTH the digest recipient mailbox AND the source mailbox — a
# divergence that the existing log.warning alone leaves operator-invisible.
# Mirror precedent 4e1e138 and
# emit a hipaa_access_events row with operation='digest_archive_failed' so
# the divergence count surfaces in daily-health beyond the buried log.
# ---------------------------------------------------------------------------


def _make_hipaa_message(uid: str = "h100") -> EmailMessage:
    """Variant of _make_message with hipaa=True for the H-06 tests."""
    m = _make_message(uid=uid)
    m.hipaa = True
    return m


class TestH06DigestArchiveFailureAudit:
    """H-06 — divergence-visibility audit row on HIPAA archive failure."""

    @pytest.fixture
    def db_and_account(self):
        """Fresh in-memory DB with v26+ schema + one HIPAA account.

        Returns (conn, account_id) — sqlite3.Connection cannot carry
        ad-hoc attributes, so the tuple is the simplest way to thread
        the seeded account id into each test.
        """
        from email_triage.web.db import init_db, create_email_account
        from datetime import datetime, timezone
        conn = track(init_db(":memory:"))
        # Seed a user (FK target; account_id needs a real owner).
        now = datetime.now(timezone.utc).isoformat()
        cur = conn.execute(
            "INSERT INTO users (email, name, role, created_at) "
            "VALUES (?, ?, ?, ?)",
            ("admin@example.com", "Admin", "admin", now),
        )
        conn.commit()
        user_id = int(cur.lastrowid)
        account_id = create_email_account(
            conn, user_id, "Clinic", "imap", {}, hipaa=True,
        )
        return conn, account_id

    @pytest.mark.asyncio
    async def test_happy_path_no_audit_row(self, db_and_account):
        """Archive succeeds → no divergence row emitted (consistency =
        absence of evidence is the operator-facing signal).
        """
        from unittest.mock import AsyncMock

        db, account_id = db_and_account
        classifier = AsyncMock()
        classifier.complete.return_value = json.dumps([
            {"headline": "X", "summary": "Y", "url": None},
        ])
        provider = AsyncMock()  # archive() succeeds by default

        await generate_digest(
            provider, classifier,
            [_make_hipaa_message()],
            delete_originals=True,
            account_id=account_id,
            db_conn=db,
        )

        rows = db.execute(
            "SELECT COUNT(*) AS c FROM hipaa_access_events "
            "WHERE operation = 'digest_archive_failed'"
        ).fetchone()
        assert rows["c"] == 0

    @pytest.mark.asyncio
    async def test_archive_failure_on_hipaa_emits_audit_row(
        self, db_and_account,
    ):
        """Archive fails on a HIPAA-flagged source → exactly one
        ``hipaa_access_events`` row with operation='digest_archive_failed'
        and the uid embedded in the detail field for operator
        correlation. This is the H-06 §164.308(a)(7) divergence-
        visibility surface.
        """
        from unittest.mock import AsyncMock

        db, account_id = db_and_account
        classifier = AsyncMock()
        classifier.complete.return_value = json.dumps([
            {"headline": "X", "summary": "Y", "url": None},
        ])
        provider = AsyncMock()
        provider.archive.side_effect = RuntimeError("IMAP move refused")

        await generate_digest(
            provider, classifier,
            [_make_hipaa_message(uid="phi-uid-42")],
            delete_originals=True,
            account_id=account_id,
            db_conn=db,
        )

        rows = db.execute(
            "SELECT account_id, operation, outcome, detail, "
            "       actor_user_id "
            "FROM hipaa_access_events "
            "WHERE operation = 'digest_archive_failed'"
        ).fetchall()
        assert len(rows) == 1
        row = rows[0]
        assert row["account_id"] == account_id
        assert row["outcome"] == "error"
        assert "phi-uid-42" in (row["detail"] or "")
        assert "IMAP move refused" in (row["detail"] or "")
        # System-initiated digest send — no human actor.
        assert row["actor_user_id"] is None

    @pytest.mark.asyncio
    async def test_archive_failure_on_non_hipaa_emits_no_row(
        self, db_and_account,
    ):
        """Gate must be ON HIPAA — non-HIPAA archive failures are
        operational concerns (logged) but NOT §164.308(a)(7)
        Contingency-Plan-scope. No audit row.
        """
        from unittest.mock import AsyncMock

        db, account_id = db_and_account
        classifier = AsyncMock()
        classifier.complete.return_value = json.dumps([
            {"headline": "X", "summary": "Y", "url": None},
        ])
        provider = AsyncMock()
        provider.archive.side_effect = RuntimeError("IMAP move refused")

        # Non-HIPAA message (hipaa=False default).
        await generate_digest(
            provider, classifier,
            [_make_message(uid="ordinary")],
            delete_originals=True,
            account_id=account_id,
            db_conn=db,
        )

        rows = db.execute(
            "SELECT COUNT(*) AS c FROM hipaa_access_events "
            "WHERE operation = 'digest_archive_failed'"
        ).fetchone()
        assert rows["c"] == 0

    @pytest.mark.asyncio
    async def test_archive_failure_without_db_context_is_log_only(
        self, db_and_account,
    ):
        """Caller didn't thread account_id / db_conn (e.g. direct
        unit-test call, or a future caller outside the sender path):
        the audit row is silently skipped, the log.warning still
        fires. Production caller (``app._fire_one_digest``) always
        threads both; this gate keeps the public API safe for
        legacy callers.
        """
        from unittest.mock import AsyncMock

        db, _account_id = db_and_account
        classifier = AsyncMock()
        classifier.complete.return_value = json.dumps([
            {"headline": "X", "summary": "Y", "url": None},
        ])
        provider = AsyncMock()
        provider.archive.side_effect = RuntimeError("IMAP move refused")

        # Neither account_id nor db_conn passed — legacy signature.
        await generate_digest(
            provider, classifier,
            [_make_hipaa_message()],
            delete_originals=True,
        )

        rows = db.execute(
            "SELECT COUNT(*) AS c FROM hipaa_access_events "
            "WHERE operation = 'digest_archive_failed'"
        ).fetchone()
        assert rows["c"] == 0

    @pytest.mark.asyncio
    async def test_partial_failure_audits_only_failed_uids(
        self, db_and_account,
    ):
        """Mixed loop: one archive succeeds, one fails. Exactly one
        audit row, on the failing uid only. Per-uid divergence
        granularity matters for operator forensics — "which messages
        are diverged?" must be answerable from the audit trail.
        """
        from unittest.mock import AsyncMock

        db, account_id = db_and_account
        classifier = AsyncMock()
        classifier.complete.return_value = json.dumps([
            {"headline": "X", "summary": "Y", "url": None},
        ])
        provider = AsyncMock()

        # First succeeds, second raises.
        async def _archive(message_id):
            if message_id == "ok-uid":
                return None
            raise RuntimeError("provider error")

        provider.archive.side_effect = _archive

        await generate_digest(
            provider, classifier,
            [
                _make_hipaa_message(uid="ok-uid"),
                _make_hipaa_message(uid="bad-uid"),
            ],
            delete_originals=True,
            account_id=account_id,
            db_conn=db,
        )

        rows = db.execute(
            "SELECT detail FROM hipaa_access_events "
            "WHERE operation = 'digest_archive_failed'"
        ).fetchall()
        assert len(rows) == 1
        assert "bad-uid" in (rows[0]["detail"] or "")
        assert "ok-uid" not in (rows[0]["detail"] or "")

    @pytest.mark.asyncio
    async def test_detail_field_carries_no_phi(self, db_and_account):
        """The ``detail`` field carries provider error + uid — never
        message body, sender, or subject. Belt-and-braces verification
        that even when the source message has PHI in subject/body, the
        audit row's detail field stays PHI-free.
        """
        from unittest.mock import AsyncMock

        db, account_id = db_and_account
        classifier = AsyncMock()
        classifier.complete.return_value = json.dumps([
            {"headline": "X", "summary": "Y", "url": None},
        ])
        provider = AsyncMock()
        provider.archive.side_effect = RuntimeError("provider err")

        msg = _make_hipaa_message(uid="m-99")
        msg.subject = "Patient SSN 123-45-6789 results"
        msg.body_text = "PHI-bearing body content"
        msg.sender = "Dr. Smith <smith@clinic.example>"

        await generate_digest(
            provider, classifier, [msg],
            delete_originals=True,
            account_id=account_id,
            db_conn=db,
        )

        rows = db.execute(
            "SELECT detail FROM hipaa_access_events "
            "WHERE operation = 'digest_archive_failed'"
        ).fetchall()
        assert len(rows) == 1
        detail = rows[0]["detail"] or ""
        # The uid + the error class are expected — nothing else.
        assert "m-99" in detail
        assert "provider err" in detail
        # PHI MUST NOT leak into the audit-row detail field.
        assert "SSN" not in detail
        assert "123-45-6789" not in detail
        assert "PHI-bearing" not in detail
        assert "Dr. Smith" not in detail
        assert "smith@clinic" not in detail


class TestBuildDigestHtmlUsDatetimeFilter:
    """Regression: `build_digest_html` renders operator html_template
    using `{{ ... | us_datetime }}` without TemplateRuntimeError.

    Pre-fix (2026-07-15): `Environment(autoescape=...)` was constructed
    without calling `_us_datetime.install_filter(env)`, so an operator
    template referencing the filter raised at render time. See
    `tests/test_us_datetime_install_filter_ssot_pin.py` for the
    interprocedural pin (scope: FileSystemLoader-Env); this test
    covers the bare-Env twin at `actions/digest.py:501`.
    """

    def test_operator_template_may_use_us_datetime_filter(self):
        groups = {
            "boss@example.com": SenderGroup(
                sender_email="boss@example.com",
                sender_name="Boss",
                articles=[
                    Article(
                        headline="Q4 numbers",
                        summary="Quarterly figures inside.",
                        url="https://example.com/q4",
                    ),
                ],
            ),
        }
        # Operator-supplied template with the us_datetime filter.
        # Pre-fix: raises `TemplateRuntimeError: No filter named 'us_datetime' found`.
        html_template = (
            "<h1>{{ digest_name }}</h1>"
            "<p>Rendered at: {{ date_str | us_datetime }}</p>"
            "{% for group in groups %}<p>{{ group.sender_name }}</p>{% endfor %}"
        )
        html = build_digest_html(
            groups,
            "2026-07-15T14:30:00+00:00",
            html_template=html_template,
            digest_name="Test Digest",
        )
        # Filter accepts ISO string; renders US-locale form (e.g.
        # "7/15/2026 …"). We don't pin exact string — timezone-aware —
        # but we do assert:
        assert "Rendered at:" in html
        assert "7/15/2026" in html  # US m/d/y locale evidence
        assert "Test Digest" in html
        assert "Boss" in html

    def test_operator_template_may_use_us_datetime_filter_on_ts_shape(self):
        """Panel-folded (hipaa-sme GO-WITH-FIXES 2026-07-15): assert the
        filter also works on a `{{ ts | us_datetime }}` template shape,
        not just `{{ date_str | ... }}` — covers the surface class, not
        the single filter-name-in-context happenstance."""
        groups = {
            "boss@example.com": SenderGroup(
                sender_email="boss@example.com",
                sender_name="Boss",
                articles=[
                    Article(
                        headline="Q4 numbers",
                        summary="Quarterly figures inside.",
                        url=None,
                    ),
                ],
            ),
        }
        # `ts` isn't in the render context — the filter should still
        # register cleanly (StrictUndefined isn't used here so the
        # empty value renders as ''), the key assertion is NO
        # `TemplateRuntimeError: No filter named 'us_datetime' found`.
        html_template = (
            "<h1>{{ digest_name }}</h1>"
            "<p>ts: {{ ts | us_datetime }}</p>"
            "<p>date_str: {{ date_str | us_datetime }}</p>"
        )
        html = build_digest_html(
            groups,
            "2026-07-15T14:30:00+00:00",
            html_template=html_template,
            digest_name="Test Digest",
        )
        # Filter registration success = renders without exception.
        # Verify both shapes reached the render:
        assert "ts:" in html
        assert "date_str:" in html
        assert "7/15/2026" in html  # date_str filter output
