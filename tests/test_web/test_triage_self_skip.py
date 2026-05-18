"""Triage entry points enforce self-skip at SEARCH + FETCH stages (#117).

Three guarantees pinned here:

1. ``run_triage`` (inline) calls ``provider.search`` with the install's
   self-from baked into the query — Gmail / IMAP / Office365 specific
   rewrites verified.
2. The secondary in-fetch check (``is_self_origin``) fires when the
   X-Email-Triage header is missing but ``message.sender`` matches
   ``smtp.from_addr``. Defense in depth against header-stripping
   forwarders.
3. The skip row carries ``reason="self_origin"`` so the /logs UI can
   render "Skipped (loop prevention)" instead of an opaque generic
   skip status.

No real domains / addresses in fixtures — abstract typed placeholders
(``triage@install.test``).
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from email_triage.config import TriageConfig, SmtpConfig
from email_triage.engine.models import Classification, EmailMessage


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _msg(*, sender="alice@elsewhere.test", headers=None, mid="1") -> EmailMessage:
    return EmailMessage(
        message_id=mid,
        provider="fake",
        sender=sender,
        recipients=["watcher@watched.test"],
        subject="S",
        body_text="B",
        date=datetime.now(timezone.utc),
        headers=dict(headers or {}),
    )


class _RecordingProvider:
    """Fake provider that records the search query it was called with
    so the test can pin the exclusion clause."""

    name = "fake"

    def __init__(self, ids=None, message=None) -> None:
        self.search_queries: list[str] = []
        self.ids = ids or []
        self._msg = message
        self.fetched: list[str] = []

    async def search(self, query, limit, **_):
        self.search_queries.append(query)
        return list(self.ids)

    async def fetch_message(self, mid, **_):
        self.fetched.append(mid)
        return self._msg

    async def close(self):
        pass


class _NoOpClassifier:
    def __init__(self) -> None:
        self.called = 0

    async def classify(self, message, categories, hints):
        self.called += 1
        return Classification(
            category="unknown", confidence=0.5, reason="x",
        )


def _seed_categories(conn):
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "INSERT INTO categories (slug, description, created_at, updated_at) "
        "VALUES (?, ?, ?, ?)",
        ("unknown", "", now, now),
    )
    conn.commit()


def _build_config(self_from="triage@install.test") -> TriageConfig:
    cfg = TriageConfig()
    cfg.smtp = SmtpConfig(
        host="smtp.install.test", port=587,
        username="triage@install.test",
        from_addr=self_from,
    )
    return cfg


# ---------------------------------------------------------------------------
# Query-stage filter — every supported provider type
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_run_triage_rewrites_query_for_imap(monkeypatch, tmp_path):
    """IMAP provider: ``query`` argument gets a NOT FROM clause appended."""
    from email_triage.web.db import init_db
    from email_triage.web.triage_runner import run_triage
    import email_triage.web.routers.ui as ui_mod

    conn = init_db(str(tmp_path / "t.db"))
    _seed_categories(conn)

    provider = _RecordingProvider(ids=[])  # empty result — focus on query
    classifier = _NoOpClassifier()
    monkeypatch.setattr(
        ui_mod, "_create_provider_from_account",
        lambda acct, secrets: provider,
    )
    monkeypatch.setattr(
        ui_mod, "_build_classifier_from_config",
        lambda cfg: classifier,
    )

    acct = {
        "id": 1, "name": "test", "user_id": None,
        "provider_type": "imap", "config": {"username": "user@watched.test"},
    }
    config = _build_config()

    await run_triage(
        conn, config, None, acct, query="UNSEEN", limit=10, trigger="t",
    )

    assert provider.search_queries
    q = provider.search_queries[0]
    assert "UNSEEN" in q
    assert 'NOT FROM "triage@install.test"' in q


@pytest.mark.asyncio
async def test_run_triage_rewrites_query_for_gmail(monkeypatch, tmp_path):
    from email_triage.web.db import init_db
    from email_triage.web.triage_runner import run_triage
    import email_triage.web.routers.ui as ui_mod

    conn = init_db(str(tmp_path / "t.db"))
    _seed_categories(conn)

    provider = _RecordingProvider(ids=[])
    classifier = _NoOpClassifier()
    monkeypatch.setattr(
        ui_mod, "_create_provider_from_account",
        lambda acct, secrets: provider,
    )
    monkeypatch.setattr(
        ui_mod, "_build_classifier_from_config",
        lambda cfg: classifier,
    )

    acct = {
        "id": 1, "name": "test", "user_id": None,
        "provider_type": "gmail_api", "config": {"account": "user@gmail.test"},
    }
    config = _build_config()

    await run_triage(
        conn, config, None, acct, query="is:unread",
        limit=10, trigger="t",
    )

    assert provider.search_queries
    q = provider.search_queries[0]
    assert "is:unread" in q
    assert "-from:triage@install.test" in q


@pytest.mark.asyncio
async def test_run_triage_rewrites_query_for_office365(monkeypatch, tmp_path):
    from email_triage.web.db import init_db
    from email_triage.web.triage_runner import run_triage
    import email_triage.web.routers.ui as ui_mod

    conn = init_db(str(tmp_path / "t.db"))
    _seed_categories(conn)

    provider = _RecordingProvider(ids=[])
    classifier = _NoOpClassifier()
    monkeypatch.setattr(
        ui_mod, "_create_provider_from_account",
        lambda acct, secrets: provider,
    )
    monkeypatch.setattr(
        ui_mod, "_build_classifier_from_config",
        lambda cfg: classifier,
    )

    acct = {
        "id": 1, "name": "test", "user_id": None,
        "provider_type": "office365",
        "config": {"account": "user@watched.test"},
    }
    config = _build_config()

    await run_triage(
        conn, config, None, acct, query="isRead eq false",
        limit=10, trigger="t",
    )

    assert provider.search_queries
    q = provider.search_queries[0]
    assert "from/emailAddress/address ne 'triage@install.test'" in q


@pytest.mark.asyncio
async def test_run_triage_no_rewrite_when_self_from_unset(
    monkeypatch, tmp_path,
):
    """No install-wide self-from configured ⇒ query left intact."""
    from email_triage.web.db import init_db
    from email_triage.web.triage_runner import run_triage
    import email_triage.web.routers.ui as ui_mod

    conn = init_db(str(tmp_path / "t.db"))
    _seed_categories(conn)

    provider = _RecordingProvider(ids=[])
    classifier = _NoOpClassifier()
    monkeypatch.setattr(
        ui_mod, "_create_provider_from_account",
        lambda acct, secrets: provider,
    )
    monkeypatch.setattr(
        ui_mod, "_build_classifier_from_config",
        lambda cfg: classifier,
    )

    acct = {
        "id": 1, "name": "test", "user_id": None,
        "provider_type": "imap", "config": {"username": "user@watched.test"},
    }
    config = _build_config(self_from="")  # unset

    await run_triage(
        conn, config, None, acct, query="UNSEEN", limit=10, trigger="t",
    )

    assert provider.search_queries == ["UNSEEN"]


# ---------------------------------------------------------------------------
# Defense-in-depth — secondary check fires on missing header
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_run_triage_skips_when_sender_matches_smtp_from(
    monkeypatch, tmp_path,
):
    """No X-Email-Triage header (forwarder stripped it) but the
    sender matches the install's smtp.from_addr — the secondary
    is_self_origin check must fire and the run records a
    ``self_from_match`` skip with reason=self_origin."""
    from email_triage.web.db import init_db
    from email_triage.web.triage_runner import run_triage
    import email_triage.web.routers.ui as ui_mod

    conn = init_db(str(tmp_path / "t.db"))
    _seed_categories(conn)

    # Sender == self-from, but headers DO NOT include X-Email-Triage.
    msg = _msg(sender="triage@install.test", headers={"Subject": "Daily"})
    provider = _RecordingProvider(ids=["1"], message=msg)
    classifier = _NoOpClassifier()
    monkeypatch.setattr(
        ui_mod, "_create_provider_from_account",
        lambda acct, secrets: provider,
    )
    monkeypatch.setattr(
        ui_mod, "_build_classifier_from_config",
        lambda cfg: classifier,
    )

    acct = {
        "id": 1, "name": "test", "user_id": None,
        "provider_type": "imap", "config": {"username": "user@watched.test"},
    }
    config = _build_config()

    result = await run_triage(
        conn, config, None, acct, query="ALL", limit=10, trigger="t",
    )

    # Classifier never ran — secondary skip caught it.
    assert classifier.called == 0
    assert result["total_messages"] == 1
    entry = result["results"][0]
    assert entry["status"] == "skipped"
    assert entry["skip_reason"] == "self_from_match"
    assert entry["reason"] == "self_origin"


@pytest.mark.asyncio
async def test_run_triage_x_header_skip_records_reason_self_origin(
    monkeypatch, tmp_path,
):
    """Even when the X-Email-Triage header IS present, the run must
    record ``reason='self_origin'`` so the recipient-digest renderer
    + /logs UI can label the skip uniformly."""
    from email_triage.mail_headers import X_EMAIL_TRIAGE_HEADER
    from email_triage.web.db import init_db
    from email_triage.web.triage_runner import run_triage
    import email_triage.web.routers.ui as ui_mod

    conn = init_db(str(tmp_path / "t.db"))
    _seed_categories(conn)

    msg = _msg(
        sender="triage@install.test",
        headers={X_EMAIL_TRIAGE_HEADER: "digest; version=v; generated=g"},
    )
    provider = _RecordingProvider(ids=["1"], message=msg)
    classifier = _NoOpClassifier()
    monkeypatch.setattr(
        ui_mod, "_create_provider_from_account",
        lambda acct, secrets: provider,
    )
    monkeypatch.setattr(
        ui_mod, "_build_classifier_from_config",
        lambda cfg: classifier,
    )

    acct = {
        "id": 1, "name": "test", "user_id": None,
        "provider_type": "imap", "config": {"username": "user@watched.test"},
    }
    config = _build_config()

    result = await run_triage(
        conn, config, None, acct, query="ALL", limit=10, trigger="t",
    )

    entry = result["results"][0]
    assert entry["status"] == "skipped"
    assert entry["skip_reason"] == "x_email_triage_header"
    assert entry["reason"] == "self_origin"
