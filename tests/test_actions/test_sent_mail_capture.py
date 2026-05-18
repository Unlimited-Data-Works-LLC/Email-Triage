"""Tests for ``actions.sent_mail_capture`` (M-6 edit-feedback loop).

Scope: header parse → captured-pair indexing, HIPAA short-circuits at
every public method, idempotency over re-scans, captured-pair retrieval
ranking boost, audit-row write, background loop wiring (which accounts
opt in / out).

No real PII anywhere: actors are ``user@example.com`` / ``Operator A``,
embedding model is ``test-embedder-v0``, and sample bodies are synthetic
("Thanks!", "Sounds good", etc.). The base64 encoded draft body in
fixtures contains no real names or message content.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from typing import Any
from unittest.mock import AsyncMock

import pytest

from email_triage.actions.sent_mail_capture import SentMailCaptureLoop
from email_triage.actions.sent_mail_index import (
    _CAPTURED_PAIR_BOOST,
    SentMailIndex,
)
from email_triage.engine.models import EmailMessage
from email_triage.mail_headers import (
    X_EMAIL_TRIAGE_DRAFT_BODY_HEADER,
    X_EMAIL_TRIAGE_HEADER,
    decode_draft_body_header,
    encode_draft_body_header,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

EMBED_MODEL_FIXTURE = "test-embedder-v0"


def _make_db() -> sqlite3.Connection:
    """In-memory DB with email_accounts + sent_mail_index (v12 + v14)."""
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute("""
        CREATE TABLE email_accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            hipaa INTEGER NOT NULL DEFAULT 0,
            created_under_system_hipaa INTEGER NOT NULL DEFAULT 0
        )
    """)
    from email_triage.web.migrations import MIGRATIONS
    # Apply v12 (creates table) then v14 (adds is_captured_pair column).
    for v in (12, 14, 15):
        for m in MIGRATIONS:
            if m.version == v:
                m.body(conn)
                break
    conn.commit()
    return conn


def _seed_account(
    conn: sqlite3.Connection, *, name: str = "Operator A",
    hipaa: bool = False,
) -> int:
    cur = conn.execute(
        "INSERT INTO email_accounts (name, hipaa) VALUES (?, ?)",
        (name, int(bool(hipaa))),
    )
    conn.commit()
    return int(cur.lastrowid)


def _draft_msg(
    sent_body: str,
    draft_body: str,
    *,
    uid: str = "u1",
    rfc_id: str = "<m1@example.com>",
    subject: str = "Re: hello",
    hipaa: bool = False,
    include_draft_header: bool = True,
    include_triage_header: bool = True,
    triage_source: str = "draft-reply",
) -> EmailMessage:
    """Build an EmailMessage that looks like a sent edited AI-draft.

    ``sent_body`` is what the user actually sent (the body indexed
    in M-4); ``draft_body`` is the original AI-drafted body (encoded
    into the X-Email-Triage-Draft-Body header).
    """
    headers: dict[str, str] = {"Message-ID": rfc_id} if rfc_id else {}
    if include_triage_header:
        headers[X_EMAIL_TRIAGE_HEADER] = (
            f"{triage_source}; category=to-respond; account=Operator A"
        )
    if include_draft_header and draft_body:
        headers[X_EMAIL_TRIAGE_DRAFT_BODY_HEADER] = encode_draft_body_header(
            draft_body,
        )
    return EmailMessage(
        message_id=uid,
        provider="imap",
        sender="user@example.com",
        recipients=["other@example.com"],
        subject=subject,
        body_text=sent_body,
        date=datetime(2026, 5, 1, tzinfo=timezone.utc),
        headers=headers,
        hipaa=hipaa,
    )


class _FakeBackend:
    """Deterministic embedding backend; identical to the M-4 test fixture."""
    backend_type = "ollama"

    def __init__(self) -> None:
        self.calls: list[str] = []

    async def embed_text(self, text: str) -> list[float]:
        self.calls.append(text)
        vec = [0.0, 0.0, 0.0, 0.0]
        for ch in text.lower():
            vec[ord(ch) % 4] += 1.0
        return vec


def _make_index(conn: sqlite3.Connection, account_id: int) -> SentMailIndex:
    return SentMailIndex(
        conn, account_id,
        embedding_backend=_FakeBackend(),
        embedding_model=EMBED_MODEL_FIXTURE,
    )


# ---------------------------------------------------------------------------
# Migration v14
# ---------------------------------------------------------------------------

class TestMigrationV14:
    def test_v14_applies_cleanly(self):
        """v14 runs against a DB that already has v12's sent_mail_index."""
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        conn.execute("CREATE TABLE email_accounts (id INTEGER PRIMARY KEY)")
        from email_triage.web.migrations import MIGRATIONS
        v12 = next(m for m in MIGRATIONS if m.version == 12)
        v12.body(conn)
        v14 = next(m for m in MIGRATIONS if m.version == 14)
        v14.body(conn)
        cols = {row[1] for row in conn.execute(
            "PRAGMA table_info(sent_mail_index)"
        ).fetchall()}
        assert "is_captured_pair" in cols

    def test_v14_idempotent(self):
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        conn.execute("CREATE TABLE email_accounts (id INTEGER PRIMARY KEY)")
        from email_triage.web.migrations import MIGRATIONS
        for v in (12, 14, 15):
            m = next(mi for mi in MIGRATIONS if mi.version == v)
            m.body(conn)
        # Re-run v14 -- should NOT raise (already-present column).
        v14 = next(m for m in MIGRATIONS if m.version == 14)
        v14.body(conn)


# ---------------------------------------------------------------------------
# Header parse helpers
# ---------------------------------------------------------------------------

class TestHeaderHelpers:
    def test_encode_decode_roundtrip(self):
        body = "Thanks for the message. I'll take a look."
        encoded = encode_draft_body_header(body)
        # Should be safe ASCII (base64).
        assert encoded.isascii()
        assert "\n" not in encoded
        decoded = decode_draft_body_header(encoded)
        assert decoded == body

    def test_encode_empty_returns_empty(self):
        assert encode_draft_body_header("") == ""

    def test_decode_handles_none_and_empty(self):
        assert decode_draft_body_header(None) == ""
        assert decode_draft_body_header("") == ""

    def test_decode_tolerates_whitespace(self):
        body = "Sounds good"
        encoded = encode_draft_body_header(body)
        # Insert spaces + newlines as some MTAs would when folding.
        with_ws = encoded[:4] + " " + encoded[4:8] + "\n" + encoded[8:]
        assert decode_draft_body_header(with_ws) == body

    def test_decode_garbage_returns_empty(self):
        # Random characters that are not valid base64.
        assert decode_draft_body_header("@@@invalid@@@") == ""


# ---------------------------------------------------------------------------
# Captured-pair detection
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestCapturedPairDetection:
    async def test_full_pair_indexes_captured_row(self):
        conn = _make_db()
        acct_id = _seed_account(conn)
        idx = _make_index(conn, acct_id)
        loop = SentMailCaptureLoop(
            conn, acct_id, provider=None, sent_mail_index=idx,
        )
        msg = _draft_msg(
            sent_body="Thanks! I'll check it out.",
            draft_body="Thank you for your message. I will take a look.",
        )
        captured = await loop.index_captured_pair(msg)
        assert captured is True
        rows = conn.execute(
            "SELECT message_id, is_captured_pair FROM sent_mail_index "
            "WHERE account_id = ?",
            (acct_id,),
        ).fetchall()
        assert len(rows) == 1
        assert rows[0]["is_captured_pair"] == 1

    async def test_missing_draft_body_header_skipped(self):
        """Old messages without the M-6 draft-body header are skipped."""
        conn = _make_db()
        acct_id = _seed_account(conn)
        idx = _make_index(conn, acct_id)
        loop = SentMailCaptureLoop(
            conn, acct_id, provider=None, sent_mail_index=idx,
        )
        # Has X-Email-Triage but lacks X-Email-Triage-Draft-Body.
        msg = _draft_msg(
            sent_body="Thanks!",
            draft_body="",  # encoder returns empty -- header dropped
            include_draft_header=False,
        )
        captured = await loop.index_captured_pair(msg)
        assert captured is False
        n = conn.execute(
            "SELECT COUNT(*) FROM sent_mail_index"
        ).fetchone()[0]
        assert n == 0

    async def test_missing_triage_header_skipped(self):
        conn = _make_db()
        acct_id = _seed_account(conn)
        idx = _make_index(conn, acct_id)
        loop = SentMailCaptureLoop(
            conn, acct_id, provider=None, sent_mail_index=idx,
        )
        msg = _draft_msg(
            sent_body="anything",
            draft_body="anything else",
            include_triage_header=False,
        )
        captured = await loop.index_captured_pair(msg)
        assert captured is False

    async def test_non_draft_reply_source_skipped(self):
        """A digest / OTP message with X-Email-Triage but a different
        source field is NOT a captured pair."""
        conn = _make_db()
        acct_id = _seed_account(conn)
        idx = _make_index(conn, acct_id)
        loop = SentMailCaptureLoop(
            conn, acct_id, provider=None, sent_mail_index=idx,
        )
        msg = _draft_msg(
            sent_body="Daily digest body",
            draft_body="anything",
            triage_source="digest",
        )
        captured = await loop.index_captured_pair(msg)
        assert captured is False

    async def test_empty_sent_body_skipped(self):
        conn = _make_db()
        acct_id = _seed_account(conn)
        idx = _make_index(conn, acct_id)
        loop = SentMailCaptureLoop(
            conn, acct_id, provider=None, sent_mail_index=idx,
        )
        msg = _draft_msg(
            sent_body="   ",
            draft_body="something",
        )
        captured = await loop.index_captured_pair(msg)
        assert captured is False


# ---------------------------------------------------------------------------
# HIPAA short-circuits (defence in depth)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestHipaaGate:
    async def test_index_captured_pair_skips_hipaa_account(self):
        conn = _make_db()
        acct_id = _seed_account(conn, hipaa=True)
        idx = _make_index(conn, acct_id)
        loop = SentMailCaptureLoop(
            conn, acct_id, provider=None, sent_mail_index=idx,
        )
        msg = _draft_msg(
            sent_body="Thanks!",
            draft_body="Thank you",
        )
        captured = await loop.index_captured_pair(msg)
        assert captured is False
        n = conn.execute(
            "SELECT COUNT(*) FROM sent_mail_index"
        ).fetchone()[0]
        assert n == 0

    async def test_scan_recent_skips_hipaa_no_provider_call(self):
        """The HIPAA gate fires BEFORE provider.search."""
        conn = _make_db()
        acct_id = _seed_account(conn, hipaa=True)
        idx = _make_index(conn, acct_id)
        provider = AsyncMock()
        provider.search.side_effect = AssertionError(
            "provider.search must not be called on HIPAA accounts",
        )
        loop = SentMailCaptureLoop(
            conn, acct_id, provider=provider, sent_mail_index=idx,
        )
        n = await loop.scan_recent(limit=10)
        assert n == 0
        provider.search.assert_not_called()

    async def test_message_marked_hipaa_skipped(self):
        """Even on a non-HIPAA account, a message tagged hipaa=True at
        fetch time (e.g. system_hipaa was on at fetch) is skipped."""
        conn = _make_db()
        acct_id = _seed_account(conn, hipaa=False)
        idx = _make_index(conn, acct_id)
        loop = SentMailCaptureLoop(
            conn, acct_id, provider=None, sent_mail_index=idx,
        )
        msg = _draft_msg(
            sent_body="Thanks!",
            draft_body="Thank you",
            hipaa=True,
        )
        captured = await loop.index_captured_pair(msg)
        assert captured is False


# ---------------------------------------------------------------------------
# Idempotency over re-scans
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestIdempotency:
    async def test_rescan_does_not_double_index(self):
        """A second scan_recent over the same Sent-folder snapshot
        returns 0 new captured rows (dedup on (account_id, rfc_message_id)).
        """
        conn = _make_db()
        acct_id = _seed_account(conn)
        idx = _make_index(conn, acct_id)

        ids = ["u1", "u2"]
        msgs = {
            "u1": _draft_msg(
                "Thanks!", "Thank you for your message",
                uid="u1", rfc_id="<a@example.com>",
            ),
            "u2": _draft_msg(
                "Sounds good", "That sounds wonderful",
                uid="u2", rfc_id="<b@example.com>",
            ),
        }

        class _StubProvider:
            async def search(self, query, limit):
                return list(ids)

            async def fetch_message(self, mid, **_kw):
                return msgs[mid]

        loop = SentMailCaptureLoop(
            conn, acct_id, provider=_StubProvider(),
            sent_mail_index=idx,
        )
        first = await loop.scan_recent(limit=10)
        assert first == 2
        # Second pass: zero new rows.
        second = await loop.scan_recent(limit=10)
        assert second == 0
        n = conn.execute(
            "SELECT COUNT(*) FROM sent_mail_index "
            "WHERE account_id = ? AND is_captured_pair = 1",
            (acct_id,),
        ).fetchone()[0]
        assert n == 2


# ---------------------------------------------------------------------------
# Captured-pair retrieval ranking boost
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestCapturedPairRanking:
    async def test_captured_pair_ranks_higher_than_equivalent_uncaptured(self):
        """Two rows with the SAME body -- one captured, one not.
        The captured row must surface first in retrieve_similar.
        """
        conn = _make_db()
        acct_id = _seed_account(conn)
        backend = _FakeBackend()
        idx = SentMailIndex(
            conn, acct_id,
            embedding_backend=backend,
            embedding_model=EMBED_MODEL_FIXTURE,
        )
        # First: a general (uncaptured) row.
        general_msg = EmailMessage(
            message_id="g1",
            provider="imap",
            sender="user@example.com",
            recipients=["other@example.com"],
            subject="Re: alpha",
            body_text="Sounds good, will do.",
            date=datetime(2026, 5, 1, tzinfo=timezone.utc),
            headers={"Message-ID": "<g1@example.com>"},
        )
        await idx.index_message(general_msg)
        # Second: a captured row with the same body but different
        # message_id / rfc_id.
        captured_msg = EmailMessage(
            message_id="c1",
            provider="imap",
            sender="user@example.com",
            recipients=["other@example.com"],
            subject="Re: alpha",
            body_text="Sounds good, will do.",
            date=datetime(2026, 5, 1, tzinfo=timezone.utc),
            headers={"Message-ID": "<c1@example.com>"},
        )
        await idx.index_message(captured_msg, is_captured_pair=True)

        hits = await idx.retrieve_similar(
            "Sounds good, will do.", top_k=5,
        )
        # Both should appear, captured first.
        assert len(hits) == 2
        assert hits[0]["message_id"] == "c1"
        assert hits[0]["is_captured_pair"] is True
        assert hits[1]["message_id"] == "g1"
        assert hits[1]["is_captured_pair"] is False
        # Cosine similarity itself is identical (same body, same query).
        assert hits[0]["similarity"] == pytest.approx(hits[1]["similarity"])

    async def test_boost_constant_documented(self):
        """The boost multiplier is exposed for ops + tests."""
        # Sanity bound: not zero, not absurd. 1.0..2.0 keeps the boost
        # in the "tilt toward captured" rather than "captured always
        # wins" regime.
        assert 1.0 < _CAPTURED_PAIR_BOOST < 2.0


# ---------------------------------------------------------------------------
# Background loop (which accounts opt in / out)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestBackgroundLoop:
    async def test_loop_skips_hipaa_and_disabled_and_unopted(self, monkeypatch):
        """``_run_sent_mail_capture_sweep`` opts in only non-HIPAA
        active accounts whose ``rag_sent_index_enabled`` toggle is on.
        """
        from email_triage.web import app as app_mod

        # Build a mock app.state with three accounts:
        #   1. opted-in non-HIPAA active   -> scanned
        #   2. HIPAA flagged               -> skipped (skipped_hipaa)
        #   3. disabled                    -> skipped (skipped_disabled)
        #   4. non-HIPAA but opt-out       -> skipped (silent)
        accts = [
            {"id": 1, "is_active": True, "hipaa": False,
             "email_address": "a@example.com", "name": "A",
             "config": {}},
            {"id": 2, "is_active": True, "hipaa": True,
             "email_address": "b@example.com", "name": "B",
             "config": {}},
            {"id": 3, "is_active": False, "hipaa": False,
             "email_address": "c@example.com", "name": "C",
             "config": {}},
            {"id": 4, "is_active": True, "hipaa": False,
             "email_address": "d@example.com", "name": "D",
             "config": {}},
        ]
        rag_enabled_ids = {1}  # only account 1 opted in

        scanned_account_ids: list[int] = []

        class _StubProvider:
            async def search(self, query, limit):
                return []
            async def fetch_message(self, mid, **_kw):
                raise AssertionError("no msgs configured")
            async def close(self):
                pass

        def _fake_create_provider(acct, secrets, **_kw):
            scanned_account_ids.append(acct["id"])
            return _StubProvider()

        # Patch the dependencies that _run_sent_mail_capture_sweep imports.
        import email_triage.web.routers.ui as ui_mod
        monkeypatch.setattr(
            ui_mod, "_create_provider_from_account", _fake_create_provider,
        )

        # Patch DB helpers via the module they're imported from.
        import email_triage.web.db as db_mod
        monkeypatch.setattr(
            db_mod, "list_email_accounts",
            lambda conn, **_kw: list(accts),
        )
        # #157 — is_rag_sent_index_enabled grew an ``account`` kwarg
        # for HIPAA-aware default; mock signature must accept it.
        monkeypatch.setattr(
            db_mod, "is_rag_sent_index_enabled",
            lambda conn, aid, *, account=None: aid in rag_enabled_ids,
        )
        monkeypatch.setattr(
            db_mod, "is_style_learning_master_enabled",
            lambda conn: True,
        )
        # No-op the audit row write so we don't need an auth_events table.
        monkeypatch.setattr(
            db_mod, "record_auth_event",
            lambda *a, **kw: 1,
        )

        # Build a minimal app.state stub.
        app = type("FakeApp", (), {})()
        app.state = type("S", (), {})()
        app.state.db = sqlite3.connect(":memory:")
        app.state.db.row_factory = sqlite3.Row
        app.state.secrets = object()
        app.state.embedding_backend = _FakeBackend()
        app.state.embedding_model = EMBED_MODEL_FIXTURE
        app.state.sqlite_vec_available = False
        # Mock email_accounts table for SentMailIndex HIPAA gate
        app.state.db.execute("""
            CREATE TABLE email_accounts (
                id INTEGER PRIMARY KEY,
                hipaa INTEGER NOT NULL DEFAULT 0,
                created_under_system_hipaa INTEGER NOT NULL DEFAULT 0
            )
        """)
        app.state.db.execute(
            "INSERT INTO email_accounts (id, hipaa) VALUES "
            "(1, 0), (2, 1), (3, 0), (4, 0)"
        )
        # Apply v12 + v14 to bring up sent_mail_index w/ is_captured_pair.
        from email_triage.web.migrations import MIGRATIONS
        for v in (12, 14, 15):
            m = next(mi for mi in MIGRATIONS if mi.version == v)
            m.body(app.state.db)
        app.state.db.commit()

        counters = await app_mod._run_sent_mail_capture_sweep(app)
        # Exactly one account scanned (account 1).
        assert scanned_account_ids == [1]
        assert counters["considered"] == 4
        assert counters["skipped_hipaa"] == 1
        assert counters["skipped_disabled"] == 1
        # Account 4 (opt-out) doesn't bump skipped_disabled or
        # skipped_hipaa; it just silently doesn't run.

    async def test_loop_no_op_when_master_toggle_off(self, monkeypatch):
        from email_triage.web import app as app_mod
        import email_triage.web.db as db_mod

        monkeypatch.setattr(
            db_mod, "is_style_learning_master_enabled",
            lambda conn: False,
        )
        called: list[Any] = []
        monkeypatch.setattr(
            db_mod, "list_email_accounts",
            lambda conn, **_kw: called.append("listed") or [],
        )

        app = type("FakeApp", (), {})()
        app.state = type("S", (), {})()
        app.state.db = sqlite3.connect(":memory:")
        app.state.secrets = object()
        app.state.embedding_backend = _FakeBackend()
        app.state.embedding_model = EMBED_MODEL_FIXTURE

        counters = await app_mod._run_sent_mail_capture_sweep(app)
        assert counters["considered"] == 0
        assert called == []  # short-circuited before listing accounts

    async def test_loop_no_op_when_no_embedding_backend(self, monkeypatch):
        from email_triage.web import app as app_mod
        import email_triage.web.db as db_mod

        monkeypatch.setattr(
            db_mod, "is_style_learning_master_enabled",
            lambda conn: True,
        )
        listed: list[Any] = []
        monkeypatch.setattr(
            db_mod, "list_email_accounts",
            lambda conn, **_kw: listed.append("x") or [],
        )

        app = type("FakeApp", (), {})()
        app.state = type("S", (), {})()
        app.state.db = sqlite3.connect(":memory:")
        app.state.secrets = object()
        app.state.embedding_backend = None  # not wired

        counters = await app_mod._run_sent_mail_capture_sweep(app)
        assert counters["skipped_no_backend"] == 1
        # Did not even reach list_email_accounts.
        assert listed == []


# ---------------------------------------------------------------------------
# Audit row written per scan attempt
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestAuditRow:
    async def test_audit_row_written_on_success(self, monkeypatch):
        """Each scan attempt writes an auth_events row with
        ``event_type=sent_mail_capture`` and ``outcome=success``.
        """
        from email_triage.web import app as app_mod
        import email_triage.web.db as db_mod
        import email_triage.web.routers.ui as ui_mod

        captured_audit_rows: list[dict] = []

        def _fake_audit(conn, *, event_type, email, outcome, detail=None,
                        **kw):
            captured_audit_rows.append({
                "event_type": event_type,
                "email": email,
                "outcome": outcome,
                "detail": detail,
            })
            return 1

        monkeypatch.setattr(db_mod, "record_auth_event", _fake_audit)
        monkeypatch.setattr(
            db_mod, "is_style_learning_master_enabled",
            lambda conn: True,
        )
        monkeypatch.setattr(
            db_mod, "list_email_accounts",
            lambda conn, **_kw: [{
                "id": 1, "is_active": True, "hipaa": False,
                "email_address": "user@example.com", "name": "A",
                "config": {},
            }],
        )
        monkeypatch.setattr(
            db_mod, "is_rag_sent_index_enabled",
            lambda conn, aid, *, account=None: True,
        )

        class _StubProvider:
            async def search(self, query, limit):
                return []
            async def fetch_message(self, mid, **_kw):
                raise AssertionError("no msgs")
            async def close(self):
                pass

        monkeypatch.setattr(
            ui_mod, "_create_provider_from_account",
            lambda acct, secrets, **_kw: _StubProvider(),
        )

        app = type("FakeApp", (), {})()
        app.state = type("S", (), {})()
        app.state.db = sqlite3.connect(":memory:")
        app.state.db.row_factory = sqlite3.Row
        app.state.secrets = object()
        app.state.embedding_backend = _FakeBackend()
        app.state.embedding_model = EMBED_MODEL_FIXTURE
        app.state.sqlite_vec_available = False
        app.state.db.execute("""
            CREATE TABLE email_accounts (
                id INTEGER PRIMARY KEY,
                hipaa INTEGER NOT NULL DEFAULT 0,
                created_under_system_hipaa INTEGER NOT NULL DEFAULT 0
            )
        """)
        app.state.db.execute(
            "INSERT INTO email_accounts (id, hipaa) VALUES (1, 0)"
        )
        from email_triage.web.migrations import MIGRATIONS
        for v in (12, 14, 15):
            m = next(mi for mi in MIGRATIONS if mi.version == v)
            m.body(app.state.db)
        app.state.db.commit()

        await app_mod._run_sent_mail_capture_sweep(app)
        # At least one success row -- count is 0 because provider
        # returned an empty list, but the audit row still fires.
        success_rows = [
            r for r in captured_audit_rows
            if r["event_type"] == "sent_mail_capture"
            and r["outcome"] == "success"
        ]
        assert len(success_rows) == 1
        assert "count=0" in (success_rows[0]["detail"] or "")


# ---------------------------------------------------------------------------
# Cron-anchor helper
# ---------------------------------------------------------------------------

class TestCronAnchor:
    def test_seconds_until_next_capture_tick_falls_in_expected_window(self):
        """For a 6-hour interval at noon UTC, the next boundary is
        18:00 UTC -- 6h away -- plus 0..300s jitter.
        """
        from email_triage.web import app as app_mod

        app = type("FakeApp", (), {})()
        app.state = type("S", (), {})()
        app.state.db = sqlite3.connect(":memory:")

        noon = datetime(2026, 5, 8, 12, 0, 0, tzinfo=timezone.utc)
        # No setting row -> default 6h interval.
        seconds = app_mod._seconds_until_next_capture_tick(app, now=noon)
        # 6h = 21600s. Window: [21600, 21600 + 300].
        assert 21600.0 <= seconds <= 21600.0 + 300.0

    def test_seconds_clamps_to_min_one(self):
        """Right on a boundary, helper still returns >=1 second."""
        from email_triage.web import app as app_mod

        app = type("FakeApp", (), {})()
        app.state = type("S", (), {})()
        app.state.db = sqlite3.connect(":memory:")

        # Choose a moment 0.001s before a boundary -- next tick is
        # almost immediate.
        boundary = datetime(2026, 5, 8, 6, 0, 0, tzinfo=timezone.utc)
        seconds = app_mod._seconds_until_next_capture_tick(
            app, now=boundary,
        )
        # Either we land just before this boundary (tiny window) or
        # we roll to the next interval; either way >= 1s.
        assert seconds >= 1.0
