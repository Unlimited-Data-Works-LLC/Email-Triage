"""Tests for M-7 per-contact style layering.

Scope: when replying to a recurring contact, ``SentMailIndex.retrieve_similar``
filters the candidate pool to "replies I've sent to THIS person" first,
then tops up from the global pool if fewer than ``top_k`` per-contact
matches exist. HIPAA short-circuits ALL retrieval paths regardless of
the per-contact flag. Per-account toggle off = legacy global retrieval.

Privacy invariant pinned: a HIPAA account flowing through M-7 MUST NOT
invoke the embedding backend even when ``contact_address`` is supplied.

No real PII anywhere -- every actor is ``user@example.com`` /
``boss@example.com`` / ``Operator A``.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import struct
from datetime import datetime, timezone
from typing import Any

import pytest

from email_triage.actions.sent_mail_index import SentMailIndex
from email_triage.engine.models import EmailMessage


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

EMBED_MODEL_FIXTURE = "test-embedder-v0"


def _make_db() -> sqlite3.Connection:
    """Bring up just the tables M-7 touches.

    Mirrors the scaffold from ``test_sent_mail_index.py``: no full
    ``init_db`` -- just the v12 migration body so we keep tests fast
    + scoped to the layer under test.
    """
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
    # Run v12 (sent_mail_index create) AND v14 (M-6 is_captured_pair
    # column add) AND v15 (#136 embedding_norm column for the numpy
    # cosine fast path). M-7 was authored before M-6 landed on main;
    # the SELECT path now references is_captured_pair AND
    # embedding_norm, so the fixture has to mirror the merged schema.
    for m in MIGRATIONS:
        if m.version in (12, 14, 15):
            m.body(conn)
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


def _msg(
    body: str,
    *,
    uid: str,
    rfc_id: str,
    subject: str = "Re: hello",
    recipients: list[str] | None = None,
    hipaa: bool = False,
) -> EmailMessage:
    return EmailMessage(
        message_id=uid,
        provider="imap",
        sender="user@example.com",
        recipients=recipients or ["other@example.com"],
        subject=subject,
        body_text=body,
        date=datetime(2026, 5, 1, tzinfo=timezone.utc),
        headers={"Message-ID": rfc_id} if rfc_id else {},
        hipaa=hipaa,
    )


class _FakeBackend:
    """Deterministic embedding backend.

    Vectors are derived from a sha256 prefix so reproducibility holds
    across Python versions. Same input ⇒ same vector. Texts that
    share the leading bytes end up with high cosine similarity, which
    is enough for the M-7 contract -- the tests assert ordering /
    presence rather than absolute scores.
    """
    backend_type = "ollama"

    def __init__(self) -> None:
        self.calls: list[str] = []

    async def embed_text(self, text: str) -> list[float]:
        self.calls.append(text)
        digest = hashlib.sha256(text.encode("utf-8")).digest()
        # Eight-dim float vector, each float in [0.0, 1.0).
        return [digest[i] / 255.0 for i in range(8)]


def _seed_row(
    conn: sqlite3.Connection,
    account_id: int,
    *,
    rfc_id: str,
    body: str,
    to_addresses: list[str],
    subject: str = "Re: hello",
    embedding_model: str = EMBED_MODEL_FIXTURE,
    vec: list[float] | None = None,
) -> None:
    """Insert a sent_mail_index row directly so we control to_addresses
    + the embedding vector.

    Tests in this module use this helper rather than ``index_message``
    so the per-contact filter behaviour can be asserted independently
    of the embedding backend's fidelity.
    """
    if vec is None:
        # Deterministic vector from the body so cosine sim with a
        # query-time embed of similar text is high.
        digest = hashlib.sha256(body.encode("utf-8")).digest()
        vec = [digest[i] / 255.0 for i in range(8)]
    blob = struct.pack(f"<{len(vec)}f", *vec)
    # #136: precomputed L2 norm matches what index_message would write.
    # Tests that bypass the public method via this helper still need to
    # populate the column or retrieve_similar will skip the row.
    import math as _math
    norm = _math.sqrt(sum(x * x for x in vec))
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "INSERT INTO sent_mail_index ("
        "account_id, message_id, rfc_message_id, sent_at, "
        "to_addresses, subject, body_excerpt, embedding_vec, "
        "embedding_model, indexed_at, embedding_norm"
        ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            account_id,
            rfc_id,                       # use rfc_id as the provider message_id surrogate
            rfc_id,
            now,
            json.dumps(to_addresses),
            subject,
            body,
            blob,
            embedding_model,
            now,
            norm,
        ),
    )
    conn.commit()


# ---------------------------------------------------------------------------
# Per-contact filter behaviour
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestPerContactFilter:
    async def test_filter_returns_matches_for_contact(self):
        """When several past replies went to ``boss@example.com`` and
        a couple went elsewhere, retrieval with
        ``contact_address='boss@example.com'`` MUST surface only the
        boss-targeted rows (since len(boss-rows) >= top_k).
        """
        conn = _make_db()
        acct_id = _seed_account(conn)
        # Five past replies to boss + two to others.
        for i in range(5):
            _seed_row(
                conn, acct_id,
                rfc_id=f"<boss-{i}@example.com>",
                body=f"reply to boss number {i}",
                to_addresses=["boss@example.com"],
            )
        _seed_row(
            conn, acct_id,
            rfc_id="<other-1@example.com>",
            body="reply to other person",
            to_addresses=["random@example.com"],
        )
        _seed_row(
            conn, acct_id,
            rfc_id="<other-2@example.com>",
            body="another reply elsewhere",
            to_addresses=["someone@example.com"],
        )

        idx = SentMailIndex(
            conn, acct_id,
            embedding_backend=_FakeBackend(),
            embedding_model=EMBED_MODEL_FIXTURE,
        )
        hits = await idx.retrieve_similar(
            "reply to boss number 2",
            top_k=5,
            contact_address="boss@example.com",
        )
        assert len(hits) == 5
        for entry in hits:
            assert "boss@example.com" in entry["to_addresses"], (
                f"Per-contact filter leaked a non-boss row: {entry}"
            )

    async def test_falls_back_to_global_when_sparse(self):
        """If the per-contact pool has fewer than ``top_k`` rows,
        the helper tops up from the unfiltered pool. Per-contact
        rows take priority; global fills the rest.
        """
        conn = _make_db()
        acct_id = _seed_account(conn)
        # Two past replies to boss.
        for i in range(2):
            _seed_row(
                conn, acct_id,
                rfc_id=f"<boss-{i}@example.com>",
                body=f"reply to boss number {i}",
                to_addresses=["boss@example.com"],
            )
        # Five past replies to other people.
        for i in range(5):
            _seed_row(
                conn, acct_id,
                rfc_id=f"<global-{i}@example.com>",
                body=f"general reply {i}",
                to_addresses=[f"person{i}@example.com"],
            )

        idx = SentMailIndex(
            conn, acct_id,
            embedding_backend=_FakeBackend(),
            embedding_model=EMBED_MODEL_FIXTURE,
        )
        hits = await idx.retrieve_similar(
            "any query",
            top_k=5,
            contact_address="boss@example.com",
        )
        # Capped at 5; both boss rows present, plus 3 global rows.
        assert len(hits) == 5
        boss_count = sum(
            1 for h in hits if "boss@example.com" in h["to_addresses"]
        )
        assert boss_count == 2

    async def test_top_up_dedupes_per_contact_rows(self):
        """The per-contact rows that already match must NOT show up
        a second time as part of the global top-up.
        """
        conn = _make_db()
        acct_id = _seed_account(conn)
        _seed_row(
            conn, acct_id,
            rfc_id="<dup-1@example.com>",
            body="reply to boss",
            to_addresses=["boss@example.com"],
        )
        # No other rows -- per-contact pool has 1, global has the
        # same 1. Without dedup the helper would return [boss, boss].
        idx = SentMailIndex(
            conn, acct_id,
            embedding_backend=_FakeBackend(),
            embedding_model=EMBED_MODEL_FIXTURE,
        )
        hits = await idx.retrieve_similar(
            "any",
            top_k=5,
            contact_address="boss@example.com",
        )
        assert len(hits) == 1
        ids = [h["rfc_message_id"] for h in hits]
        assert len(ids) == len(set(ids))

    async def test_no_contact_arg_uses_global_pool(self):
        """Backwards-compat: omitting ``contact_address`` runs the
        legacy global path (no SQL LIKE filter).
        """
        conn = _make_db()
        acct_id = _seed_account(conn)
        _seed_row(
            conn, acct_id,
            rfc_id="<a@example.com>",
            body="reply alpha",
            to_addresses=["alpha@example.com"],
        )
        _seed_row(
            conn, acct_id,
            rfc_id="<b@example.com>",
            body="reply beta",
            to_addresses=["beta@example.com"],
        )
        idx = SentMailIndex(
            conn, acct_id,
            embedding_backend=_FakeBackend(),
            embedding_model=EMBED_MODEL_FIXTURE,
        )
        hits = await idx.retrieve_similar("anything", top_k=5)
        # Both rows surface -- no per-contact filter applied.
        assert len(hits) == 2

    async def test_contact_address_case_folded(self):
        """``Alice@Example.COM`` matches a stored ``alice@example.com``.

        The stored to_addresses JSON carries the address in whatever
        case the provider supplied -- the LIKE filter must lower-case
        both sides.
        """
        conn = _make_db()
        acct_id = _seed_account(conn)
        _seed_row(
            conn, acct_id,
            rfc_id="<alice-1@example.com>",
            body="reply to alice",
            to_addresses=["alice@example.com"],
        )
        idx = SentMailIndex(
            conn, acct_id,
            embedding_backend=_FakeBackend(),
            embedding_model=EMBED_MODEL_FIXTURE,
        )
        hits = await idx.retrieve_similar(
            "anything",
            top_k=5,
            contact_address="Alice@Example.COM",
        )
        assert len(hits) == 1
        assert hits[0]["rfc_message_id"] == "<alice-1@example.com>"

    async def test_contact_address_matches_when_stored_uppercase(self):
        """Inverse case-fold: if the provider stored ``BOSS@example.com``
        but the caller supplies a lowercased form, the LIKE filter
        still matches.
        """
        conn = _make_db()
        acct_id = _seed_account(conn)
        _seed_row(
            conn, acct_id,
            rfc_id="<mixed-1@example.com>",
            body="reply to mixed-case",
            to_addresses=["BOSS@example.com"],
        )
        idx = SentMailIndex(
            conn, acct_id,
            embedding_backend=_FakeBackend(),
            embedding_model=EMBED_MODEL_FIXTURE,
        )
        hits = await idx.retrieve_similar(
            "anything",
            top_k=5,
            contact_address="boss@example.com",
        )
        assert len(hits) == 1

    async def test_top_k_zero_returns_empty(self):
        """Edge case: top_k=0 short-circuits to empty regardless of
        the per-contact filter.
        """
        conn = _make_db()
        acct_id = _seed_account(conn)
        _seed_row(
            conn, acct_id,
            rfc_id="<x@example.com>",
            body="reply",
            to_addresses=["boss@example.com"],
        )
        idx = SentMailIndex(
            conn, acct_id,
            embedding_backend=_FakeBackend(),
            embedding_model=EMBED_MODEL_FIXTURE,
        )
        hits = await idx.retrieve_similar(
            "anything", top_k=0, contact_address="boss@example.com",
        )
        assert hits == []


# ---------------------------------------------------------------------------
# HIPAA short-circuit (defence in depth -- M-7 must not bypass M-4's gate)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestHipaaShortCircuit:
    async def test_hipaa_account_returns_empty_with_contact_filter(self):
        """A HIPAA-flagged account gets ``[]`` even if rows exist AND
        a per-contact filter is supplied. Defence in depth: the M-4
        gate at SentMailIndex.retrieve_similar fires before any SQL
        the per-contact path would run.
        """
        conn = _make_db()
        # Seed rows under a non-HIPAA flag, then flip to HIPAA.
        acct_id = _seed_account(conn, hipaa=False)
        _seed_row(
            conn, acct_id,
            rfc_id="<phi-1@example.com>",
            body="phi reply",
            to_addresses=["boss@example.com"],
        )
        conn.execute(
            "UPDATE email_accounts SET hipaa = 1 WHERE id = ?",
            (acct_id,),
        )
        conn.commit()
        idx = SentMailIndex(
            conn, acct_id,
            embedding_backend=_FakeBackend(),
            embedding_model=EMBED_MODEL_FIXTURE,
        )
        hits = await idx.retrieve_similar(
            "anything", top_k=5, contact_address="boss@example.com",
        )
        assert hits == []

    async def test_hipaa_with_contact_does_not_call_backend(self):
        """Privacy invariant: even with the M-7 contact filter, the
        embedding backend MUST NOT be called for a HIPAA account.

        Sibling of the M-4 ``test_privacy_invariant_hipaa_never_calls_backend``.
        """
        conn = _make_db()
        acct_id = _seed_account(conn, hipaa=True)

        class _RaisingBackend:
            backend_type = "ollama"

            async def embed_text(self, text: str) -> list[float]:
                raise AssertionError(
                    "embed_text must not be called on a HIPAA account",
                )

        idx = SentMailIndex(
            conn, acct_id,
            embedding_backend=_RaisingBackend(),
            embedding_model=EMBED_MODEL_FIXTURE,
        )
        hits = await idx.retrieve_similar(
            "anything",
            top_k=5,
            contact_address="boss@example.com",
        )
        assert hits == []


# ---------------------------------------------------------------------------
# Per-account toggle helper
# ---------------------------------------------------------------------------

class TestPerContactToggleHelper:
    def test_default_is_on_when_key_missing(self):
        """Opt-out shape: an account whose config doesn't carry the
        key gets the on-default. Existing accounts that opted into M-4
        keep working without touching this flag.
        """
        from email_triage.web.db import (
            is_style_learning_per_contact_enabled,
        )
        acct = {"id": 1, "config": {}}
        assert is_style_learning_per_contact_enabled(acct) is True

    def test_explicit_false_disables(self):
        from email_triage.web.db import (
            is_style_learning_per_contact_enabled,
        )
        acct = {
            "id": 1,
            "config": {"style_learning_per_contact_enabled": False},
        }
        assert is_style_learning_per_contact_enabled(acct) is False

    def test_explicit_true_enables(self):
        from email_triage.web.db import (
            is_style_learning_per_contact_enabled,
        )
        acct = {
            "id": 1,
            "config": {"style_learning_per_contact_enabled": True},
        }
        assert is_style_learning_per_contact_enabled(acct) is True

    def test_none_account_returns_false(self):
        from email_triage.web.db import (
            is_style_learning_per_contact_enabled,
        )
        assert is_style_learning_per_contact_enabled(None) is False

    def test_non_dict_config_uses_default(self):
        """Defensive: a malformed account whose config isn't a dict
        falls through to the on-default rather than raising.
        """
        from email_triage.web.db import (
            is_style_learning_per_contact_enabled,
        )
        acct = {"id": 1, "config": "not-a-dict"}
        assert is_style_learning_per_contact_enabled(acct) is True


# ---------------------------------------------------------------------------
# Display-name stripping (mail_headers._extract_addr round-trip)
# ---------------------------------------------------------------------------

class TestSenderAddressExtraction:
    def test_display_name_stripped(self):
        """``"Alice" <alice@example.com>`` -> ``alice@example.com``.

        Relies on the existing _extract_addr helper from #117; pinned
        here so the M-7 wiring in build_prompt_messages doesn't depend
        on a future regression in that helper without a test fail.
        """
        from email_triage.mail_headers import _extract_addr
        assert _extract_addr('"Alice" <alice@example.com>') == (
            "alice@example.com"
        )
        assert _extract_addr("Alice <alice@example.com>") == (
            "alice@example.com"
        )
        assert _extract_addr("<alice@example.com>") == "alice@example.com"
        assert _extract_addr("alice@example.com") == "alice@example.com"
        assert _extract_addr("ALICE@EXAMPLE.COM") == "alice@example.com"
        assert _extract_addr("") == ""


# ---------------------------------------------------------------------------
# build_prompt_messages threads contact_address through (integration-ish)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestDraftReplyThreadsContact:
    async def _setup_full_db(self, *, per_contact_on: bool):
        """Bring up the full schema + a user + an account with M-4
        on so build_prompt_messages reaches the retrieval branch.

        Returns ``(conn, app, account, user_id, acct_id)``.
        """
        from types import SimpleNamespace
        from email_triage.web.db import (
            init_db,
            set_rag_sent_index_enabled,
            set_style_learning_master_enabled,
        )
        conn = init_db(":memory:")
        now = datetime.now(timezone.utc).isoformat()
        cur = conn.execute(
            "INSERT INTO users (email, name, role, created_at) "
            "VALUES (?, ?, ?, ?)",
            ("user@example.com", "Operator A", "user", now),
        )
        conn.commit()
        user_id = int(cur.lastrowid)
        cfg = {
            "style_learning_per_contact_enabled": per_contact_on,
        }
        cur2 = conn.execute(
            "INSERT INTO email_accounts ("
            "user_id, name, provider_type, config_json, hipaa, "
            "created_at, updated_at"
            ") VALUES (?, ?, ?, ?, ?, ?, ?)",
            (user_id, "Operator A Mailbox", "imap",
             json.dumps(cfg), 0, now, now),
        )
        conn.commit()
        acct_id = int(cur2.lastrowid)

        set_style_learning_master_enabled(conn, True)
        set_rag_sent_index_enabled(conn, acct_id, enabled=True)

        backend = _FakeBackend()
        app = SimpleNamespace(state=SimpleNamespace(
            embedding_backend=backend,
            embedding_model=EMBED_MODEL_FIXTURE,
            sqlite_vec_available=False,
        ))
        account = {
            "id": acct_id,
            "hipaa": False,
            "config": cfg,
        }
        return conn, app, account, user_id, acct_id, backend

    async def test_per_contact_on_narrows_to_boss(self):
        """End-to-end: with per_contact_on=True and a sender display-
        name, the build_prompt_messages stitch surfaces only past
        replies to that sender's address.
        """
        from email_triage.actions.draft_reply import build_prompt_messages
        from email_triage.engine.models import Classification
        conn, app, account, user_id, acct_id, _be = await self._setup_full_db(
            per_contact_on=True,
        )
        # Three boss-targeted replies + three other-targeted.
        for i in range(3):
            _seed_row(
                conn, acct_id,
                rfc_id=f"<boss-{i}@example.com>",
                body=f"BOSS_REPLY_{i}_marker",
                to_addresses=["boss@example.com"],
            )
        for i in range(3):
            _seed_row(
                conn, acct_id,
                rfc_id=f"<other-{i}@example.com>",
                body=f"OTHER_REPLY_{i}_marker",
                to_addresses=[f"person{i}@example.com"],
            )

        message = EmailMessage(
            message_id="m-incoming",
            provider="imap",
            sender='"Boss Person" <boss@example.com>',
            recipients=["user@example.com"],
            subject="Need an update",
            body_text="Quick update on the project please.",
            date=datetime(2026, 5, 8, tzinfo=timezone.utc),
        )
        messages = await build_prompt_messages(
            db=conn, app=app, account=account, user_id=user_id,
            message=message,
            classification=Classification(
                category="to-respond", confidence=0.9,
                reason="direct request",
            ),
        )
        flat = "\n".join(m["content"] for m in messages)
        # All boss markers present; OTHER markers must NOT appear
        # (boss pool >= top_k=5 so global top-up doesn't fire).
        boss_present = sum(
            1 for i in range(3) if f"BOSS_REPLY_{i}_marker" in flat
        )
        other_present = sum(
            1 for i in range(3) if f"OTHER_REPLY_{i}_marker" in flat
        )
        assert boss_present == 3
        # Global top-up CAN fire because top_k=5 > boss_count=3, so
        # 2 OTHER markers may show up. Verify the boss rows are
        # prioritised: all 3 boss markers must appear.
        assert other_present <= 2

    async def test_per_contact_off_falls_through_to_global(self):
        """When the per-account sub-toggle is off, the helper must
        NOT pass a contact_address -- retrieval runs across the
        global pool with no recipient filter.
        """
        from email_triage.actions.draft_reply import build_prompt_messages
        from email_triage.engine.models import Classification
        conn, app, account, user_id, acct_id, _be = await self._setup_full_db(
            per_contact_on=False,
        )
        # Seed three boss + three other rows; with per-contact off,
        # all six are eligible candidates.
        for i in range(3):
            _seed_row(
                conn, acct_id,
                rfc_id=f"<boss-{i}@example.com>",
                body=f"BOSS_REPLY_{i}_marker",
                to_addresses=["boss@example.com"],
            )
        for i in range(3):
            _seed_row(
                conn, acct_id,
                rfc_id=f"<other-{i}@example.com>",
                body=f"OTHER_REPLY_{i}_marker",
                to_addresses=[f"person{i}@example.com"],
            )

        message = EmailMessage(
            message_id="m-incoming",
            provider="imap",
            sender="Boss Person <boss@example.com>",
            recipients=["user@example.com"],
            subject="Need an update",
            body_text="Quick update on the project please.",
            date=datetime(2026, 5, 8, tzinfo=timezone.utc),
        )
        messages = await build_prompt_messages(
            db=conn, app=app, account=account, user_id=user_id,
            message=message,
            classification=Classification(
                category="to-respond", confidence=0.9,
                reason="direct request",
            ),
        )
        flat = "\n".join(m["content"] for m in messages)
        # With per-contact off and top_k=5 the helper returns the
        # five highest-similarity rows from the global pool. All six
        # rows have the same vector-derivation pattern so we don't
        # assert which five were chosen -- only that the per-contact
        # narrowing is NOT applied (i.e. at least one OTHER marker
        # is present alongside the boss markers).
        any_other_present = any(
            f"OTHER_REPLY_{i}_marker" in flat for i in range(3)
        )
        any_boss_present = any(
            f"BOSS_REPLY_{i}_marker" in flat for i in range(3)
        )
        # Without the per-contact filter, the global pool's mix of
        # both types is the signal we want; both should be present
        # given the seed pattern.
        assert any_other_present
        assert any_boss_present
