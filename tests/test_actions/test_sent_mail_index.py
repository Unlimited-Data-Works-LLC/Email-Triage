"""Tests for ``actions.sent_mail_index`` (M-4 scaffold).

Scope: storage round-trip, HIPAA short-circuits at every public
method, idempotency, in-memory cosine fallback (sqlite-vec missing),
backend allowlist, and the privacy invariant that a HIPAA flow MUST
NOT call the embedding backend.

No real PII in fixtures: every actor is ``user@example.com`` /
``Operator A``; the embedding model fixture is a pinned placeholder
``test-embedder-v0`` (not a real Ollama model name).
"""

from __future__ import annotations

import json
import sqlite3
import struct
from datetime import datetime, timezone
from typing import Any
from unittest.mock import AsyncMock

import pytest

from email_triage.actions.sent_mail_index import (
    NonLocalBackendError,
    SentMailIndex,
    _LOCAL_BACKENDS,
    _cosine,
    _pack_vec,
    _unpack_vec,
)
from email_triage.engine.models import EmailMessage


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

EMBED_MODEL_FIXTURE = "test-embedder-v0"


def _make_db() -> sqlite3.Connection:
    """Construct an in-memory DB carrying just the bits this module
    touches: ``email_accounts`` (so the HIPAA gate can resolve the
    flag) and the ``sent_mail_index`` table created by migration v12.

    We deliberately do NOT call :func:`init_db` here so the test stays
    fast (no full schema bring-up) and so we control which migrations
    have run. Verifying that migration v12 applies cleanly is the
    job of ``test_v12_applies_cleanly`` below.
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
    # Apply v12 (creates sent_mail_index) + v14 (adds the M-6
    # is_captured_pair column) + v15 (#136 embedding_norm column).
    from email_triage.web.migrations import MIGRATIONS
    for ver in (12, 14, 15):
        for m in MIGRATIONS:
            if m.version == ver:
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


def _msg(
    body: str,
    *,
    uid: str = "u1",
    rfc_id: str = "<m1@example.com>",
    subject: str = "Re: hello",
    hipaa: bool = False,
) -> EmailMessage:
    return EmailMessage(
        message_id=uid,
        provider="imap",
        sender="user@example.com",
        recipients=["other@example.com"],
        subject=subject,
        body_text=body,
        date=datetime(2026, 5, 1, tzinfo=timezone.utc),
        headers={"Message-ID": rfc_id} if rfc_id else {},
        hipaa=hipaa,
    )


class _FakeBackend:
    """Deterministic embedding backend for tests.

    Hashes the input text into a 4-dim float vector. Same text ->
    same vector, similar prefixes -> high cosine similarity.

    ``backend_type`` defaults to ``"ollama"`` so the SentMailIndex
    allowlist accepts it; tests override the attribute on instances
    that should be rejected.
    """
    backend_type = "ollama"

    def __init__(self) -> None:
        self.calls: list[str] = []

    async def embed_text(self, text: str) -> list[float]:
        self.calls.append(text)
        # Deterministic vector based on character histogram. Two
        # texts that share most characters end up with near-parallel
        # vectors -- perfect for "similar reply" matching in tests.
        vec = [0.0, 0.0, 0.0, 0.0]
        for ch in text.lower():
            vec[ord(ch) % 4] += 1.0
        return vec


# ---------------------------------------------------------------------------
# Migration v12
# ---------------------------------------------------------------------------

class TestMigrationV12:
    def test_v12_applies_cleanly(self):
        """v12 body runs cleanly against a DB that already has the
        legacy email_accounts table.

        We invoke the body directly (not through ``run_migrations``)
        because the framework would also run v5 / v6 / v7 etc, which
        depend on legacy tables that ``init_db`` builds before the
        framework runs. Verifying v12 in isolation is what this test
        is for; the full ``init_db`` path is exercised elsewhere.
        """
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        conn.execute(
            "CREATE TABLE email_accounts (id INTEGER PRIMARY KEY)"
        )
        from email_triage.web.migrations import MIGRATIONS
        v12 = next(m for m in MIGRATIONS if m.version == 12)
        v12.body(conn)
        # Table is present.
        rows = conn.execute(
            "SELECT name FROM sqlite_master "
            "WHERE type='table' AND name='sent_mail_index'"
        ).fetchall()
        assert len(rows) == 1
        # And the indexes exist.
        idx_names = {
            r[0] for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='index'"
            ).fetchall()
        }
        assert "idx_sent_mail_account" in idx_names
        assert "idx_sent_mail_indexed" in idx_names

    def test_v12_via_init_db_full_path(self):
        """End-to-end path: ``init_db`` brings up the entire schema
        (legacy + framework migrations). After it runs, v12 is
        applied and the table is in place. This is the install path
        an old DB upgrades through.
        """
        from email_triage.web.db import init_db
        from email_triage.web.migrations import schema_version
        conn = init_db(":memory:")
        try:
            assert schema_version(conn) >= 12
            rows = conn.execute(
                "SELECT name FROM sqlite_master "
                "WHERE type='table' AND name='sent_mail_index'"
            ).fetchall()
            assert len(rows) == 1
        finally:
            conn.close()

    def test_v12_is_idempotent_on_existing_table(self):
        """A DB that already has the table (legacy hand-roll) re-runs
        v12 as a no-op via ``CREATE TABLE IF NOT EXISTS``.
        """
        conn = sqlite3.connect(":memory:")
        conn.execute(
            "CREATE TABLE email_accounts (id INTEGER PRIMARY KEY)"
        )
        # Pre-create a stub of the same name -- the migration must
        # tolerate this (operator may have backfilled by hand).
        conn.execute("""
            CREATE TABLE sent_mail_index (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                account_id INTEGER NOT NULL,
                message_id TEXT NOT NULL,
                rfc_message_id TEXT,
                sent_at TEXT NOT NULL,
                to_addresses TEXT NOT NULL DEFAULT '[]',
                subject TEXT,
                body_excerpt TEXT,
                embedding_vec BLOB,
                embedding_model TEXT NOT NULL,
                indexed_at TEXT NOT NULL
            )
        """)
        conn.commit()
        from email_triage.web.migrations import MIGRATIONS
        v12 = next(m for m in MIGRATIONS if m.version == 12)
        # Should not raise -- the body is CREATE-IF-NOT-EXISTS only.
        v12.body(conn)


# ---------------------------------------------------------------------------
# Pack / unpack / cosine
# ---------------------------------------------------------------------------

class TestVectorHelpers:
    def test_pack_unpack_roundtrip(self):
        v = [0.1, 0.5, -0.25, 1.0, 0.0]
        blob = _pack_vec(v)
        assert isinstance(blob, bytes)
        # 4 bytes per float32.
        assert len(blob) == 4 * len(v)
        out = _unpack_vec(blob)
        for orig, restored in zip(v, out):
            assert abs(orig - restored) < 1e-6

    def test_unpack_handles_none_and_empty(self):
        assert _unpack_vec(None) == []
        assert _unpack_vec(b"") == []

    def test_cosine_basic(self):
        a = [1.0, 0.0]
        b = [1.0, 0.0]
        assert _cosine(a, b) == pytest.approx(1.0)
        c = [0.0, 1.0]
        assert _cosine(a, c) == pytest.approx(0.0)

    def test_cosine_handles_zero_vector(self):
        # Length-mismatch and zero-norm both return 0.0.
        assert _cosine([], []) == 0.0
        assert _cosine([0.0, 0.0], [1.0, 1.0]) == 0.0


# ---------------------------------------------------------------------------
# Backend allowlist
# ---------------------------------------------------------------------------

class TestBackendAllowlist:
    def test_local_backends_constant_includes_ollama(self):
        assert "ollama" in _LOCAL_BACKENDS

    def test_init_rejects_openai_with_clear_error(self):
        conn = _make_db()
        acct_id = _seed_account(conn)
        bad_backend = _FakeBackend()
        bad_backend.backend_type = "openai"
        with pytest.raises(NonLocalBackendError) as excinfo:
            SentMailIndex(
                conn, acct_id,
                embedding_backend=bad_backend,
                embedding_model=EMBED_MODEL_FIXTURE,
            )
        msg = str(excinfo.value)
        assert "M-4" in msg
        assert "local-only" in msg
        assert "openai" in msg

    def test_init_rejects_gemini(self):
        conn = _make_db()
        acct_id = _seed_account(conn)
        bad = _FakeBackend()
        bad.backend_type = "gemini"
        with pytest.raises(NonLocalBackendError):
            SentMailIndex(
                conn, acct_id,
                embedding_backend=bad,
                embedding_model=EMBED_MODEL_FIXTURE,
            )

    def test_init_rejects_anthropic(self):
        # Belt + suspenders: feedback_no_anthropic.md.
        conn = _make_db()
        acct_id = _seed_account(conn)
        bad = _FakeBackend()
        bad.backend_type = "anthropic"
        with pytest.raises(NonLocalBackendError):
            SentMailIndex(
                conn, acct_id,
                embedding_backend=bad,
                embedding_model=EMBED_MODEL_FIXTURE,
            )

    def test_init_rejects_missing_backend_type(self):
        conn = _make_db()
        acct_id = _seed_account(conn)

        class _NoTypeBackend:
            async def embed_text(self, text: str) -> list[float]:
                return [0.0]
        with pytest.raises(NonLocalBackendError):
            SentMailIndex(
                conn, acct_id,
                embedding_backend=_NoTypeBackend(),
                embedding_model=EMBED_MODEL_FIXTURE,
            )


# ---------------------------------------------------------------------------
# index_message + retrieve_similar round-trip
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestIndexAndRetrieve:
    async def test_round_trip_finds_indexed_message(self):
        conn = _make_db()
        acct_id = _seed_account(conn)
        backend = _FakeBackend()
        idx = SentMailIndex(
            conn, acct_id,
            embedding_backend=backend,
            embedding_model=EMBED_MODEL_FIXTURE,
        )
        await idx.index_message(_msg(
            "Sounds good, happy to help.", uid="u1",
            rfc_id="<m1@example.com>",
        ))
        await idx.index_message(_msg(
            "Sure thing, see you tomorrow.", uid="u2",
            rfc_id="<m2@example.com>",
            subject="Re: tomorrow",
        ))
        # Query close to the first body.
        hits = await idx.retrieve_similar(
            "Happy to help, sounds good.", top_k=2,
        )
        assert len(hits) == 2
        # Highest-similarity hit should be the matching message.
        assert hits[0]["message_id"] == "u1"
        # Returned dict keeps the operator-readable fields.
        assert "subject" in hits[0]
        assert "excerpt" in hits[0]
        assert isinstance(hits[0]["to_addresses"], list)
        assert hits[0]["similarity"] >= hits[1]["similarity"]

    async def test_index_skips_empty_body(self):
        conn = _make_db()
        acct_id = _seed_account(conn)
        backend = _FakeBackend()
        idx = SentMailIndex(
            conn, acct_id,
            embedding_backend=backend,
            embedding_model=EMBED_MODEL_FIXTURE,
        )
        # Quote-only body strips to empty.
        await idx.index_message(_msg(
            "> earlier message\n> nothing original",
            rfc_id="<empty@example.com>",
        ))
        # Backend was never called -- empty body short-circuits.
        assert backend.calls == []
        rows = conn.execute(
            "SELECT COUNT(*) FROM sent_mail_index"
        ).fetchone()
        assert rows[0] == 0

    async def test_retrieve_similar_empty_index_returns_empty(self):
        conn = _make_db()
        acct_id = _seed_account(conn)
        idx = SentMailIndex(
            conn, acct_id,
            embedding_backend=_FakeBackend(),
            embedding_model=EMBED_MODEL_FIXTURE,
        )
        hits = await idx.retrieve_similar("anything")
        assert hits == []

    async def test_retrieve_similar_empty_query_returns_empty(self):
        conn = _make_db()
        acct_id = _seed_account(conn)
        idx = SentMailIndex(
            conn, acct_id,
            embedding_backend=_FakeBackend(),
            embedding_model=EMBED_MODEL_FIXTURE,
        )
        # Empty query -- no embed call, no rows scanned.
        assert await idx.retrieve_similar("") == []
        assert await idx.retrieve_similar("   ") == []

    async def test_retrieve_similar_filters_by_embedding_model(self):
        """Rows with a stale embedding model (operator switched models)
        are NOT returned in the candidate set. Cross-model cosine
        is meaningless; better to surface zero hits than to mix.
        """
        conn = _make_db()
        acct_id = _seed_account(conn)
        backend = _FakeBackend()
        # Index under the old model.
        old_idx = SentMailIndex(
            conn, acct_id,
            embedding_backend=backend,
            embedding_model="old-embedder-v0",
        )
        await old_idx.index_message(_msg(
            "old reply", rfc_id="<old@example.com>",
        ))
        # Query under the new model.
        new_idx = SentMailIndex(
            conn, acct_id,
            embedding_backend=backend,
            embedding_model="new-embedder-v0",
        )
        hits = await new_idx.retrieve_similar("old reply")
        assert hits == []


# ---------------------------------------------------------------------------
# HIPAA short-circuits (defence in depth)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestHipaaGate:
    async def test_index_message_skipped_on_hipaa_account(self):
        conn = _make_db()
        acct_id = _seed_account(conn, hipaa=True)
        backend = _FakeBackend()
        idx = SentMailIndex(
            conn, acct_id,
            embedding_backend=backend,
            embedding_model=EMBED_MODEL_FIXTURE,
        )
        await idx.index_message(_msg(
            "anything", rfc_id="<phi1@example.com>",
        ))
        # No row written; backend never called.
        rows = conn.execute(
            "SELECT COUNT(*) FROM sent_mail_index"
        ).fetchone()
        assert rows[0] == 0
        assert backend.calls == []

    async def test_retrieve_similar_returns_empty_on_hipaa_even_with_rows(self):
        """Defence in depth: a non-HIPAA account that gets flipped to
        HIPAA after rows already exist must not surface those rows.
        """
        conn = _make_db()
        # Index BEFORE flipping the flag so rows exist.
        acct_id = _seed_account(conn, hipaa=False)
        backend = _FakeBackend()
        idx = SentMailIndex(
            conn, acct_id,
            embedding_backend=backend,
            embedding_model=EMBED_MODEL_FIXTURE,
        )
        await idx.index_message(_msg(
            "preflip reply", rfc_id="<pre@example.com>",
        ))
        # Sanity: the row exists.
        n = conn.execute(
            "SELECT COUNT(*) FROM sent_mail_index"
        ).fetchone()[0]
        assert n == 1
        # Flip the account to HIPAA.
        conn.execute(
            "UPDATE email_accounts SET hipaa = 1 WHERE id = ?",
            (acct_id,),
        )
        conn.commit()
        # retrieve_similar must now refuse.
        hits = await idx.retrieve_similar("preflip reply")
        assert hits == []

    async def test_index_recent_skipped_on_hipaa(self):
        conn = _make_db()
        acct_id = _seed_account(conn, hipaa=True)
        backend = _FakeBackend()
        # Provider that would error if called -- the HIPAA gate must
        # short-circuit BEFORE any provider IO.
        provider = AsyncMock()
        provider.search.side_effect = AssertionError(
            "provider.search must not be called on HIPAA accounts",
        )
        idx = SentMailIndex(
            conn, acct_id,
            embedding_backend=backend,
            embedding_model=EMBED_MODEL_FIXTURE,
            provider=provider,
        )
        n = await idx.index_recent(limit=10)
        assert n == 0
        provider.search.assert_not_called()

    async def test_privacy_invariant_hipaa_never_calls_backend(self):
        """Pin the privacy invariant: a HIPAA account flowing through
        any public method on SentMailIndex MUST NOT invoke the
        embedding backend. We monkey-patch ``embed_text`` to RAISE on
        call; if any path forgets the gate the test fails loudly.

        This is the test specifically called out in the M-4 task
        spec under "Privacy invariant".
        """
        conn = _make_db()
        acct_id = _seed_account(conn, hipaa=True)

        class _RaisingBackend:
            backend_type = "ollama"

            async def embed_text(self, text: str) -> list[float]:
                raise AssertionError(
                    "embed_text must not be called on a HIPAA account",
                )

        backend = _RaisingBackend()
        idx = SentMailIndex(
            conn, acct_id,
            embedding_backend=backend,
            embedding_model=EMBED_MODEL_FIXTURE,
        )
        # Each public method must short-circuit before touching backend.
        await idx.index_message(_msg(
            "anything", rfc_id="<phi-raise@example.com>",
        ))
        hits = await idx.retrieve_similar("anything")
        assert hits == []
        # delete_account_index does NOT call the backend either, but
        # is intentionally NOT HIPAA-gated (the post-flip cleanup
        # path must work). Verify it doesn't error.
        idx.delete_account_index()


# ---------------------------------------------------------------------------
# Idempotency + delete
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestIdempotencyAndDelete:
    async def test_index_message_is_idempotent(self):
        conn = _make_db()
        acct_id = _seed_account(conn)
        backend = _FakeBackend()
        idx = SentMailIndex(
            conn, acct_id,
            embedding_backend=backend,
            embedding_model=EMBED_MODEL_FIXTURE,
        )
        msg = _msg(
            "first reply", uid="u1", rfc_id="<dup@example.com>",
        )
        await idx.index_message(msg)
        await idx.index_message(msg)
        n = conn.execute(
            "SELECT COUNT(*) FROM sent_mail_index"
        ).fetchone()[0]
        assert n == 1
        # The dedup hit short-circuits BEFORE the embed call -- no
        # second backend invocation.
        assert len(backend.calls) == 1

    async def test_index_recent_idempotent_via_provider(self):
        """Re-running ``index_recent`` over the same provider snapshot
        produces zero new rows on the second pass.
        """
        conn = _make_db()
        acct_id = _seed_account(conn)
        backend = _FakeBackend()

        # Stub provider that returns 3 fixed messages.
        ids = ["u1", "u2", "u3"]
        msgs = {
            "u1": _msg("alpha", uid="u1", rfc_id="<a@example.com>"),
            "u2": _msg("beta", uid="u2", rfc_id="<b@example.com>"),
            "u3": _msg("gamma", uid="u3", rfc_id="<c@example.com>"),
        }

        class _StubProvider:
            async def search(self, query, limit):
                return list(ids)

            async def fetch_message(self, mid, **_kw):
                return msgs[mid]

        idx = SentMailIndex(
            conn, acct_id,
            embedding_backend=backend,
            embedding_model=EMBED_MODEL_FIXTURE,
            provider=_StubProvider(),
        )
        first = await idx.index_recent(limit=10)
        assert first == 3
        second = await idx.index_recent(limit=10)
        assert second == 0
        n = conn.execute(
            "SELECT COUNT(*) FROM sent_mail_index"
        ).fetchone()[0]
        assert n == 3

    async def test_delete_removes_account_rows_only(self):
        conn = _make_db()
        a_id = _seed_account(conn, name="Operator A")
        b_id = _seed_account(conn, name="Operator B")
        backend = _FakeBackend()
        idx_a = SentMailIndex(
            conn, a_id,
            embedding_backend=backend,
            embedding_model=EMBED_MODEL_FIXTURE,
        )
        idx_b = SentMailIndex(
            conn, b_id,
            embedding_backend=backend,
            embedding_model=EMBED_MODEL_FIXTURE,
        )
        await idx_a.index_message(_msg(
            "a-reply", rfc_id="<a@example.com>",
        ))
        await idx_b.index_message(_msg(
            "b-reply", rfc_id="<b@example.com>",
        ))
        deleted = idx_a.delete_account_index()
        assert deleted == 1
        # B's rows are untouched.
        n_b = conn.execute(
            "SELECT COUNT(*) FROM sent_mail_index WHERE account_id = ?",
            (b_id,),
        ).fetchone()[0]
        assert n_b == 1
        n_a = conn.execute(
            "SELECT COUNT(*) FROM sent_mail_index WHERE account_id = ?",
            (a_id,),
        ).fetchone()[0]
        assert n_a == 0


# ---------------------------------------------------------------------------
# In-memory cosine fallback (sqlite-vec unavailable)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestSqliteVecFallback:
    async def test_retrieval_works_with_extension_unavailable(self):
        """Pin the install-without-extension behaviour. The scaffold
        retrieves via in-memory cosine over the rows in the canonical
        table -- the extension fast-path is opt-in. With
        ``sqlite_vec_available=False``, retrieval must still return
        ranked results.
        """
        conn = _make_db()
        acct_id = _seed_account(conn)
        backend = _FakeBackend()
        idx = SentMailIndex(
            conn, acct_id,
            embedding_backend=backend,
            embedding_model=EMBED_MODEL_FIXTURE,
            sqlite_vec_available=False,
        )
        await idx.index_message(_msg(
            "alpha message", uid="u1", rfc_id="<f1@example.com>",
        ))
        await idx.index_message(_msg(
            "totally different topic", uid="u2",
            rfc_id="<f2@example.com>",
            subject="Re: misc",
        ))
        hits = await idx.retrieve_similar("alpha", top_k=1)
        assert len(hits) == 1
        assert hits[0]["message_id"] == "u1"


# ---------------------------------------------------------------------------
# Migration v15 -- precomputed embedding_norm column (#136)
# ---------------------------------------------------------------------------

class TestMigrationV15:
    """Pin the v15 contract: column add + backfill + idempotency.

    The numpy cosine fast path in ``retrieve_similar`` reads
    ``embedding_norm`` instead of recomputing it on every call --
    seconds-per-draft-reply on a 10k row corpus. v15 adds the column
    + backfills it for installs that already have rows.
    """

    def _v12_only_db(self) -> sqlite3.Connection:
        """Bring up a sent_mail_index pre-v15: v12 (table) + v14
        (is_captured_pair) only. Used to seed rows that pre-date v15
        so the backfill has work to do.
        """
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        conn.execute(
            "CREATE TABLE email_accounts (id INTEGER PRIMARY KEY)"
        )
        from email_triage.web.migrations import MIGRATIONS
        for v in (12, 14):
            m = next(mi for mi in MIGRATIONS if mi.version == v)
            m.body(conn)
        conn.commit()
        return conn

    def test_v15_adds_embedding_norm_column(self):
        conn = self._v12_only_db()
        # Sanity: column does NOT exist pre-v15.
        cols_before = {row[1] for row in conn.execute(
            "PRAGMA table_info(sent_mail_index)"
        ).fetchall()}
        assert "embedding_norm" not in cols_before
        from email_triage.web.migrations import MIGRATIONS
        v15 = next(m for m in MIGRATIONS if m.version == 15)
        v15.body(conn)
        cols_after = {row[1] for row in conn.execute(
            "PRAGMA table_info(sent_mail_index)"
        ).fetchall()}
        assert "embedding_norm" in cols_after

    def test_v15_backfills_norm_from_existing_blob(self):
        """Seed a pre-v15 row with a known vector. Run v15. The
        embedding_norm column must equal ``math.sqrt(sum(x*x))`` of
        the unpacked vector, not 0.0.
        """
        import math as _math
        conn = self._v12_only_db()
        # Pre-v15: insert a row WITHOUT the norm column.
        vec = [0.6, 0.8, 0.0, 0.0]  # exact L2 norm = 1.0
        blob = struct.pack(f"<{len(vec)}f", *vec)
        now = "2026-05-09T12:00:00+00:00"
        conn.execute(
            "INSERT INTO sent_mail_index ("
            "account_id, message_id, rfc_message_id, sent_at, "
            "to_addresses, subject, body_excerpt, embedding_vec, "
            "embedding_model, indexed_at"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (1, "u1", "<r1@example.com>", now, "[]", "s",
             "b", blob, "m", now),
        )
        # A second row with a different vector to verify per-row math.
        vec2 = [3.0, 4.0, 0.0, 0.0]  # L2 norm = 5.0
        blob2 = struct.pack(f"<{len(vec2)}f", *vec2)
        conn.execute(
            "INSERT INTO sent_mail_index ("
            "account_id, message_id, rfc_message_id, sent_at, "
            "to_addresses, subject, body_excerpt, embedding_vec, "
            "embedding_model, indexed_at"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (1, "u2", "<r2@example.com>", now, "[]", "s",
             "b", blob2, "m", now),
        )
        conn.commit()

        from email_triage.web.migrations import MIGRATIONS
        v15 = next(m for m in MIGRATIONS if m.version == 15)
        v15.body(conn)

        rows = conn.execute(
            "SELECT message_id, embedding_norm "
            "FROM sent_mail_index ORDER BY message_id"
        ).fetchall()
        assert len(rows) == 2
        # Row 1: norm == sqrt(0.36 + 0.64) == 1.0
        assert rows[0]["message_id"] == "u1"
        assert rows[0]["embedding_norm"] == pytest.approx(1.0, rel=1e-5)
        # Row 2: norm == sqrt(9 + 16) == 5.0
        assert rows[1]["message_id"] == "u2"
        assert rows[1]["embedding_norm"] == pytest.approx(5.0, rel=1e-5)

    def test_v15_idempotent_on_second_run(self):
        """Re-running v15 must not double-write or error. The body
        skips rows where embedding_norm > 0.0 already.
        """
        conn = self._v12_only_db()
        vec = [3.0, 4.0]  # norm = 5.0
        blob = struct.pack(f"<{len(vec)}f", *vec)
        now = "2026-05-09T12:00:00+00:00"
        conn.execute(
            "INSERT INTO sent_mail_index ("
            "account_id, message_id, rfc_message_id, sent_at, "
            "to_addresses, subject, body_excerpt, embedding_vec, "
            "embedding_model, indexed_at"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (1, "u1", "<r1@example.com>", now, "[]", "s",
             "b", blob, "m", now),
        )
        conn.commit()
        from email_triage.web.migrations import MIGRATIONS
        v15 = next(m for m in MIGRATIONS if m.version == 15)
        # First run: backfills.
        v15.body(conn)
        norm_after_first = conn.execute(
            "SELECT embedding_norm FROM sent_mail_index WHERE message_id = ?",
            ("u1",),
        ).fetchone()["embedding_norm"]
        assert norm_after_first == pytest.approx(5.0, rel=1e-5)
        # Second run: must be a no-op (no error, value unchanged).
        v15.body(conn)
        norm_after_second = conn.execute(
            "SELECT embedding_norm FROM sent_mail_index WHERE message_id = ?",
            ("u1",),
        ).fetchone()["embedding_norm"]
        assert norm_after_second == pytest.approx(5.0, rel=1e-5)

    def test_v15_skips_corrupt_or_empty_blobs(self):
        """A row with NULL / empty / unaligned blob is left at the
        column default (0.0). Defensive: a corrupt write must not
        abort the migration of every other row.
        """
        conn = self._v12_only_db()
        now = "2026-05-09T12:00:00+00:00"
        # Row 1: NULL blob.
        conn.execute(
            "INSERT INTO sent_mail_index ("
            "account_id, message_id, rfc_message_id, sent_at, "
            "to_addresses, subject, body_excerpt, embedding_vec, "
            "embedding_model, indexed_at"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (1, "null", "<n@example.com>", now, "[]", "s",
             "b", None, "m", now),
        )
        # Row 2: empty blob.
        conn.execute(
            "INSERT INTO sent_mail_index ("
            "account_id, message_id, rfc_message_id, sent_at, "
            "to_addresses, subject, body_excerpt, embedding_vec, "
            "embedding_model, indexed_at"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (1, "empty", "<e@example.com>", now, "[]", "s",
             "b", b"", "m", now),
        )
        # Row 3: 7-byte (unaligned) blob.
        conn.execute(
            "INSERT INTO sent_mail_index ("
            "account_id, message_id, rfc_message_id, sent_at, "
            "to_addresses, subject, body_excerpt, embedding_vec, "
            "embedding_model, indexed_at"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (1, "bad", "<b@example.com>", now, "[]", "s",
             "b", b"\x01\x02\x03\x04\x05\x06\x07", "m", now),
        )
        # Row 4: a valid vector.
        vec = [3.0, 4.0]
        blob = struct.pack(f"<{len(vec)}f", *vec)
        conn.execute(
            "INSERT INTO sent_mail_index ("
            "account_id, message_id, rfc_message_id, sent_at, "
            "to_addresses, subject, body_excerpt, embedding_vec, "
            "embedding_model, indexed_at"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (1, "ok", "<o@example.com>", now, "[]", "s",
             "b", blob, "m", now),
        )
        conn.commit()
        from email_triage.web.migrations import MIGRATIONS
        v15 = next(m for m in MIGRATIONS if m.version == 15)
        v15.body(conn)  # must not raise
        rows = {
            r["message_id"]: r["embedding_norm"]
            for r in conn.execute(
                "SELECT message_id, embedding_norm FROM sent_mail_index"
            ).fetchall()
        }
        # Corrupt rows stay at the default 0.0 (skipped, not aborted).
        assert rows["null"] == 0.0
        assert rows["empty"] == 0.0
        assert rows["bad"] == 0.0
        assert rows["ok"] == pytest.approx(5.0, rel=1e-5)


# ---------------------------------------------------------------------------
# index_message writes the precomputed norm (#136)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestIndexMessageWritesNorm:
    async def test_norm_matches_math_sqrt_of_vec(self):
        """A row written via :meth:`SentMailIndex.index_message` carries
        an ``embedding_norm`` equal to ``math.sqrt(sum(x*x))`` of the
        backend-returned vector. Locks the contract that retrieval can
        rely on the column being populated for fresh writes.
        """
        import math as _math
        conn = _make_db()
        acct_id = _seed_account(conn)

        class _FixedVecBackend:
            backend_type = "ollama"

            def __init__(self) -> None:
                self.calls = 0

            async def embed_text(self, text):
                self.calls += 1
                # Pythagorean triple -> norm = 5.0
                return [3.0, 4.0]

        backend = _FixedVecBackend()
        idx = SentMailIndex(
            conn, acct_id,
            embedding_backend=backend,
            embedding_model=EMBED_MODEL_FIXTURE,
        )
        await idx.index_message(_msg(
            "any body text", uid="u1", rfc_id="<n1@example.com>",
        ))
        row = conn.execute(
            "SELECT embedding_norm, embedding_vec FROM sent_mail_index"
        ).fetchone()
        assert row is not None
        # Norm matches sqrt(9 + 16) = 5.0.
        assert row["embedding_norm"] == pytest.approx(5.0, rel=1e-5)
        # And consistent with the unpacked vec for belt + suspenders.
        unpacked = _unpack_vec(row["embedding_vec"])
        recomputed = _math.sqrt(sum(x * x for x in unpacked))
        assert row["embedding_norm"] == pytest.approx(recomputed, rel=1e-5)


# ---------------------------------------------------------------------------
# Numpy retrieve_similar ordering matches pre-numpy implementation (#136)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestNumpyRetrievalOrderingEquivalence:
    """The numpy cosine fast path must rank rows identically to the
    pure-Python ``_cosine`` reference. This is the regression guard
    against silent ranking drift when the implementation switched.
    """

    async def test_ordering_matches_pure_python_reference(self):
        """Build a corpus of rows with deterministic vectors, query
        with a known qvec, then compute the expected ranking via the
        pure-Python ``_cosine`` helper and assert ``retrieve_similar``
        returns the same order.

        Captured-pair boost (1.3x) is part of the contract -- one
        row in the fixture is captured so we exercise the boosted
        ordering path.
        """
        conn = _make_db()
        acct_id = _seed_account(conn)

        # Backend that returns a vector deterministically derived from
        # the input. Same input -> same vec; different bodies produce
        # vectors with different cosine distance to a fixed qvec.
        class _VectoredBackend:
            backend_type = "ollama"

            def __init__(self) -> None:
                self._table = {
                    "alpha\n\nbody alpha": [1.0, 0.0, 0.0, 0.0],
                    "beta\n\nbody beta":  [0.9, 0.1, 0.0, 0.0],
                    "gamma\n\nbody gamma": [0.5, 0.5, 0.5, 0.5],
                    "delta\n\nbody delta": [0.0, 0.0, 1.0, 0.0],
                    "QUERY": [1.0, 0.05, 0.0, 0.0],
                }

            async def embed_text(self, text):
                return list(self._table.get(text, [0.1, 0.1, 0.1, 0.1]))

        backend = _VectoredBackend()
        idx = SentMailIndex(
            conn, acct_id,
            embedding_backend=backend,
            embedding_model=EMBED_MODEL_FIXTURE,
        )
        # Index four messages. Mark "delta" as a captured pair so the
        # boost is exercised.
        await idx.index_message(
            _msg("body alpha", uid="u-alpha",
                 rfc_id="<a@example.com>", subject="alpha"),
        )
        await idx.index_message(
            _msg("body beta", uid="u-beta",
                 rfc_id="<b@example.com>", subject="beta"),
        )
        await idx.index_message(
            _msg("body gamma", uid="u-gamma",
                 rfc_id="<g@example.com>", subject="gamma"),
        )
        await idx.index_message(
            _msg("body delta", uid="u-delta",
                 rfc_id="<d@example.com>", subject="delta"),
            is_captured_pair=True,
        )

        # Compute the expected ranking via the pure-Python reference.
        from email_triage.actions.sent_mail_index import (
            _CAPTURED_PAIR_BOOST,
            _cosine,
            _unpack_vec,
        )
        qvec = await backend.embed_text("QUERY")
        rows = conn.execute(
            "SELECT id, message_id, embedding_vec, is_captured_pair "
            "FROM sent_mail_index"
        ).fetchall()
        scored = []
        for r in rows:
            cand = _unpack_vec(r["embedding_vec"])
            sim = _cosine(qvec, cand)
            boost = _CAPTURED_PAIR_BOOST if r["is_captured_pair"] else 1.0
            scored.append((sim * boost, r["message_id"]))
        scored.sort(key=lambda t: t[0], reverse=True)
        expected_order = [mid for _s, mid in scored]

        hits = await idx.retrieve_similar("QUERY", top_k=4)
        assert [h["message_id"] for h in hits] == expected_order

    async def test_similarity_field_is_unboosted_cosine(self):
        """The ``similarity`` field on each entry surfaces the raw
        unboosted cosine -- the captured-pair boost is a ranking
        detail, not the canonical similarity score. Locks the M-7+M-6
        merge contract from 2026-05-09.
        """
        conn = _make_db()
        acct_id = _seed_account(conn)

        class _ConstBackend:
            backend_type = "ollama"

            async def embed_text(self, text):
                return [1.0, 0.0]  # parallel to query -> cos = 1.0

        idx = SentMailIndex(
            conn, acct_id,
            embedding_backend=_ConstBackend(),
            embedding_model=EMBED_MODEL_FIXTURE,
        )
        # General + captured rows with identical vec.
        await idx.index_message(
            _msg("general body", uid="g1",
                 rfc_id="<g1@example.com>", subject="g"),
        )
        await idx.index_message(
            _msg("captured body", uid="c1",
                 rfc_id="<c1@example.com>", subject="c"),
            is_captured_pair=True,
        )
        hits = await idx.retrieve_similar("query", top_k=2)
        # Captured ranks first because of the boost...
        assert hits[0]["is_captured_pair"] is True
        # ...but its surfaced similarity is the raw 1.0, not 1.3.
        assert hits[0]["similarity"] == pytest.approx(1.0, rel=1e-5)
        assert hits[1]["similarity"] == pytest.approx(1.0, rel=1e-5)
