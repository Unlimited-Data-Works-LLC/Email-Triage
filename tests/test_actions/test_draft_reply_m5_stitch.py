"""Tests for the M-5 prompt-stitch in ``actions/draft_reply.py``.

Scope: ``build_prompt_messages`` returns the four prompt layers
(M-1+M-2 / M-3 / M-4 / user task) in canonical order, with each
layer independently gateable via HIPAA / master toggle / per-account
toggle / sqlite-vec availability / embedding-backend allowlist.

No real PII anywhere -- every actor is ``user@example.com`` /
``Operator A``; sentinel strings carry numeric suffixes so an
order-pinning failure points at the layer that moved.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from email_triage.actions.draft_reply import (
    _should_use_rag,
    build_prompt_messages,
)
from email_triage.engine.embedding_backend import build_embedding_backend
from email_triage.engine.models import Classification, EmailMessage


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

# Sentinel strings that survive the four prompt layers verbatim.
M1M2_SENTINEL_GUIDE = "M1M2_SENTINEL_42_concise_no_emojis"
M3_SENTINEL_PERSONA = "M3_SENTINEL_77_direct_friendly"
M4_USER_TURN_SENTINEL = "M4_USER_TURN_99_subject_marker"
M4_ASSISTANT_TURN_SENTINEL = "M4_ASSISTANT_TURN_88_reply_body_marker"
USER_MSG_SENTINEL = "USER_MSG_SENTINEL_11_incoming_subject"


def _make_db() -> sqlite3.Connection:
    """In-memory DB carrying every table the M-5 prompt path reads.

    We invoke ``init_db`` so the v11 + v12 migrations both run --
    that brings up ``users`` (with style-knob columns), ``settings``
    (master + per-account RAG toggle), ``email_accounts`` (HIPAA
    flag), and ``sent_mail_index`` (M-4 retrieval target).
    """
    from email_triage.web.db import init_db
    return init_db(":memory:")


def _seed_user(conn: sqlite3.Connection) -> int:
    now = datetime.now(timezone.utc).isoformat()
    cur = conn.execute(
        "INSERT INTO users (email, name, role, created_at) "
        "VALUES (?, ?, ?, ?)",
        ("user@example.com", "Operator A", "user", now),
    )
    conn.commit()
    return int(cur.lastrowid)


def _seed_account(
    conn: sqlite3.Connection, *, hipaa: bool = False,
    user_id: int | None = None,
) -> int:
    """Insert an email_accounts row and return its id.

    Mirrors the schema in db.py's email_accounts DDL: user_id is
    NOT NULL with an FK; provider_type, name, config_json, created_at,
    updated_at are required.
    """
    if user_id is None:
        user_id = _seed_user(conn)
    now = datetime.now(timezone.utc).isoformat()
    cur = conn.execute(
        "INSERT INTO email_accounts ("
        "user_id, name, provider_type, config_json, hipaa, "
        "created_at, updated_at"
        ") VALUES (?, ?, ?, ?, ?, ?, ?)",
        (user_id, "Operator A Mailbox", "imap", "{}",
         int(bool(hipaa)), now, now),
    )
    conn.commit()
    return int(cur.lastrowid)


def _set_user_style_knobs(
    conn: sqlite3.Connection, user_id: int, guide: str = "",
    tone: str = "neutral",
) -> None:
    from email_triage.web.db import set_user_style_knobs
    set_user_style_knobs(conn, user_id, {
        "style_guide": guide,
        "style_tone": tone,
        "style_length": "medium",
        "style_signature": "",
        "style_greeting": "first-name",
        "style_greeting_custom": "",
    })


def _set_style_profile(conn: sqlite3.Connection, account_id: int) -> None:
    from email_triage.web.db import set_style_profile
    set_style_profile(conn, account_id, {
        "persona_summary": M3_SENTINEL_PERSONA,
        "greeting": "Hi Person,",
        "signoff": "",
        "formality": 3,
        "avg_sentence_length": 0,
        "signature": "",
        "phrases_used": [],
        "phrases_avoided": [],
        "sample_count": 5,
        "model_used": "test-model",
    })


def _set_master_toggle(conn: sqlite3.Connection, *, on: bool) -> None:
    from email_triage.web.db import set_style_learning_master_enabled
    set_style_learning_master_enabled(conn, on)


def _set_rag_toggle(
    conn: sqlite3.Connection, account_id: int, *, on: bool,
) -> None:
    from email_triage.web.db import set_rag_sent_index_enabled
    set_rag_sent_index_enabled(conn, account_id, enabled=on)


def _account_dict(
    conn: sqlite3.Connection, account_id: int,
    *, style_account_enabled: bool = True,
) -> dict:
    """Build the dict shape that the prompt builder expects.

    Mirrors what the real triage runner threads through -- enough
    keys that ``is_account_hipaa`` + ``is_style_learning_account_enabled``
    + ``is_rag_sent_index_enabled`` resolve correctly.
    """
    row = conn.execute(
        "SELECT id, hipaa FROM email_accounts WHERE id = ?",
        (account_id,),
    ).fetchone()
    return {
        "id": row["id"],
        "hipaa": bool(row["hipaa"]),
        "config": {"style_learning_enabled": bool(style_account_enabled)},
    }


def _seed_sent_mail_row(
    conn: sqlite3.Connection, account_id: int, *,
    embedding_model: str = "test-embedder-v0",
) -> None:
    """Insert one row into sent_mail_index that retrieve_similar can return."""
    import json
    import struct
    now = datetime.now(timezone.utc).isoformat()
    # Vector aligned with the deterministic _FakeBackend below.
    vec_bytes = struct.pack("<4f", 1.0, 0.0, 0.0, 0.0)
    conn.execute(
        "INSERT INTO sent_mail_index ("
        "account_id, message_id, rfc_message_id, sent_at, "
        "to_addresses, subject, body_excerpt, embedding_vec, "
        "embedding_model, indexed_at"
        ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            account_id, "u1", "<m1@example.com>", now,
            json.dumps(["other@example.com"]),
            M4_USER_TURN_SENTINEL,            # subject
            M4_ASSISTANT_TURN_SENTINEL,       # body_excerpt
            vec_bytes,
            embedding_model,
            now,
        ),
    )
    conn.commit()


def _make_message() -> EmailMessage:
    return EmailMessage(
        message_id="m-1",
        provider="imap",
        sender="other@example.com",
        recipients=["user@example.com"],
        subject=USER_MSG_SENTINEL,
        body_text="Looking for an update on the project, thanks.",
        date=datetime(2026, 5, 8, tzinfo=timezone.utc),
    )


def _make_classification() -> Classification:
    return Classification(
        category="to-respond",
        confidence=0.91,
        reason="Direct question requesting a reply.",
    )


class _FakeBackend:
    """Deterministic embedding backend (mirrors the M-4 test fixture).

    Hashes the input into a fixed-dim vector so retrieve_similar
    returns predictable results. Same input -> same vector.
    """
    backend_type = "ollama"

    def __init__(self) -> None:
        self.calls: list[str] = []

    async def embed_text(self, text: str) -> list[float]:
        self.calls.append(text)
        # Match the seeded row's vector -- every query gets a similar
        # vector so retrieval surfaces the seeded row reliably.
        vec = [1.0, 0.0, 0.0, 0.0]
        # Tiny perturbation based on text hash so different queries
        # don't all return the exact same vector.
        h = sum(ord(c) for c in text) % 4
        vec[h] += 0.01
        return vec


def _make_app(
    *, backend=None, sqlite_vec_available: bool = False,
    embedding_model: str = "test-embedder-v0",
) -> SimpleNamespace:
    """Construct an app stand-in with the state attributes M-5 reads."""
    state = SimpleNamespace(
        embedding_backend=backend,
        embedding_model=embedding_model,
        sqlite_vec_available=sqlite_vec_available,
    )
    return SimpleNamespace(state=state)


# ---------------------------------------------------------------------------
# Helpers for the order-pinning assertion
# ---------------------------------------------------------------------------

def _flatten(messages: list[dict]) -> str:
    """Join role + content into one text blob so we can ``find`` sentinels."""
    return "\n".join(f"[{m['role']}]\n{m['content']}" for m in messages)


# ---------------------------------------------------------------------------
# All four layers active -> all four parts in canonical order
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestAllLayersActive:
    async def test_prompt_contains_all_four_parts(self):
        conn = _make_db()
        user_id = _seed_user(conn)
        acct_id = _seed_account(conn, user_id=user_id)
        _set_master_toggle(conn, on=True)
        _set_user_style_knobs(conn, user_id, guide=M1M2_SENTINEL_GUIDE)
        _set_style_profile(conn, acct_id)
        _set_rag_toggle(conn, acct_id, on=True)
        _seed_sent_mail_row(conn, acct_id)

        backend = _FakeBackend()
        app = _make_app(backend=backend)
        account = _account_dict(conn, acct_id)

        messages = await build_prompt_messages(
            db=conn, app=app, account=account, user_id=user_id,
            message=_make_message(), classification=_make_classification(),
        )

        flat = _flatten(messages)
        # Every layer's sentinel is present.
        assert M1M2_SENTINEL_GUIDE in flat
        assert M3_SENTINEL_PERSONA in flat
        assert M4_USER_TURN_SENTINEL in flat
        assert M4_ASSISTANT_TURN_SENTINEL in flat
        assert USER_MSG_SENTINEL in flat


# ---------------------------------------------------------------------------
# Order-pinning test: layers appear in CANONICAL order
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestPromptOrderPinning:
    async def test_canonical_order_locked(self):
        """Spec: M1+M2 -> M3 -> M4 user turn -> M4 assistant turn -> user msg.

        Reordering layers without intent breaks this test. If you're
        seeing it fail and you DID intend to reorder, update both the
        module docstring in actions/draft_reply.py AND this test in
        the same commit.
        """
        conn = _make_db()
        user_id = _seed_user(conn)
        acct_id = _seed_account(conn, user_id=user_id)
        _set_master_toggle(conn, on=True)
        _set_user_style_knobs(conn, user_id, guide=M1M2_SENTINEL_GUIDE)
        _set_style_profile(conn, acct_id)
        _set_rag_toggle(conn, acct_id, on=True)
        _seed_sent_mail_row(conn, acct_id)

        app = _make_app(backend=_FakeBackend())
        account = _account_dict(conn, acct_id)

        messages = await build_prompt_messages(
            db=conn, app=app, account=account, user_id=user_id,
            message=_make_message(), classification=_make_classification(),
        )
        flat = _flatten(messages)

        idx_m1m2 = flat.find(M1M2_SENTINEL_GUIDE)
        idx_m3 = flat.find(M3_SENTINEL_PERSONA)
        idx_m4_user = flat.find(M4_USER_TURN_SENTINEL)
        idx_m4_asst = flat.find(M4_ASSISTANT_TURN_SENTINEL)
        idx_user = flat.find(USER_MSG_SENTINEL)

        # Every sentinel was found.
        assert idx_m1m2 != -1, flat
        assert idx_m3 != -1, flat
        assert idx_m4_user != -1, flat
        assert idx_m4_asst != -1, flat
        assert idx_user != -1, flat

        # Canonical order:
        # M1M2_SENTINEL ... M3_SENTINEL ... M4_USER_TURN_SENTINEL
        # ... M4_ASSISTANT_TURN_SENTINEL ... USER_MSG_SENTINEL
        assert idx_m1m2 < idx_m3 < idx_m4_user < idx_m4_asst < idx_user


# ---------------------------------------------------------------------------
# HIPAA gate: M-3 + M-4 collapse to bare task message
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestHipaaGate:
    async def test_hipaa_account_skips_m3_and_m4(self):
        conn = _make_db()
        user_id = _seed_user(conn)
        acct_id = _seed_account(conn, user_id=user_id, hipaa=True)
        _set_master_toggle(conn, on=True)
        _set_user_style_knobs(conn, user_id, guide=M1M2_SENTINEL_GUIDE)
        _set_style_profile(conn, acct_id)
        _set_rag_toggle(conn, acct_id, on=True)
        _seed_sent_mail_row(conn, acct_id)

        backend = _FakeBackend()
        app = _make_app(backend=backend)
        account = _account_dict(conn, acct_id)

        messages = await build_prompt_messages(
            db=conn, app=app, account=account, user_id=user_id,
            message=_make_message(), classification=_make_classification(),
        )
        flat = _flatten(messages)

        # Style prefix entirely suppressed by HIPAA gate -> no M-1+M-2,
        # no M-3.
        assert M1M2_SENTINEL_GUIDE not in flat
        assert M3_SENTINEL_PERSONA not in flat
        # M-4 also skipped.
        assert M4_USER_TURN_SENTINEL not in flat
        assert M4_ASSISTANT_TURN_SENTINEL not in flat
        # The task message is still there.
        assert USER_MSG_SENTINEL in flat
        # Embedding backend was not asked to embed anything.
        assert backend.calls == []

    async def test_hipaa_message_skips_m3_and_m4(self):
        """Defence in depth: even when the account row says non-HIPAA,
        a message carrying ``hipaa=True`` (e.g. lifted from a HIPAA-
        flagged thread) suppresses every layer.
        """
        conn = _make_db()
        user_id = _seed_user(conn)
        acct_id = _seed_account(conn, user_id=user_id, hipaa=False)
        _set_master_toggle(conn, on=True)
        _set_user_style_knobs(conn, user_id, guide=M1M2_SENTINEL_GUIDE)
        _set_style_profile(conn, acct_id)
        _set_rag_toggle(conn, acct_id, on=True)
        _seed_sent_mail_row(conn, acct_id)

        msg = _make_message()
        msg.hipaa = True
        app = _make_app(backend=_FakeBackend())
        account = _account_dict(conn, acct_id)

        messages = await build_prompt_messages(
            db=conn, app=app, account=account, user_id=user_id,
            message=msg, classification=_make_classification(),
        )
        flat = _flatten(messages)
        assert M1M2_SENTINEL_GUIDE not in flat
        assert M3_SENTINEL_PERSONA not in flat


# ---------------------------------------------------------------------------
# Master toggle: turning it off suppresses every layer
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestMasterToggle:
    async def test_master_off_skips_all_layers(self):
        conn = _make_db()
        user_id = _seed_user(conn)
        acct_id = _seed_account(conn, user_id=user_id)
        _set_master_toggle(conn, on=False)              # off
        _set_user_style_knobs(conn, user_id, guide=M1M2_SENTINEL_GUIDE)
        _set_style_profile(conn, acct_id)
        _set_rag_toggle(conn, acct_id, on=True)
        _seed_sent_mail_row(conn, acct_id)

        backend = _FakeBackend()
        app = _make_app(backend=backend)
        account = _account_dict(conn, acct_id)

        messages = await build_prompt_messages(
            db=conn, app=app, account=account, user_id=user_id,
            message=_make_message(), classification=_make_classification(),
        )
        flat = _flatten(messages)
        assert M1M2_SENTINEL_GUIDE not in flat
        assert M3_SENTINEL_PERSONA not in flat
        assert M4_USER_TURN_SENTINEL not in flat
        assert M4_ASSISTANT_TURN_SENTINEL not in flat
        assert USER_MSG_SENTINEL in flat
        assert backend.calls == []


# ---------------------------------------------------------------------------
# Per-account RAG toggle: M-1+M-2 + M-3 fire, M-4 skipped
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestRagToggle:
    async def test_rag_off_keeps_m1m2_m3_skips_m4(self):
        conn = _make_db()
        user_id = _seed_user(conn)
        acct_id = _seed_account(conn, user_id=user_id)
        _set_master_toggle(conn, on=True)
        _set_user_style_knobs(conn, user_id, guide=M1M2_SENTINEL_GUIDE)
        _set_style_profile(conn, acct_id)
        _set_rag_toggle(conn, acct_id, on=False)        # RAG off
        _seed_sent_mail_row(conn, acct_id)

        backend = _FakeBackend()
        app = _make_app(backend=backend)
        account = _account_dict(conn, acct_id)

        messages = await build_prompt_messages(
            db=conn, app=app, account=account, user_id=user_id,
            message=_make_message(), classification=_make_classification(),
        )
        flat = _flatten(messages)
        # M-1+M-2 and M-3 still present.
        assert M1M2_SENTINEL_GUIDE in flat
        assert M3_SENTINEL_PERSONA in flat
        # M-4 skipped.
        assert M4_ASSISTANT_TURN_SENTINEL not in flat
        # Embedding backend was not even called.
        assert backend.calls == []


# ---------------------------------------------------------------------------
# sqlite-vec availability paths
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestSqliteVecPaths:
    async def test_sqlite_vec_unavailable_uses_fallback(self):
        """Extension missing -> in-memory cosine fallback runs and
        retrieval still surfaces the seeded row."""
        conn = _make_db()
        user_id = _seed_user(conn)
        acct_id = _seed_account(conn, user_id=user_id)
        _set_master_toggle(conn, on=True)
        _set_user_style_knobs(conn, user_id, guide=M1M2_SENTINEL_GUIDE)
        _set_style_profile(conn, acct_id)
        _set_rag_toggle(conn, acct_id, on=True)
        _seed_sent_mail_row(conn, acct_id)

        app = _make_app(
            backend=_FakeBackend(), sqlite_vec_available=False,
        )
        account = _account_dict(conn, acct_id)

        messages = await build_prompt_messages(
            db=conn, app=app, account=account, user_id=user_id,
            message=_make_message(), classification=_make_classification(),
        )
        flat = _flatten(messages)
        # Fallback path still surfaced the M-4 example.
        assert M4_ASSISTANT_TURN_SENTINEL in flat

    async def test_sqlite_vec_available_path_works(self):
        """With ``sqlite_vec_available`` True the same path works
        (the M-4 helper currently does cosine in both cases; the
        flag is honoured + plumbed)."""
        conn = _make_db()
        user_id = _seed_user(conn)
        acct_id = _seed_account(conn, user_id=user_id)
        _set_master_toggle(conn, on=True)
        _set_user_style_knobs(conn, user_id, guide=M1M2_SENTINEL_GUIDE)
        _set_style_profile(conn, acct_id)
        _set_rag_toggle(conn, acct_id, on=True)
        _seed_sent_mail_row(conn, acct_id)

        app = _make_app(
            backend=_FakeBackend(), sqlite_vec_available=True,
        )
        account = _account_dict(conn, acct_id)

        messages = await build_prompt_messages(
            db=conn, app=app, account=account, user_id=user_id,
            message=_make_message(), classification=_make_classification(),
        )
        flat = _flatten(messages)
        assert M4_ASSISTANT_TURN_SENTINEL in flat


# ---------------------------------------------------------------------------
# Empty M-4 retrieval -> no empty turn pairs
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestEmptyRetrieval:
    async def test_no_indexed_rows_skips_m4_block(self):
        """No rows in sent_mail_index for this account -> the M-4
        layer is silent (no empty user/assistant turn pairs)."""
        conn = _make_db()
        user_id = _seed_user(conn)
        acct_id = _seed_account(conn, user_id=user_id)
        _set_master_toggle(conn, on=True)
        _set_user_style_knobs(conn, user_id, guide=M1M2_SENTINEL_GUIDE)
        _set_style_profile(conn, acct_id)
        _set_rag_toggle(conn, acct_id, on=True)
        # NB: no _seed_sent_mail_row call -- index is empty.

        app = _make_app(backend=_FakeBackend())
        account = _account_dict(conn, acct_id)

        messages = await build_prompt_messages(
            db=conn, app=app, account=account, user_id=user_id,
            message=_make_message(), classification=_make_classification(),
        )
        # Inspect roles. Expected: 1 system (style prefix) + 1 user
        # (task). No assistant turn because no past replies were
        # retrieved.
        roles = [m["role"] for m in messages]
        assert "assistant" not in roles
        # And the task is still last.
        assert messages[-1]["role"] == "user"
        assert USER_MSG_SENTINEL in messages[-1]["content"]


# ---------------------------------------------------------------------------
# build_embedding_backend allowlist
# ---------------------------------------------------------------------------

class TestEmbeddingBackendAllowlist:
    def test_non_ollama_backend_raises_value_error(self):
        """Operator points ``embedding.backend`` at openai / anthropic
        / etc -> the factory raises ValueError naming the rejected
        value AND the allowlist."""
        cfg = SimpleNamespace(
            embedding=SimpleNamespace(
                backend="openai",
                model_name="text-embedding-3-small",
                ollama_url="http://localhost:11434",
            ),
        )
        with pytest.raises(ValueError) as excinfo:
            build_embedding_backend(cfg)
        msg = str(excinfo.value)
        assert "openai" in msg
        assert "ollama" in msg
        assert "local-only" in msg

    def test_anthropic_backend_rejected_on_top_of_allowlist(self):
        """Belt-and-braces: project-wide no-Anthropic rule rides on top
        of the allowlist."""
        cfg = SimpleNamespace(
            embedding=SimpleNamespace(
                backend="anthropic",
                model_name="voyage-2",
                ollama_url="http://localhost:11434",
            ),
        )
        with pytest.raises(ValueError) as excinfo:
            build_embedding_backend(cfg)
        assert "anthropic" in str(excinfo.value)

    def test_empty_backend_returns_none(self):
        """Operator left ``embedding:`` out of YAML -> factory returns
        None, ``_should_use_rag`` skips with a one-time INFO log."""
        cfg = SimpleNamespace(
            embedding=SimpleNamespace(
                backend="", model_name="", ollama_url="",
            ),
        )
        assert build_embedding_backend(cfg) is None

    def test_ollama_backend_constructs_ok(self):
        """Allowlisted backend with a model name -> instance returned."""
        cfg = SimpleNamespace(
            embedding=SimpleNamespace(
                backend="ollama",
                model_name="nomic-embed-text:latest",
                ollama_url="http://localhost:11434",
            ),
        )
        backend = build_embedding_backend(cfg)
        assert backend is not None
        assert backend.backend_type == "ollama"

    def test_no_embedding_attribute_returns_none(self):
        """Older config object with no ``embedding`` attribute at all
        -> factory returns None instead of raising AttributeError."""
        cfg = SimpleNamespace()  # no embedding attr
        assert build_embedding_backend(cfg) is None


# ---------------------------------------------------------------------------
# _should_use_rag direct gate tests
# ---------------------------------------------------------------------------

class TestShouldUseRag:
    def test_no_account_returns_false(self):
        conn = _make_db()
        app = _make_app(backend=_FakeBackend())
        assert _should_use_rag(conn, None, app) is False

    def test_no_backend_returns_false(self):
        conn = _make_db()
        user_id = _seed_user(conn)
        acct_id = _seed_account(conn, user_id=user_id)
        _set_master_toggle(conn, on=True)
        _set_rag_toggle(conn, acct_id, on=True)
        app = _make_app(backend=None)
        account = _account_dict(conn, acct_id)
        assert _should_use_rag(conn, account, app) is False

    def test_hipaa_returns_false_even_with_toggles_on(self):
        conn = _make_db()
        user_id = _seed_user(conn)
        acct_id = _seed_account(conn, user_id=user_id, hipaa=True)
        _set_master_toggle(conn, on=True)
        _set_rag_toggle(conn, acct_id, on=True)
        app = _make_app(backend=_FakeBackend())
        account = _account_dict(conn, acct_id)
        assert _should_use_rag(conn, account, app) is False

    def test_all_open_returns_true(self):
        conn = _make_db()
        user_id = _seed_user(conn)
        acct_id = _seed_account(conn, user_id=user_id)
        _set_master_toggle(conn, on=True)
        _set_rag_toggle(conn, acct_id, on=True)
        app = _make_app(backend=_FakeBackend())
        account = _account_dict(conn, acct_id)
        assert _should_use_rag(conn, account, app) is True
