"""Privacy invariants for the M-series style-learning ladder (M-9).

This is the CI guard for M-1 through M-5: backend allowlists, HIPAA
hard-off behaviour, master toggle, per-account toggle. Every assert
site below pins a contract that, if loosened by a future commit,
should fail this test rather than silently relax the privacy posture.

No real PII anywhere -- ``user@example.com`` / ``Operator A`` only.
The fake embedding backend uses an abstract pinned model name.

Sibling modules:
  * tests/test_privacy_invariants_dep_review.py -- dep-list guard
  * tests/test_privacy_invariants_log_scrub.py  -- log scrub keys

See ``docs/privacy-audit-runbook.md`` for the full operator contract.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from email_triage.actions import sent_mail_index as sent_mail_index_mod
from email_triage.actions.sent_mail_index import (
    NonLocalBackendError,
    SentMailIndex,
    _LOCAL_BACKENDS,
)
from email_triage.actions.style_profile import (
    StyleProfile,
    build_style_prompt_prefix,
    format_profile_for_prompt,
    format_style_knobs_for_prompt,
)
from email_triage.engine import embedding_backend as embedding_backend_mod
from email_triage.engine.embedding_backend import _ALLOWED_EMBEDDING_BACKENDS
from email_triage.engine.models import Classification, EmailMessage


# ---------------------------------------------------------------------------
# Fixtures (mirror the M-4 + M-5 test patterns)
# ---------------------------------------------------------------------------

EMBED_MODEL_FIXTURE = "test-embedder-v0"

# Sentinels reused from the M-5 stitch tests so an order-pinning
# regression here points at the right layer.
M1M2_SENTINEL = "M1M2_GUIDE_SENTINEL_concise"
M3_SENTINEL = "M3_PERSONA_SENTINEL_direct"
USER_TASK_SENTINEL = "USER_TASK_SENTINEL_subject"


def _make_db_full() -> sqlite3.Connection:
    """Bring up the full schema via init_db so every helper this
    module pokes at has the columns / settings rows it needs."""
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


def _account_dict(
    conn: sqlite3.Connection, account_id: int,
) -> dict:
    row = conn.execute(
        "SELECT id, hipaa FROM email_accounts WHERE id = ?",
        (account_id,),
    ).fetchone()
    return {
        "id": row["id"],
        "hipaa": bool(row["hipaa"]),
        "config": {"style_learning_enabled": True},
    }


class _RaisingBackend:
    """Embedding backend that raises on every call.

    Used to PROVE that a code path under test never reaches an
    embed_text invocation. The backend_type is "ollama" so the
    SentMailIndex allowlist accepts construction; the raise inside
    embed_text fires only if the path forgets the HIPAA gate.
    """

    backend_type = "ollama"

    def __init__(self) -> None:
        self.calls: list[str] = []

    async def embed_text(self, text: str) -> list[float]:
        self.calls.append(text)
        raise AssertionError(
            "embed_text was called on a path that should have "
            "short-circuited before reaching the embedding backend"
        )


class _FakeBackend:
    """Cooperative embedding backend that returns a fixed vector.

    Used in non-HIPAA paths where the embedding call IS expected to
    fire. Same shape as the M-4 / M-5 test fixture so retrieval
    surfaces deterministic results.
    """

    backend_type = "ollama"

    def __init__(self) -> None:
        self.calls: list[str] = []

    async def embed_text(self, text: str) -> list[float]:
        self.calls.append(text)
        return [1.0, 0.0, 0.0, 0.0]


def _msg_for_index(*, hipaa: bool = False) -> EmailMessage:
    """Build a sent-mail message suitable for index_message tests."""
    return EmailMessage(
        message_id="u1",
        provider="imap",
        sender="user@example.com",
        recipients=["other@example.com"],
        subject="Re: hello",
        body_text="A reply body the test does not actually look at.",
        date=datetime(2026, 5, 1, tzinfo=timezone.utc),
        headers={"Message-ID": "<m1@example.com>"},
        hipaa=hipaa,
    )


def _msg_for_draft() -> EmailMessage:
    return EmailMessage(
        message_id="m-incoming",
        provider="imap",
        sender="other@example.com",
        recipients=["user@example.com"],
        subject=USER_TASK_SENTINEL,
        body_text="Looking for an update.",
        date=datetime(2026, 5, 8, tzinfo=timezone.utc),
    )


def _make_classification() -> Classification:
    return Classification(
        category="to-respond",
        confidence=0.91,
        reason="Direct reply requested.",
    )


# ---------------------------------------------------------------------------
# Invariant 1+2+3: backend allowlists are local-only and agree
# ---------------------------------------------------------------------------

class TestBackendAllowlists:
    """The two allowlists are the privacy-critical constants for M-4
    and M-5. Future commits that reach for OpenAI / Gemini / Anthropic
    embeddings should land on a pre-failed test, not a green merge.
    """

    # 2026-05-13 — pinned values expanded to include the explicit
    # local-only additions for the AI Backends feature:
    #   * "sentence_transformers" — in-process CPU embedder, no
    #     network hop, no external service.
    #   * "fallback" — composite wrapper that re-validates both of
    #     its wrapped members against this same allowlist at
    #     construction, so a non-local backup can't sneak in via
    #     the YAML fallback key.
    # Each addition was a conscious privacy decision; the test below
    # forces ANY future expansion to land on a pre-failed test the
    # same way.
    _PINNED_LOCAL_BACKENDS = (
        "ollama",
        "sentence_transformers",
        "fallback",
    )

    def test_local_backends_constant_pinned(self):
        """``actions.sent_mail_index._LOCAL_BACKENDS`` must equal
        exactly the pinned tuple — adding any non-local backend is a
        privacy decision and requires a separate review."""
        # Direct tuple equality (not a subset / superset check) so
        # ANY change fails this test loudly.
        assert _LOCAL_BACKENDS == self._PINNED_LOCAL_BACKENDS
        # Defence in depth: explicit denylist of names a future
        # contributor might reach for.
        for forbidden in (
            "openai", "anthropic", "gemini", "groq",
            "mistral", "cohere", "voyage",
        ):
            assert forbidden not in _LOCAL_BACKENDS

    def test_allowed_embedding_backends_constant_pinned(self):
        """``engine.embedding_backend._ALLOWED_EMBEDDING_BACKENDS``
        must equal exactly the pinned tuple — mirror of the
        sent-mail-index constant."""
        assert _ALLOWED_EMBEDDING_BACKENDS == self._PINNED_LOCAL_BACKENDS
        for forbidden in (
            "openai", "anthropic", "gemini", "groq",
            "mistral", "cohere", "voyage",
        ):
            assert forbidden not in _ALLOWED_EMBEDDING_BACKENDS

    def test_two_allowlists_agree(self):
        """The two constants must always be identical -- the comment
        in ``engine/embedding_backend.py`` promises they flip
        together. Drift breaks the privacy guarantee."""
        assert _LOCAL_BACKENDS == _ALLOWED_EMBEDDING_BACKENDS

    def test_constants_are_tuples_not_lists(self):
        """Pin the type so a future commit cannot turn the constant
        into a mutable list and append at runtime via
        ``_LOCAL_BACKENDS.append(...)``. Tuples are immutable."""
        assert isinstance(_LOCAL_BACKENDS, tuple)
        assert isinstance(_ALLOWED_EMBEDDING_BACKENDS, tuple)

    def test_module_level_constants_have_not_been_replaced(self):
        """Belt-and-braces: re-import the module attribute name
        directly to catch a future commit that shadowed the symbol
        with a different value at module-import time."""
        from email_triage.actions.sent_mail_index import (
            _LOCAL_BACKENDS as live_local,
        )
        from email_triage.engine.embedding_backend import (
            _ALLOWED_EMBEDDING_BACKENDS as live_allowed,
        )
        assert live_local == self._PINNED_LOCAL_BACKENDS
        assert live_allowed == self._PINNED_LOCAL_BACKENDS


# ---------------------------------------------------------------------------
# Invariant 4: HIPAA never reaches the embedding backend
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestHipaaNeverEmbeds:
    """A HIPAA account flowing through ANY public method on
    ``SentMailIndex`` must short-circuit before invoking the embedding
    backend. We use a backend that raises on call -- a missed gate
    fires AssertionError, the test reports the path that broke."""

    async def test_index_message_short_circuits_on_hipaa(self):
        conn = _make_db_full()
        user_id = _seed_user(conn)
        acct_id = _seed_account(conn, user_id=user_id, hipaa=True)
        backend = _RaisingBackend()
        idx = SentMailIndex(
            conn, acct_id,
            embedding_backend=backend,
            embedding_model=EMBED_MODEL_FIXTURE,
        )
        # Must NOT raise -- the gate fires before the backend call.
        await idx.index_message(_msg_for_index())
        assert backend.calls == []

    async def test_retrieve_similar_short_circuits_on_hipaa(self):
        conn = _make_db_full()
        user_id = _seed_user(conn)
        acct_id = _seed_account(conn, user_id=user_id, hipaa=True)
        backend = _RaisingBackend()
        idx = SentMailIndex(
            conn, acct_id,
            embedding_backend=backend,
            embedding_model=EMBED_MODEL_FIXTURE,
        )
        hits = await idx.retrieve_similar("anything")
        assert hits == []
        assert backend.calls == []

    async def test_index_recent_short_circuits_on_hipaa(self):
        """The provider isn't even consulted -- the gate runs
        before the search call."""

        class _ProviderRaises:
            async def search(self, *_a, **_kw):
                raise AssertionError(
                    "provider.search must not run on HIPAA accounts"
                )

            async def fetch_message(self, *_a, **_kw):
                raise AssertionError(
                    "provider.fetch_message must not run on HIPAA accounts"
                )

        conn = _make_db_full()
        user_id = _seed_user(conn)
        acct_id = _seed_account(conn, user_id=user_id, hipaa=True)
        backend = _RaisingBackend()
        idx = SentMailIndex(
            conn, acct_id,
            embedding_backend=backend,
            embedding_model=EMBED_MODEL_FIXTURE,
            provider=_ProviderRaises(),
        )
        n = await idx.index_recent(limit=10)
        assert n == 0
        assert backend.calls == []

    async def test_post_flip_retrieval_does_not_embed(self):
        """Account was non-HIPAA when rows landed; flipped to HIPAA
        afterwards. retrieve_similar must NOT call embed_text on the
        new query (defence in depth)."""
        conn = _make_db_full()
        user_id = _seed_user(conn)
        acct_id = _seed_account(conn, user_id=user_id, hipaa=False)
        # Index a couple rows under non-HIPAA using a cooperative
        # backend.
        cooperative = _FakeBackend()
        idx_pre = SentMailIndex(
            conn, acct_id,
            embedding_backend=cooperative,
            embedding_model=EMBED_MODEL_FIXTURE,
        )
        await idx_pre.index_message(_msg_for_index())
        # Flip the flag.
        conn.execute(
            "UPDATE email_accounts SET hipaa = 1 WHERE id = ?",
            (acct_id,),
        )
        conn.commit()
        # New retrieval must short-circuit; use a raising backend so
        # any embed call is a hard failure.
        raising = _RaisingBackend()
        idx_post = SentMailIndex(
            conn, acct_id,
            embedding_backend=raising,
            embedding_model=EMBED_MODEL_FIXTURE,
        )
        hits = await idx_post.retrieve_similar("anything")
        assert hits == []
        assert raising.calls == []


# ---------------------------------------------------------------------------
# Invariant 5: M-3 profile renders empty for HIPAA
# ---------------------------------------------------------------------------

class TestM3ProfileGate:
    def test_m3_profile_empty_for_hipaa_account(self):
        """``format_profile_for_prompt`` is the M-3 render entry point.
        The wrapping ``build_style_prompt_prefix`` enforces HIPAA --
        verifying the prefix-builder gate is what keeps a populated
        profile from leaking into a draft prompt."""
        profile = StyleProfile(
            persona_summary=M3_SENTINEL,
            greeting="Hi Person,",
            sample_count=5,
        )
        # Sanity: the renderer DOES produce content for a non-HIPAA
        # account -- we want to compare the gate behaviour against the
        # populated baseline.
        non_hipaa = format_profile_for_prompt(profile)
        assert M3_SENTINEL in non_hipaa, (
            "Sanity check: format_profile_for_prompt should render the "
            "persona summary for a populated profile"
        )

        # The prefix-builder gates HIPAA at the top. Even when the
        # underlying profile is fully populated, the prefix returns "".
        prefix = build_style_prompt_prefix(
            knobs=None, profile=profile,
            hipaa=True, master_enabled=True, account_enabled=True,
        )
        assert prefix == ""

    def test_m1m2_knobs_empty_for_hipaa(self):
        """``format_style_knobs_for_prompt`` honours the HIPAA flag
        directly -- pin that contract."""
        knobs = {
            "style_guide": M1M2_SENTINEL,
            "style_tone": "casual",
            "style_length": "brief",
            "style_signature": "",
            "style_greeting": "first-name",
            "style_greeting_custom": "",
        }
        # Populated baseline.
        non_hipaa = format_style_knobs_for_prompt(
            knobs, hipaa=False, master_enabled=True, account_enabled=True,
        )
        assert M1M2_SENTINEL in non_hipaa
        # HIPAA collapses the block.
        hipaa_render = format_style_knobs_for_prompt(
            knobs, hipaa=True, master_enabled=True, account_enabled=True,
        )
        assert hipaa_render == ""


# ---------------------------------------------------------------------------
# Invariants 7+8: master toggle + per-account toggle gate behaviour
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestStyleLearningToggles:
    async def test_master_off_suppresses_every_layer(self):
        """``style_learning:master`` off -> M-1, M-2, M-3, M-4, M-5
        all silent. The prompt collapses to the bare task message."""
        from email_triage.actions.draft_reply import build_prompt_messages
        from email_triage.web.db import (
            set_rag_sent_index_enabled,
            set_style_learning_master_enabled,
            set_style_profile,
            set_user_style_knobs,
        )

        conn = _make_db_full()
        user_id = _seed_user(conn)
        acct_id = _seed_account(conn, user_id=user_id)
        # Master OFF -- the privacy-critical gate.
        set_style_learning_master_enabled(conn, False)
        # All layers populated underneath.
        set_user_style_knobs(conn, user_id, {
            "style_guide": M1M2_SENTINEL,
            "style_tone": "casual",
            "style_length": "brief",
            "style_signature": "",
            "style_greeting": "first-name",
            "style_greeting_custom": "",
        })
        set_style_profile(conn, acct_id, {
            "persona_summary": M3_SENTINEL,
            "greeting": "",
            "signoff": "",
            "formality": 3,
            "avg_sentence_length": 0,
            "signature": "",
            "phrases_used": [],
            "phrases_avoided": [],
            "sample_count": 5,
            "model_used": "test-model",
        })
        set_rag_sent_index_enabled(conn, acct_id, enabled=True)

        backend = _RaisingBackend()  # any embed call = test failure
        app = SimpleNamespace(state=SimpleNamespace(
            embedding_backend=backend,
            embedding_model=EMBED_MODEL_FIXTURE,
            sqlite_vec_available=False,
        ))
        account = _account_dict(conn, acct_id)

        messages = await build_prompt_messages(
            db=conn, app=app, account=account, user_id=user_id,
            message=_msg_for_draft(),
            classification=_make_classification(),
        )
        flat = "\n".join(m["content"] for m in messages)
        # No style sentinel survived.
        assert M1M2_SENTINEL not in flat
        assert M3_SENTINEL not in flat
        # Task message survived.
        assert USER_TASK_SENTINEL in flat
        # Embedding never called.
        assert backend.calls == []

    async def test_rag_toggle_off_skips_m4_keeps_m1m2_m3(self):
        """Per-account RAG toggle off -> M-4 silent, M-1/2/3 still
        fire. The toggle is granular: it gates the RAG block only."""
        from email_triage.actions.draft_reply import build_prompt_messages
        from email_triage.web.db import (
            set_rag_sent_index_enabled,
            set_style_learning_master_enabled,
            set_style_profile,
            set_user_style_knobs,
        )

        conn = _make_db_full()
        user_id = _seed_user(conn)
        acct_id = _seed_account(conn, user_id=user_id)
        set_style_learning_master_enabled(conn, True)
        set_user_style_knobs(conn, user_id, {
            "style_guide": M1M2_SENTINEL,
            "style_tone": "casual",
            "style_length": "brief",
            "style_signature": "",
            "style_greeting": "first-name",
            "style_greeting_custom": "",
        })
        set_style_profile(conn, acct_id, {
            "persona_summary": M3_SENTINEL,
            "greeting": "",
            "signoff": "",
            "formality": 3,
            "avg_sentence_length": 0,
            "signature": "",
            "phrases_used": [],
            "phrases_avoided": [],
            "sample_count": 5,
            "model_used": "test-model",
        })
        # RAG OFF -- M-4 should not fire.
        set_rag_sent_index_enabled(conn, acct_id, enabled=False)

        backend = _RaisingBackend()
        app = SimpleNamespace(state=SimpleNamespace(
            embedding_backend=backend,
            embedding_model=EMBED_MODEL_FIXTURE,
            sqlite_vec_available=False,
        ))
        account = _account_dict(conn, acct_id)

        messages = await build_prompt_messages(
            db=conn, app=app, account=account, user_id=user_id,
            message=_msg_for_draft(),
            classification=_make_classification(),
        )
        flat = "\n".join(m["content"] for m in messages)
        # M-1+M-2 and M-3 still appear -- master is on, account is on.
        assert M1M2_SENTINEL in flat
        assert M3_SENTINEL in flat
        # M-4 path never invoked the embedder.
        assert backend.calls == []


# ---------------------------------------------------------------------------
# Invariant 9: HIPAA draft-reply prompt collapses to bare task message
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestHipaaDraftReply:
    async def test_hipaa_draft_reply_prompt_only_user_task(self):
        """End-to-end privacy invariant on the M-5 stitch: HIPAA
        account flowing through ``build_prompt_messages`` collapses
        to a single user-role message containing only the task.

        Pinned because this is the THE contract the M-9 task spec
        names: 'no M-3, no M-4, no M-1/2 -- only the user task
        message survives'."""
        from email_triage.actions.draft_reply import build_prompt_messages
        from email_triage.web.db import (
            set_rag_sent_index_enabled,
            set_style_learning_master_enabled,
            set_style_profile,
            set_user_style_knobs,
        )

        conn = _make_db_full()
        user_id = _seed_user(conn)
        acct_id = _seed_account(conn, user_id=user_id, hipaa=True)
        # Populate everything underneath -- the gate must beat them.
        set_style_learning_master_enabled(conn, True)
        set_user_style_knobs(conn, user_id, {
            "style_guide": M1M2_SENTINEL,
            "style_tone": "casual",
            "style_length": "brief",
            "style_signature": "",
            "style_greeting": "first-name",
            "style_greeting_custom": "",
        })
        set_style_profile(conn, acct_id, {
            "persona_summary": M3_SENTINEL,
            "greeting": "",
            "signoff": "",
            "formality": 3,
            "avg_sentence_length": 0,
            "signature": "",
            "phrases_used": [],
            "phrases_avoided": [],
            "sample_count": 5,
            "model_used": "test-model",
        })
        set_rag_sent_index_enabled(conn, acct_id, enabled=True)

        # Use a raising backend so any embed call is a test failure.
        backend = _RaisingBackend()
        app = SimpleNamespace(state=SimpleNamespace(
            embedding_backend=backend,
            embedding_model=EMBED_MODEL_FIXTURE,
            sqlite_vec_available=False,
        ))
        account = _account_dict(conn, acct_id)

        messages = await build_prompt_messages(
            db=conn, app=app, account=account, user_id=user_id,
            message=_msg_for_draft(),
            classification=_make_classification(),
        )
        # Exactly one message -- the user task.
        roles = [m["role"] for m in messages]
        assert roles == ["user"], (
            f"HIPAA prompt should be a single user message; got roles={roles}"
        )
        # Sentinel from the underlying layers does NOT survive.
        only = messages[0]["content"]
        assert M1M2_SENTINEL not in only
        assert M3_SENTINEL not in only
        # Task message survived.
        assert USER_TASK_SENTINEL in only
        # Embedding never invoked.
        assert backend.calls == []


# ---------------------------------------------------------------------------
# Belt-and-braces: rejected backends fail at construction
# ---------------------------------------------------------------------------

class TestNonLocalBackendRejection:
    """SentMailIndex.__init__ must refuse non-local backends. The
    sibling ``test_sent_mail_index.py`` covers the openai / gemini /
    anthropic cases; this module pins the contract a second time so a
    future test-file deletion doesn't silently strip the guard."""

    @pytest.mark.parametrize("forbidden", [
        "openai", "anthropic", "gemini", "groq", "mistral", "cohere",
    ])
    def test_construction_rejects_non_local(self, forbidden):
        conn = _make_db_full()
        user_id = _seed_user(conn)
        acct_id = _seed_account(conn, user_id=user_id)
        bad = _FakeBackend()
        bad.backend_type = forbidden
        with pytest.raises(NonLocalBackendError):
            SentMailIndex(
                conn, acct_id,
                embedding_backend=bad,
                embedding_model=EMBED_MODEL_FIXTURE,
            )


# ---------------------------------------------------------------------------
# build_embedding_backend factory mirrors the allowlist
# ---------------------------------------------------------------------------

class TestEmbeddingBackendFactoryAllowlist:
    """The factory in ``engine/embedding_backend.py`` is the OTHER
    arm of the privacy guarantee: it stops a YAML-configured
    non-local backend from ever being constructed. Pin the rejection
    here so the factory drift can't slip past the live test suite."""

    @pytest.mark.parametrize("forbidden", [
        "openai", "anthropic", "gemini", "groq", "mistral", "cohere",
    ])
    def test_factory_rejects_non_local(self, forbidden):
        cfg = SimpleNamespace(
            embedding=SimpleNamespace(
                backend=forbidden,
                model_name="some-model",
                ollama_url="http://localhost:11434",
            ),
        )
        with pytest.raises(ValueError) as excinfo:
            embedding_backend_mod.build_embedding_backend(cfg)
        # The error must name the rejected value AND the allowlist.
        msg = str(excinfo.value)
        assert forbidden in msg
        assert "ollama" in msg


# ---------------------------------------------------------------------------
# Invariants 10 + 11 — #152 Phase 2 M-1+M-2 HIPAA opt-in
#
# The lift: M-1 (free-text style guide) + M-2 (tone / length / greeting /
# signature radios) take operator-typed strings as input. Per §164.502(a)
# self-disclosure carve-out, operator-typed knobs are first-party data,
# not PHI. Per-account ``style_knobs_hipaa_allow:<id>`` setting (default
# False) lets the operator opt in for a specific HIPAA-flagged account.
#
# Two new invariants pin the contract:
#   * Invariant 10: the opt-in path renders the M-1+M-2 block under HIPAA.
#   * Invariant 11: flipping the M-1+M-2 opt-in does NOT lift M-3 / M-4
#     / M-7 — they stay hard-off (the opt-in is scoped to operator self-
#     disclosure, not derivative-of-PHI surfaces).
#
# Companion drawer: docs/m-series-hipaa-audit.md walks the per-layer
# audit; docs/privacy-audit-runbook.md carries the sign-off log entry.
# ---------------------------------------------------------------------------

class TestM1M2HipaaOptIn:
    """Phase 2 lift — operator-stated knobs under HIPAA-with-opt-in."""

    def test_m1m2_knobs_allowed_for_hipaa_when_opted_in(self):
        """``format_style_knobs_for_prompt`` renders the operator-typed
        knob block when ``hipaa=True`` AND ``m1m2_hipaa_allow=True``.
        Default behaviour (no opt-in) stays the empty-string contract
        pinned by ``test_m1m2_knobs_empty_for_hipaa``."""
        knobs = {
            "style_guide": M1M2_SENTINEL,
            "style_tone": "casual",
            "style_length": "brief",
            "style_signature": "",
            "style_greeting": "first-name",
            "style_greeting_custom": "",
        }
        # Default (no opt-in) — must still return "".
        no_opt_in = format_style_knobs_for_prompt(
            knobs, hipaa=True, master_enabled=True, account_enabled=True,
        )
        assert no_opt_in == ""

        # Opt-in path — the same knobs render.
        with_opt_in = format_style_knobs_for_prompt(
            knobs, hipaa=True, master_enabled=True, account_enabled=True,
            m1m2_hipaa_allow=True,
        )
        assert M1M2_SENTINEL in with_opt_in, (
            "M-1+M-2 opt-in path should render the operator-typed "
            "style guide on HIPAA accounts; this is the §164.502(a) "
            "self-disclosure carve-out the Phase 2 lift relies on."
        )

        # Master / per-account toggles still gate even when opt-in is on.
        # (The opt-in is layered ON TOP of the existing gates, not a
        # substitute for them.)
        master_off = format_style_knobs_for_prompt(
            knobs, hipaa=True, master_enabled=False, account_enabled=True,
            m1m2_hipaa_allow=True,
        )
        assert master_off == ""
        account_off = format_style_knobs_for_prompt(
            knobs, hipaa=True, master_enabled=True, account_enabled=False,
            m1m2_hipaa_allow=True,
        )
        assert account_off == ""

    def test_m3_m4_m7_stay_hard_off_when_m1m2_opted_in(self):
        """Flipping the M-1+M-2 opt-in must NOT lift M-3 (the derived
        profile renderer) or M-4 (the sent-mail RAG embedding path).
        M-7 is a query-time refinement of M-4, so the M-4 gate covers
        it transitively — verifying via the build_style_prompt_prefix
        contract that the M-3 block stays empty under HIPAA even when
        m1m2_hipaa_allow=True. The M-4 embedding path is covered
        separately by TestHipaaNeverEmbeds (it doesn't take an
        m1m2_hipaa_allow parameter — the gate at SentMailIndex is on
        ``is_account_hipaa(acct)`` directly, no flag override)."""
        profile = StyleProfile(
            persona_summary=M3_SENTINEL,
            greeting="Hi Person,",
            sample_count=5,
        )
        knobs = {
            "style_guide": M1M2_SENTINEL,
            "style_tone": "casual",
            "style_length": "brief",
            "style_signature": "",
            "style_greeting": "first-name",
            "style_greeting_custom": "",
        }
        # Opt-in flipped to True under HIPAA.
        prefix = build_style_prompt_prefix(
            knobs, profile,
            hipaa=True, master_enabled=True, account_enabled=True,
            m1m2_hipaa_allow=True,
        )
        # M-1+M-2 sentinel DOES appear (the lift fired).
        assert M1M2_SENTINEL in prefix, (
            "M-1+M-2 opt-in should lift the knob block under HIPAA"
        )
        # M-3 sentinel does NOT appear (the lift is scoped to M-1+M-2
        # only; M-3 reads sent-mail bodies and stays hard-off).
        assert M3_SENTINEL not in prefix, (
            "M-3 derived profile must stay suppressed under HIPAA "
            "even when the M-1+M-2 opt-in is on. M-3 reads PHI; the "
            "opt-in is only for operator-typed knobs."
        )

    def test_m4_embedding_gate_independent_of_m1m2_opt_in(self):
        """Belt-and-braces: the SentMailIndex HIPAA short-circuit
        does NOT consult the M-1+M-2 opt-in. The gate at
        ``actions/sent_mail_index.py::_hipaa_short_circuit`` reads
        ``is_account_hipaa(acct)`` directly — there is no path by
        which a flipped M-1+M-2 opt-in can leak into M-4 retrieval.
        Pin this so a future refactor that adds an
        ``m1m2_hipaa_allow`` parameter to SentMailIndex (mis-scoping
        the lift) fails this test."""
        import inspect
        from email_triage.actions.sent_mail_index import (
            SentMailIndex,
        )
        # The signature must not have an opt-in parameter that
        # could be wired to lift the M-4 gate. If a future refactor
        # adds one, this assertion will fire and the reviewer can
        # decide whether it's the Phase 3 / 4 surface (in which case
        # the test moves) or an unintended mis-scoping.
        init_sig = inspect.signature(SentMailIndex.__init__)
        forbidden_params = {
            "m1m2_hipaa_allow",
            "style_knobs_hipaa_allow",
            "hipaa_allow",
            "allow_hipaa",
        }
        leak = forbidden_params.intersection(init_sig.parameters)
        assert leak == set(), (
            f"SentMailIndex.__init__ gained M-1+M-2-lift-shaped "
            f"params {leak} — the Phase 2 opt-in must NOT wire into "
            f"the M-4 embedding path. M-4 needs Phase 3 "
            f"describe-and-discard, not a flag flip."
        )


@pytest.mark.asyncio
class TestM1M2OptInEndToEnd:
    """End-to-end: per-account opt-in setting flips the draft-reply
    prompt-build output. Pin both directions (off → empty, on →
    knobs render) and that M-3 / M-4 stay hard-off either way."""

    async def test_opt_in_off_hipaa_prompt_collapses(self):
        """Default state (no opt-in row): HIPAA prompt collapses to
        bare task. Mirror of ``test_hipaa_draft_reply_prompt_only_user_task``
        with explicit assertion that the new setting is OFF."""
        from email_triage.actions.draft_reply import build_prompt_messages
        from email_triage.web.db import (
            is_style_knobs_hipaa_allow,
            set_style_learning_master_enabled,
            set_user_style_knobs,
        )

        conn = _make_db_full()
        user_id = _seed_user(conn)
        acct_id = _seed_account(conn, user_id=user_id, hipaa=True)
        set_style_learning_master_enabled(conn, True)
        set_user_style_knobs(conn, user_id, {
            "style_guide": M1M2_SENTINEL,
            "style_tone": "casual",
            "style_length": "brief",
            "style_signature": "",
            "style_greeting": "first-name",
            "style_greeting_custom": "",
        })
        # Sanity: default OFF, no row written.
        assert is_style_knobs_hipaa_allow(conn, acct_id) is False

        backend = _RaisingBackend()
        app = SimpleNamespace(state=SimpleNamespace(
            embedding_backend=backend,
            embedding_model=EMBED_MODEL_FIXTURE,
            sqlite_vec_available=False,
        ))
        account = _account_dict(conn, acct_id)

        messages = await build_prompt_messages(
            db=conn, app=app, account=account, user_id=user_id,
            message=_msg_for_draft(),
            classification=_make_classification(),
        )
        only = messages[0]["content"]
        assert M1M2_SENTINEL not in only
        assert USER_TASK_SENTINEL in only

    async def test_opt_in_on_hipaa_prompt_has_m1m2_only(self):
        """Opt-in flipped ON: the M-1+M-2 prefix lands in the prompt,
        M-3 (and M-4 embedding) stay suppressed."""
        from email_triage.actions.draft_reply import build_prompt_messages
        from email_triage.web.db import (
            set_rag_sent_index_enabled,
            set_style_knobs_hipaa_allow,
            set_style_learning_master_enabled,
            set_style_profile,
            set_user_style_knobs,
        )

        conn = _make_db_full()
        user_id = _seed_user(conn)
        acct_id = _seed_account(conn, user_id=user_id, hipaa=True)
        set_style_learning_master_enabled(conn, True)
        set_user_style_knobs(conn, user_id, {
            "style_guide": M1M2_SENTINEL,
            "style_tone": "casual",
            "style_length": "brief",
            "style_signature": "",
            "style_greeting": "first-name",
            "style_greeting_custom": "",
        })
        # Populate M-3 profile + M-4 RAG toggle to verify they stay
        # hard-off even when M-1+M-2 is lifted.
        set_style_profile(conn, acct_id, {
            "persona_summary": M3_SENTINEL,
            "greeting": "",
            "signoff": "",
            "formality": 3,
            "avg_sentence_length": 0,
            "signature": "",
            "phrases_used": [],
            "phrases_avoided": [],
            "sample_count": 5,
            "model_used": "test-model",
        })
        set_rag_sent_index_enabled(conn, acct_id, enabled=True)
        # Flip the opt-in.
        set_style_knobs_hipaa_allow(conn, acct_id, enabled=True)

        backend = _RaisingBackend()  # any embed call = failure
        app = SimpleNamespace(state=SimpleNamespace(
            embedding_backend=backend,
            embedding_model=EMBED_MODEL_FIXTURE,
            sqlite_vec_available=False,
        ))
        account = _account_dict(conn, acct_id)

        messages = await build_prompt_messages(
            db=conn, app=app, account=account, user_id=user_id,
            message=_msg_for_draft(),
            classification=_make_classification(),
        )
        flat = "\n".join(m["content"] for m in messages)
        # M-1+M-2 lift fired.
        assert M1M2_SENTINEL in flat, (
            "Per-account M-1+M-2 opt-in must render the operator's "
            "typed style knobs under HIPAA"
        )
        # M-3 derived profile stays suppressed (reads PHI).
        assert M3_SENTINEL not in flat, (
            "M-3 derived profile must stay hard-off under HIPAA even "
            "when the M-1+M-2 opt-in is on"
        )
        # M-4 embedding backend never called.
        assert backend.calls == [], (
            "M-4 RAG embedding must stay hard-off under HIPAA even "
            "when the M-1+M-2 opt-in is on"
        )


# ---------------------------------------------------------------------------
# Invariant: auto-scan default is HIPAA-aware (#157, 2026-05-11)
#
# Sent-mail auto-scan (the per-account ``rag_sent_index_enabled`` toggle)
# must default OFF for HIPAA-flagged accounts and ON for non-HIPAA. Today
# the toggle is the operator UX surface; the M-4 SentMailIndex hard-gate
# stays unchanged (it refuses HIPAA even if the toggle is on), but the
# UX default should match the privacy posture so a new HIPAA-flagged
# account doesn't show as "auto-scan ON" the first time it opens.
# ---------------------------------------------------------------------------

class TestAutoScanDefaultHipaaAware:
    """Per-account ``rag_sent_index_enabled`` default depends on the
    account's HIPAA flag. Explicitly-saved values override the default
    on either side."""

    def test_non_hipaa_account_defaults_on(self):
        """Fresh non-HIPAA account, no saved value → True."""
        from email_triage.web.db import is_rag_sent_index_enabled
        conn = _make_db_full()
        user_id = _seed_user(conn)
        acct_id = _seed_account(conn, user_id=user_id, hipaa=False)
        acct = _account_dict(conn, acct_id)
        # The HIPAA-aware default requires the caller to pass the
        # account dict; the legacy default-off behaviour stays in
        # place when account=None for back-compat.
        assert is_rag_sent_index_enabled(conn, acct_id, account=acct) is True

    def test_hipaa_account_defaults_off(self):
        """Fresh HIPAA-flagged account, no saved value → False.

        Owner gets the choice (§164.502(a) self-disclosure) but the
        install does not auto-mine PHI mail. The owner can flip the
        toggle on per-account; until then, default is off."""
        from email_triage.web.db import is_rag_sent_index_enabled
        conn = _make_db_full()
        user_id = _seed_user(conn)
        acct_id = _seed_account(conn, user_id=user_id, hipaa=True)
        acct = _account_dict(conn, acct_id)
        assert is_rag_sent_index_enabled(conn, acct_id, account=acct) is False

    def test_explicit_save_overrides_hipaa_default(self):
        """An owner who explicitly opts in to auto-scan on a HIPAA
        account gets that value back (the privacy-critical M-4 path
        still gates them at the SentMailIndex layer)."""
        from email_triage.web.db import (
            is_rag_sent_index_enabled, set_rag_sent_index_enabled,
        )
        conn = _make_db_full()
        user_id = _seed_user(conn)
        acct_id = _seed_account(conn, user_id=user_id, hipaa=True)
        acct = _account_dict(conn, acct_id)
        set_rag_sent_index_enabled(conn, acct_id, enabled=True)
        assert is_rag_sent_index_enabled(conn, acct_id, account=acct) is True

    def test_explicit_off_overrides_non_hipaa_default(self):
        """A non-HIPAA owner who explicitly turns auto-scan off keeps
        that value (default-on doesn't retroactively flip)."""
        from email_triage.web.db import (
            is_rag_sent_index_enabled, set_rag_sent_index_enabled,
        )
        conn = _make_db_full()
        user_id = _seed_user(conn)
        acct_id = _seed_account(conn, user_id=user_id, hipaa=False)
        acct = _account_dict(conn, acct_id)
        set_rag_sent_index_enabled(conn, acct_id, enabled=False)
        assert is_rag_sent_index_enabled(conn, acct_id, account=acct) is False

    def test_legacy_signature_keeps_default_off(self):
        """The pre-#157 callers (which pass account_id only, no
        ``account`` kwarg) retain the conservative default-off
        behaviour. New callers opt into HIPAA-awareness by passing
        the dict."""
        from email_triage.web.db import is_rag_sent_index_enabled
        conn = _make_db_full()
        user_id = _seed_user(conn)
        acct_id = _seed_account(conn, user_id=user_id, hipaa=False)
        # No account kwarg → legacy default-off.
        assert is_rag_sent_index_enabled(conn, acct_id) is False


# ---------------------------------------------------------------------------
# Invariant 12 — Anti-AI style guide tracks the M-1+M-2 HIPAA gate
#
# The anti-AI style guide takes operator-typed strings as input (admin
# /config global + per-user /profile?tab=writing override). Per §164.502(a)
# self-disclosure carve-out, operator-typed text is first-party data,
# not PHI. The anti-AI block routes through ``build_style_prompt_prefix``
# which already enforces ``hipaa and not m1m2_hipaa_allow → empty
# prefix``; the anti-AI section piggybacks on that gate.
#
# This invariant pins the contract: a HIPAA-flagged account without the
# per-account opt-in must produce no anti-AI text in the prompt, even
# when both the global guide and the user override are populated.
# ---------------------------------------------------------------------------

ANTI_AI_GLOBAL_SENTINEL = "ANTI_GLOBAL_SENTINEL_certainly"
ANTI_AI_USER_SENTINEL = "ANTI_USER_SENTINEL_emdash"


class TestAntiAiStyleGuideHipaaGate:
    """Anti-AI text must follow the M-1+M-2 HIPAA opt-in contract."""

    def test_hipaa_without_optin_suppresses_anti_ai(self):
        """HIPAA + no per-account opt-in → anti-AI block is empty
        even with both surfaces populated."""
        prefix = build_style_prompt_prefix(
            knobs=None, profile=None,
            hipaa=True,
            master_enabled=True, account_enabled=True,
            m1m2_hipaa_allow=False,
            anti_ai_global=ANTI_AI_GLOBAL_SENTINEL,
            anti_ai_user=ANTI_AI_USER_SENTINEL,
        )
        assert prefix == ""

    def test_hipaa_with_optin_renders_anti_ai(self):
        """Opt-in flipped → operator-typed anti-AI text renders under
        HIPAA. Same §164.502(a) carve-out as M-1+M-2."""
        prefix = build_style_prompt_prefix(
            knobs=None, profile=None,
            hipaa=True,
            master_enabled=True, account_enabled=True,
            m1m2_hipaa_allow=True,
            anti_ai_global=ANTI_AI_GLOBAL_SENTINEL,
            anti_ai_user=ANTI_AI_USER_SENTINEL,
        )
        assert ANTI_AI_GLOBAL_SENTINEL in prefix
        assert ANTI_AI_USER_SENTINEL in prefix

    def test_master_off_suppresses_anti_ai_regardless(self):
        """Install-wide master toggle off → no prefix, even with the
        anti-AI surfaces populated and a non-HIPAA account."""
        prefix = build_style_prompt_prefix(
            knobs=None, profile=None,
            hipaa=False,
            master_enabled=False, account_enabled=True,
            anti_ai_global=ANTI_AI_GLOBAL_SENTINEL,
            anti_ai_user=ANTI_AI_USER_SENTINEL,
        )
        assert prefix == ""

    def test_disable_global_skips_install_wide_text(self):
        """Per-user disable-global flag drops the install-wide text
        from the prompt block. Sibling to the M-1+M-2 stacking
        contract — user-stated text always wins over install-wide
        defaults."""
        prefix = build_style_prompt_prefix(
            knobs=None, profile=None,
            hipaa=False,
            master_enabled=True, account_enabled=True,
            anti_ai_global=ANTI_AI_GLOBAL_SENTINEL,
            anti_ai_user=ANTI_AI_USER_SENTINEL,
            anti_ai_disable_global=True,
        )
        assert ANTI_AI_GLOBAL_SENTINEL not in prefix
        assert ANTI_AI_USER_SENTINEL in prefix


# ---------------------------------------------------------------------------
# Invariant 13 — #152 Phase 3 HIPAA-safe M-3 scrubber
#
# The phase-3 "describe-and-discard" architecture builds a structured
# style descriptor from sent-mail bodies on HIPAA-opted-in accounts,
# then runs a PHI scrubber over the LLM response before persistence.
# The scrubber is the final gate between an LLM that occasionally
# misbehaves and a stored descriptor that lasts ~1 week.
#
# This invariant pins the contract on a SYNTHETIC poisoned corpus:
# every planted PHI leak (names, MRNs, DOBs, phone numbers, addresses,
# medical terminology) must either drop the descriptor entirely (when
# the leak hits a non-phrase field — a contract violation that
# survived enum coercion) or be filtered out of the ``common_phrases``
# list (the designed-leak surface, where per-phrase scrubbing is the
# expected response).
#
# Companion module:
#   * tests/test_actions/test_hipaa_style_distill.py — covers the
#     orchestrator + per-pattern scrubber behaviour in detail.
# This file pins the *privacy* contract: no PHI shape from the
# synthetic catalogue can survive a scrub pass into a persistable
# descriptor.
# ---------------------------------------------------------------------------

# Synthetic PHI catalogue. Every entry is fictional + designed to match
# a specific scrubber rule. The poisoned descriptor below carries every
# entry in one shape or another so the test can assert the scrubber
# caught every plant.
#
# NOTE: these strings appear in TEST source — the
# test_privacy_invariants_no_customer_names sibling-test scans
# src/email_triage/ only, so synthetic fictional names here don't
# trip that gate. Real PHI must never appear in tests either — these
# are clearly-fictional ("Smith", "Jones", "1234567" digit run, etc.).

_SYNTHETIC_PHI_CATALOGUE: dict[str, str] = {
    "mrn_long_digit_run": "follow-up on 1234567 chart review",
    "date_dob_slash": "DOB 04/12/1965 noted",
    "date_year_4digit": "patient since 2019",
    "ssn_format": "SSN 123-45-6789 on file",
    "phone_us_dashed": "call 555-123-4567",
    "phone_parens": "ring (555) 123-4567",
    "email_address": "loop in nurse@clinic.example",
    "street_address": "see 123 Main Street",
    "zip_code": "ZIP 90210 nearby",
    "honorific_name": "follow up with Dr. Jones",
    "medical_term": "regarding patient diagnosis",
}


class TestM3HipaaScrubberCatchesPhiCatalogue:
    """The scrubber must catch every planted PHI leak in the synthetic
    catalogue. Failure = leak risk on stored descriptors."""

    def test_each_phi_pattern_dropped_from_phrases(self):
        """Run each catalogue entry through the scrubber as a
        ``common_phrases`` list of one + assert the entry is dropped
        (the safe-phrase list comes out empty)."""
        from email_triage.actions.hipaa_style_distill import _scrub_descriptor

        unscrubbed: list[str] = []
        for label, phrase in _SYNTHETIC_PHI_CATALOGUE.items():
            descriptor = {
                "tone": "casual",
                "formality": 3,
                "length_bucket": "medium",
                "greeting_pattern": "none",
                "signoff_pattern": "none",
                "common_phrases": [phrase],
            }
            out, dropped_structural, fired = _scrub_descriptor(descriptor)
            # Phrase-only PHI doesn't drop the descriptor; it filters
            # the phrase out of the list.
            if out["common_phrases"]:
                unscrubbed.append(
                    f"  {label!r} -> phrase {phrase!r} survived; "
                    f"fired={fired}"
                )

        assert not unscrubbed, (
            "Scrubber missed PHI patterns from the synthetic catalogue. "
            "Every fictional PHI shape below should be caught by at "
            "least one regex in actions.hipaa_style_distill._PHI_PATTERNS. "
            "Add a matching pattern + re-run.\n"
            + "\n".join(unscrubbed)
        )

    def test_clean_phrase_alongside_phi_survives(self):
        """A poisoned list ``[<phi>, <clean>]`` keeps the clean entry
        and drops only the poisoned one. Pin to confirm the scrubber
        is filtering, not nuking the whole list on any single hit."""
        from email_triage.actions.hipaa_style_distill import _scrub_descriptor

        descriptor = {
            "tone": "casual",
            "formality": 3,
            "length_bucket": "medium",
            "greeting_pattern": "none",
            "signoff_pattern": "none",
            "common_phrases": [
                "call 555-123-4567",   # PHI
                "let me know",         # clean
            ],
        }
        out, dropped, fired = _scrub_descriptor(descriptor)
        assert dropped is False
        assert "let me know" in out["common_phrases"]
        assert all("555" not in p for p in out["common_phrases"])
        assert fired  # at least one pattern fired

    def test_structural_leak_drops_entire_descriptor(self):
        """PHI in a non-phrase field is a contract violation — the
        scrubber drops the WHOLE descriptor. Pin so a future relaxation
        (e.g. "redact and keep") doesn't slip through unnoticed."""
        from email_triage.actions.hipaa_style_distill import _scrub_descriptor

        # tone field carries an email pattern — bypasses _coerce_enum
        # by passing the dict directly to the scrubber.
        poisoned = {
            "tone": "user@clinic.example",
            "formality": 3,
            "length_bucket": "medium",
            "greeting_pattern": "none",
            "signoff_pattern": "none",
            "common_phrases": ["let me know"],
        }
        _out, dropped, fired = _scrub_descriptor(poisoned)
        assert dropped is True
        assert any("tone" in label for label in fired)

    def test_descriptor_has_no_freeform_fields(self):
        """The phase-3 descriptor schema must NOT carry persona_summary
        or signature — those were the highest-leak surfaces on the
        non-HIPAA M-3 path. Pin so a future schema extension can't
        re-introduce them without failing this test."""
        from email_triage.actions.hipaa_style_distill import (
            HipaaStyleDescriptor,
        )
        empty = HipaaStyleDescriptor().to_dict()
        assert "persona_summary" not in empty, (
            "HipaaStyleDescriptor should not carry persona_summary — "
            "free-form prose is the highest PHI-leak surface on M-3 "
            "and the phase-3 schema is closed-enum by design."
        )
        assert "signature" not in empty, (
            "HipaaStyleDescriptor should not carry signature — "
            "operator's full sig block typically contains name + "
            "clinic + phone. Phase 3 drops it."
        )
