"""Privacy invariants for the HIPAA describe-and-discard distill (#152 S1).

CI guard for the orchestrator at
:mod:`email_triage.style_learning.distill_hipaa`. Each test asserts a
contract that, if loosened, would let PHI escape into storage or the
LLM response into the audit log.

The backend is ALWAYS mocked here — no test in this module touches a
real LLM endpoint.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import pytest

from email_triage.engine.models import EmailMessage
from email_triage.style_learning import (
    DistillResult,
    distill_hipaa_account,
)
from email_triage.style_learning import distill_hipaa as distill_mod
from email_triage.web.db import (
    enqueue_style_distill_retry,  # noqa: F401 — wired by orchestrator
    get_hipaa_style_descriptor,
    get_style_distill_queue_entry,
    init_db,
    list_paused_style_distill_accounts,
    list_style_distill_events,
    set_hipaa_style_distill_enabled,
    set_style_knobs_hipaa_allow,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def db() -> sqlite3.Connection:
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
    conn: sqlite3.Connection, *, user_id: int, hipaa: bool,
) -> int:
    now = datetime.now(timezone.utc).isoformat()
    cur = conn.execute(
        "INSERT INTO email_accounts ("
        "user_id, name, provider_type, config_json, hipaa, "
        "created_at, updated_at"
        ") VALUES (?, ?, ?, ?, ?, ?, ?)",
        (user_id, "Mailbox", "imap", "{}",
         int(bool(hipaa)), now, now),
    )
    conn.commit()
    return int(cur.lastrowid)


def _make_messages(n: int = 3) -> list[EmailMessage]:
    return [
        EmailMessage(
            message_id=f"m{i}",
            provider="imap",
            sender="user@example.com",
            recipients=["other@example.com"],
            subject=f"Subject {i}",
            body_text=(
                "A short reply body. Patient John Smith MRN 12345678 "
                "phone 555-867-5309 lives at 123 Main Street."
            ),
            date=datetime(2026, 5, 1, tzinfo=timezone.utc),
        )
        for i in range(n)
    ]


# ---------------------------------------------------------------------------
# Mock backend
# ---------------------------------------------------------------------------

class _MockBackend:
    """In-process backend adapter. Returns a pre-baked response.

    Mirrors :class:`email_triage.ai_backends.BackendAdapter` shape so
    the distill code path treats it identically to a real adapter.
    """

    def __init__(
        self, response: str, *,
        is_local: bool = True,
        backend_type: str = "ollama",
        raise_on_call: Exception | None = None,
    ) -> None:
        self.response = response
        self.is_local = is_local
        self.backend_type = backend_type
        self._raise_on_call = raise_on_call
        self.calls: list[dict] = []

    async def chat_complete(
        self, messages: list[dict],
        *, response_format: Any = None, max_tokens: int | None = None,
        **_: Any,
    ) -> str:
        self.calls.append({
            "messages": messages,
            "response_format": response_format,
        })
        if self._raise_on_call is not None:
            raise self._raise_on_call
        return self.response

    async def close(self) -> None:  # pragma: no cover - trivial
        return None


def _install_mock_backend(monkeypatch, backend: _MockBackend) -> None:
    """Monkeypatch ``load_backend`` to return our mock."""
    def fake_loader(backend_id, *, db_conn, secrets=None, config=None):
        return backend
    monkeypatch.setattr(distill_mod, "load_backend", fake_loader)


# A clean structured response the LLM would return on a successful run.
CLEAN_LLM_RESPONSE = (
    '{"tone": "professional", "formality_level": 4, '
    '"greeting_style": "hi_first_name", "signoff_style": "thanks", '
    '"sentence_length_pref": "medium", "vocabulary_register": "plain", '
    '"paragraph_count_typical": 2, '
    '"common_phrases": ["let me know", "happy to help"]}'
)

# A response that intentionally leaks PHI in non-phrase fields. Layer
# 1 catches the enum violation but a malicious / broken LLM could
# leak via the phrase list; layer 2 catches THAT in the next test.
LEAKY_LLM_RESPONSE_STRUCTURAL = (
    '{"tone": "professional follow-up with Dr. Smith about MRN 12345678", '
    '"formality_level": 4, '
    '"greeting_style": "hi_first_name", "signoff_style": "thanks", '
    '"sentence_length_pref": "medium", "vocabulary_register": "plain", '
    '"paragraph_count_typical": 2, "common_phrases": []}'
)

# A response that leaks PHI only via the phrase list — should partially
# scrub (phrases drop), descriptor still persists.
LEAKY_LLM_RESPONSE_PHRASE = (
    '{"tone": "professional", "formality_level": 4, '
    '"greeting_style": "hi_first_name", "signoff_style": "thanks", '
    '"sentence_length_pref": "medium", "vocabulary_register": "plain", '
    '"paragraph_count_typical": 2, '
    '"common_phrases": ["let me know", "Mr. Smith called", '
    '"ping op@example.org", "happy to help"]}'
)


# ---------------------------------------------------------------------------
# Gating tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestGating:
    """The distill function MUST short-circuit before reaching the LLM
    when any gate is closed."""

    async def test_install_wide_flag_off(self, db, monkeypatch):
        """Default install: hipaa_distill_enabled=False -> outcome=disabled."""
        uid = _seed_user(db)
        aid = _seed_account(db, user_id=uid, hipaa=True)
        backend = _MockBackend(CLEAN_LLM_RESPONSE)
        _install_mock_backend(monkeypatch, backend)
        result = await distill_hipaa_account(
            aid, db_conn=db, messages=_make_messages(),
            actor_user_id=uid, skip_ner=True,
        )
        assert result.status == "disabled"
        # Backend NEVER called.
        assert backend.calls == []
        # Audit row landed.
        events = list_style_distill_events(db, account_id=aid)
        assert len(events) == 1
        assert events[0]["outcome"] == "disabled"

    async def test_not_hipaa_account(self, db, monkeypatch):
        """Non-HIPAA account: outcome=not_hipaa, backend not called."""
        uid = _seed_user(db)
        aid = _seed_account(db, user_id=uid, hipaa=False)
        set_hipaa_style_distill_enabled(db, True)
        backend = _MockBackend(CLEAN_LLM_RESPONSE)
        _install_mock_backend(monkeypatch, backend)
        result = await distill_hipaa_account(
            aid, db_conn=db, messages=_make_messages(),
            actor_user_id=uid, skip_ner=True,
        )
        assert result.status == "not_hipaa"
        assert backend.calls == []

    async def test_not_opted_in(self, db, monkeypatch):
        """HIPAA account WITHOUT the per-account opt-in: outcome=not_opted_in."""
        uid = _seed_user(db)
        aid = _seed_account(db, user_id=uid, hipaa=True)
        set_hipaa_style_distill_enabled(db, True)
        # No set_style_knobs_hipaa_allow call.
        backend = _MockBackend(CLEAN_LLM_RESPONSE)
        _install_mock_backend(monkeypatch, backend)
        result = await distill_hipaa_account(
            aid, db_conn=db, messages=_make_messages(),
            actor_user_id=uid, skip_ner=True,
        )
        assert result.status == "not_opted_in"
        assert backend.calls == []

    async def test_missing_account(self, db, monkeypatch):
        """Unknown account_id -> outcome=not_hipaa (defensive)."""
        backend = _MockBackend(CLEAN_LLM_RESPONSE)
        _install_mock_backend(monkeypatch, backend)
        result = await distill_hipaa_account(
            99999, db_conn=db, messages=_make_messages(),
            actor_user_id=None, skip_ner=True,
        )
        assert result.status == "not_hipaa"
        assert backend.calls == []


# ---------------------------------------------------------------------------
# Happy path + scrubber outcomes
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestDistillOutcomes:
    """End-to-end: gates open, backend called, response scrubbed,
    descriptor persisted or dropped."""

    async def _open_all_gates(self, db, *, hipaa: bool = True) -> tuple[int, int]:
        uid = _seed_user(db)
        aid = _seed_account(db, user_id=uid, hipaa=hipaa)
        set_hipaa_style_distill_enabled(db, True)
        set_style_knobs_hipaa_allow(db, aid, enabled=True)
        return uid, aid

    async def test_clean_response_persists_descriptor(self, db, monkeypatch):
        uid, aid = await self._open_all_gates(db)
        backend = _MockBackend(CLEAN_LLM_RESPONSE)
        _install_mock_backend(monkeypatch, backend)
        result = await distill_hipaa_account(
            aid, db_conn=db, messages=_make_messages(),
            actor_user_id=uid, skip_ner=True,
        )
        assert result.status == "success"
        assert backend.calls and backend.calls[0]["response_format"] is not None
        # Descriptor persisted.
        row = get_hipaa_style_descriptor(db, aid)
        assert row is not None
        assert row["descriptor"]["tone"] == "professional"
        # Audit row says success.
        events = list_style_distill_events(db, account_id=aid)
        assert events[0]["outcome"] == "success"
        # Queue cleared on success.
        assert get_style_distill_queue_entry(db, account_id=aid) is None

    async def test_phrase_level_leak_persists_partial(self, db, monkeypatch):
        """LLM leaks PHI only via phrase list -> partial scrub,
        descriptor still persists with offending phrases removed."""
        uid, aid = await self._open_all_gates(db)
        backend = _MockBackend(LEAKY_LLM_RESPONSE_PHRASE)
        _install_mock_backend(monkeypatch, backend)
        result = await distill_hipaa_account(
            aid, db_conn=db, messages=_make_messages(),
            actor_user_id=uid, skip_ner=True,
        )
        assert result.status == "scrubbed_partial"
        # Descriptor persisted but with PHI phrases stripped.
        row = get_hipaa_style_descriptor(db, aid)
        assert row is not None
        phrases = row["descriptor"]["common_phrases"]
        for forbidden in ("Mr. Smith", "op@example.org"):
            for ph in phrases:
                assert forbidden not in ph

    async def test_structural_leak_drops_descriptor(self, db, monkeypatch):
        """LLM leaks PHI into a closed-enum field -> scrubber fails,
        descriptor NOT persisted, account paused."""
        uid, aid = await self._open_all_gates(db)
        # We want a response that fails the scrubber at the structural
        # level. Layer 1 snaps closed-enum violations to safe defaults
        # (so a name in 'tone' is sanitised), which means we need PHI
        # in a field that survives layer-1 coercion. The phrase-list
        # is exempt, so structural failure has to come via layer-3
        # NER on a closed-enum field. With skip_ner=True the test
        # would never hit layer-3.
        #
        # The clean test path of "structural failure" is therefore:
        # mock scrub_descriptor directly to return passed=False. This
        # validates the orchestrator's response to a failed scrub.
        from email_triage.style_learning.phi_scrubber import ScrubResult
        backend = _MockBackend(CLEAN_LLM_RESPONSE)
        _install_mock_backend(monkeypatch, backend)

        def fake_scrub(_d, *, skip_ner=False):
            return ScrubResult(
                passed=False,
                scrubbed_descriptor={},
                layer1_fields_dropped=[],
                layer2_matches=[("tone", "name_honorific")],
                layer3_entities=[],
                degraded=True,
            )
        monkeypatch.setattr(distill_mod, "scrub_descriptor", fake_scrub)

        result = await distill_hipaa_account(
            aid, db_conn=db, messages=_make_messages(),
            actor_user_id=uid, skip_ner=True,
        )
        assert result.status == "scrubber_fail"
        # No descriptor persisted.
        assert get_hipaa_style_descriptor(db, aid) is None
        # Account paused.
        paused = list_paused_style_distill_accounts(db)
        assert any(p["account_id"] == aid for p in paused)
        # Audit row.
        events = list_style_distill_events(db, account_id=aid)
        assert events[0]["outcome"] == "scrubber_fail"

    async def test_backend_failure_enqueues_retry_no_descriptor(
        self, db, monkeypatch,
    ):
        """Backend raises -> outcome=backend_fail, retry queued,
        descriptor NOT persisted."""
        uid, aid = await self._open_all_gates(db)
        backend = _MockBackend(
            "", raise_on_call=RuntimeError("network unreachable"),
        )
        _install_mock_backend(monkeypatch, backend)
        result = await distill_hipaa_account(
            aid, db_conn=db, messages=_make_messages(),
            actor_user_id=uid, skip_ner=True,
        )
        assert result.status == "backend_fail"
        # Retry queue gained an entry.
        qrow = get_style_distill_queue_entry(db, account_id=aid)
        assert qrow is not None
        assert qrow["attempt_count"] == 1
        assert qrow["next_retry_at"] is not None
        # Descriptor not persisted.
        assert get_hipaa_style_descriptor(db, aid) is None
        # Error class captured WITHOUT the message text.
        events = list_style_distill_events(db, account_id=aid)
        assert events[0]["outcome"] == "backend_fail"
        assert events[0]["error_class"] == "RuntimeError"
        # The audit row must NEVER carry the exception message
        # ("network unreachable") — verify it doesn't appear in any
        # field.
        for v in events[0].values():
            if isinstance(v, str):
                assert "network unreachable" not in v

    async def test_no_messages_short_circuits(self, db, monkeypatch):
        """Empty corpus -> outcome=no_messages, backend NOT called."""
        uid, aid = await self._open_all_gates(db)
        backend = _MockBackend(CLEAN_LLM_RESPONSE)
        _install_mock_backend(monkeypatch, backend)
        result = await distill_hipaa_account(
            aid, db_conn=db, messages=[],  # empty
            actor_user_id=uid, skip_ner=True,
        )
        assert result.status == "no_messages"
        assert backend.calls == []


# ---------------------------------------------------------------------------
# Body-never-persisted invariant
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestBodyNeverPersists:
    """The headline HIPAA invariant: message bodies must NEVER land in
    storage. Verified via two complementary checks:

      1. The persisted descriptor row carries only the structured
         scrubbed fields — no body fragments.
      2. The audit row carries only counts + labels — no body text,
         no error message text.
    """

    async def test_body_not_in_descriptor_or_audit(self, db, monkeypatch):
        uid = _seed_user(db)
        aid = _seed_account(db, user_id=uid, hipaa=True)
        set_hipaa_style_distill_enabled(db, True)
        set_style_knobs_hipaa_allow(db, aid, enabled=True)
        backend = _MockBackend(CLEAN_LLM_RESPONSE)
        _install_mock_backend(monkeypatch, backend)

        # Messages with a known PHI marker in the body. We then assert
        # that marker NEVER appears in any persisted column.
        PHI_MARKER = "MRN-12345678-PATIENT-JOHN-SMITH-DOB-1972-03-15"
        msgs = [
            EmailMessage(
                message_id="m1",
                provider="imap",
                sender="user@example.com",
                recipients=["other@example.com"],
                subject="Re: hi",
                body_text=f"reply body containing {PHI_MARKER}",
                date=datetime(2026, 5, 1, tzinfo=timezone.utc),
            ),
        ]
        await distill_hipaa_account(
            aid, db_conn=db, messages=msgs,
            actor_user_id=uid, skip_ner=True,
        )

        # 1. Descriptor row carries no PHI marker.
        desc_row = get_hipaa_style_descriptor(db, aid)
        assert desc_row is not None
        import json as _json
        desc_json = _json.dumps(desc_row["descriptor"])
        assert PHI_MARKER not in desc_json

        # 2. Audit row carries no PHI marker.
        events = list_style_distill_events(db, account_id=aid)
        assert events
        for ev in events:
            for v in ev.values():
                if isinstance(v, str):
                    assert PHI_MARKER not in v

        # 3. The hipaa_style_descriptors raw JSON column carries no
        #    PHI marker either (paranoia — descriptor read goes through
        #    a JSON parse already; this validates the on-disk shape).
        on_disk = db.execute(
            "SELECT descriptor_json FROM hipaa_style_descriptors "
            "WHERE account_id = ?",
            (aid,),
        ).fetchone()
        assert PHI_MARKER not in on_disk["descriptor_json"]


# ---------------------------------------------------------------------------
# Cadence + force
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestCadence:
    """Within-cadence repeated runs short-circuit; force=True overrides."""

    async def test_cadence_skip_after_recent_success(self, db, monkeypatch):
        uid = _seed_user(db)
        aid = _seed_account(db, user_id=uid, hipaa=True)
        set_hipaa_style_distill_enabled(db, True)
        set_style_knobs_hipaa_allow(db, aid, enabled=True)
        backend = _MockBackend(CLEAN_LLM_RESPONSE)
        _install_mock_backend(monkeypatch, backend)
        # First run lands a descriptor.
        await distill_hipaa_account(
            aid, db_conn=db, messages=_make_messages(),
            actor_user_id=uid, skip_ner=True,
        )
        assert len(backend.calls) == 1
        # Second run within the cadence window: skipped.
        result = await distill_hipaa_account(
            aid, db_conn=db, messages=_make_messages(),
            actor_user_id=uid, skip_ner=True,
        )
        assert result.status == "cadence_skip"
        assert len(backend.calls) == 1  # no second LLM call

    async def test_force_overrides_cadence(self, db, monkeypatch):
        uid = _seed_user(db)
        aid = _seed_account(db, user_id=uid, hipaa=True)
        set_hipaa_style_distill_enabled(db, True)
        set_style_knobs_hipaa_allow(db, aid, enabled=True)
        backend = _MockBackend(CLEAN_LLM_RESPONSE)
        _install_mock_backend(monkeypatch, backend)
        await distill_hipaa_account(
            aid, db_conn=db, messages=_make_messages(),
            actor_user_id=uid, skip_ner=True,
        )
        result = await distill_hipaa_account(
            aid, db_conn=db, messages=_make_messages(),
            actor_user_id=uid, skip_ner=True, force=True,
        )
        assert result.status == "success"
        assert len(backend.calls) == 2
