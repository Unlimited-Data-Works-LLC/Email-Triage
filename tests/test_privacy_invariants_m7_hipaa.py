"""Privacy invariants for HIPAA-safe per-contact style descriptors (#152 W3).

CI guard for the M-7 HIPAA path at
:mod:`email_triage.style_learning.per_contact_hipaa`. Each test pins a
contract that, if loosened, would let the plaintext recipient identity
escape into storage / audit / logs.

The backend is ALWAYS mocked here — no test in this module touches a
real LLM endpoint. The salt source is a stub ``InMemorySecrets`` so we
can pin the salted-hash semantics without hitting Fernet.

Sibling: ``tests/test_privacy_invariants_distill_hipaa.py`` pins the
M-3 (account-level) path. The per-contact tests REUSE the same
fixtures + mock backend shape so divergence between the two paths
shows up as a behavioural delta rather than a fixture refactor.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone, timedelta
from typing import Any

import pytest

from email_triage.engine.models import EmailMessage
from email_triage.style_learning import (
    HIPAA_RECIPIENT_SALT_SECRET_KEY,
    PerContactDistillResult,
    SaltUnavailableError,
    distill_hipaa_per_contact,
    get_contact_style_overlay,
    get_or_init_recipient_salt,
    hash_recipient_for_install,
    per_contact_gc_daily_sweep,
)
from email_triage.style_learning import per_contact_hipaa as per_contact_mod
from email_triage.web.db import (
    HIPAA_PER_CONTACT_FRESHNESS_DAYS,
    HIPAA_PER_CONTACT_GC_DAYS,
    delete_per_contact_style_hipaa,
    delete_all_per_contact_style_hipaa,
    get_per_contact_style_hipaa,
    get_style_distill_contact_queue_entry,
    init_db,
    list_paused_style_distill_contacts,
    list_per_contact_style_hipaa_for_account,
    list_style_distill_events,
    set_hipaa_style_distill_enabled,
    set_per_contact_style_hipaa,
    set_style_knobs_hipaa_allow,
)


# ---------------------------------------------------------------------------
# Fixtures (mirror test_privacy_invariants_distill_hipaa.py for parity)
# ---------------------------------------------------------------------------

@pytest.fixture
def db() -> sqlite3.Connection:
    return init_db(":memory:")


class _InMemorySecrets:
    """Stand-in for :class:`DbSecrets` — in-memory key→value store.

    Mirrors the get/set/delete surface. Tests use this so we can pin
    the salt source without needing a real Fernet master key.
    """

    def __init__(self, initial: dict[str, str] | None = None) -> None:
        self.store: dict[str, str] = dict(initial or {})
        self.read_log: list[str] = []
        self.write_log: list[str] = []

    def get(self, key: str) -> str | None:
        self.read_log.append(key)
        return self.store.get(key)

    def set(self, key: str, value: str) -> None:
        self.write_log.append(key)
        self.store[key] = value

    def delete(self, key: str) -> bool:
        return self.store.pop(key, None) is not None


@pytest.fixture
def secrets() -> _InMemorySecrets:
    """A fresh in-memory secrets store per test."""
    return _InMemorySecrets()


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
            recipients=["contact@external.example"],
            subject=f"Subject {i}",
            body_text=(
                "A short reply body. Patient John Smith MRN 12345678 "
                "phone 555-867-5309 lives at 123 Main Street."
            ),
            date=datetime(2026, 5, 1, tzinfo=timezone.utc),
        )
        for i in range(n)
    ]


# Mock backend identical to the M-3 fixture shape so the two test
# modules stay in lock-step.
class _MockBackend:
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
    """Monkeypatch the per-contact module's load_backend symbol."""
    def fake_loader(backend_id, *, db_conn, secrets=None, config=None):
        return backend
    monkeypatch.setattr(per_contact_mod, "load_backend", fake_loader)


# Clean JSON the LLM would return on a successful run. Same shape as
# the M-3 fixture so the per-contact path produces an identical
# descriptor shape.
CLEAN_LLM_RESPONSE = (
    '{"tone": "professional", "formality_level": 4, '
    '"greeting_style": "hi_first_name", "signoff_style": "thanks", '
    '"sentence_length_pref": "medium", "vocabulary_register": "plain", '
    '"paragraph_count_typical": 2, '
    '"common_phrases": ["let me know", "happy to help"]}'
)


# A plaintext recipient address used across multiple tests. The hash
# of this with the test fixture's salt is what should land in storage;
# the plaintext should NEVER appear in any persisted column or log.
PLAINTEXT_RECIPIENT_MARKER = "PerSon.Recurring+phi@External-Example.org"


# ---------------------------------------------------------------------------
# Hash helper invariants
# ---------------------------------------------------------------------------

class TestHashRecipientForInstall:
    """The salted-hash helper is the foundation of the privacy posture.

    Every persistence + audit path goes through it; if it breaks, the
    whole pipeline regresses. Pin shape, salt-required behaviour, and
    per-install isolation here.
    """

    def test_hash_is_64_hex_lowercase(self, secrets):
        """Output shape: 64-char lowercase SHA-256 hex digest."""
        h = hash_recipient_for_install(
            PLAINTEXT_RECIPIENT_MARKER, secrets=secrets,
        )
        assert len(h) == 64
        assert h == h.lower()
        assert all(c in "0123456789abcdef" for c in h)

    def test_hash_is_deterministic_same_salt(self, secrets):
        """Same input + same salt -> same hash (look-up works)."""
        h1 = hash_recipient_for_install(
            PLAINTEXT_RECIPIENT_MARKER, secrets=secrets,
        )
        h2 = hash_recipient_for_install(
            PLAINTEXT_RECIPIENT_MARKER, secrets=secrets,
        )
        assert h1 == h2

    def test_hash_normalises_case_and_whitespace(self, secrets):
        """``a@b`` and ``  A@B  `` hash to the same digest.

        Provider casing drift (some mailers upper-case the host part)
        must not cause look-up misses.
        """
        h1 = hash_recipient_for_install(
            "a@b.example", secrets=secrets,
        )
        h2 = hash_recipient_for_install(
            "  A@B.EXAMPLE  ", secrets=secrets,
        )
        assert h1 == h2

    def test_hash_strips_display_name_wrapper(self, secrets):
        """``Name <a@b>`` and ``a@b`` hash to the same digest."""
        h1 = hash_recipient_for_install(
            "x@y.example", secrets=secrets,
        )
        h2 = hash_recipient_for_install(
            "Some Name <x@y.example>", secrets=secrets,
        )
        assert h1 == h2

    def test_hash_differs_across_installs(self):
        """Two installs with different salts produce different hashes
        for the same input. Prevents cross-install correlation."""
        secrets_a = _InMemorySecrets()
        secrets_b = _InMemorySecrets()
        # Force salt generation in both.
        get_or_init_recipient_salt(secrets_a)
        get_or_init_recipient_salt(secrets_b)
        assert (
            secrets_a.store[HIPAA_RECIPIENT_SALT_SECRET_KEY]
            != secrets_b.store[HIPAA_RECIPIENT_SALT_SECRET_KEY]
        )
        h_a = hash_recipient_for_install(
            PLAINTEXT_RECIPIENT_MARKER, secrets=secrets_a,
        )
        h_b = hash_recipient_for_install(
            PLAINTEXT_RECIPIENT_MARKER, secrets=secrets_b,
        )
        assert h_a != h_b, (
            "salts collided OR cross-install correlation possible — "
            "this breaks the per-install isolation invariant"
        )

    def test_hash_rejects_no_secrets(self):
        """secrets=None must raise — no empty-salt fallback.

        The empty-salt path is a rainbow-table attack vector. The
        helper MUST refuse rather than hash with an empty / known
        salt.
        """
        with pytest.raises(SaltUnavailableError):
            hash_recipient_for_install(
                PLAINTEXT_RECIPIENT_MARKER, secrets=None,
            )

    def test_hash_rejects_empty_address(self, secrets):
        """Empty string raises ValueError — caller bug."""
        with pytest.raises(ValueError):
            hash_recipient_for_install("", secrets=secrets)

    def test_hash_rejects_non_email_string(self, secrets):
        """A string with no ``@`` raises ValueError — caller bug."""
        with pytest.raises(ValueError):
            hash_recipient_for_install(
                "just-a-name-no-at-sign", secrets=secrets,
            )

    def test_salt_is_auto_generated_on_first_use(self, secrets):
        """First call generates + persists; subsequent calls re-read."""
        assert HIPAA_RECIPIENT_SALT_SECRET_KEY not in secrets.store
        salt1 = get_or_init_recipient_salt(secrets)
        # Persisted now.
        assert HIPAA_RECIPIENT_SALT_SECRET_KEY in secrets.store
        # Second call returns the same value.
        salt2 = get_or_init_recipient_salt(secrets)
        assert salt1 == salt2

    def test_salt_is_at_least_32_bytes(self, secrets):
        """Salt size meets the minimum bar (32 bytes = 256 bits)."""
        salt = get_or_init_recipient_salt(secrets)
        assert len(salt) >= 32

    def test_corrupted_stored_salt_raises(self):
        """A non-hex string in the store raises SaltUnavailableError."""
        secrets = _InMemorySecrets({
            HIPAA_RECIPIENT_SALT_SECRET_KEY: "not-hex-at-all-zzz",
        })
        with pytest.raises(SaltUnavailableError):
            get_or_init_recipient_salt(secrets)


# ---------------------------------------------------------------------------
# Persistence invariants — recipient identity NEVER stored in plaintext
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestRecipientNotPlainTextOnDisk:
    """The headline M-7 HIPAA invariant: the plaintext recipient address
    NEVER lands in any persisted column."""

    async def _open_all_gates(self, db) -> tuple[int, int]:
        uid = _seed_user(db)
        aid = _seed_account(db, user_id=uid, hipaa=True)
        set_hipaa_style_distill_enabled(db, True)
        set_style_knobs_hipaa_allow(db, aid, enabled=True)
        return uid, aid

    async def test_plaintext_recipient_not_in_descriptor_row(
        self, db, secrets, monkeypatch,
    ):
        uid, aid = await self._open_all_gates(db)
        backend = _MockBackend(CLEAN_LLM_RESPONSE)
        _install_mock_backend(monkeypatch, backend)
        result = await distill_hipaa_per_contact(
            aid, PLAINTEXT_RECIPIENT_MARKER,
            db_conn=db, secrets=secrets,
            messages=_make_messages(),
            actor_user_id=uid, skip_ner=True,
        )
        assert result.status == "success"
        assert result.recipient_hash
        # The plaintext marker must NOT appear in any column of any row.
        rows = db.execute(
            "SELECT * FROM per_contact_style_hipaa"
        ).fetchall()
        assert rows
        for row in rows:
            for v in row:
                if isinstance(v, str):
                    assert PLAINTEXT_RECIPIENT_MARKER not in v
                    # Also reject case-variant leakage.
                    assert PLAINTEXT_RECIPIENT_MARKER.lower() not in v.lower()

    async def test_plaintext_recipient_not_in_audit_row(
        self, db, secrets, monkeypatch,
    ):
        uid, aid = await self._open_all_gates(db)
        backend = _MockBackend(CLEAN_LLM_RESPONSE)
        _install_mock_backend(monkeypatch, backend)
        await distill_hipaa_per_contact(
            aid, PLAINTEXT_RECIPIENT_MARKER,
            db_conn=db, secrets=secrets,
            messages=_make_messages(),
            actor_user_id=uid, skip_ner=True,
        )
        # Audit rows for THIS account; check both per_contact + any
        # account_m3 rows in case a sibling write happened.
        events = list_style_distill_events(db, account_id=aid)
        assert events
        for ev in events:
            for v in ev.values():
                if isinstance(v, str):
                    assert PLAINTEXT_RECIPIENT_MARKER not in v
                    assert PLAINTEXT_RECIPIENT_MARKER.lower() not in v.lower()
        # And the per_contact row carries kind='per_contact' +
        # recipient_hash populated (not the plaintext).
        per_contact_events = [e for e in events if e["kind"] == "per_contact"]
        assert per_contact_events
        for ev in per_contact_events:
            assert ev["recipient_hash"]
            assert len(ev["recipient_hash"]) == 64
            assert "@" not in ev["recipient_hash"]

    async def test_plaintext_recipient_not_in_queue_row_on_failure(
        self, db, secrets, monkeypatch,
    ):
        """Backend failure -> queue row exists; plaintext never lands."""
        uid, aid = await self._open_all_gates(db)
        backend = _MockBackend(
            "", raise_on_call=RuntimeError("network unreachable"),
        )
        _install_mock_backend(monkeypatch, backend)
        await distill_hipaa_per_contact(
            aid, PLAINTEXT_RECIPIENT_MARKER,
            db_conn=db, secrets=secrets,
            messages=_make_messages(),
            actor_user_id=uid, skip_ner=True,
        )
        rows = db.execute(
            "SELECT * FROM style_distill_queue_contacts"
        ).fetchall()
        assert rows
        for row in rows:
            for v in row:
                if isinstance(v, str):
                    assert PLAINTEXT_RECIPIENT_MARKER not in v
                    assert PLAINTEXT_RECIPIENT_MARKER.lower() not in v.lower()

    async def test_helper_rejects_plaintext_in_recipient_hash_param(
        self, db, secrets,
    ):
        """``set_per_contact_style_hipaa`` rejects any non-hex-digest
        value in the recipient_hash slot — guards against a caller
        accidentally passing the plaintext."""
        from email_triage.web.db import set_per_contact_style_hipaa
        with pytest.raises(ValueError):
            set_per_contact_style_hipaa(
                db,
                account_id=1,
                recipient_hash=PLAINTEXT_RECIPIENT_MARKER,  # plaintext!
                descriptor={"tone": "professional"},
                version=1,
                message_count=1,
            )


# ---------------------------------------------------------------------------
# Body-never-persisted invariant (mirrors M-3 test)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestBodyNeverPersists:
    """Same headline HIPAA invariant as M-3: message bodies must NEVER
    land in storage. The per-contact path must hold the line."""

    async def test_body_not_in_descriptor_or_audit(
        self, db, secrets, monkeypatch,
    ):
        uid = _seed_user(db)
        aid = _seed_account(db, user_id=uid, hipaa=True)
        set_hipaa_style_distill_enabled(db, True)
        set_style_knobs_hipaa_allow(db, aid, enabled=True)
        backend = _MockBackend(CLEAN_LLM_RESPONSE)
        _install_mock_backend(monkeypatch, backend)

        PHI_MARKER = "MRN-12345678-PATIENT-JOHN-SMITH-DOB-1972-03-15"
        msgs = [
            EmailMessage(
                message_id="m1",
                provider="imap",
                sender="user@example.com",
                recipients=["contact@external.example"],
                subject="Re: hi",
                body_text=f"reply body containing {PHI_MARKER}",
                date=datetime(2026, 5, 1, tzinfo=timezone.utc),
            ),
        ]
        await distill_hipaa_per_contact(
            aid, PLAINTEXT_RECIPIENT_MARKER,
            db_conn=db, secrets=secrets,
            messages=msgs,
            actor_user_id=uid, skip_ner=True,
        )

        # Descriptor row.
        rh = hash_recipient_for_install(
            PLAINTEXT_RECIPIENT_MARKER, secrets=secrets,
        )
        desc_row = get_per_contact_style_hipaa(
            db, account_id=aid, recipient_hash=rh,
        )
        assert desc_row is not None
        import json as _json
        desc_json = _json.dumps(desc_row["descriptor"])
        assert PHI_MARKER not in desc_json

        # Audit rows.
        events = list_style_distill_events(db, account_id=aid)
        assert events
        for ev in events:
            for v in ev.values():
                if isinstance(v, str):
                    assert PHI_MARKER not in v

        # On-disk JSON column.
        on_disk = db.execute(
            "SELECT descriptor_json FROM per_contact_style_hipaa "
            "WHERE account_id = ? AND recipient_hash = ?",
            (aid, rh),
        ).fetchone()
        assert PHI_MARKER not in on_disk["descriptor_json"]


# ---------------------------------------------------------------------------
# Gating tests (mirror the M-3 gating tests for parity)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestGating:
    """The per-contact distill MUST short-circuit before reaching the
    LLM when any gate is closed, just like the M-3 path."""

    async def test_install_wide_flag_off(self, db, secrets, monkeypatch):
        uid = _seed_user(db)
        aid = _seed_account(db, user_id=uid, hipaa=True)
        backend = _MockBackend(CLEAN_LLM_RESPONSE)
        _install_mock_backend(monkeypatch, backend)
        result = await distill_hipaa_per_contact(
            aid, PLAINTEXT_RECIPIENT_MARKER,
            db_conn=db, secrets=secrets,
            messages=_make_messages(),
            actor_user_id=uid, skip_ner=True,
        )
        assert result.status == "disabled"
        assert backend.calls == []
        # Audit row landed with kind='per_contact'.
        events = list_style_distill_events(db, account_id=aid)
        assert len(events) == 1
        assert events[0]["outcome"] == "disabled"
        assert events[0]["kind"] == "per_contact"

    async def test_not_hipaa_account(self, db, secrets, monkeypatch):
        uid = _seed_user(db)
        aid = _seed_account(db, user_id=uid, hipaa=False)
        set_hipaa_style_distill_enabled(db, True)
        backend = _MockBackend(CLEAN_LLM_RESPONSE)
        _install_mock_backend(monkeypatch, backend)
        result = await distill_hipaa_per_contact(
            aid, PLAINTEXT_RECIPIENT_MARKER,
            db_conn=db, secrets=secrets,
            messages=_make_messages(),
            actor_user_id=uid, skip_ner=True,
        )
        assert result.status == "not_hipaa"
        assert backend.calls == []

    async def test_not_opted_in(self, db, secrets, monkeypatch):
        uid = _seed_user(db)
        aid = _seed_account(db, user_id=uid, hipaa=True)
        set_hipaa_style_distill_enabled(db, True)
        backend = _MockBackend(CLEAN_LLM_RESPONSE)
        _install_mock_backend(monkeypatch, backend)
        result = await distill_hipaa_per_contact(
            aid, PLAINTEXT_RECIPIENT_MARKER,
            db_conn=db, secrets=secrets,
            messages=_make_messages(),
            actor_user_id=uid, skip_ner=True,
        )
        assert result.status == "not_opted_in"
        assert backend.calls == []

    async def test_salt_unavailable_short_circuits(self, db, monkeypatch):
        """secrets=None -> backend_fail, no LLM call, no plaintext stored."""
        uid = _seed_user(db)
        aid = _seed_account(db, user_id=uid, hipaa=True)
        set_hipaa_style_distill_enabled(db, True)
        set_style_knobs_hipaa_allow(db, aid, enabled=True)
        backend = _MockBackend(CLEAN_LLM_RESPONSE)
        _install_mock_backend(monkeypatch, backend)
        result = await distill_hipaa_per_contact(
            aid, PLAINTEXT_RECIPIENT_MARKER,
            db_conn=db, secrets=None,  # no salt provider
            messages=_make_messages(),
            actor_user_id=uid, skip_ner=True,
        )
        assert result.status == "backend_fail"
        assert result.error_class == "SaltUnavailableError"
        assert backend.calls == []
        # Audit row exists with recipient_hash NULL (we couldn't
        # hash safely).
        events = list_style_distill_events(db, account_id=aid)
        assert len(events) == 1
        assert events[0]["error_class"] == "SaltUnavailableError"
        # No descriptor row.
        rows = db.execute(
            "SELECT 1 FROM per_contact_style_hipaa WHERE account_id = ?",
            (aid,),
        ).fetchall()
        assert rows == []


# ---------------------------------------------------------------------------
# Happy path + scrubber outcomes
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestDistillOutcomes:
    """End-to-end behaviours: clean / phrase-leak / structural-leak /
    backend-fail / no-messages."""

    async def _open_all_gates(self, db) -> tuple[int, int]:
        uid = _seed_user(db)
        aid = _seed_account(db, user_id=uid, hipaa=True)
        set_hipaa_style_distill_enabled(db, True)
        set_style_knobs_hipaa_allow(db, aid, enabled=True)
        return uid, aid

    async def test_clean_response_persists_overlay(
        self, db, secrets, monkeypatch,
    ):
        uid, aid = await self._open_all_gates(db)
        backend = _MockBackend(CLEAN_LLM_RESPONSE)
        _install_mock_backend(monkeypatch, backend)
        result = await distill_hipaa_per_contact(
            aid, PLAINTEXT_RECIPIENT_MARKER,
            db_conn=db, secrets=secrets,
            messages=_make_messages(),
            actor_user_id=uid, skip_ner=True,
        )
        assert result.status == "success"
        assert backend.calls
        rh = hash_recipient_for_install(
            PLAINTEXT_RECIPIENT_MARKER, secrets=secrets,
        )
        row = get_per_contact_style_hipaa(
            db, account_id=aid, recipient_hash=rh,
        )
        assert row is not None
        assert row["descriptor"]["tone"] == "professional"
        # No queue entry on success.
        assert get_style_distill_contact_queue_entry(
            db, account_id=aid, recipient_hash=rh,
        ) is None

    async def test_structural_leak_drops_overlay(
        self, db, secrets, monkeypatch,
    ):
        """LLM leaks PHI into a closed-enum field -> scrubber fails,
        overlay NOT persisted, ONLY this contact pauses (account-
        level + other contacts unaffected)."""
        uid, aid = await self._open_all_gates(db)
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
        monkeypatch.setattr(per_contact_mod, "scrub_descriptor", fake_scrub)

        result = await distill_hipaa_per_contact(
            aid, PLAINTEXT_RECIPIENT_MARKER,
            db_conn=db, secrets=secrets,
            messages=_make_messages(),
            actor_user_id=uid, skip_ner=True,
        )
        assert result.status == "scrubber_fail"
        rh = hash_recipient_for_install(
            PLAINTEXT_RECIPIENT_MARKER, secrets=secrets,
        )
        # No overlay row.
        assert get_per_contact_style_hipaa(
            db, account_id=aid, recipient_hash=rh,
        ) is None
        # Per-contact queue row paused.
        paused = list_paused_style_distill_contacts(db)
        assert any(
            p["account_id"] == aid and p["recipient_hash"] == rh
            for p in paused
        )
        # Audit row.
        events = list_style_distill_events(db, account_id=aid)
        assert events[0]["outcome"] == "scrubber_fail"
        assert events[0]["kind"] == "per_contact"

    async def test_backend_failure_enqueues_retry(
        self, db, secrets, monkeypatch,
    ):
        uid, aid = await self._open_all_gates(db)
        backend = _MockBackend(
            "", raise_on_call=RuntimeError("network unreachable"),
        )
        _install_mock_backend(monkeypatch, backend)
        result = await distill_hipaa_per_contact(
            aid, PLAINTEXT_RECIPIENT_MARKER,
            db_conn=db, secrets=secrets,
            messages=_make_messages(),
            actor_user_id=uid, skip_ner=True,
        )
        assert result.status == "backend_fail"
        rh = hash_recipient_for_install(
            PLAINTEXT_RECIPIENT_MARKER, secrets=secrets,
        )
        qrow = get_style_distill_contact_queue_entry(
            db, account_id=aid, recipient_hash=rh,
        )
        assert qrow is not None
        assert qrow["attempt_count"] == 1
        # Error class but never the message text.
        events = list_style_distill_events(db, account_id=aid)
        assert events[0]["error_class"] == "RuntimeError"
        for v in events[0].values():
            if isinstance(v, str):
                assert "network unreachable" not in v

    async def test_no_messages_short_circuits(
        self, db, secrets, monkeypatch,
    ):
        uid, aid = await self._open_all_gates(db)
        backend = _MockBackend(CLEAN_LLM_RESPONSE)
        _install_mock_backend(monkeypatch, backend)
        result = await distill_hipaa_per_contact(
            aid, PLAINTEXT_RECIPIENT_MARKER,
            db_conn=db, secrets=secrets,
            messages=[],
            actor_user_id=uid, skip_ner=True,
        )
        assert result.status == "no_messages"
        assert backend.calls == []


# ---------------------------------------------------------------------------
# Per-contact pause does NOT affect account-level path
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestPerContactIsolation:
    """Pausing one contact's overlay MUST NOT affect the account-level
    M-3 path or other contacts."""

    async def test_pause_one_contact_other_contact_untouched(
        self, db, secrets, monkeypatch,
    ):
        uid = _seed_user(db)
        aid = _seed_account(db, user_id=uid, hipaa=True)
        set_hipaa_style_distill_enabled(db, True)
        set_style_knobs_hipaa_allow(db, aid, enabled=True)

        # First contact: structural leak -> pause.
        from email_triage.style_learning.phi_scrubber import ScrubResult
        backend = _MockBackend(CLEAN_LLM_RESPONSE)
        _install_mock_backend(monkeypatch, backend)
        monkeypatch.setattr(
            per_contact_mod, "scrub_descriptor",
            lambda _d, *, skip_ner=False: ScrubResult(
                passed=False, scrubbed_descriptor={},
                layer2_matches=[("tone", "name_honorific")],
            ),
        )
        await distill_hipaa_per_contact(
            aid, "leak@one.example",
            db_conn=db, secrets=secrets,
            messages=_make_messages(),
            actor_user_id=uid, skip_ner=True,
        )

        # Second contact: clean path.
        monkeypatch.setattr(
            per_contact_mod, "scrub_descriptor",
            __import__(
                "email_triage.style_learning.phi_scrubber",
                fromlist=["scrub_descriptor"],
            ).scrub_descriptor,
        )
        result2 = await distill_hipaa_per_contact(
            aid, "clean@two.example",
            db_conn=db, secrets=secrets,
            messages=_make_messages(),
            actor_user_id=uid, skip_ner=True,
        )
        assert result2.status == "success"
        # Second contact has an overlay.
        rh2 = hash_recipient_for_install(
            "clean@two.example", secrets=secrets,
        )
        assert get_per_contact_style_hipaa(
            db, account_id=aid, recipient_hash=rh2,
        ) is not None
        # First contact is paused but second contact is NOT.
        paused = list_paused_style_distill_contacts(db)
        rh1 = hash_recipient_for_install(
            "leak@one.example", secrets=secrets,
        )
        paused_hashes = {p["recipient_hash"] for p in paused}
        assert rh1 in paused_hashes
        assert rh2 not in paused_hashes


# ---------------------------------------------------------------------------
# Draft-time overlay look-up
# ---------------------------------------------------------------------------

class TestGetContactStyleOverlay:
    """Look-up semantics: hash the To: address, fetch by hash + account,
    apply freshness gate, return None for misses + stale rows."""

    def test_returns_none_when_no_row(self, db, secrets):
        """No row for hashed recipient -> None."""
        uid = _seed_user(db)
        aid = _seed_account(db, user_id=uid, hipaa=True)
        result = get_contact_style_overlay(
            db,
            account_id=aid,
            recipient_address="never-seen@external.example",
            secrets=secrets,
        )
        assert result is None

    def test_returns_descriptor_when_fresh(self, db, secrets):
        uid = _seed_user(db)
        aid = _seed_account(db, user_id=uid, hipaa=True)
        rh = hash_recipient_for_install(
            PLAINTEXT_RECIPIENT_MARKER, secrets=secrets,
        )
        # Seed a fresh row directly.
        set_per_contact_style_hipaa(
            db,
            account_id=aid,
            recipient_hash=rh,
            descriptor={
                "tone": "professional",
                "formality_level": 4,
                "greeting_style": "hi_first_name",
                "signoff_style": "thanks",
                "sentence_length_pref": "medium",
                "vocabulary_register": "plain",
                "paragraph_count_typical": 2,
                "common_phrases": ["let me know"],
            },
            version=1,
            message_count=20,
        )
        overlay = get_contact_style_overlay(
            db,
            account_id=aid,
            recipient_address=PLAINTEXT_RECIPIENT_MARKER,
            secrets=secrets,
        )
        assert overlay is not None
        assert overlay["tone"] == "professional"

    def test_returns_none_when_stale(self, db, secrets):
        """Row exists but ``last_distilled_at`` is past the freshness
        window -> None (caller falls back to account-level)."""
        uid = _seed_user(db)
        aid = _seed_account(db, user_id=uid, hipaa=True)
        rh = hash_recipient_for_install(
            PLAINTEXT_RECIPIENT_MARKER, secrets=secrets,
        )
        # Seed a row, then back-date last_distilled_at to 60 days ago.
        set_per_contact_style_hipaa(
            db,
            account_id=aid,
            recipient_hash=rh,
            descriptor={
                "tone": "neutral",
                "formality_level": 3,
                "greeting_style": "none",
                "signoff_style": "none",
                "sentence_length_pref": "medium",
                "vocabulary_register": "plain",
                "paragraph_count_typical": 2,
                "common_phrases": [],
            },
            version=1,
            message_count=20,
        )
        stale_iso = (
            datetime.now(timezone.utc) - timedelta(days=60)
        ).isoformat()
        db.execute(
            "UPDATE per_contact_style_hipaa SET last_distilled_at = ? "
            "WHERE account_id = ? AND recipient_hash = ?",
            (stale_iso, aid, rh),
        )
        db.commit()
        overlay = get_contact_style_overlay(
            db,
            account_id=aid,
            recipient_address=PLAINTEXT_RECIPIENT_MARKER,
            secrets=secrets,
            freshness_days=HIPAA_PER_CONTACT_FRESHNESS_DAYS,
        )
        assert overlay is None

    def test_returns_none_when_salt_unavailable(self, db):
        """No secrets -> None (can't hash; caller falls back).

        This is the look-up path's defense — it must NOT raise. The
        draft-reply call site catches the absence of an overlay by
        seeing None; raising would crash drafting entirely."""
        uid = _seed_user(db)
        aid = _seed_account(db, user_id=uid, hipaa=True)
        overlay = get_contact_style_overlay(
            db,
            account_id=aid,
            recipient_address=PLAINTEXT_RECIPIENT_MARKER,
            secrets=None,
        )
        assert overlay is None


# ---------------------------------------------------------------------------
# GC sweep
# ---------------------------------------------------------------------------

class TestGCSweep:
    """``per_contact_gc_daily_sweep`` deletes rows older than
    :data:`HIPAA_PER_CONTACT_GC_DAYS` (90 days)."""

    def test_no_op_when_clean(self, db):
        summary = per_contact_gc_daily_sweep(db)
        assert summary["removed"] == 0
        assert summary["gc_days"] == HIPAA_PER_CONTACT_GC_DAYS

    def test_removes_old_rows_only(self, db, secrets):
        uid = _seed_user(db)
        aid = _seed_account(db, user_id=uid, hipaa=True)
        # Two rows: one fresh, one 120 days old.
        rh_fresh = hash_recipient_for_install(
            "fresh@external.example", secrets=secrets,
        )
        rh_stale = hash_recipient_for_install(
            "stale@external.example", secrets=secrets,
        )
        set_per_contact_style_hipaa(
            db,
            account_id=aid,
            recipient_hash=rh_fresh,
            descriptor={
                "tone": "professional",
                "formality_level": 4,
                "greeting_style": "hi_first_name",
                "signoff_style": "thanks",
                "sentence_length_pref": "medium",
                "vocabulary_register": "plain",
                "paragraph_count_typical": 2,
                "common_phrases": [],
            },
            version=1,
            message_count=20,
        )
        set_per_contact_style_hipaa(
            db,
            account_id=aid,
            recipient_hash=rh_stale,
            descriptor={
                "tone": "neutral",
                "formality_level": 3,
                "greeting_style": "none",
                "signoff_style": "none",
                "sentence_length_pref": "medium",
                "vocabulary_register": "plain",
                "paragraph_count_typical": 2,
                "common_phrases": [],
            },
            version=1,
            message_count=20,
        )
        # Back-date the stale row.
        old_iso = (
            datetime.now(timezone.utc) - timedelta(days=120)
        ).isoformat()
        db.execute(
            "UPDATE per_contact_style_hipaa SET last_distilled_at = ? "
            "WHERE account_id = ? AND recipient_hash = ?",
            (old_iso, aid, rh_stale),
        )
        db.commit()

        summary = per_contact_gc_daily_sweep(db)
        assert summary["removed"] == 1
        # Fresh row survived; stale row gone.
        assert get_per_contact_style_hipaa(
            db, account_id=aid, recipient_hash=rh_fresh,
        ) is not None
        assert get_per_contact_style_hipaa(
            db, account_id=aid, recipient_hash=rh_stale,
        ) is None

    def test_idempotent(self, db, secrets):
        """Re-running on a clean state returns 0."""
        per_contact_gc_daily_sweep(db)
        summary = per_contact_gc_daily_sweep(db)
        assert summary["removed"] == 0

    def test_cascades_on_account_delete(self, db, secrets):
        """FK ON DELETE CASCADE removes per-contact rows when the
        account is deleted."""
        uid = _seed_user(db)
        aid = _seed_account(db, user_id=uid, hipaa=True)
        rh = hash_recipient_for_install(
            PLAINTEXT_RECIPIENT_MARKER, secrets=secrets,
        )
        set_per_contact_style_hipaa(
            db,
            account_id=aid,
            recipient_hash=rh,
            descriptor={
                "tone": "professional",
                "formality_level": 4,
                "greeting_style": "hi_first_name",
                "signoff_style": "thanks",
                "sentence_length_pref": "medium",
                "vocabulary_register": "plain",
                "paragraph_count_typical": 2,
                "common_phrases": [],
            },
            version=1,
            message_count=20,
        )
        # Ensure FK pragma on for this connection.
        db.execute("PRAGMA foreign_keys = ON")
        db.execute("DELETE FROM email_accounts WHERE id = ?", (aid,))
        db.commit()
        # Row gone.
        rows = db.execute(
            "SELECT 1 FROM per_contact_style_hipaa "
            "WHERE account_id = ?",
            (aid,),
        ).fetchall()
        assert rows == []


# ---------------------------------------------------------------------------
# Operator "Clear style data" helper
# ---------------------------------------------------------------------------

class TestClearStyleData:
    """``delete_all_per_contact_style_hipaa`` clears every per-contact
    row for an account in one call (operator-driven cleanup)."""

    def test_clear_all_returns_rowcount(self, db, secrets):
        uid = _seed_user(db)
        aid = _seed_account(db, user_id=uid, hipaa=True)
        for addr in ("a@x.example", "b@x.example", "c@x.example"):
            rh = hash_recipient_for_install(addr, secrets=secrets)
            set_per_contact_style_hipaa(
                db,
                account_id=aid,
                recipient_hash=rh,
                descriptor={
                    "tone": "neutral",
                    "formality_level": 3,
                    "greeting_style": "none",
                    "signoff_style": "none",
                    "sentence_length_pref": "medium",
                    "vocabulary_register": "plain",
                    "paragraph_count_typical": 2,
                    "common_phrases": [],
                },
                version=1,
                message_count=20,
            )
        assert len(list_per_contact_style_hipaa_for_account(
            db, account_id=aid,
        )) == 3
        n = delete_all_per_contact_style_hipaa(db, account_id=aid)
        assert n == 3
        assert list_per_contact_style_hipaa_for_account(
            db, account_id=aid,
        ) == []


# ---------------------------------------------------------------------------
# Log-scrub invariant — plaintext recipient never logged
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestLogScrub:
    """The plaintext recipient address must not appear in any log
    record produced during the per-contact distill pass.

    Implementation note: the per-contact distill module deletes the
    plaintext reference immediately after computing the hash and uses
    only the hash in subsequent log lines. This test catches a
    regression where a future commit re-introduces logging the raw
    address (e.g. for "debug").
    """

    async def test_plaintext_never_in_log_records(
        self, db, secrets, monkeypatch, caplog,
    ):
        import logging
        caplog.set_level(logging.DEBUG, logger="email_triage")

        uid = _seed_user(db)
        aid = _seed_account(db, user_id=uid, hipaa=True)
        set_hipaa_style_distill_enabled(db, True)
        set_style_knobs_hipaa_allow(db, aid, enabled=True)
        backend = _MockBackend(CLEAN_LLM_RESPONSE)
        _install_mock_backend(monkeypatch, backend)

        await distill_hipaa_per_contact(
            aid, PLAINTEXT_RECIPIENT_MARKER,
            db_conn=db, secrets=secrets,
            messages=_make_messages(),
            actor_user_id=uid, skip_ner=True,
        )

        for record in caplog.records:
            msg = record.getMessage()
            assert PLAINTEXT_RECIPIENT_MARKER not in msg
            assert PLAINTEXT_RECIPIENT_MARKER.lower() not in msg.lower()
            # Also check structured extras.
            for v in record.__dict__.values():
                if isinstance(v, str):
                    assert PLAINTEXT_RECIPIENT_MARKER not in v
                    assert PLAINTEXT_RECIPIENT_MARKER.lower() not in v.lower()
