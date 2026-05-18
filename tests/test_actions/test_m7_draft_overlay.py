"""Tests for the M-7 per-contact HIPAA overlay draft-time consumer (#171-C).

Scope: when ``build_prompt_messages`` runs for a HIPAA-flagged account,
it looks up per-contact style descriptors (via W3's
``get_contact_style_overlay`` keyed on the salted recipient hash) and
merges them on top of the account-level direction before passing the
result into ``build_style_prompt_prefix``.

Privacy invariants pinned here:

  * HIPAA gate: overlay lookup ONLY fires for HIPAA-flagged accounts.
    A non-HIPAA account with the same recipient hash NEVER consults
    the per-contact table.
  * Log line ``m7_overlay_applied`` carries recipient HASHES only —
    never the plaintext address.
  * Storage path goes through W3's helpers:
    ``hash_recipient_for_install`` + ``set_per_contact_style_hipaa``.

Plus unit coverage for the two new helpers in W3's
``per_contact_hipaa`` module: ``apply_contact_overlay`` (pure dict
merge with string / numeric / list / unknown-field semantics) and
``merge_overlays_for_recipients`` (layered look-up + audit-hash list).

No real PII anywhere -- recipients are ``boss@example.com`` /
``other@example.com`` etc.
"""

from __future__ import annotations

import logging
import sqlite3
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from email_triage.actions.draft_reply import build_prompt_messages
from email_triage.engine.models import Classification, EmailMessage
from email_triage.style_learning.per_contact_hipaa import (
    HIPAA_RECIPIENT_SALT_SECRET_KEY,
    apply_contact_overlay,
    get_contact_style_overlay,
    hash_recipient_for_install,
    merge_overlays_for_recipients,
)
from email_triage.web.db import (
    HIPAA_PER_CONTACT_FRESHNESS_DAYS,
    set_per_contact_style_hipaa,
)


# ---------------------------------------------------------------------------
# Test doubles
# ---------------------------------------------------------------------------

class _FakeSecrets:
    """Minimal SecretsProvider stand-in for W3's salt storage.

    Stores keys in an in-process dict. Compatible with the
    ``get(key)`` / ``set(key, value)`` contract documented in
    :func:`get_or_init_recipient_salt`. The salt that lands here is
    a hex string; subsequent reads return the same string verbatim.
    """

    def __init__(self) -> None:
        self._store: dict[str, str] = {}

    def get(self, key: str) -> str | None:
        return self._store.get(key)

    def set(self, key: str, value: str) -> None:
        self._store[key] = value


# Sentinels for the descriptor shape we feed in. These are HIPAA-
# schema enums; renderer output is asserted via these strings.
ACCT_TONE = "neutral"
OVERLAY_TONE = "formal"
OVERLAY_PHRASE = "OVERLAY_PHRASE_77_specific_to_recipient"
ACCT_PHRASE = "ACCT_PHRASE_42_general"
USER_MSG_SENTINEL = "USER_MSG_SENTINEL_11_incoming_subject"


def _hipaa_descriptor(
    *,
    tone: str = "neutral",
    formality: int = 3,
    common_phrases: list[str] | None = None,
    greeting: str = "hi_first_name",
    signoff: str = "thanks",
    sentence_length: str = "medium",
    vocab: str = "plain",
    paragraph_count: int = 2,
) -> dict:
    """Build a closed-vocabulary HIPAA-schema descriptor."""
    return {
        "tone": tone,
        "formality_level": formality,
        "greeting_style": greeting,
        "signoff_style": signoff,
        "sentence_length_pref": sentence_length,
        "vocabulary_register": vocab,
        "paragraph_count_typical": paragraph_count,
        "common_phrases": list(common_phrases or []),
    }


# ---------------------------------------------------------------------------
# DB fixtures
# ---------------------------------------------------------------------------

def _make_db() -> sqlite3.Connection:
    """Full init_db so every migration ran (per_contact_style_hipaa v28)."""
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
    conn: sqlite3.Connection,
    *,
    hipaa: bool = False,
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


def _account_dict(conn: sqlite3.Connection, account_id: int) -> dict:
    row = conn.execute(
        "SELECT id, hipaa FROM email_accounts WHERE id = ?",
        (account_id,),
    ).fetchone()
    return {
        "id": row["id"],
        "hipaa": bool(row["hipaa"]),
        "config": {"style_learning_enabled": True},
    }


def _make_app(secrets: _FakeSecrets) -> SimpleNamespace:
    """app stand-in with state.secrets but no embedding backend."""
    state = SimpleNamespace(
        embedding_backend=None,
        embedding_model="",
        sqlite_vec_available=False,
        secrets=secrets,
    )
    return SimpleNamespace(state=state)


def _make_message(sender: str = "boss@example.com") -> EmailMessage:
    return EmailMessage(
        message_id="m-1",
        provider="imap",
        sender=sender,
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


def _seed_per_contact_overlay(
    conn: sqlite3.Connection,
    *,
    account_id: int,
    recipient_address: str,
    secrets: _FakeSecrets,
    descriptor: dict,
) -> str:
    """Seed a per-contact descriptor via W3's storage path.

    Computes the hash with W3's ``hash_recipient_for_install`` and
    persists via ``set_per_contact_style_hipaa`` exactly like the
    real distill pipeline. Returns the hash so the test can assert
    audit lines mention it.
    """
    rh = hash_recipient_for_install(recipient_address, secrets=secrets)
    set_per_contact_style_hipaa(
        conn,
        account_id=account_id,
        recipient_hash=rh,
        descriptor=descriptor,
        version=1,
        message_count=20,
        scrubber_outcome="clean",
    )
    return rh


def _enable_style_learning(conn: sqlite3.Connection, account_id: int) -> None:
    """Turn on master + per-account style-learning toggles."""
    from email_triage.web.db import set_style_learning_master_enabled
    set_style_learning_master_enabled(conn, True)
    # Per-account toggle is read from account.config (already True
    # in _account_dict's helper); no DB write needed.


# ===========================================================================
# Integration tests — draft_reply.build_prompt_messages
# ===========================================================================

@pytest.mark.asyncio
class TestHipaaOverlayApplied:
    """When the recipient has a stored overlay, the prompt reflects it."""

    async def test_overlay_descriptor_lands_in_prompt(self, caplog):
        conn = _make_db()
        user_id = _seed_user(conn)
        acct_id = _seed_account(conn, user_id=user_id, hipaa=True)
        _enable_style_learning(conn, acct_id)
        secrets = _FakeSecrets()
        # Seed via W3's documented storage path.
        rh = _seed_per_contact_overlay(
            conn,
            account_id=acct_id,
            recipient_address="boss@example.com",
            secrets=secrets,
            descriptor=_hipaa_descriptor(
                tone=OVERLAY_TONE,
                formality=5,
                common_phrases=[OVERLAY_PHRASE],
            ),
        )
        app = _make_app(secrets)
        account = _account_dict(conn, acct_id)

        with caplog.at_level(logging.INFO, logger="email_triage.actions.draft_reply"):
            messages = await build_prompt_messages(
                db=conn, app=app, account=account, user_id=user_id,
                message=_make_message("boss@example.com"),
                classification=_make_classification(),
            )

        flat = "\n".join(f"[{m['role']}]\n{m['content']}" for m in messages)
        # Descriptor fields surface in the rendered block.
        assert OVERLAY_TONE in flat
        assert OVERLAY_PHRASE in flat
        # Section heading present.
        assert "RECIPIENT STYLE OVERLAY" in flat

        # Audit log fired with the HASH, never the plaintext recipient.
        m7_records = [
            r for r in caplog.records if r.message == "m7_overlay_applied"
        ]
        assert m7_records, "Expected m7_overlay_applied log line"
        rec = m7_records[0]
        # The hash is in the extra dict — never the plaintext.
        hashes = getattr(rec, "recipient_hashes", None)
        assert hashes is not None
        assert rh in hashes
        # Plaintext recipient does NOT leak into the log record.
        rendered = str(rec.__dict__)
        assert "boss@example.com" not in rendered


@pytest.mark.asyncio
class TestHipaaNoOverlay:
    """HIPAA account but no overlay for THIS recipient — fall through."""

    async def test_no_overlay_omits_block(self, caplog):
        conn = _make_db()
        user_id = _seed_user(conn)
        acct_id = _seed_account(conn, user_id=user_id, hipaa=True)
        _enable_style_learning(conn, acct_id)
        secrets = _FakeSecrets()
        # Seed an overlay for someone ELSE so the table isn't empty,
        # to prove we miss the lookup precisely (not by accident).
        _seed_per_contact_overlay(
            conn,
            account_id=acct_id,
            recipient_address="other@example.com",
            secrets=secrets,
            descriptor=_hipaa_descriptor(tone=OVERLAY_TONE),
        )
        app = _make_app(secrets)
        account = _account_dict(conn, acct_id)

        with caplog.at_level(logging.INFO, logger="email_triage.actions.draft_reply"):
            messages = await build_prompt_messages(
                db=conn, app=app, account=account, user_id=user_id,
                # Different recipient -> no overlay match.
                message=_make_message("boss@example.com"),
                classification=_make_classification(),
            )

        flat = "\n".join(f"[{m['role']}]\n{m['content']}" for m in messages)
        # No overlay block.
        assert "RECIPIENT STYLE OVERLAY" not in flat
        assert OVERLAY_TONE not in flat
        # No audit line fired.
        m7_records = [
            r for r in caplog.records if r.message == "m7_overlay_applied"
        ]
        assert m7_records == []


@pytest.mark.asyncio
class TestNonHipaaPrivacyGate:
    """Non-HIPAA accounts MUST NOT consult the per-contact table.

    Defence in depth: even if a per-contact row exists with the
    same hash (e.g. account was HIPAA-flagged then flipped off),
    the overlay lookup never fires.
    """

    async def test_non_hipaa_skips_overlay_lookup(self, caplog):
        conn = _make_db()
        user_id = _seed_user(conn)
        acct_id = _seed_account(conn, user_id=user_id, hipaa=False)
        _enable_style_learning(conn, acct_id)
        secrets = _FakeSecrets()
        # Seed an overlay for the recipient. Should never be consulted.
        _seed_per_contact_overlay(
            conn,
            account_id=acct_id,
            recipient_address="boss@example.com",
            secrets=secrets,
            descriptor=_hipaa_descriptor(
                tone=OVERLAY_TONE,
                common_phrases=[OVERLAY_PHRASE],
            ),
        )
        app = _make_app(secrets)
        account = _account_dict(conn, acct_id)

        with caplog.at_level(logging.INFO, logger="email_triage.actions.draft_reply"):
            messages = await build_prompt_messages(
                db=conn, app=app, account=account, user_id=user_id,
                message=_make_message("boss@example.com"),
                classification=_make_classification(),
            )

        flat = "\n".join(f"[{m['role']}]\n{m['content']}" for m in messages)
        # Overlay strings absent from prompt.
        assert OVERLAY_TONE not in flat
        assert OVERLAY_PHRASE not in flat
        assert "RECIPIENT STYLE OVERLAY" not in flat
        # Audit log never fired.
        m7_records = [
            r for r in caplog.records if r.message == "m7_overlay_applied"
        ]
        assert m7_records == []


# ===========================================================================
# Unit tests — apply_contact_overlay
# ===========================================================================

class TestApplyContactOverlayStrings:
    def test_overlay_string_wins_when_different(self):
        base = {"tone": "neutral"}
        overlay = {"tone": "formal"}
        merged, overridden = apply_contact_overlay(base, overlay)
        assert merged["tone"] == "formal"
        assert "tone" in overridden

    def test_overlay_empty_string_does_not_override(self):
        base = {"tone": "neutral"}
        overlay = {"tone": ""}
        merged, overridden = apply_contact_overlay(base, overlay)
        assert merged["tone"] == "neutral"
        assert overridden == []

    def test_overlay_same_string_not_recorded(self):
        base = {"tone": "neutral"}
        overlay = {"tone": "neutral"}
        merged, overridden = apply_contact_overlay(base, overlay)
        assert merged["tone"] == "neutral"
        assert overridden == []


class TestApplyContactOverlayNumerics:
    def test_overlay_numeric_wins_for_different_value(self):
        base = {"formality_level": 3}
        overlay = {"formality_level": 5}
        merged, overridden = apply_contact_overlay(base, overlay)
        assert merged["formality_level"] == 5
        assert "formality_level" in overridden

    def test_overlay_numeric_zero_overrides(self):
        # Per spec: numerics — overlay wins for ANY different value
        # including 0.
        base = {"paragraph_count_typical": 2}
        overlay = {"paragraph_count_typical": 0}
        merged, overridden = apply_contact_overlay(base, overlay)
        assert merged["paragraph_count_typical"] == 0
        assert "paragraph_count_typical" in overridden

    def test_overlay_numeric_invalid_skipped(self):
        base = {"formality_level": 3}
        overlay = {"formality_level": "not-a-number"}
        merged, overridden = apply_contact_overlay(base, overlay)
        assert merged["formality_level"] == 3
        assert overridden == []


class TestApplyContactOverlayLists:
    def test_common_phrases_union_preserves_order(self):
        base = {"common_phrases": ["alpha", "beta"]}
        overlay = {"common_phrases": ["gamma", "alpha"]}
        merged, overridden = apply_contact_overlay(base, overlay)
        assert merged["common_phrases"] == ["alpha", "beta", "gamma"]
        assert "common_phrases" in overridden

    def test_common_phrases_dedupe_case_insensitive(self):
        base = {"common_phrases": ["Alpha"]}
        overlay = {"common_phrases": ["alpha", "BETA"]}
        merged, overridden = apply_contact_overlay(base, overlay)
        # "alpha" matches "Alpha" case-insensitively, so it is dropped.
        # "BETA" is new -> appended.
        assert merged["common_phrases"] == ["Alpha", "BETA"]
        assert "common_phrases" in overridden

    def test_common_phrases_no_new_entries_no_override(self):
        base = {"common_phrases": ["alpha", "beta"]}
        overlay = {"common_phrases": ["ALPHA"]}
        merged, overridden = apply_contact_overlay(base, overlay)
        # Already represented case-insensitively, nothing added.
        assert merged["common_phrases"] == ["alpha", "beta"]
        assert overridden == []


class TestApplyContactOverlayBoundary:
    def test_empty_overlay_returns_base_unchanged(self):
        base = {"tone": "neutral", "common_phrases": ["a"]}
        merged, overridden = apply_contact_overlay(base, None)
        assert merged == base
        assert overridden == []

        merged, overridden = apply_contact_overlay(base, {})
        assert merged == base
        assert overridden == []

    def test_empty_base_returns_overlay_verbatim(self):
        overlay = {"tone": "formal", "formality_level": 5}
        merged, overridden = apply_contact_overlay(None, overlay)
        assert merged == overlay
        # Every overlay key counts as overridden.
        assert set(overridden) == {"tone", "formality_level"}

        merged, overridden = apply_contact_overlay({}, overlay)
        assert merged == overlay
        assert set(overridden) == {"tone", "formality_level"}

    def test_unknown_fields_forward_compat(self):
        """Schema additions land without a parallel update here."""
        base = {"tone": "neutral"}
        overlay = {"future_field": "future_value"}
        merged, overridden = apply_contact_overlay(base, overlay)
        assert merged["future_field"] == "future_value"
        assert "future_field" in overridden


# ===========================================================================
# Unit tests — merge_overlays_for_recipients
# ===========================================================================

class TestMergeOverlaysSingle:
    def test_single_recipient_with_overlay(self):
        conn = _make_db()
        user_id = _seed_user(conn)
        acct_id = _seed_account(conn, user_id=user_id, hipaa=True)
        secrets = _FakeSecrets()
        rh = _seed_per_contact_overlay(
            conn,
            account_id=acct_id,
            recipient_address="boss@example.com",
            secrets=secrets,
            descriptor=_hipaa_descriptor(tone=OVERLAY_TONE),
        )
        merged, hashes = merge_overlays_for_recipients(
            conn, acct_id, ["boss@example.com"],
            secrets=secrets,
        )
        assert merged is not None
        assert merged["tone"] == OVERLAY_TONE
        assert hashes == [rh]

    def test_no_overlay_returns_none(self):
        conn = _make_db()
        user_id = _seed_user(conn)
        acct_id = _seed_account(conn, user_id=user_id, hipaa=True)
        secrets = _FakeSecrets()
        merged, hashes = merge_overlays_for_recipients(
            conn, acct_id, ["boss@example.com"],
            secrets=secrets,
        )
        assert merged is None
        assert hashes == []


class TestMergeOverlaysMulti:
    def test_multi_recipient_last_wins_on_scalar(self):
        conn = _make_db()
        user_id = _seed_user(conn)
        acct_id = _seed_account(conn, user_id=user_id, hipaa=True)
        secrets = _FakeSecrets()
        # Two recipients, two overlays. Second's tone wins.
        rh1 = _seed_per_contact_overlay(
            conn,
            account_id=acct_id,
            recipient_address="first@example.com",
            secrets=secrets,
            descriptor=_hipaa_descriptor(
                tone="casual",
                common_phrases=["first-phrase"],
            ),
        )
        rh2 = _seed_per_contact_overlay(
            conn,
            account_id=acct_id,
            recipient_address="second@example.com",
            secrets=secrets,
            descriptor=_hipaa_descriptor(
                tone="formal",
                common_phrases=["second-phrase"],
            ),
        )
        merged, hashes = merge_overlays_for_recipients(
            conn, acct_id,
            ["first@example.com", "second@example.com"],
            secrets=secrets,
        )
        assert merged is not None
        # Last recipient wins on scalar.
        assert merged["tone"] == "formal"
        # Lists are unioned across recipients.
        assert "first-phrase" in merged["common_phrases"]
        assert "second-phrase" in merged["common_phrases"]
        # Both hashes appear in the audit list.
        assert set(hashes) == {rh1, rh2}


class TestMergeOverlaysCache:
    def test_cache_memoises_lookup(self):
        conn = _make_db()
        user_id = _seed_user(conn)
        acct_id = _seed_account(conn, user_id=user_id, hipaa=True)
        secrets = _FakeSecrets()
        _seed_per_contact_overlay(
            conn,
            account_id=acct_id,
            recipient_address="boss@example.com",
            secrets=secrets,
            descriptor=_hipaa_descriptor(tone=OVERLAY_TONE),
        )
        cache: dict = {}
        merged1, hashes1 = merge_overlays_for_recipients(
            conn, acct_id, ["boss@example.com"],
            secrets=secrets, cache=cache,
        )
        assert merged1 is not None
        assert len(cache) == 1
        # Re-call with the same cache — should hit the cached entry
        # rather than re-hashing. Verify by deleting the underlying
        # row + re-calling: the cached entry still surfaces.
        conn.execute(
            "DELETE FROM per_contact_style_hipaa WHERE account_id = ?",
            (acct_id,),
        )
        conn.commit()
        merged2, hashes2 = merge_overlays_for_recipients(
            conn, acct_id, ["boss@example.com"],
            secrets=secrets, cache=cache,
        )
        # The cached overlay still applies.
        assert merged2 is not None
        assert merged2["tone"] == OVERLAY_TONE
        assert hashes2 == hashes1


class TestMergeOverlaysSafeFailure:
    def test_empty_recipient_list_returns_none(self):
        conn = _make_db()
        user_id = _seed_user(conn)
        acct_id = _seed_account(conn, user_id=user_id, hipaa=True)
        secrets = _FakeSecrets()
        merged, hashes = merge_overlays_for_recipients(
            conn, acct_id, [], secrets=secrets,
        )
        assert merged is None
        assert hashes == []

    def test_unparseable_recipient_skipped_silently(self):
        """Bad address shape doesn't raise — overlay just doesn't fire."""
        conn = _make_db()
        user_id = _seed_user(conn)
        acct_id = _seed_account(conn, user_id=user_id, hipaa=True)
        secrets = _FakeSecrets()
        # Mint the salt by seeding one real overlay first, so the
        # bad-address path doesn't hit "salt unavailable" by coincidence.
        _seed_per_contact_overlay(
            conn,
            account_id=acct_id,
            recipient_address="real@example.com",
            secrets=secrets,
            descriptor=_hipaa_descriptor(tone=OVERLAY_TONE),
        )
        merged, hashes = merge_overlays_for_recipients(
            conn, acct_id, ["not-a-valid-address"],
            secrets=secrets,
        )
        assert merged is None
        assert hashes == []


# ===========================================================================
# Smoke: W3's get_contact_style_overlay round-trips through our seed path
# ===========================================================================

class TestSeedPathRoundTrip:
    """Sanity check: the test fixture (set_per_contact_style_hipaa
    + hash_recipient_for_install) round-trips through W3's
    get_contact_style_overlay reader. If this test fails, every
    other test in this file is calibrated against the wrong storage
    shape."""

    def test_roundtrip(self):
        conn = _make_db()
        user_id = _seed_user(conn)
        acct_id = _seed_account(conn, user_id=user_id, hipaa=True)
        secrets = _FakeSecrets()
        _seed_per_contact_overlay(
            conn,
            account_id=acct_id,
            recipient_address="boss@example.com",
            secrets=secrets,
            descriptor=_hipaa_descriptor(
                tone=OVERLAY_TONE,
                common_phrases=[OVERLAY_PHRASE],
            ),
        )
        # Salt is stored under W3's canonical key.
        assert secrets.get(HIPAA_RECIPIENT_SALT_SECRET_KEY) is not None
        # Reader returns the descriptor we seeded.
        overlay = get_contact_style_overlay(
            conn, account_id=acct_id,
            recipient_address="boss@example.com",
            secrets=secrets,
        )
        assert overlay is not None
        assert overlay["tone"] == OVERLAY_TONE
        assert OVERLAY_PHRASE in overlay["common_phrases"]
