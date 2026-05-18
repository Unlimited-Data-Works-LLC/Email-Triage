"""Tests for punch list #162 — alias-aware writing-style learning.

When an operator has multiple addresses on the same account (primary +
aliases), the per-alias toggle on ``/profile/style-data`` partitions the
M-3 mine + draft-stitch paths by parsed ``From:`` address. The default
is OFF so existing single-descriptor behaviour is preserved.

Surfaces under test:

  * v23 migration is idempotent.
  * ``set_alias_mode_enabled_for_account`` / read helper round-trip.
  * From-header normalisation (display name, ``+suffix``, casing).
  * Partition logic in ``extract_style_profiles_per_alias`` — three
    sent messages from two distinct addresses produce two descriptor
    rows; unknown buckets surface in the unknown-counts return.
  * Prompt-stitch fallback chain: alias → primary → account-wide → none.
  * HIPAA gate: non-owner ticking the toggle on a HIPAA account is
    silently refused + audited; owner is allowed (§164.502(a)).
  * Dry-run preview returns the per-alias fragment; mine-now commits
    one row per bucket.
  * Privacy invariant pin — no operator identifiers in the new module
    surface.

Fixtures mirror tests/test_web/test_style_data_preview_and_mine.py so
the live provider + classifier paths are mocked via monkeypatch.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from email_triage.actions.style_profile import (
    StyleProfile,
    build_style_prompt_prefix,
    extract_style_profiles_per_alias,
    resolve_alias_profile,
)
from email_triage.engine.models import EmailMessage
from email_triage.web.db import (
    add_account_delegate,
    create_email_account,
    delete_account_style_per_alias,
    get_account_style_per_alias,
    is_alias_mode_enabled_for_account,
    list_account_style_per_alias,
    list_auth_events,
    normalise_from_address,
    set_account_hipaa,
    set_account_style_per_alias,
    set_alias_mode_enabled_for_account,
    set_style_knobs_hipaa_allow,
    set_style_profile,
    update_email_account_aliases,
)


# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------

def _make_acct(
    db, owner_id: int, name: str = "Acct",
    primary: str = "primary@example.com",
    aliases: list[dict] | None = None,
) -> int:
    """Create an account with a primary + optional aliases.

    Aliases are stored via ``update_email_account_aliases`` (JSON column).
    The primary is stored on ``config.account`` per the legacy resolver.
    """
    aid = create_email_account(
        db, owner_id, name, "imap",
        {"host": "mail.example.com", "account": primary},
    )
    if aliases:
        update_email_account_aliases(db, aid, aliases)
    return aid


def _sent_msg(
    *, mid: str, sender: str, body: str = "Thanks for the note. I'll look.",
) -> EmailMessage:
    """Build a synthetic sent-folder ``EmailMessage`` for the partition tests."""
    return EmailMessage(
        message_id=mid,
        provider="imap",
        sender=sender,
        recipients=["other@example.com"],
        subject=f"Re: {mid}",
        body_text=body,
        date=datetime(2026, 5, 1, tzinfo=timezone.utc),
        headers={"Message-ID": f"<{mid}@example.com>"},
    )


class _FixedClassifier:
    """Classifier whose ``.complete`` returns a fixed descriptor JSON."""

    model = "fake-alias-classifier-v1"

    async def complete(self, prompt: str) -> str:
        # Single canned descriptor; the bucket-distinguishing test
        # patches this to per-bucket sentinels.
        return (
            '{"greeting":"Hi","signoff":"Thanks,\\nOperator",'
            '"formality":3,"avg_sentence_length":10,'
            '"signature":"","phrases_used":[],'
            '"phrases_avoided":[],'
            '"persona_summary":"ALIAS_SENTINEL friendly."}'
        )


class _PerBucketClassifier:
    """Classifier that returns a different persona per call.

    Used so the partition test can verify each bucket's descriptor
    came from a distinct LLM call (and is keyed by the right address).
    """

    model = "fake-per-bucket-classifier-v1"

    def __init__(self) -> None:
        self._calls = 0

    async def complete(self, prompt: str) -> str:
        self._calls += 1
        return (
            '{"greeting":"Hi","signoff":"Thanks","formality":3,'
            '"avg_sentence_length":10,"signature":"",'
            '"phrases_used":[],"phrases_avoided":[],'
            f'"persona_summary":"BUCKET_PERSONA_{self._calls}"}}'
        )


class _StubProvider:
    """Provider whose Sent folder returns messages with controllable From: values.

    The ``alias_from_addresses`` ctor arg controls how the synthesised
    messages are signed; the partition tests use this to construct
    corpora with multiple From: addresses.
    """

    name = "imap"

    def __init__(
        self,
        *,
        sender_per_id: dict[str, str] | None = None,
    ) -> None:
        self._sender_per_id = sender_per_id or {
            "m1": "primary@example.com",
            "m2": "primary@example.com",
            "m3": "alias@example.com",
        }
        self.closed = False

    async def list_folders(self) -> list[str]:
        return ["INBOX", "Sent", "Drafts", "Trash"]

    async def search(
        self, query: str, limit: int = 50, *, filter=None,
    ) -> list[str]:
        return list(self._sender_per_id.keys())[:limit]

    async def fetch_message(self, mid: str, **_kw) -> EmailMessage:
        return _sent_msg(
            mid=mid, sender=self._sender_per_id.get(mid, "unknown@example.com"),
        )

    async def close(self) -> None:
        self.closed = True


@pytest.fixture
def patched_pipeline(monkeypatch):
    """Patch the provider + classifier builders used by the handlers."""
    state = {"provider": _StubProvider(), "classifier": _FixedClassifier}
    from email_triage.web.routers.ui import profile as profile_mod

    def _fake_create_provider(acct, secrets, **_kw):
        return state["provider"]

    def _fake_build_classifier(config):
        return state["classifier"]()

    monkeypatch.setattr(
        profile_mod, "_create_provider_from_account",
        _fake_create_provider,
    )
    monkeypatch.setattr(
        profile_mod, "_build_classifier_from_config",
        _fake_build_classifier,
    )
    yield state


# ---------------------------------------------------------------------------
# 1. v23 migration idempotency
# ---------------------------------------------------------------------------

class TestMigrationV23:
    def test_v23_migration_idempotent(self, db):
        # init_db already ran v23. Re-running run_migrations is a no-op
        # because the schema_migrations row is present; running the
        # body itself a second time must also succeed (the body uses
        # IF NOT EXISTS / PRAGMA-guards).
        from email_triage.web.migrations import _v23_add_account_style_per_alias

        # Run the body twice on the same connection; both calls must
        # complete cleanly.
        _v23_add_account_style_per_alias(db)
        _v23_add_account_style_per_alias(db)

        # Sanity: the table + column exist after the second run.
        cols = {row[1] for row in db.execute(
            "PRAGMA table_info(account_style_per_alias)"
        ).fetchall()}
        assert "from_address" in cols
        assert "descriptor_json" in cols
        ea_cols = {row[1] for row in db.execute(
            "PRAGMA table_info(email_accounts)"
        ).fetchall()}
        assert "style_alias_mode_enabled" in ea_cols


# ---------------------------------------------------------------------------
# 2. alias-mode toggle off keeps single-descriptor behaviour
# ---------------------------------------------------------------------------

class TestAliasModeOffSingleDescriptor:
    def test_alias_mode_off_keeps_single_descriptor(
        self, client, user_cookies, db, regular_user, patched_pipeline,
    ):
        """With alias-mode OFF (the default), mining writes one row to
        the settings-table descriptor and zero rows to the per-alias
        table — the pre-#162 shape."""
        a = _make_acct(db, regular_user["id"], "Personal")
        # Default is off.
        assert is_alias_mode_enabled_for_account(db, a) is False

        resp = client.post(
            f"/profile/style-data/mine-now?account_id={a}",
            cookies=user_cookies,
        )
        assert resp.status_code == 200

        # Per-alias table is empty.
        assert list_account_style_per_alias(db, a) == []
        # Account-wide settings row IS populated.
        from email_triage.web.db import get_style_profile
        stored = get_style_profile(db, a)
        assert stored is not None
        assert "ALIAS_SENTINEL" in (stored.get("persona_summary") or "")


# ---------------------------------------------------------------------------
# 3. alias-mode on partitions by From-address
# ---------------------------------------------------------------------------

class TestAliasModeOnPartition:
    @pytest.mark.asyncio
    async def test_alias_mode_on_partitions_by_from_address(self):
        """Three sent messages: two from primary, one from alias.
        Result: two descriptor rows (primary + alias)."""
        messages = [
            _sent_msg(mid="m1", sender="primary@example.com",
                      body="Body of message one."),
            _sent_msg(mid="m2", sender="primary@example.com",
                      body="Body of message two."),
            _sent_msg(mid="m3", sender="alias@example.com",
                      body="Body of message three."),
        ]
        classifier = _PerBucketClassifier()
        descriptors, unknown = await extract_style_profiles_per_alias(
            messages, classifier,
            known_addresses={"primary@example.com", "alias@example.com"},
        )
        # Two distinct From-addresses, two descriptor rows.
        assert set(descriptors.keys()) == {
            "primary@example.com", "alias@example.com",
        }
        # Sample counts reflect the partition (2 vs 1).
        assert descriptors["primary@example.com"].sample_count == 2
        assert descriptors["alias@example.com"].sample_count == 1
        # Both From-values were known; no unknown bucket reported.
        assert unknown == []


# ---------------------------------------------------------------------------
# 4. From-header normalisation
# ---------------------------------------------------------------------------

class TestFromNormalisation:
    def test_from_address_normalisation_display_name(self):
        assert normalise_from_address(
            '"Display Name" <CL@WORK.TLD>',
        ) == "cl@work.tld"

    def test_from_address_normalisation_plus_suffix(self):
        assert normalise_from_address(
            "alice+work@example.com",
        ) == "alice@example.com"

    def test_from_address_normalisation_angle_brackets(self):
        assert normalise_from_address("<sam@example.com>") == "sam@example.com"

    def test_from_address_normalisation_case_insensitive(self):
        assert normalise_from_address("SAM@Example.Com") == "sam@example.com"

    def test_from_address_normalisation_empty(self):
        assert normalise_from_address("") == ""
        assert normalise_from_address(None) == ""

    def test_from_address_normalisation_combined(self):
        assert normalise_from_address(
            '"Display" <Sam+work@Example.Tld>',
        ) == "sam@example.tld"


# ---------------------------------------------------------------------------
# 5. Unknown From-address surfaces in unknown-counts
# ---------------------------------------------------------------------------

class TestUnknownFromAddress:
    @pytest.mark.asyncio
    async def test_unknown_from_address_falls_into_no_bucket(self):
        """A From-address not in known_addresses still gets distilled
        but is reported in unknown_counts so the UI can prompt the
        operator to add it."""
        messages = [
            _sent_msg(mid="m1", sender="primary@example.com",
                      body="Body of message one."),
            _sent_msg(mid="m2", sender="surprise@example.com",
                      body="Body of message two."),
            _sent_msg(mid="m3", sender="surprise@example.com",
                      body="Body of message three."),
        ]
        descriptors, unknown = await extract_style_profiles_per_alias(
            messages, _PerBucketClassifier(),
            known_addresses={"primary@example.com"},
        )
        # Both buckets get descriptor rows; the unknown one too.
        assert "primary@example.com" in descriptors
        assert "surprise@example.com" in descriptors
        # The unknown report shows the unknown address with its count.
        assert unknown == [("surprise@example.com", 2)]


# ---------------------------------------------------------------------------
# 6. Prompt-stitch fallback chain
# ---------------------------------------------------------------------------

class TestPromptStitchFallback:
    def test_prompt_stitch_picks_alias_descriptor(self):
        alias_descs = {
            "primary@example.com": StyleProfile(
                persona_summary="PRIMARY voice", sample_count=5,
            ),
            "alias@example.com": StyleProfile(
                persona_summary="ALIAS voice", sample_count=3,
            ),
        }
        # Specific alias match wins.
        chosen = resolve_alias_profile(
            from_address="alias@example.com",
            alias_profiles=alias_descs,
            primary_address="primary@example.com",
            account_profile=StyleProfile(persona_summary="ACCOUNTWIDE voice"),
        )
        assert chosen.persona_summary == "ALIAS voice"

    def test_prompt_stitch_falls_back_to_primary(self):
        alias_descs = {
            "primary@example.com": StyleProfile(
                persona_summary="PRIMARY voice", sample_count=5,
            ),
        }
        # From-address absent from the per-alias dict → primary fallback.
        chosen = resolve_alias_profile(
            from_address="ghost@example.com",
            alias_profiles=alias_descs,
            primary_address="primary@example.com",
            account_profile=StyleProfile(persona_summary="ACCOUNTWIDE voice"),
        )
        assert chosen.persona_summary == "PRIMARY voice"

    def test_prompt_stitch_falls_back_to_account_wide(self):
        # Empty per-alias dict → account-wide.
        chosen = resolve_alias_profile(
            from_address="anyone@example.com",
            alias_profiles={},
            primary_address="primary@example.com",
            account_profile=StyleProfile(persona_summary="ACCOUNTWIDE voice"),
        )
        assert chosen.persona_summary == "ACCOUNTWIDE voice"

    def test_prompt_stitch_no_descriptor_returns_none(self):
        # Nothing at any layer → None (no prefix at all).
        assert resolve_alias_profile(
            from_address="anyone@example.com",
            alias_profiles=None,
            primary_address="primary@example.com",
            account_profile=None,
        ) is None

    def test_prompt_stitch_renders_alias_block_in_prefix(self):
        """Smoke test that the resolver's output flows through
        build_style_prompt_prefix into a non-empty block."""
        prof = StyleProfile(
            persona_summary="resolved-alias-voice",
            sample_count=4,
        )
        prefix = build_style_prompt_prefix(
            None,  # no M-1+M-2 knobs
            prof,
            hipaa=False,
            master_enabled=True,
            account_enabled=True,
        )
        assert "resolved-alias-voice" in prefix


# ---------------------------------------------------------------------------
# 7. HIPAA gate — non-owner ticking refused + audited
# ---------------------------------------------------------------------------

class TestHipaaGate:
    def test_hipaa_account_alias_mode_blocked_for_non_owner(
        self, client, db, admin_user, regular_user, admin_cookies,
    ):
        """Non-owner (delegate) ticking the toggle on a HIPAA-flagged
        account belonging to a different user must be refused + write
        a hipaa_access_events row. The audit row is also written so
        an operator review can see the refused attempt.

        Setup: admin is added as a DELEGATE on regular_user's account
        so they have access via _resolve_managed_accounts. Admin is
        not the owner so the HIPAA gate fires (no style_knobs opt-in
        in place)."""
        a = _make_acct(db, regular_user["id"], "MedAcct")
        set_account_hipaa(db, a, True, actor_id=regular_user["id"])
        # Make admin a delegate so they can resolve the account.
        add_account_delegate(db, a, admin_user["id"], regular_user["id"])
        # NO style_knobs_hipaa_allow opt-in.
        resp = client.post(
            f"/profile/style-data/toggle-alias-mode?account_id={a}",
            data={"alias_mode_submitted": "1",
                  "style_alias_mode_enabled": "1"},
            cookies=admin_cookies,
        )
        # Soft refusal — redirect back without flipping the flag.
        # TestClient follows redirects by default, so the visible
        # status is the redirect target (200 = /profile/style-data).
        assert resp.status_code in (200, 303, 302)
        # Toggle state unchanged.
        assert is_alias_mode_enabled_for_account(db, a) is False
        # Audit row written with failure outcome.
        rows = list_auth_events(
            db, event_type="style_data_toggle_alias_mode", limit=10,
        )
        # At least one failure row exists.
        assert any(r["outcome"] == "failure" for r in rows)

    def test_hipaa_account_owner_alias_mode_allowed(
        self, client, db, regular_user, user_cookies,
    ):
        """Owner ticking the toggle on their OWN HIPAA-flagged account
        is allowed under §164.502(a) — once they've also ticked the
        per-account style-knobs opt-in (operator-self-disclosure)."""
        a = _make_acct(db, regular_user["id"], "MedAcct")
        set_account_hipaa(db, a, True, actor_id=regular_user["id"])
        set_style_knobs_hipaa_allow(db, a, enabled=True)
        resp = client.post(
            f"/profile/style-data/toggle-alias-mode?account_id={a}",
            data={"alias_mode_submitted": "1",
                  "style_alias_mode_enabled": "1"},
            cookies=user_cookies,
        )
        assert resp.status_code in (200, 303, 302)
        assert is_alias_mode_enabled_for_account(db, a) is True


# ---------------------------------------------------------------------------
# 8. Dry-run preview per alias
# ---------------------------------------------------------------------------

class TestDryRunPreviewPerAlias:
    def test_dry_run_preview_per_alias(
        self, client, user_cookies, db, regular_user, patched_pipeline,
    ):
        """With alias-mode on, a POST to /preview?alias_from_address=X
        runs the partition but writes nothing to the per-alias table.
        Result fragment contains the per-alias section header."""
        a = _make_acct(
            db, regular_user["id"], "MultiAccount",
            primary="primary@example.com",
            aliases=[{"address": "alias@example.com", "label": "work"}],
        )
        set_alias_mode_enabled_for_account(db, a, enabled=True)

        # Stub provider returns 2 from primary + 1 from alias.
        patched_pipeline["provider"] = _StubProvider(
            sender_per_id={
                "m1": "primary@example.com",
                "m2": "primary@example.com",
                "m3": "alias@example.com",
            },
        )
        resp = client.post(
            f"/profile/style-data/preview?account_id={a}",
            cookies=user_cookies,
        )
        assert resp.status_code == 200
        # Per-alias fragment header.
        assert "per-alias writing-style summaries" in resp.text.lower()
        # No writes performed.
        assert list_account_style_per_alias(db, a) == []

    def test_mine_now_per_alias_persists_rows(
        self, client, user_cookies, db, regular_user, patched_pipeline,
    ):
        """Mine-now with alias-mode on writes one row per bucket."""
        a = _make_acct(
            db, regular_user["id"], "MultiAccount",
            primary="primary@example.com",
            aliases=[{"address": "alias@example.com", "label": "work"}],
        )
        set_alias_mode_enabled_for_account(db, a, enabled=True)

        patched_pipeline["provider"] = _StubProvider(
            sender_per_id={
                "m1": "primary@example.com",
                "m2": "primary@example.com",
                "m3": "alias@example.com",
            },
        )
        # Use a per-bucket classifier so each row has a distinguishable persona.
        patched_pipeline["classifier"] = _PerBucketClassifier
        resp = client.post(
            f"/profile/style-data/mine-now?account_id={a}",
            cookies=user_cookies,
        )
        assert resp.status_code == 200
        rows = list_account_style_per_alias(db, a)
        addrs = {r["from_address"] for r in rows}
        assert addrs == {"primary@example.com", "alias@example.com"}

    def test_mine_now_scoped_to_single_alias_writes_only_that_row(
        self, client, user_cookies, db, regular_user, patched_pipeline,
    ):
        """Picker-scoped mine writes the matching bucket only."""
        a = _make_acct(
            db, regular_user["id"], "MultiAccount",
            primary="primary@example.com",
            aliases=[{"address": "alias@example.com", "label": "work"}],
        )
        set_alias_mode_enabled_for_account(db, a, enabled=True)
        patched_pipeline["provider"] = _StubProvider(
            sender_per_id={
                "m1": "primary@example.com",
                "m2": "alias@example.com",
            },
        )
        resp = client.post(
            f"/profile/style-data/mine-now?account_id={a}"
            f"&alias_from_address=alias@example.com",
            cookies=user_cookies,
        )
        assert resp.status_code == 200
        rows = list_account_style_per_alias(db, a)
        addrs = {r["from_address"] for r in rows}
        # Only the requested bucket got persisted.
        assert addrs == {"alias@example.com"}


# ---------------------------------------------------------------------------
# 9. DB helpers round-trip
# ---------------------------------------------------------------------------

class TestDbHelpersRoundtrip:
    def test_set_get_account_style_per_alias(self, db, regular_user):
        a = _make_acct(db, regular_user["id"])
        set_account_style_per_alias(
            db, a, "Sam+work@Example.TLD",
            {"persona_summary": "voice", "sample_count": 7},
        )
        # Lookup normalises the address — case + suffix don't matter.
        out = get_account_style_per_alias(db, a, "sam@example.tld")
        assert out is not None
        assert out.get("persona_summary") == "voice"
        # Listing returns the normalised key.
        rows = list_account_style_per_alias(db, a)
        assert len(rows) == 1
        assert rows[0]["from_address"] == "sam@example.tld"
        assert rows[0]["sample_count"] == 7

    def test_set_account_style_per_alias_upsert(self, db, regular_user):
        a = _make_acct(db, regular_user["id"])
        set_account_style_per_alias(
            db, a, "x@example.com", {"persona_summary": "v1"},
            sample_count=2,
        )
        set_account_style_per_alias(
            db, a, "x@example.com", {"persona_summary": "v2"},
            sample_count=5,
        )
        rows = list_account_style_per_alias(db, a)
        assert len(rows) == 1
        assert rows[0]["descriptor"]["persona_summary"] == "v2"
        assert rows[0]["sample_count"] == 5

    def test_delete_account_style_per_alias_single(self, db, regular_user):
        a = _make_acct(db, regular_user["id"])
        set_account_style_per_alias(
            db, a, "x@example.com", {"persona_summary": "v"},
        )
        set_account_style_per_alias(
            db, a, "y@example.com", {"persona_summary": "v"},
        )
        n = delete_account_style_per_alias(db, a, "x@example.com")
        assert n == 1
        remaining = {r["from_address"] for r in list_account_style_per_alias(db, a)}
        assert remaining == {"y@example.com"}

    def test_delete_account_style_per_alias_all(self, db, regular_user):
        a = _make_acct(db, regular_user["id"])
        set_account_style_per_alias(
            db, a, "x@example.com", {"persona_summary": "v"},
        )
        set_account_style_per_alias(
            db, a, "y@example.com", {"persona_summary": "v"},
        )
        n = delete_account_style_per_alias(db, a)
        assert n == 2
        assert list_account_style_per_alias(db, a) == []


# ---------------------------------------------------------------------------
# 10. Privacy invariant pin
# ---------------------------------------------------------------------------

class TestPrivacyInvariantPin:
    def test_privacy_invariant_no_operator_identifiers_in_alias_module(self):
        """The new alias-aware code paths (and the migration body)
        must not embed any operator identifier — only generic
        placeholders (example.com / your-domain.example / etc.).
        Mirrors the install-wide privacy invariant test."""
        import inspect

        from email_triage.web.db import (
            normalise_from_address as _norm,
            is_alias_mode_enabled_for_account as _check,
            list_account_style_per_alias as _list,
            set_account_style_per_alias as _set,
        )
        from email_triage.actions.style_profile import (
            extract_style_profiles_per_alias as _epa,
            resolve_alias_profile as _rap,
        )

        forbidden = (
            "Alex", "Maintainer", "friend", "family-member",
            "therealms", "agents-host", "deploy-host", "redis-host",
        )
        sources = [
            inspect.getsource(fn)
            for fn in (_norm, _check, _list, _set, _epa, _rap)
        ]
        text = "\n".join(sources).lower()
        for needle in forbidden:
            assert needle not in text, (
                f"Operator identifier {needle!r} leaked into alias-aware "
                "code path; replace with a generic placeholder."
            )


# ---------------------------------------------------------------------------
# 11. Toggle helper round-trip
# ---------------------------------------------------------------------------

class TestToggleHelperRoundtrip:
    def test_toggle_helper_roundtrip(self, db, regular_user):
        a = _make_acct(db, regular_user["id"])
        assert is_alias_mode_enabled_for_account(db, a) is False
        set_alias_mode_enabled_for_account(db, a, enabled=True)
        assert is_alias_mode_enabled_for_account(db, a) is True
        set_alias_mode_enabled_for_account(db, a, enabled=False)
        assert is_alias_mode_enabled_for_account(db, a) is False
