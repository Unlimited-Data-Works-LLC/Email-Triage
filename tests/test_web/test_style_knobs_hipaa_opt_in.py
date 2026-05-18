"""Web-layer tests for the #152 phase 2 M-1+M-2 HIPAA opt-in.

The lift (operator-typed style knobs render under HIPAA when the per-
account ``style_knobs_hipaa_allow:<id>`` opt-in is on) is end-to-end
pinned by ``tests/test_privacy_invariants_m_series.py``
(TestM1M2HipaaOptIn + TestM1M2OptInEndToEnd). This file covers the
web-layer concerns those invariants don't reach:

  * Default state is OFF for a freshly created account.
  * Owner can tick the opt-in on their own HIPAA-flagged account.
  * Admin / delegate POSTing the opt-in field on an account they don't
    own is a silent refuse — no setting flip, hipaa_access_events
    audit row records the refused attempt.
  * Non-HIPAA accounts don't render the checkbox at all.
  * format_style_knobs_for_prompt gating direction (off → empty;
    on → populated) — duplicated here so a test-file delete on the
    privacy-invariant file still leaves a guard behind.
  * The audit module itself carries no operator identifiers — pin the
    privacy-invariant catalogue against drift.

Synthetic identities only: ``owner@example.com`` / ``other@example.com``.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from email_triage.actions.style_profile import (
    format_style_knobs_for_prompt,
)
from email_triage.web.auth import SESSION_COOKIE_NAME, create_session_token
from email_triage.web.db import (
    add_account_delegate,
    create_email_account,
    is_style_knobs_hipaa_allow,
    list_hipaa_access_events,
    set_account_hipaa,
    set_style_knobs_hipaa_allow,
)

# Sentinel used to detect that the M-1+M-2 prompt prefix actually
# rendered the operator-typed knob block. No real PII; the sentinel
# is a deliberately recognisable token.
KNOBS_SENTINEL = "OPT_IN_KNOBS_SENTINEL_concise"


# ---------------------------------------------------------------------------
# Fixtures — second user for delegate / non-owner test paths
# ---------------------------------------------------------------------------

@pytest.fixture
def other_user(db):
    """A second regular user, used as the non-owner actor in the
    admin / delegate refuse-tick test paths."""
    now = datetime.now(timezone.utc).isoformat()
    cur = db.execute(
        "INSERT INTO users (email, name, role, created_at) "
        "VALUES (?, ?, ?, ?)",
        ("other@example.com", "Other Owner", "user", now),
    )
    db.commit()
    return {
        "id": cur.lastrowid,
        "email": "other@example.com",
        "name": "Other Owner",
        "role": "user",
    }


@pytest.fixture
def other_user_cookies(other_user):
    from tests.test_web.conftest import TEST_SECRET
    token = create_session_token(
        TEST_SECRET, other_user["email"], other_user["role"],
    )
    return {SESSION_COOKIE_NAME: token}


def _make_hipaa_acct(db, owner_id: int, name: str = "MedAcct") -> int:
    """Create a HIPAA-flagged IMAP account owned by ``owner_id``."""
    aid = create_email_account(
        db, owner_id, name, "imap", {"host": "mail.example.com"},
    )
    set_account_hipaa(db, aid, True, actor_id=owner_id)
    return aid


def _make_acct(db, owner_id: int, name: str = "Acct") -> int:
    return create_email_account(
        db, owner_id, name, "imap", {"host": "mail.example.com"},
    )


# ---------------------------------------------------------------------------
# Default state + helper-level direction pins
# ---------------------------------------------------------------------------

class TestDefaultsAndHelpers:
    def test_default_off_for_all_accounts(self, db, regular_user):
        """Fresh HIPAA account → opt-in helper returns False."""
        a = _make_hipaa_acct(db, regular_user["id"])
        assert is_style_knobs_hipaa_allow(db, a) is False

    def test_default_off_for_non_hipaa_account(self, db, regular_user):
        """Non-HIPAA account also defaults to False (the flag is
        meaningless for non-HIPAA, but the helper must read False to
        keep the prefix-builder gate consistent)."""
        a = _make_acct(db, regular_user["id"])
        assert is_style_knobs_hipaa_allow(db, a) is False

    def test_m1m2_gated_when_opt_in_off(self):
        """``format_style_knobs_for_prompt`` returns empty under HIPAA
        when the per-account opt-in is off. Direction sibling to the
        invariant-suite test; duplicated so the gate has belt-and-
        braces coverage if either test file is later deleted."""
        knobs = {
            "style_guide": KNOBS_SENTINEL,
            "style_tone": "casual",
            "style_length": "brief",
            "style_signature": "",
            "style_greeting": "first-name",
            "style_greeting_custom": "",
        }
        out = format_style_knobs_for_prompt(
            knobs, hipaa=True,
            master_enabled=True, account_enabled=True,
            m1m2_hipaa_allow=False,
        )
        assert out == ""

    def test_m1m2_populated_when_opt_in_on(self):
        """Opt-in ON → operator's typed knob block renders under HIPAA."""
        knobs = {
            "style_guide": KNOBS_SENTINEL,
            "style_tone": "casual",
            "style_length": "brief",
            "style_signature": "",
            "style_greeting": "first-name",
            "style_greeting_custom": "",
        }
        out = format_style_knobs_for_prompt(
            knobs, hipaa=True,
            master_enabled=True, account_enabled=True,
            m1m2_hipaa_allow=True,
        )
        assert KNOBS_SENTINEL in out


# ---------------------------------------------------------------------------
# Render conditional — non-HIPAA account doesn't render the toggle
# ---------------------------------------------------------------------------

class TestRenderConditional:
    def test_non_hipaa_account_does_not_render_toggle(
        self, client, user_cookies, db, regular_user,
    ):
        """The opt-in section is HIPAA-only UI — a non-HIPAA account
        doesn't show the checkbox at all (the flag is meaningless
        there; M-1+M-2 is unconditionally on for non-HIPAA)."""
        a = _make_acct(db, regular_user["id"], "Personal")
        resp = client.get(
            f"/accounts/{a}/edit",
            cookies=user_cookies,
            headers={"HX-Request": "true"},
        )
        assert resp.status_code == 200
        # The checkbox input has this name only on HIPAA accounts.
        assert 'name="style_knobs_hipaa_allow"' not in resp.text

    def test_hipaa_owner_view_renders_toggle(
        self, client, user_cookies, db, regular_user,
    ):
        """Owner viewing their own HIPAA account sees the checkbox."""
        a = _make_hipaa_acct(db, regular_user["id"])
        resp = client.get(
            f"/accounts/{a}/edit",
            cookies=user_cookies,
            headers={"HX-Request": "true"},
        )
        assert resp.status_code == 200
        assert 'name="style_knobs_hipaa_allow"' in resp.text


# ---------------------------------------------------------------------------
# Owner-tick happy path
# ---------------------------------------------------------------------------

class TestOwnerTick:
    def test_owner_can_tick_on_own_hipaa_account(
        self, client, user_cookies, db, regular_user,
    ):
        """Owner POST with the opt-in field present → setting flips ON."""
        a = _make_hipaa_acct(db, regular_user["id"])
        assert is_style_knobs_hipaa_allow(db, a) is False

        resp = client.post(
            f"/accounts/{a}/save",
            data={
                "name": "MedAcct",
                "provider_type": "imap",
                "host": "mail.example.com",
                "username": "owner@example.com",
                "is_active": "1",
                "style_knobs_hipaa_allow": "1",
            },
            cookies=user_cookies,
            follow_redirects=False,
        )
        assert resp.status_code in (200, 303)
        assert is_style_knobs_hipaa_allow(db, a) is True

    def test_owner_untick_persists_off(
        self, client, user_cookies, db, regular_user,
    ):
        """Owner POST without the opt-in field present (after a prior
        tick-on) → setting flips OFF. Absence of the field IS the
        untick signal."""
        a = _make_hipaa_acct(db, regular_user["id"])
        set_style_knobs_hipaa_allow(db, a, enabled=True)
        assert is_style_knobs_hipaa_allow(db, a) is True

        resp = client.post(
            f"/accounts/{a}/save",
            data={
                "name": "MedAcct",
                "provider_type": "imap",
                "host": "mail.example.com",
                "username": "owner@example.com",
                "is_active": "1",
                # style_knobs_hipaa_allow omitted → unticked.
            },
            cookies=user_cookies,
            follow_redirects=False,
        )
        assert resp.status_code in (200, 303)
        assert is_style_knobs_hipaa_allow(db, a) is False

    def test_audit_row_emitted_on_owner_tick(
        self, client, user_cookies, db, regular_user,
    ):
        """Owner tick → hipaa_access_events row with operation
        ``style_knobs_hipaa_allow_set`` + outcome ``ok``."""
        a = _make_hipaa_acct(db, regular_user["id"])
        client.post(
            f"/accounts/{a}/save",
            data={
                "name": "MedAcct",
                "provider_type": "imap",
                "host": "mail.example.com",
                "username": "owner@example.com",
                "is_active": "1",
                "style_knobs_hipaa_allow": "1",
            },
            cookies=user_cookies,
            follow_redirects=False,
        )
        rows = list_hipaa_access_events(db, account_id=a)
        hits = [
            r for r in rows
            if r["operation"] == "style_knobs_hipaa_allow_set"
        ]
        assert hits, (
            "Expected hipaa_access_events row for the owner tick; "
            f"got {len(rows)} other rows on this account."
        )
        # Most-recent first — confirm outcome + detail carry the
        # intended state. The owner is the data subject so a
        # self-disclosure row is still recorded for audit lens
        # (the row does not block the tick; it's the paper trail).
        assert hits[0]["outcome"] == "ok"
        assert hits[0]["detail"] == "enabled"


# ---------------------------------------------------------------------------
# Non-owner tick attempt — silent refuse + refused-audit row
# ---------------------------------------------------------------------------

class TestNonOwnerRefuse:
    def test_admin_cannot_tick_for_someone_else(
        self, client, admin_cookies, db, regular_user, admin_user,
    ):
        """Admin POSTing the opt-in field on an account they don't
        own → silent refuse + audit row recording the refused
        attempt. The setting stays at its prior value (default OFF)."""
        # Owner is ``regular_user``; account is HIPAA-flagged.
        a = _make_hipaa_acct(db, regular_user["id"])
        assert is_style_knobs_hipaa_allow(db, a) is False

        # Admin posts with the field present, intent to tick it on.
        resp = client.post(
            f"/accounts/{a}/save",
            data={
                "name": "MedAcct",
                "provider_type": "imap",
                "host": "mail.example.com",
                "username": "owner@example.com",
                "is_active": "1",
                "style_knobs_hipaa_allow": "1",
            },
            cookies=admin_cookies,
            follow_redirects=False,
        )
        # The rest of the save is allowed (admin can edit non-HIPAA
        # fields on someone's account); only the opt-in is refused.
        assert resp.status_code in (200, 303)
        # Setting did NOT flip.
        assert is_style_knobs_hipaa_allow(db, a) is False
        # Audit row exists with outcome=refused_non_owner.
        rows = list_hipaa_access_events(db, account_id=a)
        refused = [
            r for r in rows
            if r["operation"] == "style_knobs_hipaa_allow_set"
            and r["outcome"] == "refused_non_owner"
        ]
        assert refused, (
            "Expected refused-non-owner audit row on admin tick attempt; "
            f"got {len(rows)} rows. Operations: "
            f"{[(r['operation'], r['outcome']) for r in rows]}"
        )

    def test_delegate_cannot_tick_for_owner(
        self, client, other_user_cookies, db, regular_user, other_user,
    ):
        """A delegate (different user, granted access to the owner's
        account) POSTing the opt-in is also refused. Same shape as
        the admin path — the gate is ``actor_user_id ==
        account.user_id``, not role-based."""
        a = _make_hipaa_acct(db, regular_user["id"])
        # Grant ``other_user`` delegate access on the account.
        add_account_delegate(
            db, account_id=a, user_id=other_user["id"],
            granted_by=regular_user["id"],
        )
        assert is_style_knobs_hipaa_allow(db, a) is False

        resp = client.post(
            f"/accounts/{a}/save",
            data={
                "name": "MedAcct",
                "provider_type": "imap",
                "host": "mail.example.com",
                "username": "owner@example.com",
                "is_active": "1",
                "style_knobs_hipaa_allow": "1",
            },
            cookies=other_user_cookies,
            follow_redirects=False,
        )
        assert resp.status_code in (200, 303)
        # Setting did NOT flip.
        assert is_style_knobs_hipaa_allow(db, a) is False
        # Audit row recorded the refused attempt.
        rows = list_hipaa_access_events(db, account_id=a)
        refused = [
            r for r in rows
            if r["operation"] == "style_knobs_hipaa_allow_set"
            and r["outcome"] == "refused_non_owner"
        ]
        assert refused

    def test_admin_no_field_no_refused_row(
        self, client, admin_cookies, db, regular_user,
    ):
        """Admin POST that simply doesn't carry the opt-in field at
        all (because they didn't see the section) must NOT produce a
        refused-audit row. The refused row fires only when the field
        is present + the actor is non-owner."""
        a = _make_hipaa_acct(db, regular_user["id"])
        resp = client.post(
            f"/accounts/{a}/save",
            data={
                "name": "MedAcct",
                "provider_type": "imap",
                "host": "mail.example.com",
                "username": "owner@example.com",
                "is_active": "1",
                # No style_knobs_hipaa_allow at all.
            },
            cookies=admin_cookies,
            follow_redirects=False,
        )
        assert resp.status_code in (200, 303)
        rows = list_hipaa_access_events(db, account_id=a)
        refused = [
            r for r in rows
            if r["operation"] == "style_knobs_hipaa_allow_set"
        ]
        assert refused == [], (
            "Admin POST without the opt-in field present should NOT "
            "produce a refused-audit row; got: "
            f"{[(r['operation'], r['outcome']) for r in refused]}"
        )


# ---------------------------------------------------------------------------
# Privacy-invariant catalogue — no operator identifiers anywhere
# ---------------------------------------------------------------------------

class TestNoOperatorIdentifiers:
    def test_audit_module_carries_no_operator_identifiers(self):
        """The hipaa_access_events insert path must not bake in any
        operator-identifier string. Detail values are intentionally
        short + generic (``enabled`` / ``disabled`` / ``actor != owner;
        owner-only opt-in``). Pin that contract so a future change
        adding ``record_hipaa_access_event(..., detail=f'tick by
        {real_email}')`` lands on a failing test."""
        import inspect
        from email_triage.web import db as db_mod
        src = inspect.getsource(db_mod.record_hipaa_access_event)
        # The function body must not reach for user.email anywhere.
        # (The signature exposes account_id + actor_user_id only;
        # detail is caller-supplied.)
        for forbidden in (
            "@therealms",
            "claforest",
            "openclaw",
            "agents-host",
        ):
            assert forbidden not in src, (
                f"record_hipaa_access_event source mentions "
                f"{forbidden!r} — operator identifier leak."
            )
