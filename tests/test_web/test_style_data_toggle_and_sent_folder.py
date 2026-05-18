"""Tests for the 2026-05-11 AI-learns toggle relocation +
sent-folder override.

Covers:

  * GET /profile/style-data — checkbox state reflects the resolved
    default (#157 HIPAA-aware: non-HIPAA → checked, HIPAA without
    opt-in → disabled with reason chip).
  * POST /profile/style-data/toggle-rag — non-HIPAA save persists;
    HIPAA-without-opt-in save refused silently (no state change).
  * /accounts/<id>/save auto-off behaviour: flipping HIPAA 0→1 forces
    the AI-learns toggle off.
  * POST /profile/style-data/sent-folder-override — empty / non-empty
    values round-trip through account config_json.
  * SentMailIndex.index_recent uses the override via a MailFilter
    when set.
  * Render placeholder shows the auto-discovered folder when no
    override is set.

The toggle was relocated off ``accounts/_edit.html`` (where it had
no save handler — dead UI) onto the per-account row on
``/profile/style-data`` where the helper-backed live setting lives.
"""

from __future__ import annotations

import pytest

from email_triage.web.db import (
    create_email_account,
    is_rag_sent_index_enabled,
    set_account_hipaa,
    set_rag_sent_index_enabled,
    set_style_knobs_hipaa_allow,
)


def _make_acct(db, owner_id: int, name: str = "Acct") -> int:
    return create_email_account(
        db, owner_id, name, "imap", {"host": "mail.example.com"},
    )


# ---------------------------------------------------------------------------
# GET /profile/style-data — toggle render
# ---------------------------------------------------------------------------

class TestToggleRender:
    def test_non_hipaa_account_checkbox_checked_by_default(
        self, client, user_cookies, db, regular_user,
    ):
        """Per #157 — non-HIPAA accounts default ON. The relocated
        checkbox renders with the ``checked`` attribute even when no
        explicit setting row exists."""
        _make_acct(db, regular_user["id"], "Personal")
        resp = client.get(
            "/profile/style-data", cookies=user_cookies,
        )
        assert resp.status_code == 200
        # Checkbox name present and checked attribute on its line.
        assert 'name="rag_sent_index_enabled"' in resp.text
        # Anchor on the checked attribute appearing alongside the
        # input — Jinja renders it inline.
        assert "checked" in resp.text
        # The new helper text + tooltip phrase is the inline label.
        assert "AI learns from your past replies" in resp.text

    def test_hipaa_without_optin_checkbox_disabled(
        self, client, user_cookies, db, regular_user,
    ):
        """HIPAA-flagged + no M-1+M-2 opt-in → checkbox renders with
        the disabled attribute and a HIPAA-opt-in-first reason chip."""
        a = _make_acct(db, regular_user["id"], "MedAcct")
        set_account_hipaa(db, a, True, actor_id=regular_user["id"])
        resp = client.get(
            "/profile/style-data", cookies=user_cookies,
        )
        assert resp.status_code == 200
        # Reason chip surfaces the opt-in-first copy.
        assert "HIPAA" in resp.text
        # The checkbox carries the disabled attribute.
        assert "disabled" in resp.text


# ---------------------------------------------------------------------------
# POST /profile/style-data/toggle-rag
# ---------------------------------------------------------------------------

class TestToggleSave:
    def test_non_hipaa_save_persists(
        self, client, user_cookies, db, regular_user,
    ):
        a = _make_acct(db, regular_user["id"], "Personal")
        # Start: no explicit row → non-HIPAA default is True.
        resp = client.post(
            f"/profile/style-data/toggle-rag?account_id={a}",
            data={
                "rag_submitted": "1",
                # rag_sent_index_enabled omitted → operator unchecked.
            },
            cookies=user_cookies,
        )
        # Handler redirects back to /profile/style-data.
        assert resp.status_code in (200, 303)
        # Now explicitly OFF.
        acct = {"hipaa": 0}  # non-HIPAA shape for the helper's account kwarg.
        assert is_rag_sent_index_enabled(db, a, account=acct) is False

        # Flip back ON.
        resp2 = client.post(
            f"/profile/style-data/toggle-rag?account_id={a}",
            data={
                "rag_submitted": "1",
                "rag_sent_index_enabled": "1",
            },
            cookies=user_cookies,
        )
        assert resp2.status_code in (200, 303)
        assert is_rag_sent_index_enabled(db, a, account=acct) is True

    def test_hipaa_without_optin_refused(
        self, client, user_cookies, db, regular_user,
    ):
        a = _make_acct(db, regular_user["id"], "MedAcct")
        set_account_hipaa(db, a, True, actor_id=regular_user["id"])
        # NO style_knobs_hipaa_allow opt-in.

        # Try to turn it ON.
        resp = client.post(
            f"/profile/style-data/toggle-rag?account_id={a}",
            data={
                "rag_submitted": "1",
                "rag_sent_index_enabled": "1",
            },
            cookies=user_cookies,
        )
        assert resp.status_code in (200, 303)
        # Setting did NOT flip on — helper still returns False for
        # HIPAA accounts without an explicit row (default OFF) AND no
        # explicit row was written.
        acct = {"hipaa": 1}
        assert is_rag_sent_index_enabled(db, a, account=acct) is False

    def test_hipaa_with_optin_can_save(
        self, client, user_cookies, db, regular_user,
    ):
        a = _make_acct(db, regular_user["id"], "MedAcct")
        set_account_hipaa(db, a, True, actor_id=regular_user["id"])
        set_style_knobs_hipaa_allow(db, a, enabled=True)

        resp = client.post(
            f"/profile/style-data/toggle-rag?account_id={a}",
            data={
                "rag_submitted": "1",
                "rag_sent_index_enabled": "1",
            },
            cookies=user_cookies,
        )
        assert resp.status_code in (200, 303)
        acct = {"hipaa": 1}
        assert is_rag_sent_index_enabled(db, a, account=acct) is True


# ---------------------------------------------------------------------------
# /accounts/<id>/save — auto-off on HIPAA 0→1 flip
# ---------------------------------------------------------------------------

class TestAutoOffOnHipaaFlip:
    def test_flip_to_hipaa_disables_rag_toggle(
        self, client, user_cookies, db, regular_user,
    ):
        """Per operator spec: when an account flips on HIPAA, the
        AI-learns toggle must be forced off so future renders reflect
        the explicit OFF state. The operator can re-enable it
        manually after opting in to M-1+M-2."""
        a = _make_acct(db, regular_user["id"], "WillBeHipaa")
        # Pre-condition: non-HIPAA, AI-learns explicitly ON.
        set_rag_sent_index_enabled(db, a, enabled=True)
        non_hipaa_view = {"hipaa": 0}
        assert (
            is_rag_sent_index_enabled(db, a, account=non_hipaa_view)
            is True
        )

        # Post the edit form with hipaa flipped on. The handler reads
        # all the standard form fields; we send the minimum to
        # satisfy the IMAP provider type + the hipaa_submitted marker.
        resp = client.post(
            f"/accounts/{a}/save",
            data={
                "name": "WillBeHipaa",
                "provider_type": "imap",
                "host": "mail.example.com",
                "username": "alice@example.com",
                "is_active": "1",
                "hipaa_submitted": "1",
                "hipaa": "1",
            },
            cookies=user_cookies,
            follow_redirects=False,
        )
        # Either redirect (clean save) or 200 (inline error); both are
        # acceptable here — what matters is the side effect.
        assert resp.status_code in (200, 303)

        # After save: helper now sees the explicit OFF row.
        hipaa_view = {"hipaa": 1}
        assert (
            is_rag_sent_index_enabled(db, a, account=hipaa_view)
            is False
        )


# ---------------------------------------------------------------------------
# POST /profile/style-data/sent-folder-override
# ---------------------------------------------------------------------------

class TestSentFolderOverride:
    def test_save_override_writes_config_key(
        self, client, user_cookies, db, regular_user,
    ):
        from email_triage.web.db import get_email_account
        a = _make_acct(db, regular_user["id"], "OverrideAcct")
        resp = client.post(
            f"/profile/style-data/sent-folder-override?account_id={a}",
            data={"sent_folder_override": "[Gmail]/Sent Mail"},
            cookies=user_cookies,
        )
        assert resp.status_code in (200, 303)
        acct = get_email_account(db, a)
        cfg = acct.get("config") or {}
        # Post-v19 — stored as a single-element list.
        assert cfg.get("sent_folder_override") == ["[Gmail]/Sent Mail"]

    def test_empty_override_clears_key(
        self, client, user_cookies, db, regular_user,
    ):
        from email_triage.web.db import (
            get_email_account, update_account_config_keys,
        )
        a = _make_acct(db, regular_user["id"], "ClearAcct")
        # Seed an override first (post-v19 list shape).
        update_account_config_keys(
            db, a, sent_folder_override=["INBOX.Sent"],
        )
        acct = get_email_account(db, a)
        assert (acct.get("config") or {}).get("sent_folder_override") == ["INBOX.Sent"]

        # Empty submit (no value posted) should clear.
        resp = client.post(
            f"/profile/style-data/sent-folder-override?account_id={a}",
            data={},
            cookies=user_cookies,
        )
        assert resp.status_code in (200, 303)
        acct2 = get_email_account(db, a)
        # Key removed entirely (update_account_config_keys deletes on
        # None) so the get returns None / missing / empty list.
        assert (
            (acct2.get("config") or {}).get("sent_folder_override")
            in (None, [], "")
        )

    def test_render_shows_discovered_default_in_picker(
        self, client, user_cookies, db, regular_user,
    ):
        """Empty override → multi-select picker still renders the
        auto-discovered default, marked inline as "(auto-discovered)"."""
        _make_acct(db, regular_user["id"], "Personal")
        resp = client.get(
            "/profile/style-data", cookies=user_cookies,
        )
        assert resp.status_code == 200
        # Multi-select rendered.
        assert '<select name="sent_folder_override" multiple' in resp.text
        # IMAP provider type → discovered name is "Sent" + marked.
        assert "(auto-discovered)" in resp.text


# ---------------------------------------------------------------------------
# Mining-path read — SentMailIndex uses override via MailFilter
# ---------------------------------------------------------------------------

class TestMiningPathHonorsOverride:
    @pytest.mark.asyncio
    async def test_index_recent_passes_override_as_filter(
        self, db, regular_user,
    ):
        """When the override is set on the constructor, index_recent
        passes ``MailFilter(folder=<override>)`` to provider.search
        instead of the bare ``in:sent`` query. Confirms the wiring;
        provider-side SELECT behaviour is tested in the IMAP test
        suite."""
        from email_triage.actions.sent_mail_index import SentMailIndex
        from email_triage.engine.models import MailFilter

        a = _make_acct(db, regular_user["id"], "OverrideMining")

        captured_filters: list = []

        class _FakeProvider:
            async def search(self, query, limit, *, filter=None):
                captured_filters.append(filter)
                return []

            async def fetch_message(self, mid, **_):
                raise AssertionError("no ids should fetch")

        class _LocalBackend:
            backend_type = "ollama"
            async def embed_text(self, text):
                return [0.0]

        index = SentMailIndex(
            db, a,
            embedding_backend=_LocalBackend(),
            embedding_model="test-model",
            provider=_FakeProvider(),
            sent_folders=["INBOX.Sent_Items"],
        )
        result = await index.index_recent(limit=10)
        assert result == 0
        # Verify the filter carried the override.
        assert len(captured_filters) == 1
        assert isinstance(captured_filters[0], MailFilter)
        assert captured_filters[0].folder == "INBOX.Sent_Items"

    @pytest.mark.asyncio
    async def test_index_recent_no_override_no_filter(
        self, db, regular_user,
    ):
        """No override → bare ``in:sent`` query, no MailFilter kwarg —
        preserves the pre-2026-05-11 contract for Gmail/O365 where
        the in:sent query (or equivalent) carries the routing."""
        from email_triage.actions.sent_mail_index import SentMailIndex

        a = _make_acct(db, regular_user["id"], "DefaultMining")

        captured = {}

        class _FakeProvider:
            async def search(self, query, limit, *, filter=None):
                captured["filter"] = filter
                return []

        class _LocalBackend:
            backend_type = "ollama"

        index = SentMailIndex(
            db, a,
            embedding_backend=_LocalBackend(),
            embedding_model="test-model",
            provider=_FakeProvider(),
        )
        await index.index_recent(limit=10)
        # No override → no filter passed.
        assert captured.get("filter") is None
