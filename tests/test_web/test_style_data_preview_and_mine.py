"""Tests for #157 — preview + mine-now on /profile/style-data.

Covers two new POST handlers + the surrounding UX:

  * POST /profile/style-data/preview   — dry-run distillation; no commit.
  * POST /profile/style-data/mine-now  — on-demand distillation + commit.

Both share an HTMX fragment surface so the result swaps inline into
``#mine-result-<account_id>``. Both honour the same HIPAA gate as
the M-1+M-2 layer per #152 phase 2: HIPAA-flagged accounts without
the ``style_knobs_hipaa_allow:<id>`` opt-in render disabled with a
reason chip on GET + refuse on POST.

The tests mock the live provider + classifier paths via monkeypatch
so they exercise the handler wiring without an Ollama / IMAP / Gmail
round-trip. No real PII anywhere — synthetic addresses + bodies only.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone

import pytest

from email_triage.actions.style_profile import StyleProfile
from email_triage.engine.models import EmailMessage
from email_triage.web.db import (
    create_email_account,
    get_style_profile,
    list_auth_events,
    set_account_hipaa,
    set_style_knobs_hipaa_allow,
    set_style_learning_master_enabled as set_style_learning_master,
)


# ---------------------------------------------------------------------------
# Helpers / fixtures (mirror tests/test_web/test_profile_style_data.py)
# ---------------------------------------------------------------------------

def _make_acct(db, owner_id: int, name: str = "Acct") -> int:
    return create_email_account(
        db, owner_id, name, "imap", {"host": "mail.example.com"},
    )


class _StubProvider:
    """Minimal provider that returns a fixed Sent-folder message set.

    The handler asks for ``search`` then ``fetch_message`` per id, then
    ``close``. We synthesise three sent messages with example bodies the
    style-profile distillation can run against. ``find_sent_folder``
    expects either a ``name`` attribute pointing at the provider type
    OR a ``_connect`` coroutine for the IMAP SPECIAL-USE probe; we
    expose ``name='imap'`` and let the helper fall through to
    ``list_folders``.
    """

    name = "imap"

    def __init__(self, *, sent_count: int = 3) -> None:
        self._ids = [f"m{i}" for i in range(1, sent_count + 1)]
        self.closed = False

    async def list_folders(self) -> list[str]:
        return ["INBOX", "Sent", "Drafts", "Trash"]

    async def search(
        self, query: str, limit: int = 50, *, filter=None,
    ) -> list[str]:
        # 2026-05-11: handler now threads a MailFilter(folder=sent_folder)
        # so IMAP SELECTs the right mailbox before SEARCH. Stub accepts
        # + ignores; pre-fix the handler called search(query, limit)
        # with no filter, which silently scanned INBOX on real IMAP.
        return list(self._ids[:limit])

    async def fetch_message(self, mid: str, **_kw) -> EmailMessage:
        return EmailMessage(
            message_id=mid,
            provider="imap",
            sender="user@example.com",
            recipients=["other@example.com"],
            subject=f"Re: synthetic {mid}",
            body_text=(
                "Hi Person,\n\nThanks for the note. I'll take a look "
                "and get back to you.\n\nThanks,\nOperator A"
            ),
            date=datetime(2026, 5, 1, tzinfo=timezone.utc),
            headers={"Message-ID": f"<{mid}@example.com>"},
        )

    async def close(self) -> None:
        self.closed = True


class _EmptyProvider(_StubProvider):
    """Provider whose Sent folder is empty — exercises the no-mail branch."""

    def __init__(self) -> None:
        super().__init__(sent_count=0)


class _SearchFailProvider(_StubProvider):
    """Provider whose search() raises — exercises the error branch."""

    async def search(
        self, query: str, limit: int = 50, *, filter=None,
    ) -> list[str]:
        raise RuntimeError("simulated SEARCH failure")


class _FakeClassifier:
    """Classifier whose .complete() returns a fixed JSON descriptor.

    extract_style_profile is async + parses the JSON; the descriptor
    here mirrors what a real M-3 distillation produces.
    """

    model = "fake-style-classifier-v1"

    async def complete(self, prompt: str) -> str:
        # Pin a sentinel persona so tests can grep for it.
        return (
            '{"greeting":"Hi {name},",'
            '"signoff":"Thanks,\\nOperator A",'
            '"formality":2,'
            '"avg_sentence_length":12,'
            '"signature":"Operator A\\n+1 555 0100",'
            '"phrases_used":["let me know","happy to"],'
            '"phrases_avoided":["I hope this email finds you well"],'
            '"persona_summary":'
            '"STYLE_PREVIEW_SENTINEL friendly and concise."}'
        )


@pytest.fixture
def patched_pipeline(monkeypatch):
    """Patch the provider + classifier builders used by the handlers.

    Yields a state-bag so individual tests can swap in
    ``_EmptyProvider`` / ``_SearchFailProvider`` mid-test.
    """
    state = {"provider_cls": _StubProvider, "classifier": _FakeClassifier}

    from email_triage.web.routers.ui import profile as profile_mod

    def _fake_create_provider(acct, secrets, **_kw):
        return state["provider_cls"]()

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
# GET /profile/style-data — Preview / Mine button rendering
# ---------------------------------------------------------------------------

class TestPageRendersNewButtons:
    def test_buttons_render_for_owner(
        self, client, user_cookies, db, regular_user,
    ):
        _make_acct(db, regular_user["id"], "Personal")
        resp = client.get(
            "/profile/style-data", cookies=user_cookies,
        )
        assert resp.status_code == 200
        assert "Preview what would be learned" in resp.text
        assert "Mine the Sent Items Now" in resp.text

    def test_buttons_disabled_for_hipaa_without_optin(
        self, client, user_cookies, db, regular_user,
    ):
        a = _make_acct(db, regular_user["id"], "MedAcct")
        set_account_hipaa(db, a, True, actor_id=regular_user["id"])
        resp = client.get(
            "/profile/style-data", cookies=user_cookies,
        )
        assert resp.status_code == 200
        # Reason chip surfaces inline (any presence of the disable
        # chip's signature text is enough — exact copy may shift).
        assert (
            "Your writing-style preferences on this HIPAA account"
            in resp.text
        )
        # Both buttons carry the disabled attribute.
        # We can't grep "disabled" alone (Pico CSS uses it elsewhere)
        # — anchor on the button label + the attribute on the same line.
        # Jinja renders the disabled attribute right before the >.
        assert "disabled>" in resp.text

    def test_buttons_enabled_for_hipaa_with_optin(
        self, client, user_cookies, db, regular_user,
    ):
        a = _make_acct(db, regular_user["id"], "MedAcct")
        set_account_hipaa(db, a, True, actor_id=regular_user["id"])
        set_style_knobs_hipaa_allow(db, a, enabled=True)
        resp = client.get(
            "/profile/style-data", cookies=user_cookies,
        )
        assert resp.status_code == 200
        # Reason chip absent because buttons are enabled.
        assert (
            "Your writing-style preferences on this HIPAA account"
            not in resp.text
        )

    def test_empty_state_points_to_inline_toggle(
        self, client, user_cookies, db, regular_user,
    ):
        """2026-05-11 — empty-state copy used to link out to the
        per-account settings tab. The AI-learns toggle now lives
        inline on this page, so the copy says 'turn on the toggle
        below'. The empty-state must not link out anywhere — disabled
        controls speak via their own state."""
        _make_acct(db, regular_user["id"], "Personal")
        resp = client.get(
            "/profile/style-data", cookies=user_cookies,
        )
        assert resp.status_code == 200
        # New inline-pointer copy (Jinja renders with whitespace
        # between the words; substring-match the key tokens).
        assert "turn on the toggle" in resp.text
        assert "below." in resp.text
        # The empty-state copy must not name the long-retired tab or
        # link out to /accounts/<id>/edit. Anchor on substrings that
        # appeared only in the OLD copy.
        assert "the account's\n            Integrations" not in resp.text
        assert "the account's\n            <a" not in resp.text


# ---------------------------------------------------------------------------
# POST /profile/style-data/preview — dry-run, no commit
# ---------------------------------------------------------------------------

class TestPreviewEndpoint:
    def test_preview_returns_descriptor_fragment(
        self, client, user_cookies, db, regular_user, patched_pipeline,
    ):
        a = _make_acct(db, regular_user["id"], "Personal")
        resp = client.post(
            f"/profile/style-data/preview?account_id={a}",
            cookies=user_cookies,
        )
        assert resp.status_code == 200
        # Sentinel from the fake classifier survives the round-trip.
        assert "STYLE_PREVIEW_SENTINEL" in resp.text
        # The "Discard" button appears in the dry-run fragment.
        assert "Discard preview" in resp.text

    def test_preview_does_not_write_descriptor(
        self, client, user_cookies, db, regular_user, patched_pipeline,
    ):
        a = _make_acct(db, regular_user["id"], "Personal")
        # Before: no profile stored.
        assert get_style_profile(db, a) is None
        client.post(
            f"/profile/style-data/preview?account_id={a}",
            cookies=user_cookies,
        )
        # After: still no profile stored (dry run).
        assert get_style_profile(db, a) is None

    def test_preview_writes_no_mine_now_audit_row(
        self, client, user_cookies, db, regular_user, patched_pipeline,
    ):
        """A dry-run preview must not show up under the mine-now audit
        event; it can write its OWN event_type so an operator who
        wants to count previews can. The contract: no
        ``style_data_mine_now`` row from a preview call."""
        a = _make_acct(db, regular_user["id"], "Personal")
        client.post(
            f"/profile/style-data/preview?account_id={a}",
            cookies=user_cookies,
        )
        mine_rows = list_auth_events(
            db, event_type="style_data_mine_now", limit=10,
        )
        assert mine_rows == []

    def test_preview_hipaa_no_optin_refused(
        self, client, user_cookies, db, regular_user, patched_pipeline,
    ):
        a = _make_acct(db, regular_user["id"], "MedAcct")
        set_account_hipaa(db, a, True, actor_id=regular_user["id"])
        # NO style_knobs_hipaa_allow opt-in.
        resp = client.post(
            f"/profile/style-data/preview?account_id={a}",
            cookies=user_cookies,
        )
        # Soft refusal — 200 with an error fragment, so HTMX swaps
        # the result in place.
        assert resp.status_code == 200
        assert "HIPAA mailbox" in resp.text
        # Sentinel from the classifier did NOT run.
        assert "STYLE_PREVIEW_SENTINEL" not in resp.text

    def test_preview_hipaa_with_optin_runs(
        self, client, user_cookies, db, regular_user, patched_pipeline,
    ):
        a = _make_acct(db, regular_user["id"], "MedAcct")
        set_account_hipaa(db, a, True, actor_id=regular_user["id"])
        set_style_knobs_hipaa_allow(db, a, enabled=True)
        resp = client.post(
            f"/profile/style-data/preview?account_id={a}",
            cookies=user_cookies,
        )
        assert resp.status_code == 200
        # Classifier fired — descriptor sentinel present.
        assert "STYLE_PREVIEW_SENTINEL" in resp.text


# ---------------------------------------------------------------------------
# POST /profile/style-data/mine-now — commit branch
# ---------------------------------------------------------------------------

class TestMineNowEndpoint:
    def test_mine_now_persists_profile(
        self, client, user_cookies, db, regular_user, patched_pipeline,
    ):
        a = _make_acct(db, regular_user["id"], "Personal")
        assert get_style_profile(db, a) is None
        resp = client.post(
            f"/profile/style-data/mine-now?account_id={a}",
            cookies=user_cookies,
        )
        assert resp.status_code == 200
        stored = get_style_profile(db, a)
        assert stored is not None
        assert "friendly and concise" in (stored.get("persona_summary") or "")

    def test_mine_now_writes_audit_row(
        self, client, user_cookies, db, regular_user, patched_pipeline,
    ):
        a = _make_acct(db, regular_user["id"], "Personal")
        client.post(
            f"/profile/style-data/mine-now?account_id={a}",
            cookies=user_cookies,
        )
        rows = list_auth_events(
            db, event_type="style_data_mine_now", limit=10,
        )
        assert len(rows) == 1
        assert rows[0]["outcome"] == "success"
        assert f"account_id={a}" in (rows[0].get("detail") or "")

    def test_mine_now_renders_folder_label(
        self, client, user_cookies, db, regular_user, patched_pipeline,
    ):
        """The fragment should show which Sent folder was scanned so the
        operator can verify."""
        a = _make_acct(db, regular_user["id"], "Personal")
        resp = client.post(
            f"/profile/style-data/mine-now?account_id={a}",
            cookies=user_cookies,
        )
        assert resp.status_code == 200
        assert "Folder used" in resp.text
        # The fake provider's name="imap"; our find_sent_folder
        # discovery falls through to list_folders() and picks
        # "Sent" from the stub's folder list.
        assert "Sent" in resp.text

    def test_mine_now_handles_empty_sent_folder(
        self, client, user_cookies, db, regular_user, patched_pipeline,
    ):
        a = _make_acct(db, regular_user["id"], "Personal")
        patched_pipeline["provider_cls"] = _EmptyProvider
        resp = client.post(
            f"/profile/style-data/mine-now?account_id={a}",
            cookies=user_cookies,
        )
        # 200 with a soft-fail fragment.
        assert resp.status_code == 200
        assert (
            "Nothing to learn" in resp.text or "No messages" in resp.text
        )
        # No profile saved.
        assert get_style_profile(db, a) is None

    def test_mine_now_handles_search_failure(
        self, client, user_cookies, db, regular_user, patched_pipeline,
    ):
        a = _make_acct(db, regular_user["id"], "Personal")
        patched_pipeline["provider_cls"] = _SearchFailProvider
        resp = client.post(
            f"/profile/style-data/mine-now?account_id={a}",
            cookies=user_cookies,
        )
        assert resp.status_code == 200
        # Operator-facing copy uses the discovered folder name; the
        # critical assertion is that the descriptor was NOT saved.
        assert get_style_profile(db, a) is None

    def test_mine_now_hipaa_no_optin_refused(
        self, client, user_cookies, db, regular_user, patched_pipeline,
    ):
        a = _make_acct(db, regular_user["id"], "MedAcct")
        set_account_hipaa(db, a, True, actor_id=regular_user["id"])
        resp = client.post(
            f"/profile/style-data/mine-now?account_id={a}",
            cookies=user_cookies,
        )
        assert resp.status_code == 200
        assert "HIPAA mailbox" in resp.text
        # Refusal path -> no persisted profile.
        assert get_style_profile(db, a) is None
        # Failure audit row written so an operator-side audit grep
        # finds the refusal.
        rows = list_auth_events(
            db, event_type="style_data_mine_now", limit=10,
        )
        assert any(
            r.get("outcome") == "failure"
            and "hipaa_gate" in (r.get("detail") or "")
            for r in rows
        )

    def test_mine_now_inaccessible_account_returns_403(
        self, client, user_cookies, db, regular_user, admin_user,
        patched_pipeline,
    ):
        not_mine = _make_acct(db, admin_user["id"], "Foreign")
        resp = client.post(
            f"/profile/style-data/mine-now?account_id={not_mine}",
            cookies=user_cookies,
        )
        assert resp.status_code == 403


# ---------------------------------------------------------------------------
# CSRF coverage
# ---------------------------------------------------------------------------

class TestCsrfFieldsRender:
    """test_csrf_input_helper.py runs a separate grep over the
    template fileset; this targeted test belt-and-braces that the
    new POST forms each carry a CSRF field stamp."""

    def test_each_new_form_carries_csrf_field(
        self, client, user_cookies, db, regular_user,
    ):
        _make_acct(db, regular_user["id"], "Personal")
        resp = client.get(
            "/profile/style-data", cookies=user_cookies,
        )
        assert resp.status_code == 200
        text = resp.text
        # The Preview + Mine forms are HTMX hx-post forms; the CSRF
        # macro emits a hidden ``name="csrf_token"`` input. Both new
        # forms should stamp the field (existing test_csrf_input_helper
        # grep enforces this across every POST in the template tree).
        assert text.count('name="csrf_token"') >= 2
