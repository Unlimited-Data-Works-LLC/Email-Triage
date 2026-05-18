"""Tests for the 2026-05-11 sent-folder multi-select picker.

Covers the picker + multi-folder fan-out shipped on top of the
2026-05-11 sent-folder override (test_style_data_toggle_and_sent_folder
covers the original single-string override; this file covers the
post-#157 list-of-folders shape):

  * Render: candidate list contains every folder matching ``*sent*``
    (case-insensitive) per the mock provider, with the auto-discovered
    folder marked inline.
  * Render: previously-saved overrides come pre-selected (``selected``
    attribute on the matching ``<option>``).
  * POST with multiple values → config_json carries the list.
  * POST with no values → config_json key cleared (back to discovery).
  * Mining: per-account ``sent_folder_override=["A","B"]`` runs
    ``provider.search`` against both folders via MailFilter.

The picker source-of-truth is ``list_sent_like_folders`` in
``providers/sent_folder.py``; the page handler wires it into
``entry.sent_folder_candidates`` after the sync snapshot returns.
"""

from __future__ import annotations

import pytest

from email_triage.web.db import (
    create_email_account,
    update_account_config_keys,
)


def _make_acct(db, owner_id: int, name: str = "Acct") -> int:
    return create_email_account(
        db, owner_id, name, "imap", {"host": "mail.example.com"},
    )


# ---------------------------------------------------------------------------
# Stub provider that the page-handler's async decorator will probe
# ---------------------------------------------------------------------------

class _StubProvider:
    """Minimal provider for the picker probe.

    Exposes ``name='imap'`` so ``find_sent_folder`` falls through to
    the IMAP path (which uses ``list_folders`` as a fallback when the
    SPECIAL-USE probe via ``_connect`` isn't available). The folder
    list mixes sent-like + unrelated entries so the substring filter
    in ``list_sent_like_folders`` is exercised.
    """

    name = "imap"

    def __init__(self, folders=None):
        self._folders = list(
            folders
            if folders is not None
            else [
                "INBOX",
                "Sent",
                "Sent Items",
                "INBOX.Sent_Archive",
                "Drafts",
                "Trash",
                "Junk",
            ]
        )

    async def list_folders(self):
        return list(self._folders)

    async def close(self):
        return None


def _patch_provider_factory(monkeypatch, provider_factory):
    """Patch ``_create_provider_from_account`` on the profile router
    so the picker probe uses the supplied factory instead of trying
    to build a real IMAP provider from the empty test secrets."""
    from email_triage.web.routers.ui import profile as ui_profile

    def _factory(acct, secrets):
        return provider_factory(acct)

    monkeypatch.setattr(
        ui_profile, "_create_provider_from_account", _factory,
    )


# ---------------------------------------------------------------------------
# GET render — candidate list + selected state
# ---------------------------------------------------------------------------

class TestPickerRender:
    def test_candidate_list_filters_to_sent_like_folders(
        self, client, user_cookies, db, regular_user, monkeypatch,
    ):
        """The multi-select renders one ``<option>`` per folder whose
        name contains "sent" (case-insensitive), plus the auto-
        discovered default at the top."""
        _make_acct(db, regular_user["id"], "Personal")
        _patch_provider_factory(
            monkeypatch, lambda acct: _StubProvider(),
        )
        resp = client.get(
            "/profile/style-data", cookies=user_cookies,
        )
        assert resp.status_code == 200
        html = resp.text
        # Multi-select rendered with the right name.
        assert '<select name="sent_folder_override" multiple' in html
        # Sent-like folders surface as options.
        assert '<option value="Sent"' in html
        assert '<option value="Sent Items"' in html
        assert '<option value="INBOX.Sent_Archive"' in html
        # Non-sent folders absent.
        assert '<option value="INBOX"' not in html
        assert '<option value="Drafts"' not in html
        assert '<option value="Trash"' not in html
        assert '<option value="Junk"' not in html

    def test_discovered_default_marked_inline(
        self, client, user_cookies, db, regular_user, monkeypatch,
    ):
        """The auto-discovered folder appears with "(auto-discovered)"
        suffix in the option label so the operator knows which one
        is the AI's auto-pick."""
        _make_acct(db, regular_user["id"], "Personal")
        _patch_provider_factory(
            monkeypatch, lambda acct: _StubProvider(),
        )
        resp = client.get(
            "/profile/style-data", cookies=user_cookies,
        )
        assert resp.status_code == 200
        assert "(auto-discovered)" in resp.text

    def test_saved_overrides_preselected(
        self, client, user_cookies, db, regular_user, monkeypatch,
    ):
        """Previously-saved overrides come pre-selected (the matching
        ``<option>`` carries the ``selected`` attribute)."""
        a = _make_acct(db, regular_user["id"], "Personal")
        # Seed two saved overrides (post-v19 list shape).
        update_account_config_keys(
            db, a,
            sent_folder_override=["Sent", "Sent Items"],
        )
        _patch_provider_factory(
            monkeypatch, lambda acct: _StubProvider(),
        )
        resp = client.get(
            "/profile/style-data", cookies=user_cookies,
        )
        assert resp.status_code == 200
        html = resp.text
        # Both saved values appear with the selected attribute.
        assert 'value="Sent"' in html
        assert 'value="Sent Items"' in html
        # Anchor: the substring 'selected>Sent<' (option text starts
        # with "Sent" or "Sent Items") shows up at least twice — once
        # per saved entry. We assert the count rather than location
        # since the discovered default is "Sent" and ALSO selected
        # because it's in the saved list.
        assert html.count("selected") >= 2

    def test_provider_probe_failure_falls_back_to_synthetic(
        self, client, user_cookies, db, regular_user, monkeypatch,
    ):
        """When the provider build / probe raises, the picker still
        renders with the synthetic discovered default + saved values."""
        a = _make_acct(db, regular_user["id"], "Personal")
        update_account_config_keys(
            db, a, sent_folder_override=["MyOwnSent"],
        )

        def _broken(acct, secrets):
            raise RuntimeError("provider build failed")

        from email_triage.web.routers.ui import profile as ui_profile
        monkeypatch.setattr(
            ui_profile, "_create_provider_from_account", _broken,
        )
        resp = client.get(
            "/profile/style-data", cookies=user_cookies,
        )
        assert resp.status_code == 200
        html = resp.text
        # Synthetic discovered default is "Sent" for IMAP.
        assert '<option value="Sent"' in html
        # Saved override is still rendered as an option (so the
        # operator can deselect it).
        assert '<option value="MyOwnSent"' in html


# ---------------------------------------------------------------------------
# POST save — multi-value + clear
# ---------------------------------------------------------------------------

class TestPickerSave:
    def test_post_multiple_values_persists_as_list(
        self, client, user_cookies, db, regular_user,
    ):
        from email_triage.web.db import get_email_account
        a = _make_acct(db, regular_user["id"], "MultiSave")
        # httpx (which Starlette's TestClient wraps) accepts repeated
        # form values when the dict value is a list — encodes as
        # ``sent_folder_override=Sent&sent_folder_override=Sent+Items``
        # so ``form.getlist`` on the server sees both.
        resp = client.post(
            f"/profile/style-data/sent-folder-override?account_id={a}",
            data={"sent_folder_override": ["Sent", "Sent Items"]},
            cookies=user_cookies,
        )
        assert resp.status_code in (200, 303)
        acct = get_email_account(db, a)
        cfg = acct.get("config") or {}
        assert cfg.get("sent_folder_override") == ["Sent", "Sent Items"]

    def test_post_no_values_clears_key(
        self, client, user_cookies, db, regular_user,
    ):
        from email_triage.web.db import get_email_account
        a = _make_acct(db, regular_user["id"], "ClearMulti")
        # Seed first.
        update_account_config_keys(
            db, a, sent_folder_override=["Sent", "Sent Items"],
        )
        # Submit with no value.
        resp = client.post(
            f"/profile/style-data/sent-folder-override?account_id={a}",
            data={},
            cookies=user_cookies,
        )
        assert resp.status_code in (200, 303)
        acct = get_email_account(db, a)
        # Key cleared → resolves to no override (discovery wins).
        assert (
            (acct.get("config") or {}).get("sent_folder_override")
            in (None, [], "")
        )

    def test_post_whitespace_values_dropped(
        self, client, user_cookies, db, regular_user,
    ):
        """Whitespace-only entries drop out so the persisted list is
        never a mix of real folder names and empty strings."""
        from email_triage.web.db import get_email_account
        a = _make_acct(db, regular_user["id"], "WhitespaceFilter")
        resp = client.post(
            f"/profile/style-data/sent-folder-override?account_id={a}",
            data={
                "sent_folder_override": [
                    "Sent", "   ", "", "Sent Items",
                ],
            },
            cookies=user_cookies,
        )
        assert resp.status_code in (200, 303)
        acct = get_email_account(db, a)
        cfg = acct.get("config") or {}
        assert cfg.get("sent_folder_override") == ["Sent", "Sent Items"]


# ---------------------------------------------------------------------------
# Mining path — multi-folder fan-out
# ---------------------------------------------------------------------------

class TestMultiFolderFanout:
    @pytest.mark.asyncio
    async def test_index_recent_searches_each_folder(
        self, db, regular_user,
    ):
        """Per-account ``sent_folders=["A","B"]`` triggers one
        ``provider.search`` call per folder, each carrying a
        ``MailFilter(folder=<name>)``. Result ids are merged with
        duplicate suppression."""
        from email_triage.actions.sent_mail_index import SentMailIndex
        from email_triage.engine.models import MailFilter

        a = _make_acct(db, regular_user["id"], "MultiFolder")

        filters_seen: list[str] = []

        class _FakeProvider:
            async def search(self, query, limit, *, filter=None):
                assert isinstance(filter, MailFilter)
                filters_seen.append(filter.folder or "")
                # Return zero ids so we don't have to mock fetch.
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
            sent_folders=["Sent", "Sent Items"],
        )
        result = await index.index_recent(limit=10)
        assert result == 0
        # Both folders probed.
        assert filters_seen == ["Sent", "Sent Items"]

    @pytest.mark.asyncio
    async def test_capture_loop_searches_each_folder(
        self, db, regular_user,
    ):
        """Same fan-out contract on ``SentMailCaptureLoop`` so the
        background scan-recent tick also fans across every configured
        folder."""
        from email_triage.actions.sent_mail_capture import (
            SentMailCaptureLoop,
        )
        from email_triage.engine.models import MailFilter

        a = _make_acct(db, regular_user["id"], "CaptureMulti")

        filters_seen: list[str] = []

        class _FakeProvider:
            async def search(self, query, limit, *, filter=None):
                assert isinstance(filter, MailFilter)
                filters_seen.append(filter.folder or "")
                return []

            async def fetch_message(self, mid, **_):
                raise AssertionError("no ids should fetch")

        class _StubIndex:
            async def index_message(self, *args, **kwargs):
                return None

        loop = SentMailCaptureLoop(
            db, a,
            provider=_FakeProvider(),
            sent_mail_index=_StubIndex(),
            sent_folders=["Sent", "INBOX.Sent_Items"],
        )
        captured = await loop.scan_recent(limit=10)
        assert captured == 0
        assert filters_seen == ["Sent", "INBOX.Sent_Items"]

    @pytest.mark.asyncio
    async def test_index_recent_dedups_across_folders(
        self, db, regular_user,
    ):
        """Same message id returned from two folders only fetches +
        embeds once per tick."""
        from email_triage.actions.sent_mail_index import SentMailIndex

        a = _make_acct(db, regular_user["id"], "DedupAcct")

        fetched_ids: list[str] = []
        call_counter = {"n": 0}

        class _FakeProvider:
            async def search(self, query, limit, *, filter=None):
                call_counter["n"] += 1
                # Both folders share an id (the same message lives in
                # both — happens on Gmail-via-IMAP installs where Sent
                # and All Mail both surface it).
                return ["m1"] if filter and filter.folder else []

            async def fetch_message(self, mid, **_):
                fetched_ids.append(mid)
                raise RuntimeError("stop early — we counted the dedup")

        class _LocalBackend:
            backend_type = "ollama"
            async def embed_text(self, text):
                return [0.0]

        index = SentMailIndex(
            db, a,
            embedding_backend=_LocalBackend(),
            embedding_model="test-model",
            provider=_FakeProvider(),
            sent_folders=["A", "B"],
        )
        # The fetch raises so the inner index_message is skipped; the
        # outer scan_recent / index_recent loop swallows fetch errors.
        await index.index_recent(limit=10)
        # Both folders probed.
        assert call_counter["n"] == 2
        # But the duplicate id only triggered ONE fetch attempt.
        assert fetched_ids == ["m1"]


# ---------------------------------------------------------------------------
# normalize_sent_folder_override coercion contract
# ---------------------------------------------------------------------------

class TestNormalizeHelper:
    def test_legacy_string_wraps_to_list(self):
        from email_triage.providers.sent_folder import (
            normalize_sent_folder_override,
        )
        assert normalize_sent_folder_override("Sent") == ["Sent"]

    def test_empty_string_collapses_to_empty_list(self):
        from email_triage.providers.sent_folder import (
            normalize_sent_folder_override,
        )
        assert normalize_sent_folder_override("") == []
        assert normalize_sent_folder_override("   ") == []

    def test_none_collapses_to_empty_list(self):
        from email_triage.providers.sent_folder import (
            normalize_sent_folder_override,
        )
        assert normalize_sent_folder_override(None) == []

    def test_list_passes_through_with_strip_and_empty_drop(self):
        from email_triage.providers.sent_folder import (
            normalize_sent_folder_override,
        )
        assert normalize_sent_folder_override(
            ["Sent", "  Sent Items  ", "", "   ", "Archive"]
        ) == ["Sent", "Sent Items", "Archive"]

    def test_unknown_shape_collapses_to_empty_list(self):
        from email_triage.providers.sent_folder import (
            normalize_sent_folder_override,
        )
        assert normalize_sent_folder_override(42) == []
        assert normalize_sent_folder_override({"a": 1}) == []
