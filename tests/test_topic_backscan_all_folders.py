"""Topic back-scan default fetcher — all-folders scan + provider-build fix.

Bugs pinned here (surfaced 2026-06-11 diagnosing "topic digest finds no
matches"), plus the SME-panel hardening:

1. **Provider-build ImportError (CRITICAL).** The fetcher imported
   ``_create_provider_from_account`` from ``web.triage_runner_bulk``, where that
   name is only a *function-local* import — never a module-level attribute. So
   the import raised ``ImportError`` the instant a real back-scan first iterated
   the fetcher → drain caught it → every non-test back-scan failed with ZERO
   hits. Fixed: import from ``web.routers.ui``. These tests patch the symbol
   *there* — if the fetcher still imported from ``triage_runner_bulk`` the patch
   wouldn't apply and the generator would ImportError, failing the test.

2. **INBOX-only folder scope.** The fetcher searched only the selected IMAP
   mailbox. Fixed: providers exposing ``search_all_folders`` (IMAP) drive a
   cross-folder scan; providers whose plain ``search`` is already mailbox-wide
   (Gmail/Graph) take the single-search path.

3. **Special-use exclusion (hipaa-sme/DA BLOCKER).** The cross-folder scan must
   NOT rake Trash / Junk / Drafts / Gmail-All-Mail (resurrecting user-deleted /
   quarantined PHI into a digest, and double-counting the \\All mirror). The
   fetcher passes ``exclude_special_use=True``.

4. **Per-folder batched fetch (db-sme SHOULD-FIX).** Over a large mailbox the
   per-message TLS+LOGIN cost dominates; the fetcher groups by folder and uses
   ``fetch_messages_batch(uids, folder=…)``, chunked at FETCH_BATCH_SIZE.
"""

from __future__ import annotations

import inspect
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from email_triage.jobs import topic_backscan
from email_triage.providers.imap_blocking import _folder_excluded_from_topic_scan

_AFTER = datetime(2026, 1, 1, tzinfo=timezone.utc)


async def _passthrough_db_call(fn, *a, **k):
    res = fn(*a, **k)
    if inspect.isawaitable(res):
        return await res
    return res


def _fake_msg(folder, uid):
    m = MagicMock()
    m.folder = folder
    m.provider_uid = uid
    return m


async def _drain_fetcher(provider, acct):
    """Drive the real ``_default_provider_fetcher_batches`` generator with the
    provider build + db_call + outcome-recorder patched, collecting messages."""
    app = MagicMock()
    app.state.secrets = MagicMock()
    seen: list = []
    with (
        patch("email_triage.web.db_threadpool.db_call", _passthrough_db_call),
        patch("email_triage.jobs.topic_backscan.get_email_account",
              MagicMock(return_value=acct)),
        patch("email_triage.web.routers.ui._create_provider_from_account",
              MagicMock(return_value=provider)),
        patch("email_triage.web.app.record_provider_outcome", MagicMock()),
    ):
        async for batch in topic_backscan._default_provider_fetcher_batches(
            app, MagicMock(), int(acct["id"]), _AFTER,
        ):
            seen.extend(batch or [])
    return seen


# ---------------------------------------------------------------------------
# Fetcher routing
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_fetcher_stamp_folder_pins_source_mailbox_on_each_message():
    """``stamp_folder=True`` pins each message's source ``.folder`` so a later
    re-fetch (the topic Preview "Test Details" body pull) can re-address the
    mailbox-scoped UID (RFC 3501 §2.3.1.1) — a parsed ``EmailMessage`` does NOT
    otherwise carry which mailbox it came from. Regression for the prod
    2026-06-12 "(metadata unavailable)" / empty-body-details class.
    """
    from types import SimpleNamespace
    acct = {"id": 7, "provider_type": "imap", "user_id": 1}
    pairs = [("INBOX", "1"), ("Archive", "2")]
    provider = MagicMock()

    async def _saf(query, limit, *, filter=None, exclude_special_use=False):
        return pairs
    provider.search_all_folders = AsyncMock(side_effect=_saf)

    async def _batch(uids, *, folder=None, headers_only=False):
        # Real EmailMessages do NOT carry ``.folder`` — return bare ones so the
        # assertion proves the FETCHER stamped it, not the fake.
        return [SimpleNamespace(message_id=u) for u in uids]
    provider.fetch_messages_batch = AsyncMock(side_effect=_batch)
    provider.close = MagicMock()

    app = MagicMock()
    app.state.secrets = MagicMock()
    stamped: list = []
    with (
        patch("email_triage.web.db_threadpool.db_call", _passthrough_db_call),
        patch("email_triage.jobs.topic_backscan.get_email_account",
              MagicMock(return_value=acct)),
        patch("email_triage.web.routers.ui._create_provider_from_account",
              MagicMock(return_value=provider)),
        patch("email_triage.web.app.record_provider_outcome", MagicMock()),
    ):
        async for batch in topic_backscan._default_provider_fetcher_batches(
            app, MagicMock(), 7, _AFTER, stamp_folder=True,
        ):
            stamped.extend(batch or [])

    assert sorted(getattr(m, "folder", None) for m in stamped) == ["Archive", "INBOX"]
    # _msg_folder now resolves for every message (was "" pre-stamp).
    assert all(topic_backscan._msg_folder(m) for m in stamped)


@pytest.mark.asyncio
async def test_fetcher_default_does_not_stamp_folder_backscan_identity_unchanged():
    """Default (``stamp_folder=False``, the back-scan path) leaves messages
    untouched — the persisted ``topic_hits`` identity keys on the durable RFC
    Message-ID, NOT the folder/UID, and must stay byte-for-byte unchanged."""
    from types import SimpleNamespace
    acct = {"id": 7, "provider_type": "imap", "user_id": 1}
    provider = MagicMock()

    async def _saf(query, limit, *, filter=None, exclude_special_use=False):
        return [("Archive", "9")]
    provider.search_all_folders = AsyncMock(side_effect=_saf)

    async def _batch(uids, *, folder=None, headers_only=False):
        return [SimpleNamespace(message_id=u) for u in uids]
    provider.fetch_messages_batch = AsyncMock(side_effect=_batch)
    provider.close = MagicMock()

    seen = await _drain_fetcher(provider, acct)   # no stamp_folder → default
    assert seen and not any(hasattr(m, "folder") for m in seen)


class _Gmailish:
    """A provider WITHOUT ``search_all_folders`` (Gmail/Graph shape) that
    paginates ``search_iter``. Used to drive Bug-A's paginated enumeration."""

    def __init__(self, pages):
        self._pages = pages          # list[list[str]]
        self.search_filter = "UNSET"
        self.fetched: list[str] = []

    async def search_iter(self, query, *, filter=None, **kw):
        self.search_filter = filter
        n = len(self._pages)
        for i, ids in enumerate(self._pages):
            yield ids, (f"tok{i}" if i < n - 1 else None)

    async def fetch_message(self, mid, *, headers_only=False, folder=None):
        from types import SimpleNamespace
        self.fetched.append(mid)
        return SimpleNamespace(message_id=mid)

    def close(self):
        pass


@pytest.mark.asyncio
async def test_fetcher_gmail_paginates_search_iter_with_window_filter():
    """Bug-A (operator 2026-06-12): a provider without ``search_all_folders``
    (Gmail/Graph) enumerates the WHOLE window via the PAGINATED ``search_iter``
    — the single-page ``search`` is provider-capped (Google's hard 500), which
    silently dropped everything past the first page. Every page is collected and
    the date-window filter is threaded to the iterator."""
    acct = {"id": 7, "provider_type": "gmail", "user_id": 1}
    provider = _Gmailish([["g1", "g2"], ["g3", "g4"], ["g5"]])

    seen = await _drain_fetcher(provider, acct)

    # All five across three pages — not just the first page.
    assert sorted(m.message_id for m in seen) == ["g1", "g2", "g3", "g4", "g5"]
    assert provider.fetched == ["g1", "g2", "g3", "g4", "g5"]
    # The window filter (MailFilter(after=...)) was threaded to search_iter.
    assert getattr(provider.search_filter, "after", None) is not None


@pytest.mark.asyncio
async def test_fetcher_ceiling_truncates_and_is_not_silent(monkeypatch, caplog):
    """Bug-A: hitting the enumeration ceiling truncates to it AND logs a WARNING
    — never a silent drop (the back-scan LLM-classifies every enumerated message,
    so the ceiling is a real bound)."""
    import logging
    monkeypatch.setattr(topic_backscan, "BACKSCAN_SEARCH_CEILING", 2)
    acct = {"id": 7, "provider_type": "gmail", "user_id": 1}
    provider = _Gmailish([["g1", "g2"], ["g3", "g4"], ["g5"]])

    with caplog.at_level(logging.WARNING):
        seen = await _drain_fetcher(provider, acct)

    # Truncated to the ceiling (2); the break stops further pagination too.
    assert [m.message_id for m in seen] == ["g1", "g2"]
    assert any("ceiling" in r.message for r in caplog.records)


@pytest.mark.asyncio
async def test_fetcher_imap_all_folders_excludes_special_use_and_batches():
    """IMAP: cross-folder search WITH exclude_special_use=True, then one
    batched fetch per folder (not per message)."""
    acct = {"id": 7, "provider_type": "imap", "user_id": 1}
    pairs = [("INBOX", "1"), ("INBOX", "2"), ("Archive", "3")]
    captured: dict = {}

    provider = MagicMock()

    async def _saf(query, limit, *, filter=None, exclude_special_use=False):
        captured["exclude_special_use"] = exclude_special_use
        return pairs

    provider.search_all_folders = AsyncMock(side_effect=_saf)
    provider.search = AsyncMock(return_value=["MUST-NOT-BE-USED"])

    async def _batch(uids, *, folder=None, headers_only=False):
        return [_fake_msg(folder, u) for u in uids]

    provider.fetch_messages_batch = AsyncMock(side_effect=_batch)
    provider.fetch_message = AsyncMock(
        side_effect=AssertionError("must batch-fetch, not single-fetch"))
    provider.close = MagicMock()

    seen = await _drain_fetcher(provider, acct)

    provider.search_all_folders.assert_awaited_once()
    assert captured["exclude_special_use"] is True   # BLOCKER fix
    provider.search.assert_not_awaited()
    # Batched once per folder with that folder's UIDs (not per message).
    calls = {
        (c.kwargs.get("folder"), tuple(c.args[0]))
        for c in provider.fetch_messages_batch.await_args_list
    }
    assert calls == {("INBOX", ("1", "2")), ("Archive", ("3",))}
    assert len(seen) == 3


@pytest.mark.asyncio
async def test_fetcher_non_imap_single_search_folderless_per_message():
    """Gmail/Graph-like provider (no search_all_folders, no batch) → plain
    search + folderless per-message fetch."""
    acct = {"id": 9, "provider_type": "gmail_api", "user_id": 1}

    provider = MagicMock(spec=["search", "fetch_message"])
    provider.search = AsyncMock(return_value=["m1", "m2"])

    async def _fetch(mid, *, folder=None, headers_only=False):
        return _fake_msg(None, mid)

    provider.fetch_message = AsyncMock(side_effect=_fetch)

    assert getattr(provider, "search_all_folders", None) is None
    assert getattr(provider, "fetch_messages_batch", None) is None

    seen = await _drain_fetcher(provider, acct)

    provider.search.assert_awaited_once()
    for c in provider.fetch_message.await_args_list:
        assert c.kwargs.get("folder") is None
    assert len(seen) == 2


@pytest.mark.asyncio
async def test_fetcher_imports_provider_builder_without_error():
    """Regression guard for the ImportError: the generator must reach the
    provider build (patched at web.routers.ui) without raising."""
    acct = {"id": 3, "provider_type": "imap", "user_id": 1}
    provider = MagicMock()
    provider.search_all_folders = AsyncMock(return_value=[])
    provider.fetch_messages_batch = AsyncMock(
        side_effect=AssertionError("no msgs to fetch"))
    provider.close = MagicMock()

    seen = await _drain_fetcher(provider, acct)
    assert seen == []
    provider.search_all_folders.assert_awaited_once()


# ---------------------------------------------------------------------------
# Special-use folder exclusion (the BLOCKER mechanism)
# ---------------------------------------------------------------------------

def test_special_use_exclusion_flag_based():
    """RFC 6154 SPECIAL-USE flags drive precise exclusion; real folders kept."""
    f = _folder_excluded_from_topic_scan
    assert f(r'(\HasNoChildren \Trash) "/" "Trash"', "Trash") is True
    assert f(r'(\Junk) "/" "Junk"', "Junk") is True
    assert f(r'(\Drafts) "/" "Drafts"', "Drafts") is True
    assert f(r'(\All) "/" "[Gmail]/All Mail"', "[Gmail]/All Mail") is True
    # Kept: real correspondence folders.
    assert f(r'(\HasNoChildren) "/" "INBOX"', "INBOX") is False
    assert f(r'(\Sent) "/" "Sent"', "Sent") is False
    assert f(r'(\Archive) "/" "Archive"', "Archive") is False
    assert f(r'(\HasNoChildren) "/" "Projects/Lupus"', "Projects/Lupus") is False


def test_special_use_exclusion_name_fallback():
    """Servers without SPECIAL-USE flags fall back to the leaf-name heuristic."""
    f = _folder_excluded_from_topic_scan
    assert f(r'(\HasNoChildren) "." "INBOX.Trash"', "INBOX.Trash") is True
    assert f(r'(\HasNoChildren) "." "INBOX.Junk"', "INBOX.Junk") is True
    assert f(r'(\HasNoChildren) "." "INBOX.Drafts"', "INBOX.Drafts") is True
    assert f(r'(\HasNoChildren) "/" "Deleted Items"', "Deleted Items") is True
    assert f(r'(\HasNoChildren) "." "INBOX.Spam"', "INBOX.Spam") is True
    # Kept.
    assert f(r'(\HasNoChildren) "." "INBOX.Sent"', "INBOX.Sent") is False
    assert f(r'(\HasNoChildren) "." "INBOX.Archive"', "INBOX.Archive") is False
    assert f(r'(\HasNoChildren) "." "INBOX"', "INBOX") is False
