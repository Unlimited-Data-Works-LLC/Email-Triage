"""Abstract email provider interface.

All email providers (Gmail API, IMAP, Office 365) implement
this interface so the flow engine can fetch and act on emails without
knowing which backend is in use.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, AsyncIterator

from email_triage.engine.models import EmailMessage


class ProviderTransientError(Exception):
    """Raised by a provider when a polling RPC failed for a recoverable
    reason (network blip, server returned non-OK status, auth refresh
    in flight). Distinct from "no new mail" — callers that previously
    treated an empty list as success now have a third state:

        - returned non-empty list  → process the messages.
        - returned empty list      → no new mail; this poll succeeded.
        - raised this exception    → poll failed; bump retry counter,
          surface in /health, do NOT update HWM.

    The previous shape (``return []`` on SEARCH/FETCH failure) made
    "broken provider" look identical to "quiet mailbox" — the operator
    only noticed via downstream symptoms (digest stops arriving, last
    triage run grows stale). With this exception the failure is
    explicit and the WatcherManager.failing_since plumbing (PR 5 / C1)
    surfaces it within 15 minutes.

    The exception is recoverable; the caller should retry with backoff,
    not crash the watcher coroutine.
    """


class EmailProvider(ABC):
    """Fetch and manipulate emails from a single mailbox."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Short identifier for this provider (e.g. 'gmail_api', 'imap')."""

    @abstractmethod
    async def search(
        self,
        query: str,
        limit: int = 50,
    ) -> list[str]:
        """Search for message IDs matching ``query``.

        The query format is provider-specific (Gmail query syntax, IMAP
        search criteria, Graph OData filter, etc.).
        """

    async def search_iter(
        self,
        query: str,
        *,
        batch_size: int = 500,
        resume_cursor: str | None = None,
    ) -> AsyncIterator[tuple[list[str], str | None]]:
        """Yield ``(batch, cursor)`` tuples for paged enumeration.

        Bulk-triage callers want every match in the mailbox, not the
        first ``batch_size``. Concrete providers override this to use
        their native pagination (Gmail's ``pageToken``, Graph's
        ``@odata.nextLink``, IMAP's UID range constraint) so a
        multi-thousand-message sweep doesn't pull the whole result
        set into a single Python list AND can resume from where a
        crashed pass left off.

        The second tuple value is an opaque resume handle the
        consumer persists after each batch. Provider-specific format:

          IMAP   — string-encoded max UID processed in the batch
          Gmail  — nextPageToken from messages.list
          O365   — fully-qualified @odata.nextLink URL

        On a fresh run the consumer passes ``resume_cursor=None``;
        on resume after a crash, the consumer passes the last
        persisted cursor and the generator picks up from there.

        Default implementation: single ``search()`` call, yields
        once with ``cursor=None`` — covers providers that haven't
        grown a paged variant. Sweeps against those providers cap
        at ``batch_size`` and have no resume support; the dedup
        table (#101 step 8) still prevents double-processing on
        resume, just less efficiently.

        Args:
            query: provider-specific query string.
            batch_size: target page size. Providers may cap this
                lower (Gmail's max ``maxResults`` is 500; Graph's
                max ``$top`` is 1000).
            resume_cursor: opaque handle from a prior batch's
                second tuple value. None on fresh runs.

        Yields:
            (batch, cursor) tuples. Final batch's cursor may still
            be non-None; consumer continues until the generator
            terminates (i.e. no further yield).
        """
        # Default — single non-paged call, no resume support.
        # Concrete providers override.
        ids = await self.search(query, batch_size)
        if ids:
            yield ids, None
        return  # pragma: no cover — bare return for the empty-ids case

    @abstractmethod
    async def fetch_message(
        self,
        message_id: str,
        *,
        headers_only: bool = False,
        folder: str | None = None,
    ) -> EmailMessage:
        """Fetch a single message by ID and return it normalised.

        ``headers_only`` (default False) is an opt-in fast-path for
        metadata-list callers. Providers that have no cheaper
        headers-only mode are free to ignore the flag and return the
        full message — the contract guarantees that the returned
        EmailMessage's metadata fields (sender / recipients / subject /
        date / labels / headers) are populated; ``body_text``,
        ``body_html``, ``links``, and ``attachments`` MAY be empty
        when ``headers_only=True``.

        ``folder`` (default None) is an optional per-call mailbox
        override. Used by IMAP's cross-folder search path —
        :meth:`search_all_folders` returns ``(folder, uid)`` pairs and
        callers fetch each UID against the folder it was found in,
        since IMAP UIDs are mailbox-scoped (RFC 3501 § 2.3.1.1).
        Providers without per-folder semantics (Gmail API has global
        labels; Graph paginates messages globally) are free to ignore
        the kwarg.
        """

    async def create_draft(
        self,
        to: list[str],
        subject: str,
        body: str,
        in_reply_to: str | None = None,
        thread_id: str | None = None,
        *,
        extra_headers: dict[str, str] | None = None,
        from_addr: str | None = None,
        from_name: str | None = None,
        reply_to: str | None = None,
    ) -> str:
        """Create a draft message.  Returns the draft ID.

        ``extra_headers`` carries optional RFC 5322 headers that
        callers (notably the loop-prevention ``X-Email-Triage:``
        stamp) want on the outbound MIME. Providers that can't plumb
        arbitrary headers through to their wire format are free to
        drop them, but stamping is the default expectation.

        ``from_addr``/``from_name``/``reply_to`` are optional overrides
        for system-generated mail (digests etc.) where the triage
        identity — not the mailbox owner — is the honest ``From:``.
        When omitted, providers fall back to the mailbox's own address.

        Not all providers support drafts — the default raises
        ``NotImplementedError``.
        """
        raise NotImplementedError(f"{self.name} does not support drafts")

    async def deliver_to_inbox(
        self,
        to: list[str],
        subject: str,
        body: str,
        *,
        extra_headers: dict[str, str] | None = None,
        from_addr: str | None = None,
        from_name: str | None = None,
        reply_to: str | None = None,
    ) -> str:
        """Deliver a self-composed message directly to the user's inbox.

        Used by features like newsletter digests that produce content
        for the user to read — skipping the Drafts-folder detour.  Body
        is HTML.  Returns a provider-specific identifier (e.g. the new
        UID).  Default raises ``NotImplementedError``.
        """
        raise NotImplementedError(
            f"{self.name} does not support inbox delivery"
        )

    async def apply_label(
        self,
        message_id: str,
        label: str,
    ) -> None:
        """Apply a label/category/tag to a message.

        Not all providers support labels — the default raises
        ``NotImplementedError``.
        """
        raise NotImplementedError(f"{self.name} does not support labels")

    async def list_labels(self) -> list[dict[str, str]]:
        """List available labels.  Returns list of {id, name} dicts."""
        raise NotImplementedError(f"{self.name} does not support label listing")

    async def archive(self, message_id: str) -> None:
        """Archive a message (remove from inbox)."""
        raise NotImplementedError(f"{self.name} does not support archiving")

    async def list_folders(self) -> list[str]:
        """List available folders/mailboxes.

        Returns a sorted list of folder names (e.g. ``["INBOX", "Archive",
        "Triage/invoices"]``).  For Gmail, these are labels.
        """
        raise NotImplementedError(f"{self.name} does not support folder listing")

    async def create_folder(self, folder: str) -> None:
        """Create a new folder/mailbox.

        For Gmail this creates a label; for IMAP it creates a mailbox.
        """
        raise NotImplementedError(f"{self.name} does not support folder creation")

    async def move_message(self, message_id: str, folder: str) -> None:
        """Move a message to a different folder.

        The message is removed from the current folder and placed in
        ``folder``.  For IMAP this is COPY + DELETE; for Gmail it's
        label add + INBOX remove.
        """
        raise NotImplementedError(f"{self.name} does not support moving messages")

    async def set_keywords(self, message_id: str, keywords: list[str]) -> None:
        """Set IMAP keywords (custom flags) on a message.

        Keywords are arbitrary strings stored as IMAP flags.  Thunderbird
        and other clients can display these as colored tags if configured.
        Only meaningful for IMAP providers; others raise NotImplementedError.
        """
        raise NotImplementedError(f"{self.name} does not support keywords")

    async def close(self) -> None:
        """Release any held connections or resources."""


class PushCapable(ABC):
    """Mixin for providers that support real-time push notifications.

    Providers implementing this expose a ``watch`` async iterator that
    yields new message IDs as they arrive.
    """

    @abstractmethod
    async def watch(self) -> AsyncIterator[str]:
        """Yield message IDs as new mail arrives.

        This is a long-lived async generator.  Implementations:
        - IMAP IDLE: maintains an open IMAP connection
        - Gmail Pub/Sub: receives webhook hits and yields IDs
        - Graph webhooks: receives subscription notifications
        """
        yield ""  # pragma: no cover — abstract
