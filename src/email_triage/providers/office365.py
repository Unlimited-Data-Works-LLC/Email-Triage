"""Microsoft Office 365 / Graph API email provider.

Uses ``httpx`` for Microsoft Graph API calls and ``msal`` for OAuth 2.0
authentication.  Install with::

    pip install email-triage[office365]

Supports:
- Search via OData ``$filter`` and ``$search``
- Read full message content (plain text + HTML)
- Categorize messages (Graph categories)
- Move messages between folders
- Create drafts
- Graph webhook subscriptions for push notifications

Authentication uses MSAL with a serialisable token cache so that after
initial device-code login, subsequent runs use cached refresh tokens.
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, AsyncIterator

import httpx

from email_triage.engine.models import EmailMessage
from email_triage.providers.base import EmailProvider, PushCapable
from email_triage.providers._oauth_http import oauth_request, refresh_lock_for

logger = logging.getLogger("email_triage.providers.office365")

# Guard the import — msal is optional.
try:
    import msal
    HAS_MSAL = True
except ImportError:
    HAS_MSAL = False

GRAPH_BASE = "https://graph.microsoft.com/v1.0"

# Default scopes for delegated access to user mail.
DEFAULT_SCOPES = [
    "Mail.Read",
    "Mail.ReadWrite",
    "Mail.Send",
]

# Added during the per-account "Enable Calendar" device-code flow on
# the Accounts page. Re-auth with these scopes appended replaces the
# old refresh token in DbSecrets.
CALENDAR_SCOPES = [
    "Calendars.ReadWrite",
]

# Fields to request from Graph for message listings.
_MESSAGE_SELECT = (
    "id,subject,from,toRecipients,ccRecipients,"
    "body,bodyPreview,receivedDateTime,categories,"
    "conversationId,isRead,isDraft,importance,flag"
)


class GraphError(Exception):
    """Raised when a Graph API call returns an error."""

    def __init__(self, status: int, error: dict[str, Any] | str, url: str = ""):
        self.status = status
        self.error = error
        self.url = url
        if isinstance(error, dict):
            msg = error.get("error", {}).get("message", str(error))
        else:
            msg = error
        super().__init__(f"Graph API {status}: {msg} ({url})")


class GraphDeltaResyncRequiredError(GraphError):
    """Raised when Graph reports the stored deltaLink can no longer be
    used and a fresh walk is required.

    Graph returns 410 Gone (or a body containing ``"resyncRequired"``)
    when the server-side delta cursor has expired or the underlying
    resource has shifted in a way that breaks the cursor. The caller
    should drop the stored cursor and either restart from a fresh
    delta query or fall back to a bounded backfill — same shape as
    Gmail's ``GmailHistoryExpiredError``.
    """


class Office365Provider(EmailProvider, PushCapable):
    """Microsoft 365 email via the Graph API.

    Parameters
    ----------
    client_id:
        Azure AD application (client) ID.
    tenant_id:
        Azure AD tenant ID, or ``"common"`` / ``"organizations"``
        for multi-tenant apps.
    client_secret:
        Client secret for confidential apps.  Omit for public client
        (device-code flow).
    token_cache_path:
        Path to persist the MSAL token cache.  Defaults to
        ``./data/msal_cache.json``.
    scopes:
        Graph API permission scopes.  Defaults to Mail.Read,
        Mail.ReadWrite, Mail.Send.
    """

    def __init__(
        self,
        client_id: str = "",
        tenant_id: str = "common",
        client_secret: str = "",
        token_cache_path: str = "./data/msal_cache.json",
        scopes: list[str] | None = None,
    ):
        if not HAS_MSAL:
            raise ImportError(
                "msal is required for the Office 365 provider. "
                "Install with: pip install email-triage[office365]"
            )
        self._client_id = client_id
        self._tenant_id = tenant_id
        self._client_secret = client_secret
        self._token_cache_path = Path(token_cache_path)
        self._scopes = scopes or DEFAULT_SCOPES
        self._http: httpx.AsyncClient | None = None
        self._app: Any = None  # MSAL application
        self._cache: Any = None  # MSAL SerializableTokenCache

    @property
    def name(self) -> str:
        return "office365"

    # ------------------------------------------------------------------
    # Authentication
    # ------------------------------------------------------------------

    def _init_cache(self) -> Any:
        """Load or create a serialisable MSAL token cache."""
        if self._cache is not None:
            return self._cache

        self._cache = msal.SerializableTokenCache()
        if self._token_cache_path.exists():
            self._cache.deserialize(self._token_cache_path.read_text())
        return self._cache

    def _save_cache(self) -> None:
        """Persist the token cache if it has changed."""
        if self._cache and self._cache.has_state_changed:
            self._token_cache_path.parent.mkdir(parents=True, exist_ok=True)
            self._token_cache_path.write_text(self._cache.serialize())

    def _get_app(self) -> Any:
        """Create or return the MSAL application instance."""
        if self._app is not None:
            return self._app

        cache = self._init_cache()
        authority = f"https://login.microsoftonline.com/{self._tenant_id}"

        if self._client_secret:
            self._app = msal.ConfidentialClientApplication(
                self._client_id,
                authority=authority,
                client_credential=self._client_secret,
                token_cache=cache,
            )
        else:
            self._app = msal.PublicClientApplication(
                self._client_id,
                authority=authority,
                token_cache=cache,
            )
        return self._app

    async def acquire_token(self) -> str:
        """Get a valid access token, refreshing if necessary.

        For cached accounts, uses the silent flow (refresh token).
        If no cached account exists, initiates device-code flow.
        Returns the access token string.
        """
        app = self._get_app()

        # Try silent acquisition first (cached refresh token).
        accounts = app.get_accounts()
        if accounts:
            result = app.acquire_token_silent(self._scopes, account=accounts[0])
            if result and "access_token" in result:
                self._save_cache()
                return result["access_token"]

        # For confidential client (daemon), use client credentials.
        if self._client_secret:
            # Client credentials use .default scope.
            result = app.acquire_token_for_client(
                scopes=["https://graph.microsoft.com/.default"]
            )
            if result and "access_token" in result:
                self._save_cache()
                return result["access_token"]
            error = result.get("error_description", result.get("error", "Unknown"))
            raise RuntimeError(f"Failed to acquire token: {error}")

        # Device-code flow for interactive auth.
        flow = app.initiate_device_flow(scopes=self._scopes)
        if "user_code" not in flow:
            raise RuntimeError(
                f"Device code flow failed: {flow.get('error_description', 'unknown')}"
            )

        logger.info(
            "Device code auth required",
            extra={
                "device_message": flow.get("message", ""),
                "user_code": flow.get("user_code", ""),
                "verification_uri": flow.get("verification_uri", ""),
            },
        )
        # This prints to console for the user.
        print(f"\n{flow['message']}\n")

        result = app.acquire_token_by_device_flow(flow)
        if "access_token" not in result:
            error = result.get("error_description", result.get("error", "Unknown"))
            raise RuntimeError(f"Device code auth failed: {error}")

        self._save_cache()
        return result["access_token"]

    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create an authenticated HTTP client.

        Wrapped in the per-instance ``asyncio.Lock`` (#142) so two
        concurrent coroutines hitting the cold path can't both run
        the device-code / silent-token-acquisition flow + each
        construct their own httpx client. The second would orphan
        the first's connection pool and waste a token exchange
        round-trip with Microsoft.

        Phase 2 (#138 phase 2): the client no longer carries a
        persistent ``Authorization`` header. Auth is attached per
        request via :func:`oauth_request`, matching the Gmail shape.
        Acquiring the token here still warms the MSAL cache so the
        first :meth:`_request` call doesn't pay device-code latency.
        """
        if self._http is not None:
            return self._http
        async with refresh_lock_for(self):
            # Re-check inside the lock — another coroutine may have
            # constructed it while we waited.
            if self._http is not None:
                return self._http
            # Warm the MSAL cache so the first _request call has a
            # token ready (initial_token in oauth_request). The token
            # itself isn't pinned onto the client — every request
            # reads through ``acquire_token`` again, which is cheap
            # against the cache.
            await self.acquire_token()
            self._http = httpx.AsyncClient(
                base_url=GRAPH_BASE,
                headers={
                    "Content-Type": "application/json",
                },
                timeout=30.0,
            )
            return self._http

    async def _request(
        self,
        method: str,
        path: str,
        json_data: dict | None = None,
        params: dict | None = None,
        *,
        absolute: bool = False,
    ) -> Any:
        """Make an authenticated Graph API request.

        Body lifted onto :func:`oauth_request` in #138 phase 2.
        ``acquire_token`` is the source of truth for the bearer
        token (MSAL handles refresh internally), and the typed
        :class:`GraphError` factory is the error_factory callback.

        ``absolute=True`` treats ``path`` as a fully-qualified URL
        rather than a path relative to the client base. Used by the
        paged-search generator that follows Graph's
        ``@odata.nextLink`` (which Graph returns as an absolute URL
        with the server-side cursor encoded in the query string).
        httpx's per-request URL overrides the client's ``base_url``
        when an absolute URL is passed, and the existing query
        string is preserved verbatim — important here because Graph
        encodes the page cursor as ``$skiptoken`` and we must NOT
        rebuild that from ``params``.
        """
        client = await self._get_client()

        # When absolute=True we don't pass ``params`` separately —
        # Graph's @odata.nextLink already carries the original
        # filter / select / orderby / page cursor in its query string.
        request_params = None if absolute else params

        token = await self.acquire_token()

        return await oauth_request(
            client=client,
            method=method,
            path=path,
            params=request_params,
            json_data=json_data,
            initial_token=token,
            refresh_token=self.acquire_token,
            error_factory=GraphError,
        )

    # ------------------------------------------------------------------
    # EmailProvider interface
    # ------------------------------------------------------------------

    async def search(
        self,
        query: str = "",
        limit: int = 50,
        *,
        filter: Any = None,  # MailFilter | None
    ) -> list[str]:
        """Search for messages.

        Either pass a raw query / OData filter ``query``, or a
        structured :class:`MailFilter` via ``filter``. Structured
        filter wins when both are present (raw query is ignored).
        """
        params: dict[str, str] = {
            "$top": str(limit),
            "$select": "id",
            "$orderby": "receivedDateTime desc",
        }

        # Folder selection comes from the structured filter.
        path = "/me/messages"
        if filter is not None and getattr(filter, "folder", None):
            # Graph addresses folders by display name OR well-known id.
            # We let the user supply a well-known id ("Inbox") or a
            # custom folder name; Graph accepts both for $filter on
            # mailFolders/{id}/messages.
            path = f"/me/mailFolders/{filter.folder}/messages"

        if filter is not None:
            odata_filter = self._translate_filter(filter)
        else:
            odata_filter = self._translate_query(query)

        if odata_filter:
            params["$filter"] = odata_filter
        elif query and query.strip().upper() != "ALL":
            # Use $search for free-text queries. RFC 3501 ``ALL`` is
            # the IMAP idiom for "every message"; Graph's equivalent
            # is an unconstrained list (no $filter, no $search) so
            # the orderby alone returns everything. A literal $search
            # for "ALL" would match the word in messages — wrong.
            params["$search"] = f'"{query}"'

        data = await self._request("GET", path, params=params)
        messages = data.get("value", []) if data else []
        return [m["id"] for m in messages if "id" in m]

    async def search_iter(
        self,
        query: str,
        *,
        batch_size: int = 500,
        resume_cursor: str | None = None,
    ):
        """Yield ``(batch, cursor)`` tuples by following Graph's
        ``@odata.nextLink``.

        Microsoft Graph's ``/me/messages`` returns up to ``$top``
        per call (Graph caps individual collection page sizes at
        1000) and an ``@odata.nextLink`` URL when more results
        exist. Loop the link until absent.

        Resume support: the cursor IS the absolute ``@odata.nextLink``
        URL. On a fresh run the caller passes ``resume_cursor=None``
        and the generator builds the first request from
        ``$top/$select/$orderby/$search`` params; on resume, the
        runner passes the last persisted nextLink and the loop
        starts from that page directly via ``_request(absolute=True)``.
        Graph's ``$skiptoken`` cursor lives inside the URL's query
        string and survives across processes for the lifetime of
        the underlying Graph cursor (undocumented but on the order
        of hours-to-days). If the cursor expires, Graph errors and
        the runner can fall back to a fresh walk while the dedup
        table (#101 step 8) catches duplicates.
        """
        page_size = min(int(batch_size), 1000)
        path = "/me/messages"
        first_params: dict[str, str] = {
            "$top": str(page_size),
            "$select": "id",
            "$orderby": "receivedDateTime desc",
        }
        if query and query.strip().upper() != "ALL":
            # Mirror search's behaviour: bare query becomes $search.
            # RFC 3501 ``ALL`` translates to an unconstrained list
            # (orderby alone returns everything); a literal $search
            # for "ALL" would match the word in messages.
            first_params["$search"] = f'"{query}"'
        next_link: str | None = resume_cursor or None
        while True:
            if next_link:
                # Graph returns a fully-qualified URL in
                # @odata.nextLink; call _request with absolute=True
                # so the embedded query-string ($skiptoken etc.) is
                # preserved verbatim.
                data = await self._request(
                    "GET", next_link, absolute=True,
                )
            else:
                data = await self._request(
                    "GET", path, params=first_params,
                )
            messages = (data or {}).get("value", []) if isinstance(data, dict) else []
            ids = [m["id"] for m in messages if "id" in m]
            new_cursor = (
                (data or {}).get("@odata.nextLink")
                if isinstance(data, dict) else None
            )
            if ids:
                yield ids, new_cursor
            next_link = new_cursor
            if not next_link:
                return

    @staticmethod
    def _translate_filter(filt) -> str:
        """MailFilter → Graph OData $filter string.

        Delegates to :func:`engine.query_lang.emit_o365_filter` (#138.3).
        """
        from email_triage.engine.query_lang import emit_o365_filter
        return emit_o365_filter(filt)

    @staticmethod
    def _translate_query(query: str) -> str:
        """Translate common query shortcuts to OData $filter.

        Delegates to :func:`engine.query_lang.translate_imap_query_to_o365`
        (#138.3). Returns an OData filter string, or empty string to
        signal ``$search`` should be used instead.
        """
        from email_triage.engine.query_lang import translate_imap_query_to_o365
        return translate_imap_query_to_o365(query)

    async def fetch_message(
        self,
        message_id: str,
        *,
        headers_only: bool = False,
        folder: str | None = None,
    ) -> EmailMessage:
        """Fetch a single message by Graph ID, including any attachments.

        ``headers_only`` and ``folder`` are accepted for cross-provider
        symmetry but ignored — the Graph API's ``/me/messages/{id}``
        endpoint with ``$select`` already returns a tightly-scoped
        projection, and bulk paths use ``$expand=attachments``
        regardless. Graph identifies messages by an opaque global ID,
        not a per-folder UID, so the IMAP wildcard-folder semantics
        don't apply.
        """
        _ = headers_only
        _ = folder
        data = await self._request(
            "GET",
            f"/me/messages/{message_id}",
            params={
                "$select": _MESSAGE_SELECT + ",hasAttachments",
                "$expand": "attachments",
            },
        )
        return self._normalise(data, message_id)

    def _normalise(self, data: dict[str, Any], message_id: str) -> EmailMessage:
        """Convert a Graph message resource to EmailMessage.

        Extract Graph-dialect fields then hand off to the shared
        :func:`providers._normalize.build_email_message` helper
        (#145.8) for the final assembly + link extraction.
        """
        from email_triage.providers._normalize import build_email_message

        sender = ""
        from_field = data.get("from", {})
        if from_field and isinstance(from_field, dict):
            email_addr = from_field.get("emailAddress", {})
            sender_name = email_addr.get("name", "")
            sender_addr = email_addr.get("address", "")
            sender = f"{sender_name} <{sender_addr}>" if sender_name else sender_addr

        recipients = []
        for recip in data.get("toRecipients", []):
            addr = recip.get("emailAddress", {}).get("address", "")
            if addr:
                recipients.append(addr)

        subject = data.get("subject", "")

        # Extract body — prefer plain text, fall back to HTML content.
        body = data.get("body", {})
        body_text = ""
        body_html = ""
        if body.get("contentType") == "text":
            body_text = body.get("content", "")
        elif body.get("content"):
            # HTML content — keep original HTML for link extraction, also
            # provide a stripped plain-text rendering for body_text.
            body_html = body["content"]
            body_text = self._strip_html(body_html)
        if not body_text:
            body_text = data.get("bodyPreview", "")

        # Parse date.
        date = datetime.now(timezone.utc)
        received = data.get("receivedDateTime")
        if received:
            try:
                # Graph returns ISO 8601 with Z suffix.
                date = datetime.fromisoformat(received.replace("Z", "+00:00"))
            except (ValueError, TypeError):
                pass

        labels = data.get("categories", [])
        attachments = self._extract_attachments(data)

        # Graph's /messages/{id} returns internetMessageHeaders only when
        # explicitly requested via $select=internetMessageHeaders. If the
        # fetcher included that in the query, populate here; otherwise
        # leave the dict empty. The X-Email-Triage loop-skip depends on
        # this being populated — any fetch path that feeds the triage
        # pipeline needs to request the header field too.
        headers: dict[str, str] = {}
        imh = data.get("internetMessageHeaders") or []
        for h in imh:
            name = h.get("name")
            value = h.get("value")
            if name and value is not None:
                headers[name] = str(value)

        return build_email_message(
            message_id=data.get("id", message_id),
            provider=self.name,
            sender=sender,
            recipients=recipients,
            subject=subject,
            body_text=body_text,
            body_html=body_html,
            date=date,
            thread_id=data.get("conversationId"),
            labels=labels,
            headers=headers,
            raw_metadata=data,
            attachments=attachments,
        )

    def _extract_attachments(self, data: dict[str, Any]) -> list:
        """Surface text/calendar attachments as Attachment objects.

        Other content types are listed as metadata-only (no bytes
        loaded). Graph returns ``contentBytes`` base64-encoded only
        when ``$expand=attachments`` was used at fetch time.
        """
        from email_triage.engine.models import Attachment
        from email_triage.engine.ics import parse_ics
        import base64

        out: list = []
        for raw in data.get("attachments", []) or []:
            if not isinstance(raw, dict):
                continue
            content_type = (raw.get("contentType") or "").lower()
            filename = raw.get("name", "")
            size = int(raw.get("size") or 0)
            blob: bytes | None = None
            parsed = None
            if content_type.startswith("text/calendar"):
                content_b64 = raw.get("contentBytes") or ""
                if content_b64:
                    try:
                        blob = base64.b64decode(content_b64)
                    except Exception:
                        blob = None
                if blob:
                    parsed = parse_ics(blob)
            out.append(Attachment(
                filename=filename or "attachment",
                content_type=content_type or "application/octet-stream",
                size_bytes=size,
                data=blob,
                parsed=parsed,
            ))
        return out

    @staticmethod
    def _strip_html(html: str) -> str:
        """Minimal HTML tag stripping for body text extraction."""
        import re
        # Remove HTML tags.
        text = re.sub(r"<[^>]+>", " ", html)
        # Collapse whitespace.
        text = re.sub(r"\s+", " ", text).strip()
        return text

    async def create_draft(
        self,
        to: list[str],
        subject: str,
        body: str,
        in_reply_to: str | None = None,
        thread_id: str | None = None,
        *,
        extra_headers: dict[str, str] | None = None,
    ) -> str:
        """Create a draft message via Graph API."""
        message: dict[str, Any] = {
            "subject": subject,
            "body": {
                "contentType": "text",
                "content": body,
            },
            "toRecipients": [
                {"emailAddress": {"address": addr}} for addr in to
            ],
        }

        if thread_id:
            message["conversationId"] = thread_id

        if extra_headers:
            # Graph requires custom headers to use the ``x-`` prefix
            # and go in ``internetMessageHeaders``. Standard wire
            # format for everything else is handled for us.
            message["internetMessageHeaders"] = [
                {"name": k, "value": v} for k, v in extra_headers.items()
            ]

        data = await self._request("POST", "/me/messages", json_data=message)
        return data.get("id", "") if data else ""

    async def apply_label(self, message_id: str, label: str) -> None:
        """Add a category to a message."""
        # First get current categories to avoid overwriting.
        data = await self._request(
            "GET",
            f"/me/messages/{message_id}",
            params={"$select": "categories"},
        )
        current = data.get("categories", []) if data else []
        if label not in current:
            current.append(label)
            await self._request(
                "PATCH",
                f"/me/messages/{message_id}",
                json_data={"categories": current},
            )

    async def list_labels(self) -> list[dict[str, str]]:
        """List Outlook categories.

        Uses the ``/me/outlook/masterCategories`` endpoint.
        """
        data = await self._request("GET", "/me/outlook/masterCategories")
        categories = data.get("value", []) if data else []
        return [
            {"id": c.get("id", ""), "name": c.get("displayName", "")}
            for c in categories
        ]

    async def list_folders(self) -> list[str]:
        """List all mail folder displayNames on the mailbox.

        Walks the Outlook mail-folder tree via Microsoft Graph:

          * ``GET /me/mailFolders`` returns top-level folders with
            ``childFolderCount`` per row. We page through
            ``@odata.nextLink`` when the server splits the response.
          * For every folder whose ``childFolderCount > 0`` we enqueue
            ``/me/mailFolders/{id}/childFolders`` and walk that too —
            mailboxes routinely nest under ``Inbox/Subfolder`` and the
            operator's actual Sent variant may live there.

        Returns a sorted, de-duped list of folder ``displayName``
        strings. Walks iteratively (FIFO queue) so a deeply-nested
        tree doesn't blow Python's recursion limit. Per-folder
        ``$select`` keeps the response trim; ``$top=100`` is the
        Graph default for this endpoint — pagination handles the rest.

        Used by :func:`providers.sent_folder.list_sent_like_folders`
        to populate the multi-select picker on the style-data page.
        ``find_sent_folder`` short-circuits to ``"sentitems"`` for
        Graph (the well-known folder id is accepted directly in
        ``/me/mailFolders('sentitems')/messages`` URLs) so a list
        walk failure here only affects the picker, not the canonical
        Sent-mining path.
        """
        select = "$select=id,displayName,childFolderCount&$top=100"
        names: set[str] = set()
        # FIFO queue of paths to walk; seed with the root list.
        queue: list[str] = [f"/me/mailFolders?{select}"]
        # Guard against pathological cycles or runaway responses;
        # 1000 entries is generous for any real Outlook mailbox and
        # acts as a circuit-breaker if Graph misbehaves.
        max_entries = 1000
        while queue and len(names) < max_entries:
            path = queue.pop(0)
            # Absolute URLs come from ``@odata.nextLink``; relative
            # paths are folder-list / childFolders endpoints we built.
            is_absolute = path.startswith("http://") or path.startswith("https://")
            try:
                data = await self._request(
                    "GET", path, absolute=is_absolute,
                )
            except Exception as e:
                # Capture the full message — operator caught the prior
                # ``type(e).__name__`` form was emitting bare
                # "RuntimeError" with no actionable detail. Auth-shape
                # failures demote to DEBUG (operator hasn't completed
                # OAuth, token expired, AADSTS); real failures still
                # WARN with the full message.
                err_msg = f"{type(e).__name__}: {e}"
                is_auth_shape = any(
                    tok in err_msg for tok in (
                        "AADSTS", "device code", "401", "Unauthorized",
                        "invalid_grant", "missing OAuth", "no token",
                    )
                )
                if is_auth_shape:
                    logger.debug(
                        "list_folders: skipped (account not authenticated)",
                        extra={"path": path, "error": err_msg[:120]},
                    )
                else:
                    logger.warning(
                        "list_folders: mailFolders fetch failed",
                        extra={"path": path, "error": err_msg[:200]},
                    )
                # Bail on this branch but keep what we've collected
                # so far so the caller still gets a partial list.
                continue
            for f in (data or {}).get("value", []) or []:
                name = f.get("displayName") or ""
                if name:
                    names.add(name)
                # Enqueue child walk if this folder declares children.
                if (f.get("childFolderCount") or 0) > 0:
                    fid = f.get("id") or ""
                    if fid:
                        queue.append(
                            f"/me/mailFolders/{fid}/childFolders?{select}"
                        )
            # Follow @odata.nextLink for the current listing if Graph
            # paginated the response.
            next_link = (data or {}).get("@odata.nextLink") or ""
            if next_link:
                queue.append(next_link)
        return sorted(names)

    async def archive(self, message_id: str) -> None:
        """Move a message to the Archive folder."""
        await self._request(
            "POST",
            f"/me/messages/{message_id}/move",
            json_data={"destinationId": "archive"},
        )

    async def mark_read(self, message_id: str) -> None:
        """Mark a message as read."""
        await self._request(
            "PATCH",
            f"/me/messages/{message_id}",
            json_data={"isRead": True},
        )

    # ------------------------------------------------------------------
    # Delta query (push-consumer companion)
    # ------------------------------------------------------------------

    async def poll_delta(
        self,
        delta_link: str | None = None,
        *,
        max_pages: int = 20,
    ) -> tuple[list[str], str]:
        """Walk the Inbox delta feed and return ``(message_ids, next_link)``.

        Mirrors the return-contract shape of
        :meth:`GmailApiProvider.list_history`: caller passes the
        cursor it stored last time (``delta_link``) and gets back
        the message ids that changed since plus a new cursor to
        persist for the next call.

        ``delta_link`` is None on the very first walk for a fresh
        subscription — Graph kicks off a fresh feed when no cursor
        is supplied. Subsequent calls pass back the previous walk's
        ``@odata.deltaLink``.

        Pagination: Graph caps individual delta pages and returns
        ``@odata.nextLink`` for intermediate pages plus a final
        ``@odata.deltaLink`` on the last page. The walk follows
        nextLink up to ``max_pages`` and uses the final deltaLink
        as the new cursor. Hitting the cap mid-walk returns the
        last nextLink as the cursor — the consumer treats that as
        valid and resumes there next call.

        Raises :class:`GraphDeltaResyncRequiredError` if Graph
        reports the stored cursor is no longer valid (HTTP 410 Gone
        or body containing ``resyncRequired``). Caller drops the
        cursor and falls back to a bounded backfill.
        """
        # First call: hit the delta endpoint with $select=id only.
        # Subsequent calls: use the stored absolute deltaLink which
        # already has $select / $deltatoken baked in.
        if delta_link:
            initial_path = delta_link
            absolute = True
            params: dict[str, str] | None = None
        else:
            initial_path = "/me/mailFolders('Inbox')/messages/delta"
            absolute = False
            params = {"$select": "id"}

        seen: set[str] = set()
        message_ids: list[str] = []
        cursor: str | None = None
        next_link: str | None = initial_path

        for _page in range(max_pages):
            if next_link is None:
                break
            try:
                if absolute:
                    data = await self._request(
                        "GET", next_link, absolute=True,
                    )
                else:
                    data = await self._request(
                        "GET", next_link, params=params,
                    )
            except GraphError as e:
                # 410 Gone or body mentioning resyncRequired → cursor
                # is dead. Mirror Gmail's history-expired contract.
                body_str = ""
                if isinstance(e.error, dict):
                    body_str = json.dumps(e.error).lower()
                else:
                    body_str = str(e.error).lower()
                if e.status == 410 or "resyncrequired" in body_str:
                    raise GraphDeltaResyncRequiredError(
                        e.status, e.error, e.url,
                    )
                raise

            if not isinstance(data, dict):
                break

            for entry in data.get("value", []) or []:
                mid = entry.get("id")
                if mid and mid not in seen:
                    seen.add(mid)
                    message_ids.append(mid)

            # nextLink wins for intermediate pages; deltaLink
            # arrives on the final page.
            nl = data.get("@odata.nextLink")
            dl = data.get("@odata.deltaLink")
            if nl:
                next_link = nl
                absolute = True
                params = None
                continue
            if dl:
                cursor = dl
            next_link = None
            break
        else:
            # Hit the page cap — preserve the last nextLink so the
            # next call resumes there. Empty cursor is recoverable
            # by the consumer (it'll start a fresh walk).
            cursor = next_link or ""

        return message_ids, cursor or ""

    # ------------------------------------------------------------------
    # Graph webhook subscriptions (PushCapable)
    # ------------------------------------------------------------------

    async def create_subscription(
        self,
        webhook_url: str,
        client_state: str = "",
        expiry_minutes: int = 4230,  # ~2.9 days (max is 3 days)
    ) -> dict[str, Any]:
        """Create a Graph webhook subscription for new inbox messages.

        Parameters
        ----------
        webhook_url:
            The HTTPS URL for webhook delivery (e.g.
            ``https://host.tailnet.ts.net/webhooks/graph``).
        client_state:
            Optional secret included in each notification for verification.
        expiry_minutes:
            Subscription lifetime in minutes.  Graph allows max 4230
            (~2.9 days) for mail resources.

        Returns the subscription resource dict (id, expirationDateTime, etc).
        """
        from datetime import timedelta

        expiry = datetime.now(timezone.utc) + timedelta(minutes=expiry_minutes)

        payload: dict[str, Any] = {
            "changeType": "created",
            "notificationUrl": webhook_url,
            "resource": "me/mailFolders('Inbox')/messages",
            "expirationDateTime": expiry.strftime("%Y-%m-%dT%H:%M:%S.0000000Z"),
        }
        if client_state:
            payload["clientState"] = client_state

        data = await self._request("POST", "/subscriptions", json_data=payload)
        logger.info(
            "Graph subscription created",
            extra={
                "subscription_id": data.get("id"),
                "expiration": data.get("expirationDateTime"),
            },
        )
        return data

    async def renew_subscription(
        self,
        subscription_id: str,
        expiry_minutes: int = 4230,
    ) -> dict[str, Any]:
        """Renew an existing Graph webhook subscription."""
        from datetime import timedelta

        expiry = datetime.now(timezone.utc) + timedelta(minutes=expiry_minutes)
        data = await self._request(
            "PATCH",
            f"/subscriptions/{subscription_id}",
            json_data={
                "expirationDateTime": expiry.strftime("%Y-%m-%dT%H:%M:%S.0000000Z"),
            },
        )
        logger.info(
            "Graph subscription renewed",
            extra={
                "subscription_id": subscription_id,
                "expiration": data.get("expirationDateTime") if data else None,
            },
        )
        return data or {}

    async def delete_subscription(self, subscription_id: str) -> None:
        """Delete a Graph webhook subscription."""
        await self._request("DELETE", f"/subscriptions/{subscription_id}")
        logger.info("Graph subscription deleted", extra={"subscription_id": subscription_id})

    async def watch(self) -> AsyncIterator[str]:
        """Watch for new messages via Graph webhooks.

        Graph push uses webhook delivery to ``/webhooks/graph``.
        Use ``create_subscription()`` to register, then handle
        incoming notifications in the webhook handler.

        This method is not directly usable as a standalone generator.
        """
        raise NotImplementedError(
            "Graph push uses webhooks, not a generator. "
            "Call create_subscription() and use the /webhooks/graph endpoint."
        )
        yield ""  # pragma: no cover — makes this a generator

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def close(self) -> None:
        """Close the HTTP client and save token cache."""
        if self._http is not None:
            await self._http.aclose()
            self._http = None
        self._save_cache()
