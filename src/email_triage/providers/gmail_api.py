"""Gmail provider via the Gmail REST API.

Talks directly to
``https://gmail.googleapis.com`` using ``httpx`` and manages OAuth 2.0
tokens in-process. No external binary, no subprocess, no on-disk token
cache — refresh tokens live encrypted in :class:`DbSecrets` and access
tokens are cached in memory.

Device-code flow is the MVP; the redirect flow lands when a public
HTTPS endpoint is available. The provider is populated with a refresh
token at construction time — acquiring that refresh token is handled
by the accounts-page auth flow, not by this class.
"""

from __future__ import annotations

import asyncio
import base64
import difflib
import json
import logging
import time
from datetime import datetime, timezone
from email.message import EmailMessage as MIMEEmailMessage
from email.utils import parsedate_to_datetime
from typing import Any, AsyncIterator

import httpx

from email_triage.engine.models import EmailMessage
from email_triage.providers.base import EmailProvider, PushCapable
from email_triage.providers._oauth_http import oauth_request, refresh_lock_for

logger = logging.getLogger("email_triage.providers.gmail_api")

GMAIL_BASE = "https://gmail.googleapis.com/gmail/v1"
OAUTH_TOKEN_URL = "https://oauth2.googleapis.com/token"  # noqa: S105
OAUTH_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"  # noqa: S105

DEFAULT_SCOPES = [
    "https://www.googleapis.com/auth/gmail.modify",
    "https://www.googleapis.com/auth/gmail.labels",
]

# Scopes requested when the user explicitly enables the calendar
# subsystem on an account — appended to DEFAULT_SCOPES during the
# re-auth device-code flow. The new refresh token replaces the old.
CALENDAR_SCOPES = [
    "https://www.googleapis.com/auth/calendar",
]


def _html_to_text_fallback(html_str: str) -> str:
    """Crude HTML → text for the multipart/alternative plain fallback.

    Not trying to render HTML beautifully in text — just produce a
    readable fallback so strict-plain-text IMAP clients + accessibility
    readers have something coherent. Strips tags, decodes entities,
    collapses whitespace. No external dependencies.
    """
    import html as _html
    import re as _re
    # Replace block-level tags with newlines before stripping so the
    # output has some structure.
    with_breaks = _re.sub(
        r"</?(?:p|div|br|li|tr|h[1-6]|ul|ol|hr)[^>]*>", "\n", html_str,
        flags=_re.IGNORECASE,
    )
    # Strip remaining tags.
    no_tags = _re.sub(r"<[^>]+>", "", with_breaks)
    # Decode HTML entities.
    decoded = _html.unescape(no_tags)
    # Collapse whitespace: trim each line, drop empties, join with \n.
    lines = [ln.strip() for ln in decoded.splitlines()]
    lines = [ln for ln in lines if ln]
    return "\n".join(lines) + "\n"


class GmailApiError(Exception):
    """Raised when a Gmail API call returns an error."""

    def __init__(self, status: int, body: Any, url: str = ""):
        self.status = status
        self.body = body
        self.url = url
        if isinstance(body, dict):
            # Defensive scrub (#168 hardening): before any str(body)
            # fallback can fire, drop any key whose name matches the
            # canonical _TOKEN_KEYS frozenset. No call site triggers a
            # success-shape body today — Google's 4xx bodies always
            # carry an ``error`` key, and ``_refresh_access_token``
            # only raises on status >= 400 — but a future refactor
            # that constructs the exception from a token-response
            # dict would silently leak ``access_token`` /
            # ``refresh_token`` / ``id_token`` values verbatim. The
            # scrub is cheap (single dict comprehension) and the
            # canonical TriageLogger._TOKEN_KEYS is the single source
            # of truth — do NOT inline a separate list here.
            from email_triage.triage_logging import TriageLogger
            _token_keys = TriageLogger._TOKEN_KEYS
            safe_body = {
                k: v for k, v in body.items() if k.lower() not in _token_keys
            }
            err = body.get("error", {})
            if isinstance(err, dict):
                msg = err.get("message", str(safe_body))
            else:
                # OAuth device-flow returns {"error": "authorization_pending",
                # "error_description": "..."} — a flat string error.
                msg = body.get("error_description") or str(err) or str(safe_body)
        else:
            msg = str(body)
        super().__init__(f"Gmail API {status}: {msg} ({url})")


class GmailAuthError(GmailApiError):
    """Raised when OAuth token acquisition/refresh fails."""


class GmailHistoryExpiredError(GmailApiError):
    """Raised when ``startHistoryId`` is older than Gmail's retention window.

    Gmail returns 404 with body containing ``"historyId is too old"`` once
    the stored cursor falls off the server's window (typically ~7 days).
    Callers should resync via ``search()`` with a bounded time filter and
    reset their stored history_id to the new watermark.
    """


class GmailApiProvider(EmailProvider, PushCapable):
    """Native Gmail provider.

    Parameters
    ----------
    account:
        The Gmail address — kept for labelling/logging only; the API uses
        ``me`` for all user-scoped calls.
    client_id:
        Google OAuth client id (public client — no secret for device-code).
    client_secret:
        Optional client secret (only when using a confidential client;
        device-code flow accepts public clients).
    refresh_token:
        OAuth 2.0 refresh token. May be empty on first construction;
        ``fetch_message`` etc. will raise ``GmailAuthError`` until one
        is set via the account's auth endpoint.
    scopes:
        OAuth scopes; defaults to gmail.modify + gmail.labels.
    """

    def __init__(
        self,
        account: str = "",
        client_id: str = "",
        client_secret: str = "",
        refresh_token: str = "",
        scopes: list[str] | None = None,
        timeout: float = 30.0,
    ):
        self._account = account
        self._client_id = client_id
        self._client_secret = client_secret
        self._refresh_token = refresh_token
        self._scopes = scopes or list(DEFAULT_SCOPES)
        self._timeout = timeout
        self._access_token: str = ""
        self._access_token_expires_at: float = 0.0
        self._http: httpx.AsyncClient | None = None
        self._label_cache: dict[str, str] | None = None

    @property
    def name(self) -> str:
        return "gmail_api"

    # ------------------------------------------------------------------
    # OAuth
    # ------------------------------------------------------------------

    async def _refresh_access_token(self) -> str:
        """Exchange the refresh token for a fresh access token.

        ``client_secret`` is required — Google's token endpoint rejects
        the refresh-token grant without it for BOTH Web application and
        Desktop client types. Fast-fail here with an actionable message
        instead of letting Google's generic "client_secret is missing"
        surface on the first API call of a triage run.

        Wrapped in a per-instance ``asyncio.Lock`` (#142) to prevent
        the thundering-herd refresh + orphan httpx-client problem when
        N concurrent API calls all hit a 401 simultaneously. The lock
        check inside the critical section short-circuits the second
        through Nth caller — they re-read the cached token instead of
        firing N parallel refresh requests at Google.
        """
        async with refresh_lock_for(self):
            # Re-check inside the lock: another coroutine that won the
            # race may have already refreshed. Avoid burning a token
            # exchange when the cached one is now valid.
            if (
                self._access_token
                and time.time() < self._access_token_expires_at
            ):
                return self._access_token

            if not self._refresh_token:
                raise GmailAuthError(401, "No refresh token — account not authenticated")
            if not self._client_id:
                raise GmailAuthError(400, "client_id not configured")
            if not self._client_secret:
                raise GmailAuthError(
                    400,
                    "client_secret not configured — edit the account and re-enter "
                    "the OAuth client secret in the account form",
                )

            data: dict[str, str] = {
                "client_id": self._client_id,
                "client_secret": self._client_secret,
                "refresh_token": self._refresh_token,
                "grant_type": "refresh_token",
            }

            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.post(OAUTH_TOKEN_URL, data=data)

            if resp.status_code >= 400:
                try:
                    body = resp.json()
                except Exception:
                    body = resp.text
                raise GmailAuthError(resp.status_code, body, OAUTH_TOKEN_URL)

            payload = resp.json()
            token = payload.get("access_token", "")
            if not token:
                raise GmailAuthError(500, "Token response missing access_token", OAUTH_TOKEN_URL)
            expires_in = int(payload.get("expires_in", 3600))
            self._access_token = token
            self._access_token_expires_at = time.time() + expires_in - 60
            return token

    async def _ensure_token(self) -> str:
        """Return a valid access token, refreshing if near expiry."""
        if self._access_token and time.time() < self._access_token_expires_at:
            return self._access_token
        return await self._refresh_access_token()

    async def _get_client(self) -> httpx.AsyncClient:
        """Lazy-init the httpx.AsyncClient.

        Wrapped in the per-instance lock (#142) so two concurrent
        coroutines can't both observe ``self._http is None`` and each
        construct their own client — the second would overwrite the
        first and orphan a live httpx connection pool.
        """
        if self._http is not None:
            return self._http
        async with refresh_lock_for(self):
            # Re-check after acquiring — another coroutine may have
            # constructed it while we waited.
            if self._http is None:
                self._http = httpx.AsyncClient(
                    base_url=GMAIL_BASE,
                    timeout=self._timeout,
                )
            return self._http

    async def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json_data: Any = None,
    ) -> Any:
        """Authenticated Gmail API request with 401 retry.

        Body lifted onto :func:`oauth_request` in #138 phase 2; the
        dialect-specific bits (per-request ``Authorization`` header
        + the typed :class:`GmailApiError` factory) ride into the
        shared helper as callbacks.
        """
        client = await self._get_client()
        token = await self._ensure_token()

        return await oauth_request(
            client=client,
            method=method,
            path=path,
            params=params,
            json_data=json_data,
            initial_token=token,
            refresh_token=self._refresh_access_token,
            error_factory=GmailApiError,
        )

    # ------------------------------------------------------------------
    # Search + fetch
    # ------------------------------------------------------------------

    async def search(
        self,
        query: str = "",
        limit: int = 50,
        *,
        filter: Any = None,  # MailFilter | None — typed loosely to avoid circular import
    ) -> list[str]:
        """Search messages.

        Either pass a raw Gmail-syntax ``query`` or a structured
        :class:`email_triage.engine.models.MailFilter` via ``filter``.
        When both are supplied the structured filter is translated and
        the raw query is appended.

        If ``query`` looks like IMAP search syntax (e.g.
        ``"UNSEEN SINCE 16-Apr-2026"``) it's translated to Gmail's
        ``q=`` shape first — so callers built for IMAP (the digest
        handler, in particular) can point the same criteria at Gmail.
        """
        params: dict[str, Any] = {"maxResults": str(limit)}
        translated_filter = self._translate_filter(filter) if filter is not None else ""
        translated_query = self._translate_imap_query(query) if query else ""
        merged = " ".join(s for s in (translated_filter, translated_query) if s).strip()
        if merged:
            params["q"] = merged
        data = await self._request("GET", "/users/me/messages", params=params)
        messages = (data or {}).get("messages", []) if isinstance(data, dict) else []
        return [m.get("id", "") for m in messages if m.get("id")]

    async def search_iter(
        self,
        query: str,
        *,
        batch_size: int = 500,
        resume_cursor: str | None = None,
    ):
        """Yield ``(batch, cursor)`` tuples via Gmail's ``pageToken``.

        Gmail's ``users.messages.list`` returns up to ``maxResults``
        per call (capped at 500 by Google) and a ``nextPageToken``
        when more results exist. Loop until that token is absent.

        Resume support: the cursor IS the pageToken. On a fresh run
        the caller passes ``resume_cursor=None``; on resume after a
        crash, pass the last persisted token and the loop starts
        from that page directly. pageTokens have a TTL on Google's
        side (typically days, not hours, but undocumented) — if the
        token has expired, Gmail rejects the request and the runner
        falls back to a fresh walk while the dedup table (#101 step
        8) catches duplicates from already-processed UIDs.
        """
        page_size = min(int(batch_size), 500)
        translated_query = self._translate_imap_query(query) if query else ""
        merged = translated_query.strip()
        page_token: str | None = resume_cursor or None
        while True:
            params: dict[str, Any] = {"maxResults": str(page_size)}
            if merged:
                params["q"] = merged
            if page_token:
                params["pageToken"] = page_token
            data = await self._request(
                "GET", "/users/me/messages", params=params,
            )
            messages = (
                (data or {}).get("messages", [])
                if isinstance(data, dict) else []
            )
            ids = [m.get("id", "") for m in messages if m.get("id")]
            new_cursor = (
                (data or {}).get("nextPageToken")
                if isinstance(data, dict) else None
            )
            if ids:
                yield ids, new_cursor
            page_token = new_cursor
            if not page_token:
                return

    @staticmethod
    def _translate_imap_query(q: str) -> str:
        """Best-effort IMAP SEARCH → Gmail q= translation.

        Delegates to :func:`engine.query_lang.translate_imap_query_to_gmail`
        (#138.3). Recognises the tokens the digest + triage handlers
        currently emit: ``UNSEEN`` / ``SEEN`` / ``ALL`` / ``SINCE`` /
        ``BEFORE``. Tokens already in Gmail shape pass through.
        """
        from email_triage.engine.query_lang import translate_imap_query_to_gmail
        return translate_imap_query_to_gmail(q)

    @staticmethod
    def _translate_filter(filt) -> str:
        """MailFilter → Gmail search-operator string.

        Delegates to :func:`engine.query_lang.emit_gmail_filter` (#138.3).
        """
        from email_triage.engine.query_lang import emit_gmail_filter
        return emit_gmail_filter(filt)

    async def fetch_message(
        self,
        message_id: str,
        *,
        headers_only: bool = False,
        folder: str | None = None,
    ) -> EmailMessage:
        # Gmail API supports format=metadata for headers-only, but the
        # bulk-list path that drives ``headers_only`` is currently
        # IMAP-specific (the kwarg dodges an aioimaplib parens bug).
        # Switching Gmail to format=metadata would also work but
        # offers no win here, and metadata mode drops the snippet
        # field that ``_summarise_message`` happily renders. Leave
        # Gmail on ``format=full`` until there's a measured payoff.
        # ``folder`` is also no-op here — Gmail labels are global,
        # not folder-scoped, and the messages.get endpoint resolves
        # by message_id alone.
        _ = headers_only
        _ = folder
        data = await self._request(
            "GET",
            f"/users/me/messages/{message_id}",
            params={"format": "full"},
        )
        if not isinstance(data, dict):
            raise GmailApiError(500, f"Unexpected response for {message_id}")
        return self._normalise(data, message_id)

    async def list_history(
        self,
        start_history_id: str,
        history_types: list[str] | None = None,
        label_id: str | None = "INBOX",
    ) -> dict[str, Any]:
        """Return the Gmail history delta since ``start_history_id``.

        Walks ``nextPageToken`` internally and returns a dict with the
        merged ``history`` array and the latest ``historyId`` seen.
        Raises :class:`GmailHistoryExpiredError` if Gmail reports the
        cursor has fallen off its retention window.
        """
        params: dict[str, Any] = {"startHistoryId": str(start_history_id)}
        for t in history_types or ["messageAdded"]:
            # httpx renders repeated keys correctly when value is a list.
            params.setdefault("historyTypes", []).append(t)
        if label_id:
            params["labelId"] = label_id

        merged: list[dict[str, Any]] = []
        latest_history_id = str(start_history_id)
        next_page: str | None = None

        while True:
            if next_page:
                params["pageToken"] = next_page
            try:
                data = await self._request(
                    "GET", "/users/me/history", params=params,
                )
            except GmailApiError as e:
                if e.status == 404:
                    body_str = (
                        json.dumps(e.body) if isinstance(e.body, dict) else str(e.body)
                    ).lower()
                    if "too old" in body_str or "not found" in body_str:
                        raise GmailHistoryExpiredError(
                            404, e.body, "/users/me/history",
                        )
                raise

            if not isinstance(data, dict):
                break

            page_history = data.get("history") or []
            merged.extend(page_history)

            hid = data.get("historyId")
            if hid:
                latest_history_id = str(hid)

            next_page = data.get("nextPageToken")
            if not next_page:
                break

        return {"history": merged, "historyId": latest_history_id}

    def _normalise(self, data: dict[str, Any], message_id: str) -> EmailMessage:
        """Extract Gmail-dialect fields and hand off to the shared
        :func:`providers._normalize.build_email_message` helper (#145.8).

        Provider-specific work — header dict construction, internalDate
        parsing, MIME tree walk for body / html / attachments — stays
        here. The final EmailMessage assembly + ``extract_links``
        post-step is shared with O365 + IMAP.
        """
        from email_triage.providers._normalize import build_email_message

        payload = data.get("payload", {}) or {}
        headers: dict[str, str] = {}
        for h in payload.get("headers", []):
            name = (h.get("name") or "").lower()
            if name:
                headers[name] = h.get("value", "")

        sender = headers.get("from", "")
        subject = headers.get("subject", "")
        to_header = headers.get("to", "")
        recipients = (
            [r.strip() for r in to_header.split(",") if r.strip()]
            if to_header
            else []
        )

        date = datetime.now(timezone.utc)
        internal_date = data.get("internalDate")
        if internal_date:
            try:
                date = datetime.fromtimestamp(
                    int(internal_date) / 1000, tz=timezone.utc,
                )
            except (ValueError, TypeError):
                pass
        elif headers.get("date"):
            try:
                date = parsedate_to_datetime(headers["date"])
                if date.tzinfo is None:
                    date = date.replace(tzinfo=timezone.utc)
            except (ValueError, TypeError):
                logger.warning("Failed to parse Date header", extra={"message_id": message_id})

        body_text = self._extract_body(payload)
        body_html = self._extract_html_body(payload)
        attachments = self._extract_attachments(payload)

        return build_email_message(
            message_id=data.get("id", message_id),
            provider=self.name,
            sender=sender,
            recipients=recipients,
            subject=subject,
            body_text=body_text,
            body_html=body_html,
            date=date,
            thread_id=data.get("threadId"),
            labels=list(data.get("labelIds", []) or []),
            headers=headers,
            raw_metadata={
                "snippet": data.get("snippet", ""),
                "historyId": data.get("historyId"),
            },
            attachments=attachments,
        )

    def _extract_attachments(self, payload: dict[str, Any]) -> list:
        """Walk the MIME tree and surface text/calendar parts.

        Other content types are deliberately skipped — we don't load
        binary attachments into memory until something downstream
        actually needs them.
        """
        from email_triage.engine.models import Attachment
        from email_triage.engine.ics import parse_ics

        out: list = []

        def _walk(part: dict[str, Any]) -> None:
            mime = (part.get("mimeType") or "").lower()
            body = part.get("body") or {}
            inner_data = body.get("data", "")
            if mime.startswith("text/calendar"):
                blob = b""
                if inner_data:
                    decoded_str = _b64url_decode(inner_data)
                    if decoded_str is not None:
                        blob = decoded_str.encode("utf-8", errors="replace")
                parsed = parse_ics(blob) if blob else None
                filename = ""
                for hdr in part.get("headers", []) or []:
                    if (hdr.get("name") or "").lower() == "content-disposition":
                        # very loose filename grab
                        v = hdr.get("value", "")
                        if "filename=" in v:
                            filename = v.split("filename=", 1)[1].strip(' ";')
                            break
                out.append(Attachment(
                    filename=filename or "invite.ics",
                    content_type="text/calendar",
                    size_bytes=int(body.get("size") or len(blob)),
                    data=blob or None,
                    parsed=parsed,
                ))
                return
            for child in part.get("parts", []) or []:
                _walk(child)

        _walk(payload)
        return out

    def _extract_html_body(self, payload: dict[str, Any]) -> str:
        """Pull text/html body out of a Gmail payload structure."""
        body_data = (payload.get("body") or {}).get("data", "")
        mime_type = payload.get("mimeType", "")
        if body_data and mime_type == "text/html":
            decoded = _b64url_decode(body_data)
            if decoded is not None:
                return decoded

        for part in payload.get("parts", []) or []:
            if part.get("mimeType") == "text/html":
                part_data = (part.get("body") or {}).get("data", "")
                if part_data:
                    decoded = _b64url_decode(part_data)
                    if decoded is not None:
                        return decoded

        for part in payload.get("parts", []) or []:
            nested = self._extract_html_body(part)
            if nested:
                return nested

        return ""

    def _extract_body(self, payload: dict[str, Any]) -> str:
        """Pull text/plain body out of a Gmail payload structure."""
        body_data = (payload.get("body") or {}).get("data", "")
        mime_type = payload.get("mimeType", "")
        if body_data and mime_type.startswith("text/"):
            decoded = _b64url_decode(body_data)
            if decoded is not None:
                return decoded

        for part in payload.get("parts", []) or []:
            if part.get("mimeType") == "text/plain":
                part_data = (part.get("body") or {}).get("data", "")
                if part_data:
                    decoded = _b64url_decode(part_data)
                    if decoded is not None:
                        return decoded

        for part in payload.get("parts", []) or []:
            nested = self._extract_body(part)
            if nested:
                return nested

        return ""

    # ------------------------------------------------------------------
    # Labels / folders
    # ------------------------------------------------------------------

    async def list_labels(self) -> list[dict[str, str]]:
        data = await self._request("GET", "/users/me/labels")
        labels = (data or {}).get("labels", []) if isinstance(data, dict) else []
        out = [
            {"id": l.get("id", ""), "name": l.get("name", "")}
            for l in labels
            if isinstance(l, dict) and l.get("id")
        ]
        self._label_cache = {l["name"]: l["id"] for l in out}
        return out

    async def list_folders(self) -> list[str]:
        labels = await self.list_labels()
        return sorted({l["name"] for l in labels if l.get("name")})

    async def _resolve_label_id(self, name: str) -> str:
        """Look up a Gmail label id by name, caching the full list.

        Gmail preserves case on user-created labels, but route config often
        stores whatever the user typed (e.g. "newsletters" vs the real
        "Newsletters"). We try the exact match first (fast path), then fall
        back to a case-insensitive scan of the cache before giving up.
        """
        if self._label_cache is None:
            await self.list_labels()
        assert self._label_cache is not None
        lid = self._label_cache.get(name)
        if lid:
            return lid
        # Case-insensitive fallback for user-created labels.
        lower = name.lower()
        for cached_name, cached_id in self._label_cache.items():
            if cached_name.lower() == lower:
                return cached_id
        # Gmail built-ins are addressable by their name directly.
        if name.upper() in {
            "INBOX", "SENT", "DRAFT", "TRASH", "SPAM", "STARRED",
            "IMPORTANT", "UNREAD", "CHAT", "CATEGORY_PERSONAL",
            "CATEGORY_SOCIAL", "CATEGORY_UPDATES", "CATEGORY_FORUMS",
            "CATEGORY_PROMOTIONS",
        }:
            return name.upper()
        suggestions = difflib.get_close_matches(
            name, list(self._label_cache.keys()), n=3, cutoff=0.6,
        )
        msg = f"Label not found: {name}"
        if suggestions:
            msg += f". Did you mean: {', '.join(suggestions)}?"
        raise GmailApiError(404, msg)

    async def create_folder(self, folder: str) -> None:
        try:
            await self._request(
                "POST",
                "/users/me/labels",
                json_data={
                    "name": folder,
                    "labelListVisibility": "labelShow",
                    "messageListVisibility": "show",
                },
            )
        except GmailApiError as e:
            body_str = (
                json.dumps(e.body) if isinstance(e.body, dict) else str(e.body)
            ).lower()
            already = "already exists" in body_str or (
                "label" in body_str and "exists" in body_str
            )
            if e.status == 409 or already:
                # Label already present — don't touch the cache; a prior
                # list_labels() snapshot is still valid for this name.
                return
            raise
        # Fresh label minted. Null the cache so the next _resolve_label_id()
        # refetches from Gmail. Patch-inserting the returned id races with
        # concurrent writers; null-then-refetch is boring and correct.
        self._label_cache = None

    async def _resolve_or_create_label_id(self, name: str) -> str:
        """Resolve label id; if Gmail returns 404 (label missing),
        create it and retry. Built-ins are returned as-is by
        ``_resolve_label_id``, so the create path only fires for
        user-defined names like ``notifications`` / ``finance``.

        Mirrors the IMAP ``create_folder`` auto-heal pattern so the
        triage pipeline can introduce new categories without an
        operator pre-creating each label in the Gmail UI.

        Logs an INFO line on every successful auto-create so admins
        have audit visibility without opening the Gmail web UI.
        """
        try:
            return await self._resolve_label_id(name)
        except GmailApiError as e:
            if e.status != 404:
                raise
            await self.create_folder(name)
            # create_folder nulls _label_cache; retry resolve hits a
            # fresh list_labels and finds the just-minted id.
            label_id = await self._resolve_label_id(name)
            logger.info(
                "Auto-created Gmail label",
                extra={
                    "label": name,
                    "label_id": label_id,
                    "provider": "gmail_api",
                },
            )
            return label_id

    async def apply_label(self, message_id: str, label: str) -> None:
        label_id = await self._resolve_or_create_label_id(label)
        await self._request(
            "POST",
            f"/users/me/messages/{message_id}/modify",
            json_data={"addLabelIds": [label_id]},
        )

    async def archive(self, message_id: str) -> None:
        await self._request(
            "POST",
            f"/users/me/messages/{message_id}/modify",
            json_data={"removeLabelIds": ["INBOX"]},
        )

    async def move_message(self, message_id: str, folder: str) -> None:
        label_id = await self._resolve_or_create_label_id(folder)
        await self._request(
            "POST",
            f"/users/me/messages/{message_id}/modify",
            json_data={
                "addLabelIds": [label_id],
                "removeLabelIds": ["INBOX"],
            },
        )

    # ------------------------------------------------------------------
    # Drafts / inbox delivery
    # ------------------------------------------------------------------

    def _build_raw_message(
        self,
        to: list[str],
        subject: str,
        body: str,
        in_reply_to: str | None = None,
        extra_headers: dict[str, str] | None = None,
        *,
        from_addr: str | None = None,
        from_name: str | None = None,
        reply_to: str | None = None,
        subtype: str = "plain",
    ) -> str:
        """Build a base64url-encoded MIME message for the Gmail API.

        The default ``From:`` is ``self._account`` — correct for draft
        replies where the user is sending as themselves. Callers that
        generate SYSTEM mail (e.g. digests) pass ``from_addr`` +
        optional ``from_name`` so the recipient sees the triage
        identity rather than the Gmail mailbox owner's address.

        ``subtype`` controls the MIME shape:
        - ``"plain"`` (default) — single-part ``text/plain``; matches
          the typed-reply path where ``body`` is literal user prose
        - ``"html"`` — ``multipart/alternative`` with a crude text
          fallback derived from the HTML. Required for digest
          delivery; strict IMAP clients that honour Content-Type were
          hiding single-part-plain-with-HTML-inside messages (live-
          observed 2026-04-24).
        """
        msg = MIMEEmailMessage()
        msg["To"] = ", ".join(to)
        msg["Subject"] = subject
        if from_addr:
            # Build an RFC-5322 From value. Keep the quoting contained
            # here so callers don't need to import format_from_header.
            if from_name:
                safe = from_name.replace("\\", "\\\\").replace('"', '\\"')
                msg["From"] = f'"{safe}" <{from_addr}>'
            else:
                msg["From"] = from_addr
        elif self._account:
            msg["From"] = self._account
        if reply_to:
            msg["Reply-To"] = reply_to
        if in_reply_to:
            msg["In-Reply-To"] = in_reply_to
            msg["References"] = in_reply_to
        if extra_headers:
            for key, value in extra_headers.items():
                msg[key] = value

        if subtype == "html":
            # Build multipart/alternative: plain text fallback first,
            # then HTML. The first part is what clients fall back to
            # when they can't render HTML (accessibility readers,
            # plain-text-only clients, log scrapers).
            text_alt = _html_to_text_fallback(body)
            msg.set_content(text_alt, subtype="plain")
            msg.add_alternative(body, subtype="html")
        else:
            msg.set_content(body, subtype=subtype)

        return base64.urlsafe_b64encode(msg.as_bytes()).decode("ascii").rstrip("=")

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
        subtype: str = "plain",
    ) -> str:
        raw = self._build_raw_message(
            to, subject, body, in_reply_to, extra_headers,
            from_addr=from_addr, from_name=from_name, reply_to=reply_to,
            subtype=subtype,
        )
        payload: dict[str, Any] = {"message": {"raw": raw}}
        if thread_id:
            payload["message"]["threadId"] = thread_id
        data = await self._request("POST", "/users/me/drafts", json_data=payload)
        if isinstance(data, dict):
            return data.get("id", "")
        return ""

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
        subtype: str = "plain",
    ) -> str:
        raw = self._build_raw_message(
            to, subject, body, extra_headers=extra_headers,
            from_addr=from_addr, from_name=from_name, reply_to=reply_to,
            subtype=subtype,
        )
        # messages.insert with proper multipart/alternative MIME.
        # Earlier rounds: insert alone (Inbox web view showed, IMAP
        # clients hid — Content-Type was text/plain containing HTML).
        # Then switched to messages.import (runs spam + classifier) —
        # message still in All Mail only, because response was delayed
        # + user filters still ran. Root cause was the MIME shape all
        # along. With proper multipart/alternative (text + HTML),
        # insert is the right endpoint: bypasses classification, puts
        # message with INBOX label directly, and now IMAP clients
        # honour Content-Type correctly.
        data = await self._request(
            "POST",
            "/users/me/messages",
            json_data={"raw": raw, "labelIds": ["INBOX", "UNREAD"]},
        )
        # Capture what Gmail actually applied — `labelIds` in the
        # request is a RECOMMENDATION; Gmail's post-insert processing
        # (category auto-tagging, user filter rules, spam filter) can
        # add/remove labels freely. Logging the response labels tells
        # us WHERE the message actually ended up so diagnostic
        # "digest delivered but not in inbox" questions have a data
        # trail.
        if isinstance(data, dict):
            logger.info(
                "Gmail deliver_to_inbox response",
                extra={
                    "requested_labels": ["INBOX", "UNREAD"],
                    "applied_labels": data.get("labelIds") or [],
                    "message_id": data.get("id", ""),
                    "thread_id": data.get("threadId", ""),
                    "size_estimate": data.get("sizeEstimate"),
                },
            )
            return data.get("id", "")
        return ""

    # ------------------------------------------------------------------
    # Push (watch registration only; webhook handling lives elsewhere)
    # ------------------------------------------------------------------

    async def register_watch(self, topic: str) -> dict[str, Any]:
        data = await self._request(
            "POST",
            "/users/me/watch",
            json_data={"topicName": topic, "labelIds": ["INBOX"]},
        )
        if isinstance(data, dict):
            logger.info(
                "Gmail watch registered",
                extra={
                    "history_id": data.get("historyId"),
                    "expiration": data.get("expiration"),
                },
            )
            return data
        return {"raw": data}

    async def stop_watch(self) -> None:
        await self._request("POST", "/users/me/stop")

    async def get_profile(self) -> dict[str, Any]:
        """Return the Gmail profile for the authenticated user.

        Fields of interest: ``emailAddress`` and ``historyId`` — the
        history-poll loop (B3) uses the latter to bootstrap a cursor
        for poll-mode accounts that have never had a Pub/Sub watch
        registered.
        """
        data = await self._request("GET", "/users/me/profile")
        return data if isinstance(data, dict) else {}

    async def watch(self) -> AsyncIterator[str]:
        # Real-time delivery on Gmail is webhook-based (register_watch +
        # Pub/Sub) — there's no IDLE-style generator to consume. The
        # route layer should dispatch away from this path for Gmail
        # accounts; if something still reaches here, the WatcherManager
        # loop catches NotImplementedError and marks the watcher as
        # unsupported (no retry spam).
        raise NotImplementedError(
            "Real-time watch is not supported on this provider via the "
            "generator path."
        )
        yield ""  # pragma: no cover

    async def close(self) -> None:
        if self._http is not None:
            await self._http.aclose()
            self._http = None


# ---------------------------------------------------------------------------
# Authorization-code auth helpers (used by the accounts router).
#
# Why not device-code: Google removed Gmail (and most non-Drive/YouTube)
# scopes from the device-flow allowlist in 2022. The web-app
# authorization-code flow with a registered redirect URI is the only
# path that still works for `gmail.modify` etc. The OAuth client must
# be type "Web application" in the Google Cloud console, with the
# install's `<public_url>/oauth/google/callback` listed as an
# authorized redirect URI.
# ---------------------------------------------------------------------------

def build_auth_url(
    client_id: str,
    redirect_uri: str,
    state: str,
    scopes: list[str] | None = None,
    *,
    login_hint: str = "",
    prompt: str = "consent",
    access_type: str = "offline",
) -> str:
    """Build Google's OAuth 2.0 authorization-code URL.

    The browser navigates here; Google authenticates the user, asks
    for consent, then redirects back to ``redirect_uri`` with
    ``?code=...&state=...``.

    ``prompt=consent`` is set so Google always returns a refresh token
    (a re-auth without it returns access-token only). ``access_type=offline``
    is required to get a refresh token at all.
    """
    from urllib.parse import urlencode
    scopes = scopes or DEFAULT_SCOPES
    params: dict[str, str] = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": " ".join(scopes),
        "access_type": access_type,
        "prompt": prompt,
        "state": state,
        "include_granted_scopes": "true",
    }
    if login_hint:
        params["login_hint"] = login_hint
    return OAUTH_AUTH_URL + "?" + urlencode(params)


async def exchange_code_for_tokens(
    client_id: str,
    client_secret: str,
    code: str,
    redirect_uri: str,
    *,
    timeout: float = 30.0,
) -> dict[str, Any]:
    """Exchange an authorization code for access + refresh tokens.

    ``client_secret`` is required regardless of OAuth client type —
    Google's token endpoint rejects the exchange without it for both
    Web application and Desktop clients. (Earlier versions of this
    helper treated the secret as optional on the assumption that
    Desktop apps skipped it; that was wrong.)

    Raises :class:`GmailAuthError` with Google's error body on any
    non-2xx (typically ``invalid_grant`` if the code was reused or
    expired, or ``redirect_uri_mismatch`` if the GCP console doesn't
    list the URI we sent).
    """
    if not code:
        raise GmailAuthError(400, "missing authorization code")
    if not client_id:
        raise GmailAuthError(400, "client_id not configured")
    if not client_secret:
        raise GmailAuthError(400, "client_secret not configured")
    if not redirect_uri:
        raise GmailAuthError(400, "redirect_uri not configured")

    data: dict[str, str] = {
        "client_id": client_id,
        "client_secret": client_secret,
        "code": code,
        "redirect_uri": redirect_uri,
        "grant_type": "authorization_code",
    }

    async with httpx.AsyncClient(timeout=timeout) as client:
        resp = await client.post(OAUTH_TOKEN_URL, data=data)
    try:
        payload = resp.json()
    except Exception:
        payload = resp.text
    if resp.status_code >= 400:
        raise GmailAuthError(resp.status_code, payload, OAUTH_TOKEN_URL)
    return payload if isinstance(payload, dict) else {}


def extract_code_from_pasted(text: str) -> tuple[str, str]:
    """Pull ``code`` and ``state`` out of a manual-flow paste.

    Accepts either a raw code or a full redirect URL (the loopback
    URL the user's browser tried and failed to load). Tolerant of
    leading/trailing whitespace and either ``http://127.0.0.1:.../?code=...``
    or just ``code=...&state=...`` fragments. Returns ``("", "")`` if
    nothing recognisable is found.
    """
    from urllib.parse import urlparse, parse_qs
    s = (text or "").strip()
    if not s:
        return "", ""
    # If the user pasted a URL, parse the query.
    if "://" in s or s.startswith("?") or s.startswith("/"):
        parsed = urlparse(s)
        qs = parse_qs(parsed.query) if parsed.query else parse_qs(s.lstrip("?"))
        code = (qs.get("code") or [""])[0]
        state = (qs.get("state") or [""])[0]
        return code, state
    # If it looks like a query-string fragment without the prefix.
    if "code=" in s:
        qs = parse_qs(s)
        return (qs.get("code") or [""])[0], (qs.get("state") or [""])[0]
    # Otherwise treat the whole thing as the raw code.
    return s, ""


def _b64url_decode(data: str) -> str | None:
    """Decode a Gmail base64url body part to UTF-8 text, tolerating padding."""
    if not data:
        return None
    padded = data + "=" * ((4 - len(data) % 4) % 4)
    try:
        raw = base64.urlsafe_b64decode(padded)
    except Exception:
        return None
    return raw.decode("utf-8", errors="replace")
