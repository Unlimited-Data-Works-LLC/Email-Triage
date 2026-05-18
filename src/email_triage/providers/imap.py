"""IMAP email provider with async support and IDLE push.

Uses ``aioimaplib`` for async IMAP operations.  Install with::

    pip install email-triage[imap]

Supports:
- Search via IMAP SEARCH command
- Fetch message content and parse headers/body
- Move messages between folders (via COPY + flag)
- Set flags (\\Seen, \\Flagged)
- IMAP IDLE for real-time push notifications

Works with any IMAP server (Dovecot, Exchange, Gmail IMAP, etc.).
"""

from __future__ import annotations

import asyncio
import collections
import email
import email.policy
import email.utils
import time
from datetime import datetime, timezone
from typing import Any, AsyncIterator

from email_triage.engine.models import EmailMessage
from email_triage.providers.base import EmailProvider, PushCapable
from email_triage.triage_logging import get_logger
from email_triage._errfmt import fmt_exc

log = get_logger("providers.imap")


def _seen_uids_remember(
    uid: str,
    seen_q: "collections.deque[str]",
    seen_set: "set[str]",
) -> None:
    """Append ``uid`` to a bounded-FIFO seen-tracker pair.

    #143 — the original IDLE seen-tracker was a single ``set`` pruned
    via ``set(list(seen)[-500:])``. ``set`` has no insertion order, so
    the slice picked an arbitrary subset, not the most recent. After
    a prune the dropped-but-still-recent UIDs would re-yield as
    "new" — silent duplicate triage runs.

    The replacement is two structures kept in lockstep: a bounded
    ``deque`` whose ``maxlen`` enforces FIFO eviction of the oldest
    UID when capacity is hit, and a parallel ``set`` for O(1)
    membership tests in the hot loop. ``_seen_uids_remember`` is the
    single mutation path — it handles the "deque is full + new uid"
    case by manually evicting the front entry from BOTH structures
    before the append, otherwise the set would drift behind the deque
    after each natural deque overflow.

    Module-level for the test suite (the per-watch deque + set live
    inside :meth:`IMAPProvider.watch`'s closure; the helper is the
    seam).
    """
    # Already-known UID: nothing to do (the caller already gated on
    # ``uid not in seen_set`` before getting here, but defence-in-
    # depth keeps the helper safe to call from new test sites).
    if uid in seen_set:
        return
    if len(seen_q) == seen_q.maxlen:
        evicted = seen_q[0]
        seen_set.discard(evicted)
    seen_q.append(uid)
    seen_set.add(uid)


def _fmt_imap_response(data: Any) -> str:
    """Render aioimaplib response payload as a readable string.

    aioimaplib returns response data as ``list[bytes | str]`` (or
    sometimes a single bytes value). The tagged response carries the
    server's actual reason for a NO/BAD result — discarding it loses
    the diagnostic. Surface it on the error path so an operator can
    distinguish "ALREADYEXISTS" from "permission denied" from
    "invalid mailbox name" without enabling debug-level IMAP traces.
    """
    if data is None:
        return ""
    items: list[str] = []
    if isinstance(data, (list, tuple)):
        for item in data:
            if isinstance(item, bytes):
                items.append(item.decode(errors="replace"))
            elif item is None:
                continue
            else:
                items.append(str(item))
    elif isinstance(data, bytes):
        items.append(data.decode(errors="replace"))
    else:
        items.append(str(data))
    # Trim whitespace and drop empties; cap total length so a chatty
    # server can't blow the log row.
    joined = " | ".join(s.strip() for s in items if s and s.strip())
    return joined[:400]


# Guard the import — aioimaplib is optional.
try:
    import aioimaplib
    HAS_AIOIMAPLIB = True
    # Apply the upstream-bug parser patch before ANY IMAP4ClientProtocol
    # instance is created in the process. See _aioimaplib_patch.py for
    # rationale (upstream issue #118: large-response recursion).
    from email_triage.providers import _aioimaplib_patch  # noqa: F401
except ImportError:
    HAS_AIOIMAPLIB = False


# ---------------------------------------------------------------------------
# #147 — IMAP connection-state diagnostics + pre-flight auth check
# ---------------------------------------------------------------------------

class IMAPClientLogoutError(RuntimeError):
    """Raised when a SELECT-issuing path discovers the client is in
    LOGOUT state — the caller can no longer recover by re-LOGIN, the
    socket is gone. Caller is expected to drop the cached client and
    let the next provider call open a fresh transport.

    Distinct from ``aioimaplib.Abort`` so the digest path can
    distinguish "transient reconnect" from "we tried to re-LOGIN and
    the underlying transport said no."
    """


def _capture_imap_state(client: Any) -> dict[str, Any]:
    """Snapshot the IMAP client's connection state for an error log.

    Used on every IMAP error path that touches SELECT so the
    next #147-shaped occurrence is diagnosable without enabling
    debug-level traces. Returns a dict suitable for splatting as
    ``**_capture_imap_state(client)`` into a structured ``log.error``
    call.

    Fields:

    * ``auth_state`` — the protocol's current state (``NONAUTH`` /
      ``AUTH`` / ``SELECTED`` / ``LOGOUT``). The headline diagnostic
      for the SELECT-illegal-in-state-NONAUTH class of error.
    * ``age_secs`` — how long the cached client instance has been
      alive (rounded to integer). Stale connections that survived
      a server-side IDLE timeout are the prime suspect.
    * ``capabilities`` — server-advertised capability list, comma-
      joined. Surfaces which auth mechanisms / extensions the server
      offered; empty when the connection never reached the AUTH
      banner. Truncated to 200 chars.
    * ``has_pending_idle`` — best-effort read; tells us whether the
      protocol thought it was mid-IDLE when the error fired.

    The helper never raises — every accessor is wrapped so
    diagnostic capture can't itself become a new error path.
    """
    out: dict[str, Any] = {
        "auth_state": "unknown",
        "age_secs": -1,
        "capabilities": "",
        "has_pending_idle": "unknown",
    }
    if client is None:
        return out

    try:
        # aioimaplib 2.x: ``IMAP4.get_state()`` reads ``protocol.state``.
        state = getattr(client, "get_state", None)
        if callable(state):
            out["auth_state"] = str(state())
        else:
            proto = getattr(client, "protocol", None)
            if proto is not None:
                out["auth_state"] = str(getattr(proto, "state", "unknown"))
    except Exception:
        pass

    try:
        born = getattr(client, "_et_connect_ts", None)
        if born is not None:
            out["age_secs"] = int(time.monotonic() - float(born))
    except Exception:
        pass

    try:
        proto = getattr(client, "protocol", None)
        caps = getattr(proto, "capabilities", None) if proto else None
        if caps:
            joined = ",".join(str(c) for c in caps)
            out["capabilities"] = joined[:200]
    except Exception:
        pass

    try:
        pending = getattr(client, "has_pending_idle", None)
        if callable(pending):
            out["has_pending_idle"] = bool(pending())
    except Exception:
        pass

    return out


async def _ensure_authenticated(client: Any) -> str:
    """Pre-flight authentication check before any SELECT-bearing op.

    Returns the protocol state observed AFTER any recovery action
    so the caller can log the resolved state.

    Behaviour by current state:

    * ``AUTH`` / ``SELECTED`` — no-op, returns the state.
    * ``NONAUTH`` — raise :class:`aioimaplib.Abort`. The caller (a
      provider method) doesn't have the password handy here at the
      module-scope helper; the *provider instance* knows how to
      re-LOGIN. ``ImapProvider._ensure_authenticated`` (the bound
      wrapper, defined below) does the actual re-LOGIN and delegates
      to this module-level helper for the state-only path used by
      tests + non-instance callers. Most call sites should use the
      bound version.
    * ``LOGOUT`` — raise :class:`IMAPClientLogoutError`. The caller
      MUST drop the cached client; re-LOGIN on a closed transport
      will not recover.

    The intentional split (module-level reads state + raises;
    instance method does re-LOGIN) keeps the helper testable
    without a real provider instance, which matches how the rest
    of this file's helpers are structured (``_seen_uids_remember``,
    ``_fmt_imap_response``).
    """
    if client is None:
        # Fresh client — caller's :meth:`_connect` will create + login.
        # Nothing to validate.
        return "AUTH"

    try:
        state = client.get_state()
    except Exception:
        # If we can't even read the state, treat as broken — the caller
        # will recover by dropping the client.
        raise IMAPClientLogoutError(
            "IMAP client state unreadable — client likely disconnected"
        )

    if state in ("AUTH", "SELECTED"):
        return state
    if state == "LOGOUT":
        raise IMAPClientLogoutError(
            f"IMAP client in LOGOUT state — caller must reconnect "
            f"(state={state})"
        )
    # NONAUTH (or any other unknown state we shouldn't SELECT in):
    # surface as Abort. The bound :meth:`ImapProvider._ensure_authenticated`
    # catches this and tries re-LOGIN; module-level callers that don't
    # have credentials raise out to their own reconnect path.
    raise aioimaplib.Abort(
        f"IMAP client in {state} state — re-LOGIN required before SELECT"
    )


class ImapProvider(EmailProvider, PushCapable):
    """IMAP provider using aioimaplib for async operations.

    Parameters:
        host: IMAP server hostname
        port: IMAP server port (993 for IMAPS, 143 for IMAP)
        username: IMAP login username
        password: IMAP login password
        use_ssl: Whether to use SSL/TLS (default True for port 993)
        mailbox: Mailbox to operate on (default "INBOX")
        idle_timeout: Seconds before IDLE refresh (default 1680 = 28 min,
                      RFC 2177 recommends < 29 min)
    """

    def __init__(
        self,
        host: str,
        port: int = 993,
        username: str = "",
        password: str = "",
        use_ssl: bool = True,
        mailbox: str = "INBOX",
        idle_timeout: int = 1680,
        email_address: str = "",
        drafts_folder: str = "",
    ):
        if not HAS_AIOIMAPLIB:
            raise ImportError(
                "aioimaplib is required for the IMAP provider. "
                "Install with: pip install email-triage[imap]"
            )
        self._host = host
        self._port = port
        self._username = username
        self._password = password
        self._use_ssl = use_ssl
        self._mailbox = mailbox
        self._idle_timeout = idle_timeout
        # 2026-05-13 — separate "Your email address" field
        # (config["email_address"]; falls back to username for
        # legacy accounts whose IMAP LOGIN already includes the
        # @domain). Used as the default From: in create_draft so
        # drafts don't ship with the bare LOGIN username
        # (``user``) as the From header.
        self._email_address = email_address
        # 2026-05-13 — operator override for the Drafts folder name.
        # When non-empty, create_draft APPENDs straight to this folder
        # and skips the SPECIAL-USE / name-match discovery. Falls back
        # to the discovery + "INBOX.Drafts" default when empty.
        # Needed for servers whose Drafts folder isn't named in the
        # canonical SPECIAL-USE or name-variant lists (or where the
        # operator just wants to pin a different target).
        self._drafts_folder = drafts_folder
        self._client: Any = None

    @property
    def name(self) -> str:
        return "imap"

    async def _connect(self) -> Any:
        """Connect and authenticate if not already connected."""
        if self._client is not None:
            return self._client

        if self._use_ssl:
            self._client = aioimaplib.IMAP4_SSL(
                host=self._host,
                port=self._port,
            )
        else:
            self._client = aioimaplib.IMAP4(
                host=self._host,
                port=self._port,
            )

        await self._client.wait_hello_from_server()
        await self._client.login(self._username, self._password)
        # Stamp the client with its birth-time so ``_capture_imap_state``
        # can report connection age on the next #147-shaped error. The
        # custom attribute is namespaced (``_et_*``) to avoid colliding
        # with anything aioimaplib might add in a future release.
        try:
            self._client._et_connect_ts = time.monotonic()
        except Exception:
            pass
        # aioimaplib's select() forwards the mailbox name to the server
        # as-is — it does NOT quote names containing spaces / non-atom
        # chars. A Dovecot install with mailboxes like "Sent Items"
        # parses ``SELECT Sent Items`` as ``SELECT Sent`` (whitespace
        # splits IMAP atoms) — the trailing ``Items`` is consumed as a
        # second argument and silently dropped. Quote here per RFC 3501
        # § 4.3 (string syntax). Bug surfaced 2026-05-13 on an operator
        # whose IMAP server had both ``Sent`` AND ``Sent Items`` — the
        # mis-SELECT returned UIDs from the wrong folder, downstream
        # fetches against the correctly-quoted name found nothing.
        await self._client.select(self._quote_mailbox(self._mailbox))
        log.info("IMAP connected", host=self._host, mailbox=self._mailbox)
        return self._client

    async def _ensure_authenticated(self) -> str:
        """Bound wrapper around the module-level ``_ensure_authenticated``.

        #147 — Wired into the digest path (``fetch_messages_in_folder``
        equivalent: :meth:`select_folder` + :meth:`search` + the
        in-folder fetch sequence) before each IMAP operation that
        issues a SELECT. The triage runner has its own reconnect
        surface — this is the digest-only pre-flight.

        Behaviour by current state:

        * ``AUTH`` / ``SELECTED`` — no-op, returns state.
        * ``NONAUTH`` — re-LOGIN with the provider's stored credentials.
          We don't reset the client first because the underlying
          transport is fine; only the protocol's auth state has
          drifted. After re-LOGIN the caller can SELECT normally.
        * ``LOGOUT`` — raise :class:`IMAPClientLogoutError` so the
          caller drops the cached client and the next provider call
          opens a fresh transport via :meth:`_connect`.

        Returns the resolved state (post-recovery) so callers can
        include it in success-path log lines.
        """
        client = self._client
        if client is None:
            # Fresh provider — let the caller's :meth:`_connect` open
            # a new connection. Nothing to validate.
            return "AUTH"

        try:
            return await _ensure_authenticated(client)
        except aioimaplib.Abort:
            # NONAUTH path — replay LOGIN on the existing transport.
            log.warning(
                "IMAP client in NONAUTH; re-LOGIN before next operation",
                **_capture_imap_state(client),
            )
            try:
                await client.login(self._username, self._password)
            except Exception as e:
                # Re-LOGIN failed: the connection is unusable. Reset
                # the cached client so the next call opens fresh.
                log.warning(
                    "IMAP re-LOGIN failed; dropping cached client",
                    error=fmt_exc(e), **_capture_imap_state(client),
                )
                await self._reset_client_after_parser_error()
                raise IMAPClientLogoutError(
                    f"IMAP re-LOGIN failed: {e}"
                ) from e
            # Verify state actually transitioned.
            try:
                state = client.get_state()
            except Exception:
                state = "unknown"
            if state not in ("AUTH", "SELECTED"):
                # LOGIN said OK but state didn't move — bail.
                await self._reset_client_after_parser_error()
                raise IMAPClientLogoutError(
                    f"IMAP re-LOGIN returned OK but state={state}"
                )
            log.info("IMAP re-LOGIN succeeded", auth_state=state)
            return state

    async def _reset_client_after_parser_error(self) -> None:
        """Force-close the current client + null it.

        Called when an upstream aioimaplib parser-state corruption is
        detected (Abort or CommandTimeout — see ``fetch_message`` for
        the full chain). The next provider call hits :meth:`_connect`
        which opens a fresh socket. Without this, every subsequent
        operation on the dead socket times out, turning one bad fetch
        into N cascading errors across the whole bulk run.
        """
        client = self._client
        self._client = None
        if client is None:
            return
        # Best-effort close — the socket is already in an unknown
        # state; we just want to ensure the transport is torn down so
        # the IDLE / poll loop doesn't keep receiving on it.
        try:
            await client.logout()
        except Exception:
            pass
        try:
            transport = getattr(getattr(client, "protocol", None), "transport", None)
            if transport is not None:
                transport.close()
        except Exception:
            pass

    async def search(
        self,
        query: str = "",
        limit: int = 50,
        *,
        filter=None,  # MailFilter | None
    ) -> list[str]:
        """Search for message UIDs using IMAP SEARCH.

        Either pass raw IMAP search criteria via ``query`` or a
        structured :class:`MailFilter` via ``filter``. Structured
        filter wins when both are present. ``filter.folder`` switches
        the selected mailbox before searching, then restores the
        configured one.

        ``filter.folder == "*"`` (or ``"ALL"``) is a wildcard: search
        every mailbox the account can list, then merge the matches.
        Useful for cross-folder lookups like the backup-status agent
        that hunts for sender-keyed messages regardless of which
        category folder triage may have moved them into. The bulk
        endpoints accept this via ``?folder=*`` and dispatch to
        :meth:`search_all_folders` instead, which returns
        ``(folder, uid)`` tuples — UIDs are mailbox-scoped per RFC
        3501 so plain UIDs aren't enough across folders. This
        method's wildcard branch flattens that to UID-only for
        compatibility with single-folder callers; if you need the
        folder back (e.g. to fetch with the correct mailbox), call
        :meth:`search_all_folders` directly.

        #147 — Pre-flight :meth:`_ensure_authenticated` covers both
        the explicit ``filter.folder`` SELECT branch below AND the
        no-folder-switch path (whose underlying SEARCH still requires
        AUTH/SELECTED state). A stale connection that drifted to
        NONAUTH between the constructor's :meth:`_connect` and the
        digest scheduler firing N minutes later would have surfaced
        as ``command SELECT illegal in state NONAUTH`` (or, on the
        no-switch branch, ``command SEARCH illegal in state ...``).
        """
        client = await self._connect()
        try:
            await self._ensure_authenticated()
        except IMAPClientLogoutError:
            client = await self._connect()

        folder = getattr(filter, "folder", None) if filter is not None else None
        if folder in ("*", "ALL"):
            pairs = await self.search_all_folders(query, limit, filter=filter)
            return [uid for _folder, uid in pairs]

        if filter is not None and folder and folder != self._mailbox:
            try:
                # Quote mailbox names with spaces / non-atom chars —
                # aioimaplib doesn't auto-quote. See _connect() for the
                # 2026-05-13 root-cause writeup.
                await client.select(self._quote_mailbox(folder))
            except aioimaplib.Abort as e:
                log.error(
                    "IMAP SELECT aborted in search()",
                    folder=folder, error=str(e),
                    **_capture_imap_state(client),
                )
                raise
            try:
                return await self._search_in_current_mailbox(
                    client, query, limit, filter,
                )
            finally:
                # Restore the configured default mailbox so subsequent
                # calls in this connection don't drift.
                try:
                    await client.select(self._quote_mailbox(self._mailbox))
                except Exception:
                    pass

        return await self._search_in_current_mailbox(client, query, limit, filter)

    async def search_iter(
        self,
        query: str,
        *,
        batch_size: int = 500,
        resume_cursor: str | None = None,
    ):
        """Yield ``(batch, cursor)`` tuples by running SEARCH then
        chunking the result in ascending UID order.

        IMAP has no native pagination — RFC 3501 SEARCH returns
        every matching UID in a single response. For whole-mailbox
        triage (#101) the runner wants those UIDs in operator-
        controllable chunks (so per-batch progress + cancel checks
        work), not as one giant list.

        Order is ascending by UID. UIDs are monotonically assigned
        by the IMAP server (RFC 3501 § 2.3.1.1: "messages SHOULD be
        assigned UIDs in strictly ascending order in the mailbox"),
        so the highest UID seen so far is a valid resume
        high-water-mark. After each batch, the second tuple value
        is the max UID in that batch — the runner persists this as
        the cursor.

        Resume support: when ``resume_cursor`` is set, the SEARCH
        is constrained to ``UID <cursor+1>:* <criteria>`` so already-
        processed UIDs aren't re-walked. New mail arriving during
        the run gets UIDs strictly greater than any previously
        assigned UID, so a SEARCH re-issued with the latest cursor
        picks them up alongside the not-yet-walked tail of the
        original snapshot.

        Memory cost is one Python list of UID strings per call —
        ~30 bytes/UID, so a 100k-message mailbox = ~3 MB transient.
        Acceptable for the single-shot read; the runner consumes
        each batch fully before the next yield so the per-batch
        downstream state doesn't accumulate.

        ``filter`` keyword is intentionally absent — bulk-triage
        passes its query as a raw IMAP-syntax string. The filter
        path through MailFilter is for the structured/typed callers
        (digest builder, etc.); whole-mailbox triage operates on
        operator-typed criteria.
        """
        EFFECTIVELY_ALL = 10 ** 9

        # Splice the cursor constraint into the IMAP query when
        # present. RFC 3501 SEARCH supports ``UID <range>`` as a
        # criterion that AND-combines with everything else.
        effective_query = query.strip() if query else ""
        if resume_cursor:
            try:
                cursor_uid = int(str(resume_cursor).strip())
                cursor_clause = f"UID {cursor_uid + 1}:*"
                effective_query = (
                    f"{cursor_clause} {effective_query}".strip()
                )
            except (TypeError, ValueError):
                # Bad cursor — fall through to a fresh walk; the
                # dedup table will catch already-processed UIDs.
                pass

        client = await self._connect()
        all_uids = await self._search_in_current_mailbox(
            client, effective_query, EFFECTIVELY_ALL, filter=None,
        )
        if not all_uids:
            return

        # Sort ascending so each batch's max-UID is monotonically
        # increasing across the run. The helper returns reversed
        # order (most-recent-first); resort here.
        try:
            all_uids_sorted = sorted(all_uids, key=lambda u: int(u))
        except (TypeError, ValueError):
            # Defensive — shouldn't fire in practice (UIDs are ints).
            all_uids_sorted = list(all_uids)

        chunk = max(1, int(batch_size))
        for i in range(0, len(all_uids_sorted), chunk):
            batch = all_uids_sorted[i:i + chunk]
            # Cursor after this batch = max UID in batch (last
            # element since the list is sorted ascending).
            new_cursor = batch[-1] if batch else None
            yield batch, new_cursor

    async def search_all_folders(
        self,
        query: str = "",
        limit: int = 50,
        *,
        filter=None,  # MailFilter | None
    ) -> list[tuple[str, str]]:
        """Cross-folder variant of :meth:`search`.

        Routes through the **stdlib-imaplib** blocking backend
        (``providers/imap_blocking``) for the same reason
        :meth:`fetch_message` does — aioimaplib's parser defects
        affect SEARCH responses across folder hierarchies (BAD
        replies cascading from a single connection's state drift
        after LIST + per-folder SELECT). stdlib imaplib doesn't try
        to parse FETCH-shaped responses, so the parens-counting and
        recursion bugs (upstream issue #118) don't apply.

        Returns ``[(folder, uid), ...]`` capped at ``limit``. UIDs
        are scoped per mailbox in IMAP (RFC 3501 § 2.3.1.1) so the
        folder name MUST ride along with each UID — callers need it
        to SELECT the right mailbox before fetching.

        Skipped mailboxes (per the blocking backend):
        - ``\\Noselect`` parents (LIST entries that aren't real
          mailboxes).
        - Per-folder errors (auth, encoding mismatches, lazy-expunge
          mid-scan) are silently skipped — partial coverage beats a
          single bad folder blowing up the whole bulk call.
        """
        # Strip folder out of the filter — the cross-folder backend
        # drives the mailbox switch from its loop; the filter only
        # carries the rest of the criteria (sender, subject, date,
        # etc.). Translation to RFC 3501 SEARCH criteria reuses the
        # provider's own translator so behaviour matches the
        # single-folder path.
        per_folder_filter = filter
        if filter is not None and getattr(filter, "folder", None):
            try:
                from copy import copy as _copy
                per_folder_filter = _copy(filter)
                per_folder_filter.folder = None  # type: ignore[attr-defined]
            except Exception:
                per_folder_filter = filter  # tolerate frozen dataclass

        if per_folder_filter is not None:
            criteria = self._translate_filter(per_folder_filter)
        else:
            criteria = self._translate_query(query)
        if not criteria:
            criteria = "ALL"

        from email_triage.providers.imap_blocking import (
            search_all_folders_blocking,
        )
        try:
            return await search_all_folders_blocking(
                host=self._host,
                port=self._port,
                use_ssl=self._use_ssl,
                username=self._username,
                password=self._password,
                criteria=criteria,
                limit=limit,
            )
        except Exception as e:
            log.warning(
                "IMAP cross-folder search failed; falling back to "
                "default mailbox only",
                error=fmt_exc(e),
            )
            uids = await self._search_in_current_mailbox(
                await self._connect(), query, limit, per_folder_filter,
            )
            return [(self._mailbox, u) for u in uids]

    async def _search_in_current_mailbox(
        self, client, query: str, limit: int, filter,
    ) -> list[str]:
        # Translate the query / filter to IMAP search criteria.
        if filter is not None:
            imap_query = self._translate_filter(filter)
        else:
            imap_query = self._translate_query(query)
        if not imap_query:
            imap_query = "ALL"

        # Use SEARCH (returns sequence numbers) then FETCH UIDs.
        # aioimaplib 2.0 restricts uid() to COPY/FETCH/STORE/EXPUNGE,
        # so we can't do uid("search", ...).
        result, data = await client.search(imap_query)
        if result != "OK":
            log.warning("IMAP search failed", result=result)
            return []

        # Parse sequence numbers from SEARCH response.
        # aioimaplib 2.0 includes status lines like "Search completed ..."
        # in the response data — only keep numeric tokens.
        seq_nums = []
        for line in data:
            if isinstance(line, bytes):
                line = line.decode()
            for token in line.strip().split():
                if token.isdigit():
                    seq_nums.append(token)

        if not seq_nums:
            return []

        # Fetch UIDs for the sequence numbers (most recent first).
        seq_nums.reverse()
        seq_nums = seq_nums[:limit]

        # Batch fetch UIDs for all matching sequence numbers.
        seq_set = ",".join(seq_nums)
        result, uid_data = await client.fetch(seq_set, "(UID)")
        if result != "OK":
            log.warning("IMAP FETCH UIDs failed", result=result)
            return []

        # Parse UIDs from FETCH response lines like "1 FETCH (UID 12345)".
        import re
        uids = []
        for line in uid_data:
            if isinstance(line, bytes):
                line = line.decode(errors="replace")
            if "UID" in line:
                match = re.search(r"UID\s+(\d+)", line)
                if match:
                    uids.append(match.group(1))

        return uids

    @staticmethod
    def _translate_query(query: str) -> str:
        """Translate common query shortcuts to IMAP SEARCH syntax.

        Delegates to :func:`engine.query_lang.translate_imap_query_to_imap`
        (#138.3).
        """
        from email_triage.engine.query_lang import translate_imap_query_to_imap
        return translate_imap_query_to_imap(query)

    @staticmethod
    def _translate_filter(filt) -> str:
        """MailFilter → RFC 3501 IMAP SEARCH criteria.

        Delegates to :func:`engine.query_lang.emit_imap_filter` (#138.3).
        ``folder`` is handled by the caller (it switches mailboxes
        before issuing SEARCH).
        """
        from email_triage.engine.query_lang import emit_imap_filter
        return emit_imap_filter(filt)

    async def fetch_message(
        self,
        message_id: str,
        *,
        headers_only: bool = False,
        folder: str | None = None,
    ) -> EmailMessage:
        """Fetch a message by UID and parse it into EmailMessage.

        **Routes through the stdlib-imaplib blocking backend**
        (:mod:`providers.imap_blocking`) running in
        ``asyncio.to_thread``. This is Layer 3 of the aioimaplib
        bug mitigation (full rationale in
        ``memory/bug_aioimaplib_recursion.md``): aioimaplib's
        ``FetchCommand.wait_data()`` counts parens across the
        entire literal payload, so a body / header literal with
        unbalanced parens (HTML, MIME signatures, free-form
        Subject lines per RFC 5322 § 3.2.4) corrupts the parser
        state and cascades into ``CommandTimeout`` for any
        in-flight bulk gather on the same connection. Stdlib
        ``imaplib`` doesn't have this defect — it streams bytes
        directly into the consumer without trying to parse FETCH
        response structure. We pay one TLS-handshake-and-LOGIN
        per fetch (~50-200ms) for not having to fight the broken
        parser.

        aioimaplib still owns IDLE (long-poll, no fetch literals)
        and SEARCH (no literal payload) — the rest of this
        provider is unchanged.

        ``headers_only`` (default False) sends BODY.PEEK[HEADER]
        instead of BODY.PEEK[]. Body / link / attachment fields
        are left empty when True.

        Path C: a single retry on
        :class:`aioimaplib.Abort` /
        :class:`aioimaplib.CommandTimeout` covers the rare
        residual case where even the stdlib path hiccups
        (network blip, mid-fetch IDLE interleave on a sibling
        connection). Second failure surfaces to the caller.
        """
        from email_triage.providers.imap_blocking import (
            fetch_message_blocking,
        )

        # ``folder`` overrides the default mailbox for this fetch only —
        # used by the cross-folder search path so a UID found in
        # "Archive.2024" is fetched against that mailbox, not INBOX.
        # UIDs are mailbox-scoped per RFC 3501 § 2.3.1.1.
        target_mailbox = folder or self._mailbox

        async def _fetch_via_stdlib() -> tuple[bytes, list[str]]:
            return await fetch_message_blocking(
                host=self._host,
                port=self._port,
                use_ssl=self._use_ssl,
                username=self._username,
                password=self._password,
                mailbox=target_mailbox,
                uid=message_id,
                headers_only=headers_only,
            )

        try:
            raw_bytes, labels = await _fetch_via_stdlib()
        except (aioimaplib.Abort, aioimaplib.CommandTimeout) as e:
            # Path C: retry once on a fresh stdlib connection.
            log.warning(
                "IMAP stdlib fetch hit aioimaplib-shaped error — "
                "retrying once on a fresh connection",
                message_id=message_id, error=fmt_exc(e),
            )
            await self._reset_client_after_parser_error()
            raw_bytes, labels = await _fetch_via_stdlib()

        msg = email.message_from_bytes(raw_bytes, policy=email.policy.default)

        sender = msg.get("From", "")
        to_header = msg.get("To", "")
        recipients = [addr.strip() for addr in to_header.split(",") if addr.strip()]
        subject = msg.get("Subject", "")
        date = self._parse_date(msg.get("Date", ""))

        if headers_only:
            body_text = ""
            body_html = ""
            attachments: list = []
        else:
            body_text = self._extract_body(msg)
            body_html = self._extract_html_body(msg)
            attachments = self._extract_attachments(msg)
            # Diagnostic 2026-05-13: operator hit the style-mine
            # "No usable sent messages" symptom with seen=50 +
            # empty_body_text=50, meaning BOTH _extract_body and
            # _extract_html_body return "" for every fetched
            # Sent item. Surface the message's actual MIME shape
            # + raw_bytes length on every empty-body fetch so we
            # can tell whether (a) raw_bytes is short / empty
            # (FETCH didn't return the body), (b) walk() finds
            # zero content-typed parts, or (c) text/plain +
            # text/html parts exist but `decode=True` returns
            # None. Logs the first 200 chars of raw_bytes
            # (header-only sniff, no PHI risk on the
            # operator-side install).
            if not body_text and not body_html:
                parts_shape: list[str] = []
                for part in msg.walk():
                    parts_shape.append(part.get_content_type() or "<?>")
                log.warning(
                    "IMAP fetch: both body_text + body_html empty",
                    uid=message_id,
                    raw_bytes_len=len(raw_bytes),
                    parts=parts_shape,
                    is_multipart=msg.is_multipart(),
                    top_content_type=msg.get_content_type() or "<?>",
                    raw_head=raw_bytes[:200].decode(
                        "utf-8", errors="replace",
                    ),
                )

        # Preserve all wire headers so downstream consumers can read
        # things like X-Email-Triage (loop-prevention skip), List-Id,
        # Auto-Submitted, etc. Stdlib's email.message.Message.items()
        # returns (name, value) pairs; collapse duplicates to the last
        # occurrence (rare in practice, and downstream uses case-
        # insensitive lookup which doesn't care about order).
        headers = {name: value for name, value in msg.items()}

        # Final assembly — link extraction handled by the shared helper
        # (#145.8) so it's not duplicated across the three providers.
        from email_triage.providers._normalize import build_email_message
        return build_email_message(
            message_id=message_id,
            provider="imap",
            sender=sender,
            recipients=recipients,
            subject=subject,
            body_text=body_text,
            body_html=body_html,
            date=date,
            labels=labels,
            attachments=attachments,
            headers=headers,
        )

    @staticmethod
    def _extract_attachments(msg) -> list:
        """Walk the email's MIME tree and surface text/calendar parts.

        Other attachments are listed as metadata only — we don't load
        binary blobs into memory until something downstream needs them.
        """
        from email_triage.engine.models import Attachment
        from email_triage.engine.ics import parse_ics

        out: list = []
        for part in msg.walk():
            content_type = (part.get_content_type() or "").lower()
            if not content_type.startswith("text/calendar"):
                continue
            try:
                blob = part.get_payload(decode=True) or b""
            except Exception:
                blob = b""
            parsed = parse_ics(blob) if blob else None
            out.append(Attachment(
                filename=part.get_filename() or "invite.ics",
                content_type="text/calendar",
                size_bytes=len(blob),
                data=blob or None,
                parsed=parsed,
            ))
        return out

    @staticmethod
    def _extract_message_bytes(data: list) -> bytes:
        """Extract the raw message bytes from IMAP FETCH response.

        aioimaplib 2.0 returns flat list items rather than nested tuples:
          [0] b'1771 FETCH (UID 82257 FLAGS (\\Seen) BODY[] {71390}'
          [1] bytearray(b'Return-Path: ...')   ← the actual message
          [2] b')'
          [3] b'Fetch completed ...'
        """
        # aioimaplib 2.0: look for the bytearray (the message body).
        for item in data:
            if isinstance(item, bytearray):
                return bytes(item)
        # Legacy format: nested tuple (header, body).
        for item in data:
            if isinstance(item, tuple) and len(item) == 2:
                return item[1]
        # Last resort: skip the FETCH header line and status lines,
        # return the largest bytes item that isn't a single paren or status.
        candidates = []
        for item in data:
            if isinstance(item, bytes) and len(item) > 10:
                if not item.strip().startswith(b"Fetch ") and b"FETCH" not in item:
                    candidates.append(item)
        if candidates:
            return max(candidates, key=len)
        # Final fallback: join all byte items.
        parts = [item for item in data if isinstance(item, (bytes, bytearray))]
        return b"".join(parts)

    @staticmethod
    def _parse_date(date_str: str) -> datetime:
        """Parse an email Date header into a UTC datetime."""
        if not date_str:
            return datetime.now(timezone.utc)
        parsed = email.utils.parsedate_to_datetime(date_str)
        return parsed.astimezone(timezone.utc)

    @staticmethod
    def _extract_body(msg: email.message.Message) -> str:
        """Extract the plain-text body from an email message."""
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                if content_type == "text/plain":
                    payload = part.get_payload(decode=True)
                    if payload:
                        charset = part.get_content_charset() or "utf-8"
                        return payload.decode(charset, errors="replace")
        else:
            payload = msg.get_payload(decode=True)
            if payload:
                charset = msg.get_content_charset() or "utf-8"
                return payload.decode(charset, errors="replace")
        return ""

    @staticmethod
    def _extract_html_body(msg: email.message.Message) -> str:
        """Extract the text/html body if present. Empty string otherwise."""
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == "text/html":
                    payload = part.get_payload(decode=True)
                    if payload:
                        charset = part.get_content_charset() or "utf-8"
                        return payload.decode(charset, errors="replace")
        else:
            if msg.get_content_type() == "text/html":
                payload = msg.get_payload(decode=True)
                if payload:
                    charset = msg.get_content_charset() or "utf-8"
                    return payload.decode(charset, errors="replace")
        return ""

    @staticmethod
    def _extract_flags(data: list) -> list[str]:
        """Extract IMAP flags from FETCH response as label strings."""
        flags = []
        for item in data:
            if isinstance(item, bytes):
                item = item.decode(errors="replace")
            if isinstance(item, str) and "FLAGS" in item:
                # Parse flags from "(\\Seen \\Flagged)" format.
                import re
                match = re.search(r"FLAGS \(([^)]*)\)", item)
                if match:
                    flags = match.group(1).split()
        return flags

    async def apply_label(self, message_id: str, label: str) -> None:
        """Apply a flag or copy to a folder.

        For standard IMAP flags (\\Seen, \\Flagged, etc.), uses STORE.
        For custom labels, COPY to a folder with that name. Folder is
        auto-created on first use (parity with Gmail's label
        auto-create) — categories don't need pre-provisioning.
        """
        client = await self._connect()

        if label.startswith("\\"):
            # Standard IMAP flag.
            await client.uid("store", message_id, "+FLAGS", f"({label})")
            return

        # Treat as folder name — copy the message there. On COPY
        # failure (typically TRYCREATE / [NO] for missing folder),
        # CREATE then retry once.
        quoted = self._quote_mailbox(label)
        result, data = await client.uid("copy", message_id, quoted)
        if result != "OK":
            log.info(
                "IMAP COPY failed; creating folder and retrying",
                uid=message_id, folder=label, result=result,
                reason=_fmt_imap_response(data),
            )
            try:
                await self.create_folder(label)
            except Exception as ce:
                log.warning(
                    "Auto-create folder failed",
                    folder=label, error=str(ce),
                )
                raise
            result2, data2 = await client.uid(
                "copy", message_id, quoted,
            )
            if result2 != "OK":
                reason2 = _fmt_imap_response(data2)
                raise RuntimeError(
                    f"IMAP COPY to '{label}' failed after auto-create "
                    f"(uid {message_id}, result {result2}"
                    + (f", server: {reason2}" if reason2 else "")
                    + ")"
                )
        log.info("Copied message to folder", uid=message_id, folder=label)

    async def list_folders(self) -> list[str]:
        """List all IMAP folders/mailboxes."""
        client = await self._connect()
        result, data = await client.list('""', "*")
        if result != "OK":
            log.warning("IMAP LIST failed", result=result)
            return []

        import re
        folders = []
        for line in data:
            if isinstance(line, bytes):
                line = line.decode(errors="replace")
            if not line or not line.strip():
                continue
            # Parse LIST response: (\\flags) "delimiter" "name"
            # Example: (\\HasNoChildren) "." "INBOX.Triage"
            match = re.search(r'\) "(.)" "?([^"]+)"?$', line)
            if match:
                folder_name = match.group(2).strip('"')
                folders.append(folder_name)
        folders.sort()
        return folders

    async def create_folder(self, folder: str) -> None:
        """Create an IMAP mailbox/folder."""
        client = await self._connect()
        result, data = await client.create(self._quote_mailbox(folder))
        if result != "OK":
            # Surface the server's tagged-response reason. Dovecot
            # returns shapes like ``NO [ALREADYEXISTS] Mailbox already
            # exists`` / ``NO Permission denied`` / ``NO Invalid
            # mailbox name``; without this the operator sees only the
            # generic "Failed to create" and has to enable debug logs
            # to recover the cause.
            reason = _fmt_imap_response(data)
            if reason:
                raise RuntimeError(
                    f"Failed to create folder '{folder}' "
                    f"(server: {result} {reason})"
                )
            raise RuntimeError(
                f"Failed to create folder '{folder}' (server: {result})"
            )
        log.info("IMAP folder created", folder=folder)

    async def move_message(self, message_id: str, folder: str) -> None:
        """Move a message to a folder via COPY + DELETE.

        Folder is auto-created on first use (parity with Gmail label
        auto-create). Avoids the ``Failed to apply label`` /
        ``IMAP COPY failed`` class of error when a category names a
        folder the operator never pre-created.
        """
        client = await self._connect()
        quoted = self._quote_mailbox(folder)
        result, data = await client.uid("copy", message_id, quoted)
        first_copy_reason = ""
        if result != "OK":
            first_copy_reason = _fmt_imap_response(data)
            log.info(
                "IMAP COPY failed; creating folder and retrying",
                uid=message_id, folder=folder, result=result,
                reason=first_copy_reason,
            )
            try:
                await self.create_folder(folder)
            except Exception as ce:
                log.warning(
                    "Auto-create folder failed",
                    folder=folder, error=str(ce),
                )
                # ``ce`` already carries the server's NO-reason from
                # create_folder. Add the COPY-NO reason too so a
                # single error line shows both server-side rejections.
                copy_part = (
                    f" (initial COPY: {first_copy_reason})"
                    if first_copy_reason else ""
                )
                raise RuntimeError(
                    f"IMAP COPY to '{folder}' failed for UID {message_id}"
                    f"{copy_part} and auto-create raised: {ce}"
                ) from ce
            result, data = await client.uid("copy", message_id, quoted)
            if result != "OK":
                reason = _fmt_imap_response(data)
                raise RuntimeError(
                    f"IMAP COPY to '{folder}' failed for UID {message_id} "
                    f"after auto-create (result {result}"
                    + (f", server: {reason}" if reason else "")
                    + ")"
                )
        # Mark original as deleted.
        await client.uid("store", message_id, "+FLAGS", "(\\Deleted)")
        await client.expunge()
        log.info("Message moved", uid=message_id, folder=folder)

    async def set_keywords(self, message_id: str, keywords: list[str]) -> None:
        """Set IMAP keywords (custom flags) on a message.

        Keywords are stored as IMAP flags.  By convention, user-defined
        keywords start with ``$``.  Example: ``$triage_invoices``.
        """
        if not keywords:
            return
        client = await self._connect()
        flags_str = " ".join(keywords)
        await client.uid("store", message_id, "+FLAGS", f"({flags_str})")
        log.info("Keywords set", uid=message_id, keywords=keywords)

    async def select_folder(self, folder: str) -> None:
        """Select a different mailbox for subsequent operations.

        Folder names containing spaces or special characters must be
        quoted per IMAP RFC 3501.  Names already quoted are left alone.

        #147 — Pre-flight :meth:`_ensure_authenticated` ahead of the
        SELECT. A stale cached client whose auth state drifted to
        NONAUTH (server-side IDLE timeout, IMAP-LOGOUT race with the
        watcher, etc.) is the failure mode that produced
        ``command SELECT illegal in state NONAUTH`` in the digest
        scheduler at 06:00. The pre-flight either confirms AUTH /
        SELECTED, replays LOGIN on the existing transport, or
        raises :class:`IMAPClientLogoutError` when even re-LOGIN
        can't recover — at which point the helper has already
        dropped the cached client so the next provider call opens
        a fresh transport via :meth:`_connect`.
        """
        client = await self._connect()
        try:
            await self._ensure_authenticated()
        except IMAPClientLogoutError:
            # Cached client was unrecoverable; reconnect once.
            client = await self._connect()
        folder_arg = self._quote_mailbox(folder)
        try:
            result, data = await client.select(folder_arg)
        except aioimaplib.Abort as e:
            log.error(
                "IMAP SELECT aborted",
                folder=folder, error=str(e),
                **_capture_imap_state(client),
            )
            raise
        if result != "OK":
            log.warning(
                "IMAP SELECT failed",
                folder=folder, result=result,
                reason=_fmt_imap_response(data),
                **_capture_imap_state(client),
            )
            raise RuntimeError(f"Failed to select folder '{folder}'")
        log.info("Selected folder", folder=folder)

    @staticmethod
    def _quote_mailbox(folder: str) -> str:
        """Quote an IMAP mailbox name if it needs it (RFC 3501)."""
        if folder.startswith('"') and folder.endswith('"'):
            return folder
        # Quote if contains space or any non-atom-safe char.
        needs_quote = any(c in folder for c in ' "\\')
        if needs_quote:
            escaped = folder.replace("\\", "\\\\").replace('"', '\\"')
            return f'"{escaped}"'
        return folder

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
        """Create a draft email by APPENDing to the Drafts folder.

        The body is treated as HTML content.  Returns a placeholder draft ID.
        """
        import email.mime.multipart
        import email.mime.text

        msg = email.mime.multipart.MIMEMultipart("alternative")
        if from_addr:
            if from_name:
                safe = from_name.replace("\\", "\\\\").replace('"', '\\"')
                msg["From"] = f'"{safe}" <{from_addr}>'
            else:
                msg["From"] = from_addr
        else:
            # 2026-05-13 — prefer the configured email_address field
            # over IMAP LOGIN username for the default From header.
            # Falls back to username for legacy accounts whose IMAP
            # username already carries the @domain. Pre-fix drafts
            # shipped with bare LOGIN (e.g. ``user``), which mail
            # servers reject or rewrite.
            msg["From"] = self._email_address or self._username
        msg["To"] = ", ".join(to)
        msg["Subject"] = subject
        msg["Date"] = email.utils.formatdate(localtime=True)
        if reply_to:
            msg["Reply-To"] = reply_to
        if in_reply_to:
            msg["In-Reply-To"] = in_reply_to
        if extra_headers:
            for key, value in extra_headers.items():
                msg[key] = value

        # Plain text fallback.
        import re
        plain = re.sub(r"<[^>]+>", "", body)
        plain = re.sub(r"\s+", " ", plain).strip()
        msg.attach(email.mime.text.MIMEText(plain, "plain", "utf-8"))
        # HTML version.
        msg.attach(email.mime.text.MIMEText(body, "html", "utf-8"))

        client = await self._connect()

        # Find the Drafts folder. RFC 6154 SPECIAL-USE flag (\Drafts)
        # is the canonical signal across server implementations; fall
        # back to name-based discovery for legacy servers that don't
        # emit SPECIAL-USE flags. Hardcoded INBOX.Drafts is the last-
        # resort default for Dovecot installs that use the INBOX
        # namespace prefix.
        #
        # An earlier version of this discovery loop matched name
        # contains "drafts" AND "\\drafts" NOT in the line -- which
        # SKIPPED the SPECIAL-USE-flagged folder and fell through to
        # the default. On servers where the actual folder is just
        # "Drafts" (no INBOX prefix), the APPEND failed with NO.
        drafts_folder = "INBOX.Drafts"
        discovery_method = "default"
        # 2026-05-13 — operator override wins over auto-discovery.
        # When the account form's "Drafts folder" field is filled in
        # (account config["drafts_folder"]; passed into the provider
        # constructor + stored on self._drafts_folder), use it as-is
        # and skip the LIST / SPECIAL-USE probe entirely. Saves a
        # round-trip + makes the resolution deterministic on servers
        # whose folder naming doesn't match the canonical fallbacks.
        if self._drafts_folder:
            drafts_folder = self._drafts_folder
            discovery_method = "operator-override"
        else:
            try:
                import re as _re
                result, data = await client.list('""', "*")
                if result == "OK":
                    # Decode all lines once; pass 1 looks for SPECIAL-USE,
                    # pass 2 falls back to name match.
                    decoded = []
                    for line in data:
                        if isinstance(line, bytes):
                            line = line.decode(errors="replace")
                        decoded.append(line)
                    # Pass 1: SPECIAL-USE flag (canonical, RFC 6154).
                    # LIST line shape: `* LIST (\Drafts \HasNoChildren) "." "Drafts"`.
                    # The folder name is the LAST quoted token on the line.
                    found = False
                    for line in decoded:
                        if "\\drafts" in line.lower():
                            match = _re.search(r'"([^"]*)"\s*$', line.rstrip())
                            if match and match.group(1):
                                drafts_folder = match.group(1)
                                discovery_method = "special-use"
                                found = True
                                break
                    # Pass 2: name-based fallback (any quoted folder name
                    # whose last segment looks like a Drafts variant).
                    if not found:
                        for line in decoded:
                            match = _re.search(
                                r'"([^"]*[Dd]rafts[^"]*)"', line,
                            )
                            if match:
                                drafts_folder = match.group(1)
                                discovery_method = "name-match"
                                break
            except Exception as exc:
                # Used to silently ``pass`` here — every fall-through to
                # INBOX.Drafts looked like a configured default, not a
                # discovery failure. Log so the next mystery APPEND-NO
                # has a breadcrumb trail.
                log.warning(
                    "Drafts folder discovery failed; using default",
                    error=fmt_exc(exc), default=drafts_folder,
                )

        # Some IMAP servers reject APPEND when the target folder
        # doesn't exist (rather than auto-creating it). Issue an
        # idempotent CREATE first; ``NO`` from CREATE is harmless
        # when the folder already exists. This closes the failure
        # mode where SPECIAL-USE picks a name the user never
        # explicitly subscribed to + the server refuses APPEND.
        try:
            create_result, _ = await client.create(
                self._quote_mailbox(drafts_folder),
            )
            if create_result not in ("OK", "NO"):
                log.warning(
                    "IMAP CREATE returned unexpected status",
                    folder=drafts_folder, result=create_result,
                )
        except Exception as exc:
            # Don't fail the draft on CREATE error — fall through
            # to APPEND and let it surface the real cause.
            log.warning(
                "IMAP CREATE failed; attempting APPEND anyway",
                folder=drafts_folder, error=fmt_exc(exc),
            )

        # aioimaplib 2.0 signature: append(message_bytes, mailbox, flags, date).
        # message_bytes is FIRST — not mailbox — and the flags kwarg is `flags`,
        # not `flag_list`.
        result, _ = await client.append(
            msg.as_bytes(),
            mailbox=self._quote_mailbox(drafts_folder),
            flags="(\\Draft \\Seen)",
        )
        if result != "OK":
            # If the discovered folder failed but we hadn't tried
            # the alternate ("Drafts" without INBOX prefix vs
            # "INBOX.Drafts" with), give it one shot before raising.
            # Covers Dovecot installs whose namespace prefix doesn't
            # match what SPECIAL-USE returned.
            alt = None
            if drafts_folder == "INBOX.Drafts":
                alt = "Drafts"
            elif drafts_folder == "Drafts":
                alt = "INBOX.Drafts"
            if alt:
                log.warning(
                    "IMAP APPEND failed; trying alternate folder name",
                    folder=drafts_folder, alt=alt, result=result,
                )
                try:
                    await client.create(self._quote_mailbox(alt))
                except Exception:
                    pass
                result, _ = await client.append(
                    msg.as_bytes(),
                    mailbox=self._quote_mailbox(alt),
                    flags="(\\Draft \\Seen)",
                )
                if result == "OK":
                    drafts_folder = alt
                    discovery_method = f"{discovery_method}+alt"
            if result != "OK":
                raise RuntimeError(
                    f"IMAP APPEND to '{drafts_folder}' failed: {result}"
                )

        log.info(
            "Draft created", folder=drafts_folder, subject=subject,
            discovery=discovery_method,
        )
        return f"draft-{drafts_folder}"

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
        """APPEND a self-composed HTML message directly to the INBOX.

        For digest-style features: the user schedules it, so they've
        already consented to see it — drop it in the inbox (unread) so
        it surfaces like any other new mail.  No SMTP round-trip.
        """
        import email.mime.multipart
        import email.mime.text
        import re

        msg = email.mime.multipart.MIMEMultipart("alternative")
        if from_addr:
            if from_name:
                safe = from_name.replace("\\", "\\\\").replace('"', '\\"')
                msg["From"] = f'"{safe}" <{from_addr}>'
            else:
                msg["From"] = from_addr
        else:
            # 2026-05-13 — same email_address fallback as create_draft.
            msg["From"] = self._email_address or self._username
        msg["To"] = ", ".join(to) if to else (
            self._email_address or self._username
        )
        msg["Subject"] = subject
        msg["Date"] = email.utils.formatdate(localtime=True)
        if reply_to:
            msg["Reply-To"] = reply_to
        if extra_headers:
            for key, value in extra_headers.items():
                msg[key] = value

        plain = re.sub(r"<[^>]+>", "", body)
        plain = re.sub(r"\s+", " ", plain).strip()
        msg.attach(email.mime.text.MIMEText(plain, "plain", "utf-8"))
        msg.attach(email.mime.text.MIMEText(body, "html", "utf-8"))

        client = await self._connect()
        # aioimaplib 2.0: append(message_bytes, mailbox, flags, date).
        # Omit flags entirely so the message arrives unread (shows as new).
        result, _ = await client.append(
            msg.as_bytes(),
            mailbox=self._quote_mailbox("INBOX"),
        )
        if result != "OK":
            raise RuntimeError(f"IMAP APPEND to INBOX failed: {result}")

        log.info("Delivered to inbox", subject=subject)
        return "inbox-delivered"

    async def archive(self, message_id: str) -> None:
        """Archive a message by adding \\Seen and moving to Archive folder."""
        client = await self._connect()
        await client.uid("store", message_id, "+FLAGS", "(\\Seen)")
        try:
            await client.uid("copy", message_id, self._quote_mailbox("Archive"))
            await client.uid("store", message_id, "+FLAGS", "(\\Deleted)")
            await client.expunge()
        except Exception:
            log.warning("Archive folder not available, just marking as read", uid=message_id)

    async def peek_recent_uids(
        self, query: str, max_per_folder: int = 50,
    ) -> list[tuple[str, str]]:
        """Lightweight peek: search + fetch UIDs with INTERNALDATE.

        Returns a list of ``(uid, internaldate_str)`` pairs from the
        *currently selected* folder, newest first.  Only fetches UID and
        INTERNALDATE — no message bodies — so this is very cheap.
        """
        import re as _re

        client = await self._connect()
        imap_query = self._translate_query(query)
        result, data = await client.search(imap_query)
        if result != "OK":
            return []

        seq_nums: list[str] = []
        for line in data:
            if isinstance(line, bytes):
                line = line.decode()
            for token in line.strip().split():
                if token.isdigit():
                    seq_nums.append(token)

        if not seq_nums:
            return []

        # Take the most recent ones (highest seq numbers = newest).
        seq_nums.reverse()
        seq_nums = seq_nums[:max_per_folder]

        seq_set = ",".join(seq_nums)
        result, fetch_data = await client.fetch(seq_set, "(UID INTERNALDATE)")
        if result != "OK":
            return []

        pairs: list[tuple[str, str]] = []
        for line in fetch_data:
            if isinstance(line, bytes):
                line = line.decode(errors="replace")
            line_str = str(line)
            uid_match = _re.search(r"UID\s+(\d+)", line_str)
            date_match = _re.search(r'INTERNALDATE\s+"([^"]+)"', line_str)
            if uid_match and date_match:
                pairs.append((uid_match.group(1), date_match.group(1)))

        return pairs

    async def poll_once(
        self, mailbox: str, since_uid: int,
    ) -> list[EmailMessage]:
        """Single-shot poll: fetch any messages with UID > ``since_uid``.

        Used by the unified poll loop as the "cheap no-op when nothing
        changed" path. The typical tick does:

          SELECT <mailbox>
          UID SEARCH UID <since_uid+1>:*
          → empty set → return []

        and never issues a body fetch. When there ARE new UIDs we batch-
        fetch them with ``BODY.PEEK[]`` and parse each into
        :class:`EmailMessage`. ``since_uid=0`` means "fresh account"; the
        caller is responsible for seeding the HWM so we don't dump the
        entire backlog (matches the IDLE watcher's seed-on-first-start
        behaviour). Here, the SEARCH ``1:*`` range would return every
        message, so we short-circuit and return [] when ``since_uid=0``.

        Errors (connection, auth, protocol) bubble up — the unified
        poll loop's per-account try/except handles isolation.
        """
        if since_uid == 0:
            # Fresh HWM — skip the poll; caller seeds from get_latest_uid.
            return []

        import re as _re

        client = await self._connect()
        # Select the mailbox — we allow the caller to pass a mailbox
        # that differs from the constructor's default so the unified
        # poll loop can walk every configured folder on one provider
        # instance. The poll tick is short-lived so there's no need to
        # restore the previous selection.
        await client.select(self._quote_mailbox(mailbox))

        # aioimaplib 2.0 restricts client.uid() to COPY/FETCH/STORE/EXPUNGE
        # (see the comment near _search_in_current_mailbox) — we can't do
        # uid("search", ...). The server's complaint is exactly:
        #   "command UID only possible with COPY, FETCH, EXPUNGE
        #    (w/UIDPLUS) or STORE (was SEARCH)"
        # Use plain SEARCH with a UID criterion instead. Plain SEARCH
        # returns *sequence numbers*, so we follow the existing codebase
        # pattern of SEARCH-then-batch-FETCH-UIDs.
        range_spec = f"{since_uid + 1}:*"
        imap_query = f"UID {range_spec}"
        result, data = await client.search(imap_query)
        if result != "OK":
            # PR 7 / C3 — surface as a transient error so the caller
            # can distinguish "no new mail" (empty result) from
            # "provider broken" (this branch). The previous return-[]
            # behaviour silently masked broken providers as quiet
            # mailboxes.
            from email_triage.providers.base import ProviderTransientError
            log.warning(
                "IMAP poll SEARCH failed",
                mailbox=mailbox, query=imap_query, result=result,
            )
            raise ProviderTransientError(
                f"IMAP SEARCH failed on {mailbox!r}: result={result}"
            )

        # Parse sequence numbers from SEARCH response.
        seq_nums: list[str] = []
        for line in data:
            if isinstance(line, bytes):
                line = line.decode(errors="replace")
            for token in str(line).strip().split():
                if token.isdigit():
                    seq_nums.append(token)

        if not seq_nums:
            return []

        # Batch-fetch UIDs for the matched sequence numbers.
        seq_set = ",".join(seq_nums)
        result, uid_data = await client.fetch(seq_set, "(UID)")
        if result != "OK":
            from email_triage.providers.base import ProviderTransientError
            log.warning(
                "IMAP poll FETCH UIDs failed",
                mailbox=mailbox, seq_set=seq_set, result=result,
            )
            raise ProviderTransientError(
                f"IMAP FETCH UIDs failed on {mailbox!r}: result={result}"
            )

        uids: list[str] = []
        for line in uid_data:
            if isinstance(line, bytes):
                line = line.decode(errors="replace")
            uid_match = _re.search(r"UID\s+(\d+)", str(line))
            if uid_match:
                token = uid_match.group(1)
                # Filter anchor-UID echo some servers include.
                try:
                    if int(token) > since_uid:
                        uids.append(token)
                except ValueError:
                    continue

        if not uids:
            return []

        messages: list[EmailMessage] = []
        # Fetch one UID at a time — the existing fetch_message helper
        # handles the response-parsing differences across aioimaplib
        # versions. The typical poll brings in a handful of UIDs at
        # most; if cadence falls far behind we'd want to batch, but
        # that's a future optimisation.
        for uid in uids:
            try:
                msg = await self.fetch_message(uid)
                messages.append(msg)
            except Exception as e:
                log.warning(
                    "IMAP poll_once: fetch failed, skipping",
                    mailbox=mailbox, uid=uid, error=fmt_exc(e),
                )

        return messages

    async def get_latest_uid(self) -> int:
        """Return the UID of the most recent message in the current mailbox.

        Uses ``FETCH * (UID)`` — sequence number ``*`` is always the last
        message.  Returns 0 if the mailbox is empty.
        """
        import re as _re
        client = await self._connect()
        result, data = await client.fetch("*", "(UID)")
        if result != "OK":
            return 0
        for line in data:
            if isinstance(line, bytes):
                line = line.decode(errors="replace")
            if "UID" in str(line):
                match = _re.search(r"UID\s+(\d+)", str(line))
                if match:
                    return int(match.group(1))
        return 0

    async def watch(self) -> AsyncIterator[str]:
        """Watch for new messages using IMAP IDLE.

        Yields UIDs of new messages as they arrive.  Refreshes the IDLE
        connection every ``idle_timeout`` seconds to comply with RFC 2177.

        Uses ``client.search()`` + ``client.fetch(seq, "(UID)")`` instead
        of ``client.uid("search", ...)`` because aioimaplib 2.0 restricts
        ``uid()`` to COPY, FETCH, STORE, and EXPUNGE only.
        """
        import re as _re

        client = await self._connect()
        log.info("Starting IMAP IDLE watch", mailbox=self._mailbox)

        # Track UIDs we've already yielded to avoid duplicates across
        # IDLE cycles (a UID might stay UNSEEN if triage doesn't flag
        # it). #143 — see ``_seen_uids_remember`` for the design
        # rationale (was a single ``set`` with an order-undefined
        # prune; now a bounded deque + parallel set for FIFO).
        seen_uids_q: collections.deque[str] = collections.deque(maxlen=1000)
        seen_uids: set[str] = set()

        while True:
            idle_task = await client.idle_start(timeout=self._idle_timeout)

            # Wait for the IDLE response or timeout.
            msg = await client.wait_server_push()

            client.idle_done()
            await asyncio.wait_for(idle_task, timeout=10)

            # Check if we got an EXISTS notification (new mail).
            has_new = False
            for response in msg:
                if isinstance(response, bytes):
                    response = response.decode()
                if "EXISTS" in str(response):
                    has_new = True
                    break

            if not has_new:
                # Timeout or non-EXISTS push — just re-enter IDLE.
                continue

            # Search for unseen messages using non-UID SEARCH.
            result, data = await client.search("UNSEEN")
            if result != "OK":
                log.warning("IMAP SEARCH after IDLE failed", result=result)
                continue

            # Parse sequence numbers (filter out status lines).
            seq_nums = []
            for line in data:
                if isinstance(line, bytes):
                    line = line.decode()
                for token in line.strip().split():
                    if token.isdigit():
                        seq_nums.append(token)

            if not seq_nums:
                continue

            # Fetch UIDs for the sequence numbers.
            seq_set = ",".join(seq_nums)
            result, uid_data = await client.fetch(seq_set, "(UID)")
            if result != "OK":
                log.warning("IMAP FETCH UIDs after IDLE failed", result=result)
                continue

            new_uids = []
            for line in uid_data:
                if isinstance(line, bytes):
                    line = line.decode(errors="replace")
                if "UID" in line:
                    match = _re.search(r"UID\s+(\d+)", line)
                    if match:
                        uid = match.group(1)
                        if uid not in seen_uids:
                            new_uids.append(uid)
                            _seen_uids_remember(
                                uid, seen_uids_q, seen_uids,
                            )

            for uid in new_uids:
                yield uid

            # No manual prune needed — the deque's ``maxlen`` handles
            # FIFO eviction inside ``_remember_uid``.

    async def close(self) -> None:
        """Close the IMAP connection without hanging shutdown.

        ``logout()`` can stall indefinitely if the connection is
        mid-IDLE or the server is slow, so we cap it at 2 seconds and
        fall back to ripping the transport. That's important: this
        coroutine runs from the watcher's ``finally`` block during
        SIGTERM-driven shutdown, and podman's default stop-timeout is
        only 10 s — a hung logout per account would push us past that
        and force a SIGKILL with stale state.
        """
        if self._client is None:
            return
        client = self._client
        self._client = None
        try:
            await asyncio.wait_for(client.logout(), timeout=2.0)
        except asyncio.TimeoutError:
            # Expected on shutdown for servers that don't ACK LOGOUT
            # fast — some Dovecot deployments reliably time out here
            # when the connection was mid-IDLE. The fallback (transport
            # close below) handles cleanup. Demoted from WARNING to
            # INFO 2026-05-10 since it fires every IMAP poll cycle
            # and was filling the operator's log view without any
            # actionable signal.
            log.info(
                "IMAP logout timed out; forcing transport close",
                host=getattr(self, "_host", None),
                port=getattr(self, "_port", None),
            )
        except Exception as e:
            log.debug("IMAP logout raised", error=fmt_exc(e))
        # Belt-and-braces: tear the transport down so the event loop
        # releases the socket even if logout was a no-op.
        try:
            transport = getattr(getattr(client, "protocol", None), "transport", None)
            if transport is not None:
                transport.close()
        except Exception:
            pass
        log.info("IMAP connection closed")
