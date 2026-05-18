"""Provider-native label enumeration for the rule editor (#163).

The install-internal ``labels`` catalog (v18 migration) is independent
of the labels operators already maintain on their provider mailboxes:

  * Gmail accounts carry per-user labels (``users.labels.list``)
  * Office 365 accounts carry mailbox-wide categories
    (``/me/outlook/masterCategories``)
  * IMAP accounts CAN carry per-message keywords (a.k.a. tags / flags
    per RFC 3501) — operator-defined keywords sit alongside the
    system flags (``\\Seen``, ``\\Flagged``, etc.) and can serve as
    labels. We deliberately skip IMAP from this picker anyway because
    mail-client support for custom keywords is uneven and the per-
    message keywords frequently don't survive round-trips across
    mixed clients. The route editor's "move" action covers the
    folder-membership case for IMAP; that works everywhere.

This module exposes a single helper, :func:`list_provider_labels_for_account`,
that surfaces those labels in a uniform shape so the rule-editor
picker can render them. Per-account dispatch keeps the call site
provider-agnostic; the caller only needs an account_id + a secrets
handle.

Caching: in-process module-level dict with a 5-minute TTL keyed by
``(account_id, provider_type)``. Provider API calls cost a round-trip
(Gmail = one HTTP, O365 = one HTTP, IMAP = one LIST); a single rule
editor page-load can fan out across all the user's accounts, so a
brief cache spares the provider load on the second tab open. Cache
is capped at 200 entries to bound memory if an install adds and
removes a lot of accounts.

HIPAA: returns ``[]`` for HIPAA-flagged accounts. Defense-in-depth
duplicate of the caller-side check; the picker route already filters
out HIPAA accounts when building groups, but the per-account-loop
shape means a future caller could call this helper directly without
the route-level filter, so the gate stays here too.

Privacy: this module never logs label names (which can carry
operator-meaningful semantics like a Gmail label named after a
patient). Only error class + provider type + account id appears in
log output. Caller is responsible for downstream redaction.
"""

from __future__ import annotations

import asyncio
import sqlite3
import time
from typing import Any

from email_triage._errfmt import fmt_exc
from email_triage.providers.factory import build_provider
from email_triage.triage_logging import get_logger, is_account_hipaa
from email_triage.web.db import list_email_accounts

log = get_logger("providers.provider_labels")

# Gmail system labels that the operator doesn't get to "apply via
# rule" — they're managed by Gmail itself (INBOX, SENT, TRASH, etc).
# Surfacing them in the rule editor's picker pollutes the UI + would
# let operators tick nonsensical actions like "apply INBOX". Operator
# caught this 2026-05-12 with a screenshot showing 50+ system labels
# + nested archive paths flooding the picker.
_GMAIL_SYSTEM_LABEL_NAMES = frozenset({
    # Core system labels — Gmail manages these.
    "CHAT", "SENT", "INBOX", "IMPORTANT", "TRASH",
    "DRAFT", "DRAFTS", "SPAM", "STARRED", "UNREAD",
})

# Gmail "category" tabs (Promotions / Social / Updates / Forums /
# Personal) — operator can't change category assignment via labels
# API, so don't offer them in the picker.
_GMAIL_CATEGORY_PREFIX = "CATEGORY_"

# Coloured-star variants (YELLOW_STAR, RED_STAR, ...) — Gmail's
# alternative star colours that show up as labels. Not useful in the
# rule-editor picker.
_GMAIL_STAR_SUFFIX = "_STAR"

# Gmail's IMAP-compat namespace — labels named "[Gmail]/All Mail/X"
# or "[Imap]/Trash" are Gmail's hidden folder-shim paths, not user-
# facing labels. Skip them.
_GMAIL_PATH_PREFIXES = ("[Gmail]/", "[Imap]/")


def _is_gmail_system_label(name: str) -> bool:
    """Return True for Gmail labels the operator doesn't manage."""
    if not name:
        return True
    if name in _GMAIL_SYSTEM_LABEL_NAMES:
        return True
    if name.startswith(_GMAIL_CATEGORY_PREFIX):
        return True
    if name.endswith(_GMAIL_STAR_SUFFIX):
        return True
    if name.startswith(_GMAIL_PATH_PREFIXES):
        return True
    return False


# Cache TTL — 5 minutes. Long enough to make rapid tab-switches on
# the rule-editor page cheap, short enough that newly-created Gmail
# labels show up on the picker without restarting the install.
_CACHE_TTL_SECS = 300

# Cap on total cache entries — bounds memory for installs that cycle
# through many accounts. LRU eviction not needed at this scale; we
# just drop oldest by insertion order when over cap.
_CACHE_MAX_ENTRIES = 200

# Module-level cache: {(account_id, provider_type): (timestamp, [entries])}.
_cache: dict[tuple[int, str], tuple[float, list[dict]]] = {}


def _cache_get(key: tuple[int, str]) -> list[dict] | None:
    """Return a fresh cache hit, or None on miss / expiry."""
    hit = _cache.get(key)
    if hit is None:
        return None
    ts, value = hit
    if (time.monotonic() - ts) > _CACHE_TTL_SECS:
        # Stale — drop and miss.
        _cache.pop(key, None)
        return None
    return value


def _cache_put(key: tuple[int, str], value: list[dict]) -> None:
    """Store + evict-oldest-on-overflow."""
    if len(_cache) >= _CACHE_MAX_ENTRIES and key not in _cache:
        # Oldest by insertion order (dicts preserve order in Python 3.7+).
        oldest = next(iter(_cache))
        _cache.pop(oldest, None)
    _cache[key] = (time.monotonic(), value)


def _cache_clear() -> None:
    """Test hook — flush every entry. Not exposed to runtime callers."""
    _cache.clear()


async def list_provider_labels_for_account(
    *,
    db: sqlite3.Connection,
    secrets: Any,
    account_id: int,
) -> list[dict]:
    """Return labels/folders/categories that already exist on the
    provider for this account.

    Per-provider dispatch:
      * ``gmail_api`` → provider.list_labels() — Gmail labels with the
        color hex when the user assigned one (Gmail's color field is
        nested under ``color.backgroundColor``; we surface it as
        ``color`` in the result).
      * ``office365`` → provider.list_labels() — Outlook
        masterCategories. Graph returns ``preset`` color names like
        ``preset0`` rather than hex; we leave the color empty and
        let the caller render a default chip.
      * ``imap`` → provider.list_folders() — folder names. No color
        concept; ``color`` is "".

    Each result entry has the shape::

        {"slug": "<provider-side identifier>",
         "name": "<display name>",
         "color": "<hex or empty>"}

    For Gmail / O365, ``slug`` is the label/category name (what
    ``apply_label`` accepts at the API surface), and ``name`` is the
    same value (Gmail + O365 don't distinguish slug from display).
    For IMAP, ``slug`` is the full folder name (``INBOX.Receipts``).

    HIPAA gate: returns ``[]`` for HIPAA-flagged accounts. Caller
    must not display the picker for HIPAA accounts at all; this is
    the defensive second layer.

    Failure modes (each returns ``[]`` + logs at WARNING so the page
    render never breaks on a misconfigured / unreachable provider):
      * Account not found in DB
      * No secret for the account (provider can't authenticate)
      * Provider raises any exception during list_labels/list_folders
      * Provider doesn't implement the method (NotImplementedError)

    Caching: hit returns the cached list without re-contacting the
    provider; misses populate the cache after the provider call.
    """
    # Look up the account row. Admin view (user_id=None) returns every
    # account, so we can isolate by id without knowing the requesting
    # user — the caller is responsible for the auth check.
    rows = list_email_accounts(db, user_id=None)
    acct = next((r for r in rows if int(r["id"]) == int(account_id)), None)
    if acct is None:
        log.warning(
            "provider_labels: account not found",
            account_id=account_id,
        )
        return []

    # HIPAA gate (defensive). Returns empty before any provider work.
    if is_account_hipaa(acct):
        return []

    provider_type = acct.get("provider_type", "")

    # IMAP technically supports labels via the per-message keywords
    # / tags / flags surface in RFC 3501 (the same channel that
    # carries \Seen, \Flagged, \Deleted, etc — operator-defined
    # keywords are addable alongside the system ones). We skip IMAP
    # from the picker anyway because:
    #
    #   1. Client support is uneven — many mail apps don't render
    #      custom keywords or strip them on copy, so operator-set
    #      labels would frequently disappear in transit.
    #   2. The prior implementation surfaced FOLDER names as labels,
    #      which is conceptually wrong (folders are single-membership
    #      move destinations, not multi-membership tags) AND filled
    #      the picker with hundreds of nested archive folders.
    #
    # Both reasons point to: don't pretend IMAP carries labels here.
    # The route editor's "move" action covers folder-membership; if
    # operator IS on a mail client that handles keywords (e.g. some
    # modern Thunderbird builds), they can surface that via watches
    # or a custom action — but it's not the default rule-editor
    # picker surface.
    if provider_type == "imap":
        return []

    cache_key = (int(account_id), provider_type)
    cached = _cache_get(cache_key)
    if cached is not None:
        return cached

    try:
        provider = build_provider(acct, secrets)
    except Exception as exc:
        # Same auth-shape demote as the fetch path below — operator
        # opening the rule editor on an account that hasn't completed
        # OAuth shouldn't generate WARN noise. Picker just shows zero
        # entries for that account.
        err_str = fmt_exc(exc)
        is_auth_shape = any(
            tok in err_str for tok in (
                "AADSTS", "device code", "NONAUTH",
                "invalid_grant", "401", "Unauthorized",
                "missing OAuth", "secret not found", "no token",
            )
        )
        if is_auth_shape:
            log.debug(
                "provider_labels: build skipped (account not authenticated)",
                account_id=account_id,
                provider_type=provider_type,
                error=err_str[:120],
            )
        else:
            log.warning(
                "provider_labels: build_provider failed",
                account_id=account_id,
                provider_type=provider_type,
                error=err_str,
            )
        return []

    entries: list[dict] = []
    try:
        if provider_type in ("gmail_api", "office365"):
            try:
                raw = await provider.list_labels()
            except NotImplementedError:
                raw = []
            for item in raw or []:
                if not isinstance(item, dict):
                    continue
                name = item.get("name", "") or ""
                if not name:
                    continue
                # Filter Gmail system + category + star + path-shim
                # labels so the picker only shows operator-curated
                # labels. O365 categories are operator-created by
                # construction (no system set), so no equivalent
                # filter applies for office365.
                if provider_type == "gmail_api" and _is_gmail_system_label(name):
                    continue
                # Gmail returns color as a nested dict; we surface
                # ``backgroundColor`` if present. O365 carries a
                # ``color`` preset name that doesn't map to hex —
                # leave it empty so the template renders the default
                # chip background.
                color = ""
                raw_color = item.get("color")
                if isinstance(raw_color, dict):
                    color = str(raw_color.get("backgroundColor", "")) or ""
                # Slug == name for Gmail + O365: the apply_label call
                # accepts the user-visible name as the identifier
                # (Gmail resolves to id via the cache; O365 stores
                # the category by displayName).
                entries.append({
                    "slug": name,
                    "name": name,
                    "color": color,
                })
            # Sort operator-curated labels alphabetically. Gmail
            # returns labels in API insertion order which has no
            # operator-meaningful sort; alphabetic is predictable
            # + matches what operators see in the Gmail sidebar.
            entries.sort(key=lambda e: e["name"].lower())
        elif provider_type == "imap":
            try:
                folders = await provider.list_folders()
            except NotImplementedError:
                folders = []
            for folder in folders or []:
                if not isinstance(folder, str) or not folder:
                    continue
                entries.append({
                    "slug": folder,
                    "name": folder,
                    "color": "",
                })
        else:
            # Unknown provider type — silently skip. Caller can add
            # a branch here when a new provider lands.
            entries = []
    except Exception as exc:
        # Auth-shaped failures (operator hasn't completed OAuth, token
        # expired, AADSTS code, IMAP NONAUTH, etc.) are operator-side
        # config issues — not server bugs. Demote them to DEBUG so the
        # WARN noise on /logs isn't dominated by "we tried to enumerate
        # labels on an account that hasn't been authenticated yet."
        # The picker silently shows zero entries for that account; the
        # operator-facing surface for the auth problem is the account
        # edit page's status chip, not this WARN.
        err_str = fmt_exc(exc)
        is_auth_shape = any(
            tok in err_str for tok in (
                "AADSTS", "device code", "NONAUTH",
                "invalid_grant", "401", "Unauthorized",
                "missing OAuth", "secret not found", "no token",
            )
        )
        if is_auth_shape:
            log.debug(
                "provider_labels: fetch skipped (account not authenticated)",
                account_id=account_id,
                provider_type=provider_type,
                error=err_str[:120],
            )
        else:
            log.warning(
                "provider_labels: fetch failed",
                account_id=account_id,
                provider_type=provider_type,
                error=err_str,
            )
        entries = []
    finally:
        # Best-effort close — some providers leak a session otherwise.
        close = getattr(provider, "close", None)
        if close is not None:
            try:
                result = close()
                if asyncio.iscoroutine(result):
                    await result
            except Exception:
                pass

    _cache_put(cache_key, entries)
    return entries
