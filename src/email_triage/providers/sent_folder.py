"""Discover the Sent / Sent Items folder name for a given provider.

#157 — needed by the on-demand "Mine the Sent Items Now" button on
``/profile/style-data``. Discovery rules per provider:

  IMAP — RFC 6154 SPECIAL-USE (`\\Sent` flag) via LIST response, then
         name-based fallback against common variants
         (``Sent``, ``INBOX.Sent``, ``Sent Items``, ``Sent Messages``).
  Gmail API — the system label ``SENT`` is always present; return
         that constant directly (no probe needed).
  Office 365 — the Graph well-known folder name ``sentitems`` works
         in messages list/queries without per-tenant probing.

The discovery returns a string the caller passes to the provider's
own search / list path. Callers are expected to use it as a hint —
they don't always need to switch folders explicitly (IMAP needs a
SELECT, Gmail just adds ``in:sent`` to the query, O365 takes the
well-known folder id in the URL).

We deliberately mirror the Drafts-folder discovery logic in
``providers/imap.py`` (same RFC 6154 LIST probe, same fallback order)
rather than refactor — the Drafts path lives inside ``send_draft``
where it's intertwined with APPEND retry, and lifting it cleanly is
out of scope for #157. Keeping the two helpers separate also lets a
future change to one (e.g. Drafts gets a different fallback order)
land without coupling the other.
"""

from __future__ import annotations

import re

from email_triage.triage_logging import get_logger

log = get_logger("providers.sent_folder")


# Order matters: the first IMAP-name fallback wins when SPECIAL-USE
# is silent. The bare ``Sent`` is most common across Dovecot /
# Cyrus / modern Exchange-via-IMAP; ``INBOX.Sent`` covers Dovecot
# installs with the INBOX namespace prefix turned on; ``Sent Items``
# is the historic Exchange-via-IMAP shape; ``Sent Messages`` is the
# legacy macOS Mail / iCloud spelling.
_IMAP_SENT_FALLBACKS: tuple[str, ...] = (
    "Sent",
    "INBOX.Sent",
    "Sent Items",
    "INBOX.Sent Items",
    "Sent Messages",
    "INBOX.Sent Messages",
)


async def find_sent_folder(provider) -> str:
    """Return the Sent / Sent Items folder name on ``provider``.

    Provider-type dispatch:

      * ``gmail_api`` → ``"SENT"`` (Gmail system label name).
      * ``office365`` → ``"sentitems"`` (Graph well-known folder).
      * IMAP (anything else with ``list_folders``) → SPECIAL-USE probe
        via the raw LIST response, then a name-based fallback against
        the operator-actual folder list, then a fixed-order default.

    Never raises. On a discovery failure the function falls back to
    the most common name (``"Sent"`` for IMAP) so callers always get
    a usable string — the operator can verify on-screen and override
    in a future iteration if needed.

    The provider is assumed to be already connected / authenticated;
    this helper does not call ``provider.close()`` (the caller owns
    the connection lifecycle).
    """
    name = getattr(provider, "name", "") or type(provider).__name__.lower()

    # Gmail API — the SENT system label is canonical and always
    # present. The search filter ``in:sent`` resolves to it. We
    # return the label name as a string for display + a hint that
    # the consumer should use Gmail's query syntax.
    if "gmail" in name.lower():
        return "SENT"

    # Office 365 — Graph well-known folder ids are accepted as
    # display strings in messages/{wellKnownFolderName} URLs. The
    # canonical id is ``sentitems`` (single token, lowercase). The
    # display name on the user's mailbox is "Sent Items", but the
    # API path uses the well-known id.
    if "office365" in name.lower() or "o365" in name.lower():
        return "sentitems"

    # IMAP — SPECIAL-USE probe (RFC 6154 \Sent flag) via the LIST
    # response. We invoke the raw LIST through the provider's
    # private client to get the flags + folder names; if the
    # provider doesn't expose that, we fall through to a name match
    # against ``list_folders()``.
    discovered, method = await _discover_imap_sent(provider)
    log.info(
        "Sent folder discovery",
        provider=name,
        folder=discovered,
        method=method,
    )
    return discovered


async def _discover_imap_sent(provider) -> tuple[str, str]:
    """Run the RFC 6154 + name-fallback probe against an IMAP provider.

    Returns ``(folder_name, discovery_method)`` so the caller can
    log the method used (special-use / name-match / default).
    """
    # Pass 1 — SPECIAL-USE via the raw LIST response. We need access
    # to the underlying aioimaplib client; the IMAPProvider exposes
    # it via the private ``_connect`` coroutine. Be tolerant of a
    # provider shape we don't recognise — fall through to pass 2.
    try:
        connect = getattr(provider, "_connect", None)
        if connect is not None:
            client = await connect()
            result, data = await client.list('""', "*")
            if result == "OK":
                decoded: list[str] = []
                for line in data:
                    if isinstance(line, bytes):
                        line = line.decode(errors="replace")
                    decoded.append(line)
                # Look for the \Sent SPECIAL-USE flag.
                for line in decoded:
                    if "\\sent" in line.lower():
                        match = re.search(r'"([^"]*)"\s*$', line.rstrip())
                        if match and match.group(1):
                            return match.group(1), "special-use"
                # Pass 2a — name-based fallback on the raw LIST
                # response (catches servers that don't emit
                # SPECIAL-USE but DO carry a sensible name).
                for candidate in _IMAP_SENT_FALLBACKS:
                    for line in decoded:
                        # Match the trailing quoted folder name; the
                        # LIST line shape is ``* LIST (<flags>)
                        # "<delim>" "<name>"`` so the candidate must
                        # equal the LAST quoted token (not appear
                        # anywhere on the line — that would match
                        # delimiter quirks).
                        match = re.search(
                            r'"([^"]*)"\s*$', line.rstrip(),
                        )
                        if match and match.group(1) == candidate:
                            return candidate, "name-match"
    except Exception as e:
        log.warning(
            "IMAP Sent folder LIST probe failed; falling back",
            error=type(e).__name__,
        )

    # Pass 2b — list_folders() fallback. Most IMAP providers expose a
    # parsed folder name list; pick the first candidate that exists.
    try:
        list_folders = getattr(provider, "list_folders", None)
        if list_folders is not None:
            folders = await list_folders()
            available = set(folders or [])
            for candidate in _IMAP_SENT_FALLBACKS:
                if candidate in available:
                    return candidate, "name-match"
    except NotImplementedError:
        # Provider doesn't implement folder listing — fall through to
        # the fixed default below. Not noisy.
        log.debug(
            "list_folders not implemented during Sent discovery",
        )
    except Exception as e:
        log.warning(
            "list_folders fallback failed during Sent discovery",
            error=type(e).__name__,
        )

    # Pass 3 — fixed default. The operator can override via the page
    # once it lands; until then ``Sent`` is the modal correct value
    # across the IMAP server population we've seen.
    return "Sent", "default"


# Cap on the number of sent-like candidates returned. Some IMAP servers
# can list hundreds of mailboxes; the picker only needs a manageable
# slice. 50 covers every observed operator setup (Gmail w/ IMAP shows
# 2-3, Exchange-via-IMAP shows 3-5, Dovecot installs with INBOX-prefix
# namespaces top out around 6).
_SENT_LIKE_CAP = 50


async def list_sent_like_folders(provider) -> list[str]:
    """Return every folder on ``provider`` whose name contains "sent".

    Case-insensitive substring match. Always includes the discovery
    pick (the value :func:`find_sent_folder` returns) at the FRONT of
    the list so the multi-select picker can mark it as the auto-
    discovered default. Subsequent matches keep the provider's order
    (alphabetical for IMAP via ``list_folders``, label-list order for
    Gmail, recursive-walk order for O365).

    Result is de-duplicated (case-sensitive — ``Sent`` and ``sent`` on
    the same provider are kept distinct because the IMAP / Gmail label
    APIs treat them as different folders) and capped at
    :data:`_SENT_LIKE_CAP` entries.

    Never raises. On a discovery failure the function returns at
    minimum the auto-discovered default (so the picker always has
    something to render).

    Provider-type dispatch mirrors :func:`find_sent_folder`:

      * **Gmail** — pulls labels via ``list_folders`` (which wraps
        ``users.labels.list``); the ``SENT`` system label is always
        present so it appears first.
      * **Office 365** — pulls top-level mail folders via
        ``list_folders`` if implemented; otherwise falls back to the
        canonical ``sentitems`` so the picker still has the
        well-known default.
      * **IMAP** — pulls folder names via ``list_folders`` (which
        wraps ``LIST "" "*"``); filters substring-match in Python.

    The caller is responsible for closing the provider connection.
    """
    name = getattr(provider, "name", "") or type(provider).__name__.lower()
    is_gmail = "gmail" in name.lower()
    is_o365 = "office365" in name.lower() or "o365" in name.lower()

    discovered = await find_sent_folder(provider)

    # Pull the full folder / label list. Any failure falls through to
    # returning just the discovered default so the picker still works.
    folders: list[str] = []
    try:
        list_folders = getattr(provider, "list_folders", None)
        if list_folders is not None:
            raw = await list_folders()
            folders = [f for f in (raw or []) if isinstance(f, str)]
    except NotImplementedError:
        # Architectural fallthrough — the provider hasn't implemented
        # folder listing yet (legacy O365 sessions, future providers).
        # Not an error; the well-known-folder pad below still gives
        # the picker at least one entry. Log at DEBUG so the page-load
        # path stays quiet.
        log.debug(
            "list_sent_like_folders: list_folders not implemented",
            provider=name,
        )
        folders = []
    except Exception as e:
        log.warning(
            "list_sent_like_folders: list_folders probe failed",
            provider=name,
            error=type(e).__name__,
        )
        folders = []

    # Case-insensitive substring filter.
    matched = [f for f in folders if "sent" in f.lower()]

    # On Gmail, list_folders includes user-created labels with arbitrary
    # case; ensure the canonical SENT system label is present.
    if is_gmail and "SENT" not in matched:
        matched.insert(0, "SENT")

    # On O365, list_folders is not implemented on the provider today;
    # ensure the well-known sentitems is available so the picker has
    # at least one entry.
    if is_o365 and "sentitems" not in matched:
        matched.insert(0, "sentitems")

    # Place the discovered default at the front; preserve insertion
    # order for the rest (de-dupe via seen-set).
    ordered: list[str] = []
    seen: set[str] = set()
    if discovered:
        ordered.append(discovered)
        seen.add(discovered)
    for f in matched:
        if f not in seen:
            ordered.append(f)
            seen.add(f)
        if len(ordered) >= _SENT_LIKE_CAP:
            break

    return ordered


def normalize_sent_folder_override(value) -> list[str]:
    """Coerce a stored ``sent_folder_override`` value into a list[str].

    Tolerates the pre-v19 scalar string shape and the post-v19 list
    shape. Empty / whitespace / None / unknown shapes collapse to the
    empty list so readers can treat "no override, discover at mine
    time" as a single condition (``not result``). Each surviving
    entry is stripped of surrounding whitespace; empty entries are
    dropped.

    Used by the capture-loop constructor in ``web/app.py``, the UI
    save handler, the ``_build_style_data_entry`` render helper, and
    the on-demand mine/preview handler — all of which read the same
    config-json key and need the same coercion contract.
    """
    if isinstance(value, str):
        s = value.strip()
        return [s] if s else []
    if isinstance(value, (list, tuple)):
        out: list[str] = []
        for item in value:
            if isinstance(item, str):
                s = item.strip()
                if s:
                    out.append(s)
        return out
    return []


__all__ = (
    "find_sent_folder",
    "list_sent_like_folders",
    "normalize_sent_folder_override",
)
