"""Stdlib-imaplib body-fetch fallback for the IMAP provider.

Layer 3 of the aioimaplib bug mitigation (see
``memory/bug_aioimaplib_recursion.md``). aioimaplib's
``FetchCommand.wait_data()`` counts parens across the literal
payload of a FETCH response, so any literal whose bytes contain
unbalanced parens (HTML body, MIME signature, RFC 5322 Subject —
which is an unstructured field with no comment-balance
requirement) corrupts the parser state. The recursion fix in
``_aioimaplib_patch`` removed one symptom; the parens-counting
defect remains and isn't easy to fix without invasive surgery on
upstream's state machine.

This module sidesteps the parser entirely for fetch operations.
We use Python's stdlib ``imaplib.IMAP4_SSL`` — sync and blocking,
but battle-tested for decades — and wrap each call in
``asyncio.to_thread`` so the caller's await contract is
preserved.

aioimaplib still owns IDLE (long-poll; no fetch literals) and
SEARCH (no literal payload). Only the body / header literal
fetch path migrates here.

Key design points:

- **Connection per fetch** (not pooled). The blocking backend is
  spun up + torn down inside ``asyncio.to_thread`` per call.
  Connection establishment costs ~50-200ms (TLS handshake +
  LOGIN), but bulk-list calls are serialised behind a
  ``MailFilter`` search anyway, and the fetch fan-out is bounded
  by ``push.bulk_max_batch_size`` (default 50). Pooling can be
  added if real workloads show it's worth the complexity.
- **No state in this module.** Each call is a self-contained
  unit. The only persistent state is the credentials passed in
  by the caller.
- **Returns raw bytes + flags.** Parsing into ``EmailMessage`` is
  the caller's job; this module just hands back what stdlib
  imaplib produced. Matches the data shape that
  ``ImapProvider._extract_message_bytes`` expects (after the
  caller adapts list-of-tuples → list-of-flat-items).
"""

from __future__ import annotations

import asyncio
import imaplib
import re
from typing import Tuple


# Strip ``\Recent`` from FLAGS — it's a session-only flag (RFC 3501
# § 2.3.2) and including it confuses some downstream loop-detect
# heuristics that key on "set of persistent labels".
_FLAGS_RE = re.compile(rb"FLAGS \(([^)]*)\)")

# LIST response shape: (\\flags) "delim" "name" — name in the LAST
# group, optionally quoted. Hierarchy delimiter (group 1) ignored
# here; we just need the mailbox name to drive SELECT.
_LIST_NAME_RE = re.compile(r'"[^"]?"\s+"?([^"]+?)"?\s*$')


def _quote_mailbox(name: str) -> str:
    """Wrap a mailbox name for the IMAP wire when needed.

    stdlib :mod:`imaplib` doesn't quote mailbox names automatically.
    Names with whitespace, quotes, or backslash MUST be quoted per
    RFC 3501 § 4.3 (string syntax). Names that are pure atom
    characters (letters, digits, dots, slashes) can go bare. We
    over-quote slightly for safety: any name with whitespace OR a
    char outside the safe atom set gets wrapped + escaped.
    """
    safe = set(
        "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "0123456789"
        "._-/"
    )
    if name and all(c in safe for c in name):
        return name
    escaped = name.replace("\\", "\\\\").replace('"', '\\"')
    return '"' + escaped + '"'


def _blocking_fetch(
    *,
    host: str,
    port: int,
    use_ssl: bool,
    username: str,
    password: str,
    mailbox: str,
    uid: str,
    headers_only: bool,
) -> Tuple[bytes, list[str]]:
    """Fetch one message by UID via stdlib ``imaplib``.

    Runs synchronously — caller is responsible for putting this
    behind ``asyncio.to_thread`` (or equivalent) when invoking
    from async code. Opens a fresh IMAP connection, logs in,
    selects the mailbox, fetches one UID with the appropriate
    BODY.PEEK section, parses out raw message bytes + flags, and
    closes the connection cleanly.

    Returns ``(raw_message_bytes, flag_list)``.

    Raises:
        RuntimeError: on protocol-level failure (login refused,
        SELECT failure, FETCH non-OK, or unparseable response
        shape). The caller wraps this in the provider's own
        error semantics.
    """
    if use_ssl:
        client = imaplib.IMAP4_SSL(host, port)
    else:
        client = imaplib.IMAP4(host, port)

    try:
        typ, _ = client.login(username, password)
        if typ != "OK":
            raise RuntimeError(
                f"IMAP LOGIN refused: {typ}"
            )

        # stdlib imaplib doesn't auto-quote mailbox names with spaces
        # or other special chars; we have to do it ourselves.
        # Hierarchy delimiters (".", "/") are fine bare; only the
        # presence of whitespace / quotes / backslash forces quoting.
        typ, _ = client.select(_quote_mailbox(mailbox), readonly=True)
        if typ != "OK":
            raise RuntimeError(
                f"IMAP SELECT {mailbox!r} failed: {typ}"
            )

        section = (
            "(BODY.PEEK[HEADER] FLAGS)"
            if headers_only
            else "(BODY.PEEK[] FLAGS)"
        )
        typ, data = client.uid("FETCH", uid, section)
        if typ != "OK":
            raise RuntimeError(
                f"IMAP UID FETCH {uid} failed: {typ}"
            )

        # imaplib's response shape for a single-UID fetch:
        #   data = [
        #       (b'1 (UID 99 BODY[HEADER] {123}', b'<header bytes>'),
        #       b' FLAGS (\\Seen))',
        #   ]
        # or sometimes flat with the FLAGS folded into the tuple.
        # We extract: (a) the literal payload bytes (header or
        # full body) and (b) FLAGS list.
        raw_bytes = b""
        flag_blob = b""
        for item in data:
            if isinstance(item, tuple):
                # tuple = (response_line, literal_payload).
                if len(item) >= 2 and isinstance(item[1], (bytes, bytearray)):
                    raw_bytes = bytes(item[1])
                if isinstance(item[0], (bytes, bytearray)):
                    flag_blob += bytes(item[0])
            elif isinstance(item, (bytes, bytearray)):
                flag_blob += bytes(item)

        # When raw_bytes is empty after parsing, the IMAP server
        # returned ``data=[None]`` — typically means the requested
        # UID does not exist in the SELECTed mailbox. This happens
        # when a caller passes a UID from one folder while ``mailbox``
        # selects another (UIDs are mailbox-scoped per RFC 3501
        # § 2.3.1.1). The fix is at the call site — pass ``folder=``
        # to fetch_message_blocking matching the search's folder.
        # We do NOT raise here so the caller still gets a valid
        # (raw_bytes, flags) tuple; the empty bytes parse cleanly
        # into an empty EmailMessage downstream, and the IMAP
        # fetch_message wrapper's MIME-shape WARNING surfaces the
        # mismatch for diagnostic.

        flags: list[str] = []
        match = _FLAGS_RE.search(flag_blob)
        if match:
            tokens = match.group(1).decode("ascii", errors="replace").split()
            flags = [t for t in tokens if t and t != r"\Recent"]

        return raw_bytes, flags

    finally:
        try:
            client.logout()
        except Exception:
            # Server may have already closed; not fatal.
            pass


async def fetch_message_blocking(
    *,
    host: str,
    port: int,
    use_ssl: bool,
    username: str,
    password: str,
    mailbox: str,
    uid: str,
    headers_only: bool = False,
) -> Tuple[bytes, list[str]]:
    """Async wrapper — runs :func:`_blocking_fetch` in a thread.

    The thread pool is asyncio's default executor. Bulk-fetch
    callers fan out concurrently via ``asyncio.gather``; each
    coroutine ends up on a distinct thread, which is fine since
    each opens its own IMAP connection (no shared state to
    contend on). Bounded by the executor's max-workers default
    (min(32, cpu_count + 4) on Python 3.13).
    """
    return await asyncio.to_thread(
        _blocking_fetch,
        host=host,
        port=port,
        use_ssl=use_ssl,
        username=username,
        password=password,
        mailbox=mailbox,
        uid=uid,
        headers_only=headers_only,
    )


def _blocking_search_all_folders(
    *,
    host: str,
    port: int,
    use_ssl: bool,
    username: str,
    password: str,
    criteria: str,
    limit: int,
) -> list[tuple[str, str]]:
    """Cross-folder UID search via stdlib imaplib.

    LISTs mailboxes, EXAMINEs each (read-only), runs UID SEARCH
    with the given RFC 3501 criteria, accumulates ``(folder, uid)``
    pairs up to ``limit``. Skips folders that fail SELECT or
    SEARCH (auth, ``\\Noselect`` parents, encoding mismatches) —
    partial coverage beats one bad folder blowing the whole call.

    Why blocking imaplib instead of aioimaplib: the same parser
    defects that drove the fetch path off aioimaplib also affect
    SEARCH responses across folder hierarchies. stdlib imaplib
    streams bytes directly to the consumer without trying to parse
    FETCH-shaped responses, so the parens-counting and recursion
    bugs (upstream issue #118) don't apply. One TLS connection per
    cross-folder call; folder-loop happens in-process.
    """
    if use_ssl:
        client = imaplib.IMAP4_SSL(host, port)
    else:
        client = imaplib.IMAP4(host, port)

    pairs: list[tuple[str, str]] = []
    try:
        typ, _ = client.login(username, password)
        if typ != "OK":
            raise RuntimeError(f"IMAP LOGIN refused: {typ}")

        typ, list_data = client.list()
        if typ != "OK":
            raise RuntimeError(f"IMAP LIST failed: {typ}")

        folder_names: list[str] = []
        for raw in list_data:
            if not isinstance(raw, (bytes, bytearray)):
                continue
            line = bytes(raw).decode(errors="replace")
            # LIST response: (\\flags) "delim" "name"
            # Skip \Noselect parents — can't EXAMINE them.
            if "\\Noselect" in line:
                continue
            m = _LIST_NAME_RE.search(line)
            if m:
                folder_names.append(m.group(1))

        # Quote each name for IMAP wire (see :func:`_quote_mailbox`).
        for fname in folder_names:
            try:
                typ, _ = client.select(
                    _quote_mailbox(fname), readonly=True,
                )
                if typ != "OK":
                    continue
            except Exception:
                continue

            try:
                # uid("SEARCH", ...) returns matching UIDs directly.
                # Per RFC 3501 § 6.4.4 the criteria string is the
                # rest of the SEARCH command after the keyword.
                if criteria:
                    typ, search_data = client.uid(
                        "SEARCH", None, criteria,
                    )
                else:
                    typ, search_data = client.uid(
                        "SEARCH", None, "ALL",
                    )
                if typ != "OK":
                    continue
            except Exception:
                continue

            for raw in search_data:
                if not isinstance(raw, (bytes, bytearray)):
                    continue
                tokens = bytes(raw).split()
                for tok in tokens:
                    if tok.isdigit():
                        pairs.append((fname, tok.decode("ascii")))
                        if len(pairs) >= limit:
                            break
                if len(pairs) >= limit:
                    break
            if len(pairs) >= limit:
                break

        return pairs

    finally:
        try:
            client.logout()
        except Exception:
            pass


async def search_all_folders_blocking(
    *,
    host: str,
    port: int,
    use_ssl: bool,
    username: str,
    password: str,
    criteria: str,
    limit: int,
) -> list[tuple[str, str]]:
    """Async wrapper around :func:`_blocking_search_all_folders`.

    Single ``asyncio.to_thread`` so the whole LIST+SELECT+SEARCH
    cycle runs on one stdlib imaplib connection in a worker
    thread. The caller can then fan-out fetches concurrently
    (each fetch opens its own connection per
    :func:`fetch_message_blocking`), so the search→fetch pipeline
    parallelises naturally.
    """
    return await asyncio.to_thread(
        _blocking_search_all_folders,
        host=host,
        port=port,
        use_ssl=use_ssl,
        username=username,
        password=password,
        criteria=criteria,
        limit=limit,
    )
