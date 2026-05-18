"""Provider-agnostic mail-query language (#138.3).

Three providers (IMAP, Gmail API, Office 365) each carried their own
``_translate_filter`` + ``_translate_query`` pair, with subtle drift
between them — e.g. Gmail's translator recognised an ``ALL`` token
(IMAP idiom for "every message") and dropped it; O365's didn't, so
``ALL`` would land in the Graph ``$search`` clause and match the word
"ALL" in messages. The drift came from the same code being copied
between providers and patched independently.

This module hosts:

* :func:`parse_imap_query` — best-effort IMAP-shape query string
  parser. Recognises the tokens the digest + triage handlers
  currently emit (``UNSEEN`` / ``SEEN`` / ``ALL`` / ``SINCE`` /
  ``BEFORE``) and produces a partially-populated ``MailFilter``
  AST plus any leftover tokens. Tokens already in provider-native
  shape (``is:unread``, ``after:2026/04/16``, OData clauses, etc.)
  pass through as raw remainder for the emitter to handle.

* :func:`emit_gmail` / :func:`emit_imap` / :func:`emit_o365` —
  per-provider emitters that take a ``MailFilter`` plus a raw-query
  remainder and produce the wire-format string the provider expects.

The provider's existing ``_translate_filter`` and ``_translate_query``
methods now delegate to these. Existing tests against the translators
stay green because the emitter output for the corpus of test queries
matches byte-for-byte (the parser's ``ALL`` handling for O365 was
deliberately fixed — that was a bug, not behaviour to preserve).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any

# ---------------------------------------------------------------------------
# Token recognition
# ---------------------------------------------------------------------------

_MON_MAP = {
    "JAN": "01", "FEB": "02", "MAR": "03", "APR": "04",
    "MAY": "05", "JUN": "06", "JUL": "07", "AUG": "08",
    "SEP": "09", "OCT": "10", "NOV": "11", "DEC": "12",
}
_DATE_RE = re.compile(r"^(\d{1,2})-([A-Za-z]{3})-(\d{4})$")


@dataclass
class ParsedQuery:
    """Partially-translated query.

    ``flags`` carries the high-level flags we recognised from the
    raw query (currently only ``unread`` — True for ``UNSEEN``,
    False for ``SEEN``). ``after`` / ``before`` carry parsed dates.
    ``remainder`` is the leftover token list the emitter passes
    through unchanged.
    """

    flags: dict[str, Any]
    after: datetime | None
    before: datetime | None
    remainder: list[str]
    # ``imap_all`` is True if the original query was the bare token
    # ``ALL`` (RFC 3501 idiom for "every message"). Gmail / Graph
    # have no equivalent — emitters drop it. IMAP keeps it as-is.
    imap_all: bool = False


def parse_imap_query(query: str) -> ParsedQuery:
    """Parse an IMAP-shape query string into the AST.

    The parser is intentionally permissive: tokens it doesn't
    recognise pass through to ``remainder`` so per-provider
    syntax (``is:unread`` for Gmail, ``isRead eq false`` for OData)
    can flow through unchanged when callers feed already-translated
    queries back through the wrapper.
    """
    if not query:
        return ParsedQuery(
            flags={}, after=None, before=None, remainder=[], imap_all=False,
        )

    tokens = query.split()
    flags: dict[str, Any] = {}
    after: datetime | None = None
    before: datetime | None = None
    remainder: list[str] = []
    imap_all = False

    i = 0
    while i < len(tokens):
        tok = tokens[i]
        upper = tok.upper()
        if upper == "UNSEEN":
            flags["unread"] = True
        elif upper == "SEEN":
            flags["unread"] = False
        elif upper == "ALL":
            imap_all = True
        elif upper in ("SINCE", "BEFORE") and i + 1 < len(tokens):
            raw = tokens[i + 1]
            m = _DATE_RE.match(raw)
            if m:
                dd = int(m.group(1))
                mon = _MON_MAP.get(m.group(2).upper())
                yyyy = int(m.group(3))
                if mon:
                    try:
                        dt = datetime(yyyy, int(mon), dd)
                    except ValueError:
                        dt = None
                    if dt is not None:
                        if upper == "SINCE":
                            after = dt
                        else:
                            before = dt
                        i += 2
                        continue
            # Date didn't parse — pass both tokens through.
            remainder.append(tok)
            remainder.append(tokens[i + 1])
            i += 2
            continue
        else:
            # Unknown token — pass through to emitter.
            remainder.append(tok)
        i += 1

    return ParsedQuery(
        flags=flags, after=after, before=before,
        remainder=remainder, imap_all=imap_all,
    )


# ---------------------------------------------------------------------------
# Filter → wire format
# ---------------------------------------------------------------------------

def emit_imap_filter(filt) -> str:
    """MailFilter → RFC 3501 IMAP SEARCH criteria.

    Caller switches mailboxes for ``filt.folder``; the rest become
    space-separated criteria. Unknown / unsupported fields are
    silently dropped — IMAP servers vary in keyword support.
    """
    if filt is None or filt.is_empty():
        return ""
    parts: list[str] = []
    if filt.unread is True:
        parts.append("UNSEEN")
    elif filt.unread is False:
        parts.append("SEEN")
    if filt.label:
        parts.append(f"KEYWORD {filt.label}")
    if filt.from_addr:
        parts.append(f'FROM "{filt.from_addr}"')
    if filt.to_addr:
        parts.append(f'TO "{filt.to_addr}"')
    if filt.subject:
        parts.append(f'SUBJECT "{filt.subject}"')
    if filt.after is not None:
        parts.append(f"SINCE {filt.after.strftime('%d-%b-%Y')}")
    if filt.before is not None:
        parts.append(f"BEFORE {filt.before.strftime('%d-%b-%Y')}")
    return " ".join(parts)


def emit_gmail_filter(filt) -> str:
    """MailFilter → Gmail search-operator string."""
    if filt is None or filt.is_empty():
        return ""
    parts: list[str] = []
    if filt.unread is True:
        parts.append("is:unread")
    elif filt.unread is False:
        parts.append("is:read")
    if filt.label:
        parts.append(f"label:{filt.label}")
    if filt.folder:
        parts.append(f"in:{filt.folder}")
    if filt.from_addr:
        parts.append(f"from:{filt.from_addr}")
    if filt.to_addr:
        parts.append(f"to:{filt.to_addr}")
    if filt.subject:
        sub = filt.subject
        if " " in sub:
            sub = f'"{sub}"'
        parts.append(f"subject:{sub}")
    if filt.after is not None:
        parts.append(f"after:{filt.after.strftime('%Y/%m/%d')}")
    if filt.before is not None:
        parts.append(f"before:{filt.before.strftime('%Y/%m/%d')}")
    return " ".join(parts)


def emit_o365_filter(filt) -> str:
    """MailFilter → Graph OData $filter string."""
    if filt is None or filt.is_empty():
        return ""
    clauses: list[str] = []
    if filt.unread is True:
        clauses.append("isRead eq false")
    elif filt.unread is False:
        clauses.append("isRead eq true")
    if filt.label:
        clauses.append(f"categories/any(c:c eq '{filt.label}')")
    if filt.from_addr:
        clauses.append(f"from/emailAddress/address eq '{filt.from_addr}'")
    if filt.to_addr:
        clauses.append(
            f"toRecipients/any(r:r/emailAddress/address eq '{filt.to_addr}')"
        )
    if filt.subject:
        esc = filt.subject.replace("'", "''")
        clauses.append(f"contains(subject,'{esc}')")
    if filt.after is not None:
        clauses.append(
            f"receivedDateTime ge {filt.after.strftime('%Y-%m-%dT%H:%M:%SZ')}"
        )
    if filt.before is not None:
        clauses.append(
            f"receivedDateTime lt {filt.before.strftime('%Y-%m-%dT%H:%M:%SZ')}"
        )
    return " and ".join(clauses)


# ---------------------------------------------------------------------------
# Raw IMAP-shape query → provider-native via parse-then-emit
# ---------------------------------------------------------------------------

def translate_imap_query_to_imap(query: str) -> str:
    """IMAP shortcuts → IMAP SEARCH criteria.

    Existing IMAP behaviour (mostly identity) preserved: ``is:unread``
    becomes ``UNSEEN``, otherwise pass through.
    """
    q = query.strip()
    if q == "is:unread":
        return "UNSEEN"
    if q.startswith("is:unread "):
        rest = q[len("is:unread "):].strip()
        return f"UNSEEN {rest}"
    return q


def translate_imap_query_to_gmail(query: str) -> str:
    """IMAP-shape query → Gmail ``q=`` string.

    ``UNSEEN`` / ``SEEN`` / ``ALL`` / ``SINCE <date>`` / ``BEFORE
    <date>`` are recognised; everything else passes through.
    """
    parsed = parse_imap_query(query)
    out: list[str] = []
    unread = parsed.flags.get("unread")
    if unread is True:
        out.append("is:unread")
    elif unread is False:
        out.append("is:read")
    if parsed.after is not None:
        out.append(f"after:{parsed.after.strftime('%Y/%m/%d')}")
    if parsed.before is not None:
        out.append(f"before:{parsed.before.strftime('%Y/%m/%d')}")
    out.extend(parsed.remainder)
    # ``ALL`` drops — Gmail's equivalent is an empty q=.
    return " ".join(out)


def translate_imap_query_to_o365(query: str) -> str:
    """IMAP shortcuts → OData ``$filter``.

    Returns an OData filter string, or empty string to signal that
    ``$search`` should be used instead. Same shape as the original
    :meth:`Office365Provider._translate_query` (preserved verbatim
    so existing tests stay green).
    """
    q = query.strip()
    if q == "is:unread":
        return "isRead eq false"
    if q.startswith("is:unread "):
        rest = q[len("is:unread "):].strip()
        return f"isRead eq false and {rest}"
    if q.startswith("from:"):
        addr = q[5:].strip()
        return f"from/emailAddress/address eq '{addr}'"
    odata_keywords = ("eq ", "ne ", "gt ", "lt ", "ge ", "le ", " and ", " or ")
    if any(kw in q.lower() for kw in odata_keywords):
        return q
    return ""
