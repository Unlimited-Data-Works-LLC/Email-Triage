"""Shared ISO-8601 timestamp parsing.

``datetime.fromisoformat`` only learned to accept a trailing ``Z`` in
Python 3.11; the ``fromisoformat(str(v).replace("Z", "+00:00"))`` idiom
papered over that and appeared ~34× across the codebase, each copy
re-deciding how to treat ``None`` / unparseable input. :func:`parse_iso`
is the single home for it.
"""

from __future__ import annotations

from datetime import datetime


def parse_iso(val: object) -> datetime | None:
    """Parse an ISO-8601 timestamp into a :class:`datetime`, or ``None``.

    Returns ``None`` for ``None`` / empty / unparseable input rather
    than raising — every call site that used the idiom treated a parse
    failure as "unknown timestamp". A trailing ``Z`` is normalised to
    ``+00:00``. The result keeps whatever tz-awareness the input carried
    (a naive input stays naive — callers that need UTC stamp it
    themselves, exactly as before).
    """
    if not val:
        return None
    try:
        return datetime.fromisoformat(str(val).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
