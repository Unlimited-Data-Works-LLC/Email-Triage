"""Shared offset-pagination primitive.

The silent-truncation audit (N-90) first made every capped list SHOW its
truncation ("showing N of M"). The operator then chose the complete
option: make the hidden rows REACHABLE, not just counted — so a HIPAA
§164.312(b) audit trail (and the retry-queue, bulk-runs, digest
candidates) can be paged through in full, not read as a 100-row subset.

This is the ONE pagination SSOT every paged surface uses, so the
offset/limit/total math and the "is there an older/newer page" predicates
can't drift across 8 hand-rolled copies. The companion Jinja macro lives
in ``templates/_pager.html`` and renders the newer/older links off a
``PageWindow`` while preserving the page's other query params.

Offset-based (not cursor) by design: it mirrors the existing ``/logs``
page (`list_log_entries(..., offset=...)`), the only paginated surface
that predates this.

Concurrency note (do NOT over-read this as "drift is immaterial"): the
audit tables are insert-only and ordered newest-first (``ORDER BY ts
DESC``). A row inserted between two page turns shifts the window by one,
so a boundary row CAN re-appear on the next page — but, because new rows
land at the TOP (offset 0) and we page toward older offsets, a row can
only be DUPLICATED across a page turn, never HIDDEN. For a §164.312(b)
review pass duplication is immaterial and no audit row becomes
unreachable; the HMAC log-chain (``verify_log_chain``), not the pager, is
the integrity control.
"""

from __future__ import annotations

from dataclasses import dataclass

from email_triage._int_utils import parse_int_or_none  # N-219c/14 R23


@dataclass(frozen=True)
class PageWindow:
    """One page's coordinates over a larger result set.

    ``total`` is the honest COUNT(*) denominator; ``offset`` is the 0-based
    start of this page; ``limit`` is the page size (the cap that used to
    silently truncate); ``shown`` is how many rows actually came back
    (``<= limit``; smaller on the last page)."""

    total: int
    offset: int
    limit: int
    shown: int

    @property
    def start(self) -> int:
        """1-based index of the first row shown (0 when the page is empty)."""
        return self.offset + 1 if self.shown else 0

    @property
    def end(self) -> int:
        """1-based index of the last row shown."""
        return self.offset + self.shown

    @property
    def has_newer(self) -> bool:
        """True when rows BEFORE this page exist (a 'newer' page back toward
        offset 0). Newest-first ordering ⇒ lower offset = newer."""
        return self.offset > 0

    @property
    def has_older(self) -> bool:
        """True when rows AFTER this page exist (an 'older' page). This is
        the predicate that, when False, proves the trail is fully shown."""
        return self.offset + self.shown < self.total

    @property
    def newer_offset(self) -> int:
        """Offset for the previous (newer) page, clamped at 0."""
        return max(0, self.offset - self.limit)

    @property
    def older_offset(self) -> int:
        """Offset for the next (older) page."""
        return self.offset + self.limit

    @property
    def truncated(self) -> bool:
        """True when more rows exist than this single page shows (older OR
        newer) — i.e. the list is paged at all. Drives the banner."""
        return self.has_older or self.has_newer


def clamp_offset(raw, limit: int, total: int) -> int:
    """Parse a user-supplied ``offset`` query param into a safe 0-based
    offset on a ``limit``-sized grid.

    Defends the SQL ``OFFSET ?`` against junk/negative/huge input: a
    non-int or negative value collapses to 0; an offset past ``total`` is
    pulled back to the last page boundary so "load older" past the end
    lands on the final page rather than an empty one. Snaps to a multiple
    of ``limit`` so the newer/older steps stay on a stable grid."""
    off = parse_int_or_none(raw)  # N-219c/14 R23: SSOT
    if off is None or off <= 0:
        return 0
    if limit > 0:
        off = (off // limit) * limit  # snap to the page grid
    if total > 0 and off >= total:
        # Land on the last page boundary, not an empty page past the end.
        last = ((total - 1) // limit) * limit if limit > 0 else 0
        off = max(0, last)
    return off


def page_window(*, total: int, offset: int, limit: int, shown: int) -> PageWindow:
    """Build a :class:`PageWindow` (keyword-only for call-site clarity)."""
    return PageWindow(
        total=int(total), offset=int(offset),
        limit=int(limit), shown=int(shown),
    )


def page_url(request, param: str, value) -> str:
    """Return this request's path with the query param ``param`` set to
    ``value``, preserving every OTHER query param.

    Registered as a Jinja global so the ``_pager.html`` macro can build a
    newer/older link for one of several pagers on a page without clobbering
    the other pagers' offsets. ``request`` is the Starlette ``Request`` in
    the template context. The value is str()-ed and URL-encoded."""
    from urllib.parse import urlencode
    # Multi-dict → list of (k, v) preserving repeats, with our param dropped
    # then re-added once at the chosen value.
    try:
        items = [
            (k, v) for (k, v) in request.query_params.multi_items()
            if k != param
        ]
    except Exception:
        items = []
    items.append((param, str(value)))
    qs = urlencode(items)
    path = request.url.path
    return f"{path}?{qs}" if qs else path
