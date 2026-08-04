"""Shared ISO-8601 timestamp parsing.

``datetime.fromisoformat`` only learned to accept a trailing ``Z`` in
Python 3.11; the ``fromisoformat(str(v).replace("Z", "+00:00"))`` idiom
papered over that and appeared ~34× across the codebase, each copy
re-deciding how to treat ``None`` / unparseable input. :func:`parse_iso`
is the single home for it.
"""

from __future__ import annotations

from datetime import datetime, timezone


def to_utc_iso(dt: datetime) -> str:
    """Format an aware datetime as the stored/comparable UTC ISO-8601 string —
    the SSOT for the ``.isoformat()`` FORMAT of a DERIVED timestamp (a cutoff,
    an expiry, a ``now + delta``), and the sibling of :func:`now_utc_iso` (which
    is just ``to_utc_iso(datetime.now(utc))``).

    Normalises to UTC first (``astimezone(timezone.utc)``), so a stored timestamp
    is ALWAYS UTC even if a caller hands in a non-UTC-aware ``dt`` — and it is
    byte-identical to a bare ``dt.isoformat()`` for the aware-UTC datetimes every
    call site uses today. A10 (divergence census): an inline
    ``(<aware-now> ± delta).isoformat()`` or a ``now = datetime.now(tz); now.isoformat()``
    re-decides the stored format at the call site, forking the SSOT — route it
    through here (or :func:`now_utc_iso` for a pure ``now``). Pinned by
    ``tests/test_now_iso_utc_pin_a10.py``."""
    return dt.astimezone(timezone.utc).isoformat()


def now_utc_iso() -> str:
    """Current time as a UTC-aware ISO-8601 string — the SSOT for stored
    /comparable timestamps (A10, divergence census 2026-06-09).

    Every DB column, dedup key, and audit row uses UTC. This collapsed 7
    identical ``_now_iso()`` copies that each returned
    ``datetime.now(timezone.utc).isoformat()`` — AND removed a confusable
    8th ``_now_iso`` (in ``mail_headers``) that returned LOCAL time under
    the same name, a tz-collision waiting to flip a comparison if the two
    were ever crossed. Display/human-facing timestamps use
    :func:`now_local_iso` (a DISTINCT name) instead. The FORMAT primitive is
    :func:`to_utc_iso` (byte-identical: UTC-aware ``now`` → no-op astimezone)."""
    return to_utc_iso(datetime.now(timezone.utc))


def to_utc_iso_z(dt: datetime) -> str:
    """SSOT for wire-format UTC ISO with a ``Z`` suffix
    (``2026-07-03T12:34:56.789012Z``) — microsecond-precision, ``Z``-suffixed
    UTC ISO-8601, sibling of :func:`to_utc_iso` (which emits the ``+00:00``
    form).

    Two convergent SSOT-consolidations landed on this same function under
    different N-numbers (census wf_56d1585d 2026-07-09 D3 — SSOT
    self-shadowing catch): originally introduced as N-278 R29 to replace 10
    hand-rolled ``dt.astimezone(timezone.utc).isoformat().replace("+00:00",
    "Z")`` sites across ``gmail_calendar.py`` + ``office365_calendar.py``
    (Google Calendar + O365 Graph ``timeMin`` / ``timeMax`` / ``dateTime``
    payloads); then a duplicate byte-identical def landed as N-364 R31 for
    the ``_arm_hmac_clobber_bypass`` payload's ``armed_at`` / ``expires_at``
    fields. Both consumers share ONE def now (this one).

    DISTINCT from :func:`now_utc_iso_z` (second precision, always ``now``) —
    this one preserves the caller's microseconds and accepts an arbitrary
    ``now + delta`` so a payload can stamp both fields off the same monotonic
    reference. Byte-identical to the previously inline pattern
    ``dt.isoformat().replace("+00:00", "Z")`` **when ``dt`` is already
    ``timezone.utc``-aware** (the ``.astimezone(timezone.utc)`` is a no-op in
    that case). For any other aware ``dt`` the helper CONVERTS to UTC first,
    which is the desired end-state — but callers migrating an inline site
    should confirm their ``dt`` was already UTC to avoid a subtle offset
    shift on the persisted value. Pinned by
    ``tests/test_now_iso_utc_pin_a10.py`` (only this module may hand-roll the
    inline pattern) AND ``tests/test_no_duplicate_toplevel_defs.py`` (this
    SSOT stays one def).
    """
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def now_utc_iso_z() -> str:
    """Current UTC time in the ``Z``-suffixed, SECOND-precision form
    ``2026-06-11T07:50:00Z`` — DISTINCT from :func:`now_utc_iso` (which is
    ``+00:00``-offset, microsecond precision). The one home for the
    ``schema_migrations.applied_at`` metadata column's wire format (migrations
    stamp it on every applied migration). Format-identical to the old inline
    ``time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())`` it replaced, so the
    column stays single-format (no mixed Z / +00:00 rows). A future second
    Z-form metadata timestamp must use THIS, not a fresh ``strftime``/``gmtime``
    — pinned by ``tests/test_now_iso_utc_pin_a10.py`` (no raw
    ``time.strftime(…, time.gmtime())`` outside this module). Both ``parse_iso``
    and ``datetime.fromisoformat`` accept the ``Z`` form, so it round-trips."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def now_local_iso() -> str:
    """Current time as a LOCAL-tz-aware ISO-8601 string — for HUMAN-facing
    display only (e.g. the ``X-Email-Triage: generated=`` header stamp,
    matching the ``last_triage`` render style). Never a stored/compared
    key — those use :func:`now_utc_iso`. The distinct name is the point:
    it can't be mistaken for the UTC ``_now_iso`` (A10)."""
    return datetime.now().astimezone().isoformat()


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


def assume_utc_if_naive(dt: "datetime | None") -> "datetime | None":
    """N-357b R31 (2026-07-06 trust-repair fix-forward, tranche 3) — SSOT
    for the "I already hold a datetime; if it's naive, stamp UTC" idiom.

    Sibling of :func:`parse_iso_aware`: same assume-UTC-on-naive posture,
    but for callers that HAVE a datetime (from ``parsedate_to_datetime``,
    ``cert.not_valid_after_utc``, upstream provider payloads, etc.) —
    NOT a string. ``parse_iso_aware`` parses first; this one skips the
    parse. Both funnel through this exact stamping shape so an inline
    change to the naive-assume posture would need to touch only these
    two functions.

    Contract:
        None → None; aware → returned as-is; naive → stamped
        ``timezone.utc``. Never raises.

    Pinned by ``tests/test_n357_parse_iso_aware_ssot_pin.py`` — a new
    inline ``if X.tzinfo is None: X = X.replace(tzinfo=<utc>)`` outside
    ``_isotime.py`` is a baseline defect.
    """
    if dt is not None and dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def parse_iso_aware(val: object) -> datetime | None:
    """N-357 R31 (2026-07-05 trust-repair fix-forward per PHASE2 tranche
     db-sme +  hipaa-sme + the backlog  = TASK ) — SSOT for
    the "parse an ISO string; guarantee the result is tz-aware, assume
    UTC on naive" idiom.

    Collapses 3 inline shim sites:

    * ``web/auth.py:170-176`` (N-302 R30) — session-expiry parse
    * ``web/auth.py:600-603`` (N-302 R30 second site) — API-token expiry
    * ``web/poll_ingestion.py:563-569`` (N-305 R30) — last-poll cursor

    All three previously did::

        dt = parse_iso(raw)
        if dt is not None and dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)

    which drifts across sites (an inline change to the assume-UTC
    posture would need to touch every site). This SSOT owns the shape:
    None-in → None-out; unparseable → None; naive → stamped UTC;
    tz-aware → returned as-is.

    Behavioural contract identical to the 3 inline shims — safe drop-in
    replacement. A same-change AST pin at
    ``tests/test_n357_parse_iso_aware_ssot_pin.py`` bans a new naive-
    assume-UTC pair outside this SSOT.
    """
    dt = parse_iso(val)
    if dt is not None and dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def to_utc_iso_no_suffix(dt: datetime) -> str:
    """N-278 R29 — SSOT sibling for the O365 `dateTime` field which
    requires NO offset suffix (the timezone rides in a companion
    `timeZone` field). Replaced 2 hand-rolled sites (empty replacement)."""
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "")


def now_local_date_header(when: "datetime | None" = None) -> str:
    """N-269 R28 / N-287 R30 — Human date header (`"Wednesday, January 03, 2026"`)
    in the operator's LOCAL timezone. Digest emissions use this so a
    Sunday afternoon PDT render doesn't produce "Monday" (which UTC
    would show); this class of drift is the R28 census #4 finding
    with 3 sibling sites (2 already local; 1 UTC-derived at
    `web/digest.py:457`).

    Format: `"%A, %B %d, %Y"` (full weekday + long month + zero-padded
    day + 4-digit year). Locale-independent (English weekday/month
    per strftime default). Timezone: system local.

    N-287 R30: `when` optional override — pass a specific `datetime`
    to render its date-header (test seams + callers that already own
    the reference-time). Default: current system time.
    """
    if when is not None:
        # If the caller-supplied datetime is already tz-aware, respect
        # it; if naive, treat as local per the fn's contract.
        return (when if when.tzinfo else when).strftime("%A, %B %d, %Y")
    return datetime.now().astimezone().strftime("%A, %B %d, %Y")


def parse_iso_date(val: object):
    """N-269 R28 — sibling of :func:`parse_iso` for date-only ISO
    strings (`"YYYY-MM-DD"`). Returns a :class:`date` or ``None`` on
    parse failure. Handles the `T00:00:00`/`T…Z` common shape by
    routing through :func:`parse_iso` first and returning `.date()`.
    """
    from datetime import date as _date
    if not val:
        return None
    s = str(val)
    try:
        return _date.fromisoformat(s[:10])
    except (TypeError, ValueError):
        parsed = parse_iso(s)
        return parsed.date() if parsed is not None else None
