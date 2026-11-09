"""US-locale display formatter for timestamps (2026-07-13, operator ask).

Renders `datetime` / ISO-8601 strings as ``7/13/2026 9:12:33 AM EDT`` for
operator-facing surfaces. Internal storage stays ISO-8601 UTC (per
`feedback_dynamic_over_hardcoding` + audit-log HMAC integrity — this
module is DISPLAY ONLY and must NOT be written back into stored values).

Two entry points:

* :func:`format_us_datetime(dt_or_iso)` — Python API used by
  server-rendered surfaces (email digests, Signal messages, JSON
  fields whose consumer is a human, not a machine).
* Jinja filter ``{{ ts | us_datetime }}`` — registered in
  ``web/app.py`` so templates can format inline.

The **browser-side** twin lives in ``web/templates/base.html`` as a JS
helper that walks every ``[data-us-datetime]`` element after DOM load
and rewrites its text using the VIEWER'S timezone. Templates that want
viewer-local (vs. server-local) rendering emit::

    <time datetime="{{ ts.isoformat() }}" data-us-datetime>
        {{ ts | us_datetime }}
    </time>

That way the SERVER renders a defensible fallback (works with JS off,
in email clients, in print) and the CLIENT enhances to viewer-local
when JS is available. Both use the SAME format shape.

**Date-only values are calendar dates, not instants** (punch 607). A
``YYYY-MM-DD`` value such as a BAA expiry has no time and no zone: read
as UTC midnight and shifted west it renders the PREVIOUS day
(``2026-12-31`` showed as ``12/30/2026 7:00 PM EST``). Such values render
as ``M/D/YYYY`` with no time and no zone conversion, through
:func:`format_us_date` / the ``us_date`` filter, and in the browser
through ``<time datetime="YYYY-MM-DD" data-us-date>``. The date is read
the same way the BAA gate reads it (``_isotime.parse_iso_date``), so
the page and the gate cannot disagree about which day it is.
:func:`format_us_datetime` also routes a date-only input to the date
path, so a site that was not migrated still shows the right day.

Explicitly OUT-OF-SCOPE for this filter (they stay ISO-8601 by design):
* ``log_entries`` audit-chain rows — timestamps are HMAC-signed, PD .
* Machine-consumed JSON keys (``/health/detail`` for the monitoring system). the monitoring system
  parses ISO-8601; a locale-format change breaks the monitor.
* Internal storage (SQLite `INSERT`s, JSON `state` columns, etc.).
"""

from __future__ import annotations

import re
from datetime import date, datetime
from typing import Any

from email_triage._isotime import parse_iso_aware, parse_iso_date


# A date-only value: exactly ``YYYY-MM-DD``, nothing after it. Detected
# by SHAPE before any parse, because ``parse_iso_date`` reads the first
# ten characters and would also accept a full ISO datetime.
_DATE_ONLY_RE = re.compile(r"\s*\d{4}-\d{2}-\d{2}\s*")


def _is_date_only(value: Any) -> bool:
    if isinstance(value, datetime):
        return False
    if isinstance(value, date):
        return True
    return isinstance(value, str) and _DATE_ONLY_RE.fullmatch(value) is not None


def _to_server_local(dt: datetime) -> datetime:
    """Convert an aware datetime to server-local time FOR THAT INSTANT.

    ``astimezone()`` with no argument asks the C library for the local
    offset at ``dt`` itself, so January renders in standard time and July
    in daylight time. The zone comes from the same place the previous
    import-time read used (``TZ`` / ``/etc/localtime``, which the deploy
    binds in), so the zone does not change, only the offset becomes
    per-instant.

    Punch 607: the previous shape captured
    ``datetime.now().astimezone().tzinfo`` once at import. That is a
    FIXED-offset ``timezone``, not a zone, so a process started in July
    rendered every January timestamp an hour off and labelled it EDT.
    """
    return dt.astimezone()


def _zone_abbrev(local: datetime) -> str:
    """The zone label for ``local``: ``EST`` / ``EDT`` / ``UTC``.

    Windows reports long names (``Eastern Standard Time``); those are
    reduced to their initials, the same rule the browser walker in
    ``base.html`` applies, so both sides print the same label.
    """
    name = local.strftime("%Z") or ""
    if " " in name.strip():
        return "".join(w[0] for w in name.split() if w)
    return name


def _coerce(value: Any) -> datetime | None:
    """Best-effort conversion of ``value`` to a tz-aware datetime.

    Delegates to :func:`email_triage._isotime.parse_iso_aware` — the N-357
    SSOT for "parse ISO-8601 → tz-aware datetime (assume UTC on naive)".
    That SSOT covers both:
      * the trailing-``Z`` external-API form Gmail / MS Graph write
        (bare ``datetime.fromisoformat`` raises on that shape — N-263)
      * the naive-datetime tz-assume-utc shim (N-357)
    Hand-rolling either is a pin violation; the shared SSOT is the
    only permitted implementation. See docstring of
    :func:`email_triage._isotime.parse_iso_aware`.
    """
    return parse_iso_aware(value)


def format_us_datetime(value: Any, *, tz: Any = None) -> str:
    """Format ``value`` as ``M/D/YYYY H:MM:SS AM/PM TZ`` (US-locale).

    Args:
        value: A ``datetime``, ISO-8601 string, or ``None`` / empty.
        tz: Optional target timezone. Default = server-local, with the
            offset computed for each instant (DST-correct).

    Returns:
        The formatted string, e.g. ``"7/13/2026 9:12:33 AM EDT"``.
        Returns ``"—"`` for a ``None`` / empty / unparseable input so
        templates can drop the value directly without a ``or "—"`` dance.
        A date-only input (a ``date`` or a ``YYYY-MM-DD`` string) is a
        calendar date, not an instant: it is returned as ``M/D/YYYY`` by
        :func:`format_us_date`, with no time and no zone shift.

    The format shape mirrors the operator spec 2026-07-13:
    ``7/13/2026 9:12:33 AM EDT`` — full precision incl. seconds so
    admin surfaces can distinguish events within the same minute.
    """
    if _is_date_only(value):
        return format_us_date(value)
    dt = _coerce(value)
    if dt is None:
        return "—"
    local = dt.astimezone(tz) if tz is not None else _to_server_local(dt)
    # ``%-m``/``%-d`` (no zero-pad) is POSIX-only; on Windows we need
    # ``%#m``/``%#d``. Do the strip-lead-zero manually so the same
    # code works on every host.
    month = local.month
    day = local.day
    year = local.year
    hour_24 = local.hour
    hour_12 = hour_24 % 12 or 12
    ampm = "AM" if hour_24 < 12 else "PM"
    tz_abbrev = _zone_abbrev(local)
    return (
        f"{month}/{day}/{year} "
        f"{hour_12}:{local.minute:02d}:{local.second:02d} {ampm}"
        + (f" {tz_abbrev}" if tz_abbrev else "")
    )


def format_us_date(value: Any) -> str:
    """Format a calendar date as ``M/D/YYYY``: no time, no zone shift.

    For values that name a DAY rather than an instant, such as a BAA
    expiry entered through ``<input type="date">``. A string is read
    through ``_isotime.parse_iso_date``, the parser the BAA gate
    (``baa_expiry._parse_expiry``) uses, so the displayed day is the day
    the gate acts on. A ``datetime`` keeps its own calendar fields; it is
    not converted to another zone first.

    Returns ``"—"`` for ``None`` / empty / unparseable input, matching
    :func:`format_us_datetime`.
    """
    if isinstance(value, datetime):
        d: date | None = value.date()
    elif isinstance(value, date):
        d = value
    else:
        d = parse_iso_date(value.strip() if isinstance(value, str) else value)
    if d is None:
        return "—"
    return f"{d.month}/{d.day}/{d.year}"


def us_datetime_filter(value: Any) -> str:
    """Jinja filter wrapper. Registered via :func:`install_filter`."""
    return format_us_datetime(value)


def us_date_filter(value: Any) -> str:
    """Jinja ``us_date`` filter. Registered via :func:`install_filter`."""
    return format_us_date(value)


def install_filter(env: Any) -> None:
    """Register the ``us_datetime`` filter on a Jinja Environment.

    Every code path that instantiates a Jinja ``Environment`` intended to
    render templates from this repo MUST call this helper — otherwise
    templates using ``{{ x | us_datetime }}`` raise ``TemplateRuntimeError:
    No filter named 'us_datetime' found``. The registration used to live
    inline in ``web/app.py``; standalone-``Environment`` render smoke
    tests never reached it and green-locally-but-red-in-CI'd on the
    2026-07-14  fanout. See ``feedback_divergence_audit_and_ssot_pin`` —
    the SSOT for this filter's registration is HERE, not the caller.
    The date-only ``us_date`` filter registers here too, for the same
    reason.
    """
    env.filters["us_datetime"] = us_datetime_filter
    env.filters["us_date"] = us_date_filter
