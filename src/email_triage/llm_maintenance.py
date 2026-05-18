"""Operator-defined LLM maintenance windows (#149 Bundle C).

When the operator knows their LLM host is going down for scheduled
maintenance (nightly Ollama upgrade, weekly homelab patch window,
etc.), an LLM-unreachable error during that window is NOT a
production incident — it's expected. This module turns "the
classifier just failed" + "we're inside a configured maintenance
window" into a calm INFO log + retry-queue enqueue, instead of the
default ERROR log + degraded-state banner.

Config shape (from YAML)::

    llm_maintenance_windows:
      - host: llm-host      # informational, used only for log context
        cron: "0 1 * * *"   # nightly 01:00 UTC
        duration_minutes: 30
        backend: ollama     # which classifier backend this applies to

The cron parser is intentionally tiny — we only need the common
shapes (m, h, dom, mon, dow). Each field accepts ``*``, a literal
integer, a comma-separated list of integers, ``*/N`` step values,
or ``a-b`` ranges. No predefined names (``@daily`` etc.). This is
enough for the documented use cases without pulling a new
dependency (``croniter`` is not currently in requirements).

If the operator needs richer cron — named months, ``L`` /
``W`` qualifiers — adding ``croniter`` is a one-line dep bump and a
swap of :func:`_cron_match` for ``croniter.match``.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable


_log = logging.getLogger("email_triage.llm_maintenance")


# ---------------------------------------------------------------------------
# Window dataclass
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class MaintenanceWindow:
    """One operator-configured maintenance window.

    ``host`` is informational only — used in log lines and the
    dashboard banner copy ("Ollama in scheduled maintenance window
    (host=<your-llm-host>) — back at 01:30 UTC"). The matcher fires
    off ``backend`` + the cron schedule.
    """
    host: str
    cron: str
    duration_minutes: int
    backend: str  # which classifier backend this applies to (e.g. "ollama")


def parse_windows(raw: Any) -> list[MaintenanceWindow]:
    """Convert raw YAML into a list of :class:`MaintenanceWindow`.

    Returns an empty list when ``raw`` is None / empty / malformed.
    Bad entries log a warning and are skipped — never raise; the
    rest of startup must not depend on this being parseable.
    """
    out: list[MaintenanceWindow] = []
    if not raw:
        return out
    if not isinstance(raw, list):
        _log.warning("llm_maintenance_windows: expected list, got %s",
                     type(raw).__name__)
        return out
    for i, item in enumerate(raw):
        if not isinstance(item, dict):
            _log.warning("llm_maintenance_windows[%d]: not a dict, skipping", i)
            continue
        try:
            cron = str(item.get("cron", "")).strip()
            backend = str(item.get("backend", "")).strip()
            duration = int(item.get("duration_minutes", 0))
            host = str(item.get("host", "")).strip()
            if not cron or not backend or duration <= 0:
                _log.warning(
                    "llm_maintenance_windows[%d]: missing required field "
                    "(cron / backend / duration_minutes); skipping",
                    i,
                )
                continue
            # Validate parse — a bad expression at config load is a
            # user error; emit warning + skip rather than carry a
            # row that will never match.
            try:
                _parse_cron(cron)
            except ValueError as exc:
                _log.warning(
                    "llm_maintenance_windows[%d]: invalid cron %r: %s",
                    i, cron, exc,
                )
                continue
            out.append(MaintenanceWindow(
                host=host, cron=cron,
                duration_minutes=duration, backend=backend,
            ))
        except Exception as exc:
            _log.warning(
                "llm_maintenance_windows[%d]: skipping due to %s",
                i, exc,
            )
    return out


# ---------------------------------------------------------------------------
# Cron parser (5-field POSIX subset)
# ---------------------------------------------------------------------------

_FIELD_BOUNDS = (
    (0, 59),    # minute
    (0, 23),    # hour
    (1, 31),    # day-of-month
    (1, 12),    # month
    (0, 6),     # day-of-week (0=Sun ... 6=Sat). 7 also means Sunday.
)


def _expand_field(token: str, lo: int, hi: int) -> set[int]:
    """Expand one field token (``*``, integer, list, range, step) into
    the set of int values it matches.

    Raises ``ValueError`` on anything we can't parse.
    """
    token = token.strip()
    if not token:
        raise ValueError("empty cron field")

    # Step: "*/5" or "1-30/2"
    if "/" in token:
        base, step_str = token.split("/", 1)
        try:
            step = int(step_str)
        except ValueError as exc:
            raise ValueError(f"invalid step {step_str!r}") from exc
        if step <= 0:
            raise ValueError("step must be positive")
        base_values = _expand_field(base or "*", lo, hi)
        return {v for v in base_values if (v - lo) % step == 0}

    # Comma list: "1,5,15"
    if "," in token:
        out: set[int] = set()
        for piece in token.split(","):
            out |= _expand_field(piece, lo, hi)
        return out

    # Range: "5-10"
    if "-" in token:
        a, b = token.split("-", 1)
        try:
            ai, bi = int(a), int(b)
        except ValueError as exc:
            raise ValueError(f"invalid range {token!r}") from exc
        if ai < lo or bi > hi or ai > bi:
            raise ValueError(f"range {token!r} outside bounds [{lo},{hi}]")
        return set(range(ai, bi + 1))

    # Wildcard
    if token == "*":
        return set(range(lo, hi + 1))

    # Literal integer
    try:
        v = int(token)
    except ValueError as exc:
        raise ValueError(f"invalid integer {token!r}") from exc
    # day-of-week wraparound: 7 -> 0 (Sunday)
    if (lo, hi) == (0, 6) and v == 7:
        v = 0
    if v < lo or v > hi:
        raise ValueError(f"value {v} outside bounds [{lo},{hi}]")
    return {v}


_CRON_FIELD_RE = re.compile(r"\s+")


def _parse_cron(expr: str) -> tuple[set[int], set[int], set[int], set[int], set[int]]:
    """Return (minutes, hours, doms, months, dows) sets.

    Raises ``ValueError`` on any parse failure.
    """
    fields = _CRON_FIELD_RE.split(expr.strip())
    if len(fields) != 5:
        raise ValueError(
            f"expected 5 cron fields, got {len(fields)}: {expr!r}"
        )
    return tuple(  # type: ignore[return-value]
        _expand_field(f, lo, hi)
        for f, (lo, hi) in zip(fields, _FIELD_BOUNDS)
    )


def _matches_at(expr: str, when: datetime) -> bool:
    """Return True if cron ``expr`` matches the wall-clock minute
    ``when``. Compared at minute precision.

    Day-of-month + day-of-week have classic cron OR semantics: when
    BOTH fields are restricted (neither is ``*``), the row matches
    if EITHER matches. When one is ``*``, only the other constrains.
    """
    minutes, hours, doms, months, dows = _parse_cron(expr)

    # We need to know whether dom / dow were given as "*" so we can
    # apply the OR rule. Re-split the expr to grab raw fields.
    raw = _CRON_FIELD_RE.split(expr.strip())
    dom_star = raw[2].strip() == "*"
    dow_star = raw[4].strip() == "*"

    if when.minute not in minutes:
        return False
    if when.hour not in hours:
        return False
    if when.month not in months:
        return False

    py_weekday_to_cron = (1, 2, 3, 4, 5, 6, 0)  # Mon=0 -> Mon=1, ..., Sun=6 -> Sun=0
    cron_dow = py_weekday_to_cron[when.weekday()]

    dom_ok = when.day in doms
    dow_ok = cron_dow in dows

    if dom_star and dow_star:
        return True
    if dom_star:
        return dow_ok
    if dow_star:
        return dom_ok
    # Both constrained — classic OR semantics.
    return dom_ok or dow_ok


# ---------------------------------------------------------------------------
# Window matching
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ActiveWindow:
    """Describes the active maintenance window at a given moment.

    Returned by :func:`active_window_for` so the watcher / banner /
    log line can read ``ends_at`` for "back at 01:30 UTC" copy.
    """
    window: MaintenanceWindow
    started_at: datetime  # UTC, when the matching minute fired
    ends_at: datetime     # UTC, started_at + duration_minutes


def active_window_for(
    backend: str,
    windows: Iterable[MaintenanceWindow],
    *,
    now: datetime | None = None,
) -> ActiveWindow | None:
    """Return the active maintenance window for ``backend``, or None.

    ``windows`` is the parsed list from :func:`parse_windows`.
    ``now`` is UTC; defaults to ``datetime.now(timezone.utc)``.

    Algorithm: for each window matching ``backend``, walk back
    minute-by-minute up to ``duration_minutes`` from ``now``. If
    the cron expression matches at any of those minutes, the
    window is active and ends at ``match_minute + duration``.
    Bounded scan; cheap (60 iterations max for an hour-long
    window — typical durations are 15-60 minutes).
    """
    if now is None:
        now = datetime.now(timezone.utc)
    # Strip seconds + microseconds — cron is minute-precision.
    now = now.replace(second=0, microsecond=0)

    for w in windows:
        if w.backend != backend:
            continue
        for delta in range(0, w.duration_minutes):
            anchor = now - timedelta(minutes=delta)
            if _matches_at(w.cron, anchor):
                return ActiveWindow(
                    window=w,
                    started_at=anchor,
                    ends_at=anchor + timedelta(minutes=w.duration_minutes),
                )
    return None


__all__ = [
    "MaintenanceWindow",
    "ActiveWindow",
    "parse_windows",
    "active_window_for",
    "_matches_at",
    "_parse_cron",
]
