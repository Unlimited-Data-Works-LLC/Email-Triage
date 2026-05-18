"""Filter + window resolution for digest configs.

Phase 2 of the multi-digest feature. Two pure functions + a
predicate:

- :func:`resolve_window` — turns a ``DigestWindow`` (one of nine
  declarative kinds) into a ``since_iso`` / ``until_iso`` tuple
  the row collector consumes. Handles the ``since_last_sent``
  case by looking up the per-digest send-state row.
- :func:`resolve_provider_query` — when the operator filled the
  Advanced freeform field, this returns the raw provider query
  string (RFC 3501 / Gmail / OData) so it can flow to
  ``provider.search()`` unchanged. When Advanced is empty, the
  structured filter dimensions are translated into a
  :class:`MailFilter` instead.
- :func:`row_matches_filter` — predicate over a single
  ``triage_runs.results_json`` entry. Applies the structured
  filter dimensions in-process (categories / tags / from /
  subject / list-id / has-attachment / actions). Used by the
  sender path to filter the row list AFTER ``gather_digest_rows``
  pulls the broad result set, so structured + advanced queries
  AND-combine correctly without round-tripping the provider.

Read state, time window, and folder dimensions are enforced at
the provider-search layer (``MailFilter.unread`` /
``filter.after`` / ``folder``) — the in-memory predicate doesn't
re-check them. The reasoning: read-state and folder require
provider state that isn't on the triage_runs row; time window is
already gated by the ``since_iso`` query.
"""

from __future__ import annotations

from datetime import datetime, time, timedelta, timezone
from typing import Any
from zoneinfo import ZoneInfo

from email_triage.actions.digest_configs import (
    DigestConfig, DigestFilter, DigestWindow,
)


# ---------------------------------------------------------------------------
# Time window resolution
# ---------------------------------------------------------------------------


def _local_now(tz: str | None, now: datetime | None = None) -> datetime:
    """Convert ``now`` (or wall-clock if absent) to the operator's
    local zone.

    Falls back to UTC when the supplied timezone string is empty
    or unrecognised. Used by the calendar-anchored windows
    (today / this_week / this_month) so a digest scheduled at
    08:00 local fires the right way relative to local midnight.

    The ``now`` parameter exists for testability — callers (and
    the tests) pin a deterministic timestamp so the windows don't
    drift with wall-clock day rollover. Earlier shapes of this
    helper ignored ``now`` and always returned real wall-clock,
    which made today/yesterday tests fail the day after they were
    written.
    """
    base = now if now is not None else datetime.now(timezone.utc)
    if base.tzinfo is None:
        base = base.replace(tzinfo=timezone.utc)
    if tz:
        try:
            return base.astimezone(ZoneInfo(tz))
        except Exception:
            pass
    return base


def _start_of_day(d: datetime) -> datetime:
    return datetime.combine(d.date(), time.min, tzinfo=d.tzinfo)


def resolve_window(
    window: DigestWindow,
    *,
    now: datetime | None = None,
    last_sent_iso: str | None = None,
    tz: str | None = None,
) -> tuple[str, str]:
    """Translate a DigestWindow into ``(since_iso, until_iso)``.

    Both bounds are ISO 8601 strings in UTC. ``until_iso`` defaults
    to ``now`` when the window kind is open-ended (the calendar
    windows treat 'now' as the right edge).

    ``since_last_sent`` reads the per-digest send-state row to
    pick up everything new since the last successful run. On a
    first-ever fire (no prior send), falls back to a 24h rolling
    window so the inaugural digest isn't empty.

    ``custom`` reads the operator-supplied ``custom_start_iso`` /
    ``custom_end_iso`` strings; missing end defaults to ``now``,
    missing start raises (the caller already validated this in
    :func:`actions.digest_configs.validate`).
    """
    if now is None:
        now = datetime.now(timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    local_now = _local_now(tz, now=now) if tz else now

    end = now
    start: datetime

    kind = window.kind
    if kind == "rolling_24h":
        start = now - timedelta(hours=24)
    elif kind == "today":
        start = _start_of_day(local_now).astimezone(timezone.utc)
    elif kind == "yesterday":
        today_local = _start_of_day(local_now)
        yesterday = today_local - timedelta(days=1)
        start = yesterday.astimezone(timezone.utc)
        end = today_local.astimezone(timezone.utc)
    elif kind == "last_7d":
        start = now - timedelta(days=7)
    elif kind == "this_week":
        # Mon = weekday 0
        local_today = _start_of_day(local_now)
        start_local = local_today - timedelta(days=local_now.weekday())
        start = start_local.astimezone(timezone.utc)
    elif kind == "last_30d":
        start = now - timedelta(days=30)
    elif kind == "this_month":
        local_today = _start_of_day(local_now)
        start_local = local_today.replace(day=1)
        start = start_local.astimezone(timezone.utc)
    elif kind == "custom":
        start = _parse_iso(window.custom_start_iso) or (now - timedelta(hours=24))
        custom_end = _parse_iso(window.custom_end_iso)
        if custom_end is not None:
            end = custom_end
    elif kind == "since_last_sent":
        last = _parse_iso(last_sent_iso) if last_sent_iso else None
        start = last if last is not None else (now - timedelta(hours=24))
    else:
        # Unknown kind — degrade safely to 24h.
        start = now - timedelta(hours=24)

    return start.isoformat(), end.isoformat()


def _parse_iso(raw: str | None) -> datetime | None:
    if not raw:
        return None
    try:
        dt = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


# ---------------------------------------------------------------------------
# Provider-side query resolution
# ---------------------------------------------------------------------------


def resolve_provider_query(
    cfg: DigestConfig,
    *,
    since_iso: str,
    until_iso: str = "",
) -> tuple[Any, str]:
    """Build the provider search inputs from a digest config.

    Returns ``(MailFilter, raw_query)``:

    - When the operator filled the Advanced freeform field, the
      raw string flows out as ``raw_query``; the MailFilter
      carries only the time window + folder + read_state so the
      provider gets `(window) AND (advanced)` — caller passes
      both to ``provider.search(raw_query, filter=mfilter)``. The
      provider's search method already AND-combines its
      structured criteria with raw query text.
    - When Advanced is empty, ``raw_query`` is ``""`` and the
      MailFilter carries every structured dimension that maps
      cleanly to the provider's search surface (folder /
      read_state / from_addr / subject / time window). Tags /
      categories / actions / list_id / has_attachment are
      enforced in-process by :func:`row_matches_filter` against
      the triage_runs result set, since they don't have a
      portable provider-side equivalent.
    """
    from email_triage.engine.models import MailFilter

    mfilter = MailFilter()
    if since_iso:
        mfilter.after = _parse_iso(since_iso)
    if until_iso:
        mfilter.before = _parse_iso(until_iso)
    if cfg.filter.read_state == "unread":
        mfilter.unread = True
    elif cfg.filter.read_state == "read":
        mfilter.unread = False

    # Folder choice: cross-folder sentinel wins.
    if cfg.filter.folders:
        if "*" in cfg.filter.folders or "ALL" in cfg.filter.folders:
            mfilter.folder = "*"
        elif len(cfg.filter.folders) == 1:
            mfilter.folder = cfg.filter.folders[0]
        # Multi-folder selection without the wildcard isn't a
        # provider primitive — caller fans out per-folder OR uses
        # the cross-folder backend. For Phase 2 we set folder=*
        # in that case so search visits everything; row_matches_
        # filter then narrows to the operator's chosen subset.
        else:
            mfilter.folder = "*"

    if not cfg.filter.advanced and cfg.filter.from_addr:
        mfilter.from_addr = cfg.filter.from_addr
    if not cfg.filter.advanced and cfg.filter.subject:
        mfilter.subject = cfg.filter.subject

    raw_query = cfg.filter.advanced or ""
    return mfilter, raw_query


# ---------------------------------------------------------------------------
# In-process row predicate
# ---------------------------------------------------------------------------


def row_matches_filter(
    entry: dict[str, Any], filt: DigestFilter,
) -> bool:
    """True iff one ``triage_runs.results_json`` entry passes the
    structured filter dimensions enforced in-process.

    Dimensions checked here:

    - **categories** — entry's ``category`` field. Empty entry
      passes only when ``UNCLASSIFIED`` is selected. Empty filter
      list = no constraint.
    - **tags** — entry's ``labels`` list (provider keywords /
      labels round-tripped through ingestion). All filter tags
      must appear in the entry's labels (AND, not OR — operator
      writes "everything I tagged $EmailTriaged AND $Important"
      if they want both).
    - **list_id** — exact match on ``entry["headers"]["List-Id"]``
      when present (Phase 4 of the row collector populates this;
      Phase 2 tolerates absence).
    - **has_attachment** — ``True`` requires non-empty
      ``attachments``; ``False`` requires empty/missing; ``None``
      is unconstrained.
    - **actions** — every selected action key must appear in the
      entry's ``actions`` list. Empty filter = no constraint.

    Dimensions enforced at the provider-search layer (folder /
    read_state / time window / from_addr / subject) are NOT
    re-checked here — would just duplicate the provider's work.
    """
    cats = filt.categories
    if cats:
        entry_cat = (entry.get("category") or "").strip()
        wants_unclassified = "UNCLASSIFIED" in cats
        if not entry_cat:
            if not wants_unclassified:
                return False
        else:
            if (
                entry_cat not in cats
                and "*" not in cats
            ):
                return False

    if filt.tags:
        labels = entry.get("labels") or []
        if not all(t in labels for t in filt.tags):
            return False

    if filt.list_id:
        headers = entry.get("headers") or {}
        list_id_raw = (headers.get("List-Id") or "").strip()
        if filt.list_id.lower() not in list_id_raw.lower():
            return False

    if filt.has_attachment is not None:
        has = bool(entry.get("attachments"))
        if filt.has_attachment != has:
            return False

    if filt.actions:
        entry_actions = entry.get("actions") or []
        if not all(a in entry_actions for a in filt.actions):
            return False

    return True


# ---------------------------------------------------------------------------
# Schedule fire-now decision
# ---------------------------------------------------------------------------


#: Refuse to re-send a single digest within this window. Same as the
#: legacy ``MIN_RESEND_INTERVAL_HOURS`` so behaviour parity with the
#: pre-Phase-4 sender survives the cutover.
MIN_RESEND_INTERVAL_HOURS = 23


def digest_should_fire(
    cfg: DigestConfig,
    *,
    last_sent_iso: str | None,
    now_local: datetime,
) -> bool:
    """Decide whether ``cfg`` should fire RIGHT NOW.

    Three gates: enabled, schedule match, idempotence window.
    All checks operate in the operator's local-time frame
    (caller passes ``now`` already shifted to local) — matches
    the legacy ``recipient_digest.should_fire`` semantic.

    - **Enabled** — ``cfg.enabled`` must be True.
    - **Schedule match** — the current ``HH:MM`` (minute-resolved)
      must equal ``cfg.schedule.time_local``. Weekly cadence
      additionally requires today's weekday in
      ``schedule.days_of_week``. Monthly fires on the 1st of the
      month at the configured time.
    - **Idempotence** — last_sent_iso must be at least
      ``MIN_RESEND_INTERVAL_HOURS`` ago for daily. For weekly /
      monthly the same window guards against the same-time-bucket
      double fire.
    """
    if not cfg.enabled:
        return False

    sched = cfg.schedule
    if sched.cadence not in ("daily", "weekly", "monthly"):
        return False

    target = sched.time_local or ""
    current = now_local.strftime("%H:%M")
    if current != target:
        return False

    if sched.cadence == "weekly":
        wanted = sched.days_of_week or []
        if now_local.weekday() not in wanted:
            return False
    elif sched.cadence == "monthly":
        if now_local.day != 1:
            return False

    if last_sent_iso:
        last_dt = _parse_iso(last_sent_iso)
        if last_dt is not None:
            if now_local.tzinfo is None:
                _now = now_local.replace(tzinfo=timezone.utc)
            else:
                _now = now_local
            elapsed = (_now - last_dt).total_seconds() / 3600.0
            if elapsed < MIN_RESEND_INTERVAL_HOURS:
                return False

    return True
