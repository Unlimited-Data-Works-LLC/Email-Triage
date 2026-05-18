"""Core data models for the email triage system."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


# ---------------------------------------------------------------------------
# Flow lifecycle
# ---------------------------------------------------------------------------

class FlowStatus(str, Enum):
    """States in the triage flow state machine.

    Valid transitions:
        created -> fetched -> classifying -> classified -> routing -> acting -> finished
                                                                            -> waiting -> acting
                                                                   -> failed
                                          -> failed
    """
    CREATED = "created"
    FETCHED = "fetched"
    CLASSIFYING = "classifying"
    CLASSIFIED = "classified"
    ROUTING = "routing"
    ACTING = "acting"
    WAITING = "waiting"
    FINISHED = "finished"
    FAILED = "failed"


# Which transitions are legal from each state.
VALID_TRANSITIONS: dict[FlowStatus, set[FlowStatus]] = {
    FlowStatus.CREATED: {FlowStatus.FETCHED, FlowStatus.FAILED},
    FlowStatus.FETCHED: {FlowStatus.CLASSIFYING, FlowStatus.FAILED},
    FlowStatus.CLASSIFYING: {FlowStatus.CLASSIFIED, FlowStatus.FAILED},
    FlowStatus.CLASSIFIED: {FlowStatus.ROUTING, FlowStatus.FAILED},
    FlowStatus.ROUTING: {FlowStatus.ACTING, FlowStatus.FAILED},
    FlowStatus.ACTING: {FlowStatus.FINISHED, FlowStatus.WAITING, FlowStatus.FAILED},
    FlowStatus.WAITING: {FlowStatus.ACTING, FlowStatus.FAILED},
    FlowStatus.FINISHED: set(),
    FlowStatus.FAILED: set(),
}


class ActionResult(str, Enum):
    COMPLETED = "completed"
    WAITING = "waiting"
    FAILED = "failed"
    SKIPPED = "skipped"


class UserRole(str, Enum):
    ADMIN = "admin"
    POWER_USER = "power_user"
    USER = "user"


class RuleType(str, Enum):
    SENDER = "sender"
    SENDER_DOMAIN = "sender_domain"
    SUBJECT = "subject"


# ---------------------------------------------------------------------------
# Email message (provider-normalised)
# ---------------------------------------------------------------------------

@dataclass
class Attachment:
    """A MIME part on an EmailMessage.

    ``data`` and ``parsed`` are populated only for ``text/calendar`` parts
    today — every other content type is surfaced as metadata only so we
    don't blow memory on large binary blobs that nothing downstream uses.
    ``parsed`` carries the dict shape returned by :func:`engine.ics.parse_ics`.
    """
    filename: str
    content_type: str
    size_bytes: int
    data: bytes | None = None
    parsed: dict[str, Any] | None = None


@dataclass
class EmailMessage:
    """Provider-normalised email representation."""
    message_id: str
    provider: str
    sender: str
    recipients: list[str]
    subject: str
    body_text: str
    date: datetime
    thread_id: str | None = None
    labels: list[str] = field(default_factory=list)
    headers: dict[str, str] = field(default_factory=dict)
    raw_metadata: dict[str, Any] = field(default_factory=dict)
    attachments: list[Attachment] = field(default_factory=list)
    # Full HTML body if the message has a text/html part. Empty string
    # when the message is plain-text only. Populated by providers that
    # can fetch HTML. Used by the newsletter digest extractor to
    # preserve anchor URLs that are stripped when rendering to text.
    body_html: str = ""
    # (anchor_text, href) pairs extracted from body_html at fetch time.
    # Downstream consumers (digest extractor) use this as the
    # ground-truth URL set so the LLM can't hallucinate links —
    # headlines are matched to a known-real href by substring.
    links: list[tuple[str, str]] = field(default_factory=list)
    # Resolved HIPAA state at fetch time (system_hipaa OR account.hipaa).
    # Providers set this when constructing the message; downstream
    # actions read it instead of calling is_hipaa_mode() so the right
    # decision is made per-account rather than globally.
    hipaa: bool = False

    def log_repr(self, hipaa: bool = False) -> dict[str, Any]:
        """Return a dict safe for logging.

        In HIPAA mode, strips all fields that could contain PHI.
        """
        base = {
            "message_id": self.message_id,
            "provider": self.provider,
            "date": self.date.isoformat(),
        }
        if not hipaa:
            base["sender"] = self.sender
            base["subject"] = self.subject
            base["recipients"] = self.recipients
        return base


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------

@dataclass
class Classification:
    """Result of LLM (or list-rule) classification."""
    category: str
    confidence: float
    reason: str
    source: str = "llm"  # "llm" | "list_rule" | "list_hint"

    def log_repr(self, hipaa: bool = False) -> dict[str, Any]:
        base: dict[str, Any] = {
            "category": self.category,
            "confidence": self.confidence,
            "source": self.source,
        }
        if not hipaa:
            base["reason"] = self.reason
        return base


@dataclass
class ListHint:
    """A classification hint from a user/global list rule."""
    category: str
    rule_type: RuleType
    pattern: str
    skip_ai: bool = False
    list_name: str = ""
    is_global: bool = False


# ---------------------------------------------------------------------------
# Flow state (persisted in SQLite)
# ---------------------------------------------------------------------------

@dataclass
class FlowState:
    """Persistent state for one email flowing through the triage pipeline."""
    flow_id: str
    message_id: str
    provider: str
    status: FlowStatus
    revision: int = 0
    classification: Classification | None = None
    actions_completed: list[str] = field(default_factory=list)
    actions_pending: list[str] = field(default_factory=list)
    state_bag: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @staticmethod
    def new_id() -> str:
        return str(uuid.uuid4())

    def can_transition_to(self, target: FlowStatus) -> bool:
        return target in VALID_TRANSITIONS.get(self.status, set())


# ---------------------------------------------------------------------------
# User / auth
# ---------------------------------------------------------------------------

@dataclass
class User:
    """A user of the triage system."""
    id: int
    email: str
    name: str
    role: UserRole
    notify_email: str | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_login: datetime | None = None


# ---------------------------------------------------------------------------
# Classification lists / rules
# ---------------------------------------------------------------------------

@dataclass
class ClassificationList:
    """A named set of rules that hint (or force) classification."""
    id: int
    name: str
    category: str
    owner_id: int | None = None  # None = global
    is_global: bool = False
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class ListRule:
    """A single rule within a classification list."""
    id: int
    list_id: int
    rule_type: RuleType
    pattern: str
    skip_ai: bool = False
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


# ---------------------------------------------------------------------------
# Action output
# ---------------------------------------------------------------------------

@dataclass
class ActionOutput:
    """Result of executing an action."""
    result: ActionResult
    data: dict[str, Any] = field(default_factory=dict)
    error: str | None = None


# ---------------------------------------------------------------------------
# Calendar
# ---------------------------------------------------------------------------

@dataclass
class CalendarEvent:
    """Provider-normalised calendar event.

    ``start`` and ``end`` are tz-aware UTC. ``all_day`` events have midnight
    UTC bounds (start = day 00:00, end = next day 00:00); callers needing
    the user's local date should convert via the owning user's timezone.
    """
    event_id: str
    calendar_id: str = "primary"
    summary: str = ""
    description: str = ""
    location: str = ""
    start: datetime | None = None
    end: datetime | None = None
    all_day: bool = False
    organizer: str = ""
    attendees: list[dict[str, Any]] = field(default_factory=list)
    status: str = "confirmed"  # confirmed | tentative | cancelled
    # 2026-05-14 — "opaque" (default) means the event blocks the
    # time it occupies for free/busy purposes. "transparent" means
    # the event is shown on the calendar but DOES NOT block — used
    # for birthdays from contact-derived calendars, reminders, and
    # any event the operator explicitly marks "show as free." The
    # meeting-intercept's slot finder honours this so an all-day
    # birthday doesn't blank out the whole day's suggestions.
    #
    # Provider mapping:
    #   Gmail API: raw[transparency] -> "transparent" | "opaque" (default)
    #   MS Graph:  raw[showAs] in {"free", ...} -> "transparent" else opaque
    transparency: str = "opaque"
    provider: str = ""
    ical_uid: str = ""
    raw_metadata: dict[str, Any] = field(default_factory=dict)


WEEKDAYS = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]


@dataclass
class WorkingHours:
    """Per-weekday availability windows.

    Each list is zero or more (start, end) HH:MM pairs in the user's
    local timezone. Empty list ⇒ unavailable that day. Multiple
    intervals support lunch breaks, e.g.
    ``mon=[("09:00", "12:00"), ("13:00", "17:00")]``.

    Defaults: 09:00–17:00 Mon–Fri, off on weekends.
    """
    mon: list[tuple[str, str]] = field(default_factory=lambda: [("09:00", "17:00")])
    tue: list[tuple[str, str]] = field(default_factory=lambda: [("09:00", "17:00")])
    wed: list[tuple[str, str]] = field(default_factory=lambda: [("09:00", "17:00")])
    thu: list[tuple[str, str]] = field(default_factory=lambda: [("09:00", "17:00")])
    fri: list[tuple[str, str]] = field(default_factory=lambda: [("09:00", "17:00")])
    sat: list[tuple[str, str]] = field(default_factory=list)
    sun: list[tuple[str, str]] = field(default_factory=list)

    def for_weekday(self, weekday: int) -> list[tuple[str, str]]:
        """Return the intervals for a Python ``date.weekday()`` (0=Mon)."""
        if weekday < 0 or weekday > 6:
            return []
        return getattr(self, WEEKDAYS[weekday], [])

    @classmethod
    def from_dict(cls, raw: dict[str, Any] | None) -> "WorkingHours":
        if not raw:
            return cls()
        out = cls(mon=[], tue=[], wed=[], thu=[], fri=[], sat=[], sun=[])
        for day in WEEKDAYS:
            v = raw.get(day)
            if not isinstance(v, list):
                continue
            cleaned: list[tuple[str, str]] = []
            for pair in v:
                if isinstance(pair, (list, tuple)) and len(pair) == 2:
                    s, e = str(pair[0]), str(pair[1])
                    if s and e:
                        cleaned.append((s, e))
            setattr(out, day, cleaned)
        return out

    def to_dict(self) -> dict[str, Any]:
        return {day: [list(p) for p in getattr(self, day)] for day in WEEKDAYS}


@dataclass
class OutOfOfficeOverride:
    """Manual OOO override (overlays whatever the calendar carries)."""
    enabled: bool = False
    start: datetime | None = None  # tz-aware UTC
    end: datetime | None = None
    note: str = ""

    @classmethod
    def from_dict(cls, raw: dict[str, Any] | None) -> "OutOfOfficeOverride":
        if not raw:
            return cls()
        out = cls()
        out.enabled = bool(raw.get("enabled", False))
        for key in ("start", "end"):
            v = raw.get(key)
            if isinstance(v, str) and v:
                try:
                    dt = datetime.fromisoformat(v.replace("Z", "+00:00"))
                    if dt.tzinfo is None:
                        from datetime import timezone as _tz
                        dt = dt.replace(tzinfo=_tz.utc)
                    setattr(out, key, dt)
                except ValueError:
                    pass
        out.note = str(raw.get("note", ""))
        return out

    def to_dict(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "start": self.start.isoformat() if self.start else None,
            "end": self.end.isoformat() if self.end else None,
            "note": self.note,
        }


@dataclass
class MeetingPreferences:
    """User-level preferences for the meeting-request intercept."""
    default_length_minutes: int = 30
    suggestion_count: int = 3
    # 2026-05-14 — how many distinct working days to spread the
    # suggestions across. Used together with ``suggestion_count`` to
    # give "N suggestions over M days, one slot per day." Bounded
    # 1..14 in :meth:`from_dict`. Default 5 = one work week.
    # Replaces the pre-2026-05-14 algorithm which packed slots
    # contiguously inside the FIRST available day (the operator's
    # 2026-05-13 feedback: three back-to-back Friday-morning
    # suggestions vs slots picked across multiple distinct days).
    suggestion_days: int = 5
    # Legacy single-window fields. When ``working_hours`` is set
    # (the default), the slot finder prefers the per-weekday matrix;
    # these are kept so older tests / call sites keep working and so
    # the UI can show a coarse summary when the user hasn't set
    # per-day hours yet.
    business_hours_start: str = "09:00"
    business_hours_end: str = "17:00"
    skip_weekends: bool = True
    search_horizon_days: int = 14
    minimum_lead_time_hours: int = 24
    timezone: str = "UTC"
    working_hours: WorkingHours = field(default_factory=WorkingHours)
    ooo_override: OutOfOfficeOverride = field(default_factory=OutOfOfficeOverride)

    @classmethod
    def from_dict(cls, raw: dict[str, Any] | None) -> "MeetingPreferences":
        if not raw:
            return cls()
        # Tolerant of partial saves: only consume known keys, fall back
        # to defaults for anything missing or wrong-typed.
        out = cls()
        if isinstance(raw.get("default_length_minutes"), int):
            out.default_length_minutes = raw["default_length_minutes"]
        if isinstance(raw.get("suggestion_count"), int):
            out.suggestion_count = max(1, min(5, raw["suggestion_count"]))
        if isinstance(raw.get("suggestion_days"), int):
            out.suggestion_days = max(1, min(14, raw["suggestion_days"]))
        if isinstance(raw.get("business_hours_start"), str):
            out.business_hours_start = raw["business_hours_start"]
        if isinstance(raw.get("business_hours_end"), str):
            out.business_hours_end = raw["business_hours_end"]
        if isinstance(raw.get("skip_weekends"), bool):
            out.skip_weekends = raw["skip_weekends"]
        if isinstance(raw.get("search_horizon_days"), int):
            out.search_horizon_days = max(1, min(60, raw["search_horizon_days"]))
        if isinstance(raw.get("minimum_lead_time_hours"), int):
            out.minimum_lead_time_hours = max(0, raw["minimum_lead_time_hours"])
        if isinstance(raw.get("timezone"), str):
            out.timezone = raw["timezone"]
        if isinstance(raw.get("working_hours"), dict):
            out.working_hours = WorkingHours.from_dict(raw["working_hours"])
        if isinstance(raw.get("ooo_override"), dict):
            out.ooo_override = OutOfOfficeOverride.from_dict(raw["ooo_override"])
        return out

    def to_dict(self) -> dict[str, Any]:
        return {
            "default_length_minutes": self.default_length_minutes,
            "suggestion_count": self.suggestion_count,
            "suggestion_days": self.suggestion_days,
            "business_hours_start": self.business_hours_start,
            "business_hours_end": self.business_hours_end,
            "skip_weekends": self.skip_weekends,
            "search_horizon_days": self.search_horizon_days,
            "minimum_lead_time_hours": self.minimum_lead_time_hours,
            "timezone": self.timezone,
            "working_hours": self.working_hours.to_dict(),
            "ooo_override": self.ooo_override.to_dict(),
        }


@dataclass
class MailFilter:
    """Provider-agnostic mail filter; translated per-provider in search().

    Empty fields are skipped. ``after`` and ``before`` are tz-aware
    datetimes; providers translate to their native date format
    (Gmail's ``after:YYYY/MM/DD``, IMAP's ``SINCE``, Graph's
    ``receivedDateTime ge ...``).
    """
    unread: bool | None = None
    label: str | None = None
    folder: str | None = None
    from_addr: str | None = None
    to_addr: str | None = None
    subject: str | None = None
    after: datetime | None = None
    before: datetime | None = None

    def is_empty(self) -> bool:
        return all(
            getattr(self, name) in (None, "")
            for name in (
                "unread", "label", "folder", "from_addr",
                "to_addr", "subject", "after", "before",
            )
        )

    @classmethod
    def from_dict(cls, raw: dict[str, Any] | None) -> "MailFilter":
        if not raw:
            return cls()
        out = cls()
        if isinstance(raw.get("unread"), bool):
            out.unread = raw["unread"]
        for key in ("label", "folder", "from_addr", "to_addr", "subject"):
            v = raw.get(key)
            if isinstance(v, str) and v:
                setattr(out, key, v)
        # Accept "from"/"to" as aliases for the dataclass-friendly names.
        if "from" in raw and isinstance(raw["from"], str) and raw["from"]:
            out.from_addr = raw["from"]
        if "to" in raw and isinstance(raw["to"], str) and raw["to"]:
            out.to_addr = raw["to"]
        for key in ("after", "before"):
            v = raw.get(key)
            if isinstance(v, str) and v:
                try:
                    dt = datetime.fromisoformat(v.replace("Z", "+00:00"))
                    if dt.tzinfo is None:
                        from datetime import timezone as _tz
                        dt = dt.replace(tzinfo=_tz.utc)
                    setattr(out, key, dt)
                except ValueError:
                    pass
            elif isinstance(v, datetime):
                setattr(out, key, v)
        return out

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {}
        if self.unread is not None:
            out["unread"] = self.unread
        for key in ("label", "folder", "from_addr", "to_addr", "subject"):
            v = getattr(self, key)
            if v:
                out[key] = v
        for key in ("after", "before"):
            v = getattr(self, key)
            if v is not None:
                out[key] = v.isoformat()
        return out


@dataclass
class BulkItemResult:
    message_id: str
    status: str  # "ok" | "error" | "skipped"
    error: str | None = None
    data: dict[str, Any] | None = None


@dataclass
class BulkResult:
    requested: int
    succeeded: int
    failed: int
    items: list[BulkItemResult]
    elapsed_secs: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "requested": self.requested,
            "succeeded": self.succeeded,
            "failed": self.failed,
            "elapsed_secs": round(float(self.elapsed_secs), 3),
            "items": [
                {
                    "message_id": it.message_id,
                    "status": it.status,
                    "error": it.error,
                    "data": it.data,
                }
                for it in self.items
            ],
        }
