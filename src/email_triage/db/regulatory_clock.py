"""Regulatory clock awareness — policy catalog + clock-domain DB home.

The clinical-trial safety-reporting deadline engine's module (design doc
``internal documentation`` + planning ruling
``internal documentation``, commit e098da7). The
three tables land in migration **v46** (``regulatory_clock_def`` /
``regulatory_clock_instance`` / ``regulatory_clock_event``); this module owns
the SEEDED policy catalog and (Phase 2+) the clock CRUD/state machine. The
audit-event EMITTERS for the legally-meaningful transitions live in
``db/audit.py`` (the audit SSOT — Directive 3), NOT here.

Seed semantics (mirrors ``seed_categories`` / ``ensure_upgrade_categories`` in
``web/db.py``): the base catalog (rows with ``config_owner_account_id IS
NULL``) is version-controlled DATA, re-asserted idempotently on every boot so
a regulation/citation correction is a SEED edit, not a code edit (design
§"policy catalog (not hardcoded constants)"). The re-assert deliberately
EXCLUDES the operator's ``enabled`` toggle, and never touches a per-account
IRB/INTERNAL OVERRIDE row (those carry a non-NULL ``config_owner_account_id``
and a distinct ``code``, so the ``code``-keyed upsert can never reach them).
"""
from __future__ import annotations

from email_triage.db.columns import REGULATORY_CLOCK_DEF_COLUMNS
import json
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import date, datetime, timedelta
from typing import Any

from email_triage._int_utils import parse_int_or_none  # N-219c/43 R23
from email_triage._isotime import now_utc_iso, parse_iso, to_utc_iso
from email_triage.db._helpers import dump_json_col, load_json_col  # N-186 R20_10
from email_triage.db.audit import emit_clock_event_txn, require_human_clock_actor
from email_triage.web.db_writelock import db_write

# The seeded base policy catalog. Each entry is a base def row
# (``config_owner_account_id`` = NULL). Durations + citations are regulatory
# DATA — edit here and the next boot re-asserts the canonical value.
#
# FDA/EU rows are the SPONSOR's filing obligation (21 CFR 312.32; EU 536/2014
# Art. 42 place SUSAR submission on the sponsor) → ``clock_kind='informational'``
# (a surfaced "sponsor deadline noted" receipt, never the site-PI's liability,
# never escalated, no ack). ``duration_overridable=0`` + the table CHECK lock
# their federally-fixed durations against a per-account override.
#
# The IRB row is the SITE's obligation → ``clock_kind='escalating'``, but its
# duration is INSTITUTIONALLY variable (ICH E6(R3), finalized 2025-01-06,
# REMOVED the fixed investigator-notification number). Per operator decision
# D5 it ships candidate-only-until-configured: ``duration_value=0`` is the
# UNCONFIGURED sentinel (no ladder arms — ``escalation_lead_pcts='[]'`` — and
# the UI nudges "configure your IRB reporting policy"); an institution arms it
# by creating a per-account OVERRIDE row (``config_owner_account_id`` set,
# ``duration_overridable=1``) carrying its real working-day duration. We never
# invent an IRB number (D5: the operator's written policy is the source of
# truth, not a default the AI assistant fabricates).
_REGULATORY_CLOCK_SEED_CATALOG: tuple[dict[str, Any], ...] = (
    {
        "code": "FDA_IND_7D_INFO",
        "regime": "FDA",
        "citation": "21 CFR 312.32(c)(2)",
        "title": "FDA IND safety report — fatal/life-threatening (sponsor obligation)",
        "severity_class": "fatal_lt",
        "clock_kind": "informational",
        "duration_value": 7,
        "duration_unit": "calendar_day",
        "calendar_tz": "America/New_York",
        "clock_start_kind": "on_receipt",
        "pausable": 0,
        "duration_overridable": 0,
        "ack_required": 0,
        "escalation_lead_pcts": "[]",
        "action_target": None,
    },
    {
        "code": "FDA_IND_15D_INFO",
        "regime": "FDA",
        "citation": "21 CFR 312.32(c)(1)(i)",
        "title": "FDA IND safety report — other serious & unexpected (sponsor obligation)",
        "severity_class": "other_serious",
        "clock_kind": "informational",
        "duration_value": 15,
        "duration_unit": "calendar_day",
        "calendar_tz": "America/New_York",
        "clock_start_kind": "on_receipt",
        "pausable": 0,
        "duration_overridable": 0,
        "ack_required": 0,
        "escalation_lead_pcts": "[]",
        "action_target": None,
    },
    {
        "code": "EU_CTR_7D_INFO",
        "regime": "EU_CTR",
        "citation": "Regulation (EU) No 536/2014, Art. 42(2)",
        "title": "EU CTR SUSAR report — fatal/life-threatening (sponsor obligation)",
        "severity_class": "fatal_lt",
        "clock_kind": "informational",
        "duration_value": 7,
        "duration_unit": "calendar_day",
        "calendar_tz": "Europe/Brussels",
        "clock_start_kind": "on_receipt",
        "pausable": 0,
        "duration_overridable": 0,
        "ack_required": 0,
        "escalation_lead_pcts": "[]",
        "action_target": None,
    },
    {
        "code": "EU_CTR_15D_INFO",
        "regime": "EU_CTR",
        "citation": "Regulation (EU) No 536/2014, Art. 42(2)",
        "title": "EU CTR SUSAR report — other serious & unexpected (sponsor obligation)",
        "severity_class": "other_serious",
        "clock_kind": "informational",
        "duration_value": 15,
        "duration_unit": "calendar_day",
        "calendar_tz": "Europe/Brussels",
        "clock_start_kind": "on_receipt",
        "pausable": 0,
        "duration_overridable": 0,
        "ack_required": 0,
        "escalation_lead_pcts": "[]",
        "action_target": None,
    },
    {
        "code": "IRB_AWARENESS",
        "regime": "IRB",
        "citation": "Institutional IRB/HRPO reporting policy (configure per protocol)",
        "title": "IRB/HRPO unanticipated-problem report — site obligation",
        "severity_class": "irb_up",
        "clock_kind": "escalating",
        "duration_value": 0,  # UNCONFIGURED sentinel — see module docstring (D5)
        "duration_unit": "working_day",
        "calendar_tz": "America/New_York",
        "clock_start_kind": "on_awareness",
        "pausable": 0,
        "duration_overridable": 1,
        "ack_required": 1,
        "escalation_lead_pcts": "[]",  # no ladder until an institution configures it
        "action_target": None,
    },
    # Additional non-FDA IRB starting points (operator 2026-06-15). Like
    # IRB_AWARENESS these are institution-AGNOSTIC duration=0 UNCONFIGURED
    # sentinels (D5 — we never invent an IRB number; the operator arms each by
    # creating a per-account OVERRIDE carrying their written-policy duration).
    # They exist so the editor offers named, common IRB report types to start
    # from rather than a blank page.
    {
        "code": "IRB_CONTINUING_REVIEW",
        "regime": "IRB",
        "citation": "Institutional IRB continuing-review policy (configure per protocol)",
        "title": "IRB continuing-review / progress report — site obligation",
        "severity_class": "irb_up",
        "clock_kind": "escalating",
        "duration_value": 0,  # UNCONFIGURED sentinel (D5)
        "duration_unit": "working_day",
        "calendar_tz": "America/New_York",
        "clock_start_kind": "on_awareness",
        "pausable": 0,
        "duration_overridable": 1,
        "ack_required": 1,
        "escalation_lead_pcts": "[]",
        "action_target": None,
    },
    {
        "code": "IRB_PROTOCOL_DEVIATION",
        "regime": "IRB",
        "citation": "Institutional IRB protocol-deviation reporting policy (configure per protocol)",
        "title": "IRB protocol-deviation / violation report — site obligation",
        "severity_class": "irb_up",
        "clock_kind": "escalating",
        "duration_value": 0,  # UNCONFIGURED sentinel (D5)
        "duration_unit": "working_day",
        "calendar_tz": "America/New_York",
        "clock_start_kind": "on_awareness",
        "pausable": 0,
        "duration_overridable": 1,
        "ack_required": 1,
        "escalation_lead_pcts": "[]",
        "action_target": None,
    },
)

# Column order for the seed INSERT. ``config_owner_account_id``/``enabled``/
# ``created_at`` are appended by the writer (not per-entry data).
_SEED_DATA_COLS: tuple[str, ...] = (
    "code", "regime", "citation", "title", "severity_class", "clock_kind",
    "duration_value", "duration_unit", "calendar_tz", "clock_start_kind",
    "pausable", "duration_overridable", "ack_required", "escalation_lead_pcts",
    "action_target",
)

# Fields RE-ASSERTED on conflict = the regulatory FACTS. Deliberately EXCLUDES
# ``enabled`` (operator toggle), ``config_owner_account_id`` (NULL for base),
# ``created_at`` (first-seen stamp) and ``code`` (the conflict key).
_SEED_REASSERT_COLS: tuple[str, ...] = tuple(
    c for c in _SEED_DATA_COLS if c != "code"
)


def seed_regulatory_clock_catalog(conn: sqlite3.Connection) -> int:
    """Idempotently seed / refresh the base regulatory-clock policy catalog.

    Called from ``_bootstrap_schema`` after ``run_migrations`` has created the
    v46 tables (mirrors ``seed_categories``). INSERTs each base row keyed on
    the UNIQUE ``code``; on conflict, RE-ASSERTS the canonical regulatory
    fields (citation / title / duration / …) so a corrected seed value
    self-heals on the next boot — WITHOUT clobbering the operator's ``enabled``
    toggle, and (guarded by the ``WHERE`` clause) never touching a per-account
    override row. Returns the number of base catalog rows asserted.
    """
    # Defensive: a partial-migration boot (a per-migration test that clips
    # MIGRATIONS below v46 — e.g. tests/test_v35*/test_v37* call init_db with
    # MIGRATIONS<=34) runs _bootstrap_schema BEFORE this table exists. No-op
    # rather than crash; production always migrates to the latest schema first,
    # so regulatory_clock_def is present there and the seed runs normally.
    if not conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' "
        "AND name='regulatory_clock_def'"
    ).fetchone():
        return 0
    now = now_utc_iso()
    set_clause = ", ".join(
        f"{c} = excluded.{c}" for c in _SEED_REASSERT_COLS
    )
    all_cols = (*_SEED_DATA_COLS, "config_owner_account_id", "enabled", "created_at")
    placeholders = ", ".join(["?"] * len(all_cols))
    sql = (
        f"INSERT INTO regulatory_clock_def ({', '.join(all_cols)}) "
        f"VALUES ({placeholders}) "
        f"ON CONFLICT(code) DO UPDATE SET {set_clause} "
        # Belt-and-suspenders: a base ``code`` always carries a NULL owner, so
        # this conflict can only ever hit a base row — but scope the UPDATE to
        # base rows explicitly so a future override sharing a code can never be
        # silently overwritten by the seed.
        f"WHERE regulatory_clock_def.config_owner_account_id IS NULL"
    )
    for entry in _REGULATORY_CLOCK_SEED_CATALOG:
        conn.execute(sql, (
            *(entry[c] for c in _SEED_DATA_COLS),
            None,  # config_owner_account_id — base row
            1,     # enabled (only on first INSERT; re-assert preserves operator toggle)
            now,   # created_at (only on first INSERT)
        ))
    conn.commit()
    return len(_REGULATORY_CLOCK_SEED_CATALOG)


# ===========================================================================
# Operator-OWNED clock-def validation (the safety funnel for the editor CRUD)
# ===========================================================================
#
# An operator-defined IRB/INTERNAL deadline feeds the immutable v47 HMAC clock
# chain — a wrong duration / unit / timezone can chain a FALSE ``breached``
# event into a tamper-evident, ~6-year-retained log. So EVERY owned-def write
# (create + update) routes through this fail-CLOSED validator BEFORE the INSERT/
# UPDATE: a malformed field RAISES :class:`ClockDefValidationError`, never
# "coerce-and-proceed". The DB CHECK (regime IN IRB/INTERNAL when owner set) is
# the backstop; this raises a clean, actionable error first AND enforces the
# rules the CHECK can't (working-day-calendar prerequisite, lead-pct ranges, a
# resolvable timezone).

#: Operator-definable regimes. FDA / EU_CTR are SPONSOR legal obligations —
#: never operator-edited (the DB CHECK forbids an owner on them; this rejects
#: them first with a clean error).
_OWNED_REGIMES = frozenset({"IRB", "INTERNAL"})
_DURATION_UNITS = frozenset({"calendar_day", "working_day"})
_CLOCK_START_KINDS = frozenset({"on_receipt", "on_determination", "on_awareness"})
_OWNED_SEVERITY = frozenset({"irb_up", "internal"})
_CLOCK_KINDS = frozenset({"escalating", "informational"})


class ClockDefValidationError(ValueError):
    """An operator-submitted clock-def payload failed validation. Carries a
    user-facing message; the editor re-renders with it (never persists)."""


def validate_owned_clock_def(
    payload: dict[str, Any],
    *,
    working_day_calendar_configured: bool = False,
) -> dict[str, Any]:
    """Validate + normalize an operator-OWNED IRB/INTERNAL clock-def payload.

    Fail-CLOSED: raises :class:`ClockDefValidationError` on the FIRST problem
    rather than coercing a bad value that could chain a false ``breached``.
    Returns a normalized dict carrying ONLY the owned-def data columns (the
    write helper supplies owner/code/enabled/created_at — never the payload).

    ``working_day_calendar_configured`` is whether the per-install working-day
    calendar has been set up: an ARMING (duration>0) ``working_day`` def is
    REFUSED when it is False, because the default empty-holiday calendar would
    mis-count around real holidays and chain a wrong deadline (design §P4b).
    """
    def _bad(msg: str):
        raise ClockDefValidationError(msg)

    title = str(payload.get("title") or "").strip()
    if not title:
        _bad("A template needs a name.")

    regime = str(payload.get("regime") or "").strip()
    if regime not in _OWNED_REGIMES:
        _bad("You can only create IRB or internal templates here. "
             "FDA and EU sponsor deadlines are fixed and not editable.")

    # Duration: non-negative int. 0 = the UNCONFIGURED sentinel (no arming).
    raw_dur = payload.get("duration_value", 0)
    duration_value = parse_int_or_none(raw_dur)  # N-219c/43 R23: SSOT
    if duration_value is None:
        return _bad("The number of days must be a whole number.")  # noqa: RET503
    if duration_value < 0:
        _bad("The number of days can't be negative.")

    unit = str(payload.get("duration_unit") or "working_day").strip()
    if unit not in _DURATION_UNITS:
        _bad("The day type must be calendar days or working days.")
    if unit == "working_day" and duration_value > 0 and not working_day_calendar_configured:
        _bad("Set up your working-day calendar (holidays + work week) before "
             "arming a working-day deadline, so dates land correctly.")

    start_kind = str(payload.get("clock_start_kind") or "on_awareness").strip()
    if start_kind not in _CLOCK_START_KINDS:
        _bad("The start point is not recognised.")

    severity = str(payload.get("severity_class") or "").strip()
    if severity not in _OWNED_SEVERITY:
        _bad("The category must be an IRB or internal type.")

    clock_kind = str(payload.get("clock_kind") or "escalating").strip()
    if clock_kind not in _CLOCK_KINDS:
        _bad("The reminder type is not recognised.")
    # An ARMING IRB obligation must escalate (it's the site's liability) — an
    # informational arming row would be a contradiction (a deadline with no
    # follow-up). The 0-duration sentinel is exempt (nothing arms).
    if duration_value > 0 and regime == "IRB" and clock_kind != "escalating":
        _bad("An IRB deadline with a due date must be an escalating reminder.")

    # Escalation ladder: a JSON array of ints, each a percent in [0, 100].
    lead = payload.get("escalation_lead_pcts", [])
    if isinstance(lead, str):
        try:
            lead = json.loads(lead or "[]")
        except (TypeError, ValueError):
            return _bad("The reminder schedule is malformed.")  # noqa: RET503
    if not isinstance(lead, list):
        _bad("The reminder schedule must be a list.")
    pcts: list[int] = []
    for p in lead:
        ip = parse_int_or_none(p)  # N-219c/43 R23: SSOT
        if ip is None:
            return _bad("Each reminder must be a whole percent.")  # noqa: RET503
        if not (0 <= ip <= 100):
            _bad("Each reminder must be between 0 and 100 percent.")
        pcts.append(ip)

    tz = str(payload.get("calendar_tz") or "America/New_York").strip()
    try:
        from zoneinfo import ZoneInfo
        ZoneInfo(tz)
    except Exception:  # noqa: BLE001 — unknown zone => reject (mis-anchors dates)
        _bad("The time zone is not recognised.")

    def _flag(key: str, default: int) -> int:
        v = payload.get(key, default)
        return 1 if v in (1, "1", True, "on", "true") else 0

    return {
        "regime": regime,
        "citation": str(payload.get("citation") or "").strip()
        or "Institutional policy (configure per protocol)",
        "title": title,
        "severity_class": severity,
        "clock_kind": clock_kind,
        "duration_value": duration_value,
        "duration_unit": unit,
        "calendar_tz": tz,
        "clock_start_kind": start_kind,
        "pausable": _flag("pausable", 0),
        # Owned rows are ALWAYS operator-overridable (the whole point).
        "duration_overridable": 1,
        "ack_required": _flag("ack_required", 1),
        "escalation_lead_pcts": dump_json_col(pcts),  # N-186 R20_10 SSOT (ensure_ascii=False)
        "action_target": payload.get("action_target") or None,
    }


# The validator's data keys, in a stable order (NO code/owner/enabled/created_at
# — those are writer-supplied, never operator payload). The owned-def write
# helpers below build their INSERT/UPDATE from exactly these.
_OWNED_DEF_DATA_COLS: tuple[str, ...] = (
    "regime", "citation", "title", "severity_class", "clock_kind",
    "duration_value", "duration_unit", "calendar_tz", "clock_start_kind",
    "pausable", "duration_overridable", "ack_required", "escalation_lead_pcts",
    "action_target",
)

#: Editable fields where a BLANK submission PRESERVES the stored value
#: (never-clobber — incident_2026-06-08). Zeroing a live duration from a blank
#: field would silently DISARM a legal clock, so a missing/blank key on UPDATE
#: re-uses the stored value rather than coercing an empty.
_OWNED_DEF_PRESERVE_ON_BLANK: frozenset[str] = frozenset({
    "title", "citation", "duration_value", "duration_unit", "calendar_tz",
    "clock_start_kind", "severity_class", "clock_kind", "escalation_lead_pcts",
})


def _slugify_clock_code(account_id: int, title: str) -> str:
    """The per-account-namespaced UNIQUE ``code`` for an owned def:
    ``OWN_<account_id>_<slug>``. The ``OWN_`` prefix can NEVER prefix-collide
    with a base catalog code (no seed code starts with ``OWN_``), so an owned row
    can never masquerade as base catalog and the seed's ``WHERE
    config_owner_account_id IS NULL`` re-assert can never reach it."""
    import re
    slug = re.sub(r"[^a-z0-9]+", "_", str(title or "").lower()).strip("_")[:40]
    return f"OWN_{int(account_id)}_{slug or 'clock'}"


def _owned_def_row(conn: sqlite3.Connection, def_id: int) -> sqlite3.Row:
    row = conn.execute(
        f"SELECT {REGULATORY_CLOCK_DEF_COLUMNS} FROM regulatory_clock_def WHERE id = ?", (int(def_id),)
    ).fetchone()
    if row is None:
        raise ClockDefValidationError("That template no longer exists.")
    if row["config_owner_account_id"] is None:
        # A base/FDA/EU catalog row — read-only, never operator-editable.
        raise ClockDefValidationError("Built-in templates can't be changed.")
    return row


@db_write
def create_owned_clock_def(
    conn: sqlite3.Connection,
    *,
    account_id: int,
    actor_user_id: int,
    payload: dict[str, Any],
    working_day_calendar_configured: bool = False,
) -> int:
    """Create an operator-OWNED IRB/INTERNAL clock-def for ``account_id``.

    Fail-closed (validates first). The owner is FORCED to ``account_id`` (NEVER
    NULL — an owned row must never masquerade as base catalog) and the code is a
    namespaced ``OWN_`` value. The caller (route) MUST have already intersected
    ``account_id`` with the requester's manageable set (PD#9 actuator gate);
    ``actor_user_id`` identifies the human for the governance audit the route
    emits. Returns the new def id."""
    data = validate_owned_clock_def(
        payload, working_day_calendar_configured=working_day_calendar_configured,
    )
    base_code = _slugify_clock_code(account_id, data["title"])
    code, n = base_code, 1
    while conn.execute(
        "SELECT 1 FROM regulatory_clock_def WHERE code = ?", (code,)
    ).fetchone():
        n += 1
        code = f"{base_code}_{n}"
    now = now_utc_iso()
    cols = ("code", *_OWNED_DEF_DATA_COLS,
            "config_owner_account_id", "enabled", "created_at")
    vals = (code, *(data[c] for c in _OWNED_DEF_DATA_COLS),
            int(account_id), 1, now)
    cur = conn.execute(
        f"INSERT INTO regulatory_clock_def ({', '.join(cols)}) "
        f"VALUES ({', '.join(['?'] * len(cols))})",
        vals,
    )
    conn.commit()
    return int(cur.lastrowid)


@db_write
def update_owned_clock_def(
    conn: sqlite3.Connection,
    *,
    def_id: int,
    account_id: int,
    actor_user_id: int,
    payload: dict[str, Any],
    working_day_calendar_configured: bool = False,
) -> bool:
    """Update an operator-OWNED def. The owner + code are STRUCTURALLY IMMUTABLE
    (re-derived from the stored row, NEVER taken from the payload) so an operator
    can never relabel an owned row into a base-looking one (the relabel/promote
    vector). Never-clobber: a blank field PRESERVES the stored value (zeroing a
    live duration from a blank would silently disarm a legal clock)."""
    row = _owned_def_row(conn, def_id)
    if int(row["config_owner_account_id"]) != int(account_id):
        raise ClockDefValidationError("That template belongs to another account.")

    # Never-clobber merge: start from the stored values; a payload key only wins
    # when it carries a NON-BLANK value for a preserve-on-blank field.
    merged: dict[str, Any] = {c: row[c] for c in _OWNED_DEF_DATA_COLS}
    for k, v in (payload or {}).items():
        if k not in _OWNED_DEF_DATA_COLS:
            continue
        if k in _OWNED_DEF_PRESERVE_ON_BLANK and (
            v is None or (isinstance(v, str) and not v.strip())
        ):
            continue  # blank => preserve the stored value
        merged[k] = v
    data = validate_owned_clock_def(
        merged, working_day_calendar_configured=working_day_calendar_configured,
    )
    # owner + code are NOT in _OWNED_DEF_DATA_COLS, so the SET below can never
    # touch them — they stay the stored owned values (immutable by construction).
    set_cols = list(_OWNED_DEF_DATA_COLS)
    conn.execute(
        f"UPDATE regulatory_clock_def SET "
        f"{', '.join(f'{c} = ?' for c in set_cols)} "
        f"WHERE id = ? AND config_owner_account_id = ?",
        (*(data[c] for c in set_cols), int(def_id), int(account_id)),
    )
    conn.commit()
    return True


@db_write
def delete_owned_clock_def(
    conn: sqlite3.Connection,
    *,
    def_id: int,
    account_id: int,
    actor_user_id: int,
) -> bool:
    """Delete an operator-OWNED def. REFUSES (raises) while ANY clock instance
    references it — live OR terminal. The instance ``def_id`` FK has no
    ``ON DELETE`` rule (it RESTRICTS), and a historical instance's policy row
    must survive for the audit trail, so a USED template is disabled
    (``enabled=0`` via the editor), never hard-deleted; only a never-used
    template is removable. Refusing on ANY reference (not just live) matches the
    FK exactly — a live-only check would pass here then fail the FK with an
    IntegrityError. The check + delete run in ONE @db_write txn on the single-
    writer thread, so no concurrent transition can arm an instance between the
    check and the delete (no check-then-act orphan race)."""
    row = _owned_def_row(conn, def_id)
    if int(row["config_owner_account_id"]) != int(account_id):
        raise ClockDefValidationError("That template belongs to another account.")
    used = conn.execute(
        "SELECT 1 FROM regulatory_clock_instance WHERE def_id = ? LIMIT 1",
        (int(def_id),),
    ).fetchone()
    if used:
        raise ClockDefValidationError(
            "This template has been used (it has deadline history) — turn it "
            "off instead of deleting it, so past records stay intact."
        )
    conn.execute(
        "DELETE FROM regulatory_clock_def "
        "WHERE id = ? AND config_owner_account_id = ?",
        (int(def_id), int(account_id)),
    )
    conn.commit()
    return True


@db_write
def set_owned_clock_def_enabled(
    conn: sqlite3.Connection,
    *,
    def_id: int,
    account_id: int,
    actor_user_id: int,
    enabled: bool,
) -> bool:
    """Set ``enabled=0/1`` on an operator-OWNED clock def (D2 fix 2026-07-16).

    Sole post-create writer of the ``enabled`` column on
    ``regulatory_clock_def``. The two other writes are create-time literal
    ``1`` — one at :func:`create_owned_clock_def` for owned rows, one at
    :func:`seed_regulatory_clock_catalog` for base catalog rows — and all
    three writers are allow-listed by
    ``tests/test_owned_clock_def_enabled_toggle_pin.py``
    (:func:`test_enabled_writer_is_sole_ssot`). A twin write elsewhere
    forks the enable-state control surface: a route or migration that flips
    ``enabled`` outside this SSOT skips both the owner-guard AND the
    governance audit that the profile route wraps around every call, so
    the pin refuses it structurally.

    Idempotent — no-ops with ``return False`` when the current stored
    value already matches ``enabled``; returns ``True`` when a row was
    written. **Callers MUST still emit governance audit on ``False``
    return** (db-sme panel-1 O1, 2026-07-16) — operator INTENT to
    disable/enable is a §164.312(b) auditable event even when the
    state was already at target. Callers must NOT short-circuit the
    ``_record_clock_def_governance`` emit on a False return; the route
    dispatcher (:func:`_clock_def_write` in ``web/routers/ui/profile.py``)
    correctly emits regardless of return value. Fail-closed: raises
    :class:`ClockDefValidationError` when
    the def is missing / base catalog (via :func:`_owned_def_row`) OR
    when the def's stored owner does not match ``account_id`` (cross-
    account attempt to flip a foreign row). The route caller already
    intersected ``account_id`` with the requester's manageable set
    (Prime Directive #9 actuator gate); this method is the DB-layer
    belt to that suspenders. ``actor_user_id`` identifies the human
    for the governance audit the route emits.

    Scope limit — this does NOT halt live ``regulatory_clock_instance``
    rows already armed on this def. Each instance carries a frozen-policy
    snapshot at arm time and keeps ticking on that snapshot; disabling
    stops NEW instances arming (the downstream route-action picker at
    ``web/routers/ui/_shared.py`` filters ``enabled = 1``) while
    preserving §164.316(b)(2)(i) 6-year audit-retention on the
    historical rows. Full-halt of live instances would need a separate
    lifecycle transition (out of scope for D2)."""
    row = _owned_def_row(conn, def_id)
    if int(row["config_owner_account_id"]) != int(account_id):
        raise ClockDefValidationError("That template belongs to another account.")
    desired = int(bool(enabled))
    if int(row["enabled"]) == desired:
        return False  # idempotent no-op — nothing to write, no chain hop
    conn.execute(
        "UPDATE regulatory_clock_def SET enabled = ? "
        "WHERE id = ? AND config_owner_account_id = ?",
        (desired, int(def_id), int(account_id)),
    )
    conn.commit()
    return True


def list_owned_clock_defs(
    conn: sqlite3.Connection, account_id: int,
    *, include_disabled: bool = False,
) -> list[dict]:
    """The IRB/INTERNAL defs OWNED by ``account_id`` (newest first). Scoped to
    ONE account — never another account's owned defs (the caller has already
    gated ``account_id`` to the requester's manageable set).

    D2 fix 2026-07-16: gained the ``include_disabled`` kwarg (default
    ``False``). By default the listing filters out rows with
    ``enabled = 0`` so downstream read-only consumers (the compliance
    display, the route-action picker) don't surface off templates. The
    profile EDITOR passes ``include_disabled=True`` so operators can
    still see disabled rows and restore them — a listing that hid off
    rows in the editor would be a UX dead-end (the operator would have
    no path to turn them back on)."""
    if include_disabled:
        sql = (
            f"SELECT {REGULATORY_CLOCK_DEF_COLUMNS} FROM regulatory_clock_def "
            "WHERE config_owner_account_id = ? ORDER BY id DESC"
        )
    else:
        sql = (
            f"SELECT {REGULATORY_CLOCK_DEF_COLUMNS} FROM regulatory_clock_def "
            "WHERE config_owner_account_id = ? AND enabled = 1 "
            "ORDER BY id DESC"
        )
    return [dict(r) for r in conn.execute(sql, (int(account_id),)).fetchall()]


# ===========================================================================
# Phase 2 — clock instance lifecycle + state machine
# ===========================================================================
#
# Propose-then-confirm: the human's confirmation sets the WRITE-ONCE anchor and
# arms the clock; the system NEVER auto-files/auto-closes an escalating clock.
# Every legal transition routes through the Phase-1 chained emitter (here via
# the txn-aware `emit_clock_event_txn`, which does NOT commit) so the instance
# state-flip + the tamper-evident audit row land or roll back together: the
# function does its UPDATE(s) + the chained emit, then a SINGLE conn.commit()
# (rollback on any error). One implicit transaction wraps the whole transition
# (mirrors db/accounts.set_account_hipaa's atomic state-flip + audit row;
# implicit-txn rather than explicit BEGIN so a caller's already-open txn can't
# trip "transaction within a transaction").
#
# Anchors (clock_start_at / awareness_at / determination_at) are WRITE-ONCE —
# set on transition, never UPDATEd; altering the legal Day-0 in place is the top
# tamper target. deadline_at is a DERIVED cache (recomputed idempotently). A
# correction is a NEW determination_corrected event with actor + reason (21 CFR
# Part 11), never an in-place edit of the original anchor.
#
# The RESPONSIBILITY gate: an escalating ladder arms ONLY when
# responsibility='i_submit' (the site owes the report). 'unknown'/'sponsor_
# submits' stay advisory/candidate-only — an inbound safety notice the SPONSOR
# will file to the IRB on the PI's behalf creates NO site clock, and that is
# unreadable from the email (it lives in the protocol's reporting plan).


class ClockStateError(RuntimeError):
    """A regulatory-clock transition violated the state machine (a write-once
    anchor re-set, an unknown instance, an illegal transition from a terminal
    state). Fail-closed (Directive 8): callers must NOT swallow this into a
    silent no-op — a mis-stamped or double-armed legal clock is a defensibility
    defect. The explicit-transaction callers below ROLLBACK on it."""


# Terminal states — no further arming / disposition (only an append-only
# correction event may still reference the instance).
_CLOCK_TERMINAL_STATES = frozenset({"submitted", "dismissed"})

# The only columns _set_write_once_txn may target (no SQL-injection surface —
# all call sites pass a literal from this set).
_WRITE_ONCE_COLS = frozenset({
    "clock_start_at", "awareness_at", "determination_at", "acked_at",
    "submitted_at",
})


@contextmanager
def _clock_txn(conn: sqlite3.Connection):
    """Atomic boundary for ONE clock transition: the caller's UPDATE(s) + the
    txn-aware ``emit_clock_event_txn`` commit together on success, or roll back
    together on any error — so the state-flip and the tamper-evident audit row
    never diverge (the SSOT for the 8 lifecycle transitions; was 8 copies of
    try/commit/except/rollback — PD#5).

    SF-2 (db-sme): the atomicity relies on the connection being in a deferred
    (NOT autocommit) isolation mode — on an autocommit handle each statement
    would commit immediately, so the state UPDATE would land before the chained
    emit with NO rollback path. Fail CLOSED (Directive 8): refuse the transition
    rather than silently lose atomicity. Every prod/test caller opens via
    ``init_db``/``init_db_encrypted`` (deferred); only the migration framework
    uses an autocommit handle, and it never drives these transitions."""
    if conn.isolation_level is None:
        raise ClockStateError(
            "regulatory-clock transitions require a transaction-capable "
            "(non-autocommit) connection so the state-flip + chained audit "
            "event are atomic; got isolation_level=None (autocommit)"
        )
    try:
        yield
        conn.commit()
    except Exception:
        conn.rollback()
        raise


# Joined instance+def view columns the lifecycle needs.
_INSTANCE_JOIN_SQL = (
    "SELECT i.*, d.regime AS def_regime, d.clock_kind AS def_clock_kind, "
    "       d.duration_value AS def_duration_value, "
    "       d.duration_unit AS def_duration_unit, "
    "       d.clock_start_kind AS def_clock_start_kind, "
    "       d.escalation_lead_pcts AS def_escalation_lead_pcts, "
    "       d.calendar_tz AS def_calendar_tz "
    "FROM regulatory_clock_instance i "
    "JOIN regulatory_clock_def d ON d.id = i.def_id "
    "WHERE i.id = ?"
)


def _load_instance(conn: sqlite3.Connection, instance_id: int) -> sqlite3.Row:
    row = conn.execute(_INSTANCE_JOIN_SQL, (instance_id,)).fetchone()
    if row is None:
        raise ClockStateError(
            f"regulatory clock instance {instance_id} not found"
        )
    return row


def get_clock_instance(conn: sqlite3.Connection, instance_id: int) -> dict:
    """Read one clock instance joined to its def (raises if missing)."""
    return dict(_load_instance(conn, instance_id))


def list_clock_instances(
    conn: sqlite3.Connection,
    *,
    account_id: int | None = None,
    state: str | None = None,
    limit: int = 200,
    offset: int = 0,
) -> list[dict]:
    """List clock instances newest-first, optionally filtered by account/state."""
    where: list[str] = []
    params: list = []
    if account_id is not None:
        where.append("i.account_id = ?")
        params.append(account_id)
    if state is not None:
        where.append("i.state = ?")
        params.append(state)
    sql = (
        "SELECT i.*, d.regime AS def_regime, d.clock_kind AS def_clock_kind "
        "FROM regulatory_clock_instance i "
        "JOIN regulatory_clock_def d ON d.id = i.def_id"
    )
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY i.id DESC LIMIT ? OFFSET ?"
    params.extend([limit, int(offset)])
    return [dict(r) for r in conn.execute(sql, params).fetchall()]


def _resolve_anchor(inst: sqlite3.Row, fallback: str | None) -> str | None:
    """The deadline anchor for this def's clock_start_kind."""
    kind = inst["def_clock_start_kind"]
    if kind == "on_receipt":
        return inst["clock_start_at"] or fallback
    if kind == "on_awareness":
        return inst["awareness_at"] or fallback
    return inst["determination_at"] or fallback  # on_determination


@dataclass(frozen=True)
class WorkingDayCalendar:
    """The per-install working-day calendar ( P4b, LOCKED operator decision
    #3). ``holidays`` = ISO date strings that are NOT working days; ``working_
    weekdays`` = the working weekday numbers (0=Mon … 6=Sun). Pure value object
    — no config import; build it from config via :func:`working_day_calendar_
    from_config`. A wrong holiday set chains a false ``breached`` into the
    immutable log, so it is operator-configured, never guessed."""
    holidays: frozenset[str] = frozenset()
    working_weekdays: frozenset[int] = frozenset({0, 1, 2, 3, 4})

    def is_working_day(self, d: "date") -> bool:
        return d.weekday() in self.working_weekdays and \
            d.isoformat() not in self.holidays


def working_day_calendar_from_config(cfg: Any) -> WorkingDayCalendar:
    """Build a :class:`WorkingDayCalendar` from a RegulatoryClockConfig (duck-
    typed — takes ``working_day_holidays`` + ``working_week``)."""
    rc = getattr(cfg, "regulatory_clock", None)
    if rc is None:
        return WorkingDayCalendar()
    return WorkingDayCalendar(
        holidays=frozenset(getattr(rc, "working_day_holidays", []) or []),
        working_weekdays=frozenset(
            getattr(rc, "working_week", [0, 1, 2, 3, 4]) or [0, 1, 2, 3, 4]
        ),
    )


def _add_working_days(start: "datetime", n: int, cal: WorkingDayCalendar) -> "datetime":
    """The datetime N WORKING days after ``start`` (skipping non-working
    weekdays + configured holidays), preserving the time-of-day. Counts forward
    one calendar day at a time; each working day decrements the remaining count."""
    d = start
    remaining = int(n)
    while remaining > 0:
        d = d + timedelta(days=1)
        if cal.is_working_day(d.date()):
            remaining -= 1
    return d


def _compute_deadline(
    anchor_iso: str | None, duration_value: int | None, duration_unit: str,
    calendar: WorkingDayCalendar | None = None,
) -> str | None:
    """Derive deadline_at = anchor + duration. ``calendar_day`` = anchor + N
    days. ``working_day`` = anchor + N WORKING days via the per-install
    ``calendar`` (P4b) — when no ``calendar`` is supplied, working_day returns
    None so a working_day clock does NOT arm a WRONG calendar-day deadline (the
    Phase-2 default; the caller passes a calendar to arm an IRB clock). Returns
    an ISO-8601 UTC string, or None when not computable."""
    if not duration_value or duration_value <= 0:
        return None
    anchor = parse_iso(anchor_iso)
    if anchor is None:
        return None
    if duration_unit == "calendar_day":
        return to_utc_iso(anchor + timedelta(days=int(duration_value)))
    if duration_unit == "working_day":
        if calendar is None:
            return None  # no institutional calendar supplied → cannot arm safely
        return to_utc_iso(_add_working_days(anchor, int(duration_value), calendar))
    return None


def _set_write_once_txn(
    conn: sqlite3.Connection, instance_id: int, column: str, value: str,
) -> None:
    """Set a WRITE-ONCE anchor, refusing to overwrite a stamped value. Runs
    INSIDE the caller's open transaction (no commit). Raises ClockStateError if
    the anchor was already set (→ the caller ROLLBACKs) — the legal Day-0 must
    never be re-stamped in place; a correction is a determination_corrected
    event."""
    if column not in _WRITE_ONCE_COLS:  # defensive — all call sites pass a literal
        raise ValueError(f"not a write-once column: {column!r}")
    cur = conn.execute(
        f"UPDATE regulatory_clock_instance SET {column} = ?, updated_at = ? "
        f"WHERE id = ? AND {column} IS NULL",
        (value, now_utc_iso(), instance_id),
    )
    if cur.rowcount != 1:
        existing = conn.execute(
            f"SELECT {column} FROM regulatory_clock_instance WHERE id = ?",
            (instance_id,),
        ).fetchone()
        if existing is None:
            raise ClockStateError(f"instance {instance_id} not found")
        raise ClockStateError(
            f"write-once anchor {column!r} already set on instance "
            f"{instance_id} (={existing[0]!r}); a correction is a new "
            f"determination_corrected event, never an in-place re-stamp"
        )


@db_write
def create_clock_candidate(
    conn: sqlite3.Connection,
    *,
    def_id: int,
    account_id: int,
    case_ref: str,
    responsibility: str = "unknown",
    trigger_message_id: str | None = None,
    raw_deadline_phrase: str | None = None,
    detection_confidence: float | None = None,
    clock_start_at: str | None = None,
    actor_user_id: int | None = None,
) -> int:
    """Create a CANDIDATE clock instance + emit the chained ``detected`` event.

    The entry point for detection (Phase 3) and manual/admin creation. The clock
    starts ``candidate`` — no deadline, no ladder — until a human confirms
    (propose-then-confirm). ``clock_start_at`` is the on_receipt anchor for an
    informational sponsor clock (the email's received_at); leave None for
    on_awareness / on_determination clocks (the human sets the anchor later).
    ``actor_user_id`` is the creating human for a manual create, or None for
    system detection. Returns the new instance_id. State-INSERT + the chained
    ``detected`` event are atomic."""
    now = now_utc_iso()
    with _clock_txn(conn):
        # N-343 R31 (2026-07-04 Phase-4 DA finding) — defensive
        # SELECT-then-INSERT dedup on ``(account_id, case_ref)`` for
        # non-terminal states. The v51 partial-UNIQUE index would
        # raise ``sqlite3.IntegrityError`` on a concurrent second
        # insert; this guard returns the existing id instead so the
        # first-detection path stays idempotent (the caller doesn't
        # care WHICH detection created the candidate, only that one
        # exists). Terminal states (``dismissed``/``breached``/
        # ``submitted``) are excluded from the guard so a legitimate
        # re-detection after terminal creates a fresh candidate,
        # matching the v51 DDL's WHERE clause.
        existing = conn.execute(
            "SELECT id FROM regulatory_clock_instance "
            "WHERE account_id = ? AND case_ref = ? "
            "  AND state NOT IN ('dismissed','breached','submitted') "
            "LIMIT 1",
            (account_id, case_ref),
        ).fetchone()
        if existing is not None:
            return int(existing[0])
        cur = conn.execute(
            "INSERT INTO regulatory_clock_instance "
            "(def_id, account_id, responsibility, trigger_message_id, case_ref, "
            " state, detection_confidence, raw_deadline_phrase, clock_start_at, "
            " ack_required, last_escalation_pct, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, 'candidate', ?, ?, ?, "
            " (SELECT ack_required FROM regulatory_clock_def WHERE id = ?), "
            " 0, ?, ?)",
            (def_id, account_id, responsibility, trigger_message_id, case_ref,
             detection_confidence, raw_deadline_phrase, clock_start_at,
             def_id, now, now),
        )
        instance_id = cur.lastrowid
        emit_clock_event_txn(
            conn, instance_id=instance_id, event_kind="detected",
            actor_user_id=actor_user_id, to_state="candidate",
            detail=f"responsibility={responsibility}",  # bounded enum, non-PHI
        )
    return instance_id


@db_write
def record_awareness(
    conn: sqlite3.Connection, *, instance_id: int, actor_user_id: int,
    awareness_at: str | None = None,
) -> str:
    """Human confirms 'I became aware' — sets the WRITE-ONCE ``awareness_at``
    anchor (the IRB clock's Day-0; planning ruling: human-confirm, never
    auto-inferred). Emits the chained ``awareness_set`` event. Does NOT arm by
    itself — the reportability determination + the responsibility gate arm the
    ladder. Returns the awareness timestamp."""
    inst = _load_instance(conn, instance_id)
    if inst["state"] in _CLOCK_TERMINAL_STATES:
        raise ClockStateError(
            f"instance {instance_id} is terminal ({inst['state']})"
        )
    require_human_clock_actor("awareness_set", actor_user_id)
    aw = awareness_at or now_utc_iso()
    with _clock_txn(conn):
        _set_write_once_txn(conn, instance_id, "awareness_at", aw)
        emit_clock_event_txn(
            conn, instance_id=instance_id, event_kind="awareness_set",
            actor_user_id=actor_user_id, detail="awareness confirmed",
        )
    return aw


@db_write
def confirm_reportable(
    conn: sqlite3.Connection, *, instance_id: int, actor_user_id: int,
    determination_at: str | None = None,
    calendar: WorkingDayCalendar | None = None,
) -> str:
    """Human confirms the safety event is reportable (propose-then-confirm).

    Sets the WRITE-ONCE ``determination_at`` anchor, derives ``deadline_at``, and
    ARMS the clock to ``running`` ONLY when it is escalating AND
    responsibility='i_submit' AND a deadline is computable (the responsibility
    gate). Otherwise the clock stays advisory ``candidate``. ``calendar`` (P4b)
    is the per-install working-day calendar — REQUIRED to arm a ``working_day``
    clock (the IRB headline); without it a working_day clock stays candidate
    (no wrong deadline). Emits the chained ``determined`` event (human
    disposition → actor required). Returns the new state."""
    inst = _load_instance(conn, instance_id)
    if inst["state"] in _CLOCK_TERMINAL_STATES:
        raise ClockStateError(
            f"instance {instance_id} is terminal ({inst['state']}); cannot "
            f"re-determine (use correct_determination)"
        )
    require_human_clock_actor("determined", actor_user_id)
    det = determination_at or now_utc_iso()
    anchor = _resolve_anchor(inst, fallback=det)
    deadline = _compute_deadline(
        anchor, inst["def_duration_value"], inst["def_duration_unit"],
        calendar=calendar,
    )
    arm = (
        inst["def_clock_kind"] == "escalating"
        and inst["responsibility"] == "i_submit"
        and deadline is not None
    )
    new_state = "running" if arm else "candidate"
    with _clock_txn(conn):
        _set_write_once_txn(conn, instance_id, "determination_at", det)
        conn.execute(
            "UPDATE regulatory_clock_instance "
            "SET deadline_at = ?, state = ?, updated_at = ? WHERE id = ?",
            (deadline, new_state, now_utc_iso(), instance_id),
        )
        emit_clock_event_txn(
            conn, instance_id=instance_id, event_kind="determined",
            actor_user_id=actor_user_id, from_state=inst["state"],
            to_state=new_state,
            detail=f"armed={arm} responsibility={inst['responsibility']}",
        )
    return new_state


@db_write
def note_informational_receipt(
    conn: sqlite3.Connection, *, instance_id: int,
) -> str | None:
    """Auto-note a SPONSOR (informational) deadline — no human determination
    needed (it is the sponsor's obligation, surfaced as a 'deadline noted'
    receipt, never escalated). Computes ``deadline_at`` from the on_receipt
    anchor + duration and moves the clock to ``running`` (a display-only
    countdown; the Phase-4 sweep never escalates a clock_kind='informational').
    Emits a chained ``determined`` event with actor=None (a SYSTEM determination
    that this is a notable sponsor deadline). Returns the computed deadline, or
    None if not computable."""
    inst = _load_instance(conn, instance_id)
    if inst["def_clock_kind"] != "informational":
        raise ClockStateError(
            f"note_informational_receipt on a non-informational clock "
            f"({inst['def_clock_kind']}); use confirm_reportable"
        )
    if inst["state"] in _CLOCK_TERMINAL_STATES:
        raise ClockStateError(f"instance {instance_id} is terminal")
    # SF-1 (db-sme + hipaa-sme): IDEMPOTENT — a re-detect/replay of the same
    # sponsor notice must NOT pad the chain with a duplicate `determined` event.
    # Auto-note only from `candidate`; an already-noted (running) receipt is a
    # no-op returning the existing deadline.
    if inst["state"] != "candidate":
        return inst["deadline_at"]
    anchor = _resolve_anchor(inst, fallback=None)
    deadline = _compute_deadline(
        anchor, inst["def_duration_value"], inst["def_duration_unit"],
    )
    with _clock_txn(conn):
        conn.execute(
            "UPDATE regulatory_clock_instance "
            "SET deadline_at = ?, state = 'running', updated_at = ? WHERE id = ?",
            (deadline, now_utc_iso(), instance_id),
        )
        emit_clock_event_txn(
            conn, instance_id=instance_id, event_kind="determined",
            actor_user_id=None, from_state=inst["state"], to_state="running",
            detail="informational sponsor receipt auto-noted",
        )
    return deadline


@db_write
def ack_clock(
    conn: sqlite3.Connection, *, instance_id: int, actor_user_id: int,
) -> str:
    """Acknowledge a running clock — SILENCES pages but does NOT pause or
    discharge it (regulatory clocks have no pause; only an evidence-backed
    submission closes). Sets WRITE-ONCE ``acked_at`` + ``acked_by`` and moves a
    running/at_risk/breached clock to ``acked`` (the Phase-4 sweep still computes
    breach on an acked clock). Emits the chained ``acked`` event. Returns the new
    state."""
    inst = _load_instance(conn, instance_id)
    if inst["state"] in _CLOCK_TERMINAL_STATES:
        raise ClockStateError(f"instance {instance_id} is terminal")
    require_human_clock_actor("acked", actor_user_id)
    silenceable = inst["state"] in ("running", "at_risk", "breached")
    new_state = "acked" if silenceable else inst["state"]
    with _clock_txn(conn):
        _set_write_once_txn(conn, instance_id, "acked_at", now_utc_iso())
        conn.execute(
            "UPDATE regulatory_clock_instance "
            "SET acked_by = ?, state = ?, updated_at = ? WHERE id = ?",
            (actor_user_id, new_state, now_utc_iso(), instance_id),
        )
        emit_clock_event_txn(
            conn, instance_id=instance_id, event_kind="acked",
            actor_user_id=actor_user_id, from_state=inst["state"],
            to_state=new_state,
        )
    return new_state


@db_write
def submit_clock(
    conn: sqlite3.Connection, *, instance_id: int, actor_user_id: int,
    evidence_ref: str | None = None,
) -> str:
    """Discharge the clock with an evidence-backed SUBMISSION (the ONLY thing
    that closes a regulatory clock). Sets WRITE-ONCE ``submitted_at`` +
    ``submitted_by`` + ``submission_evidence_ref`` (the regulator-side filing id,
    NEVER PHI) and moves the clock to terminal ``submitted``. Emits the chained
    ``submitted`` event. Returns 'submitted'."""
    inst = _load_instance(conn, instance_id)
    if inst["state"] in _CLOCK_TERMINAL_STATES:
        raise ClockStateError(
            f"instance {instance_id} already terminal ({inst['state']})"
        )
    require_human_clock_actor("submitted", actor_user_id)
    with _clock_txn(conn):
        _set_write_once_txn(conn, instance_id, "submitted_at", now_utc_iso())
        conn.execute(
            "UPDATE regulatory_clock_instance "
            "SET submitted_by = ?, submission_evidence_ref = ?, "
            "    state = 'submitted', updated_at = ? WHERE id = ?",
            (actor_user_id, evidence_ref, now_utc_iso(), instance_id),
        )
        emit_clock_event_txn(
            conn, instance_id=instance_id, event_kind="submitted",
            actor_user_id=actor_user_id, from_state=inst["state"],
            to_state="submitted",
            delivered_to_ref=evidence_ref,  # filing id, non-PHI
        )
    return "submitted"


@db_write
def dismiss_clock(
    conn: sqlite3.Connection, *, instance_id: int, actor_user_id: int,
    reason: str | None = None,
) -> str:
    """Dismiss a candidate/running clock — a determination of NON-reportability
    (itself chained + retained, never purged). Moves to terminal ``dismissed``.
    Emits the chained ``dismissed`` event. ``reason`` is free-text (may carry
    PHI → hash-only in any gap row; encrypted at rest). Returns 'dismissed'."""
    inst = _load_instance(conn, instance_id)
    if inst["state"] in _CLOCK_TERMINAL_STATES:
        raise ClockStateError(
            f"instance {instance_id} already terminal ({inst['state']})"
        )
    require_human_clock_actor("dismissed", actor_user_id)
    with _clock_txn(conn):
        conn.execute(
            "UPDATE regulatory_clock_instance "
            "SET state = 'dismissed', updated_at = ? WHERE id = ?",
            (now_utc_iso(), instance_id),
        )
        emit_clock_event_txn(
            conn, instance_id=instance_id, event_kind="dismissed",
            actor_user_id=actor_user_id, from_state=inst["state"],
            to_state="dismissed", detail=reason,
        )
    return "dismissed"


@db_write
def correct_determination(
    conn: sqlite3.Connection, *, instance_id: int, actor_user_id: int,
    new_determination_at: str, reason: str,
) -> None:
    """Correct a determination (e.g. later found to duplicate an already-reported
    case) WITHOUT mutating the original write-once ``determination_at`` — a NEW
    append-only ``determination_corrected`` chained event with actor + reason
    (21 CFR Part 11: original preserved, change recorded with who/when/why). For
    an on_determination clock, recomputes the DERIVED ``deadline_at`` cache from
    the corrected anchor; the original anchor column stays immutable as the audit
    Day-0."""
    inst = _load_instance(conn, instance_id)
    require_human_clock_actor("determination_corrected", actor_user_id)
    if inst["determination_at"] is None:
        raise ClockStateError(
            f"instance {instance_id} has no determination to correct"
        )
    new_deadline = None
    if inst["def_clock_start_kind"] == "on_determination":
        new_deadline = _compute_deadline(
            new_determination_at, inst["def_duration_value"],
            inst["def_duration_unit"],
        )
    with _clock_txn(conn):
        if new_deadline is not None:
            conn.execute(
                "UPDATE regulatory_clock_instance "
                "SET deadline_at = ?, updated_at = ? WHERE id = ?",
                (new_deadline, now_utc_iso(), instance_id),
            )
        emit_clock_event_txn(
            conn, instance_id=instance_id, event_kind="determination_corrected",
            actor_user_id=actor_user_id, from_state=inst["state"],
            to_state=inst["state"],
            detail=f"corrected_to={new_determination_at}; {reason}",
        )


# ===========================================================================
# Phase 4a — escalation sweep
# ===========================================================================
#
# Each tick recomputes state PURELY from the anchor + derived deadline_at, so
# the sweep is idempotent and self-healing across restarts (a missed sweep sees
# an already-breached clock next tick, never double-arms). `breached` is a
# LEGAL transition (chained via record_clock_event); `at_risk` is operational
# (state + at_risk_at cache, NOT chained — it would dilute the inspector
# signal). Escalation DELIVERY (the rung notifications) is Phase 4c; this engine
# marks the derived state + chains the breach.

# Hard cap on state transitions applied per tick — a correlated SUSAR blast
# must not stampede the single-writer chain in one tick (design Risks).
_SWEEP_PER_TICK_CAP = 200

# States the sweep evaluates (armed, non-terminal). `acked` still runs
# underneath the page-silence; `breached` stays listed so a late submit/ack can
# still reference it, but _sweep_decide no-ops it (idempotent).
_SWEEPABLE_STATES = ("running", "at_risk", "acked", "breached")


def list_sweepable_instances(conn: sqlite3.Connection, *, limit: int = _SWEEP_PER_TICK_CAP) -> list[dict]:
    """Armed, non-terminal instances with a derived deadline (joined to the
    def's escalation_lead_pcts), oldest-deadline first (the most urgent swept
    first under the per-tick cap)."""
    placeholders = ", ".join(["?"] * len(_SWEEPABLE_STATES))
    rows = conn.execute(
        f"SELECT i.id, i.state, i.deadline_at, i.clock_start_at, "
        f"       i.last_escalation_pct, i.account_id, i.calendar_written_at, "
        f"       ea.user_id AS owner_user_id, "
        f"       u.email AS owner_email, "
        f"       d.clock_kind AS def_clock_kind, d.title AS def_title, "
        f"       d.escalation_lead_pcts AS def_escalation_lead_pcts "
        f"FROM regulatory_clock_instance i "
        f"JOIN regulatory_clock_def d ON d.id = i.def_id "
        f"JOIN email_accounts ea ON ea.id = i.account_id "
        f"LEFT JOIN users u ON u.id = ea.user_id "
        f"WHERE i.state IN ({placeholders}) AND i.deadline_at IS NOT NULL "
        f"ORDER BY i.deadline_at ASC LIMIT ?",
        (*_SWEEPABLE_STATES, int(limit)),
    ).fetchall()
    return [dict(r) for r in rows]


# Escalation ladder rungs (design trimmed to 80%/24h/breach for the single-PI
# persona; 4a's `at_risk` folds the 80%+24h marks → rung 1, breach → rung 3).
# rung 2 (a distinct 24h page) is a documented future refinement.
_RUNG_AT_RISK = 1
_RUNG_BREACH = 3


def _due_escalation_rung(state: str, last_escalation_pct: int) -> int | None:
    """The escalation rung to FIRE now, or None if the current state's rung was
    already fired (``last_escalation_pct`` dedup — a rung never re-pages). Only
    escalating clocks reach here; informational receipts never escalate."""
    last = int(last_escalation_pct or 0)
    if state == "breached":
        return _RUNG_BREACH if last < _RUNG_BREACH else None
    if state == "at_risk":
        return _RUNG_AT_RISK if last < _RUNG_AT_RISK else None
    return None


@db_write
def record_escalation(
    conn: sqlite3.Connection, instance_id: int, *, rung: int,
    delivered_to_ref: str | None = None, detail: str | None = None,
) -> None:
    """Record an escalation rung firing — the chained ``escalated`` event
    (system actor) + advance the ``last_escalation_pct`` dedup marker so the
    rung never re-pages. Atomic.

    AUDIT-HONESTY SEMANTICS (db-sme P4c): this fires DURING the sweep, BEFORE the
    best-effort SMTP push runs in ``_send_clock_escalations``. So
    ``delivered_to_ref`` means "ADDRESSED TO" (the rung's intended recipient —
    the §164.308(a)(1)(ii)(D) disclosure DECISION), NOT a transmission receipt.
    The DURABLE delivery is the always-on in-app Compliance surface (which
    re-renders current clock state every load); the SMTP push is a best-effort
    secondary channel that is NOT retried (the marker advances regardless of
    send outcome → the rung pushes at most once). A transient SMTP failure loses
    that rung's EMAIL but never the escalation signal (the in-app surface
    stands). A future ``escalation_delivery_failed`` follow-on event could make
    the transport outcome explicit — documented refinement, not done here."""
    inst = _load_instance(conn, instance_id)
    with _clock_txn(conn):
        conn.execute(
            "UPDATE regulatory_clock_instance "
            "SET last_escalation_pct = ?, updated_at = ? WHERE id = ?",
            (int(rung), now_utc_iso(), instance_id),
        )
        emit_clock_event_txn(
            conn, instance_id=instance_id, event_kind="escalated",
            actor_user_id=None, from_state=inst["state"], to_state=inst["state"],
            escalation_rung=int(rung), delivered_to_ref=delivered_to_ref,
            detail=detail,
        )


def _sweep_decide(
    *, deadline_at: str | None, clock_start_at: str | None,
    lead_pcts_json: str | None, current_state: str, now_iso: str,
) -> str | None:
    """Pure: the DERIVED target state for an armed clock, or None for no change.

    breached = now past the deadline (from any non-terminal armed state,
    idempotent — a clock already 'breached' yields None). at_risk = within 24h
    of the deadline OR past the first escalation-lead %, only from 'running'
    (acked clocks are page-silenced; their breach still fires)."""
    if not deadline_at:
        return None
    now = parse_iso(now_iso)
    deadline = parse_iso(deadline_at)
    if now is None or deadline is None:
        return None
    if now >= deadline:
        return "breached" if current_state != "breached" else None
    if current_state != "running":
        return None  # at_risk only escalates a running clock
    at_risk = (deadline - now) <= timedelta(hours=24)
    if not at_risk and clock_start_at:
        start = parse_iso(clock_start_at)
        if start is not None:
            total = (deadline - start).total_seconds()
            if total > 0:
                elapsed_pct = (now - start).total_seconds() / total * 100.0
                # load_json_col SSOT (census /#16b): the persisted
                # def_escalation_lead_pcts column degrades to [] on a NULL /
                # corrupt / wrong-shape value (a stored non-list would have
                # crashed the later min() — load_json_col's type-guard makes
                # that safe), exactly reproducing the prior except→[] default.
                leads = load_json_col(
                    lead_pcts_json, default=[],
                    label="regulatory_clock_def.escalation_lead_pcts",
                )
                if leads and elapsed_pct >= min(leads):
                    at_risk = True
    return "at_risk" if at_risk else None


@db_write
def mark_clock_breached(conn: sqlite3.Connection, instance_id: int) -> None:
    """Mark a clock breached (a missed legal deadline) — state→breached, with
    the chained `breached` event (system actor). Atomic. The breach INSTANT is
    the chained event's ``created_at`` (there is no denormalized ``breach_at``
    instance column — the event row is the SSOT for the legal moment).
    Idempotent: a no-op if already breached or terminal.

    NOTE (db-sme SHOULD-FIX-2): the autonomous sweep can never double-breach
    (the breached-state guard below). The ONE re-fire path is intentional — a
    human re-acks an already-breached clock (`ack_clock` allows breached→acked),
    and the next sweep re-derives breached from the now-`acked` state, chaining a
    SECOND breached event. Each is a distinct, human-initiated, append-only legal
    fact; do NOT "fix" this into a swallow."""
    inst = _load_instance(conn, instance_id)
    if inst["state"] == "breached" or inst["state"] in _CLOCK_TERMINAL_STATES:
        return
    with _clock_txn(conn):
        conn.execute(
            "UPDATE regulatory_clock_instance "
            "SET state = 'breached', updated_at = ? WHERE id = ?",
            (now_utc_iso(), instance_id),
        )
        emit_clock_event_txn(
            conn, instance_id=instance_id, event_kind="breached",
            actor_user_id=None, from_state=inst["state"], to_state="breached",
            detail="deadline missed (sweep-derived)",
        )


@db_write
def mark_clock_at_risk(conn: sqlite3.Connection, instance_id: int) -> None:
    """Mark a running clock at_risk (operational — state + at_risk_at cache, NOT
    chained). Idempotent: a no-op unless currently 'running'."""
    now = now_utc_iso()
    conn.execute(
        "UPDATE regulatory_clock_instance "
        "SET state = 'at_risk', at_risk_at = COALESCE(at_risk_at, ?), "
        "    updated_at = ? WHERE id = ? AND state = 'running'",
        (now, now, instance_id),
    )
    conn.commit()


@db_write
def mark_clock_calendar_written(
    conn: sqlite3.Connection, instance_id: int, *, when: str | None = None,
) -> None:
    """Stamp ``calendar_written_at`` ONCE (never-clobber: ``WHERE ... IS NULL``)
    so the  direct calendar-write fires at most once per clock — the deadline
    lands as a SINGLE live calendar event even though a clock may escalate twice
    (at_risk then breach). NOT an audit-chain write (the disclosure decision was
    already chained as the ``escalated`` event); a plain idempotency stamp on the
    instance row, mirroring the .ics attachment which is likewise not separately
    chained.

    The stamp is set AFTER a successful create_event, so a crash between the
    calendar write and this commit yields at most ONE *duplicate* event on the
    next sweep (at-least-once). That bias is deliberate: mark-before-write would
    instead silently DROP the event on a create failure (a missed deadline) — the
    worse direction for a compliance reminder. (db-sme P4f.)"""
    ts = when or now_utc_iso()
    conn.execute(
        "UPDATE regulatory_clock_instance "
        "SET calendar_written_at = ?, updated_at = ? "
        "WHERE id = ? AND calendar_written_at IS NULL",
        (ts, ts, instance_id),
    )
    conn.commit()


def sweep_regulatory_clocks(
    conn: sqlite3.Connection, *, now_iso: str | None = None,
) -> dict:
    """One sweep tick (sync — dispatched OFF-loop via db_call). Recomputes the
    derived state for each armed clock and applies the transition. Returns
    ``{breached, at_risk, scanned}`` counts. Bounded by ``_SWEEP_PER_TICK_CAP``."""
    now_iso = now_iso or now_utc_iso()
    rows = list_sweepable_instances(conn)
    breached = at_risk = escalated = 0
    notifications: list[dict] = []
    for r in rows:
        target = _sweep_decide(
            deadline_at=r["deadline_at"], clock_start_at=r["clock_start_at"],
            lead_pcts_json=r["def_escalation_lead_pcts"],
            current_state=r["state"], now_iso=now_iso,
        )
        if target == "breached":
            mark_clock_breached(conn, r["id"])
            breached += 1
        elif target == "at_risk":
            mark_clock_at_risk(conn, r["id"])
            at_risk += 1
        # Escalation ladder — ESCALATING clocks only (informational sponsor
        # receipts never escalate). Dedup via last_escalation_pct so a rung
        # never re-pages. delivered_to_ref = the owner user-id (non-PHI; the
        # owner is always in-scope for their own account — the BAA gate for
        # higher-rung delegate/compliance contacts is the next delivery unit).
        if r["def_clock_kind"] == "escalating":
            new_state = target or r["state"]
            rung = _due_escalation_rung(new_state, r["last_escalation_pct"])
            if rung is not None:
                owner = r["owner_user_id"]
                record_escalation(
                    conn, r["id"], rung=rung,
                    delivered_to_ref=(str(owner) if owner is not None else None),
                    detail=f"rung {rung} reached ({new_state})",
                )
                escalated += 1
                # Collect the PHI-FREE notification spec for the sweeper to push
                # (the audit record above already landed; this drives the
                # best-effort transport). label = def TITLE (non-PHI policy
                # metadata); NO case_ref / raw_deadline_phrase.
                if r["owner_email"]:
                    notifications.append({
                        "instance_id": r["id"], "rung": rung,
                        "to_addr": r["owner_email"],
                        "label": r["def_title"], "deadline_at": r["deadline_at"],
                        "state": new_state,
                        #  P4f — the direct calendar-write rides the same
                        # notification: account_id resolves the owner's calendar
                        # provider; calendar_written gates one-event-per-clock.
                        "account_id": r["account_id"],
                        "calendar_written": bool(r["calendar_written_at"]),
                    })
    return {
        "breached": breached, "at_risk": at_risk,
        "escalated": escalated, "scanned": len(rows),
        "notifications": notifications,
    }


def clock_deadline_phrase(days_left: int | None) -> str:
    """SSOT human deadline wording — ``due in N day(s)`` / ``OVERDUE by N
    day(s)`` / ``deadline not set`` — from a pre-computed ``days_left`` (floor
    of full days remaining; negative = overdue, magnitude = ceil days past the
    deadline so a sub-24h-overdue clock never reads "OVERDUE by 1 day"). ONE
    funnel so the escalation email, the per-recipient digest section, and any
    countdown render IDENTICAL wording (PD#5 — two mirrored copies WILL drift)."""
    if days_left is None:
        return "deadline not set"
    if days_left >= 0:
        return f"due in {days_left} day(s)"
    return f"OVERDUE by {abs(days_left)} day(s)"


def build_escalation_notification(
    *, label: str, deadline_at: str | None, state: str, deep_link: str,
    now_iso: str | None = None,
) -> dict:
    """Build the PHI-FREE escalation notification (subject + body). Minimum-
    necessary (§164.502(b)): the clock LABEL (non-PHI def title) + days-left +
    a deep-link back to the in-app clock — NO case_ref, NO raw_deadline_phrase,
    NO trigger-email subject/sender/body. Advisory copy (never "server-
    authoritative")."""
    now = parse_iso(now_iso or now_utc_iso())
    dl = parse_iso(deadline_at) if deadline_at else None
    # days_left = floor full days remaining (negative = overdue); the SSOT
    # clock_deadline_phrase turns it into the wording (floor due / ceil overdue).
    days_left = None
    if dl is not None and now is not None:
        days_left = int((dl - now).total_seconds() // 86400)
    when = clock_deadline_phrase(days_left)
    head = "OVERDUE" if state == "breached" else "Reminder"
    subject = f"[{head}] Regulatory deadline — {label}"
    body = (
        f"{label}\n{when} ({deadline_at or 'n/a'} UTC).\n\n"
        f"This is a reminder based on your configured policy — verify against "
        f"your SOP. Open the clock for details: {deep_link}\n"
    )
    return {"subject": subject, "body": body}


def user_owns_clock_account(
    conn: sqlite3.Connection, user_id: int, instance_id: int,
) -> bool:
    """PD#9 ACTUATOR gate: True iff ``instance_id``'s account is OWNED by
    ``user_id``. Every disposition POST (ack/submit/dismiss/confirm) MUST check
    this BEFORE acting — a user must not act on another user's clock by POSTing
    its id. Owner-only (not delegate) for the write path: a disposition sets a
    write-once legal anchor, so it is restricted to the account owner."""
    row = conn.execute(
        "SELECT ea.user_id AS owner_id "
        "FROM regulatory_clock_instance i "
        "JOIN email_accounts ea ON ea.id = i.account_id "
        "WHERE i.id = ?",
        (instance_id,),
    ).fetchone()
    return row is not None and row["owner_id"] == user_id


def list_compliance_clocks_for_account(
    conn: sqlite3.Connection, *, account_id: int,
    account_name: str | None = None, now_iso: str | None = None,
) -> list[dict]:
    """The HIPAA-MINIMAL compliance-clock view for ONE account (label + state +
    days-left + account name), NO ``case_ref`` / ``raw_deadline_phrase``. The
    per-account building block of both :func:`list_compliance_clocks` (the
    user-facing /clocks surface) and the per-recipient digest "Regulatory
    deadlines" section. Single account → no cross-account existence info leaks
    into a per-account surface. No NEW HIPAA access-event is required for this
    read: the /clocks caller is the owner viewing their OWN accounts, and the
    digest caller scopes ``account_id`` to the data-subject account whose own
    mailbox receives the (system-initiated, envelope-locked, already
    §164.312(b)-audited) digest. A maintainer wiring this into an ACTOR-bearing
    surface where a non-owner could read another user's clocks MUST add the
    actor≠owner access-event there. Newest-deadline last (most urgent first);
    terminal clocks excluded."""
    now = parse_iso(now_iso or now_utc_iso())
    rows = conn.execute(
        "SELECT i.id, i.state, i.deadline_at, i.responsibility, "
        "       d.title AS label, d.clock_kind, d.regime "
        "FROM regulatory_clock_instance i "
        "JOIN regulatory_clock_def d ON d.id = i.def_id "
        "WHERE i.account_id = ? "
        "      AND i.state NOT IN ('submitted','dismissed') "
        "ORDER BY (i.deadline_at IS NULL), i.deadline_at ASC LIMIT 100",
        (account_id,),
    ).fetchall()
    out: list[dict] = []
    for r in rows:
        days_left = None
        dl = parse_iso(r["deadline_at"]) if r["deadline_at"] else None
        if dl is not None and now is not None:
            days_left = int((dl - now).total_seconds() // 86400)
        out.append({
            "instance_id": r["id"],
            "label": r["label"],
            "state": r["state"],
            "clock_kind": r["clock_kind"],
            "regime": r["regime"],
            "responsibility": r["responsibility"],
            "deadline_at": r["deadline_at"],
            "days_left": days_left,
            # show the account NAME, never a bare id (feedback_no_account_id_alone).
            "account_name": account_name or "(unnamed account)",
        })
    return out


def list_compliance_clocks(
    conn: sqlite3.Connection, *, user_id: int, now_iso: str | None = None,
) -> list[dict]:
    """The user's regulatory clocks for the user-facing /clocks surface —
    HIPAA-MINIMAL display (label + state + days-left + account name), NO
    ``case_ref`` / ``raw_deadline_phrase`` (the design's "label + days only").

    Scoped to the user's OWNED accounts (owner self-access, §164.502(a) — NO
    actor≠owner audit fires here). The cross-account super-view (the admin
    /compliance system-wide view, with §164.514(b)(2) small-cell suppression +
    per-member audit-before-render fail-closed) is DEFERRED per the planning
    ruling; this view surfaces NO cross-account existence info. Newest-deadline
    last (most urgent first); terminal clocks excluded. Per-account work funnels
    through :func:`list_compliance_clocks_for_account` (ONE SELECT + projection —
    no drift between the /clocks surface and the digest section)."""
    from email_triage.web.db import list_email_accounts
    now_iso = now_iso or now_utc_iso()
    out: list[dict] = []
    for acct in list_email_accounts(conn, user_id=user_id):
        out.extend(list_compliance_clocks_for_account(
            conn, account_id=acct["id"],
            account_name=acct.get("name"), now_iso=now_iso,
        ))
    return out
