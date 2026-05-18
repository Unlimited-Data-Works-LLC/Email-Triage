"""Digest configuration storage + migration.

This module is the **single source of truth** for the digest model.
Each email account carries a list of digest configurations stored
under ``settings.digest_configs:<account_id>``. Two kinds:

- ``preset_daily_activity`` — the always-available preset that
  formerly lived as ``acct.config.recipient_digest_enabled`` +
  ``recipient_digest_send_at``. Renders the legacy table format
  (when / sender / category / subject / why), all triaged messages,
  rolling 24h window. **Format-locked.** Operators can toggle
  enable / send-time only.
- ``custom`` — operator-defined named digest. Filter dimensions
  (folders / categories / tags / from / subject / list-id /
  has_attachment / actions / advanced-raw-query), time window
  (from-options like Today / Last 7d / Custom / Since-last-sent),
  cadence (daily / weekly / monthly), render selector (grouped
  list / plain list / table). Default render is grouped list;
  table is opt-in.

This module owns:

* The schema dataclasses + serialization helpers.
* The migration shim that promotes legacy storage
  (``recipient_digest_enabled`` + ``digest_schedules:<id>``) into
  the unified ``digest_configs:<id>`` list on first read.
* ``list_digest_configs`` / ``get_digest_config`` /
  ``upsert_digest_config`` / ``delete_digest_config`` — the CRUD
  surface used by the web router and the OpenClaw API.

Render + scheduler logic live in ``actions.recipient_digest`` (for
the preset) and ``actions.digest_render`` (for custom; new).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field, asdict
from typing import Any


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: Reserved id for the per-account preset card. Always rendered at
#: the top of the digest list; can't be deleted (the writer ignores
#: delete attempts on this id).
PRESET_ID = "preset:daily_activity"

#: Setting key prefix.
_STORE_KEY_PREFIX = "digest_configs:"

#: Legacy keys we migrate from on first read.
_LEGACY_RECIPIENT_FLAG = "recipient_digest_enabled"
_LEGACY_RECIPIENT_TIME = "recipient_digest_send_at"
_LEGACY_SCHEDULES_KEY_PREFIX = "digest_schedules:"

#: Allowed enums — validated on save so the UI / API / scheduler
#: don't have to defend against typos.
KINDS = ("preset_daily_activity", "custom")
CADENCES = ("daily", "weekly", "monthly")
WINDOW_KINDS = (
    "rolling_24h", "today", "yesterday", "last_7d", "this_week",
    "last_30d", "this_month", "custom", "since_last_sent",
)
READ_STATES = ("any", "unread", "read")
RENDER_AS = (
    "grouped_list", "plain_list", "table",
    # Newsletter-shaped renderers — extract articles per source via
    # the LLM (re-fetches body_html from the provider) and group by
    # sender. Two visual treatments share the extraction step:
    #   "newsletter"         — compact Jinja template (matches what
    #                          ``digest.generate_digest`` produces
    #                          today by default).
    #   "newsletter_classic" — older fuller styled-HTML template
    #                          recovered from pre-8eaf959 history;
    #                          h2 title + date subtitle + sender h3
    #                          with bottom border + bullets + footer.
    "newsletter", "newsletter_classic",
)
GROUP_BYS = ("none", "category", "folder", "day", "sender")
ACTION_KEYS = ("moved", "labeled", "drafted", "escalated", "skipped")

#: Column keys available for the table render's ``columns`` config.
#:
#: - ``datetime`` — message Date header (or triage_run created_at fallback)
#: - ``sender`` — From header value
#: - ``headline`` — Subject (renamed for the newsletter-flavoured
#:   default column set; same source field as ``subject``)
#: - ``subject`` — alias for ``headline``; explicit when an operator
#:   wants the column labelled "Subject"
#: - ``link`` — first URL extracted from the message body (provider
#:   populates ``EmailMessage.links`` via the engine extractor)
#: - ``category`` — classifier output
#: - ``reason`` — classifier rationale (HIPAA-redacted to a fixed
#:   phrase per source in HIPAA mode)
#: - ``preview`` — first 200 chars of body (HIPAA-redacted to
#:   ``[redacted]``)
#: - ``unread`` — bool glyph (✉ / ✓) from labels
#: - ``attachment`` — bool glyph from attachments list
#: - ``folder`` — folder of origin (cross-folder digests)
COLUMN_KEYS = (
    "datetime", "sender", "headline", "subject", "link",
    "category", "reason", "preview", "unread", "attachment",
    "folder",
)
SORT_DIRECTIONS = ("asc", "desc")


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

@dataclass
class DigestSchedule:
    cadence: str = "daily"
    time_local: str = "08:10"
    days_of_week: list[int] = field(default_factory=list)


@dataclass
class DigestWindow:
    kind: str = "rolling_24h"
    custom_start_iso: str = ""
    custom_end_iso: str = ""


@dataclass
class DigestFilter:
    read_state: str = "any"
    folders: list[str] = field(default_factory=list)
    categories: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    from_addr: str = ""
    subject: str = ""
    list_id: str = ""
    has_attachment: bool | None = None
    actions: list[str] = field(default_factory=list)
    advanced: str = ""


@dataclass
class DigestColumn:
    """One column in a table-render digest.

    ``key`` picks the source field (see ``COLUMN_KEYS``).
    ``label`` is an optional display override; empty string falls
    back to a sensible default per key (e.g. ``datetime`` →
    "When", ``headline`` → "Headline").
    ``sort_priority`` orders the multi-key sort: 0 = unsorted,
    1 = primary, 2 = secondary, etc. Columns with priority 0
    don't participate in the sort. Multiple columns can carry
    priority 1 if the operator wants ties broken by other keys
    in column-list order — but the typical usage is one column
    at each priority level.
    ``sort_direction`` is per-column (``asc`` | ``desc``) so the
    operator can pin Date descending + Sender ascending on the
    same digest.
    """
    key: str = "datetime"
    label: str = ""
    sort_priority: int = 0
    sort_direction: str = "desc"


def _default_columns() -> list[DigestColumn]:
    """Default column set for newly-created custom digests.

    Matches the operator's flag at the time the schema landed:
    Datetime · Sender · Article headline · URL/link. Datetime
    sorts descending as the primary key (newest first); other
    columns unsorted.
    """
    return [
        DigestColumn(key="datetime", label="When",
                     sort_priority=1, sort_direction="desc"),
        DigestColumn(key="sender", label="Sender"),
        DigestColumn(key="headline", label="Headline"),
        DigestColumn(key="link", label="Link"),
    ]


@dataclass
class DigestFormat:
    # Custom-digest default flipped to ``table`` so the operator-
    # configurable ``columns`` field below has somewhere to render.
    # Other render_as values (``grouped_list`` / ``plain_list``)
    # ignore ``columns`` and use their fixed shapes.
    render_as: str = "table"
    group_by: str = "category"
    # Default flipped to False (2026-05-07) per operator feedback
    # — the per-row preview adds noise on content-aggregator
    # newsletters where the subject already carries the headline.
    # A one-time migration in web/migrations.py flips the flag on
    # all existing custom digests so the default is consistent
    # across new + old configs. Toggle stays available for
    # operators who want richer per-row context.
    include_body_preview: bool = False
    max_rows: int = 50
    columns: list[DigestColumn] = field(
        default_factory=_default_columns,
    )
    # Optional Jinja override for the newsletter format's HTML
    # body. Empty string falls through to DEFAULT_DIGEST_TEMPLATE
    # (the compact built-in) when render_as="newsletter", or to
    # _CLASSIC_NEWSLETTER_TEMPLATE when render_as="newsletter_classic".
    # Operators paste / edit a Jinja template with the same
    # context vars (groups, cat_phrase, signature, date_str,
    # category, digest_name, total_articles) as the defaults.
    # Ignored for table / grouped_list / plain_list formats —
    # those have fixed render shapes that don't accept overrides.
    html_template: str = ""


@dataclass
class DigestConfig:
    id: str = ""
    kind: str = "custom"
    name: str = ""
    enabled: bool = True
    schedule: DigestSchedule = field(default_factory=DigestSchedule)
    window: DigestWindow = field(default_factory=DigestWindow)
    filter: DigestFilter = field(default_factory=DigestFilter)
    format: DigestFormat = field(default_factory=DigestFormat)


def _coerce_column_list(raw: Any) -> list[DigestColumn]:
    """Hydrate a list of stored column dicts → DigestColumn list.

    Drops malformed entries silently; keeps the rest. Empty input
    returns the default column set so a stored config that
    pre-dates the columns field gets the default shape on read.
    """
    if not isinstance(raw, list):
        return _default_columns()
    out: list[DigestColumn] = []
    for d in raw:
        if isinstance(d, DigestColumn):
            out.append(d)
            continue
        if not isinstance(d, dict):
            continue
        fields_set = {
            f.name for f in DigestColumn.__dataclass_fields__.values()
        }
        out.append(
            DigestColumn(**{k: v for k, v in d.items() if k in fields_set})
        )
    return out or _default_columns()


def _coerce_format(raw: Any) -> "DigestFormat":
    """DigestFormat hydrator that knows about the nested
    ``columns`` list. Generic ``_coerce`` would shove the raw
    list-of-dicts in as a Python list[dict] instead of a
    list[DigestColumn], which then breaks the validator + render
    path."""
    if isinstance(raw, DigestFormat):
        return raw
    if not isinstance(raw, dict):
        return DigestFormat()
    fields_set = {
        f.name for f in DigestFormat.__dataclass_fields__.values()
    }
    base = {k: v for k, v in raw.items() if k in fields_set}
    cols_raw = base.pop("columns", None)
    fmt = DigestFormat(**base)
    if cols_raw is not None:
        fmt.columns = _coerce_column_list(cols_raw)
    return fmt


def _coerce(cls, raw: Any):
    """Build a dataclass from a dict, ignoring unknown keys.

    Lets the schema evolve without breaking on stored configs that
    predate (or post-date) the deploy reading them.
    """
    if isinstance(raw, cls):
        return raw
    if not isinstance(raw, dict):
        return cls()
    fields_set = {f.name for f in cls.__dataclass_fields__.values()}
    return cls(**{k: v for k, v in raw.items() if k in fields_set})


def from_dict(raw: dict[str, Any]) -> DigestConfig:
    """Hydrate a stored dict into a DigestConfig.

    Tolerates partial / unknown keys; missing fields default. Nested
    dataclasses get the same coerce treatment so legacy partial
    configs (e.g. just ``schedule`` set) don't blow up.
    """
    if not isinstance(raw, dict):
        return DigestConfig(id=_new_id(), name="(invalid)")
    cfg = DigestConfig(
        id=str(raw.get("id") or _new_id()),
        kind=str(raw.get("kind") or "custom"),
        name=str(raw.get("name") or ""),
        enabled=bool(raw.get("enabled", True)),
    )
    if cfg.kind not in KINDS:
        cfg.kind = "custom"
    cfg.schedule = _coerce(DigestSchedule, raw.get("schedule"))
    cfg.window = _coerce(DigestWindow, raw.get("window"))
    cfg.filter = _coerce(DigestFilter, raw.get("filter"))
    cfg.format = _coerce_format(raw.get("format"))
    return cfg


def to_dict(cfg: DigestConfig) -> dict[str, Any]:
    """Plain-dict round-trip for JSON storage / API surfaces."""
    return asdict(cfg)


def _new_id() -> str:
    """Mint an opaque id for a new digest config."""
    return f"digest_{uuid.uuid4().hex[:12]}"


# ---------------------------------------------------------------------------
# Storage CRUD
# ---------------------------------------------------------------------------

def _store_key(account_id: int) -> str:
    return f"{_STORE_KEY_PREFIX}{account_id}"


def list_digest_configs(db, account_id: int) -> list[DigestConfig]:
    """Return all digest configs for an account, preset first.

    Reads the unified ``digest_configs:<id>`` setting if present.
    Otherwise migrates from legacy storage:

    1. ``recipient_digest_enabled`` (in ``email_accounts.config_json``)
       becomes a ``preset_daily_activity`` entry.
    2. ``digest_schedules:<id>`` list becomes one ``custom`` entry
       per schedule, with the legacy ``category`` field promoted to
       a single-element ``categories`` list and ``render_as`` set
       to ``grouped_list`` (default for custom).

    The migrated list is persisted in the unified format on first
    read so subsequent reads don't repeat the work. Always inserts
    a preset entry — even on accounts that never enabled it — so
    the UI can render the toggle uniformly.
    """
    from email_triage.web.db import get_setting, set_setting

    raw = get_setting(db, _store_key(account_id))
    if isinstance(raw, list):
        configs = [from_dict(d) for d in raw if isinstance(d, dict)]
    else:
        configs = _migrate_legacy(db, account_id)
        # Persist migrated form so we don't redo on every read.
        set_setting(
            db, _store_key(account_id),
            [to_dict(c) for c in configs],
        )

    # Ensure the preset card is always present + first.
    if not any(c.id == PRESET_ID for c in configs):
        configs.insert(0, _default_preset())
    else:
        preset = next(c for c in configs if c.id == PRESET_ID)
        others = [c for c in configs if c.id != PRESET_ID]
        configs = [preset] + others
    return configs


def get_digest_config(
    db, account_id: int, digest_id: str,
) -> DigestConfig | None:
    """Return one digest config by id, or None when absent."""
    for cfg in list_digest_configs(db, account_id):
        if cfg.id == digest_id:
            return cfg
    return None


def upsert_digest_config(
    db, account_id: int, cfg: DigestConfig,
) -> DigestConfig:
    """Insert or update a digest config in the account's list.

    Mints an id if the incoming config doesn't carry one.
    Refuses to demote the preset to ``custom`` — preset id is
    locked. Returns the persisted config (id-stamped).
    """
    from email_triage.web.db import set_setting

    configs = list_digest_configs(db, account_id)
    if not cfg.id:
        cfg.id = _new_id()
    if cfg.id == PRESET_ID:
        cfg.kind = "preset_daily_activity"
        cfg.name = "Daily Activity"
        cfg.format = DigestFormat(
            render_as="table", group_by="none",
            include_body_preview=False, max_rows=200,
        )

    found = False
    for i, existing in enumerate(configs):
        if existing.id == cfg.id:
            configs[i] = cfg
            found = True
            break
    if not found:
        configs.append(cfg)

    set_setting(
        db, _store_key(account_id),
        [to_dict(c) for c in configs],
    )
    return cfg


def delete_digest_config(
    db, account_id: int, digest_id: str,
) -> bool:
    """Remove a digest config by id. Refuses to delete the preset.

    Returns True if a row was removed, False otherwise.
    """
    from email_triage.web.db import set_setting

    if digest_id == PRESET_ID:
        return False
    configs = list_digest_configs(db, account_id)
    new_configs = [c for c in configs if c.id != digest_id]
    if len(new_configs) == len(configs):
        return False
    set_setting(
        db, _store_key(account_id),
        [to_dict(c) for c in new_configs],
    )
    return True


# ---------------------------------------------------------------------------
# Migration
# ---------------------------------------------------------------------------

def _default_preset() -> DigestConfig:
    """Build the always-on preset card for a freshly-migrated account.

    Disabled by default; the operator opts in via the toggle.
    Send time defaults to 08:10 (the legacy default).
    """
    return DigestConfig(
        id=PRESET_ID,
        kind="preset_daily_activity",
        name="Daily Activity",
        enabled=False,
        schedule=DigestSchedule(cadence="daily", time_local="08:10"),
        window=DigestWindow(kind="rolling_24h"),
        filter=DigestFilter(),  # ignored for preset; kept for shape
        format=DigestFormat(
            render_as="table", group_by="none",
            include_body_preview=False, max_rows=200,
        ),
    )


def _migrate_legacy(db, account_id: int) -> list[DigestConfig]:
    """Convert legacy storage into the unified config list.

    Pulls:
    - ``recipient_digest_enabled`` / ``recipient_digest_send_at``
      from the account's ``config_json`` (one preset entry).
    - ``digest_schedules:<id>`` list (zero+ custom entries).

    Doesn't delete the legacy fields — leaves them in place so a
    rollback can still read them. The unified-format write happens
    in the caller after we hand back the list.
    """
    from email_triage.web.db import get_email_account, get_setting

    out: list[DigestConfig] = []
    acct = get_email_account(db, account_id)
    if acct is None:
        return [_default_preset()]
    cfg_json = acct.get("config") or {}

    preset = _default_preset()
    legacy_enabled = bool(cfg_json.get(_LEGACY_RECIPIENT_FLAG, False))
    legacy_time = (cfg_json.get(_LEGACY_RECIPIENT_TIME) or "").strip()
    if legacy_enabled:
        preset.enabled = True
    if legacy_time:
        preset.schedule.time_local = legacy_time
    out.append(preset)

    legacy_schedules = get_setting(
        db, f"{_LEGACY_SCHEDULES_KEY_PREFIX}{account_id}",
    )
    if isinstance(legacy_schedules, list):
        for sched in legacy_schedules:
            if not isinstance(sched, dict):
                continue
            cat = sched.get("category") or ""
            cfg = DigestConfig(
                id=_new_id(),
                kind="custom",
                name=(
                    f"{cat.title()} digest" if cat else "Custom digest"
                ),
                enabled=bool(sched.get("enabled", True)),
                schedule=DigestSchedule(
                    cadence=sched.get("cadence", "daily"),
                    time_local=sched.get("time_utc", "07:00"),
                    days_of_week=list(
                        sched.get("days_of_week") or []
                    ),
                ),
                window=DigestWindow(kind="rolling_24h"),
                filter=DigestFilter(
                    categories=[cat] if cat else [],
                ),
                format=DigestFormat(
                    render_as="grouped_list", group_by="category",
                ),
            )
            out.append(cfg)
    return out


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

_STATE_KEY_PREFIX = "digest_state:"


def _state_key(account_id: int, digest_id: str) -> str:
    return f"{_STATE_KEY_PREFIX}{account_id}:{digest_id}"


def get_last_sent(db, account_id: int, digest_id: str) -> str | None:
    """Read the last-sent ISO timestamp for one digest.

    The preset (``preset:daily_activity``) inherits from the
    legacy ``recipient_digest_state:<acct_id>`` row when the new
    key is absent — preserves first-fire idempotence across the
    Phase 4 cutover so the migration boundary doesn't double-send.
    Custom digests have no legacy parallel; absent = first fire.
    """
    from email_triage.web.db import get_setting
    new_state = get_setting(db, _state_key(account_id, digest_id)) or {}
    last = (new_state or {}).get("last_sent_at")
    if last:
        return last
    if digest_id == PRESET_ID:
        legacy = (
            get_setting(db, f"recipient_digest_state:{account_id}") or {}
        )
        return (legacy or {}).get("last_sent_at")
    return None


def mark_sent(
    db, account_id: int, digest_id: str,
    now: Any, row_count: int,
) -> None:
    """Stamp the last-sent state for one digest after a successful send.

    For the preset, also writes the legacy state key so a rollback
    past Phase 4 picks up the new fire and doesn't re-send.
    """
    from email_triage.web.db import set_setting
    iso = now.isoformat() if hasattr(now, "isoformat") else str(now)
    payload = {"last_sent_at": iso, "row_count": int(row_count)}
    set_setting(db, _state_key(account_id, digest_id), payload)
    if digest_id == PRESET_ID:
        set_setting(
            db, f"recipient_digest_state:{account_id}", payload,
        )


def validate(cfg: DigestConfig) -> list[str]:
    """Return a list of human-readable validation errors, empty when ok.

    Used by the save handler + API to bounce malformed configs with
    actionable messages instead of letting a typo break the
    scheduler loop.
    """
    errors: list[str] = []
    if cfg.kind not in KINDS:
        errors.append(f"kind must be one of {KINDS}")
    if cfg.kind == "custom" and not cfg.name.strip():
        errors.append("name is required for custom digests")
    if cfg.schedule.cadence not in CADENCES:
        errors.append(f"cadence must be one of {CADENCES}")
    if cfg.schedule.cadence == "weekly" and not cfg.schedule.days_of_week:
        errors.append(
            "weekly cadence requires at least one day_of_week",
        )
    # HH:MM
    t = cfg.schedule.time_local
    if not (
        len(t) == 5 and t[2] == ":"
        and t[:2].isdigit() and t[3:].isdigit()
        and 0 <= int(t[:2]) <= 23 and 0 <= int(t[3:]) <= 59
    ):
        errors.append("time_local must be HH:MM (24h)")
    if cfg.window.kind not in WINDOW_KINDS:
        errors.append(f"window.kind must be one of {WINDOW_KINDS}")
    if cfg.window.kind == "custom":
        if not cfg.window.custom_start_iso:
            errors.append("window.custom_start_iso required for custom window")
    if cfg.filter.read_state not in READ_STATES:
        errors.append(f"filter.read_state must be one of {READ_STATES}")
    for a in cfg.filter.actions:
        if a not in ACTION_KEYS:
            errors.append(f"unknown action key: {a}")
    if cfg.format.render_as not in RENDER_AS:
        errors.append(f"format.render_as must be one of {RENDER_AS}")
    if cfg.format.group_by not in GROUP_BYS:
        errors.append(f"format.group_by must be one of {GROUP_BYS}")
    if cfg.format.max_rows < 1 or cfg.format.max_rows > 1000:
        errors.append("format.max_rows must be 1..1000")

    # Column config (table render uses these; other render_as
    # values ignore them but we still validate so a future
    # render_as=table flip doesn't surface stale column config
    # errors at send time).
    if cfg.format.render_as == "table" and not cfg.format.columns:
        errors.append("format.columns must not be empty for table render")
    seen_keys: set[str] = set()
    for i, col in enumerate(cfg.format.columns or []):
        if col.key not in COLUMN_KEYS:
            errors.append(
                f"format.columns[{i}].key must be one of {COLUMN_KEYS}"
            )
        if col.sort_direction not in SORT_DIRECTIONS:
            errors.append(
                f"format.columns[{i}].sort_direction must be "
                f"one of {SORT_DIRECTIONS}"
            )
        if col.sort_priority < 0:
            errors.append(
                f"format.columns[{i}].sort_priority must be >= 0"
            )
        if col.key in seen_keys:
            errors.append(
                f"format.columns[{i}].key duplicates earlier "
                f"column ({col.key})"
            )
        seen_keys.add(col.key)
    return errors


# ---------------------------------------------------------------------------
# One-time backfill — restore newsletter render_as on legacy configs
# ---------------------------------------------------------------------------


def _backfill_newsletter_render_as(conn) -> int:
    """Flip category=newsletters configs to render_as=newsletter.

    Background. The 2026-05-05 multi-digest migration converted
    legacy ``digest_schedules:<id>`` rows into custom DigestConfigs
    with ``render_as="grouped_list"`` (see ``_migrate_legacy``).
    The pre-migration scheduler called the LLM article-extraction
    rendering directly — operators with category=newsletters
    schedules got article-card emails. Post-migration the same
    data renders as a grouped list of subjects + senders,
    losing the per-article extraction.

    Article-card rendering re-shipped 2026-05-06 as ``render_as=
    "newsletter"`` (and ``"newsletter_classic"`` for the older
    styled HTML). This helper flips category-newsletter custom
    configs that are still on grouped_list / plain_list — i.e.
    untouched migration output — to ``render_as="newsletter"``.

    Idempotent. Only flips configs whose:
      - kind == "custom"
      - filter.categories list contains "newsletters" (or the
        singular "newsletter")
      - format.render_as is "grouped_list" or "plain_list"

    Configs the operator explicitly switched away from the
    migration default (e.g. table, or a different category) are
    untouched. Re-running the function does nothing on a
    second pass.

    Returns the count of configs flipped.
    """
    from email_triage.web.db import get_setting, set_setting

    flipped = 0
    # Find every account that has a digest_configs setting key.
    # The setting layer doesn't expose a key prefix scan helper;
    # iterate accounts via email_accounts.
    rows = conn.execute("SELECT id FROM email_accounts").fetchall()
    for r in rows:
        account_id = int(r["id"]) if hasattr(r, "keys") else int(r[0])
        key = f"{_STORE_KEY_PREFIX}{account_id}"
        raw = get_setting(conn, key)
        if not isinstance(raw, list):
            continue
        changed = False
        for entry in raw:
            if not isinstance(entry, dict):
                continue
            if entry.get("kind") != "custom":
                continue
            cats = (entry.get("filter") or {}).get("categories") or []
            if not isinstance(cats, list):
                continue
            cats_lower = {str(c).lower() for c in cats}
            if not (cats_lower & {"newsletters", "newsletter"}):
                continue
            fmt = entry.get("format") or {}
            cur_render = fmt.get("render_as")
            if cur_render not in ("grouped_list", "plain_list"):
                continue
            fmt["render_as"] = "newsletter"
            entry["format"] = fmt
            changed = True
            flipped += 1
        if changed:
            set_setting(conn, key, raw)
    return flipped
