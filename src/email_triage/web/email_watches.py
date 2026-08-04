"""Email watches — operator-defined match-and-fire on incoming mail.

the backlog . A watch is a lightweight rule that fires action(s)
when a freshly-classified message matches a filter. Use cases:

    * "Text me when my boss writes." → escalate (SMS gateway)
    * "Ping the inventory webhook when an invoice lands." → webhook
    * "Both — text me AND ping inventory." → escalate + webhook

Filter dimensions (any combination):
    * ``from``           — exact email address (case-insensitive substring)
    * ``from_domain``    — domain only (after ``@``)
    * ``subject_contains`` — substring (case-insensitive)
    * ``keyword``        — substring (case-insensitive) checked against
                           subject and body_text
    * ``advanced``       — raw provider query, evaluated by the upstream
                           classifier flow (best-effort; this module
                           just stashes the string for the operator)

Scope:
    * ``account_id``     — single account (``account_id`` set, ``all_accounts``
                           false), or
    * ``all_accounts``   — every NON-HIPAA account on the install. HIPAA
                           accounts are excluded from the all-scope sweep:
                           PHI never leaves the box via webhook, and the
                           operator sets a per-account watch if they want
                           an SMS for a HIPAA mailbox.

Storage shape (``email_watches`` table, migration v9):

    watch_id      TEXT PK
    name          TEXT
    enabled       INT
    account_id    INT NULL  (NULL means "all_accounts")
    filter_json   TEXT  (JSON dict — see ``WatchFilter``)
    actions_json  TEXT  (JSON dict — see ``WatchActions``)
    created_at    TEXT
    updated_at    TEXT

Per-watch HMAC secret lives in the secrets store under
``watch_<id>_hmac``. Minted on create; rotated never (delete and
re-create if the secret is suspected leaked).

HIPAA contract:
    * Webhook payload under HIPAA mode (per-account ``hipaa`` flag
      true OR system flag set) carries first-name + sender-domain
      only; subject is replaced with ``[redacted]``; body never appears.
    * Audit row written on every fire — ``access_log`` with outcome
      ``watch_fired`` and a JSON detail string carrying the watch_id,
      action mix, redaction posture, and message_id.
"""

from __future__ import annotations

from email_triage.db._helpers import dump_json_col, load_json_col

import json
import sqlite3
import uuid
from dataclasses import dataclass, field, asdict
from email_triage._isotime import now_utc_iso
from typing import Any
from email_triage.triage_logging import REDACTED_PLACEHOLDER  # N-217 R23


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------


@dataclass
class WatchFilter:
    """Match dimensions. Each is optional; empty string means "no filter
    on that dimension". An empty filter (everything blank) matches every
    message — explicit; the operator opts in by leaving fields empty.
    """
    from_addr: str = ""
    from_domain: str = ""
    subject_contains: str = ""
    keyword: str = ""
    advanced: str = ""


@dataclass
class EscalateAction:
    enabled: bool = False
    # Optional override; when blank the action falls back to the
    # account's notify_email (the same routing the regular escalate
    # action uses).
    notify_email: str = ""
    # Channels list — kept as a free-form list of labels so future
    # carriers / SMS gateways layer in without a schema migration.
    # Common values: ``"sms"`` (carrier email-to-SMS gateway),
    # ``"email"`` (plain notify_email).
    channels: list[str] = field(default_factory=lambda: ["sms"])


@dataclass
class WebhookAction:
    enabled: bool = False
    url: str = ""


@dataclass
class AutoRetireAction:
    """ — auto-retire a watch once it has produced N matches (fires).

    ``after_n <= 0`` disables the feature (the default — a watch runs
    indefinitely). ``action`` is ``"disable"`` (set ``enabled=0``, reversible
    — the operator can re-enable) or ``"delete"`` (remove the watch row). Stored
    inside ``actions_json`` (no schema migration); the match count is derived
    from the durable ``watch_fire_idempotency`` table at fire time, so it counts
    DISTINCT delivered matches and survives restarts."""
    after_n: int = 0
    action: str = "disable"


_AUTO_RETIRE_ACTIONS = ("disable", "delete")


@dataclass
class WatchActions:
    escalate: EscalateAction = field(default_factory=EscalateAction)
    webhook: WebhookAction = field(default_factory=WebhookAction)
    auto_retire: AutoRetireAction = field(default_factory=AutoRetireAction)


@dataclass
class EmailWatch:
    watch_id: str = ""
    name: str = ""
    enabled: bool = True
    account_id: int | None = None  # None: legacy "all accounts" row;
    # post-v17 fan-out, NULL should never appear in fresh rows.
    filter: WatchFilter = field(default_factory=WatchFilter)
    actions: WatchActions = field(default_factory=WatchActions)
    created_at: str = ""
    updated_at: str = ""
    # Post-#154 (migration v17). NULL on legacy rows that pre-date
    # the column; the new editor groups those by
    # ``(created_by_user_id, name)`` as a fallback.
    watch_group_id: str | None = None
    created_by_user_id: int | None = None

    @property
    def all_accounts(self) -> bool:
        # Kept for back-compat with the webhook-API JSON serializer and
        # any downstream reader; post-v17 fresh rows always have an
        # account_id, so this is False in practice.
        return self.account_id is None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _now_iso() -> str:
    return now_utc_iso()


def _new_id() -> str:
    # N-244 R24: SSOT — `_ids.new_short_id`. Byte-identical wire shape.
    from email_triage._ids import new_short_id
    return new_short_id("watch")


def hmac_secret_key(watch_id: str) -> str:
    """Stable secrets-store key for a watch's HMAC secret."""
    return f"watch_{watch_id}_hmac"


def _coerce(cls, raw: Any):
    """Build a dataclass from a dict, ignoring unknown keys."""
    if isinstance(raw, cls):
        return raw
    if not isinstance(raw, dict):
        return cls()
    fields_set = {f.name for f in cls.__dataclass_fields__.values()}
    return cls(**{k: v for k, v in raw.items() if k in fields_set})


def _coerce_actions(raw: Any) -> WatchActions:
    if isinstance(raw, WatchActions):
        return raw
    if not isinstance(raw, dict):
        return WatchActions()
    return WatchActions(
        escalate=_coerce(EscalateAction, raw.get("escalate")),
        webhook=_coerce(WebhookAction, raw.get("webhook")),
        auto_retire=_coerce(AutoRetireAction, raw.get("auto_retire")),
    )


def from_dict(raw: dict[str, Any]) -> EmailWatch:
    """Hydrate a stored dict into an EmailWatch.

    Tolerates partial / unknown keys; missing fields default. Used by
    the webhook API + the UI route handlers.
    """
    if not isinstance(raw, dict):
        return EmailWatch()
    w = EmailWatch(
        watch_id=str(raw.get("watch_id") or raw.get("id") or ""),
        name=str(raw.get("name") or ""),
        enabled=bool(raw.get("enabled", True)),
        account_id=(
            int(raw["account_id"])
            if raw.get("account_id") not in (None, "", "null")
            else None
        ),
        created_at=str(raw.get("created_at") or ""),
        updated_at=str(raw.get("updated_at") or ""),
        watch_group_id=(
            str(raw["watch_group_id"])
            if raw.get("watch_group_id") not in (None, "")
            else None
        ),
        created_by_user_id=(
            int(raw["created_by_user_id"])
            if raw.get("created_by_user_id") not in (None, "", "null")
            else None
        ),
    )
    w.filter = _coerce(WatchFilter, raw.get("filter"))
    w.actions = _coerce_actions(raw.get("actions"))
    return w


def to_dict(w: EmailWatch) -> dict[str, Any]:
    """Plain dict for JSON storage / API surface."""
    return asdict(w)


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def validate(w: EmailWatch) -> list[str]:
    """Return a list of human-readable validation errors. Empty = ok."""
    errors: list[str] = []
    name = (w.name or "").strip()
    if not name:
        errors.append("Watch name is required.")
    elif len(name) > 80:
        errors.append("Watch name must be 80 characters or fewer.")

    # At least one filter dimension OR an advanced query — otherwise the
    # watch matches everything, which is almost certainly an operator
    # mistake. They can still set advanced="" and one structured field
    # to "" to opt into a catch-all, but we surface a hint.
    f = w.filter
    has_any = any([
        (f.from_addr or "").strip(),
        (f.from_domain or "").strip(),
        (f.subject_contains or "").strip(),
        (f.keyword or "").strip(),
        (f.advanced or "").strip(),
    ])
    if not has_any:
        errors.append(
            "Add at least one filter (from, sender domain, subject, "
            "keyword, or an advanced query) — otherwise this watch "
            "fires on every email."
        )

    if "@" in (f.from_domain or ""):
        errors.append(
            "Sender domain must not contain '@' — enter just the domain "
            "part (e.g., 'example.com', not 'alice@example.com'). Use "
            "the 'From address' field for a full address."
        )

    # At least one action selected.
    a = w.actions
    if not (a.escalate.enabled or a.webhook.enabled):
        errors.append(
            "Pick at least one action — Send a text alert, Call a webhook, "
            "or both."
        )

    if a.webhook.enabled:
        url = (a.webhook.url or "").strip()
        if not url:
            errors.append(
                "Webhook URL is required when 'Call a webhook' is selected."
            )
        elif not (url.startswith("http://") or url.startswith("https://")):
            errors.append(
                "Webhook URL must start with http:// or https:// — "
                "example: http://192.168.1.10:8080/hook."
            )

    #  — auto-retire config. Off by default (after_n <= 0); when on,
    # require a sane positive threshold + a known action.
    ar = a.auto_retire
    if ar.after_n:
        if not isinstance(ar.after_n, int) or ar.after_n < 0:
            errors.append("Auto-retire 'after N matches' must be a positive whole number.")
        if ar.action not in _AUTO_RETIRE_ACTIONS:
            errors.append(
                "Auto-retire action must be 'disable' (re-enableable) or 'delete'."
            )

    return errors


# ---------------------------------------------------------------------------
# Storage CRUD
# ---------------------------------------------------------------------------


def _row_to_watch(row: sqlite3.Row | tuple) -> EmailWatch:
    if hasattr(row, "keys"):
        d = dict(row)
    else:
        # Defensive — we always set sqlite3.Row factory in init_db, but
        # let raw-tuple fallback work too for future direct callers.
        keys = (
            "watch_id", "name", "enabled", "account_id",
            "filter_json", "actions_json", "created_at", "updated_at",
            "watch_group_id", "created_by_user_id",
        )
        d = dict(zip(keys, row))
    return EmailWatch(
        watch_id=d["watch_id"],
        name=d["name"],
        enabled=bool(d["enabled"]),
        account_id=d["account_id"],
        filter=_coerce(WatchFilter, load_json_col(d["filter_json"], default={})),
        actions=_coerce_actions(load_json_col(d["actions_json"], default={})),
        created_at=d.get("created_at", "") or "",
        updated_at=d.get("updated_at", "") or "",
        watch_group_id=d.get("watch_group_id") or None,
        created_by_user_id=d.get("created_by_user_id") or None,
    )


def list_watches(
    db: sqlite3.Connection,
    *,
    account_id: int | None = None,
    include_all_accounts: bool = True,
) -> list[EmailWatch]:
    """Return watches scoped to an account.

    When ``account_id`` is set: returns watches whose ``account_id``
    matches OR (when ``include_all_accounts`` is true) whose
    ``account_id`` is NULL (the cross-account watches).

    When ``account_id`` is None: returns every watch (admin /admin/watches
    surface). Order: created_at ascending.
    """
    if account_id is None:
        rows = db.execute(
            "SELECT * FROM email_watches ORDER BY created_at ASC"
        ).fetchall()
    elif include_all_accounts:
        rows = db.execute(
            "SELECT * FROM email_watches "
            "WHERE account_id = ? OR account_id IS NULL "
            "ORDER BY created_at ASC",
            (account_id,),
        ).fetchall()
    else:
        rows = db.execute(
            "SELECT * FROM email_watches "
            "WHERE account_id = ? "
            "ORDER BY created_at ASC",
            (account_id,),
        ).fetchall()
    return [_row_to_watch(r) for r in rows]


def get_watch(db: sqlite3.Connection, watch_id: str) -> EmailWatch | None:
    row = db.execute(
        "SELECT * FROM email_watches WHERE watch_id = ?", (watch_id,),
    ).fetchone()
    if row is None:
        return None
    return _row_to_watch(row)


def upsert_watch(db: sqlite3.Connection, w: EmailWatch) -> EmailWatch:
    """Insert or update a watch. Mints id + created_at if absent."""
    if not w.watch_id:
        w.watch_id = _new_id()
    now = _now_iso()
    if not w.created_at:
        w.created_at = now
    w.updated_at = now
    filter_json = dump_json_col(asdict(w.filter))
    actions_json = dump_json_col(asdict(w.actions))
    db.execute(
        "INSERT INTO email_watches "
        "(watch_id, name, enabled, account_id, filter_json, actions_json, "
        " created_at, updated_at, watch_group_id, created_by_user_id) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
        "ON CONFLICT(watch_id) DO UPDATE SET "
        " name = excluded.name, enabled = excluded.enabled, "
        " account_id = excluded.account_id, "
        " filter_json = excluded.filter_json, "
        " actions_json = excluded.actions_json, "
        " updated_at = excluded.updated_at, "
        " watch_group_id = excluded.watch_group_id, "
        " created_by_user_id = excluded.created_by_user_id",
        (
            w.watch_id, w.name, 1 if w.enabled else 0,
            w.account_id, filter_json, actions_json,
            w.created_at, w.updated_at,
            w.watch_group_id, w.created_by_user_id,
        ),
    )
    db.commit()
    return w


# ---------------------------------------------------------------------------
# Group helpers —  (/profile/watches uses these to render N rows
# that share a watch_group_id as one logical row for editing).
# ---------------------------------------------------------------------------


def new_watch_group_id() -> str:
    """Mint a fresh ``watch_group_id`` (uuid hex)."""
    return uuid.uuid4().hex


def list_watch_groups_for_user(
    db: sqlite3.Connection, user_id: int,
) -> list[dict[str, Any]]:
    """Return one entry per logical watch (group) owned by ``user_id``.

    Each entry has:
      * ``group_id``         — synthetic; equals ``watch_group_id`` when
                               set, else ``"name:<name>"`` for legacy
                               rows that pre-date the column.
      * ``watch_group_id``   — actual column value (None on legacy).
      * ``representative``   — one :class:`EmailWatch` (the earliest-
                               created row in the group) used to render
                               common fields (name, enabled, filter,
                               actions) in the editor list.
      * ``account_ids``      — list of every email_accounts.id this
                               group fires on (i.e. every row's
                               ``account_id`` in the group).
      * ``watch_ids``        — list of every ``watch_id`` in the group.

    Ordering: groups are sorted by the representative's ``created_at``.

    "Owned by user_id" means at least one row in the group has
    ``created_by_user_id = user_id`` OR ``email_accounts.user_id =
    user_id`` for the row's account. The OR clause keeps backfilled
    rows (created_by_user_id set from the account owner during the
    v17 migration) visible to the right operator AND makes admins
    who manually delete-and-recreate via SQL show up to the account
    owner rather than orphaning the watch.
    """
    rows = db.execute(
        "SELECT ew.*, ea.user_id AS acct_owner_id "
        "FROM email_watches ew "
        "LEFT JOIN email_accounts ea ON ew.account_id = ea.id "
        "WHERE ew.created_by_user_id = ? OR ea.user_id = ? "
        "ORDER BY ew.created_at ASC, ew.watch_id ASC",
        (user_id, user_id),
    ).fetchall()

    by_group: dict[str, dict[str, Any]] = {}
    for r in rows:
        d = dict(r)
        wgi = d.get("watch_group_id")
        # Fallback grouping for legacy rows: same (creator, name).
        # Use a stable string key for both cases so the dict ordering
        # below is deterministic across legacy + new rows.
        if wgi:
            key = f"gid:{wgi}"
        elif d.get("created_by_user_id"):
            # Legacy rows with a KNOWN creator still group by (creator, name).
            key = f"legacy:{d['created_by_user_id']}:{d.get('name') or ''}"
        else:
            #  — a doubly-NULL legacy row (no watch_group_id AND no creator)
            # is its OWN group, keyed by watch_id. Grouping NULL-creator rows by
            # name would merge two UNRELATED watches that happen to share a name
            # → an auto-retire/delete on one would wrongly hit the other.
            # Mirrored in _group_watch_ids.
            key = f"legacy:none:{d.get('watch_id')}"

        if key not in by_group:
            by_group[key] = {
                "group_id": key,
                "watch_group_id": wgi,
                "representative": _row_to_watch(r),
                "account_ids": [],
                "watch_ids": [],
            }
        entry = by_group[key]
        if d.get("account_id") is not None:
            entry["account_ids"].append(int(d["account_id"]))
        entry["watch_ids"].append(d["watch_id"])

    return list(by_group.values())


def get_watch_group(
    db: sqlite3.Connection, group_id: str, user_id: int,
) -> dict[str, Any] | None:
    """Fetch one watch group by the synthetic ``group_id`` key.

    The ``group_id`` shape mirrors :func:`list_watch_groups_for_user`:
    ``gid:<uuid_hex>`` for the post-v17 column-backed case, or
    ``legacy:<creator>:<name>`` for legacy rows. Returns None if no
    group exists, OR if the user doesn't own at least one row in
    the group (route handlers convert that into 404 to avoid
    enumerating group ids).
    """
    groups = list_watch_groups_for_user(db, user_id)
    for g in groups:
        if g["group_id"] == group_id:
            return g
    return None


def save_watch_group(
    db: sqlite3.Connection,
    *,
    user_id: int,
    group_id: str | None,
    name: str,
    enabled: bool,
    filter_: WatchFilter,
    actions: WatchActions,
    target_account_ids: list[int],
) -> tuple[str, list[str], list[str]]:
    """Insert / update / delete watch rows so the group exactly matches
    ``target_account_ids``.

    Behaviour for each ticked account_id:
      * row exists in group → UPDATE (name / enabled / filter / actions).
      * row missing         → INSERT new row sharing the group's
                              ``watch_group_id``.
    Behaviour for each currently-bound account_id NOT in target:
      * row exists in group → DELETE (its HMAC secret is the caller's
                              responsibility to clean up; storage
                              CRUD is side-effect-only on the DB).

    Returns ``(group_id_final, created_watch_ids, deleted_watch_ids)``.
    ``group_id_final`` is the synthetic ``gid:<uuid>`` key for the
    saved group — callers can redirect to it via a URL like
    ``/profile/watches/<group_id_final>/edit``.

    Caller-side invariants:
      * ``target_account_ids`` should be deduplicated + HIPAA-
        filtered BEFORE calling. This helper does not re-check HIPAA;
        the route handler is the boundary that knows the operator's
        permission set.
      * ``user_id`` is the creator-attribution for any newly-inserted
        row. Existing rows keep their original ``created_by_user_id``.
    """
    existing = None
    if group_id:
        existing = get_watch_group(db, group_id, user_id)

    if existing is not None:
        wgi = existing["watch_group_id"] or new_watch_group_id()
        existing_by_acct: dict[int, EmailWatch] = {}
        for wid in existing["watch_ids"]:
            w = get_watch(db, wid)
            if w is not None and w.account_id is not None:
                existing_by_acct[int(w.account_id)] = w
    else:
        wgi = new_watch_group_id()
        existing_by_acct = {}

    target_set = set(int(a) for a in target_account_ids)
    existing_set = set(existing_by_acct.keys())

    created_watch_ids: list[str] = []
    deleted_watch_ids: list[str] = []

    # UPDATE + INSERT.
    for acct_id in target_set:
        if acct_id in existing_by_acct:
            w = existing_by_acct[acct_id]
            w.name = name
            w.enabled = enabled
            w.filter = filter_
            w.actions = actions
            w.watch_group_id = wgi
            # Preserve the original creator on update; do not
            # overwrite with the actor's user_id.
            upsert_watch(db, w)
        else:
            w = EmailWatch(
                watch_id="",
                name=name,
                enabled=enabled,
                account_id=acct_id,
                filter=filter_,
                actions=actions,
                watch_group_id=wgi,
                created_by_user_id=user_id,
            )
            upsert_watch(db, w)
            created_watch_ids.append(w.watch_id)

    # DELETE the ones the operator unticked.
    for acct_id in (existing_set - target_set):
        w = existing_by_acct[acct_id]
        if delete_watch(db, w.watch_id):
            deleted_watch_ids.append(w.watch_id)

    return f"gid:{wgi}", created_watch_ids, deleted_watch_ids


def delete_watch(db: sqlite3.Connection, watch_id: str) -> bool:
    """Remove a watch row. Returns True if a row was removed.

    Deleting a watch does NOT remove its HMAC secret from the secrets
    store automatically — that is left to the caller (the UI / API
    handlers do the cleanup). Keeps this function side-effect-only on
    the DB.
    """
    cur = db.execute(
        "DELETE FROM email_watches WHERE watch_id = ?", (watch_id,),
    )
    db.commit()
    return cur.rowcount > 0


def _group_watch_ids(db: sqlite3.Connection, watch: EmailWatch) -> list[str]:
    """Every ``watch_id`` in the SAME logical watch (group) as ``watch``.

    A user-facing watch is a GROUP of per-account rows sharing a
    ``watch_group_id`` (``save_watch_group`` fans the multi-account select out
    to one row per account). The grouping here MIRRORS
    :func:`list_watch_groups_for_user`: by ``watch_group_id`` when set, else the
    legacy ``(created_by_user_id, name)`` key for pre-v17 rows that have a
    KNOWN creator. A doubly-NULL legacy row (no group column AND no creator) is
    a SINGLETON — see . Returns ``[watch.watch_id]`` as a defensive fallback
    if the lookup finds nothing (e.g. an unsaved watch).
    """
    if watch.watch_group_id:
        rows = db.execute(
            "SELECT watch_id FROM email_watches WHERE watch_group_id = ?",
            (watch.watch_group_id,),
        ).fetchall()
    elif watch.created_by_user_id is not None:
        # Legacy fallback for a KNOWN creator — match (creator, name). A
        # NULL-creator row is excluded by the equality (NULL = ? is never true),
        # mirroring list_watch_groups_for_user's known-creator key.
        rows = db.execute(
            "SELECT watch_id FROM email_watches "
            "WHERE watch_group_id IS NULL "
            "AND created_by_user_id = ? "
            "AND IFNULL(name, '') = IFNULL(?, '')",
            (watch.created_by_user_id, watch.name),
        ).fetchall()
    else:
        #  — a doubly-NULL legacy row (no watch_group_id AND no creator) is a
        # SINGLETON: grouping NULL-creator rows by name would over-group two
        # UNRELATED same-name watches, so an auto-retire/delete on one would
        # wrongly hit the other. Mirrors list_watch_groups_for_user.
        return [watch.watch_id]
    ids = [r[0] for r in rows]
    return ids or [watch.watch_id]


def delete_watch_hmac_secrets(secrets: Any, watch_ids: list[str]) -> None:
    """Best-effort: remove each watch's HMAC secret (``watch_<id>_hmac``) from
    the secrets store. Backends without a ``delete`` primitive (or that error)
    leave a dangling key — harmless, since ``watch_id``s are never reused so the
    key is never matched again. The SSOT both the interactive watch-delete and
    the  auto-retire DELETE call, so the two clean up identically."""
    if secrets is None or not hasattr(secrets, "delete"):
        return
    for wid in watch_ids:
        try:
            secrets.delete(hmac_secret_key(wid))
        except Exception:
            pass


def maybe_auto_retire_watch(
    db: sqlite3.Connection, watch: EmailWatch, *, secrets: Any = None,
) -> str | None:
    """ — retire a watch that has hit its auto-retire match threshold.

    Call AFTER a new DELIVERED fire has been recorded in
    ``watch_fire_idempotency`` (the durable, per-distinct-message fire log).

    Counts at the GROUP grain: a user-facing watch may span several accounts
    (one ``email_watches`` row each, sharing a ``watch_group_id``), but the
    operator sets ONE ``after_n`` threshold for the whole watch. So this sums
    delivered fires across EVERY row in the group and, at/above
    ``actions.auto_retire.after_n``, retires the group ATOMICALLY:
      * ``"disable"`` — ``enabled = 0`` on every row (REVERSIBLE; re-enableable),
      * ``"delete"``  — remove every row in the group (+ purge its now-dead
        ``watch_fire_idempotency`` rows AND, when ``secrets`` is threaded in,
        each row's ``watch_<id>_hmac`` secret — ; ``watch_id``s never reused).
    A single-account watch is just a group of one, so its behavior is unchanged.
    Counting per-row would make "after N" mean "N PER ACCOUNT" and, for delete,
    fragment the group account-by-account — the bug this grain fixes.

    Returns ``"disabled"`` / ``"deleted"`` if it retired, else ``None`` (which
    includes the off case, ``after_n <= 0``). Counting the durable table means
    the threshold is exact across restarts + ignores idempotent re-fires.
    Sync DB work — dispatch via ``db_call`` (its  RLock serializes the whole
    call, so the multi-statement delete/disable is atomic against other writers).
    """
    ar = getattr(watch.actions, "auto_retire", None)
    if not ar or not ar.after_n or ar.after_n <= 0:
        return None
    ids = _group_watch_ids(db, watch)
    placeholders = ",".join("?" for _ in ids)
    row = db.execute(
        f"SELECT COUNT(*) FROM watch_fire_idempotency "
        f"WHERE watch_id IN ({placeholders})",
        ids,
    ).fetchone()
    fires = int(row[0] if row else 0)
    if fires < ar.after_n:
        return None
    #  — record the retirement in access_log (operator-visible on /compliance)
    # BEFORE the action, so a DELETE that removes the rows still leaves the trail.
    # Best-effort: the retire is the source of truth + the runner still log.info's,
    # so a failed audit row must not block the retire.
    try:
        write_auto_retire_audit_row(
            db, watch=watch, account_id=watch.account_id,
            action=ar.action, fires=fires, after_n=ar.after_n,
            rows_affected=len(ids),
        )
    except Exception:
        # N-242b R24: TriageLogger SSOT.
        from email_triage.triage_logging import get_logger
        get_logger("web.email_watches").warning(
            "watch auto-retire audit row failed (continuing)",
            watch_id=watch.watch_id,
        )
    if ar.action == "delete":
        # Atomic group delete + purge the group's dead fire log.
        db.execute(
            f"DELETE FROM watch_fire_idempotency WHERE watch_id IN ({placeholders})",
            ids,
        )
        db.execute(
            f"DELETE FROM email_watches WHERE watch_id IN ({placeholders})",
            ids,
        )
        db.commit()
        #  — also purge each deleted watch's HMAC secret. The interactive
        # delete path already does this; the auto-retire DELETE used to leave
        # the per-watch ``watch_<id>_hmac`` key dangling. Best-effort + after
        # the row delete commits (the rows are the source of truth; a leftover
        # secret is harmless but untidy). When ``secrets`` isn't threaded in
        # (e.g. a db-only test caller), this is a no-op.
        delete_watch_hmac_secrets(secrets, ids)
        return "deleted"
    # "disable" (default): reversible — disable every row in the group.
    db.execute(
        f"UPDATE email_watches SET enabled = 0, updated_at = ? "
        f"WHERE watch_id IN ({placeholders})",
        [_now_iso(), *ids],
    )
    db.commit()
    return "disabled"


# ---------------------------------------------------------------------------
# Matcher
# ---------------------------------------------------------------------------


def _email_address(sender: str) -> str:
    """Pull the addr-spec out of a From header.

    "Alice <a@b.com>" -> "a@b.com"
    "a@b.com"          -> "a@b.com"

    A7 (census 2026-06-09): delegates to the bare-address SSOT. The old
    ``s[s.index("<"):s.index(">")]`` first-bracket slice produced garbage
    when the display name itself contained ``>`` (e.g. ``"A > B" <a@b>``);
    the SSOT regex anchors on the addr-spec block. (The SSOT also
    lower-cases — correct for case-insensitive sender/domain matching.)
    """
    from email_triage.mail_headers import extract_bare_address
    return extract_bare_address(sender)


def _domain_of(addr: str) -> str:
    # N-71: delegate to the mail_headers.extract_domain SSOT (rsplit on the
    # rightmost @ so double-@ spoof addresses resolve to the real domain).
    from email_triage.mail_headers import extract_domain as _ed
    return _ed(addr)


def matches(watch: EmailWatch, *, sender: str, subject: str,
            body_text: str = "") -> bool:
    """True iff the watch's filter matches the message metadata.

    Any-of-empty-string is treated as "no filter on that dimension".
    All non-empty dimensions must hit (AND across dimensions). Within
    a single dimension the match is case-insensitive substring (for
    addresses + domain it normalises to lowercase first; for keyword
    it checks subject AND body_text together).

    The ``advanced`` field is informational at the match layer — it's
    intended to be threaded into the upstream provider query so that
    the provider returns only matching messages. The matcher does not
    re-evaluate provider syntax; if ``advanced`` is set and no other
    structured field is, this matcher returns True (the operator
    delegated the match to the provider). When BOTH advanced AND
    structured fields are set, the structured fields are AND-applied
    (the operator can use advanced as the gross filter and structured
    as the fine-tune).
    """
    if not watch.enabled:
        return False
    f = watch.filter

    has_structured = any([
        (f.from_addr or "").strip(),
        (f.from_domain or "").strip(),
        (f.subject_contains or "").strip(),
        (f.keyword or "").strip(),
    ])
    has_advanced = bool((f.advanced or "").strip())

    # Catch-all branch: every structured dim is empty AND no advanced.
    # An empty filter matches every message — validate() warns the
    # operator at save-time, but the matcher itself stays predictable
    # for the test path.
    if not has_structured and not has_advanced:
        return True

    # Advanced-only: trust the provider; matcher is permissive.
    if has_advanced and not has_structured:
        return True

    # run21 D3 fold: route BOTH needle and haystack through canonical_email
    # SSOT — N-317 IDNA parity. Without this the haystack (sender_email /
    # sender_domain) was NOT IDNA-normalized while the from_addr needle
    # was — a §164.312(a)(1) watcher allow-list bypass on IDN A/U-label
    # envelope variants (alice@münchen.de vs alice@xn--mnchen-3ya.de).
    from email_triage.mail_headers import canonical_email
    sender_email = canonical_email(sender)
    # Derive domain from the already-canonicalized sender so the domain
    # gate inherits the IDNA fold; empty-string sentinel preserved when
    # sender has no @ (canonical_email returns "" or a no-@ bare form).
    sender_domain = sender_email.rpartition("@")[2] if "@" in sender_email else ""
    subj_l = (subject or "").lower()
    body_l = (body_text or "").lower()

    if (f.from_addr or "").strip():
        # N-253 R25: route through canonical-email SSOT so a display-
        # name-wrapped filter value matches the bare-address sender_email
        # against the allow-list gate.
        if canonical_email(f.from_addr) not in sender_email:
            return False
    if (f.from_domain or "").strip():
        # run21 D3 fold: IDNA-normalize the needle via the canonical_email
        # SSOT (synthetic local-part so the helper's @-shape contract is
        # met). Keeps both sides of the domain gate on the same normal
        # form — N-317 IDNA parity.
        raw_needle = (f.from_domain or "").strip().lower().lstrip("@")
        needle = canonical_email(f"_@{raw_needle}").rpartition("@")[2] if raw_needle else ""
        if not needle or needle not in sender_domain:
            return False
    if (f.subject_contains or "").strip():
        if (f.subject_contains or "").strip().lower() not in subj_l:
            return False
    if (f.keyword or "").strip():
        kw = (f.keyword or "").strip().lower()
        if kw not in subj_l and kw not in body_l:
            return False
    return True


# ---------------------------------------------------------------------------
# Redaction (HIPAA payload shaping)
# ---------------------------------------------------------------------------


def _first_name(sender: str) -> str:
    """First word of the display-name portion of a From header.

    "Dr. Jane Smith <a@b.com>" -> "Jane"
    "a@b.com"                  -> "a"
    """
    from email_triage.mail_headers import extract_display_name
    s = (sender or "").strip()
    if "<" in s:
        s = extract_display_name(sender)  # census run13  — shared <…> extraction
    parts = s.split()
    prefixes = {"dr.", "mr.", "mrs.", "ms.", "prof."}
    for p in parts:
        if p.lower() not in prefixes:
            return p
    return parts[0] if parts else ""


def shape_webhook_payload(
    watch: EmailWatch,
    *,
    sender: str,
    subject: str,
    body_text: str = "",
    category: str = "",
    account_id: int | None = None,
    account_name: str = "",
    message_id: str = "",
    hipaa: bool = False,
) -> dict[str, Any]:
    """Build the JSON body that gets HMAC-signed and POSTed.

    HIPAA mode redacts subject + sender to first-name + domain only;
    body is always omitted regardless of mode. Standard mode includes
    sender display + subject; body is still dropped (the receiver can
    fetch full content via a follow-up authenticated API call if it
    needs it).
    """
    if hipaa:
        out_sender = f"{_first_name(sender)} @ {_domain_of(sender)}".strip(" @")
        out_subject = REDACTED_PLACEHOLDER
        redaction = "hipaa_redacted"
    else:
        out_sender = sender or ""
        out_subject = subject or ""
        redaction = "standard"

    return {
        "event": "watch.fired",
        "watch_id": watch.watch_id,
        "watch_name": watch.name,
        "account_id": account_id,
        "account_name": account_name,
        "category": category,
        "sender": out_sender,
        "subject": out_subject,
        "message_id": message_id,
        "redaction": redaction,
        "fired_at": _now_iso(),
    }


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------


def write_audit_row(
    db: sqlite3.Connection,
    *,
    watch: EmailWatch,
    account_id: int | None,
    actor_user_id: int | None,
    message_id: str,
    escalate_fired: bool,
    webhook_fired: bool,
    redaction: str,
    request_id: str | None = None,
    outcome: str = "watch_fired",
) -> int:
    """Write a row to ``access_log`` for every watch fire.

    HIPAA §164.312(b) audit gate — covers PHI-touch (sender/subject)
    even when the payload is webhook-redacted, because the matcher
    saw the unredacted source. ``detail`` is a JSON string with the
    watch + action mix; intentionally NOT containing the sender or
    subject (the audit row indexes the WHO/WHAT/WHEN, not the message
    content). The structured-log path on the same request scope
    carries the verbose match info.
    """
    from email_triage.web.db import record_access_event

    detail = json.dumps({
        "watch_id": watch.watch_id,
        "watch_name": watch.name,
        "escalate": escalate_fired,
        "webhook": webhook_fired,
        "redaction": redaction,
    })
    return record_access_event(
        db,
        actor_user_id=actor_user_id,
        method="POST",
        route=f"/internal/watches/{watch.watch_id}/fire",
        account_id=account_id,
        message_id=message_id or None,
        status_code=200,
        outcome=outcome,
        detail=detail,
        request_id=request_id,
    )


def write_auto_retire_audit_row(
    db: sqlite3.Connection,
    *,
    watch: EmailWatch,
    account_id: int | None,
    action: str,
    fires: int,
    after_n: int,
    rows_affected: int,
) -> int:
    """ — operator-visible ``access_log`` row when a watch AUTO-retires.

    The auto-retire previously emitted only a ``log.info``, so a watch that
    auto-disabled/deleted itself vanished from the UI with no operator-facing
    trail (especially for the irreversible ``delete``). This lands a row in the
    same ``access_log`` the fires write to (rendered on /compliance), via the
    ``record_access_event`` emitter SSOT — never a raw INSERT (that would fork
    the audit HMAC chain). PHI-free detail: watch metadata + counts only.
    """
    from email_triage.web.db import record_access_event

    detail = json.dumps({
        "watch_id": watch.watch_id,
        "watch_name": watch.name,
        "auto_retire_action": action,      # "disable" | "delete"
        "fires": fires,
        "after_n": after_n,
        "rows_affected": rows_affected,
    })
    return record_access_event(
        db,
        actor_user_id=None,                # system-initiated, not a user action
        method="POST",
        route=f"/internal/watches/{watch.watch_id}/auto-retire",
        account_id=account_id,
        message_id=None,
        status_code=200,
        # "watch_auto_disabled" / "watch_auto_deleted" — distinct, greppable.
        outcome=f"watch_auto_{action}d",
        detail=detail,
    )
