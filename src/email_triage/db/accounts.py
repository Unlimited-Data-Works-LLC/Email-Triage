"""Account-cluster DB helpers — extracted from web/db.py.

Drop-in refactor. NO semantic changes. The email-accounts cluster
(email_accounts / account_delegates / account_routes / folder_prefs +
the pure-Python account-identity/alias helpers + alias-mode flags +
route-override settings wrappers) moves here from ``web/db.py`` as the
2nd  god-module extraction (after ``db/audit.py`` #277a, commit
64ea61b). ``web/db.py`` retains an explicit re-export shim at its bottom
so every existing ``from email_triage.web.db import <name>`` import
string keeps working unchanged — verified at extraction time against the
336-name public surface (zero names lost).

Partition axis: TABLE OWNERSHIP, not name (db-sme manifest gate
2026-05-29). Defs that touch ``email_accounts`` only as a JOIN/FK for
ownership/display (push deliveries, style/triage/ai-backend helpers)
stayed in their own clusters; init/migration infra (``init_db``,
``_apply_migrations``, the ``migrate_*`` one-shots, ``scrub_queue_
summary_from_routes``) stayed in ``web/db.py`` because ``init_db`` /
``_bootstrap_schema`` call them (moving = import cycle).

Dependency cut (db-sme Criterion-1 CONFIRMED clean — no shim-unbreakable
cycle):
  * ``_rows`` comes from :mod:`email_triage.db._helpers` (promoted per
    db-sme Ruling 1; was duplicated inline in web/db.py + audit.py).
  * ``get_setting`` / ``set_setting`` / ``delete_setting`` are
    LATE-IMPORTED from ``email_triage.web.db`` inside the two
    route-override wrappers that need them (mirrors the audit.py:580
    ``invalidate_setting_cache`` late-import precedent) — avoids a
    top-level import cycle, since web/db.py re-exports the names defined
    here.

§-anchors (hipaa-sme CLEAR 2026-05-29):
    §164.312(b) Audit Controls — ``set_account_hipaa`` keeps its INLINE
        atomic tx (BEGIN; UPDATE email_accounts; INSERT
        hipaa_boundary_events; COMMIT). The PHI flag-flip + the boundary
        audit row land or roll back together; moving the whole function
        keeps the tx single-module + intact (no cross-module split). The
        ``@db_write`` tag is preserved (load-bearing for  writer-
        routing AND compatible with the explicit BEGIN/COMMIT — the
        decorator holds the lock for the whole call, it does NOT inject a
        commit).
    §164.308(a)(4) Access Management — ``can_manage_account`` + the
        delegate helpers relocate with the re-export shim; the
        admin/owner/delegate authz semantics + the sensitive-op-bypasses-
        delegate invariant are byte-identical.
"""

from __future__ import annotations

import json
import sqlite3
from typing import Any

from email_triage.db._helpers import _rows
from email_triage.web.db_writelock import db_write


def get_mailbox_route_overrides(
    conn: sqlite3.Connection,
    account_id: int,
    mailbox: str,
) -> list[dict]:
    """ — per-(account, mailbox) route overrides.

    Stored under the settings key ``mailbox_routes:<account_id>:<mailbox>``
    as a JSON list of ``{category, actions: [...]}`` rows. Returns an
    empty list when no overrides exist for that mailbox (caller should
    then fall back to the account-wide ``account_routes`` table).
    """
    # Late import: the settings helpers stay in web/db.py; importing
    # them at module top would cycle (web/db.py re-exports the names defined
    # here). Mirrors the audit.py:580 invalidate_setting_cache precedent.
    from email_triage.web.db import get_setting
    raw = get_setting(conn, f"mailbox_routes:{account_id}:{mailbox}")
    if not isinstance(raw, list):
        return []
    return [r for r in raw if isinstance(r, dict)]

def set_mailbox_route_overrides(
    conn: sqlite3.Connection,
    account_id: int,
    mailbox: str,
    routes: list[dict],
) -> None:
    """Persist per-(account, mailbox) route overrides. Pass an empty
    list to clear all overrides for that mailbox."""
    # Late import — see get_mailbox_route_overrides rationale.
    from email_triage.web.db import delete_setting, set_setting
    key = f"mailbox_routes:{account_id}:{mailbox}"
    if not routes:
        # Empty -> drop the row so the account-wide fallback kicks in
        # cleanly without a stub override. delete_setting() invalidates
        # the in-process cache.
        delete_setting(conn, key)
        return
    set_setting(conn, key, routes)

def effective_routes_by_cat(
    conn: sqlite3.Connection,
    account_id: int,
    mailbox: str | None = None,
) -> dict[str, list[dict]]:
    """Return ``{category: actions}`` for the given mailbox.

    Per-mailbox overrides (if any) layer on top of the account-wide
    ``account_routes`` table. Per-category granularity: a mailbox can
    override one category and inherit the rest. Pass ``mailbox=None``
    (or a mailbox with no overrides) to get the legacy account-wide
    map unchanged.
    """
    base = {
        r["category"]: r["actions"]
        for r in list_account_routes(conn, account_id)
    }
    if not mailbox:
        return base
    overrides = get_mailbox_route_overrides(conn, account_id, mailbox)
    for r in overrides:
        cat = r.get("category")
        if not cat:
            continue
        actions = r.get("actions") or []
        if isinstance(actions, list):
            base[cat] = actions
    return base

def _account_mailboxes(cfg: dict) -> list[str]:
    """Return the effective list of mailboxes for an IMAP account config.

    Applies the legacy-compat shim then validates: must be a non-empty
    list of non-empty strings. Falls back to ``["INBOX"]`` for any shape
    that would otherwise leave us with nothing to watch.
    """
    if not isinstance(cfg, dict):
        return ["INBOX"]
    mbs = cfg.get("mailboxes")
    if isinstance(mbs, list):
        valid = [m for m in mbs if isinstance(m, str) and m.strip()]
        if valid:
            return valid
    legacy = cfg.get("mailbox")
    if isinstance(legacy, str) and legacy.strip():
        return [legacy]
    return ["INBOX"]

def _apply_account_config_back_compat(cfg: dict) -> dict:
    """Read-side shim: fill in ``mailboxes`` for legacy single-mailbox configs.

    Older configs stored one folder as ``mailbox`` (str). The current
    canonical shape is ``mailboxes`` (list[str]). We leave the legacy
    ``mailbox`` key alone when present so any lingering readers of the
    old key keep working; we only ADD ``mailboxes`` alongside it.

    Idempotent — safe to call on already-migrated configs.
    """
    if not isinstance(cfg, dict):
        return cfg
    if "mailboxes" not in cfg and "mailbox" in cfg:
        legacy = cfg.get("mailbox")
        if isinstance(legacy, str) and legacy:
            cfg["mailboxes"] = [legacy]
        else:
            cfg["mailboxes"] = ["INBOX"]
    return cfg

INGESTION_POLL_MIN = 10
INGESTION_POLL_MAX = 240
INGESTION_POLL_STEP = 10
INGESTION_POLL_DEFAULT = 60

def clamp_poll_interval_minutes(value: int) -> int:
    """Clamp a poll interval to [POLL_MIN, POLL_MAX] and snap to step 10.

    Shared by the save handler, the back-compat shim, and any test that
    needs to normalise an interval — keeps the "what's a valid cadence"
    answer in one place.
    """
    try:
        v = int(value)
    except (TypeError, ValueError):
        return INGESTION_POLL_DEFAULT
    v = max(INGESTION_POLL_MIN, min(INGESTION_POLL_MAX, v))
    # Snap to nearest step.
    v = INGESTION_POLL_MIN + round(
        (v - INGESTION_POLL_MIN) / INGESTION_POLL_STEP
    ) * INGESTION_POLL_STEP
    return max(INGESTION_POLL_MIN, min(INGESTION_POLL_MAX, v))

def apply_ingestion_back_compat(
    conn: sqlite3.Connection,
    account_id: int,
    provider_type: str,
    cfg: dict,
    default_minutes: int = INGESTION_POLL_DEFAULT,
) -> dict:
    """Materialise ``push_enabled`` / ``poll_enabled`` / ``poll_interval_minutes``
    onto ``cfg`` if any are missing.

    Back-compat rules:
      * ``push_enabled``: mirror legacy ``watch:{id}`` setting for IMAP
        accounts (True when setting is enabled, False when missing or
        disabled). For Gmail, True when an active gmail_watches row
        exists (non-empty topic + unexpired). For other providers,
        default to True (push_enabled is "start the provider's push
        mechanism" — the WatcherManager decides whether to act).
      * ``poll_enabled``: ALWAYS True for legacy accounts — dormant
        accounts start getting 60-min polls. Operators can opt out via
        the edit form.
      * ``poll_interval_minutes``: carry forward the B3-era
        ``poll_interval_override`` if set; otherwise use
        ``default_minutes``. Always clamped + step-snapped.

    Mutates and returns ``cfg``. Safe to call on already-migrated configs
    (keys already present are left alone).

    .2 — fast-path: when ``push_enabled``, ``poll_enabled``, AND
    ``poll_interval_minutes`` are already present in ``cfg``, skip the
    legacy ``settings``/``gmail_watches`` lookups entirely. Migrated rows
    (the common case for new accounts created post-B3) take this path and
    avoid 1-2 DB round-trips per account on every ``list_email_accounts``
    fold.
    """
    if not isinstance(cfg, dict):
        return cfg

    # Fast path: already migrated, nothing to back-fill. Per-account
    # ``list_email_accounts`` calls inside loops (digest scheduler,
    # poll loop) used to issue a settings + gmail_watches SELECT for
    # every row even when the cfg was already complete; this short-circuit
    # eliminates that noise.
    if (
        "push_enabled" in cfg
        and "poll_enabled" in cfg
        and "poll_interval_minutes" in cfg
    ):
        # Defensive: still clamp the interval in case of out-of-band edit.
        cfg["poll_interval_minutes"] = clamp_poll_interval_minutes(
            cfg["poll_interval_minutes"],
        )
        return cfg

    import json as _json

    # poll_interval_minutes
    if "poll_interval_minutes" not in cfg:
        raw = cfg.get("poll_interval_override")
        if isinstance(raw, int):
            cfg["poll_interval_minutes"] = clamp_poll_interval_minutes(raw)
        else:
            cfg["poll_interval_minutes"] = clamp_poll_interval_minutes(
                default_minutes,
            )
    else:
        # Normalise in case someone hand-edited config_json out of band.
        cfg["poll_interval_minutes"] = clamp_poll_interval_minutes(
            cfg.get("poll_interval_minutes", default_minutes),
        )

    # poll_enabled — default True for every provider (legacy or fresh).
    if "poll_enabled" not in cfg:
        cfg["poll_enabled"] = True

    # push_enabled — provider-specific inference.
    #  phase 2 — table-driven dispatch via ProviderDispatcher.
    # Each ptype's ``infer_push_enabled`` reads its own state row
    # (settings ``watch:<id>`` for IMAP, ``gmail_watches`` for Gmail,
    # default-only for O365 until Graph wiring lands).
    if "push_enabled" not in cfg:
        from email_triage.providers.dispatcher import get_dispatch
        disp = get_dispatch(provider_type)
        if disp is None:
            cfg["push_enabled"] = True
        else:
            cfg["push_enabled"] = disp.infer_push_enabled(
                conn, account_id, default=True,
            )

    return cfg

def account_email(acct: dict | None) -> str:
    """Resolve the operator-facing email address for an account.

    Different provider types store the address under different keys:

    - **Gmail (native)** stores it as ``config["account"]``
      (the Google account selected via OAuth).
    - **Office 365 (Graph)** stores it as ``config["account"]``
      (the AAD identity from MSAL).
    - **IMAP** prefers ``config["email_address"]`` (operator-set
      on the account edit page, shipped 2026-05-13 after operator
      hit the alias-mode bug where IMAP LOGIN usernames like
      ``you`` collide with actual addresses like
      ``you@example.com`` — Dovecot allows bare usernames +
      a server-side default domain, so the LOGIN value isn't the
      email). Falls back to ``config["username"]`` for older
      accounts where the operator hasn't filled in the new field
      yet — many IMAP installs do use the full address as the
      LOGIN, so the legacy fallback stays correct for them.

    Returns the first non-empty hit in priority order, or "" when
    neither is set (account not yet saved). Single source of truth
    for every read site; the alternative (each caller open-coding
    the fallback) shipped silent gaps — see the "Send digest now
    (test)" bug 2026-05-05 where the digest-test handler only read
    ``config["account"]`` and rejected every IMAP account as
    "no email address".
    """
    if not acct:
        return ""
    cfg = acct.get("config") or {}
    addr = (cfg.get("account") or "").strip()
    if addr:
        return addr
    email_addr = (cfg.get("email_address") or "").strip()
    if email_addr:
        return email_addr
    return (cfg.get("username") or "").strip()

def account_aliases(acct: dict | None) -> list[dict]:
    """Return the list of additional addresses configured for an account.

    Each entry is ``{"address": "...", "label": "..."}``. Stored as
    ``email_accounts.aliases_json`` (JSON list, default ``[]``) and
    surfaced on the read path by ``list_email_accounts`` /
    ``get_email_account``. The primary address (``account_email``)
    is NOT in this list — it's tracked separately in the provider
    config. Use ``account_addresses`` when you want the union.

    Returns an empty list on a missing or malformed value rather
    than raising; the storage column is parsed once on read so
    callers can treat the result as authoritative.
    """
    if not acct:
        return []
    raw = acct.get("aliases") or []
    if isinstance(raw, list):
        out: list[dict] = []
        for entry in raw:
            if not isinstance(entry, dict):
                continue
            addr = str(entry.get("address") or "").strip().lower()
            if not addr:
                continue
            label = str(entry.get("label") or "").strip()
            out.append({"address": addr, "label": label})
        return out
    return []

def account_addresses(acct: dict | None) -> set[str]:
    """Return the full set of addresses that route to this account.

    Union of the resolved primary address (``account_email``) and any
    additional addresses configured under ``aliases_json`` ('s
    schema-backed storage) PLUS legacy ``config["aliases"]`` strings
    ('s pre-merge format — tolerated for back-compat with any
    operator who set them via the older path). All values normalized
    to lowercase + stripped so callers can compare with a normalized
    incoming ``to_addr`` directly.

    The primary is implicit-included; alias UI / save paths reject
    storing the primary as an alias to keep the union de-duplicated
    by construction. An account with no primary yet (fresh row, never
    saved) yields just the alias addresses (or the empty set if none).

    Used by:
      - HIPAA recipient-mismatch guard
      - Recipient-digest collector (alias mail flows under parent acct)
      - Triage-runner self-match
    """
    if not acct:
        return set()
    out: set[str] = set()
    primary = account_email(acct).strip().lower()
    if primary:
        out.add(primary)
    #  canonical path — JSON-array column.
    for entry in account_aliases(acct):
        addr = entry.get("address", "")
        if addr:
            out.add(addr)
    # Legacy / pre-merge fallback: config["aliases"] as list[str] or
    # comma-separated string. Kept so any account configured via the
    #  ad-hoc path during the parallel-build window still routes
    # correctly. Future cleanup can drop this once the operator
    # confirms zero rows use the legacy shape.
    cfg = acct.get("config") or {}
    raw = cfg.get("aliases")
    if isinstance(raw, list):
        candidates = [str(x or "") for x in raw]
    elif isinstance(raw, str):
        candidates = []
        for chunk in raw.replace("\n", ",").replace(";", ",").split(","):
            candidates.append(chunk)
    else:
        candidates = []
    for c in candidates:
        addr = c.strip().lower()
        if addr and "@" in addr:
            out.add(addr)
    return out

def list_email_accounts(
    conn: sqlite3.Connection,
    user_id: int | None = None,
    include_delegated: bool = True,
) -> list[dict]:
    """List email accounts. If user_id is None, returns all (admin view).

    With ``user_id`` set:
    * Returns accounts where this user is the owner.
    * Plus accounts where this user is a delegate — unless
      ``include_delegated=False`` (legacy callers that genuinely
      want owner-only).

    Each row includes ``is_delegate`` (False for owner-of, True
    when surfaced via the delegates JOIN) so the UI can chip
    appropriately.
    """
    import json
    if user_id is not None:
        # Owner rows.
        owner_rows = conn.execute(
            "SELECT ea.*, u.email AS owner_email, u.name AS owner_name, "
            "       0 AS is_delegate "
            "FROM email_accounts ea JOIN users u ON ea.user_id = u.id "
            "WHERE ea.user_id = ? ORDER BY ea.id",
            (user_id,),
        ).fetchall()
        rows = list(owner_rows)
        if include_delegated:
            delegate_rows = conn.execute(
                "SELECT ea.*, u.email AS owner_email, u.name AS owner_name, "
                "       1 AS is_delegate "
                "FROM email_accounts ea "
                "JOIN users u ON ea.user_id = u.id "
                "JOIN account_delegates ad ON ad.account_id = ea.id "
                "WHERE ad.user_id = ? AND ea.user_id != ? "
                "ORDER BY ea.id",
                (user_id, user_id),
            ).fetchall()
            rows.extend(delegate_rows)
    else:
        rows = conn.execute(
            "SELECT ea.*, u.email AS owner_email, u.name AS owner_name, "
            "       0 AS is_delegate "
            "FROM email_accounts ea JOIN users u ON ea.user_id = u.id "
            "ORDER BY u.email, ea.id",
        ).fetchall()
    result = []
    for r in rows:
        d = dict(r)
        cfg = _apply_account_config_back_compat(
            json.loads(d.pop("config_json", "{}")),
        )
        cfg = apply_ingestion_back_compat(conn, d["id"], d["provider_type"], cfg)
        d["config"] = cfg
        # Parse the alias list once on read. Stored as a JSON array of
        # ``{"address","label"}`` dicts; malformed values fall back to
        # an empty list so a corrupt row doesn't blow up the whole
        # /accounts page render. Pre-aliases-column rows (legacy DBs
        # before v10) surface as missing keys in the dict_factory
        # output — also coerce to empty list.
        raw_aliases = d.pop("aliases_json", "[]") or "[]"
        try:
            parsed_aliases = json.loads(raw_aliases)
        except (TypeError, ValueError):
            parsed_aliases = []
        if not isinstance(parsed_aliases, list):
            parsed_aliases = []
        d["aliases"] = parsed_aliases
        # Synthesize the resolved email address up-front so callers
        # don't have to know the per-provider field-name dance. See
        # ``account_email`` for the resolution rules.
        d["email_address"] = account_email(d)
        result.append(d)
    return result

@db_write
def add_account_delegate(
    conn: sqlite3.Connection,
    account_id: int,
    user_id: int,
    granted_by: int | None,
) -> bool:
    """Grant a user delegate access to an account. Idempotent: returns
    True on first add, False if the row already exists. Raises ValueError
    if user_id == account_owner (owner is not a delegate of their own
    account)."""
    from datetime import datetime, timezone
    owner = conn.execute(
        "SELECT user_id FROM email_accounts WHERE id = ?",
        (account_id,),
    ).fetchone()
    if owner is None:
        raise ValueError(f"Account {account_id} not found")
    if owner["user_id"] == user_id:
        raise ValueError(
            "Owner cannot be added as a delegate of their own account"
        )
    now = datetime.now(timezone.utc).isoformat()
    cur = conn.execute(
        "INSERT OR IGNORE INTO account_delegates "
        "(account_id, user_id, granted_by, granted_at) VALUES (?, ?, ?, ?)",
        (account_id, user_id, granted_by, now),
    )
    conn.commit()
    return cur.rowcount > 0

@db_write
def remove_account_delegate(
    conn: sqlite3.Connection,
    account_id: int,
    user_id: int,
) -> bool:
    """Revoke delegate access. Returns True if a row was removed."""
    cur = conn.execute(
        "DELETE FROM account_delegates "
        "WHERE account_id = ? AND user_id = ?",
        (account_id, user_id),
    )
    conn.commit()
    return cur.rowcount > 0

def list_account_delegates(
    conn: sqlite3.Connection,
    account_id: int,
) -> list[dict]:
    """Return delegates for ``account_id`` as ``[{user_id, email, name,
    granted_by, granted_by_email, granted_at}, ...]`` ordered by grant
    time."""
    rows = conn.execute(
        "SELECT ad.user_id, u.email, u.name, "
        "       ad.granted_by, "
        "       gu.email AS granted_by_email, "
        "       ad.granted_at "
        "FROM account_delegates ad "
        "JOIN users u ON u.id = ad.user_id "
        "LEFT JOIN users gu ON gu.id = ad.granted_by "
        "WHERE ad.account_id = ? "
        "ORDER BY ad.granted_at",
        (account_id,),
    ).fetchall()
    return _rows(rows)

def is_account_delegate(
    conn: sqlite3.Connection,
    account_id: int,
    user_id: int,
) -> bool:
    """True if ``user_id`` has delegate access to ``account_id``."""
    row = conn.execute(
        "SELECT 1 FROM account_delegates "
        "WHERE account_id = ? AND user_id = ?",
        (account_id, user_id),
    ).fetchone()
    return row is not None

def can_manage_account(
    conn: sqlite3.Connection,
    user: dict | None,
    acct: dict | None,
) -> bool:
    """Authz gate for per-account operations. True when:

    * ``user`` has admin role, OR
    * ``user`` is the account owner, OR
    * ``user`` has a delegate row for this account.

    Sensitive operations (HIPAA flag flip, account deletion) bypass
    this and check admin/owner directly — delegates intentionally
    cannot escalate or destroy the account.
    """
    if not user or not acct:
        return False
    if user.get("role") == "admin":
        return True
    if acct.get("user_id") == user.get("id"):
        return True
    return is_account_delegate(conn, acct["id"], user["id"])

def get_email_account(conn: sqlite3.Connection, account_id: int) -> dict | None:
    """Get a single email account by ID."""
    import json
    row = conn.execute(
        "SELECT ea.*, u.email AS owner_email, u.name AS owner_name "
        "FROM email_accounts ea JOIN users u ON ea.user_id = u.id "
        "WHERE ea.id = ?",
        (account_id,),
    ).fetchone()
    if row is None:
        return None
    d = dict(row)
    cfg = _apply_account_config_back_compat(
        json.loads(d.pop("config_json", "{}")),
    )
    cfg = apply_ingestion_back_compat(conn, d["id"], d["provider_type"], cfg)
    d["config"] = cfg
    raw_aliases = d.pop("aliases_json", "[]") or "[]"
    try:
        parsed_aliases = json.loads(raw_aliases)
    except (TypeError, ValueError):
        parsed_aliases = []
    if not isinstance(parsed_aliases, list):
        parsed_aliases = []
    d["aliases"] = parsed_aliases
    d["email_address"] = account_email(d)
    return d

@db_write
def create_email_account(
    conn: sqlite3.Connection,
    user_id: int,
    name: str,
    provider_type: str,
    config: dict,
    hipaa: bool | None = None,
    is_active: bool = True,
) -> int:
    """Create an email account. Returns the new ID.

    If ``hipaa`` is None (the default), the per-account flag is inferred
    from the current system HIPAA state — if system HIPAA is ON the
    account is auto-flagged and ``created_under_system_hipaa`` is set
    so the flag cannot be unset until system HIPAA is later turned off
    ("sticky inheritance").  An explicit ``hipaa`` value from the
    caller overrides the inference.

    ``is_active`` defaults to True for full-form callers (manual-add
    POST /accounts where every credential lands in one submit). The
    new-account wizard's step-1 handler passes ``is_active=False`` so
    the half-configured stub (empty ``config``) does not get polled
    by background watchers / pollers / triage workers until the wizard
    finishes (item ). Step-5 submit flips to True via
    ``set_account_active``. Background pollers already gate on
    ``is_active`` (six call sites in app.py + ui.py), so flipping the
    flag suppresses the "missing credentials" error spam that triggered
    the monitoring system alerts on the homelab monitoring path.
    """
    import json
    from datetime import datetime, timezone
    from email_triage.triage_logging import is_hipaa_mode
    now = datetime.now(timezone.utc).isoformat()
    system_hipaa = is_hipaa_mode()
    if hipaa is None:
        hipaa = system_hipaa
    created_under = 1 if system_hipaa else 0
    cursor = conn.execute(
        "INSERT INTO email_accounts "
        "(user_id, name, provider_type, config_json, hipaa, "
        " created_under_system_hipaa, is_active, "
        " created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (user_id, name, provider_type, json.dumps(config),
         int(bool(hipaa)), created_under, int(bool(is_active)),
         now, now),
    )
    conn.commit()
    return cursor.lastrowid

@db_write
def set_account_active(
    conn: sqlite3.Connection,
    account_id: int,
    active: bool,
) -> bool:
    """Flip ``is_active`` without touching name / provider_type / config.

    Used by the wizard's step-5 finish handler to enable an account
    that was created in the disabled state at step 1 (item ).
    Also useful for an admin "pause this account" surface that we
    might add later.

    Returns True when a row was updated.
    """
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    cursor = conn.execute(
        "UPDATE email_accounts SET is_active = ?, updated_at = ? "
        "WHERE id = ?",
        (int(bool(active)), now, account_id),
    )
    conn.commit()
    return cursor.rowcount > 0

@db_write
def set_account_hipaa(
    conn: sqlite3.Connection,
    account_id: int,
    hipaa: bool,
    actor_id: int | None = None,
    reason: str = "",
) -> dict:
    """Flip an account's HIPAA flag and record the boundary event.

    Enforces the lock rule: if the account was created while system
    HIPAA was on AND system HIPAA is still on, the flag cannot be
    turned off.  Raises ``PermissionError`` in that case.  The flip
    and the boundary-event write happen in a single transaction.

    Returns the refreshed account dict.
    """
    from email_triage.triage_logging import is_hipaa_mode, is_account_hipaa_locked
    acct = get_email_account(conn, account_id)
    if acct is None:
        raise ValueError(f"Account {account_id} not found")

    # No-op: flag already in the requested state.
    current = bool(acct.get("hipaa", False))
    if current == bool(hipaa):
        return acct

    # Lock enforcement.
    if not hipaa and is_account_hipaa_locked(acct):
        raise PermissionError(
            "Cannot unset HIPAA flag while system HIPAA mode is active "
            "for an account that was created under system HIPAA."
        )

    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    direction = "on" if hipaa else "off"
    scope = f"account:{account_id}"
    try:
        conn.execute("BEGIN")
        conn.execute(
            "UPDATE email_accounts SET hipaa = ?, updated_at = ? WHERE id = ?",
            (int(bool(hipaa)), now, account_id),
        )
        conn.execute(
            "INSERT INTO hipaa_boundary_events "
            "(ts, scope, direction, actor_id, reason) VALUES (?, ?, ?, ?, ?)",
            (now, scope, direction, actor_id, reason),
        )
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise
    return get_email_account(conn, account_id)

@db_write
def update_email_account(
    conn: sqlite3.Connection,
    account_id: int,
    name: str,
    provider_type: str,
    config: dict,
    is_active: bool = True,
) -> bool:
    """Update an email account. Returns True if updated."""
    import json
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    cursor = conn.execute(
        "UPDATE email_accounts SET name = ?, provider_type = ?, config_json = ?, "
        "is_active = ?, updated_at = ? WHERE id = ?",
        (name, provider_type, json.dumps(config), int(is_active), now, account_id),
    )
    conn.commit()
    return cursor.rowcount > 0

@db_write
def update_email_account_config(
    conn: sqlite3.Connection, account_id: int, config: dict,
) -> bool:
    """Patch the config_json for an account without touching the other
    columns. Used by the history-poll loop to clear a
    ``poll_interval_override`` on push↔poll transitions."""
    import json
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    cursor = conn.execute(
        "UPDATE email_accounts SET config_json = ?, updated_at = ? WHERE id = ?",
        (json.dumps(config), now, account_id),
    )
    conn.commit()
    return cursor.rowcount > 0

@db_write
def update_account_config_keys(
    conn: sqlite3.Connection,
    account_id: int,
    /,
    **patches: Any,
) -> bool:
    """Read-modify-write a subset of an account's ``config_json`` keys
    atomically.

    Replaces the 7-site idiom::

        config = dict(acct.get("config") or {})
        config[k] = v
        update_email_account_config(db, aid, config)

    The read-modify-write happens inside a single ``BEGIN IMMEDIATE``
    transaction so a concurrent writer cannot clobber an unrelated
    key between the read and the write — the pre-fix idiom hit this
    on the calendar-surrogate save vs the digest-schedule save when
    both arrive in the same second. Other config keys not named in
    ``patches`` are preserved verbatim.

    Patches with value ``None`` mean "delete the key" (the operator
    is clearing a setting). Patches with any other value overwrite.

    Emits a single structured INFO log per call listing the keys
    that changed (audit signal — operators reviewing config drift
    can see which knob moved without enabling row-level audit). The
    log line does NOT include values, since some config knobs (e.g.
    ``imap.host``) may pin to operator-identifying infrastructure;
    the keys-only shape is the conservative-safe surface.

    Returns
    -------
    bool
        True when the row was found and updated; False when
        ``account_id`` does not exist.
    """
    import json
    from datetime import datetime, timezone

    # BEGIN IMMEDIATE acquires the write lock up front so a concurrent
    # reader-then-writer can't slot in between our SELECT and UPDATE.
    # SQLite's default deferred mode would hit "database is locked"
    # under contention but only after the SELECT — too late. We fold
    # the read + write into one transaction explicitly.
    conn.execute("BEGIN IMMEDIATE")
    try:
        row = conn.execute(
            "SELECT config_json FROM email_accounts WHERE id = ?",
            (account_id,),
        ).fetchone()
        if row is None:
            conn.execute("ROLLBACK")
            return False
        try:
            current = json.loads(row[0] or "{}")
        except (TypeError, ValueError):
            current = {}
        if not isinstance(current, dict):
            current = {}

        merged = dict(current)
        changed_keys: list[str] = []
        for key, value in patches.items():
            if value is None:
                if key in merged:
                    merged.pop(key, None)
                    changed_keys.append(key)
            else:
                if merged.get(key) != value:
                    merged[key] = value
                    changed_keys.append(key)

        if not changed_keys:
            conn.execute("ROLLBACK")
            return True  # No-op write — row exists, nothing to change.

        now = datetime.now(timezone.utc).isoformat()
        conn.execute(
            "UPDATE email_accounts "
            "SET config_json = ?, updated_at = ? WHERE id = ?",
            (json.dumps(merged), now, account_id),
        )
        conn.execute("COMMIT")
    except Exception:
        try:
            conn.execute("ROLLBACK")
        except Exception:
            pass
        raise

    # Structured-log emission AFTER the commit so a log failure
    # cannot orphan a successful write. owner + account_name surface
    # per ``feedback_no_account_id_alone.md`` — the numeric account_id
    # is a tiebreaker only; logs use the human-readable owner +
    # account_name as the primary key.
    try:
        meta = conn.execute(
            "SELECT ea.name AS account_name, "
            "       u.email AS owner, u.name AS owner_name "
            "FROM email_accounts ea JOIN users u ON ea.user_id = u.id "
            "WHERE ea.id = ?",
            (account_id,),
        ).fetchone()
        import logging
        logger = logging.getLogger("email_triage.web.db")
        log_extra: dict[str, Any] = {"account_id": account_id}
        if meta is not None:
            d = dict(meta)
            if d.get("owner_name"):
                log_extra["owner"] = d["owner_name"]
            elif d.get("owner"):
                log_extra["owner"] = d["owner"]
            if d.get("account_name"):
                log_extra["account_name"] = d["account_name"]
        log_extra["changed_keys"] = sorted(changed_keys)
        logger.info(
            "Account config keys updated",
            extra={"_extra": log_extra},
        )
    except Exception:
        # Log emission must never sink the call — the write already
        # landed. Best-effort only.
        pass
    return True

class AliasValidationError(ValueError):
    """Raised when a proposed alias list violates the storage contract.

    Constructor takes a single human-readable reason that's safe to
    surface to the operator (the UI just renders this string verbatim
    above the alias form).
    """

def _looks_like_email(addr: str) -> bool:
    """Lightweight RFC-shaped check used by the alias validator.

    Intentionally conservative: requires an ``@`` plus at least one
    dot in the host part. Doesn't try to validate the local part —
    real RFC 5322 grammar is too permissive to be useful as a UI
    gate, and we already let the SMTP / IMAP layer reject impossible
    addresses at the actual-use point.
    """
    s = (addr or "").strip()
    if "@" not in s:
        return False
    host = s.split("@")[-1]
    return "." in host and len(host) > 2

def normalize_aliases(
    raw: list[dict],
    *,
    primary: str = "",
) -> list[dict]:
    """Validate + normalize an alias list before write.

    Rules:
    * Each entry must be a dict with at least an ``address`` key.
    * Address must be RFC-shaped (``_looks_like_email``).
    * Address is lowercased + stripped.
    * Label is stripped (empty allowed).
    * The primary address (when supplied) cannot also be an alias.
    * Duplicate addresses across entries are rejected.

    Raises :class:`AliasValidationError` on first violation with a
    plain-language reason. Returns the cleaned list on success.
    """
    norm_primary = (primary or "").strip().lower()
    seen: set[str] = set()
    out: list[dict] = []
    for entry in raw or []:
        if not isinstance(entry, dict):
            raise AliasValidationError(
                "Each additional address must be a name/value entry."
            )
        addr = str(entry.get("address") or "").strip().lower()
        label = str(entry.get("label") or "").strip()
        if not addr:
            raise AliasValidationError(
                "Address can't be blank — type the email address you want to add."
            )
        if not _looks_like_email(addr):
            raise AliasValidationError(
                f"'{addr}' doesn't look like a valid email address. "
                f"It needs an @ and a dot in the part after the @."
            )
        if norm_primary and addr == norm_primary:
            raise AliasValidationError(
                "That's already this account's main address — "
                "no need to add it again."
            )
        if addr in seen:
            raise AliasValidationError(
                f"'{addr}' is listed twice. Each address can only appear once."
            )
        seen.add(addr)
        out.append({"address": addr, "label": label})
    return out

@db_write
def update_email_account_aliases(
    conn: sqlite3.Connection,
    account_id: int,
    aliases: list[dict],
) -> bool:
    """Replace the stored alias list for an account.

    ``aliases`` should already be validated via :func:`normalize_aliases`
    — this writer is dumb (json.dumps + UPDATE). Returns True if a row
    was updated.
    """
    import json
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    cursor = conn.execute(
        "UPDATE email_accounts SET aliases_json = ?, updated_at = ? "
        "WHERE id = ?",
        (json.dumps(aliases), now, account_id),
    )
    conn.commit()
    return cursor.rowcount > 0

@db_write
def delete_email_account(conn: sqlite3.Connection, account_id: int) -> bool:
    """Delete an email account. Returns True if deleted."""
    cursor = conn.execute("DELETE FROM email_accounts WHERE id = ?", (account_id,))
    conn.commit()
    return cursor.rowcount > 0

def list_account_routes(conn: sqlite3.Connection, account_id: int) -> list[dict]:
    """Return all route mappings for an account."""
    import json
    rows = conn.execute(
        "SELECT id, account_id, category, actions_json, created_at, updated_at "
        "FROM account_routes WHERE account_id = ? ORDER BY category",
        (account_id,),
    ).fetchall()
    result = []
    for r in rows:
        d = dict(r)
        d["actions"] = json.loads(d.pop("actions_json", "[]"))
        result.append(d)
    return result

def get_account_route(conn: sqlite3.Connection, account_id: int, category: str) -> dict | None:
    """Get a single route mapping for an account + category."""
    import json
    row = conn.execute(
        "SELECT id, account_id, category, actions_json FROM account_routes "
        "WHERE account_id = ? AND category = ?",
        (account_id, category),
    ).fetchone()
    if row is None:
        return None
    d = dict(row)
    d["actions"] = json.loads(d.pop("actions_json", "[]"))
    return d

@db_write
def upsert_account_route(
    conn: sqlite3.Connection,
    account_id: int,
    category: str,
    actions: list[dict],
) -> int:
    """Create or update a route mapping. Returns the row ID."""
    import json
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    actions_json = json.dumps(actions)

    existing = conn.execute(
        "SELECT id FROM account_routes WHERE account_id = ? AND category = ?",
        (account_id, category),
    ).fetchone()

    if existing:
        conn.execute(
            "UPDATE account_routes SET actions_json = ?, updated_at = ? WHERE id = ?",
            (actions_json, now, existing["id"]),
        )
        conn.commit()
        return existing["id"]
    else:
        cursor = conn.execute(
            "INSERT INTO account_routes (account_id, category, actions_json, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (account_id, category, actions_json, now, now),
        )
        conn.commit()
        return cursor.lastrowid

@db_write
def delete_account_route(conn: sqlite3.Connection, route_id: int) -> bool:
    """Delete a route mapping. Returns True if deleted."""
    cursor = conn.execute("DELETE FROM account_routes WHERE id = ?", (route_id,))
    conn.commit()
    return cursor.rowcount > 0

def get_folder_prefs(conn: sqlite3.Connection, account_id: int) -> dict[str, bool]:
    """Return folder preferences as {folder_path: included}.

    Folders not in the table are considered included (default behaviour).
    Only explicitly excluded folders are stored with included=0.
    """
    rows = conn.execute(
        "SELECT folder_path, included FROM account_folder_prefs WHERE account_id = ?",
        (account_id,),
    ).fetchall()
    return {row["folder_path"]: bool(row["included"]) for row in rows}

@db_write
def save_folder_prefs(
    conn: sqlite3.Connection,
    account_id: int,
    prefs: dict[str, bool],
) -> None:
    """Save folder include/exclude preferences.

    *prefs* is ``{folder_path: included}``.  Existing prefs for the
    account are replaced entirely (delete + re-insert).
    """
    conn.execute(
        "DELETE FROM account_folder_prefs WHERE account_id = ?",
        (account_id,),
    )
    for folder_path, included in prefs.items():
        conn.execute(
            "INSERT INTO account_folder_prefs (account_id, folder_path, included) "
            "VALUES (?, ?, ?)",
            (account_id, folder_path, int(included)),
        )
    conn.commit()

def get_visible_folders(
    conn: sqlite3.Connection,
    account_id: int,
    all_folders: list[str],
    separator: str = ".",
) -> list[str]:
    """Filter a list of server folders by the account's preferences.

    A folder is excluded if:
    - It is explicitly excluded (included=0), OR
    - Any of its ancestor folders are explicitly excluded.

    Folders with no preference entry are included by default.
    """
    prefs = get_folder_prefs(conn, account_id)
    # Build set of excluded paths.
    excluded = {path for path, inc in prefs.items() if not inc}

    visible = []
    for folder in all_folders:
        # Check if this folder or any ancestor is excluded.
        is_excluded = False
        for ex_path in excluded:
            if folder == ex_path or folder.startswith(ex_path + separator):
                is_excluded = True
                break
        if not is_excluded:
            visible.append(folder)
    return visible

def normalise_from_address(value: str | None) -> str:
    """Reduce a free-form ``From:`` header value to a comparable bare address.

    Drops the display-name prefix, surrounding angle brackets, the
    ``+suffix`` tag (Gmail-style "subaddress"), and casing. Empty /
    invalid inputs collapse to ``""`` so callers can treat the result
    as ``str`` unconditionally.

    Examples
    --------
    >>> normalise_from_address('"Display Name" <Sam+work@Example.Tld>')
    'sam@example.tld'
    >>> normalise_from_address('alice@example.com')
    'alice@example.com'
    >>> normalise_from_address(None)
    ''
    """
    if not value:
        return ""
    s = str(value).strip()
    if not s:
        return ""
    # If a ``<addr>`` block is present, prefer its content over the
    # display-name part. We deliberately don't try to be RFC 5322
    # complete — the inputs are ``From:`` header values pulled from
    # an ``EmailMessage`` that the providers have already normalised
    # one level (display name + bare address coexisting is the
    # mainstream shape).
    if "<" in s and ">" in s:
        lt = s.rfind("<")
        gt = s.find(">", lt)
        if lt != -1 and gt != -1 and gt > lt:
            s = s[lt + 1: gt].strip()
    # Drop any surrounding quotes / whitespace.
    s = s.strip().strip('"').strip("'").strip()
    if not s:
        return ""
    # Lowercase + split off the ``+suffix`` tag if present. The tag
    # is part of the same delivery destination on Gmail-style "plus
    # addressing" -- two captures of ``alice+work@x`` and ``alice@x``
    # belong in the same bucket.
    s = s.lower()
    if "@" not in s:
        return s
    local, _, domain = s.partition("@")
    if "+" in local:
        local = local.split("+", 1)[0]
    if not local or not domain:
        return ""
    return f"{local}@{domain}"

def is_alias_mode_enabled_for_account(
    conn: sqlite3.Connection, account_id: int,
) -> bool:
    """Return True when alias-aware learning is on for ``account_id``.

    Default False so existing accounts retain single-descriptor
    behaviour until the operator explicitly opts in on
    ``/profile/style-data``. Pre-v23 DBs (no column) read as False.
    """
    try:
        row = conn.execute(
            "SELECT style_alias_mode_enabled FROM email_accounts "
            "WHERE id = ?",
            (int(account_id),),
        ).fetchone()
    except sqlite3.OperationalError:
        return False
    if row is None:
        return False
    val = row["style_alias_mode_enabled"] if hasattr(row, "keys") else row[0]
    return bool(val)

@db_write
def set_alias_mode_enabled_for_account(
    conn: sqlite3.Connection, account_id: int, *, enabled: bool,
) -> None:
    """Flip the alias-aware-learning toggle for ``account_id``."""
    conn.execute(
        "UPDATE email_accounts SET style_alias_mode_enabled = ? "
        "WHERE id = ?",
        (1 if enabled else 0, int(account_id)),
    )
    conn.commit()

