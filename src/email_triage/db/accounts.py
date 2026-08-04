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

from email_triage._int_utils import bounded_int  # N-219c/21 R23
from email_triage._isotime import now_utc_iso

import json
import sqlite3
from typing import Any

from email_triage.db._helpers import _rows, dump_json_col, load_json_col
from email_triage.mail_headers import canonical_email  # N-346 R31 SSOT
from email_triage.web.db_writelock import db_write
from email_triage.web.dependencies import is_admin  # N-222b R22 bool SSOT


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
    v = bounded_int(value, default=INGESTION_POLL_DEFAULT)  # N-219c/21 R23: SSOT
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
            addr = canonical_email(str(entry.get("address") or ""))
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
    primary = canonical_email(account_email(acct))
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
        addr = canonical_email(c)
        if addr and "@" in addr:
            out.add(addr)
    return out

def list_email_accounts(
    conn: sqlite3.Connection,
    user_id: int | None = None,
    include_delegated: bool = True,
    active_only: bool = False,
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

    ``active_only`` (N-109): operational PICKERS — surfaces where a human or an
    API client SELECTS a mailbox to act on (route targets, watch lists, digest
    recipients, bulk-triage/discover, the webhook-API roster) — pass ``True`` to
    drop deactivated (``is_active=0``) accounts. A Removed account's credentials
    are purged, so offering it for selection is a footgun. **Default ``False``
    PRESERVES every management / audit / re-enable / background-purge caller**,
    which MUST still see deactivated rows (a disabled account stays visible on
    the /accounts page so it can be re-enabled, exactly like a disabled user).
    ``COALESCE(is_active, 1)`` so legacy NULL rows count as active — matches the
    consumer-side ``acct.get("is_active", True)`` gate at watcher.py / admin.py.
    """
    import json
    _active = " AND COALESCE(ea.is_active, 1) = 1" if active_only else ""
    if user_id is not None:
        # Owner rows.
        owner_rows = conn.execute(
            "SELECT ea.*, u.email AS owner_email, u.name AS owner_name, "
            "       0 AS is_delegate "
            "FROM email_accounts ea JOIN users u ON ea.user_id = u.id "
            f"WHERE ea.user_id = ?{_active} ORDER BY ea.id",
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
                f"WHERE ad.user_id = ? AND ea.user_id != ?{_active} "
                "ORDER BY ea.id",
                (user_id, user_id),
            ).fetchall()
            rows.extend(delegate_rows)
    else:
        _active_where = " WHERE COALESCE(ea.is_active, 1) = 1" if active_only else ""
        rows = conn.execute(
            "SELECT ea.*, u.email AS owner_email, u.name AS owner_name, "
            "       0 AS is_delegate "
            "FROM email_accounts ea JOIN users u ON ea.user_id = u.id "
            f"{_active_where} ORDER BY u.email, ea.id",
        ).fetchall()
    result = []
    for r in rows:
        d = dict(r)
        cfg = _apply_account_config_back_compat(
            load_json_col(d.pop("config_json", "{}"), default={}),
        )
        cfg = apply_ingestion_back_compat(conn, d["id"], d["provider_type"], cfg)
        d["config"] = cfg
        # Parse the alias list once on read (census  SSOT). Stored as
        # a JSON array of ``{"address","label"}`` dicts; a malformed/NULL
        # column degrades to ``[]`` so a corrupt row doesn't blow up the
        # /accounts page render. Pre-aliases-column legacy rows (pre-v10)
        # surface as a missing key → ``"[]"`` default → ``[]``.
        d["aliases"] = load_json_col(d.pop("aliases_json", "[]"), default=[])
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
    now = now_utc_iso()
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
    # N-222b R22: fold onto the is_admin bool SSOT.
    if is_admin(user):
        return True
    if acct.get("user_id") == user.get("id"):
        return True
    return is_account_delegate(conn, acct["id"], user["id"])

def can_administer_account(
    conn: sqlite3.Connection,
    user: dict | None,
    acct: dict | None,
) -> bool:
    """Authz gate for SENSITIVE per-account operations — the HIPAA-flag
    flip, account deletion, and delegate grant/revoke. True when:

    * ``user`` has admin role, OR
    * ``user`` is the account owner.

    Deliberately STRICTER than :func:`can_manage_account`: **a delegate is
    NOT an administrator.** A delegate may run the account (manage) but must
    never escalate (grant/revoke further delegation), flip the HIPAA flag,
    or destroy the account — exactly the carve-out :func:`can_manage_account`
    documents ("Sensitive operations … bypass this and check admin/owner
    directly — delegates intentionally cannot escalate or destroy the
    account"). This is the SSOT for the ``owner-or-admin, no-delegate``
    decision that was previously inlined as
    ``acct["user_id"] == user["id"] or is_admin`` across the sensitive-op
    handlers (divergence census 2026-06-11). Using :func:`can_manage_account`
    for any of these ops would silently let a delegate escalate — the
    actuator pin (``tests/test_account_administer_gate_pin.py``) forbids it.

    ``conn`` is unused today (the role+owner decision needs no DB lookup) but
    kept for signature-parity with :func:`can_manage_account`, so the two
    gates are mechanically interchangeable at call sites and a future
    ``account_admins`` table can extend the decision here alone without
    touching every caller.
    """
    if not user or not acct:
        return False
    # N-222b R22: fold onto the is_admin bool SSOT.
    if is_admin(user):
        return True
    return acct.get("user_id") == user.get("id")

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
        load_json_col(d.pop("config_json", "{}"), default={}),
    )
    cfg = apply_ingestion_back_compat(conn, d["id"], d["provider_type"], cfg)
    d["config"] = cfg
    # census  SSOT — corrupt/NULL aliases column degrades to [].
    d["aliases"] = load_json_col(d.pop("aliases_json", "[]"), default=[])
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
    from email_triage.triage_logging import is_hipaa_mode
    now = now_utc_iso()
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
        (user_id, name, provider_type, dump_json_col(config),
         int(bool(hipaa)), created_under, int(bool(is_active)),
         now, now),
    )
    conn.commit()
    return cursor.lastrowid


def account_is_active(conn: sqlite3.Connection, account_id: int) -> bool:
    """Cheap single-column read of an account's ``is_active`` flag.

    Used by the IMAP IDLE watcher's per-message fail-closed re-check
    (Loop-5 census) — a full ``get_email_account`` would JOIN users +
    run the config back-compat shim on a hot path. Fail-closed default:
    a vanished account (no row) reads False (stop ingesting); a row with
    a NULL/absent column reads as active (the column is NOT NULL DEFAULT
    1, so this only matters for a corrupt row, and pausing-everyone on a
    NULL would be worse than the rare corrupt-row over-run).
    """
    row = conn.execute(
        "SELECT is_active FROM email_accounts WHERE id = ?",
        (account_id,),
    ).fetchone()
    if row is None:
        return False
    val = row[0]
    if val is None:
        return True
    return bool(val)


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
    now = now_utc_iso()
    cursor = conn.execute(
        "UPDATE email_accounts SET is_active = ?, updated_at = ? "
        "WHERE id = ?",
        (int(bool(active)), now, account_id),
    )
    conn.commit()
    ok = cursor.rowcount > 0
    if ok:
        #  R32 (census wf_56d1585d 2026-07-09 MED-UX) — flush the
        # 5-min-TTL provider-labels cache so the picker doesn't serve
        # stale entries for a paused/re-enabled account. Sibling of the
        # delete_email_account invalidator at line 1318. Best-effort per
        # N-294 R30 (observable failure, not silent).
        try:
            from email_triage.providers.provider_labels import (
                invalidate_cache_for_account,
            )
            invalidate_cache_for_account(int(account_id))
        except Exception as _n322_e:
            from email_triage.triage_logging import get_logger as _gl
            _gl(__name__).debug(
                "N-322 R32: provider_labels invalidate skipped after "
                "set_account_active(account_id=%d): %s",
                account_id, _n322_e,
            )
    return ok

@db_write
def _hipaa_flip_on_cascade(
    conn: sqlite3.Connection,
    account_id: int,
    actor_id: int | None = None,
) -> dict[str, Any]:
    """N-262 R26 — cascade side-effects on a HIPAA 0→1 flip.

    Per-field semantics (operator-decided 2026-07-03 during the R26
    cascade sweep):

    * ``auto_scan_enabled`` → **force-OFF**. Auto-scanning under HIPAA
      is a §164.502(a) risk — fail-closed on flip. Operator can
      re-enable knowing HIPAA is on; the UI carries a warning banner
      at the flip surface communicating this cascade.
    * ``style_alias_mode_enabled`` → **leave-as-is**. Existing style-
      mine PHI-scrub handles the PHI-derived-identity concern.
    * ``calendar_surrogate_account_id`` → **leave-as-is**. The
      resolver at ``web/calendars.py:318`` already refuses if EITHER
      account is HIPAA (bidirectional gate).
    * calendar ``api`` role → **force-downgrade to viewer + audit
      event**. The per-request ``HIPAA_RESTRICTED_ROLES`` gate is
      belt-and-braces at read time; proactively downgrade the
      persisted role too so the account can't hit the request-time
      block. Actual downgrade is DEFERRED — the api-role persistence
      path is complex; a follow-up commit lands the calendar-role
      strip once the persistence seam is fully mapped.
    * ``style_knobs_hipaa_allow`` → **leave-as-is**. Operator's
      explicit opt-in; don't unwind it on flip.
    * ``style_profile`` → **leave-as-is**. Read-time PHI-scrub
      handles the pre-HIPAA-signal concern.

    Called AFTER the flag flip UPDATE + audit event write, inside the
    SAME transaction. Returns a dict of {field: (before, after)}
    describing the applied cascade so the caller can log / audit the
    per-field decisions.
    """
    from email_triage.web.db import (
        is_auto_scan_enabled_for_account,
        set_auto_scan_enabled_for_account,
    )
    applied: dict[str, Any] = {}
    acct_after_flip = get_email_account(conn, account_id)
    if acct_after_flip is None:
        return applied
    # Force-OFF auto_scan_enabled if currently on.
    if is_auto_scan_enabled_for_account(acct_after_flip):
        set_auto_scan_enabled_for_account(conn, account_id, False)
        applied["auto_scan_enabled"] = (True, False)
    # N-262c R26 — calendar api-role force-downgrade. Per operator's
    # per-field decision, any calendar carrying `roles.api = True` for
    # this account is downgraded on the HIPAA flip (the belt-and-braces
    # `HIPAA_RESTRICTED_ROLES` request-time gate is preserved; this
    # proactively strips the persisted role so the account cannot ever
    # hit the request-time block).
    cfg = acct_after_flip.get("config") or {}
    cals = cfg.get("calendars") if isinstance(cfg, dict) else None
    if isinstance(cals, list):
        api_downgrade_count = 0
        new_cals: list[dict[str, Any]] = []
        for cal in cals:
            if not isinstance(cal, dict):
                new_cals.append(cal)
                continue
            roles = cal.get("roles") if isinstance(cal.get("roles"), dict) else None
            if roles and roles.get("api"):
                # Copy-on-write so the original list stays clean if we
                # abort. Force api=False; other roles unchanged.
                new_roles = dict(roles)
                new_roles["api"] = False
                new_cal = dict(cal)
                new_cal["roles"] = new_roles
                new_cals.append(new_cal)
                api_downgrade_count += 1
            else:
                new_cals.append(cal)
        if api_downgrade_count > 0:
            update_account_config_keys(conn, account_id, calendars=new_cals)
            applied["calendar_api_role"] = (
                f"downgraded {api_downgrade_count} calendar(s)"
            )
    return applied


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

    N-262 R26 — on a 0→1 transition, ``_hipaa_flip_on_cascade`` runs
    inside the same transaction to force-off derived-state fields
    that would otherwise silently continue to permit non-HIPAA-safe
    processing (see helper docstring for the per-field decisions).

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

    now = now_utc_iso()
    direction = "on" if hipaa else "off"
    scope = f"account:{account_id}"
    try:
        conn.execute("BEGIN")
        conn.execute(
            "UPDATE email_accounts SET hipaa = ?, updated_at = ? WHERE id = ?",
            (int(bool(hipaa)), now, account_id),
        )
        #  — chained audit write via the SSOT (the SECOND writer of this
        # table; record_hipaa_boundary in db/audit.py is the first). Txn-aware:
        # NO commit here — the explicit COMMIT below keeps the hipaa flag flip +
        # the boundary-event row atomic. Imported locally to avoid any cycle.
        from email_triage.db.audit import _chain_insert
        _chain_insert(conn, "hipaa_boundary_events", {
            "ts": now,
            "scope": scope,
            "direction": direction,
            "actor_id": actor_id,
            "reason": reason,
        })
        # N-262 R26 — cascade side-effects on a 0→1 transition (fail-
        # closed HIPAA posture). Runs inside the same transaction; a
        # cascade failure rolls back the flag flip too. The 1→0
        # direction has no cascade (revealing pre-existing settings
        # is the operator's explicit choice).
        cascade: dict[str, Any] = {}
        if hipaa and not current:
            cascade = _hipaa_flip_on_cascade(conn, account_id, actor_id=actor_id)
            if cascade:
                _chain_insert(conn, "hipaa_boundary_events", {
                    "ts": now,
                    "scope": scope,
                    "direction": "cascade",
                    "actor_id": actor_id,
                    "reason": (
                        "0->1 cascade: " + ", ".join(
                            f"{k}=off" for k in cascade
                        )
                    ),
                })
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
    """Update an email account. Returns True if updated.

    N-280 R29: on-config-change, sweep the per-mailbox settings that
    the old config's mailbox list minted but the new config's list
    dropped (`watch_hwm:<id>:mailbox:<name>`, `mailbox_routes:<id>:
    <mailbox>`). Otherwise those settings orphan forever — the
    census R29 #7 finding.
    """
    import json
    # Read OLD config BEFORE the UPDATE so we can compute the removed-
    # mailbox delta. Failure to read = fall through to the UPDATE (best-
    # effort orphan cleanup; the account update itself must not block).
    removed_mailboxes: set[str] = set()
    try:
        old_row = conn.execute(
            "SELECT config_json FROM email_accounts WHERE id = ?", (account_id,),
        ).fetchone()
        if old_row is not None:
            # N-296 R30 (CI-red fix-forward on N-280): route through
            # the `row_get` SSOT — the N-234 hasattr ratchet caught
            # the bare-hasattr I hand-rolled here + fired at
            # baseline 81→82.
            from email_triage.db._helpers import load_json_col, row_get
            old_cfg_raw = row_get(old_row, "config_json", 0)
            if old_cfg_raw:
                # N-309 R30 (CI-red fix-forward + tranche  batch
                # A DB-SME + DA panel): route the JSON-col decode
                # through the `load_json_col` SSOT — pin
                # `test_json_col_decode_pin` census  fires on the
                # bare `json.loads` (corrupt column → 500). SSOT
                # returns `{}` on corrupt so the orphan-sweep degrades
                # to "no mailboxes removed" instead of a bare 500.
                old_cfg = load_json_col(old_cfg_raw, default={})
                old_mailboxes = set(old_cfg.get("mailboxes") or [])
                new_mailboxes = set(config.get("mailboxes") or [])
                removed_mailboxes = old_mailboxes - new_mailboxes
    except Exception as _n309_e:
        # N-309 R30: DA flagged the pre-fix broad `except: pass` as
        # a silent-swallow that would hide a bug in the OLD-read /
        # JSON decode from any forensic review. Route to `.debug`
        # per N-294 pattern (silent-swallow → debug log at 4
        # provider_labels sites, same session). Best-effort orphan
        # sweep MUST still not block the parent UPDATE, so we don't
        # re-raise — but the observability is now there.
        from email_triage.triage_logging import get_logger as _n309_gl
        _n309_gl("db.accounts").debug(
            "N-280 orphan-mailbox sweep: OLD config read/decode failed",
            account_id=account_id,
            error=type(_n309_e).__name__,
        )

    now = now_utc_iso()
    cursor = conn.execute(
        "UPDATE email_accounts SET name = ?, provider_type = ?, config_json = ?, "
        "is_active = ?, updated_at = ? WHERE id = ?",
        (name, provider_type, dump_json_col(config), int(is_active), now, account_id),
    )
    ok = cursor.rowcount > 0
    # N-280 R29: per-removed-mailbox settings sweep. Bidirectional PD#18
    # — mint a key when a mailbox is added, delete the key when it's
    # removed. Without this, `watch_hwm:<id>:mailbox:<removed>` +
    # `mailbox_routes:<id>:<removed>` orphan across the update boundary.
    if ok and removed_mailboxes:
        try:
            from email_triage.web.db import delete_setting
            for mb in removed_mailboxes:
                # watch_hwm
                delete_setting(conn, f"watch_hwm:{account_id}:mailbox:{mb}")
                # mailbox_routes
                delete_setting(conn, f"mailbox_routes:{account_id}:{mb}")
        except Exception:
            # Best-effort: the update already committed. A cleanup miss
            # here means the orphan will re-appear until manually
            # cleaned — surface via the audit log rather than block
            # the update.
            pass
    conn.commit()
    if ok:
        #  R32 (census wf_56d1585d 2026-07-09 MED-UX) — flush the
        # 5-min-TTL provider-labels cache so the picker doesn't serve
        # stale entries after name/provider_type/config change.
        # Sibling of the invalidator at update_email_account_config:1025
        # + set_account_active + delete_email_account. Best-effort per
        # N-294 R30 (observable failure, not silent).
        try:
            from email_triage.providers.provider_labels import (
                invalidate_cache_for_account,
            )
            invalidate_cache_for_account(int(account_id))
        except Exception as _n322_e:
            from email_triage.triage_logging import get_logger as _gl
            _gl(__name__).debug(
                "N-322 R32: provider_labels invalidate skipped after "
                "update_email_account(account_id=%d): %s",
                account_id, _n322_e,
            )
    return ok

@db_write
def update_email_account_config(
    conn: sqlite3.Connection, account_id: int, config: dict,
) -> bool:
    """Patch the config_json for an account without touching the other
    columns. Used by the history-poll loop to clear a
    ``poll_interval_override`` on push↔poll transitions."""
    import json
    now = now_utc_iso()
    cursor = conn.execute(
        "UPDATE email_accounts SET config_json = ?, updated_at = ? WHERE id = ?",
        (dump_json_col(config), now, account_id),
    )
    conn.commit()
    # N-348b R31 (2026-07-04, census follow-up on N-348 partial): bust
    # provider_labels cache — any config_json write may have changed
    # imap.host / smtp.host / oauth-scope-adjacent knobs the
    # provider_labels cache-key is sensitive to. Unconditional bust
    # keeps the SSOT close in the seam without per-key inspection.
    from email_triage.providers.provider_labels import (
        invalidate_cache_for_account,
    )
    invalidate_cache_for_account(account_id)
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

    # BEGIN IMMEDIATE acquires the write lock up front so a concurrent
    # reader-then-writer can't slot in between our SELECT and UPDATE.
    # SQLite's default deferred mode would hit "database is locked"
    # under contention but only after the SELECT — too late. We fold
    # the read + write into one transaction explicitly.
    #
    # N-342 R31 (2026-07-04 CI-red fix-forward from Phase-4 DA finding):
    # detect an already-open outer transaction so a caller that owns the
    # BEGIN (e.g. ``set_account_hipaa`` + ``_hipaa_flip_on_cascade`` on
    # accounts with ``auto_scan_enabled=True`` or a calendar carrying
    # the ``api`` role) doesn't trip ``sqlite3.OperationalError: cannot
    # start a transaction within a transaction``. When nested we skip
    # our OWN BEGIN/COMMIT/ROLLBACK and let the caller's outer txn own
    # the atomicity — the read-modify-write is still safe because the
    # outer BEGIN already holds the write lock. Raises propagate to the
    # caller's rollback path unchanged.
    nested = bool(getattr(conn, "in_transaction", False))
    if not nested:
        conn.execute("BEGIN IMMEDIATE")
    try:
        row = conn.execute(
            "SELECT config_json FROM email_accounts WHERE id = ?",
            (account_id,),
        ).fetchone()
        if row is None:
            if not nested:
                conn.execute("ROLLBACK")
            return False
        # census  SSOT — corrupt config_json degrades to {} so this
        # read-modify-write doesn't crash inside the BEGIN IMMEDIATE txn.
        current = load_json_col(row[0], default={})

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
            if not nested:
                conn.execute("ROLLBACK")
            return True  # No-op write — row exists, nothing to change.

        now = now_utc_iso()
        conn.execute(
            "UPDATE email_accounts "
            "SET config_json = ?, updated_at = ? WHERE id = ?",
            (dump_json_col(merged), now, account_id),
        )
        if not nested:
            conn.execute("COMMIT")
    except Exception:
        if not nested:
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
        # N-242b R24: TriageLogger SSOT.
        from email_triage.triage_logging import get_logger
        logger = get_logger("web.db")
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
            **log_extra,  # N-242b R24: TriageLogger takes kwargs, not extra=
        )
    except Exception:
        # Log emission must never sink the call — the write already
        # landed. Best-effort only.
        pass
    # N-348c R31 (2026-07-04 census follow-up): bust provider_labels
    # cache when config_json keys changed — any patched key may have
    # touched imap.host / smtp.host / oauth-scope-adjacent config the
    # cache-key depends on. Gated on `changed_keys` so a no-op call
    # doesn't churn the cache. Best-effort — never sink the caller.
    if changed_keys:
        try:
            from email_triage.providers.provider_labels import (
                invalidate_cache_for_account,
            )
            invalidate_cache_for_account(account_id)
        except Exception:
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
    norm_primary = canonical_email(primary or "")
    seen: set[str] = set()
    out: list[dict] = []
    for entry in raw or []:
        if not isinstance(entry, dict):
            raise AliasValidationError(
                "Each additional address must be a name/value entry."
            )
        addr = canonical_email(str(entry.get("address") or ""))
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
    now = now_utc_iso()
    cursor = conn.execute(
        "UPDATE email_accounts SET aliases_json = ?, updated_at = ? "
        "WHERE id = ?",
        (dump_json_col(aliases), now, account_id),
    )
    conn.commit()
    return cursor.rowcount > 0

@db_write
def delete_email_account(conn: sqlite3.Connection, account_id: int) -> bool:
    """N-275 R28: SOFT-deactivate the email account. Returns True if the
    account existed + was deactivated.

    OPERATOR DESIGN RULING (2026-07-03, punch ): "No delete, ever.
    Mark as disabled and hide from any picker not in the /admin
    section." A hard `DELETE FROM email_accounts` cascade-destroys
    the account's `hipaa_access_events` rows (`account_id ON DELETE
    CASCADE`) — the SAME §164.312(b)/(c)(1) tamper-evident audit
    destruction the  ruling forbade for users. This function used
    to hard-delete; now it soft-deactivates by flipping `is_active=0`
    (the "disabled" state operator ruling references) so:
      - The row + ALL its `hipaa_access_events` history are RETAINED.
      - Account pickers filtering `active_only=True` (the default
        outside `/admin`) drop it invisibly.
      - `/admin` views see the deactivated row and can re-enable it.

    The primitive KEEPS its `delete_email_account` name for backwards
    compat + so the pin `test_account_delete_purge_pin` continues to
    guard the "delete-shape ⇒ pair with purge" invariant. Credentials
    purge is still the caller's responsibility (via
    `WatcherManager.apply_account_deleted` → `purge_account_local_
    state`) — this function does NOT purge.
    """
    now = now_utc_iso()
    cursor = conn.execute(
        "UPDATE email_accounts SET is_active = 0, updated_at = ? "
        "WHERE id = ? AND COALESCE(is_active, 1) = 1",
        (now, account_id),
    )
    conn.commit()
    ok = cursor.rowcount > 0
    if ok:
        # N-247 R24: flush the 5-min-TTL provider-labels cache so the
        # picker doesn't serve stale labels for a deactivated account.
        try:
            from email_triage.providers.provider_labels import (
                invalidate_cache_for_account,
            )
            invalidate_cache_for_account(int(account_id))
        except Exception as _n271_e:  # N-294 R30 (HIPAA-SME follow-up)
            # Best-effort still, but the failure is now observable —
            # a broken invalidator SSOT (e.g. new required arg) previously
            # silently deleted the invalidation across all 4 sites.
            from email_triage.triage_logging import get_logger as _gl
            _gl(__name__).debug(
                "provider_labels invalidate best-effort failed",
                extra={"error": type(_n271_e).__name__, "account_id": account_id},
            )
    return ok


def purge_account_local_state(
    conn: sqlite3.Connection,
    account_id: int,
    secrets=None,
) -> dict:
    """Purge ALL account-scoped persistent state (settings + secrets).

    This is the L1 §164.310(d)(2)(i) media-disposal SSOT for per-account
    credential/state cleanup.  It MUST be called (via
    :func:`WatcherManager.apply_account_deleted`) before or as part of
    deleting an ``email_accounts`` row.  It does NOT delete the row
    itself — the caller does that, or the FK CASCADE on a user-delete does.

    Three stores are purged:

    1. **Settings table** — every key scheme keyed by ``account_id``,
       via :func:`email_triage.web.settings_keys.delete_account_settings`
       (the pre-existing SSOT for the ``settings`` table sweep).

    2. **Secrets store** — account-scoped provider credentials:
       * ``ACCOUNT_{id}_IMAP_PASSWORD``
       * ``ACCOUNT_{id}_O365_SECRET``
       * ``ACCOUNT_{id}_GMAIL_REFRESH_TOKEN``
       * ``ACCOUNT_{id}_%`` LIKE prefix — forward-compat catch; any
         future per-account secret that obeys the ``ACCOUNT_{id}_``
         naming convention is removed without a code change.
       * ``office365_clientstate:{id}`` — Graph webhook clientState,
         stored in secrets (not settings; see docstring in
         ``settings_keys.office365_clientstate``).  It is purged HERE via
         the secrets path; it was REMOVED from ``_ACCOUNT_KEY_CATALOG``
         (run17 ) because a settings-sweep entry was a no-op against the
         settings table (the value never lives there) and falsely implied
         coverage.  This call is the real — and only — disposal path.

    3. **On-disk per-account MSAL token cache** (run18 #1) —
       ``./data/msal_cache_<id>.json`` holds PLAINTEXT O365 OAuth
       access+refresh tokens (written 0o600 but UNENCRYPTED, OUTSIDE the
       SQLCipher DB).  It is the ONLY purged store that lives on the
       FILESYSTEM rather than in the DB; the path is derived from the SSOT
       ``providers.factory.msal_cache_path_for_account`` so the unlink can
       never diverge from the factory writer.  This is the §164.310(d)(2)(i)
       disposal for the most-exposed token copy — without it the token file
       SURVIVED account deletion (and stayed redeemable).

    Key derivation for the ACCOUNT_ family delegates entirely to
    :func:`email_triage.providers.traits.secret_key_for_account` (the
    SSOT).  The LIKE sweep catches any key the SSOT constructs, so
    adding a new provider key to the SSOT automatically catches it here
    without a separate code change.

    Args:
        conn:       A live DB connection (used only for the settings sweep).
        account_id: The account being deleted.
        secrets:    The ``DbSecrets`` provider (or any compatible object
                    with ``.delete(key) -> bool`` and ``.list_keys() ->
                    list[str]``).  When ``None`` the secrets sweep is
                    skipped (e.g. unit-test environments that need to
                    verify the settings sweep in isolation; the caller
                    MUST pass secrets in production).

    Returns a dict with counts::

        {
            "settings_deleted": int,
            "secrets_deleted": int,
            "phi_rows_deleted": int,
            "msal_cache_deleted": int,  # 0/1 — the on-disk token-cache file
            "account_id": int,
        }

    FAIL-CLOSED contract (PD#8): a secrets ``delete()`` that RAISES — OR a real
    on-disk MSAL-cache ``unlink()`` error (perms / FS; NOT a "file absent",
    which ``missing_ok=True`` swallows) — is a real backend error (locked store
    / decrypt failure / undeletable credential file; NOT a "key absent", which
    returns False). It is collected (in ``secret_failures``) and RE-RAISED at
    the end, so the caller refuses the row delete rather than orphan
    credentials. The settings + PHI-table deletes that already committed are
    idempotent on the operator's retry.

    Also purged (census N-64 SME panel — the builder's original enumeration was
    INCOMPLETE; these share the same "an account goes away" root cause +
    §164.310(d)(2)(i) disposal obligation):
      * ``watch_{watch_id}_hmac`` — per-watch HMAC signing secrets, keyed by
        WATCH id (not ``ACCOUNT_{id}_*``) so the prefix sweep misses them; the
        ``email_watches`` rows cascade with the account but their secrets do not.
      * ``hipaa_style_descriptors`` + ``per_contact_style_hipaa`` rows — PHI-
        derived per-account style data. NOTE (verify-don't-accept): these DO
        have a table-level FK ``ON DELETE CASCADE`` to ``email_accounts`` and
        ``PRAGMA foreign_keys=ON`` makes it fire, so the cascade is the primary
        disposal; this explicit DELETE is belt-and-braces defense-in-depth.
    """
    # N-242 R24: TriageLogger SSOT — the account-delete cascade is
    # §164.310(d) load-bearing; a raw `logging.getLogger` fork this
    # sensitive audit outside the HMAC chain.
    from email_triage._errfmt import fmt_exc
    from email_triage.triage_logging import get_logger
    _log = get_logger("db.accounts")

    # ------------------------------------------------------------------
    # 1. Settings sweep — delegate to the existing SSOT.
    # ------------------------------------------------------------------
    from email_triage.web.settings_keys import delete_account_settings
    settings_deleted = delete_account_settings(conn, account_id)

    # ------------------------------------------------------------------
    # 2. Secrets sweep — provider credentials + clientstate.
    # ------------------------------------------------------------------
    secrets_deleted = 0
    secret_failures: list[str] = []  # keys whose delete()/list RAISED → fail closed

    def _purge_secret(key: str) -> None:
        nonlocal secrets_deleted
        try:
            if secrets.delete(key):
                secrets_deleted += 1
        except Exception as exc:  # noqa: BLE001 — a real backend error (locked
            # store / decrypt). NOT a "key absent" (delete returns False for
            # that). Collect + fail closed below; never silently swallow.
            secret_failures.append(key)
            _log.warning(
                "purge_account_local_state: secret delete FAILED (fail closed)",
                extra={"account_id": account_id, "key_name": key,
                       "error": fmt_exc(exc)},
            )

    if secrets is not None:
        from email_triage.providers.traits import secret_key_for_account
        from email_triage.web import settings_keys as _S

        # Explicit per-provider keys via the SSOT constructor.
        explicit = {
            secret_key_for_account(account_id, pt)
            for pt in ("imap", "office365", "gmail_api")
            if secret_key_for_account(account_id, pt)
        }
        for sk in explicit:
            _purge_secret(sk)

        # LIKE-prefix forward-compat sweep — any future ACCOUNT_{id}_* key.
        prefix = f"ACCOUNT_{int(account_id)}_"
        try:
            for k in list(secrets.list_keys()):
                if k.startswith(prefix) and k not in explicit:
                    _purge_secret(k)
        except Exception as exc:  # noqa: BLE001
            secret_failures.append("<list_keys>")
            _log.warning(
                "purge_account_local_state: list_keys FAILED (LIKE sweep "
                "skipped; fail closed)",
                extra={"account_id": account_id, "error": fmt_exc(exc)},
            )

        # Graph webhook clientState — in secrets, not settings.
        _purge_secret(_S.office365_clientstate(account_id))

        # Per-WATCH HMAC signing secrets `watch_{watch_id}_hmac` (census N-64
        # DA must-fix): keyed by WATCH id, not ACCOUNT_{id}_*, so the prefix
        # sweep misses them. The email_watches rows cascade with the account
        # but their secrets do not — enumerate the account's watches NOW
        # (before the cascade) and purge each watch's key.
        from email_triage.web.email_watches import hmac_secret_key
        try:
            watch_ids = [
                r[0] for r in conn.execute(
                    "SELECT watch_id FROM email_watches WHERE account_id = ?",
                    (int(account_id),),
                ).fetchall()
            ]
        except sqlite3.OperationalError:
            watch_ids = []  # table absent (older schema)
        for wid in watch_ids:
            _purge_secret(hmac_secret_key(wid))  # SSOT key: watch_{id}_hmac

    # ------------------------------------------------------------------
    # 2b. On-disk per-account MSAL token cache — §164.310(d)(2)(i) MEDIA
    #     DISPOSAL (run18 #1). ``./data/msal_cache_<id>.json`` persists
    #     PLAINTEXT O365 OAuth access+refresh tokens (providers/office365.py
    #     :_save_cache — atomic 0o600 but UNENCRYPTED, OUTSIDE the SQLCipher
    #     DB), so it lives on the FILESYSTEM, not in any DB-backed store the
    #     sweeps above touch. Without THIS unlink the MORE-exposed token copy
    #     SURVIVES the purge chartered to erase it (and stays redeemable — the
    #     install-level client_secret persists). Runs UNCONDITIONALLY (not
    #     gated on ``secrets``) since it is a filesystem op. Path via the
    #     factory SSOT so the unlink can NEVER disagree with the writer.
    # ------------------------------------------------------------------
    # N-245b R24: route through the per-account artifact REGISTRY funnel
    # (`providers/_ondisk_artifacts::dispose_all_per_account_artifacts`)
    # so a NEW per-account artifact inherits the disposal without editing
    # this handler. Keep the path-derivation reference for the error-msg
    # sentinel so the fail-closed audit reads the actual filename.
    from email_triage.providers._ondisk_artifacts import (
        dispose_all_per_account_artifacts,
    )
    from email_triage.providers.factory import msal_cache_path_for_account
    msal_cache_deleted = 0
    _cache_path = msal_cache_path_for_account(account_id)  # kept for the error-msg sentinel
    try:
        msal_cache_deleted = dispose_all_per_account_artifacts(account_id)
    except OSError as exc:  # a REAL unlink error (perms / FS),
        # NOT a "file absent" (missing_ok=True already swallows that). A token
        # file we could not delete is an orphaned PLAINTEXT credential, so
        # collect + fail CLOSED below EXACTLY like the secrets sweep (the
        # ``<...>`` sentinel mirrors the ``<list_keys>`` entry above; the final
        # ``if secret_failures: raise`` gate then refuses to report success).
        secret_failures.append(f"<msal_cache:{_cache_path}>")
        _log.warning(
            "purge_account_local_state: MSAL token-cache unlink FAILED "
            "(fail closed)",
            extra={"account_id": account_id, "path": str(_cache_path),
                   "error": fmt_exc(exc)},
        )

    # ------------------------------------------------------------------
    # 3. PHI-derived per-account style tables — DEFENSE-IN-DEPTH disposal.
    #    VERIFY-DON'T-ACCEPT (census N-64): the SME panel claimed these have NO
    #    FK and are orphaned; the actual schema (migrations.py) gives BOTH a
    #    table-level ``FOREIGN KEY (account_id) REFERENCES email_accounts(id)
    #    ON DELETE CASCADE``, and with ``PRAGMA foreign_keys=ON`` (set in
    #    db.py:862 / _engine.py) the rows DO cascade on the row delete (verified
    #    at runtime: 1->0). So the primary disposal is the FK cascade; this
    #    explicit DELETE is belt-and-braces — it guarantees §164.310(d)(2)(i)
    #    PHI disposal even if FK enforcement is ever disabled or the cascade
    #    removed, and runs BEFORE the row delete so it is idempotent with it.
    # ------------------------------------------------------------------
    phi_rows_deleted = 0
    for tbl in ("hipaa_style_descriptors", "per_contact_style_hipaa"):
        try:
            cur = conn.execute(
                f"DELETE FROM {tbl} WHERE account_id = ?", (int(account_id),),
            )
            phi_rows_deleted += cur.rowcount or 0
        except sqlite3.OperationalError:
            pass  # table absent (older schema) — defensive
    conn.commit()

    # FAIL CLOSED (PD#8): if ANY secret delete (or list_keys) RAISED, the
    # credentials may still be on disk — raise so the caller refuses the row
    # delete and the operator retries (the committed settings + PHI deletes are
    # idempotent on retry). A delete() returning False (key absent) is NOT a
    # failure. This is the must-happen §164.310(d)(2)(i) guarantee.
    if secret_failures:
        raise RuntimeError(
            f"purge_account_local_state: {len(secret_failures)} secret(s) "
            f"failed to purge for account {account_id} ({secret_failures}); "
            f"refusing to report success so the caller fails closed and does "
            f"not orphan credentials."
        )

    # N-271 R28: PROVIDER-LABELS CACHE INVALIDATION FUNNEL. Credentials
    # for this account are now purged; the 5-min-TTL label cache
    # (`providers/provider_labels.py`) was populated UNDER those
    # now-gone credentials + must NOT continue serving stale labels
    # for the account until TTL expiry. Route through the SSOT + fail-
    # open (the purge already succeeded — a cache-flush failure is
    # best-effort). Sibling to N-247 which wired it into
    # `delete_email_account`; R28 census #2 flagged this + the OAuth
    # completion sites as the un-wired siblings.
    try:
        from email_triage.providers.provider_labels import (
            invalidate_cache_for_account,
        )
        invalidate_cache_for_account(int(account_id))
    except Exception as _n271_e:  # N-294 R30 (HIPAA-SME follow-up)
        # Best-effort still, but the failure is now observable —
        # a broken invalidator SSOT (e.g. new required arg) previously
        # silently deleted the invalidation across all 4 sites.
        from email_triage.triage_logging import get_logger as _gl
        _gl(__name__).debug(
            "provider_labels invalidate best-effort failed",
            extra={"error": type(_n271_e).__name__, "account_id": account_id},
        )

    _log.info(
        "purge_account_local_state: purge complete",
        extra={
            "account_id": account_id,
            "settings_deleted": settings_deleted,
            "secrets_deleted": secrets_deleted,
            "phi_rows_deleted": phi_rows_deleted,
            "msal_cache_deleted": msal_cache_deleted,
        },
    )
    return {
        "settings_deleted": settings_deleted,
        "secrets_deleted": secrets_deleted,
        "phi_rows_deleted": phi_rows_deleted,
        "msal_cache_deleted": msal_cache_deleted,
        "account_id": account_id,
    }

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
        d["actions"] = load_json_col(d.pop("actions_json", "[]"), default=[])
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
    d["actions"] = load_json_col(d.pop("actions_json", "[]"), default=[])
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
    now = now_utc_iso()
    actions_json = dump_json_col(actions)

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
    # A7 (census 2026-06-09): the bare-address extraction is the shared
    # SSOT; this function ADDS the account-bucket canonicalization on top
    # (Gmail-style ``+suffix`` collapse) — its distinct purpose. The SSOT
    # already drops the display name + angle brackets and lower-cases.
    #
    # KNOWN EDGE (SME DA-#4, verified): the SSOT anchors on the FIRST
    # ``<...>`` block; the prior impl used ``rfind("<")`` (LAST). They are
    # byte-identical for every mainstream From shape (display-name,
    # bracketed, bare, +suffix, quoted-display-name, "Last, First") — the
    # ONLY divergence is a display name that itself contains an unescaped
    # ``<`` (e.g. ``'"a<b" <real@x>'``), which RFC 5322 requires quoted and
    # which providers normalize away one level before this is reached. On
    # that pathological input the bucket key degrades; the failure mode is
    # graceful — a wrong/no per-alias bucket falls back to the account
    # profile (no crash, no cross-account access, no PHI surface; the bucket
    # is style-learning sample routing, not an authz key).
    from email_triage.mail_headers import extract_bare_address
    s = extract_bare_address(value)
    if not s:
        return ""
    # Split off the ``+suffix`` tag if present. The tag is part of the
    # same delivery destination on Gmail-style "plus addressing" --
    # two captures of ``alice+work@x`` and ``alice@x`` belong in the
    # same bucket.
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

