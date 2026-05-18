"""Per-account calendar selection + role assignment.

Operators see + opt-in to specific calendars from their email
account's calendar provider (Google for now; Office 365 in
follow-up). Each opted-in calendar carries a set of role flags
that downstream consumers honour:

* ``meetings`` (multi)        — conflict-check meeting requests against
                                this calendar
* ``listings`` (multi)        — include in event-listing reads
                                (digests, suggest_meeting_times)
* ``api`` (multi)             — expose to the OpenClaw / API surface
                                that lets external assistants query
                                the user's schedule
* ``self_schedule`` (single)  — destination for the self-sent-event
                                triage path (#107). At most one
                                calendar across the account.

Storage shape: ``email_accounts.config_json["calendars"]`` is a
list of dicts:

.. code-block:: python

    [
        {
            "id":      "primary",
            "summary": "operator@example.com",
            "primary": True,
            "enabled": True,
            "roles": {
                "meetings":      True,
                "listings":      True,
                "api":           True,
                "self_schedule": True,
            },
        },
        ...
    ]

Empty / missing list = legacy account, no role configuration yet.
Consumers fall back to the per-account "primary" calendar so
existing behaviour is preserved on first deploy.
"""

from __future__ import annotations

from typing import Any


# Role keys the schema permits. Order also drives column order in
# the editor table.
ROLES: tuple[str, ...] = ("meetings", "listings", "api", "self_schedule")

# Roles where exactly one calendar across the account can be picked.
# Server-side validation enforces; UI uses radio inputs.
SINGLE_ROLES: frozenset[str] = frozenset({"self_schedule"})

# Roles unavailable on HIPAA-flagged accounts. ``api`` exposes
# events to the OpenClaw / external assistant surface — that
# surface lacks the HIPAA controls (audit gate, redaction,
# §164.312(b) bookkeeping) the rest of the pipeline applies, so
# PHI events must never reach it. Other roles stay available
# inside the HIPAA boundary: ``meetings`` (read-only conflict
# scan within the same account), ``listings`` (digest delivery
# is already locked to the account's own mailbox by the
# recipient-mismatch guard), ``self_schedule`` (write to the
# account's OWN calendar — no cross-account flow).
HIPAA_RESTRICTED_ROLES: frozenset[str] = frozenset({"api"})


def _empty_role_map() -> dict[str, bool]:
    return {r: False for r in ROLES}


def normalize_calendars(
    stored: list[dict[str, Any]] | None,
    discovered: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Merge the operator's stored selection with a fresh discovery.

    For each calendar the provider returns, preserve the operator's
    enabled + role flags + ``display_name`` override if they had a
    row for that ID; otherwise seed a new row with everything off.
    Calendars that no longer appear in the provider's discovery are
    dropped from the stored state (operator removed access via the
    calendar UI; we follow).

    The cached display fields (``summary``, ``primary``, plus the
    new ``access_role``) get refreshed from the discovery on every
    call so renames + sharing changes flow through immediately.
    The operator's ``display_name`` is preserved verbatim — it's the
    override that lets a calendar named ``user@gmail.com`` (Google's
    convention for the user's own primary) render as something
    friendlier in API responses ("Personal", "Family", whatever).

    Order of the returned list mirrors the discovery order so the
    UI table stays stable across refreshes.
    """
    by_id: dict[str, dict[str, Any]] = {}
    for entry in stored or []:
        if not isinstance(entry, dict):
            continue
        cid = str(entry.get("id") or "")
        if cid:
            by_id[cid] = entry

    out: list[dict[str, Any]] = []
    for cal in discovered:
        if not isinstance(cal, dict):
            continue
        cid = str(cal.get("id") or "")
        if not cid:
            continue
        prior = by_id.get(cid)
        roles_in = {}
        if prior:
            prior_roles = prior.get("roles") or {}
            if isinstance(prior_roles, dict):
                roles_in = prior_roles
        roles = _empty_role_map()
        for k in ROLES:
            roles[k] = bool(roles_in.get(k, False))
        out.append({
            "id": cid,
            "summary": str(cal.get("summary") or cid),
            "primary": bool(cal.get("primary", False)),
            "access_role": str(cal.get("access_role") or "reader"),
            "display_name": (
                str(prior.get("display_name") or "") if prior else ""
            ),
            "enabled": bool(prior.get("enabled", False)) if prior else False,
            "roles": roles,
        })
    return out


def calendar_display_label(entry: dict[str, Any]) -> str:
    """Pick the operator-facing display name for one calendar entry.

    Operator's ``display_name`` override wins. Falls back to
    Google's ``summary`` (which for a user's primary calendar is
    the user's email address — readable but not friendly). Final
    fallback: the calendar id. Always returns a non-empty string
    when the entry has any of those fields.
    """
    if not isinstance(entry, dict):
        return ""
    return (
        str(entry.get("display_name") or "")
        or str(entry.get("summary") or "")
        or str(entry.get("id") or "")
    )


def parse_calendars_form(
    form_items: list[tuple[str, str]],
    discovered_ids: list[str],
    discovered_meta: dict[str, dict[str, Any]] | None = None,
    *,
    hipaa: bool = False,
) -> list[dict[str, Any]]:
    """Build the ``calendars`` list-of-dicts from raw form fields.

    Field convention (mirrors the IMAP folder selector pattern):

      ``cal_enabled[<id>]``           — opt-in checkbox (presence == True)
      ``cal_role_meetings[<id>]``     — multi-pick checkbox
      ``cal_role_listings[<id>]``     — ditto
      ``cal_role_api[<id>]``          — ditto
      ``cal_role_self_schedule``      — radio; value is the chosen <id>

    ``discovered_ids`` constrains which calendars the form is
    allowed to reference. An attacker who appends extra
    ``cal_enabled[fake@evil.com]`` fields can't smuggle a row past
    discovery — the parser ignores anything not in the discovery
    set. ``discovered_meta`` carries display fields (summary,
    primary, access_role) keyed by id; pulled from the most-recent
    discovery so the persisted row reflects what the operator just
    saw on screen.
    """
    discovered_meta = discovered_meta or {}
    field_map: dict[str, list[str]] = {}
    for k, v in form_items:
        field_map.setdefault(k, []).append(v)

    self_schedule_pick = ""
    for v in field_map.get("cal_role_self_schedule", []):
        v = (v or "").strip()
        if v:
            self_schedule_pick = v
            break

    out: list[dict[str, Any]] = []
    for cid in discovered_ids:
        meta = discovered_meta.get(cid) or {}
        enabled_key = f"cal_enabled[{cid}]"
        meetings_key = f"cal_role_meetings[{cid}]"
        listings_key = f"cal_role_listings[{cid}]"
        api_key = f"cal_role_api[{cid}]"
        display_key = f"cal_display_name[{cid}]"
        enabled = enabled_key in field_map
        roles = _empty_role_map()
        if enabled:
            roles["meetings"] = meetings_key in field_map
            roles["listings"] = listings_key in field_map
            roles["api"] = (api_key in field_map)
            roles["self_schedule"] = (cid == self_schedule_pick)
            # HIPAA accounts can never carry HIPAA-restricted roles
            # — strip server-side regardless of what the form
            # claimed. UI also disables the inputs; this is the
            # authoritative gate.
            if hipaa:
                for restricted in HIPAA_RESTRICTED_ROLES:
                    roles[restricted] = False
        # Operator's display_name override. Persist for every row
        # (enabled or not) so a row that's currently off doesn't
        # forget the friendlier label.
        display_name = ""
        if display_key in field_map:
            display_name = (field_map[display_key][0] or "").strip()
        out.append({
            "id": cid,
            "summary": str(meta.get("summary") or cid),
            "primary": bool(meta.get("primary", False)),
            "access_role": str(meta.get("access_role") or "reader"),
            "display_name": display_name,
            "enabled": enabled,
            "roles": roles,
        })
    return out


def calendars_with_role(
    acct: dict[str, Any], role: str,
) -> list[str]:
    """Return the calendar IDs the operator picked for ``role``.

    Reads ``acct.config.calendars``. Skips disabled rows. For
    single-pick roles (``self_schedule``) returns at most one
    element — the parser already enforces uniqueness, but the
    consumer doesn't have to know that.

    Empty config (legacy account, never opened the editor) returns
    an empty list. Callers MUST handle this — the typical fallback
    is to use the account's "primary" calendar so existing
    behaviour persists on accounts that haven't migrated yet.
    """
    cfg = acct.get("config") or {}
    cals = cfg.get("calendars") or []
    if not isinstance(cals, list):
        return []
    out: list[str] = []
    for entry in cals:
        if not isinstance(entry, dict):
            continue
        if not entry.get("enabled"):
            continue
        roles = entry.get("roles") or {}
        if isinstance(roles, dict) and roles.get(role):
            cid = str(entry.get("id") or "")
            if cid:
                out.append(cid)
    return out


def get_self_schedule_calendar_id(
    acct: dict[str, Any],
) -> str | None:
    """Single-pick helper for the ``self_schedule`` role.

    Returns the calendar ID the operator picked for self-sent
    events (#107), or ``None`` if no calendar carries the role.
    Mirrors ``calendars_with_role(acct, "self_schedule")[:1]`` but
    returns a string (or None) for ergonomic single-pick callers.
    """
    matches = calendars_with_role(acct, "self_schedule")
    return matches[0] if matches else None


# ---------------------------------------------------------------------------
# Calendar surrogate
# ---------------------------------------------------------------------------
#
# Operator can route calendar ops on any account through another
# account's provider. Use cases:
#
#   * IMAP mailbox has no native calendar; surrogate to a Gmail /
#     Office 365 account that does.
#   * Multiple Gmail mailboxes (e.g. work@gmail + personal@gmail)
#     should share a single Calendar identity rather than each
#     account using its own.
#
# The "surrogate" supplies the provider (OAuth identity,
# calendarList visibility); the consuming account's own
# ``calendars`` list still drives role assignments — so two
# accounts surrogating to the same target carry independent
# role flags (e.g. one gets Meetings on Work, the other gets
# Meetings on Personal, both on the same calendar identity).


def get_surrogate_account_id(acct: dict[str, Any]) -> int | None:
    """Read the surrogate-account-id off an account's config.

    Available to every account type — operator may want to route
    calendar ops on a Gmail mailbox through a different Gmail
    account, not just IMAP-with-no-calendar. Returns ``None``
    when no surrogate is configured.
    """
    raw = (acct.get("config") or {}).get("calendar_surrogate_account_id")
    if raw is None or raw == "":
        return None
    try:
        return int(raw)
    except (TypeError, ValueError):
        return None


def resolve_surrogate_account(
    db, acct: dict[str, Any],
) -> dict[str, Any] | None:
    """Return the surrogate account dict (or ``None``) for an
    account that points at one. Five guards apply (defense in
    depth against config corruption / admin-edit footguns):

      * surrogate must exist
      * surrogate must belong to the SAME owner
      * surrogate must NOT be the account itself (no self-surrogate)
      * surrogate's provider must support calendars
        (gmail_api or office365 today)
      * NEITHER side may be HIPAA-flagged. HIPAA accounts are
        self-only — events on a HIPAA calendar can carry PHI,
        and surrogating bridges that calendar to another
        account's read/write/audit context. Refuse in both
        directions: HIPAA → non-HIPAA leaks PHI outward via
        self_schedule writes; non-HIPAA → HIPAA leaks PHI
        outward via listings / api reads. HIPAA → HIPAA also
        refuses (still cross-account, still outside the source
        account's recipient-mismatch + audit guarantees).
    """
    sid = get_surrogate_account_id(acct)
    if sid is None:
        return None
    if sid == acct.get("id"):
        return None  # self-surrogate prevented
    from email_triage.web.db import get_email_account
    surrogate = get_email_account(db, sid)
    if surrogate is None:
        return None
    if surrogate.get("user_id") != acct.get("user_id"):
        return None
    if surrogate.get("provider_type") not in ("gmail_api", "office365"):
        return None
    from email_triage.triage_logging import is_account_hipaa
    if is_account_hipaa(acct) or is_account_hipaa(surrogate):
        return None
    return surrogate


def is_calendar_effectively_enabled(
    db, acct: dict[str, Any],
) -> bool:
    """Surrogate-aware version of :func:`is_calendar_enabled`.

    Returns True when the account itself has the ``calendar_enabled``
    flag set OR when the account points at a valid surrogate whose
    ``calendar_enabled`` flag is set. Otherwise False.

    Single source of truth for "should this account get a
    calendar provider?" across the dispatch surface (IDLE
    watcher, Gmail / O365 push consumers, poll loop, manual
    triage_runner). Pre-2026-05-13 each site called
    ``is_calendar_enabled(db, account_id)`` directly, which
    returned False for an IMAP account with a calendar
    surrogate — even though the surrogate's flag was the one
    that actually governed. Symptom: calendar_provider was
    None on the IMAP path, suggest_meeting_times / invite /
    self_sent_event actions all SKIPPED with
    ``calendar_not_enabled``, and the operator-side meeting-
    request intercept never produced a calendar-aware draft.

    Mirrors the gate that ``openclaw.py:_open_calendar`` has
    used since the surrogate feature shipped — that path
    correctly resolved the flag via the surrogate, the
    dispatch paths did not. This helper consolidates both
    behaviours under one name.
    """
    from email_triage.web.db import is_calendar_enabled
    surrogate = resolve_surrogate_account(db, acct)
    flag_acct_id = (surrogate or acct)["id"]
    return is_calendar_enabled(db, flag_acct_id)
