"""Authorization SSOT for the SELF-SCOPED manageable-account-set (§5).

The "manageable set" is the account-id set a requester may manage for their OWN
multi-account surfaces — Topic digests, style data — computed as **owner +
delegate, with NO admin-global bypass**. That self-scoping is deliberate
(divergence census 2026-06-11 + the profile.py helper docstrings): an admin
tuning THEIR OWN Topics still only watches their own/delegated mailboxes, never
every install account. It is exactly ``can_manage_account`` *minus* the
admin-global bypass — `list_email_accounts(db, user_id=requester)` already
returns owner rows plus delegate rows.

★ NOT to be confused with two DIFFERENT, intentionally-separate concepts:
  * ``db.accounts.can_manage_account`` / ``can_administer_account`` — per-account
    owner/admin/delegate gates that DO carry the admin-global bypass; used by the
    sensitive-op + routes actuators (a route picker shows an admin every account).
  * The route picker's ``manageable`` (``web/routers/ui/routes.py``) is built
    admin-global + ``active_only`` — a DISTINCT scope; it stays on its own
    ``can_manage_account`` gate and is NOT routed through here.

PD#9 contract — every CLIENT-submitted account_id on a self-scoped multi-account
surface MUST be intersected with this set BEFORE acting (read AND write), gated
at the ACTUATOR (the apply path), fail-closed. The funnels below are that gate;
``tests/test_account_scope_ssot_pin.py`` is the count-agnostic inverse pin
(no inline ``<id> in/not in manageable`` membership outside this module).
"""

from __future__ import annotations

from typing import Any, Iterable

from email_triage._int_utils import parse_int_or_none  # N-219c/8 R23


def manageable_account_ids(db: Any, user: dict) -> set[int]:
    """The requester's MANAGEABLE account-id set — owner + delegate, NO
    admin-global bypass (deliberately self-scoped). A ``set[int]`` for O(1)
    membership on the preview/gate hot paths."""
    from email_triage.web.db import list_email_accounts
    return {int(a["id"]) for a in list_email_accounts(db, user_id=user["id"])}


def manageable_accounts(db: Any, user: dict) -> list[dict]:
    """The requester's manageable accounts as full row dicts (for the
    multiselect — owner/name labels). Same self-scoping as
    :func:`manageable_account_ids`; NOT an ``is_account_hipaa`` gate (gate on the
    access boundary per the 2026-06-06 use-vs-disclosure ruling)."""
    from email_triage.web.db import list_email_accounts
    return list_email_accounts(db, user_id=user["id"])


def is_manageable(account_id: Any, db: Any, user: dict) -> bool:
    """True iff ``account_id`` is in the requester's manageable set. The GATE
    predicate for the actuator handlers (used as
    ``if not is_manageable(aid, db, user): return <reject>``). Fail-closed: a
    non-numeric ``account_id`` is NOT manageable."""
    aid = parse_int_or_none(account_id)  # N-219c/14 R23: SSOT
    if aid is None:
        return False
    return aid in manageable_account_ids(db, user)


def filter_to_manageable(ids: Iterable[Any], db: Any, user: dict) -> list[int]:
    """Intersect a CLIENT-submitted id list with the manageable set → the
    authorized ``list[int]``. Fail-closed: any id not in the set (or non-numeric)
    is dropped. The §5 per-account auth intersection for client form/query ids."""
    manageable = manageable_account_ids(db, user)
    out: list[int] = []
    for raw in ids or ():
        aid = parse_int_or_none(raw)  # N-219c/8 R23: SSOT
        if aid is None:
            continue
        if aid in manageable:
            out.append(aid)
    return out


def intersect_ids(ids: Iterable[Any], manageable_set: set[int]) -> list[int]:
    """Pure intersect of ``ids`` with an ALREADY-BUILT manageable set (no DB hop)
    — for build-once-filter-many loops (e.g. scoping each Topic's saved ids to a
    single ``manageable_account_ids`` build) where calling
    :func:`filter_to_manageable` per item would re-query. Fail-closed (non-numeric
    dropped). The membership stays in this module so the pin has no carve-out."""
    out: list[int] = []
    for raw in ids or ():
        aid = parse_int_or_none(raw)  # N-219c/8 R23: SSOT
        if aid is None:
            continue
        if aid in manageable_set:
            out.append(aid)
    return out


def is_account_owner(account: Any, requester_id: Any) -> bool:
    """STRICT account ownership — True iff ``account``'s owner (its ``user_id``) IS
    the requester. The account-domain twin of
    ``_resource_authz.can_modify_owned_resource`` with ``admin_bypass=False``: NO
    admin override and NO delegate fold (those are the manageable-set / can_manage
    concerns above) — purely "is this requester the data subject who owns this
    mailbox?". Delegates to the one ownership predicate, so it is int-coerced AND
    fail-closed (None / uncoercible owner or requester → False) — a DB-string owner
    vs a session-int requester can't read as a different owner.

    Census run14 follow-up (the N-124 §3 account-ownership cluster): the ~7
    hand-rolled ``account.get("user_id") (==|!=) user["id"]`` gates — the HIPAA
    actor≠owner audit-emit gates, the data-subject knob opt-in, the admin-view
    display flag, the webhook-API owner branch — route through here instead of
    drifting in int-coercion / ``.get`` vs ``[]`` key access. Pinned by
    ``tests/test_resource_authz_ssot_pin.py`` (the owner-field-vs-requester
    detector): once a site calls this it no longer hand-rolls the comparison and
    leaves that pin's allow-list. A caller that ALSO accepts a delegate (webhook API)
    keeps its own ``is_account_delegate`` branch — this predicate is the OWNER leg."""
    from email_triage.web._resource_authz import can_modify_owned_resource
    owner_id = account.get("user_id") if hasattr(account, "get") else getattr(account, "user_id", None)
    return can_modify_owned_resource(owner_id, requester_id=requester_id, admin_bypass=False)


def same_owner(account_a: Any, account_b: Any) -> bool:
    """True iff two accounts share the SAME (non-None) owner — an OWNER-to-OWNER
    match, NOT a requester gate. For a surface that filters a list to accounts owned
    by the SAME user as a reference account (the calendar-surrogate picker: only the
    SOURCE account's owner's OTHER accounts may be a surrogate). Fail-closed if
    either owner is None/uncoercible (an orphan account matches nothing). Reuses
    :func:`is_account_owner` so int-coercion / fail-closed are identical. (Census
    run14 DA follow-up: passing one account's owner into the other's ``requester_id``
    was numerically right but OFF-LABEL — this names the owner-to-owner concept so a
    reader doesn't misread it as a session-requester gate.)"""
    owner_a = account_a.get("user_id") if hasattr(account_a, "get") else getattr(account_a, "user_id", None)
    return is_account_owner(account_b, owner_a)


def filter_to_manageable_accounts(
    ids: Iterable[Any], db: Any, user: dict,
) -> list[dict]:
    """Like :func:`filter_to_manageable` but returns the account ROW DICTS (for
    rendering owner/name labels), in the submitted order, for the manageable
    subset. One DB hop; fail-closed (unmanaged/non-numeric ids dropped)."""
    by_id = {int(a["id"]): a for a in manageable_accounts(db, user)}
    out: list[dict] = []
    for raw in ids or ():
        aid = parse_int_or_none(raw)  # N-219c/8 R23: SSOT
        if aid is None:
            continue
        a = by_id.get(aid)
        if a is not None:
            out.append(a)
    return out
