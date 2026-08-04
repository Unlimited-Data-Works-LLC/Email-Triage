"""Resource-ownership authorization SSOT (divergence census run14 #2).

A user may modify/delete a RESOURCE they own — a saved Topic, an API key, a
personal category, etc. The ownership decision was hand-rolled inline at ~14
sites as ``int(topic.user_id) != int(user["id"])`` (owner-only) or
``row["owner_id"] != user["id"] and role != "admin"`` (owner-or-admin), with no
SSOT. That is the N-60 shape — a horizontal-privilege gate replicated per
handler that drifts into an over-grant the moment one copy is written wrong (or
a new handler copies a stale variant). Classification-list RULE access has its
own SSOT (:func:`email_triage.web._list_authz.is_list_writable_by`, with the
``is_global`` power-user carve-out); account-scope has ``can_manage_account`` /
``web.account_scope``. THIS is the third, simplest gate: "is the requester the
owner (or, where the policy allows, an admin)?".

``can_modify_owned_resource`` is the ONE place that decision is made. The
count-agnostic pin (``tests/test_resource_authz_ssot_pin.py``) forbids the inline
owner-vs-requester comparison shape outside this module.

POLICY NOTE — the ``admin_bypass`` axis is load-bearing and DIFFERS per resource:
* **owner-only** (``admin_bypass=False``): Topics (a user's own saved search —
  an admin has no business silently editing it) and regulatory-clock anchors
  (a write-once legal anchor, no admin override by design).
* **owner-or-admin** (``admin_bypass=True``, the default): API keys, personal
  categories — an admin may administer them.
Passing the wrong ``admin_bypass`` is a policy change, not a refactor — keep each
call site's value explicit.
"""

from __future__ import annotations

from typing import Any

from email_triage._int_utils import parse_int_or_none  # N-219c/15 R23


def can_modify_owned_resource(
    owner_id: Any,
    *,
    requester_id: Any,
    role: str | None = None,
    admin_bypass: bool = True,
) -> bool:
    """May ``requester_id`` modify/delete a resource owned by ``owner_id``?

    * **OWNER** (``owner_id == requester_id``) → always.
    * **ADMIN** → only when ``admin_bypass`` (the per-resource policy axis).
    * everyone else → no.

    The caller extracts ``owner_id`` from whatever shape the resource is —
    ``topic.user_id`` (an object attr), ``row["owner_id"]`` / ``row["user_id"]``
    (a Mapping/``sqlite3.Row``) — so this SSOT is shape-agnostic. Both ids are
    coerced to ``int`` (handlers compare ``int(topic.user_id) != int(user["id"])``;
    a str-vs-int DB/session mismatch must NOT read as "different owner" → privilege
    bug). **Fail-CLOSED:** a ``None`` / non-coercible ``owner_id`` or
    ``requester_id`` resolves to ``False`` (refuse), never an exception or an
    accidental match.
    """
    if admin_bypass and role == "admin":
        return True
    # N-219c/15 R23: parse_int_or_none SSOT; both must parse + be equal.
    _oi = parse_int_or_none(owner_id)
    _ri = parse_int_or_none(requester_id)
    return _oi is not None and _ri is not None and _oi == _ri
