"""Classification-list RULE access SSOT (Loop-5 divergence census → N-60).

A ``power_user`` is scoped to their OWN personal lists + GLOBAL lists (README
roles section); they may NOT touch another user's PERSONAL list. But the
list-RULE gates (add / edit / delete / read a rule) bypassed on
``role in ("admin", "power_user")`` with NO ``is_global`` check — so a
power_user could add/edit/delete/read classification rules on ANY other user's
PERSONAL list. Classification rules drive PHI routing on a HIPAA system, so
that is a real horizontal privilege over-grant (§164.308(a)(4) access
management / §164.312(a)(1) access control). The single-rule READ gate (Phase 7
list-read) was scoped by ``is_global``; the rule gates never were.

This is the ONE place the rule-access decision is made. Every rule gate routes
through it; the count-agnostic pin forbids an inline ``owner_id`` + role gate on
``classification_lists`` outside this module.

FOUR DISTINCT GATES (do not confuse them):
  * :func:`is_list_writable_by` — add / edit / delete / **READ a RULE** on a list
    (rule-level; power_user scoped to global lists). Rule-READ keeps THIS scope.
  * :func:`is_list_readable_by` — READ the LIST itself (list-level metadata / that
    it exists); LOOSER — a global list is public-read for everyone.
  * :func:`is_list_deletable_by` — DELETE the whole LIST (owner|admin only;
    STRICTER — a power_user may mutate global rules but not destroy the list).
  * :func:`may_manage_global_lists` — CREATE / manage a GLOBAL list (and view the
    global-rules page); a ROLE-only decision (no ``list_row`` exists at create
    time); ``admin`` | ``power_user`` (census run17 #2 D2 — was inlined across
    three routers).
"""

from __future__ import annotations

from typing import Any, Mapping


def is_list_writable_by(
    list_row: Mapping[str, Any], *, user_id: int, role: str | None,
) -> bool:
    """May ``user`` add / edit / delete / read RULES on this classification list?

    * **OWNER** → always.
    * **ADMIN** → always.
    * **POWER_USER** → ONLY when the list ``is_global`` (README scope =
      own-personal + global; NEVER another user's personal list).
    * everyone else → only if owner (covered above).

    ``list_row`` must carry ``owner_id`` + ``is_global`` (every rule-gate SELECT
    includes both). Fail-CLOSED: a missing/unrecognised role, or a missing
    ``is_global`` for a non-owner, resolves to ``False`` (refuse).
    """
    # NB: a real ``sqlite3.Row`` raises ``IndexError`` (not ``KeyError``) on a
    # missing column, so the fail-closed guard MUST catch IndexError too — db-sme
    # C1 on N-60. A dict raises KeyError. Both → refuse (fail-closed).
    try:
        if list_row["owner_id"] == user_id:
            return True
    except (KeyError, IndexError, TypeError):
        return False
    if role == "admin":
        return True
    if role == "power_user":
        try:
            return bool(list_row["is_global"])
        except (KeyError, IndexError, TypeError):  # pragma: no cover - fail-closed
            return False
    return False


def _owner_match(list_row: Mapping[str, Any], user_id: int) -> bool:
    """Fail-CLOSED owner check. A real ``sqlite3.Row`` raises ``IndexError`` (a
    dict ``KeyError``) on a missing column — both → False (refuse), never raise."""
    try:
        return list_row["owner_id"] == user_id
    except (KeyError, IndexError, TypeError):
        return False


def is_list_readable_by(
    list_row: Mapping[str, Any], *, user_id: int, role: str | None,
) -> bool:
    """May ``user`` READ this classification list?  (census run15 #2 — the READ
    twin of :func:`is_list_writable_by`.)

    * **OWNER** → always.   * **ADMIN** → always.
    * a **GLOBAL** list → readable by ANYONE (global lists are install-shared
      reference data, not another user's private rules).
    * everyone else → no.

    READ is LOOSER on the ``is_global`` axis than WRITE: a global list is
    public-read for *everyone*, where WRITE only lets a power_user mutate a global
    list. Fail-CLOSED on a missing ``owner_id``/``is_global`` for a non-owner.

    NB: this gates reading the LIST (its existence/metadata). Reading its RULES
    keeps the tighter :func:`is_list_writable_by` scope (power_user-global), NOT
    this — do not swap them (DA review of run15 #2).
    """
    if _owner_match(list_row, user_id):
        return True
    if role == "admin":
        return True
    try:
        return bool(list_row["is_global"])
    except (KeyError, IndexError, TypeError):
        return False


def is_list_deletable_by(
    list_row: Mapping[str, Any], *, user_id: int, role: str | None,
) -> bool:
    """May ``user`` DELETE this classification LIST (the whole list, not a rule)?
    (census run15 #2.)

    STRICTER than :func:`is_list_writable_by`: only the **OWNER** or an **ADMIN**.
    A power_user may add/edit/delete RULES on a global list (``is_list_writable_by``)
    but may NOT delete the global list itself — destroying install-shared reference
    data is an owner/admin-only act. Behaviour-preserving for the two inline
    delete-list gates this converges (both were ``owner_id != user and not admin``).
    Fail-CLOSED on a missing ``owner_id``.
    """
    if _owner_match(list_row, user_id):
        return True
    return role == "admin"


def may_manage_global_lists(role: str | None) -> bool:
    """May this ROLE create / manage a GLOBAL classification list (and view the
    global-rules page)?  (census run17 #2 D2 — the create-global role decision,
    previously inlined as ``role in ("admin", "power_user")`` across three
    routers; PD#5 duplication.)

    The ROLE-only twin of the row-level gates above: there is no ``list_row`` at
    create time, so the decision is purely the caller's role. A power_user is
    scoped to own-personal + GLOBAL lists, so both ``admin`` and ``power_user``
    may manage global lists; everyone else may not. Fail-CLOSED: a missing /
    unrecognised role (incl. ``None``) → ``False`` (refuse). Behaviour-identical
    to the three inline ``role in ("admin", "power_user")`` tests it converges.
    """
    return role in ("admin", "power_user")
