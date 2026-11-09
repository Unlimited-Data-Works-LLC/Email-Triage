"""Last-real-event store + read gate for the wizard's "My last real event" preview (punch 414).

Spec: ``spec_webhook_preview_live_event_mode_2026-07-15``. Two halves of ONE
contract, both here so neither can drift from the other (PD#5):

* **The belt** (:meth:`LastEnvelopeStore.record_fire`) -- the ONLY writer. It
  stores an envelope only for a fire whose ``is_hipaa`` is exactly ``False``, so
  a HIPAA-flagged fire never reaches the store at all.
* **The suspenders** (:func:`live_refusal_reason`) -- the read gate the preview
  endpoint runs on every live render, so a flag change AFTER a non-HIPAA fire
  cannot leak the older envelope.

PD#11 note: the store holds envelopes (``sender`` / ``subject`` for a
standard-mode notification), so it is a data store. It is in-memory only. The
spec's optional Redis backend is NOT built: the classification-cache Redis path
stores cleartext JSON and there is no encryption-aware Redis path to reuse.
Nothing is persisted, so no table, no migration and no key to inherit.
"""

from __future__ import annotations

import copy
import hashlib
import threading
from typing import Any

from email_triage._int_utils import parse_int_or_none


def webhook_target_identity(target: Any) -> str:
    """A stable identity for one webhook target: a digest of its URL plus its
    ``account_id`` scope. The store keeps the digest, never the URL (a webhook
    URL can carry a bearer token in its path).

    The ONE definition, used by the writer (fire time) and the reader (preview
    time) so the two cannot disagree about what "the same target" means (PD#5).
    """
    url = str(getattr(target, "url", "") or "")
    scope = str(getattr(target, "account_id", "") or "")
    return hashlib.sha256(f"{url}\x00{scope}".encode("utf-8")).hexdigest()


class LastEnvelopeStore:
    """LAST-1 envelope per webhook target (never a history), in process memory.

    Keyed by the target's position in the dispatcher's target list. Each entry
    also records, AT FIRE TIME, the target's ``account_id`` scope, the fire's own
    context ``account_id`` and the target's identity
    (:func:`webhook_target_identity`). The read gate checks the scopes the
    envelope was actually stored under, not only the scope the config carries
    now, and refuses an entry whose target is no longer the configured one
    (punch 414, PD#9).
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._by_target: dict[int, dict[str, Any]] = {}

    def record_fire(
        self,
        target_key: int,
        envelope: dict[str, Any],
        *,
        is_hipaa: bool,
        account_id: str | None,
        fire_account_id: str | None = None,
        target_identity: str | None = None,
    ) -> bool:
        """Store ``envelope`` as the target's last event. Returns whether it was stored.

        ``account_id`` is the TARGET's scope; ``fire_account_id`` is the account
        the fire itself carried (``EventDispatcher.fire(account_id=...)``). They
        are equal for a scoped target and differ for a wildcard one, which is
        why the gate needs both. Fail CLOSED (PD#8): anything other than the
        literal ``False`` for ``is_hipaa`` is refused, so a truthy or ``None``
        flag never stores.
        """
        if is_hipaa is not False:
            return False
        entry = {
            "envelope": copy.deepcopy(envelope),
            "account_id": account_id or None,
            "fire_account_id": fire_account_id or None,
            "target_identity": target_identity or None,
        }
        with self._lock:
            self._by_target[target_key] = entry
        return True

    def last_fire(self, target_key: int) -> dict[str, Any] | None:
        """A copy of the target's last entry (``envelope`` + the scopes and identity
        it was stored under), or ``None``."""
        with self._lock:
            entry = self._by_target.get(target_key)
            return copy.deepcopy(entry) if entry is not None else None

    def clear(self) -> None:
        """Forget every stored envelope. Called when the target list changes, so
        a position reused by a different target never shows the old one's event."""
        with self._lock:
            self._by_target.clear()


def _check_account(db: Any, user: dict, account_id: Any) -> str | None:
    """Refusal text for one account id, or ``None`` when live mode may use it."""
    from email_triage.db.accounts import get_email_account
    from email_triage.triage_logging import account_hipaa_effective
    from email_triage.web.account_scope import is_manageable

    aid = parse_int_or_none(account_id)
    if aid is None:
        return "this target's account scope is not a valid account id"
    row = get_email_account(db, aid)
    if row is None:
        return "this target's account could not be found"
    # PD#9: a client- or config-supplied account id is intersected with the
    # requester's manageable set (owner + delegate, no admin bypass) BEFORE the
    # envelope is shown. Direction of failure: closed.
    if not is_manageable(aid, db, user):
        return "this target is scoped to an account you do not manage"
    if account_hipaa_effective(account=row):
        return "one or more of this target's accounts is HIPAA-flagged"
    return None


def live_refusal_reason(
    db: Any,
    user: dict,
    scopes: list[str | None],
    envelope: dict[str, Any] | None = None,
    *,
    fire_account_id: Any = None,
    stored_target: str | None = None,
    current_target: str | None = None,
) -> str | None:
    """Why live mode must be refused for these target scopes, or ``None`` to allow it.

    ``scopes`` are every ``account_id`` scope the request touches (the scope
    stored with the envelope, the saved target's, and the one the wizard form
    carries); the strictest wins. A scope that is empty is a wildcard: the target
    could receive a fire from any account, so EVERY account on the install is
    checked for HIPAA. ``envelope`` is the stored envelope; when its
    ``data.account_id`` is present that account is checked too, so a wildcard
    target never shows an account the requester does not manage.

    ``fire_account_id`` is the account the stored fire itself carried (punch 414,
    PD#9). The emitter chooses ``data``, so the envelope's own ``account_id`` is
    not a bound anyone enforces; the fire's context account is. When it is
    present it is checked like any other scope. A wildcard target whose fire
    names no account anywhere (neither here nor in ``data``) is unbounded: it is
    shown only to a requester who manages EVERY account on the install.

    ``stored_target`` / ``current_target`` are the :func:`webhook_target_identity`
    digests of the target the envelope was stored under and of the one configured
    now. A mismatch means the position was reused by a different target (a
    reorder, a save): the stored event is not this target's, so it is refused.

    Sync (it reads the DB): run it through ``db_call``.
    """
    from email_triage.db.accounts import list_email_accounts
    from email_triage.triage_logging import account_hipaa_effective
    from email_triage.web.account_scope import is_manageable

    if stored_target != current_target:
        return "the stored event was fired for a different target than the one configured now"
    ids: list[Any] = []
    wildcard = False
    for scope in scopes:
        text = str(scope).strip() if scope is not None else ""
        if text:
            ids.append(text)
        else:
            wildcard = True
    account_named = False
    fire_text = str(fire_account_id).strip() if fire_account_id is not None else ""
    if fire_text:
        ids.append(fire_text)
        account_named = True
    data = (envelope or {}).get("data")
    if isinstance(data, dict) and data.get("account_id") not in (None, ""):
        ids.append(data["account_id"])
        account_named = True
    for account_id in ids:
        reason = _check_account(db, user, account_id)
        if reason:
            return reason
    if wildcard:
        rows = list_email_accounts(db)
        for row in rows:
            if account_hipaa_effective(account=row):
                return "one or more of this target's accounts is HIPAA-flagged"
        if not account_named:
            for row in rows:
                if not is_manageable(row["id"], db, user):
                    return (
                        "this target can receive a fire from any account and the stored "
                        "event names none, so it is shown only to a requester who manages "
                        "every account"
                    )
    return None
