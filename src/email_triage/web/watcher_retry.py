"""Small consumer shim for the watcher per-message retry queue.

The durable backbone (table, schema migration, backoff helper,
queue helpers, sweeper) is built by R-A in parallel. This module
exists so the four watcher exception-handler sites in ``app.py``
have ONE call site each — keeping those `except Exception` blocks
small + reviewable + the auth-revoked branch consistent across
provider paths.

Resolution order at runtime:

1. ``email_triage.web.db.enqueue_retry`` — R-A's canonical helper.
   Called when the worktree has been merged. Signature:

       enqueue_retry(
           conn, *, account_id, provider_type, mailbox=None,
           uid=None, uidvalidity=None, gmail_msg_id=None,
           o365_msg_id=None, error_class, error_msg,
       ) -> int

   Returns the new row id; rows start in state='pending'.

2. ``email_triage.web.db.mark_retry_dead`` — R-A's helper for the
   auth-revoked / never-retry case. Signature:

       mark_retry_dead(conn, retry_id, *, reason) -> None

   Called immediately after ``enqueue_retry`` when the failure
   class is in the auth-revoked needle set.

3. **ImportError fallback**: if R-A's helpers are not on the import
   path (this worktree merged before R-A's), every public function
   here becomes a quiet no-op. The existing error-logging path in
   the watcher loops still fires, so the operator's journalctl
   trace is unchanged — the only thing missing is the durable
   retry row, which R-A's cherry-pick will restore on merge.

Auth-revoked detection mirrors ``_maybe_mark_auth_stale`` in
``web/app.py`` (see the needle list there) so the same messages
that flip an account to ``auth_stale`` also short-circuit the
retry queue. There's no value in queuing five retries of "the
refresh token is dead" — the operator has to re-auth before any
retry can succeed.
"""

from __future__ import annotations

import logging
from typing import Any

from email_triage._errfmt import fmt_exc


from email_triage.triage_logging import get_logger  # N-196b R21_4
_log = get_logger("email_triage.web.watcher_retry")  # N-196b R21_4


# Auth-revoked detection is the SSOT in ``web/_auth_revoked.py``. Before
# 2026-06-09 the needle list was duplicated here AND in
# ``web/app.py::_maybe_mark_auth_stale`` and the two had already DRIFTED (this
# never-retry copy carried OAuthRefreshFailed/IMAPAuthError and scanned the
# class name; the SET copy did not) — the divergence census surfaced it as
# finding #1. Re-export the SSOT under the historical private names so existing
# imports (and ``__all__``) keep working; these are thin aliases, not a copy.
from email_triage.web._auth_revoked import (  # noqa: E402
    AUTH_REVOKED_NEEDLES as _AUTH_REVOKED_NEEDLES,
    is_auth_revoked as _is_auth_revoked,
)


# Provider-type normalisation. Account records carry the
# ``gmail_api`` provider_type, but ``enqueue_retry`` (the v30 schema)
# only accepts the {imap, gmail, office365} addressing-tuple slugs.
# Without this map a Gmail push failure raised ``ValueError`` inside
# ``enqueue_retry``, got swallowed by the watcher's broad except, and
# NO retry row was ever created. Map account provider_type →
# the queue's provider_type slug here, at the single watcher-retry
# call site, so every ingestion path stays consistent.
_PROVIDER_TYPE_TO_QUEUE_SLUG: dict[str, str] = {
    "gmail_api": "gmail",
    "gmail": "gmail",
    "imap": "imap",
    "office365": "office365",
}


def enqueue_watcher_retry(
    db: Any,
    *,
    account_id: int,
    provider_type: str,
    mailbox: str | None = None,
    uid: str | int | None = None,
    uidvalidity: str | int | None = None,
    gmail_msg_id: str | None = None,
    o365_msg_id: str | None = None,
    error: BaseException,
    failure_kind: str | None = None,
) -> int | None:
    """Enqueue a retry row for a watcher per-message failure.

    Returns the new retry row id, or ``None`` when:

      * R-A's helpers aren't on the import path yet (ImportError
        fallback — see module docstring).
      * The DB write itself failed; we log + swallow so the watcher
        loop keeps running on the next message.

    When the error matches the auth-revoked needle list, the row
    is enqueued AND immediately marked dead with
    ``reason='auth_revoked'``. The enqueue still happens (vs. an
    early-return) so the operator gets a durable artefact in the
    admin retry-queue page showing what the watcher saw + when,
    with a clear "this won't retry — re-auth the account" label.

    ``provider_type`` is normalised through
    :data:`_PROVIDER_TYPE_TO_QUEUE_SLUG`, so an account whose
    ``provider_type`` is ``gmail_api`` produces a valid ``gmail``
    queue row instead of a swallowed ``ValueError``.

    ``failure_kind`` is passed straight through to
    :func:`email_triage.web.db.enqueue_retry` — ``'llm_unreachable'``
    for a classify-step LLM-backend failure, NULL for an ordinary
    per-message fetch/process failure.
    """
    error_class = type(error).__name__
    error_msg = fmt_exc(error)
    #  — map the account provider_type onto the queue slug.
    queue_provider_type = _PROVIDER_TYPE_TO_QUEUE_SLUG.get(
        str(provider_type).lower().strip(), str(provider_type),
    )

    try:
        from email_triage.web.db import (  # noqa: F401  # R-A's helper
            enqueue_retry,
        )
    except ImportError:
        # R-A's commit not yet cherry-picked. Quiet no-op — the
        # existing error-log line in the watcher already fired.
        return None

    try:
        retry_id = enqueue_retry(
            db,
            account_id=int(account_id),
            provider_type=queue_provider_type,
            mailbox=mailbox,
            uid=str(uid) if uid is not None else None,
            uidvalidity=(
                str(uidvalidity) if uidvalidity is not None else None
            ),
            gmail_msg_id=gmail_msg_id,
            o365_msg_id=o365_msg_id,
            error_class=error_class,
            error_msg=error_msg,
            failure_kind=failure_kind,
        )
    except Exception as exc:  # pragma: no cover - DB failure path
        _log.warning(
            "watcher_retry.enqueue: failed to write retry row",
            extra={"_extra": {
                "account_id": account_id,
                "provider_type": provider_type,
                "error_class": error_class,
                "enqueue_error": fmt_exc(exc),
            }},
        )
        return None

    if _is_auth_revoked(error_class, error_msg):
        try:
            from email_triage.web.db import (  # noqa: F401
                mark_retry_dead,
            )
            mark_retry_dead(db, retry_id, reason="auth_revoked")
        except ImportError as import_exc:
            # Same fallback as above — R-A not yet merged.
            _log.warning(
                "watcher_retry.mark_dead: mark_retry_dead unavailable; auth_revoked row left live",
                retry_id=retry_id,
                error=fmt_exc(import_exc),
            )
        except Exception as exc:  # pragma: no cover - DB failure
            _log.warning(
                "watcher_retry.mark_dead: failed for auth_revoked row",
                extra={"_extra": {
                    "retry_id": retry_id,
                    "error_class": error_class,
                    "mark_error": fmt_exc(exc),
                }},
            )

    return int(retry_id) if retry_id is not None else None


class WatchDeliveryFailed(Exception):
    """Synthetic exception used to enqueue a retry row when one or more
    live-path email-watch fires failed to deliver.

    The retry-queue row carries the exception's class + message in its
    ``last_error_*`` columns; using a distinct class makes the source
    of the retry obvious in ``/admin/retry-queue`` ("the message itself
    was fine, but escalation didn't deliver") versus the ordinary
    fetch/process exception lineage. The message text MUST be free of
    PHI — it is the failure count and nothing else.
    """


def enqueue_watch_delivery_retry(
    db: Any,
    *,
    account_id: int,
    provider_type: str,
    failed_count: int,
    total_count: int,
    mailbox: str | None = None,
    uid: str | int | None = None,
    uidvalidity: str | int | None = None,
    gmail_msg_id: str | None = None,
    o365_msg_id: str | None = None,
) -> int | None:
    """Enqueue a ``watcher_retry_queue`` row for a live-path message
    whose email-watch fire(s) did not deliver.

    Thin shim around :func:`enqueue_watcher_retry` that builds a
    :class:`WatchDeliveryFailed` synthetic exception (PHI-free body —
    the failure count and total only) and stamps
    ``failure_kind='watch_delivery_failure'`` so the row is
    distinguishable from ordinary fetch/process retries in operator
    surfaces. The drainer's existing LLM-breaker gate is keyed on
    ``failure_kind == 'llm_unreachable'`` only, so the new kind drains
    on every tick alongside NULL.

    The retry is safe to enqueue on every non-delivered fire because
    's ``watch_fire_idempotency`` table records only DELIVERED
    fires; the drainer's re-call of
    :func:`fire_watches_for_message` will skip the already-delivered
    watches on this message and re-attempt only the not-yet-delivered
    ones.

    Returns the new retry row id, or ``None`` on enqueue failure
    (matching :func:`enqueue_watcher_retry`'s contract — the caller's
    live-path log line already fired).
    """
    err = WatchDeliveryFailed(
        f"{failed_count} of {total_count} watch fire(s) did not deliver"
    )
    return enqueue_watcher_retry(
        db,
        account_id=account_id,
        provider_type=provider_type,
        mailbox=mailbox,
        uid=uid,
        uidvalidity=uidvalidity,
        gmail_msg_id=gmail_msg_id,
        o365_msg_id=o365_msg_id,
        error=err,
        failure_kind="watch_delivery_failure",
    )


__all__ = [
    "enqueue_watcher_retry",
    "enqueue_watch_delivery_retry",
    "WatchDeliveryFailed",
    "_is_auth_revoked",
    "_AUTH_REVOKED_NEEDLES",
]
