"""Small consumer shim for the watcher per-message retry queue (#175).

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


_log = logging.getLogger("email_triage.web.watcher_retry")


# String-match needle list for auth-revoked detection. Mirrors the
# needles in ``web/app.py::_maybe_mark_auth_stale`` so the two
# auth-failure surfaces agree on what counts as "no point retrying".
_AUTH_REVOKED_NEEDLES: tuple[str, ...] = (
    "Token has been expired or revoked",
    "invalid_grant",
    "AUTHENTICATIONFAILED",
    "InvalidAuthenticationToken",
    "Invalid Credentials",
    "OAuthRefreshFailed",
    "IMAPAuthError",
)


def _is_auth_revoked(error_class: str, error_msg: str) -> bool:
    """Return True when the error is auth-revoked (never-retry).

    Both ``error_class`` (the exception class name) and ``error_msg``
    (str(exc) text) get scanned. We match on substrings to catch
    both the bare exception class name and the wrapped/formatted
    error string that bubbles out of Google / Microsoft / Dovecot.
    """
    for needle in _AUTH_REVOKED_NEEDLES:
        if needle in error_class or needle in error_msg:
            return True
    return False


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
    """
    error_class = type(error).__name__
    error_msg = fmt_exc(error)

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
            provider_type=str(provider_type),
            mailbox=mailbox,
            uid=str(uid) if uid is not None else None,
            uidvalidity=(
                str(uidvalidity) if uidvalidity is not None else None
            ),
            gmail_msg_id=gmail_msg_id,
            o365_msg_id=o365_msg_id,
            error_class=error_class,
            error_msg=error_msg,
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
        except ImportError:
            # Same fallback as above — R-A not yet merged.
            pass
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


__all__ = [
    "enqueue_watcher_retry",
    "_is_auth_revoked",
    "_AUTH_REVOKED_NEEDLES",
]
