"""Access-audit middleware).

Records every authenticated request that hits a PHI-touch route prefix
into the ``access_log`` table. Captures route + method + status +
actor + (when extractable) account_id + message_id from the URL path.
No PHI is persisted.

The route allowlist is intentional: every entry processes mail content
in some form, so an auditor reviewing the table can answer "who looked
at this account / message, and when?" without sampling the full
request stream. Routes that do not touch PHI (login, dashboard,
/health, /static, /logs admin) are excluded so the table doesn't fill
with noise.
"""

from __future__ import annotations

import asyncio
import logging
import os
import re

from email_triage._envbool import env_bool
from email_triage._int_utils import parse_int_or_none  # N-219b R23
import uuid
from typing import Any

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from email_triage.triage_logging import request_id_var
# .2: cache the record helper + db_call wrapper at module load. The
# previous middleware lazy-imported on every PHI request, which is both
# a lookup tax (~1.5µs * thousands of requests) and a foot-gun (the
# audit write happened to share an import path with anything that
# tweaked the function later).
from email_triage.web.db import record_access_event as _record_access_event
from email_triage.web.db_threadpool import db_call as _db_call
# run18 #2 — the production access_log emit routes through the audit-write SSOT
# (best-effort: run it, never raise, log a uniform ``audit_write_failed``
# WARNING visible to /health's drift counter). Module-top import mirrors the
# .2 rationale for ``_record_access_event`` (avoid the per-request lazy
# lookup tax); ``web._audit`` only depends on ``triage_logging`` (no cycle).
from email_triage.web._audit import safe_audit_write_async


from email_triage.triage_logging import get_logger  # N-196b R21_4
_log = get_logger("email_triage.web.access_audit")  # N-196b R21_4


# Path prefixes that touch mail content. Order matters only for
# readability — every prefix is checked against the inbound path with
# str.startswith.
_PHI_ROUTE_PREFIXES: tuple[str, ...] = (
    "/classify",
    "/triage/run",
    "/runs/",
    #  — the external integration API moved /api/openclaw -> /api/v1. The
    # AUDITED request is the /api/v1 one (the legacy /api/openclaw path now only
    # serves a 308 redirect that touches no PHI), so the §164.312(b) PHI-route
    # classification keys on the new path.
    "/api/v1/accounts/",
    "/api/messages",
    "/discover",
)

# Account-scoped routes that touch mail. Compiled regex captures the
# numeric account_id so the audit row carries it.
_ACCOUNT_PATH_RE = re.compile(
    r"^/accounts/(?P<account_id>\d+)/(?P<rest>"
    r"messages|digest/(?:generate|run|edit|toggle|reschedule|schedule|schedules)"
    # N-172 + N-173 — the plural ``digests/<digest_id>/...`` mail-content
    # dry-runs were NOT covered by the singular ``digest/...`` alternatives
    # above (note PLURAL ``digests`` + the ``/<digest_id>/`` segment), so
    # ``_is_phi_path`` returned False and NO §164.312(b) access_log row fired
    # for ANY actor (even the owner). The three PHI-bearing members:
    #   • candidates (N-172) — "Show matches" dry-run lists matched
    #     sender + subject = PHI (accounts.py:digest_candidates).
    #   • preview (N-173) — renders the digest body via the SAME
    #     ``_render_digest_payload`` send-render path (gather→filter→render);
    #     the iframe srcdoc embeds matched sender/subject/body = PHI
    #     (accounts.py:digest_preview).
    #   • test-send (N-173) — runs the full ``_fire_one_digest`` path
    #     (gather→filter→render→SMTP); reads + discloses matched mail
    #     content (accounts.py:digest_test_send).
    # Scoped to those THREE only — the sibling digests/* subroutes
    # (new / new/edit / {id}/edit / save / delete / validate-query) are
    # config CRUD or query-syntax checks (validate-query returns only a
    # MATCH COUNT, no sender/subject/body), not mail-content reads, so they
    # stay out to avoid audit-table noise + over-matching the net.
    r"|digests/\d+/(?:candidates|preview|test-send)"
    r"|folders|discover|triage|test|bulk"
    r")(?P<tail>/[^?]*)?$"
)

# Sub-pattern for pulling a message id out of a path like
# /api/v1/accounts/3/messages/<message_id>/...
_MESSAGE_PATH_RE = re.compile(
    r"/messages/(?P<message_id>[^/?]+)"
)


def _extract_account_id(path: str) -> int | None:
    m = _ACCOUNT_PATH_RE.match(path)
    if m:
        return parse_int_or_none(m.group("account_id"))  # N-219b R23: SSOT
    # External integration API:
    # /api/v1/accounts/<id>/...
    m2 = re.match(r"^/api/v1/accounts/(\d+)/", path)
    if m2:
        return parse_int_or_none(m2.group(1))  # N-219b R23: SSOT
    return None


def _extract_message_id(path: str) -> str | None:
    m = _MESSAGE_PATH_RE.search(path)
    if m:
        mid = m.group("message_id")
        # Length cap so a malformed URL can't blow the column.
        return mid[:200] if mid else None
    return None


def _is_phi_path(path: str) -> bool:
    """True when the path matches a PHI-touch route the auditor cares about."""
    if any(path.startswith(p) for p in _PHI_ROUTE_PREFIXES):
        return True
    if _ACCOUNT_PATH_RE.match(path):
        return True
    return False


def _outcome_from_status(status_code: int) -> str:
    if status_code < 400:
        return "ok"
    if status_code in (401, 403):
        return "denied"
    if status_code == 404:
        return "not_found"
    return "error"


class RequestIdMiddleware(BaseHTTPMiddleware):
    """Inject a request_id into every inbound HTTP request.

    Sets ``request.state.request_id`` and the ``request_id_var``
    ContextVar (so structured-log lines emitted from any awaited code
    path carry the same ID without each call site passing it). Mirrors
    the ID back as the ``X-Request-ID`` response header so an external
    monitor / reverse proxy can correlate.

    Inbound ``X-Request-ID`` is honoured **only** when the request
    originates from a trusted reverse proxy. The check defers to a
    ``request.state.from_trusted_proxy`` flag that the deployment can
    set in a sibling middleware (e.g. CIDR allowlist of the local
    Caddy / nginx). When that flag is absent the header is ignored
    and we always mint our own ID — prevents external callers from
    poisoning audit logs with crafted IDs.
    """

    async def dispatch(self, request: Request, call_next):
        rid = ""
        if getattr(request.state, "from_trusted_proxy", False):
            rid = (request.headers.get("X-Request-ID") or "").strip()
            # Defensive: cap length, strip non-hex.
            if rid:
                rid = "".join(c for c in rid if c.isalnum() or c in "-_")[:64]
        if not rid:
            # N-244b R25: SSOT — `_ids.new_short_id("")` = bare hex tail.
            from email_triage._ids import new_short_id
            rid = new_short_id("")

        request.state.request_id = rid
        token = request_id_var.set(rid)
        try:
            response: Response = await call_next(request)
        finally:
            request_id_var.reset(token)
        # Mirror back so external observers can correlate.
        response.headers["X-Request-ID"] = rid
        return response


class AccessAuditMiddleware(BaseHTTPMiddleware):
    """ASGI middleware that records PHI-touch requests.

    Failure policy: in strict-audit mode
    (``EMAIL_TRIAGE_AUDIT_STRICT`` set), audit-write exceptions
    re-raise so the bug surfaces immediately. In production they're
    logged + counted on ``app.state.audit_failures`` so the operator
    can see drift via ``/health``. Never silent — the prior behaviour
    swallowed exceptions and made ``access_log`` un-trustable for
    HIPAA audit purposes.
    """

    async def dispatch(self, request: Request, call_next):
        response: Response = await call_next(request)

        try:
            path = request.url.path or ""
            if not _is_phi_path(path):
                return response

            # .2: prefer the auth-dependency-resolved user that the
            # route handler already populated on ``request.state.user``
            # (auth dependency on the route ran upstream of us in the
            # ASGI flow). Fall back to the same ``get_current_user``
            # helper UI routes use — covers middleware-only paths
            # (e.g. /api endpoints with bearer tokens but no FastAPI
            # dependency) and pre-existing tests that don't set
            # ``request.state.user``.
            actor_user_id: int | None = None
            cached_user = getattr(request.state, "user", None)
            if isinstance(cached_user, dict):
                actor_user_id = cached_user.get("id")
            else:
                try:
                    #  — ``get_current_user`` touches the shared
                    # ``app.state.db`` connection (``verify_api_key`` is
                    # @db_write, ``get_user_by_email`` is an undecorated
                    # reader). Running it inline here did the SQLite work
                    # ON the event-loop thread, which both freezes the
                    # loop for the query duration AND can collide with a
                    # concurrent ``db_call`` worker on the one shared
                    # connection. Dispatch it through ``db_call`` so the
                    # work runs off-loop under the process-wide DB lock.
                    from email_triage.web.dependencies import get_current_user
                    user = await _db_call(get_current_user, request)
                    if user is not None:
                        actor_user_id = user.get("id")
                except Exception:
                    pass

            db = getattr(request.app.state, "db", None)
            if db is None:
                return response

            request_id = getattr(request.state, "request_id", "") or None
            app_state = request.app.state

            # .2: fire-and-forget the audit write. The write MUST
            # still happen — we just don't make the client wait on it.
            # ``asyncio.create_task`` schedules the write on the loop;
            # ``db_call`` puts the actual SQLite work on the threadpool.
            # Failure handling lives in ``_audit_write`` so an exception
            # in the threadpool doesn't go to ``asyncio``'s default
            # task-exception handler (which only logs and discards).
            #
            # Strict-audit bypass: when EMAIL_TRIAGE_AUDIT_STRICT is
            # set, run the audit write synchronously so an exception
            # surfaces on the request response (operator debug aid
            # for audit-write regressions). Production keeps
            # fire-and-forget.
            if env_bool("EMAIL_TRIAGE_AUDIT_STRICT"):
                # _audit_write already re-raises in strict mode
                # (env-var check at end of the body). Awaiting
                # synchronously here surfaces the exception on the
                # request response.
                await _audit_write(
                    db=db,
                    app_state=app_state,
                    actor_user_id=actor_user_id,
                    method=request.method,
                    path=path,
                    status_code=response.status_code,
                    request_id=request_id,
                )
                return response
            task = asyncio.create_task(
                _audit_write(
                    db=db,
                    app_state=app_state,
                    actor_user_id=actor_user_id,
                    method=request.method,
                    path=path,
                    status_code=response.status_code,
                    request_id=request_id,
                )
            )
            # the backlog  F1 (DA + db-sme convergent) — attach a
            # done-callback that stashes ``task.exception()`` /
            # ``task.cancelled()`` unconditionally on the fire-and-
            # forget task. Closes the pre-await-cancel hole where the
            # ``except BaseException`` inside ``safe_audit_write_async``
            # never runs because the loop cancelled the coroutine
            # BEFORE it hit ``await awrite()``. Idempotent with the
            # inner stash — same class name lands on _LAST_AUDIT_EXC
            # either way, so the drain-race pin fires loud on every
            # task-end mode.
            from email_triage.web._audit import (
                attach_audit_done_callback,
            )
            # the backlog  (DA  F3 root-cause fix): pass the
            # optional test-side threading.Event so the drain helper
            # wakes on task completion instead of polling every 20ms.
            # Prod app never sets ``_audit_pending_signal``; the
            # callback is a no-op there. Test fixtures set it up at
            # TestClient app boot.
            _sig = getattr(app_state, "_audit_pending_signal", None)
            attach_audit_done_callback(task, "access_audit_middleware", signal=_sig)

            # Track on app.state so tests + a future graceful-shutdown
            # path can ``await`` outstanding writes. Weak ref via list
            # so completed tasks GC normally.
            pending = getattr(app_state, "_audit_pending", None)
            if pending is None:
                pending = set()
                app_state._audit_pending = pending
            pending.add(task)
            task.add_done_callback(pending.discard)

        except Exception as exc:
            # Synchronous-path failure (path inspection, user lookup,
            # task creation). Same surface-don't-silence policy as
            # before. The audit-write itself is now async, so its
            # failures land in ``_audit_write`` instead.
            # 2026-07-10 drain-race fix — stash for test observability
            # (see _audit._LAST_AUDIT_EXC docstring).
            from email_triage.web._audit import _stash_last_audit_exc
            _stash_last_audit_exc(exc, "access_audit:dispatch")
            state = request.app.state
            current = getattr(state, "audit_failures", 0)
            state.audit_failures = int(current) + 1
            _log.error(
                "access_audit failed",
                exc_info=exc,
                extra={
                    "_extra": {
                        "path": request.url.path,
                        "method": request.method,
                        "request_id": getattr(
                            request.state, "request_id", "",
                        ),
                    }
                },
            )
            if env_bool("EMAIL_TRIAGE_AUDIT_STRICT"):
                raise

        return response


async def _audit_write(
    *,
    db: Any,
    app_state: Any,
    actor_user_id: int | None,
    method: str,
    path: str,
    status_code: int,
    request_id: str | None,
) -> None:
    """Background coroutine that performs the access_log write.

    .2: split out from ``dispatch`` so failure handling lives
    inside the task — without this, a threadpool exception would land
    in asyncio's default task-exception handler (silent log + drop)
    instead of bumping ``audit_failures`` so /health can flip degraded.

    The write is fire-and-forget from the *request*'s perspective
    (response has already returned by the time this runs). It is NOT
    optional — the task will run to completion or it will be counted
    as an audit failure, never silently dropped.

    run18 #2 — the production emit converges onto the
    ``safe_audit_write_async`` SSOT (PD#5: collapse the divergent
    funnel; the audit-emit-swallow pin sees a routed emit, not a
    hand-rolled swallowing try/except). Strict mode keeps a BARE emit
    that re-raises the ORIGINAL exception: strict's purpose is to
    surface the failure verbatim on the request response (operator
    debug aid), which the never-raise SSOT cannot do. Both paths
    preserve the /health ``audit_failures`` counter bump.
    """
    if env_bool("EMAIL_TRIAGE_AUDIT_STRICT"):
        # Strict debug mode: NOT routed through the SSOT — we WANT the
        # original exception to surface (byte-equivalent to the prior
        # strict re-raise). Bump the counter, log with context, re-raise.
        try:
            await _db_call(
                _record_access_event,
                db,
                actor_user_id=actor_user_id,
                method=method,
                route=path,
                account_id=_extract_account_id(path),
                message_id=_extract_message_id(path),
                status_code=status_code,
                outcome=_outcome_from_status(status_code),
                request_id=request_id,
            )
        except Exception as exc:
            # 2026-07-10 drain-race defensive stash — even though this
            # handler re-raises (and the upstream `safe_audit_write_async`
            # swallow stashes on the way out), we stash HERE too so a
            # future refactor that shortens the propagation chain does
            # not re-open the invisible-swallow class. See
            # `_audit._LAST_AUDIT_EXC` + `feedback_fix_flaky_tests_dont_dismiss`.
            from email_triage.web._audit import _stash_last_audit_exc
            _stash_last_audit_exc(exc, "access_audit:_audit_write")
            current = getattr(app_state, "audit_failures", 0)
            app_state.audit_failures = int(current) + 1
            _log.error(
                "access_audit write failed",
                exc_info=exc,
                extra={
                    "_extra": {
                        "path": path,
                        "method": method,
                        "request_id": request_id or "",
                    }
                },
            )
            raise
        return

    # Production: route the best-effort emit through the SSOT (run it,
    # never raise, log a uniform ``audit_write_failed`` WARNING for
    # /health's drift counter). ``record_access_event`` returns the new
    # row id, so a ``None`` return is the SSOT's swallowed-failure signal
    # — preserve the access-audit /health counter bump on it.
    result = await safe_audit_write_async(
        lambda: _db_call(
            _record_access_event,
            db,
            actor_user_id=actor_user_id,
            method=method,
            route=path,
            account_id=_extract_account_id(path),
            message_id=_extract_message_id(path),
            status_code=status_code,
            outcome=_outcome_from_status(status_code),
            request_id=request_id,
        ),
        description=f"access_log {method} route={path} status={status_code}",
    )
    if result is None:
        current = getattr(app_state, "audit_failures", 0)
        app_state.audit_failures = int(current) + 1
