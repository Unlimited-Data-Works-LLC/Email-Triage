"""API error surfacing SSOT (R20_1 sub-class 4, N-179 scaffold).

Sibling of `_flash.py` — sub-class 4 covers JSON-returning + HTTPException-
raising handlers. Shares `_flash.scrub_exc` for exception→user-string
mapping (single scrubber SSOT — never duplicate the mapping logic).

Contract:
- `api_error_response(exc, *, status_code, purpose)` — return a JSONResponse
  with `{"error": scrubbed_msg}`. Never a raw exception string.
- `raise_api_error(exc, *, status_code, purpose)` — raise HTTPException with
  scrubbed detail. Callers `raise raise_api_error(...)`. (Not a bug — the
  helper returns the exception the caller raises; keeps the pin AST-visible.)

NOT DONE (next-window build): 126-site adoption (17 in this sub-class) +
3-arm pin + 3-SME + N-179 register row.
"""
from __future__ import annotations

from typing import Any

from fastapi import HTTPException
from fastapi.responses import JSONResponse

from email_triage.web._flash import scrub_exc


def api_error_response(exc: Exception | str, *, status_code: int = 400,
                       purpose: str = "misc",
                       extra: dict[str, Any] | None = None) -> JSONResponse:
    """JSON error surface: `{"error": <scrubbed>}` + optional extra keys."""
    body: dict[str, Any] = {"error": scrub_exc(exc, purpose=purpose)}
    if extra:
        # Callers must have scrubbed extras themselves; caveat lector.
        body.update(extra)
    return JSONResponse(status_code=status_code, content=body)


#: Punch 579: the fixed error slugs an ``access_log`` row may carry in its
#: ``detail``, so §164.308(a)(1)(ii)(D) review can find, for example, an
#: attempted cross-account watch bind (``account_id_must_match_path``) that
#: the ``outcome`` column records only as ``error``. A CLOSED set of
#: constants: a value that is not a member never reaches the row, so no
#: request data and no PHI can. ``tests/test_n579_api_error_slug_audit_pin.py``
#: holds it equal to every slug literal an HTTPException is raised with.
AUDITED_ERROR_SLUGS: frozenset[str] = frozenset({
    "account_id_must_match_path", "account_not_found", "bad_attendee_address", "bad_iso_datetime",
    "calendar_not_enabled", "calendar_not_supported", "calendar_scope_missing",
    "empty_partial", "empty_responses", "expected_json_object", "hipaa_blocked",
    "invalid_json", "mfa_required", "not_watch_creator",
    "notify_email_not_settable", "rate_limited", "validation_errors",
    "watch_creator_out_of_scope", "watch_unattributed",
})


def audited_error_slug(detail: Any) -> str | None:
    """The slug an HTTPException ``detail`` (a string, or a dict's ``error``)
    names, iff it is in :data:`AUDITED_ERROR_SLUGS`; None otherwise
    (fail-closed: a free-text or request-derived detail is never recorded)."""
    error = detail.get("error") if isinstance(detail, dict) else detail
    return error if isinstance(error, str) and error in AUDITED_ERROR_SLUGS else None


def stash_error_slug(request: Any, exc: Any) -> None:
    """Called by the app's HTTPException handler: put the audited slug of
    ``exc`` on ``request.state.error_slug`` for ``AccessAuditMiddleware``,
    which writes it into the request's ``access_log`` row (punch 579)."""
    slug = audited_error_slug(getattr(exc, "detail", None))
    if slug is not None:
        request.state.error_slug = slug


def raise_api_error(exc: Exception | str, *, status_code: int = 400,
                    purpose: str = "misc",
                    extra: dict[str, Any] | None = None) -> HTTPException:
    """Return an HTTPException with scrubbed detail. Caller writes
    ``raise raise_api_error(e, status_code=422, purpose='form')``.

     tranche 6 (2026-07-09) — the ``extra`` param mirrors
    :func:`api_error_response`'s ``extra`` so raise-side callers with a
    composite ``detail={"error": <slug>, "message": ...}`` shape can also
    route through the SSOT. When ``extra`` is set, ``detail`` becomes
    ``{"error": <scrubbed>, **extra}`` (a dict); when omitted, ``detail``
    stays the bare scrubbed string (behavior-preserving for existing
    callers). Callers must have scrubbed extras themselves; caveat lector.
    """
    scrubbed = scrub_exc(exc, purpose=purpose)
    if extra:
        detail: Any = {"error": scrubbed, **extra}
    else:
        detail = scrubbed
    return HTTPException(status_code=status_code, detail=detail)
