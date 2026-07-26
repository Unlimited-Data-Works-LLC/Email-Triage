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
