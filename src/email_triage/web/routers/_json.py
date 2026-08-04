"""N-233 R22 — JSON body parse-and-validate SSOT.

Census R22 discovered class (MED, live 500-on-malformed defect):
`await request.json()` in the 4 WebAuthn/passkey/MFA finish handlers
(auth_keys.py:760, 935, 1146, 1260) raised JSONDecodeError on a
malformed body — the exception propagated as HTTP 500 instead of the
client-facing 400 the WebAuthn browser API expects. A parallel Mode C
at `agent_api.py:2620` fail-open silently treated malformed as `{}`.

`parse_json_body(request, *, require_dict=True)` is the SSOT: parse the
body, raise `HTTPException(400, detail="invalid_json")` on decode
failure, raise `HTTPException(400, detail="expected_json_object")` on
non-dict when `require_dict=True`.
"""
from __future__ import annotations

import json
from typing import Any

from fastapi import HTTPException, Request


async def parse_json_body(
    request: Request, *, require_dict: bool = True,
) -> dict[str, Any] | list[Any] | Any:
    """SSOT for `await request.json()` in every handler.

    Raises `HTTPException(400)` — NEVER 500 — on:
      - JSONDecodeError (malformed body).
      - Non-dict body when `require_dict=True`.

    Returns the parsed body (a dict when `require_dict=True`, else any
    JSON-serializable value).
    """
    try:
        body = await request.json()
    except (json.JSONDecodeError, ValueError):
        # ValueError covers both stdlib JSONDecodeError (subclass) AND
        # any provider that raises the plain form.
        raise HTTPException(status_code=400, detail="invalid_json")
    if require_dict and not isinstance(body, dict):
        raise HTTPException(status_code=400, detail="expected_json_object")
    return body
