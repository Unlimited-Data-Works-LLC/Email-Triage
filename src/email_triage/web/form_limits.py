"""SSOT for the form-parser limit our large-paste routes need to raise.

Starlette 1.3.1 (CVE-2026-54283 fix) ENFORCES ``request.form()`` limits that
1.2.x silently ignored. Empirically against the installed 1.3.1 (verified with
TestClient, 2026-06-20):

* ``max_part_size`` (default 1 MiB) is enforced **per field**, urlencoded AND
  multipart — a single field larger than 1 MiB now hard-400s.
* ``max_fields`` (default 1000) is **NOT** enforced for urlencoded field count
  (30 000 small urlencoded fields parse fine); it bounds multipart *parts*.
  ``max_part_size`` is per-field, not total-body (30 000 fields totalling
  ~1.3 MiB parse fine). So our many-small-field forms (folder include/exclude,
  bulk message-id apply, folder-scope selection) are NOT affected and keep the
  tight Starlette defaults.

The ONLY route that legitimately carries a single field over 1 MiB is the
"paste a raw email" classify box (a large HTML email with inline base64 images).
``parse_form`` raises ``max_part_size`` to a GENEROUS-but-still-BOUNDED 32 MiB
for that route — it preserves the per-field DoS bound the CVE added, it just
stops rejecting a legitimately-large pasted message. It also raises ``max_fields``
defensively (harmless: a no-op for our urlencoded forms, a safety margin for any
future large *multipart* route).

Use ``parse_form(request)`` instead of ``request.form()`` ONLY on a route whose
form can carry a single >1 MiB field; leave the tight Starlette defaults
everywhere else.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover
    from starlette.datastructures import FormData
    from starlette.requests import Request

# A large pasted HTML email with inline base64 images; bounded against the
# single-field memory-exhaustion DoS CVE-2026-54283 added the limit for.
FORM_MAX_PART_SIZE = 32 * 1024 * 1024  # 32 MiB
# Defensive headroom for any future large-multipart route (no-op for our
# urlencoded forms, where field count isn't enforced anyway).
FORM_MAX_FIELDS = 50_000
# We never accept more than one uploaded file on any route — keep tight.
FORM_MAX_FILES = 1_000


async def parse_form(
    request: "Request",
    *,
    max_part_size: int = FORM_MAX_PART_SIZE,
    max_fields: int = FORM_MAX_FIELDS,
    max_files: int = FORM_MAX_FILES,
) -> "FormData":
    """``request.form()`` with a raised per-field size cap (see module doc)."""
    return await request.form(
        max_files=max_files,
        max_fields=max_fields,
        max_part_size=max_part_size,
    )
