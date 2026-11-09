"""SSOT for the form-parser limits our large-paste and many-field routes need to raise.

Starlette 1.3.1 (CVE-2026-54283 fix) ENFORCES ``request.form()`` limits that
1.2.x silently ignored. RE-MEASURED 2026-10-30 (punch 443) against the locked
Starlette 1.6.0 + python-multipart 0.0.32 with TestClient, and re-measured on
every test run by ``tests/test_form_limits_measured_pin.py``:

* ``max_part_size`` (default 1 MiB) is enforced **per field**, urlencoded AND
  multipart — a single field larger than 1 MiB hard-400s.
* ``max_fields`` (default 1000) is enforced for **urlencoded field count AND
  multipart parts**: 30 000 small urlencoded fields hard-400 ("Too many
  fields"). ``max_part_size`` is per-field, not total-body. CORRECTION: this
  module used to say urlencoded field count was NOT enforced (1.3.1, 2026-06-20).
  The 2026-10-30 rig also 400s 30 000 urlencoded fields on 1.3.1 with
  python-multipart 0.0.31, so that reading was wrong or came from an older
  python-multipart; do not rely on it.

Also measured (punch 443, class P4, on 1.3.1 and 1.6.0): ``max_files`` (default 1000)
is enforced on multipart FILE parts; the 1 MiB ``max_part_size`` applies to every
multipart NON-file part and not to a file part (it spools); and the three defaults
are read from ``Request.form``'s signature by the same test.

So a form that can post MORE than 1000 name/value pairs needs ``parse_form``.
The folder include/exclude form (``accounts_folder_prefs_save``) posts two
fields per folder (a hidden ``all_folders`` plus a checked ``included``), so a
mailbox with about 500 folders hit the default cap. That route calls
``parse_form`` with an 8 KiB per-field cap
(``FORM_FOLDER_PATH_MAX_PART_SIZE``): the field COUNT is raised, and the size of
each field is held far below Starlette's 1 MiB default, so the body stays bounded.

The ONLY route that legitimately carries a single field over 1 MiB is the
"paste a raw email" classify box (a large HTML email with inline base64 images).
``parse_form`` raises ``max_part_size`` to a GENEROUS-but-still-BOUNDED 32 MiB
for that route — it preserves the per-field DoS bound the CVE added, it just
stops rejecting a legitimately-large pasted message. It also raises ``max_fields``
to a bounded 50 000 (60 000 fields still 400).

Use ``parse_form(request)`` instead of ``request.form()`` ONLY on a route whose
form can carry a single >1 MiB field or more than 1000 fields; leave the tight
Starlette defaults everywhere else.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover
    from starlette.datastructures import FormData
    from starlette.requests import Request

# A large pasted HTML email with inline base64 images; bounded against the
# single-field memory-exhaustion DoS CVE-2026-54283 added the limit for.
FORM_MAX_PART_SIZE = 32 * 1024 * 1024  # 32 MiB
# Bounded field-count headroom: the folder include/exclude form posts two
# fields per folder, and Starlette enforces the count for urlencoded forms too.
FORM_MAX_FIELDS = 50_000
# Starlette's own per-field default, for a many-field route that must NOT
# loosen the per-field DoS bound the CVE added.
FORM_DEFAULT_MAX_PART_SIZE = 1024 * 1024  # 1 MiB
# The folder include/exclude form posts one short IMAP mailbox name per field. With
# the field count raised to FORM_MAX_FIELDS, a 1 MiB per-field cap would allow
# 50 000 x 1 MiB (punch 443 db-sme S1 / hipaa-sme SHOULD-4); 8 KiB per field is
# far above any real folder path and bounds the body at 50 000 x 8 KiB.
FORM_FOLDER_PATH_MAX_PART_SIZE = 8 * 1024  # 8 KiB
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
