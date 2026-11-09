"""Single source of truth for credential / secret writes from web forms.

Root cause of the 2026-06-08 OAuth-clobber incident
----------------------------------------------------
Save handlers inferred *write-intent* from the **presence of a value in a
form field**. On a bundled multi-setting form (e.g. ``/admin/integrations``)
that value is not under the operator's sole control:

  * a blank ``type=password`` field is an autofill magnet — a browser
    password-manager silently fills it with a saved *login* password, so the
    ``if posted:`` guard (which only blocks the *empty* case) lets a wrong
    value overwrite a real secret; and
  * a pre-filled ``type=text`` id, written **unconditionally**, is destroyed
    when the field is cleared (or overwritten in the username slot a manager
    targets) and the empty value is written back.

Saving one unrelated setting (the SearXNG URL) thereby blanked
``GOOGLE_OAUTH_WEB_CLIENT_ID`` and overwrote the Google + O365 client
secrets — silently, with no read-back, no audit row, no UI signal — and all
Gmail/O365 auth died install-wide.

The contract this module enforces
---------------------------------
*Intent must be declared, never inferred from a value the browser can set.*

  * ``set_secret_if_changed`` — write a secret ONLY on a non-blank (and,
    where a stable format exists, *valid*) value. Blank preserves the stored
    value; an invalid value is **rejected and surfaced**, never silently
    dropped and never written.
  * ``set_id_preserve_blank`` — a plaintext id/tenant: blank PRESERVES the
    stored value (no more unconditional clobber). Returns the effective
    value so the caller can mirror it into the in-memory config.
  * ``clear_secret`` — the ONLY way to zero a stored secret/id is an
    explicit, declared clear (a dedicated control), never a blank submit.

Every credential/secret write in a web POST handler MUST route through these
helpers — they are the one place ``secrets.set(...)`` for a form-sourced
value is allowed. ``tests/test_no_unguarded_secret_write.py`` fails CI on any
handler that writes a form-derived value to the secrets store directly
(including values passed through a ``db_call(helper, ...)`` threadpool hop —
the guard is interprocedural), so the clobber class cannot silently return.

The template side is the companion defense: credential inputs render via the
``m.cred_input`` / ``m.secret_input`` macros (``_macros.html``), which add
``autocomplete="new-password"`` + ``readonly``-until-focus so a password
manager cannot populate the field at page load in the first place. For
no-validator secrets (O365 client secret, ACME TSIG, IMAP app-password) that
readonly layer is the *primary* autofill block — blank-preserve alone does
not stop an autofilled (non-blank) value, so both layers are required.
"""

from __future__ import annotations

import logging
from typing import Callable

__all__ = [
    "set_secret_if_changed",
    "set_id_preserve_blank",
    "clear_secret",
    "GOOGLE_SECRET_PREFIX",
    "looks_like_google_secret",
    "WRITTEN",
    "PRESERVED",
    "REJECTED",
]

from email_triage.triage_logging import get_logger  # N-196b R21_4
_log = get_logger("email_triage.web.secret_write")  # N-196b R21_4


# Google OAuth client secrets have carried this stable prefix since 2021.
GOOGLE_SECRET_PREFIX = "GOCSPX-"


def looks_like_google_secret(value: str) -> bool:
    """Cheap format guard for a Google OAuth *client secret*.

    A real Google client secret starts with ``GOCSPX-``; the 2026-06-08
    clobber value was an autofilled login password, which does not. Used as
    the ``validate`` argument on the Google secret fields only — O365 and
    TSIG secrets have no comparably-stable prefix, so they rely on the
    blank-preserve + readonly-until-focus layers instead of a format check.

    Deliberately permissive about everything after the prefix: we are
    rejecting an obviously-wrong autofill, not validating Google's full
    secret grammar (which could change and would then silently reject a
    *valid* secret — the very silent-failure mode we are removing).
    """
    return value.startswith(GOOGLE_SECRET_PREFIX)


WRITTEN = "written"
PRESERVED = "preserved"
REJECTED = "rejected"


def set_secret_if_changed(
    secrets,
    key: str,
    posted: str | None,
    *,
    validate: Callable[[str], bool] | None = None,
) -> str:
    """Persist a secret to the store ONLY on a non-blank, valid value.

    Args:
        secrets:  the ``DbSecrets`` wrapper (has ``.set(key, value)``).
        key:      secrets-store key.
        posted:   the raw form value (``form.get(field)``); may be ``None``.
        validate: optional predicate; if given and it returns ``False`` for
                  a non-blank value, the value is **rejected** (not written).

    Returns one of:
        * ``"preserved"`` — blank / whitespace-only submit: the stored value
          is kept, nothing written. This is what both a password-manager-
          blanked field and a deliberately-left-blank "leave blank to keep"
          field produce, so the two are indistinguishable and equally safe.
        * ``"rejected"``  — non-blank but ``validate`` failed: NOT written.
          The caller MUST surface this to the operator (a rejected write is
          never silent), and should NOT sync its in-memory config either.
        * ``"written"``   — value accepted and stored. The caller should
          mirror the value into the in-memory config so the change takes
          effect without a restart.
    """
    if posted is None or not posted.strip():
        # Blank → preserve. The whole point of the fix: never destroy a
        # stored secret because a field came across empty.
        return PRESERVED

    if validate is not None and not validate(posted):
        # Non-blank but wrong shape (e.g. an autofilled login password in a
        # Google secret field). Reject + let the caller surface it; do NOT
        # write, do NOT silently swallow.
        _log.warning(
            "secret_write_rejected: posted value failed format validation",
            extra={"_extra": {"key": key, "reason": "format"}},
        )
        return REJECTED

    secrets.set(key, posted)
    # §164.312(b) — a secret was actually overwritten. PHI-free: key name
    # only, never the value. Makes a clobber detectable in the audit trail.
    _log.info(
        "secret_overwritten",
        extra={"_extra": {"key": key}},
    )
    return WRITTEN


def set_id_preserve_blank(
    secrets,
    key: str,
    posted: str | None,
    current: str | None,
) -> str:
    """Write a plaintext id/tenant; a blank submit PRESERVES the stored value.

    On a blank/whitespace-only submit this writes **nothing** — the stored
    value is left exactly as-is — and returns ``current`` so the caller's
    ``config.x = set_id_preserve_blank(...)`` leaves the in-memory config
    unchanged too. (Deliberately does NOT write ``current`` back to the store
    on blank: if the in-memory config and the secrets store have diverged —
    which the 2026-06-08 incident shows can happen under a bug — writing the
    config value back would itself be a clobber. Never-write-on-blank is the
    only safe contract.)

    On a non-blank submit it writes the new value and returns it (for config
    sync). To intentionally clear an id, use a dedicated control that calls
    :func:`clear_secret` — never a blank submit.
    """
    posted = (posted or "").strip()
    if not posted:
        return current or ""
    secrets.set(key, posted)
    return posted


def clear_secret(secrets, key: str) -> None:
    """Explicit, declared clear of a stored secret/id (writes ``""``).

    The ONLY sanctioned way to zero a stored value — keeps "clear" an
    explicit operator action distinct from an accidental blank submit.
    """
    secrets.set(key, "")
    _log.info(
        "secret_cleared",
        extra={"_extra": {"key": key}},
    )
