"""N-231 R22 — stored-secret KEY-NAME literal SSOT (2026-07-02).

Census R22 discovered class (MED, sub-class of secret-read): key-name
literals `"SMTP_PASSWORD"`, `"session_secret"`, `"acme_account_key"` were
in-lined across 20+ sites. A rename or a case-mismatch (say `"smtp_
password"`) would decouple a WRITER from a READER silently — the read
returns None, the write clobbers into the wrong slot, and there is no
error until the credential is actually needed.

Route every read AND write of a stored secret through THIS module's
constant. A typo becomes an AttributeError at import time instead of a
silent runtime miss.
"""
from __future__ import annotations


# SMTP relay password for outgoing digest / escalation mail (see
# `actions/escalate.py` / `web/smtp_send.py`). Read on demand; blank
# means SMTP is not configured (the sender refuses fail-open).
SMTP_PASSWORD_KEY = "SMTP_PASSWORD"

# Session-token HMAC secret (see `web/app.py::_ensure_session_secret`).
# Generated on first boot, persisted to encrypted secrets. Rotating
# invalidates every live session (documented).
SESSION_SECRET_KEY = "session_secret"

# LE ACME account key (see `web/acme_renewer.py`). Generated on first
# ACME dir registration, reused across renewals. Deletion forces a fresh
# account registration on the next tick.
ACME_ACCOUNT_KEY_KEY = "acme_account_key"


# N-320 R30 (task  tranche  DA follow-up — approved by operator
# 2026-07-03, CLI-verb delivery model): rollback-resurrection surface
# per §164.308(a)(4)(ii)(A). When a secret is rotated (e.g. current
# `SMTP_PASSWORD` → future `SMTP_PASSWORD_V2`), a subsequent rollback
# to the pre-rotation binary silently RESUMES reading the OLD name IF
# the OLD row is still in the secrets store — re-arming a
# compromised credential. `KEY_HISTORY` names every retired name per
# current key; the `secrets purge-retired-keys` CLI verb deletes the
# retired rows atomically so rollback finds them GONE (auth fails
# loud, no silent re-arm).
#
# Structure: current-key-name → tuple of retired-key-names. Retired
# names REMAIN in the tuple even after they're purged from the
# store — the tuple is the rotation ledger, not the drift state.
# The purge is idempotent (delete-missing = no-op).
#
# Populate this when rotating: add the OLD name to the tuple in the
# same commit that renames the constant above.
#
# N-360 R31 (2026-07-05 trust-repair fix-forward per PHASE2 tranche
#  DA + the backlog  = TASK ) — POST-N-320 SCOPE. Empty
# tuples mean "no rotations tracked since N-320 landed (2026-07-03)."
# Pre-N-320 rotations (before this ledger existed) are NOT tracked
# here — that's a documented §164.308(a)(4)(ii)(A) scope-boundary,
# not a gap the ledger can retroactively close (there is no
# reliable evidence trail to mine). On the current email-triage
# install family the boundary is bounded:
#   * The reference install (the deploy host) was set up 2026-04-17 (per
#     `internal compliance review`) and had NO pre-N-320 credential
#     rotations before N-320 landed 2026-07-03 — the rollback-
#     resurrection surface is empty on this install.
#   * New installs post-N-320 populate the ledger going forward per
#     the "add OLD name to the tuple in the same commit" rule.
#   * Historical installs (pre-N-320) that DID rotate credentials
#     require an operator-supplied one-shot audit + backfill (see
#     `internal documentation` §4.9 N-360).
#
# The ledger IS the close for the forward path; the retroactive
# path is a documented equivalent-measure per §164.306(d)(3)(ii)(B)
# (installs get an explicit "rotation-history-since-install"
# note in `hipaa-findings-register.md` §4.9 N-360; older installs
# that rotated pre-N-320 accept the residual risk explicitly).
KEY_HISTORY: dict[str, tuple[str, ...]] = {
    SMTP_PASSWORD_KEY: (),
    SESSION_SECRET_KEY: (),
    ACME_ACCOUNT_KEY_KEY: (),
}


def retired_names() -> list[str]:
    """Flatten :data:`KEY_HISTORY` to a de-duplicated list of every
    retired-name currently tracked. Used by the ``secrets
    purge-retired-keys`` CLI verb."""
    seen: set[str] = set()
    out: list[str] = []
    for names in KEY_HISTORY.values():
        for n in names:
            if n not in seen:
                seen.add(n)
                out.append(n)
    return out
