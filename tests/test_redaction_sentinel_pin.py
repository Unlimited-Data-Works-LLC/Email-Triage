"""Structural pin (A3, divergence census 2026-06-09): one PHI-redaction
sentinel spelling.

The same logical "this field was PHI-stripped" marker had drifted to two
spellings — ``[redacted]`` (every PHI site + the ``watcher.py`` reason-guard)
and ``[REDACTED]`` (``sent_mail_index``'s HIPAA-subject branch). They never
crossed to leak (the guard checks a *reason*, the index writes a *subject*),
but the divergence is a latent hazard: a future path routing the uppercase
value to the lowercase guard would treat PHI as un-redacted content.

The canonical PHI sentinel is now the single ``REDACTED = "[redacted]"``
constant in ``triage_logging.py``. The uppercase ``[REDACTED]`` is a DISTINCT
concern — the SECRET-redaction marker (passwords/keys scrubbed from error
strings), which census #6 extracted into the leaf SSOT ``_secret_scrub.py``
(``web/db.py`` now delegates to it and holds no literal) — so the allowlist
below is its only sanctioned home (plus the migration docstring that
*describes* the legacy spelling).

Count-agnostic (``pattern_count_agnostic_structural_drift_catch``): asserts a
property over every site, not a count. A new uppercase ``[REDACTED]`` outside
the allowlist trips CI — route PHI redaction through the lowercase constant.
"""

from __future__ import annotations

import re

from _pin_harness import iter_src_files, relpath

# The ONLY sanctioned homes of the uppercase "[REDACTED]" literal — the
# secret-redaction sentinel (distinct from PHI redaction) + the migration
# docstring that documents the legacy spelling.
_UPPER_ALLOW = {
    "_secret_scrub.py",   # census #6 secret-redaction SSOT: passwords/keys in errors
    "web/migrations.py",  # docstring describing the legacy "[REDACTED]" value
    "triage_logging.py",  # the SSOT home — its comment documents both spellings
}
_UPPER = re.compile(r"\[REDACTED\]")


def test_no_uppercase_phi_redaction_sentinel():
    """No uppercase ``[REDACTED]`` outside the secret-redaction allowlist —
    PHI redaction uses the canonical lowercase ``REDACTED`` constant
    (``triage_logging.py``). This is the divergence that bit ``sent_mail_index``."""
    offenders: list[str] = []
    for p in iter_src_files():
        rel = relpath(p)
        if rel in _UPPER_ALLOW:
            continue
        for i, line in enumerate(
            p.read_text(encoding="utf-8").splitlines(), 1,
        ):
            if _UPPER.search(line):
                offenders.append(f"{rel}:{i}")
    assert not offenders, (
        "Uppercase [REDACTED] outside the secret-redaction allowlist — PHI "
        "redaction must use the canonical lowercase REDACTED constant "
        "(email_triage.triage_logging.REDACTED):\n  "
        + "\n  ".join(offenders)
        + "\n\n(If this is a NEW secret-redaction site — not PHI — add it to "
        "_UPPER_ALLOW with a one-line justification.)"
    )


def test_redacted_constant_is_lowercase_canonical():
    """The PHI sentinel constant is exactly ``[redacted]`` — the spelling the
    watcher reason-guard and every PHI producer already use."""
    from email_triage.triage_logging import REDACTED
    assert REDACTED == "[redacted]"
