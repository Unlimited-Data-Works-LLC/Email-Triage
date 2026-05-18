"""HIPAA-safe style-learning pipeline (#152 phases 3-4).

The pipeline modules live in this package:

  * :mod:`email_triage.style_learning.phi_scrubber` — 3-layer PHI gate
    over the LLM response. Layer 1 = schema enforcement; layer 2 =
    HIPAA-18 regex matcher; layer 3 = optional NER post-check.
  * :mod:`email_triage.style_learning.distill_hipaa` —
    describe-and-discard distillation entrypoint for the
    ACCOUNT-LEVEL descriptor (M-3). Reads sent messages in memory,
    sends the structured-output prompt to the per-account-selected
    backend, runs the scrubber, persists ONLY the scrubbed descriptor.
  * :mod:`email_triage.style_learning.per_contact_hipaa` —
    PER-CONTACT (M-7 HIPAA-safe) overlay distill. Same pipeline as
    M-3 but scoped to messages SENT TO a single recurring recipient,
    keyed on a salted SHA-256 hash of the recipient address rather
    than the plaintext address itself. Recipient identity NEVER
    persisted in plaintext. Wave 3 of #152.

The pre-Wave-2-β scaffold lives in
:mod:`email_triage.actions.hipaa_style_distill`. The Wave-2-β + Wave-3
paths consume :class:`email_triage.ai_backends.BackendAdapter` via
:func:`email_triage.ai_backends.load_backend` so the operator's per-
account backend choice (Wave 2-α dropdown) routes through here.
"""

from __future__ import annotations

from email_triage.style_learning.distill_hipaa import (
    DistillResult,
    distill_hipaa_account,
)
from email_triage.style_learning.per_contact_hipaa import (
    HIPAA_PER_CONTACT_REBUILD_INTERVAL_HOURS,
    HIPAA_RECIPIENT_SALT_SECRET_KEY,
    PER_CONTACT_SYSTEM_FRAMING,
    PerContactDistillResult,
    RECIPIENT_HASH_LEN,
    SaltUnavailableError,
    distill_hipaa_per_contact,
    get_contact_style_overlay,
    get_or_init_recipient_salt,
    hash_recipient_for_install,
    per_contact_gc_daily_sweep,
)
from email_triage.style_learning.phi_scrubber import (
    LAYER1_MAX_FIELD_CHARS,
    PHI_REGEX_PATTERNS,
    ScrubResult,
    scrub_descriptor,
)

__all__ = [
    "DistillResult",
    "distill_hipaa_account",
    "ScrubResult",
    "scrub_descriptor",
    "PHI_REGEX_PATTERNS",
    "LAYER1_MAX_FIELD_CHARS",
    # M-7 HIPAA-safe per-contact (Wave 3)
    "PerContactDistillResult",
    "distill_hipaa_per_contact",
    "get_contact_style_overlay",
    "hash_recipient_for_install",
    "get_or_init_recipient_salt",
    "per_contact_gc_daily_sweep",
    "SaltUnavailableError",
    "HIPAA_RECIPIENT_SALT_SECRET_KEY",
    "RECIPIENT_HASH_LEN",
    "PER_CONTACT_SYSTEM_FRAMING",
    "HIPAA_PER_CONTACT_REBUILD_INTERVAL_HOURS",
]
