"""Structural pin — SME-gate HOOK_TRIGGER_PATTERNS MUST still cover the
trust-boundary and audit-integrity files after the 2026-07-22 DA-narrow.

Story: 2026-07-22 the pattern list dropped the blanket
``scripts/hooks/.*_gate\\.py$`` (which was pulling `defer_gate.py` +
`scope_gate.py` — dev-tooling gates — into the medical-scope trigger
surface, causing feedback-loop pain on defer/scope-gate self-repair).
That narrow was correct, but a future well-meaning simplification could
overshoot and drop the remaining explicit patterns too, silently
un-covering `sme_review_gate.py` / the op-approval trust root. This pin
locks the preserved coverage in.

WHAT IT PINS (behavioural, path-set assertion):

For every path in ``_MUST_STILL_TRIGGER``, the current
``sme_review_gate._HOOK_TRIGGER_RE`` MUST match. A future pattern
narrow that drops one of these fires the pin loudly rather than
silently un-covering an audit-integrity or trust-boundary file.

Per devils-advocate finding (2026-07-22 panel on the DA-narrow commit)
compensating-control-3: unit test locking in preserved coverage
against future accidental narrowing.
"""
from __future__ import annotations

import sys
from pathlib import Path

# scripts/hooks/ is not on the Python path by default; add it so we can
# import the live regex object (guarantees the pin follows any future
# refactor of the pattern list — a hardcoded copy in this test would be
# the exact drift class the pin exists to prevent).
_HOOKS = Path(__file__).resolve().parents[1] / "scripts" / "hooks"
sys.path.insert(0, str(_HOOKS))
from sme_review_gate import _HOOK_TRIGGER_RE  # noqa: E402


# Paths that MUST still trigger SME review after the 2026-07-22 narrow.
# Every entry is either:
#   - the SME-gate module itself (N-333 audit-integrity dogfood requirement:
#     the gate must gate itself);
#   - the op-approval trust chain (client emitter, verifier, canonical-form
#     SSOT — a change here can compromise EVERY future OP-SKIP nonce);
#   - the checked-in trust root (`.github/op-approve/` — allowed_signers
#     pubkey mirror + future goldens).
#
# A drop of any of these from `HOOK_TRIGGER_PATTERNS` is a REGRESSION,
# not a legitimate narrow. Additions to this list are welcome; deletions
# require explicit operator ratification + a paired trust-boundary review.
_MUST_STILL_TRIGGER: tuple[str, ...] = (
    # SME-gate self-dogfood (N-333).
    "scripts/hooks/sme_review_gate.py",
    # Op-approval trust chain — every module in the signing / verifying
    # / canonical-form family.
    "scripts/hooks/_op_approval.py",
    "scripts/hooks/_op_approval_common.py",
    "scripts/hooks/_op_approval_server.py",
    "scripts/hooks/emit_op_approval_trailer.py",
    # Checked-in trust root (bypasses `src/email_triage/` prefix check).
    ".github/op-approve/allowed_signers",
    ".github/op-approve/some-future-golden.txt",
)


def test_preserved_hook_trigger_coverage():
    """Every path in :data:`_MUST_STILL_TRIGGER` MUST match the live
    ``_HOOK_TRIGGER_RE`` from ``sme_review_gate``. A future narrow that
    drops one of these fires this pin."""
    missing: list[str] = []
    for path in _MUST_STILL_TRIGGER:
        if not _HOOK_TRIGGER_RE.search(path):
            missing.append(path)
    assert not missing, (
        "SME-gate HOOK_TRIGGER_PATTERNS lost coverage on trust-boundary / "
        "audit-integrity paths: " + ", ".join(missing) + ". A pattern "
        "narrow overshot — restore explicit coverage in "
        "scripts/hooks/sme_review_gate.py:HOOK_TRIGGER_PATTERNS. See the "
        "2026-07-22 DA-narrow comment in that file for what was "
        "intentionally excluded (dev-tooling gates only)."
    )


def test_dev_tooling_gates_are_excluded():
    """Sanity: `defer_gate.py` + `scope_gate.py` (dev-tooling PreToolUse
    gates) MUST NOT trigger SME review — that was the whole point of the
    2026-07-22 DA-narrow. If a future pattern re-adds them, the recurrence
    class (feedback-loop pain on defer/scope-gate self-repair) reopens."""
    dev_tooling = (
        "scripts/hooks/defer_gate.py",
        "scripts/hooks/scope_gate.py",
    )
    wrong: list[str] = []
    for path in dev_tooling:
        if _HOOK_TRIGGER_RE.search(path):
            wrong.append(path)
    assert not wrong, (
        "SME-gate HOOK_TRIGGER_PATTERNS re-added dev-tooling gates: "
        + ", ".join(wrong) + ". Per the 2026-07-22 DA-narrow + "
        "feedback_gates_deterministic_only, these are dev-tooling only "
        "and should not require SME trailer. Remove the pattern that "
        "matches them."
    )
