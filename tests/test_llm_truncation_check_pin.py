"""COUNT-AGNOSTIC structural pin.

Operator 2026-06-12 ("is this silent-truncation bug a candidate for a pin?" —
yes): the LLM-token-cap-without-finish_reason-check was a drifted SSOT — fixed
for Ollama, then the IDENTICAL pattern was found unfixed in every other
backend. The fix is one SSOT (``email_triage.llm_truncation``) that EVERY capped
backend routes through. This pin asserts that property over EVERY backend module
(``ast.walk`` / glob, NOT ``len(backends) == N``), so a NEW backend that adds a
token cap without the truncation check fails CI.
"""

from __future__ import annotations

# Source walk goes through the shared pin harness (R5b — every *.py
# source walk uses iter_src_files/relpath, never a hand-rolled rglob;
# the boilerplate has drifted before).
from _pin_harness import iter_src_files, relpath

# A module that sets an LLM generation cap ...
_CAP_TOKENS = ("max_tokens", "num_predict", "maxOutputTokens")
# ... AND parses a completion response ...
_COMPLETION_READS = ("choices", "candidates", "done_reason")
# ... MUST reference the shared truncation SSOT.
_SSOT_NAMES = (
    "warn_if_llm_truncated", "is_llm_truncated", "llm_finish_reason",
    "llm_truncation",
)

_BACKEND_DIRS = ("classify", "ai_backends")


def test_every_capped_llm_backend_routes_through_truncation_ssot():
    offenders: list[str] = []
    for d in _BACKEND_DIRS:
        for f in iter_src_files(d):
            src = f.read_text(encoding="utf-8")
            sets_cap = any(tok in src for tok in _CAP_TOKENS)
            reads_completion = any(r in src for r in _COMPLETION_READS)
            checks_truncation = any(s in src for s in _SSOT_NAMES)
            if sets_cap and reads_completion and not checks_truncation:
                offenders.append(relpath(f))
    assert not offenders, (
        "These LLM backends set a generation token cap and parse a completion "
        "response but do NOT route through the email_triage.llm_truncation "
        "SSOT (the  finish-reason guard). Add "
        "`warn_if_llm_truncated(body, family=..., model=..., context=..., "
        "logger=...)` after reading the response:\n  " + "\n  ".join(offenders)
    )


def test_truncation_ssot_module_exists():
    # The SSOT itself must exist + export the guard the pin keys on.
    from email_triage import llm_truncation
    for name in ("warn_if_llm_truncated", "is_llm_truncated", "llm_finish_reason"):
        assert hasattr(llm_truncation, name), name
