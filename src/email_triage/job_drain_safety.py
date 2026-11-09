"""Distinguish PROGRAMMING-DEFECT failures from OPERATIONAL ones in job drains.

Why this exists (incident_2026-06-11_topic_digest_dead_in_prod): the  Topic
Digest shipped DEAD on an ``ImportError`` — every back-scan failed instantly —
but the job-drain ``except Exception`` recorded it as a generic "failed job",
operator-INDISTINGUISHABLE from a transient "account auth revoked" / "IMAP
unreachable" failure. Nobody reads a failed-job ``error_text`` looking for a code
bug. A structurally-dead feature whispered when it should have screamed.

The fix: split the two failure CLASSES at the drain boundary.

* **Programming defect** — ``ImportError`` / ``AttributeError`` / ``NameError`` /
  ``TypeError``: the code is wrong (a bad import path, a missing method, a typo).
  It will fail EVERY time, for EVERY input — it is not "this one job was
  unlucky". Surface it LOUD (``logging.CRITICAL`` + a ``CODE-DEFECT`` banner +
  an ``error_text`` prefix) and count it so ``/health`` can read "degraded".
* **Operational failure** — everything else (auth revoked, network blip, a
  malformed message, an LLM timeout): the normal, expected, per-job failure the
  drain already handles. Logged + recorded as before.

This is the *fail-LOUD* half of the style-guide reliability stance (PD#8 /
R-fail-closed): a security/decisional control fails closed AND noisily; a code
defect that silently degrades a feature to "0 results" is the anti-pattern.
"""

from __future__ import annotations

import logging
import threading

#: Exception types that mean "the code is wrong" — they fail deterministically
#: for every input, so they are a DEFECT to fix, never per-job bad luck. Kept
#: narrow on purpose: a ``ValueError`` / ``KeyError`` can be legitimate bad data
#: at runtime, so they stay OPERATIONAL (a noisy false-positive defect alert is
#: worse than none). ``ImportError`` covers ``ModuleNotFoundError`` (subclass).
_PROGRAMMING_DEFECT_TYPES: tuple[type[BaseException], ...] = (
    ImportError,
    AttributeError,
    NameError,
    TypeError,
)

#: Prefix stamped on a failed job's ``error_text`` for a code defect, so the
#: row is greppable + visually distinct from an operational failure.
CODE_DEFECT_PREFIX = "CODE-DEFECT"

# Process-level count of code defects seen across all drains since boot. Read by
# /health to flip ``degraded`` — a deployed image throwing ImportError on a job
# path is a release that shipped broken, which the operator must see.
_lock = threading.Lock()
_code_defect_count = 0
_last_code_defect: str | None = None


def is_programming_defect(exc: BaseException) -> bool:
    """True if ``exc`` is a deterministic code defect (vs an operational
    failure). ``ModuleNotFoundError`` is an ``ImportError`` subclass, so it is
    covered without listing it explicitly."""
    return isinstance(exc, _PROGRAMMING_DEFECT_TYPES)


def failure_text(exc: BaseException) -> str:
    """The ``error_text`` to record on a failed job — prefixed with
    ``CODE-DEFECT:`` for a programming defect so the row is unmistakable.

    Scrubbed for persistence (census run13 #2): a mail-path exception can echo
    a recipient address / mailbox path (PHI) or a token (secret), and
    ``triage_jobs.error_text`` is operator-facing — route through the both-legs
    ``scrub_error_for_persist`` SSOT. ``is_programming_defect`` keys on the raw
    exception (not this text), so the scrub never changes the defect verdict."""
    from email_triage._errfmt import scrub_class_error_for_persist
    base = scrub_class_error_for_persist(exc) or ""
    return f"{CODE_DEFECT_PREFIX}: {base}" if is_programming_defect(exc) else base


def note_drain_failure(
    log: logging.Logger, *, job_id: object, kind: str, exc: BaseException,
) -> bool:
    """Log a drain failure at the RIGHT volume and update the defect counter.

    A programming defect logs at ``CRITICAL`` with a ``CODE-DEFECT`` banner that
    says, in words, "this is a code bug that fails every time — not a transient
    operational failure"; an operational failure logs at the normal
    ``exception`` level. Returns ``True`` iff the failure was a code defect (so
    the caller can prefix the ``error_text`` via :func:`failure_text`)."""
    if is_programming_defect(exc):
        from email_triage._errfmt import fmt_exc
        global _code_defect_count, _last_code_defect
        with _lock:
            _code_defect_count += 1
            _last_code_defect = f"{kind}: {fmt_exc(exc, with_class=True)}"[:300]
        log.critical(
            "CODE DEFECT in job drain — not an operational failure: it fails "
            "every time for every input. The deployed image shipped a broken "
            "job path. Fix the code; a re-run will NOT help.",
            extra={"_extra": {"job_id": job_id, "kind": kind,
                              "error_type": type(exc).__name__,
                              "prefix": CODE_DEFECT_PREFIX}},
        )
        return True
    log.exception(
        "job raised — marking failed (operational)",
        extra={"_extra": {"job_id": job_id, "kind": kind,
                          "error_type": type(exc).__name__}},
    )
    return False


def code_defect_health() -> dict[str, object]:
    """Snapshot for /health: ``{count, last}``. A non-zero count flips the
    endpoint to ``degraded`` — a deployed image throwing code defects on a job
    path is a broken release the operator must see."""
    with _lock:
        return {"count": _code_defect_count, "last": _last_code_defect}
