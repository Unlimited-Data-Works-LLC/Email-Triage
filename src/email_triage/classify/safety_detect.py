""" Phase 3 — Stage-A safety-reporting recall gate (pure-Python, no LLM).

The cheap first stage of the regulatory-clock detection cascade. Runs on EVERY
inbound mail's SUBJECT (+ optional subject-adjacent headers) — **minimum-
necessary: NO body read at Stage A** (the body is read only at Stage B, on
candidates, for the assertion/ConText negation filter). A hit marks the mail a
CANDIDATE for the Stage-B local-Ollama confirm; it is NOT a determination and
arms nothing.

Deliberately HIGH-RECALL / over-firing: a false negative on a safety-reporting
deadline is the catastrophic error, so the lexicon casts wide; precision is
restored downstream by Stage B + the human propose-then-confirm gate. No PHI
leaves this function — it returns only which lexicon terms fired.
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from email_triage._isotime import assume_utc_if_naive, to_utc_iso  # N-357b R31
from email_triage.db._helpers import row_get  # N-234 R23 SSOT

from email_triage.triage_logging import get_logger  # N-196b R21_4
logger = get_logger(__name__)  # N-196b R21_4

# (name, compiled pattern). Names are non-PHI lexicon labels — safe to log /
# store on a candidate for transparency. Word-boundaried + case-insensitive.
_SAFETY_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("susar", re.compile(r"\bSUSARs?\b", re.I)),
    ("susar_full", re.compile(r"suspected\s+unexpected\s+serious", re.I)),
    ("sae", re.compile(r"\bSAEs?\b", re.I)),
    ("icsr", re.compile(r"\bICSRs?\b", re.I)),
    ("ind_safety", re.compile(r"\bIND\s+safety\b", re.I)),
    ("safety_report", re.compile(r"\bsafety\s+report", re.I)),
    ("expedited_report", re.compile(r"\bexpedited\b.{0,24}\breport", re.I)),
    ("eudravigilance", re.compile(r"\bEudraVigilance\b", re.I)),
    ("life_threatening", re.compile(r"\blife[\s-]?threatening\b", re.I)),
    ("unanticipated_problem", re.compile(r"\bunanticipated\s+problem", re.I)),
    ("serious_adverse", re.compile(r"\bserious\s+adverse\b", re.I)),
    ("adverse_event", re.compile(r"\badverse\s+(event|reaction)s?\b", re.I)),
    ("reportable", re.compile(r"\breportable\b", re.I)),
    ("within_n_days", re.compile(
        r"\bwithin\s+\d+\s+(calendar|business|working)?\s*days?\b", re.I)),
    ("n_day_clock", re.compile(r"\b(7|15)[\s-]day\b", re.I)),
    ("irb", re.compile(r"\bIRB\b", re.I)),
    ("hrpo", re.compile(r"\bHRPO\b", re.I)),
    ("dsmb", re.compile(r"\bDSMB\b", re.I)),
    ("reporting_deadline", re.compile(
        r"\breporting\s+(deadline|requirement|timeline|obligation)", re.I)),
)

# Subject-adjacent headers that may carry the same routing signal as the subject
# (NEVER the body). Looked up case-insensitively.
_SCANNED_HEADERS: tuple[str, ...] = ("Subject", "Thread-Topic", "Keywords")


@dataclass(frozen=True)
class SafetyRecallHit:
    """The Stage-A result for a candidate. ``matched`` is the tuple of lexicon
    term NAMES that fired (non-PHI labels) — useful for the Stage-B prompt
    context, the candidate's audit detail, and recall calibration."""
    matched: tuple[str, ...]


def _header_get(headers: dict | None, name: str) -> str:
    if not headers:
        return ""
    return str(headers.get(name) or headers.get(name.lower()) or "")


def stage_a_safety_recall(
    subject: str | None, headers: dict | None = None,
) -> SafetyRecallHit | None:
    """Run the Stage-A recall gate over the subject + subject-adjacent headers.

    Returns a :class:`SafetyRecallHit` (the matched lexicon term names) if any
    pattern fires, else ``None``. Pure function — no body read, no PHI emitted,
    no I/O."""
    haystack = subject or ""
    if headers:
        for h in _SCANNED_HEADERS:
            extra = _header_get(headers, h)
            if extra and extra != subject:
                haystack += "\n" + extra
    matched = tuple(
        name for name, pat in _SAFETY_PATTERNS if pat.search(haystack)
    )
    return SafetyRecallHit(matched) if matched else None


def resolve_phrase_date(
    phrase: str | None, base_date: datetime | None,
) -> datetime | None:
    """OFFLINE resolution of a detected deadline/anchor phrase to an absolute
    UTC datetime (design §3: the LLM proposes the PHRASE; THIS does the date
    math — the LLM never computes a date).

    Uses ``dateparser`` with ``RELATIVE_BASE = base_date`` (so a relative phrase
    like "within 7 days" resolves against the email's received_at), future-
    preferring, NO network. ``base_date`` is normalised to naive-UTC for the
    relative base; the result is returned aware-UTC. Returns ``None`` on an
    unparseable phrase (fail-soft — detection stays a candidate, the human
    confirms the anchor; a wrong auto-date is worse than none)."""
    if not phrase:
        return None
    import dateparser  # lazy — only when detection runs

    base = base_date
    if base is not None and base.tzinfo is not None:
        base = base.astimezone(timezone.utc).replace(tzinfo=None)
    settings: dict = {
        "PREFER_DATES_FROM": "future",
        "RETURN_AS_TIMEZONE_AWARE": True,
        "TIMEZONE": "UTC",
        "TO_TIMEZONE": "UTC",
    }
    if base is not None:
        settings["RELATIVE_BASE"] = base
    try:
        result = dateparser.parse(phrase, settings=settings)
    except Exception:
        return None
    if result is None:
        return None
    # N-357b (2026-07-06 baseline shrink): assume_utc_if_naive SSOT.
    return assume_utc_if_naive(result).astimezone(timezone.utc)


# ===========================================================================
# Stage B verdict + the flag-gated detection orchestrator
# ===========================================================================

@dataclass(frozen=True)
class SafetyVerdict:
    """The Stage-B structured determination. ``parse_ok=False`` means Stage-B
    could not produce a verdict (the orchestrator picks the recall-safe
    disposition rather than silently dropping a possible safety deadline)."""
    is_regulatory_clock: bool
    confidence: float
    report_class: str   # fatal_lt | other_serious | irb_up | none
    clock_anchor: str   # on_receipt | on_awareness | on_determination | unknown
    extracted_phrase: str
    assertion: str      # asserted | hypothetical | negated | historical
    parse_ok: bool = True

    @classmethod
    def from_parsed(cls, d: dict) -> "SafetyVerdict":
        try:
            conf = float(d.get("confidence", 0.0) or 0.0)
        except (TypeError, ValueError):
            conf = 0.0
        return cls(
            is_regulatory_clock=bool(d.get("is_regulatory_clock", False)),
            confidence=max(0.0, min(1.0, conf)),
            report_class=str(d.get("report_class", "none") or "none"),
            clock_anchor=str(d.get("clock_anchor", "unknown") or "unknown"),
            extracted_phrase=str(d.get("extracted_phrase", "") or ""),
            assertion=str(d.get("assertion", "asserted") or "asserted"),
        )

    @classmethod
    def unparseable(cls) -> "SafetyVerdict":
        return cls(False, 0.0, "none", "unknown", "", "asserted", parse_ok=False)


@dataclass(frozen=True)
class DetectionMatch:
    """A confirmed Stage-B detection, carrying ONLY CPU-derived, non-DB inputs.

    F1 (db-sme): the orchestrator is awaited ON the event loop, so it must touch
    NEITHER the shared ``conn`` NOR ``secrets`` (both are guarded by the 
    writer RLock that ``db_call`` holds; a bare on-loop access races the
    threadpool writer). So it does all CPU work — Stage-A/Stage-B, the
    assertion filter, the EXPLICIT case_ref regex, clock_start_at — and returns
    this match; the def-resolution SELECT + the keyed-hash salt + the candidate
    INSERT all happen OFF-loop in :func:`create_clock_candidate_from_detection`
    (dispatched via ``db_call``). Deliberately NO body field — the body is read
    transiently at Stage B and never persisted (N-97)."""
    report_class: str
    extracted_phrase: str
    confidence: float
    account_id: int
    trigger_message_id: str | None
    clock_start_at: str | None
    explicit_case_ref: str | None   # CPU-extracted; None → keyed-hash off-loop
    normalized_subject: str         # for the keyed-hash fallback (off-loop)


# report_class → seeded def code. fatal_lt/other_serious are SPONSOR
# informational receipts (FDA jurisdiction default; the operator adds EU
# per-install); irb_up is the SITE escalating clock (candidate-only until the
# institution configures its duration). No mapping for "none".
_REPORT_CLASS_TO_CODE = {
    "irb_up": "IRB_AWARENESS",
    "fatal_lt": "FDA_IND_7D_INFO",
    "other_serious": "FDA_IND_15D_INFO",
}

# Explicit case/protocol/IRB reference patterns (the preferred grouping key when
# the mail carries one — LOCKED operator decision #1). Captured ref is PHI
# (clinical-trial identifying code) and is stored encrypted-at-rest.
_CASE_REF_PATTERNS = (
    re.compile(r"\bprotocol\s+(?:no\.?|#|number)?\s*[:#-]?\s*"
               r"([A-Za-z0-9][A-Za-z0-9._/-]{2,})", re.I),
    re.compile(r"\bIRB\s*(?:no\.?|#|number)?\s*[:#-]?\s*"
               r"([0-9][A-Za-z0-9._/-]{2,})", re.I),
    re.compile(r"\bstudy\s+(?:no\.?|#|id)?\s*[:#-]?\s*"
               r"([A-Za-z0-9][A-Za-z0-9._/-]{2,})", re.I),
    re.compile(r"\bcase\s+(?:no\.?|#|number)?\s*[:#-]?\s*"
               r"([0-9][A-Za-z0-9._/-]{2,})", re.I),
    re.compile(r"\b(?:ICSR|SUSAR)\s*(?:id|no\.?|#)?\s*[:#-]?\s*"
               r"([A-Za-z0-9][A-Za-z0-9._/-]{2,})", re.I),
)


def resolve_def_for_report_class(conn, report_class: str) -> int | None:
    """The seeded base def id for a Stage-B report_class (enabled base rows
    only), or None when there is no enabled def for the class."""
    code = _REPORT_CLASS_TO_CODE.get(report_class)
    if not code:
        return None
    row = conn.execute(
        "SELECT id FROM regulatory_clock_def "
        "WHERE code = ? AND enabled = 1 AND config_owner_account_id IS NULL",
        (code,),
    ).fetchone()
    return row[0] if row else None


def _extract_explicit_case_ref(subject: str, body: str) -> str | None:
    """The explicit case/protocol/IRB reference if the mail carries one (CPU-
    only — runs in the orchestrator on the loop). An explicit ref is PHI (stored
    encrypted on the candidate). Returns None when no explicit ref is found (the
    keyed-hash fallback then runs OFF-loop)."""
    hay = (subject or "") + "\n" + (body or "")
    for pat in _CASE_REF_PATTERNS:
        m = pat.search(hay)
        if m:
            ref = m.group(1).strip().strip(".,;:")
            if ref:
                return ref
    return None


def _keyed_case_ref(normalized_subject: str, account_id: int, salt: bytes) -> str:
    """The per-account KEYED-hash grouping key for the no-explicit-ref fallback
    (LOCKED decision #1: keyed, never a global salt, scoped within the account
    so the same trial across accounts cannot merge). Needs the install salt →
    runs OFF-loop in the finalizer. One-way + install-keyed."""
    digest = hmac.new(
        salt, f"{int(account_id)}:{normalized_subject}".encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()[:24]
    return f"h:{digest}"


def create_clock_candidate_from_detection(conn, secrets: Any, match: "DetectionMatch"):
    """OFF-loop finalizer (dispatched via ``db_call`` — runs in the writer
    worker thread under the  RLock, F1): resolve the def, derive the keyed
    case_ref if there was no explicit one, and create the CANDIDATE clock.
    Returns the new instance_id, or None when there is no enabled def for the
    detected class. The ONLY place the detection path touches ``conn``/``secrets``."""
    from email_triage.db.regulatory_clock import create_clock_candidate

    def_id = resolve_def_for_report_class(conn, match.report_class)
    if def_id is None:
        return None
    case_ref = match.explicit_case_ref
    if not case_ref:
        from email_triage.style_learning.per_contact_hipaa import (
            get_or_init_recipient_salt,
        )
        salt = get_or_init_recipient_salt(secrets)
        case_ref = _keyed_case_ref(match.normalized_subject, match.account_id, salt)
    return create_clock_candidate(
        conn,
        def_id=def_id,
        account_id=match.account_id,
        case_ref=case_ref,
        responsibility="unknown",  # NEVER inferred from email (N-96)
        trigger_message_id=match.trigger_message_id,
        raw_deadline_phrase=(match.extracted_phrase or None),
        detection_confidence=match.confidence,
        clock_start_at=match.clock_start_at,
    )


def create_clock_candidate_from_route(
    conn,
    secrets: Any,
    *,
    def_code: str,
    account_id: int,
    subject: str | None,
    body: str | None,
    message_id: str | None,
    received_at: str | None,
    responsibility: str = "unknown",
) -> int | None:
    """Create a CANDIDATE clock from a ROUTE ACTION match — the OPERATOR-
    configured proposer ("mail in this category starts a <def_code> clock with
    <responsibility>"). The human-driven complement to detection: the def +
    responsibility come from the ROUTE CONFIG (out-of-band operator config — the
    ONLY sanctioned source of ``responsibility`` per N-96), NOT content
    detection, so there is no false-positive risk and ``i_submit`` is legitimate
    here. Mirrors :func:`create_clock_candidate_from_detection`; runs OFF-loop
    (``db_call`` — touches ``conn`` + ``secrets`` for the keyed case_ref).
    IDEMPOTENT: returns None (no new clock) if the def is unknown/disabled OR a
    clock already tracks this ``(account_id, case_ref)`` — so a re-routed or
    similar mail never spawns a duplicate. Returns the new instance_id else None.
    The clock starts ``candidate`` (no deadline/ladder) until a human confirms on
    /clocks (propose-then-confirm)."""
    import sqlite3

    from email_triage.db.regulatory_clock import create_clock_candidate

    row = conn.execute(
        "SELECT id, clock_start_kind FROM regulatory_clock_def "
        "WHERE code = ? AND enabled = 1 AND config_owner_account_id IS NULL",
        (def_code,),
    ).fetchone()
    if row is None:
        return None  # unknown / disabled template → nothing to create
    def_id = row_get(row, "id", 0)  # N-234 R23 SSOT — sqlcipher3 Row-factory hazard
    clock_start_kind = row_get(row, "clock_start_kind", 1)

    # case_ref grouping key — explicit ref if the mail carries one (PHI, stored
    # encrypted), else the per-account KEYED hash (LOCKED decision #1; same
    # derivation as the detection path).
    case_ref = _extract_explicit_case_ref(subject or "", body or "")
    if not case_ref:
        from email_triage.style_learning.per_contact_hipaa import (
            get_or_init_recipient_salt,
        )
        salt = get_or_init_recipient_salt(secrets)
        case_ref = _keyed_case_ref((subject or "").strip().lower(), int(account_id), salt)

    # Dedup within the account: one clock per (account, case). The route fires on
    # EVERY matching mail, so without this a thread on the same case would spawn
    # duplicate clocks.
    existing = conn.execute(
        "SELECT id FROM regulatory_clock_instance "
        "WHERE account_id = ? AND case_ref = ?",
        (int(account_id), case_ref),
    ).fetchone()
    if existing is not None:
        return None  # already tracked

    clock_start_at = received_at if clock_start_kind == "on_receipt" else None
    # Audit actor (hipaa-sme MUST-FIX): an operator-CONFIGURED create has an
    # identifiable human authority — the account owner who configured the route —
    # so record it, UNLIKE system content-detection (which honestly has no human
    # actor → None). §164.312(b) + §164.308(a)(1)(ii)(D) attribution. None only if
    # the owner was hard-deleted (FK SET NULL), which falls back to system-actor.
    owner = conn.execute(
        "SELECT user_id FROM email_accounts WHERE id = ?", (int(account_id),)
    ).fetchone()
    actor_user_id = row_get(owner, "user_id", 0) if owner is not None else None  # N-234 R23 SSOT
    try:
        return create_clock_candidate(
            conn,
            def_id=def_id,
            account_id=int(account_id),
            case_ref=case_ref,
            responsibility=responsibility,
            trigger_message_id=message_id,
            clock_start_at=clock_start_at,
            actor_user_id=actor_user_id,
        )
    except sqlite3.IntegrityError:
        # Defensive constraint-violation guard (db-sme): idx_rci_case is
        # NON-unique, so the dedup is actually enforced by the SELECT check
        # above, atomic under the shared write RLock. This catch is
        # belt-and-suspenders, not the dedup mechanism.
        return None


async def detect_regulatory_clock(
    message: Any,
    classifier: Any,
    *,
    account_id: int,
    detection_enabled: bool,
) -> DetectionMatch | None:
    """The flag-gated regulatory-clock detection cascade: Stage-A recall gate →
    Stage-B local-Ollama confirm (+ assertion/ConText filter). Returns a
    :class:`DetectionMatch` for a confirmed detection, else None.

    PURE CPU + the one LLM await — touches NEITHER ``conn`` NOR ``secrets`` (F1:
    those are RLock-guarded; the caller runs the def-resolve + keyed-hash +
    candidate INSERT OFF-loop via ``db_call`` →
    :func:`create_clock_candidate_from_detection`). Safe to await on the loop.

    Does NOTHING unless ``detection_enabled`` (default OFF). NEVER infers
    ``responsibility`` from the email — only out-of-band operator config can set
    'i_submit' (N-96). FAIL-SOFT: any error returns None; detection never blocks
    core triage. The eventual clock is candidate-only until a human confirms."""
    if not detection_enabled:
        return None
    try:
        hit = stage_a_safety_recall(
            getattr(message, "subject", None), getattr(message, "headers", None),
        )
        if hit is None:
            return None  # Stage-A high-recall gate: no hit → not a candidate

        from email_triage.llm_health import LLMBackendUnreachableError
        try:
            verdict = await classifier.classify_safety_reporting(message)
        except LLMBackendUnreachableError:
            logger.warning("safety-detect: backend unreachable; skipping")
            return None

        current = verdict.assertion == "asserted"  # ConText: only a current event
        confirmed = (
            verdict.parse_ok and verdict.is_regulatory_clock
            and current and verdict.report_class != "none"
        )
        if not confirmed:
            if not verdict.parse_ok:
                logger.warning(
                    "safety-detect: Stage-B unparseable on a Stage-A hit",
                    extra={"count": len(hit.matched) if hit.matched else 0},
                )
            return None

        subject = getattr(message, "subject", "") or ""
        clock_start_at = None
        mdate = getattr(message, "date", None)
        if mdate is not None:
            # N-357b (2026-07-06 baseline shrink): assume_utc_if_naive SSOT.
            mdate = assume_utc_if_naive(mdate)
            clock_start_at = to_utc_iso(mdate)
        return DetectionMatch(
            report_class=verdict.report_class,
            extracted_phrase=verdict.extracted_phrase,
            confidence=verdict.confidence,
            account_id=account_id,
            trigger_message_id=getattr(message, "message_id", None),
            clock_start_at=clock_start_at,
            explicit_case_ref=_extract_explicit_case_ref(
                subject, getattr(message, "body_text", "") or "",
            ),
            normalized_subject=subject.strip().lower(),
        )
    except Exception as e:  # fail-soft: detection NEVER blocks core triage
        logger.warning(
            "safety-detect: detection error (non-fatal)",
            extra={"error_type": type(e).__name__, "error_msg": str(e)},
        )
        return None
