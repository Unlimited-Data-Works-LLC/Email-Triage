""" Phase 3 — Stage-A safety-reporting recall-gate pins.

High-recall by design: real safety-reporting mail fires; ordinary mail does not.
Pure-Python, no LLM, no body read.
"""
from __future__ import annotations

import pytest

from datetime import datetime, timezone

from email_triage.classify.safety_detect import (
    SafetyRecallHit,
    resolve_phrase_date,
    stage_a_safety_recall,
)


@pytest.mark.parametrize("subject", [
    "SUSAR report — subject 014, life-threatening",
    "URGENT: IND Safety Report (expedited)",
    "Please report this SAE within 7 calendar days",
    "EudraVigilance ICSR submission reminder",
    "Unanticipated problem — IRB notification required",
    "Suspected Unexpected Serious Adverse Reaction notice",
    "15-day expedited safety report due",
    "Reportable event — DSMB review",
])
def test_recall_gate_fires_on_safety_mail(subject):
    hit = stage_a_safety_recall(subject)
    assert isinstance(hit, SafetyRecallHit)
    assert hit.matched  # at least one lexicon term


@pytest.mark.parametrize("subject", [
    "Re: your dentist appointment Tuesday",
    "Weekly newsletter — lab supplies on sale",
    "Lunch?",
    "Your invoice for March",
    "Meeting notes from standup",
])
def test_recall_gate_silent_on_ordinary_mail(subject):
    assert stage_a_safety_recall(subject) is None


def test_case_insensitive_and_reports_matched_terms():
    hit = stage_a_safety_recall("susar + sae, report within 15 working days")
    assert hit is not None
    assert "susar" in hit.matched
    assert "sae" in hit.matched
    assert "within_n_days" in hit.matched


def test_scans_subject_adjacent_headers_not_body():
    # signal only in a scanned header, not the (absent) subject
    hit = stage_a_safety_recall("", headers={"Thread-Topic": "IND safety report"})
    assert hit is not None
    assert "ind_safety" in hit.matched


def test_none_subject_is_safe():
    assert stage_a_safety_recall(None) is None
    assert stage_a_safety_recall(None, headers=None) is None


_BASE = datetime(2026, 6, 1, 12, 0, tzinfo=timezone.utc)


def test_resolve_relative_phrase_against_base():
    # "within 7 days" of 2026-06-01 → 2026-06-08
    d = resolve_phrase_date("in 7 days", _BASE)
    assert d is not None
    assert d.year == 2026 and d.month == 6 and d.day == 8
    assert d.tzinfo is not None  # aware UTC


def test_resolve_absolute_date():
    d = resolve_phrase_date("June 15, 2026", _BASE)
    assert d is not None
    assert (d.year, d.month, d.day) == (2026, 6, 15)


def test_resolve_unparseable_is_none_failsoft():
    assert resolve_phrase_date("sometime soonish maybe", _BASE) is None
    assert resolve_phrase_date("", _BASE) is None
    assert resolve_phrase_date(None, _BASE) is None


def test_resolve_no_base_still_handles_absolute():
    d = resolve_phrase_date("2026-07-04", None)
    assert d is not None
    assert (d.year, d.month, d.day) == (2026, 7, 4)
