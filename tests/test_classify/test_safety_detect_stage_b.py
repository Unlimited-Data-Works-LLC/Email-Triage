""" Phase 3b-ii — Stage-B verdict parse + the detection orchestrator.

Mocks the LLM BOUNDARY (`_chat_safety` raw text), not the `classify_safety_
reporting` seam (which is exercised for real). The orchestrator's decision logic
(Stage-A gate, ConText assertion filter, def resolution, case_ref, spec build)
is tested with a stub classifier + a patched salt resolver.
"""
from __future__ import annotations

import dataclasses
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone

import pytest

from email_triage.classify.base import JsonChatClassifier
from email_triage.classify.safety_detect import (
    DetectionMatch,
    SafetyVerdict,
    _extract_explicit_case_ref,
    _keyed_case_ref,
    create_clock_candidate_from_detection,
    detect_regulatory_clock,
    resolve_def_for_report_class,
)
from email_triage.web.db import create_email_account, init_db

from _db_tracking import track


@dataclass
class _FakeMsg:
    subject: str = ""
    body_text: str = ""
    sender: str = "sponsor@cro.example"
    recipients: list = field(default_factory=lambda: ["pi@site.example"])
    date: datetime = field(
        default_factory=lambda: datetime(2026, 6, 1, 9, 0, tzinfo=timezone.utc)
    )
    headers: dict = field(default_factory=dict)
    message_id: str = "msg-1"


class _BoundaryClassifier(JsonChatClassifier):
    """Real classify_safety_reporting; only the HTTP boundary is canned."""
    def __init__(self, raw: str):
        self._raw = raw

    async def _resolve_model(self) -> str:
        return "test-model"

    async def _chat(self, *a, **k):  # pragma: no cover - unused here
        return "{}"

    async def classify(self, *a, **k):  # pragma: no cover - unused here
        raise NotImplementedError

    async def _chat_safety(self, prompt: str, model: str) -> str:
        return self._raw


class _StubClassifier:
    """Returns a fixed verdict — for the orchestrator decision tests."""
    def __init__(self, verdict: SafetyVerdict):
        self._v = verdict

    async def classify_safety_reporting(self, message):
        return self._v


@pytest.fixture
def conn():
    c = track(init_db(":memory:"))
    yield c
    c.close()


# ---- Stage-B verdict parse (real seam, mocked boundary) -------------------

@pytest.mark.asyncio
async def test_classify_safety_reporting_parses_verdict():
    raw = json.dumps({
        "is_regulatory_clock": True, "confidence": 0.9,
        "report_class": "irb_up", "clock_anchor": "on_awareness",
        "extracted_phrase": "within 10 working days", "assertion": "asserted",
    })
    v = await _BoundaryClassifier(raw).classify_safety_reporting(_FakeMsg())
    assert v.is_regulatory_clock is True
    assert v.report_class == "irb_up"
    assert v.assertion == "asserted"
    assert v.parse_ok is True


@pytest.mark.asyncio
async def test_classify_safety_reporting_failopen_on_garbage():
    v = await _BoundaryClassifier("not json at all").classify_safety_reporting(
        _FakeMsg()
    )
    assert v.parse_ok is False
    assert v.is_regulatory_clock is False


# ---- def resolution + case_ref --------------------------------------------

def test_resolve_def_for_report_class(conn):
    assert resolve_def_for_report_class(conn, "none") is None
    assert resolve_def_for_report_class(conn, "irb_up") is not None
    fda = resolve_def_for_report_class(conn, "fatal_lt")
    code = conn.execute(
        "SELECT code FROM regulatory_clock_def WHERE id=?", (fda,)
    ).fetchone()[0]
    assert code == "FDA_IND_7D_INFO"


def test_extract_explicit_case_ref():
    assert _extract_explicit_case_ref("SUSAR — Protocol ABC-123 expedited",
                                      "") == "ABC-123"
    assert _extract_explicit_case_ref("serious adverse event", "") is None


def test_keyed_case_ref_deterministic_and_account_scoped():
    salt = b"k" * 32
    norm = "serious adverse event, life-threatening"
    r_a1 = _keyed_case_ref(norm, 1, salt)
    r_a1b = _keyed_case_ref(norm, 1, salt)
    r_a2 = _keyed_case_ref(norm, 2, salt)
    assert r_a1 == r_a1b           # deterministic within an account
    assert r_a1 != r_a2            # different account → different ref (no merge)
    assert r_a1.startswith("h:")


def test_detection_match_carries_no_body_field():
    # NIT-1 (hipaa-sme): the body is read transiently at Stage B and NEVER
    # persisted (N-97); pin that no DetectionMatch field smuggles it.
    assert not any(
        "body" in f.name for f in dataclasses.fields(DetectionMatch)
    )


# ---- orchestrator decision logic ------------------------------------------

def _account(conn):
    conn.execute(
        "INSERT INTO users (email, name, role, created_at) "
        "VALUES ('u@x','U','admin','now')"
    )
    uid = conn.execute("SELECT id FROM users").fetchone()[0]
    return create_email_account(
        conn, user_id=uid, name="A", provider_type="imap",
        config={"account": "a@x"}, hipaa=True,
    )


@pytest.mark.asyncio
async def test_orchestrator_noop_when_flag_off():
    v = SafetyVerdict(True, 0.9, "irb_up", "on_awareness", "x", "asserted")
    m = await detect_regulatory_clock(
        _FakeMsg(subject="SUSAR life-threatening"), _StubClassifier(v),
        account_id=1, detection_enabled=False,
    )
    assert m is None


@pytest.mark.asyncio
async def test_orchestrator_stage_a_miss_skips_llm():
    v = SafetyVerdict(True, 0.9, "irb_up", "on_awareness", "x", "asserted")
    m = await detect_regulatory_clock(
        _FakeMsg(subject="lunch tomorrow?"), _StubClassifier(v),
        account_id=1, detection_enabled=True,
    )
    assert m is None  # Stage-A gate never fired → Stage-B not consulted


@pytest.mark.asyncio
async def test_orchestrator_assertion_filter_drops_hypothetical():
    v = SafetyVerdict(True, 0.9, "irb_up", "on_awareness", "x", "hypothetical")
    m = await detect_regulatory_clock(
        _FakeMsg(subject="SUSAR reporting requirements"), _StubClassifier(v),
        account_id=1, detection_enabled=True,
    )
    assert m is None  # ConText: not a current obligation


@pytest.mark.asyncio
async def test_orchestrator_confirmed_returns_match():
    v = SafetyVerdict(True, 0.85, "irb_up", "on_awareness",
                      "within 10 working days", "asserted")
    m = await detect_regulatory_clock(
        _FakeMsg(subject="Unanticipated problem — IRB report required"),
        _StubClassifier(v), account_id=7, detection_enabled=True,
    )
    assert isinstance(m, DetectionMatch)
    assert m.account_id == 7
    assert m.report_class == "irb_up"
    assert m.confidence == 0.85
    assert m.extracted_phrase == "within 10 working days"
    assert m.clock_start_at is not None  # from message.date (CPU)


def test_finalizer_creates_candidate_off_loop(conn, monkeypatch):
    # the off-loop finalizer resolves the def + keyed case_ref + creates the
    # candidate (responsibility='unknown', IRB site clock, candidate state).
    monkeypatch.setattr(
        "email_triage.style_learning.per_contact_hipaa."
        "get_or_init_recipient_salt", lambda s: b"k" * 32,
    )
    aid = _account(conn)
    match = DetectionMatch(
        report_class="irb_up", extracted_phrase="within 10 working days",
        confidence=0.85, account_id=aid, trigger_message_id="m1",
        clock_start_at="2026-06-01T09:00:00+00:00",
        explicit_case_ref=None, normalized_subject="irb report required",
    )
    iid = create_clock_candidate_from_detection(conn, object(), match)
    assert iid is not None
    row = conn.execute(
        "SELECT i.responsibility, i.state, i.case_ref, d.code "
        "FROM regulatory_clock_instance i "
        "JOIN regulatory_clock_def d ON d.id = i.def_id WHERE i.id=?", (iid,)
    ).fetchone()
    assert row["responsibility"] == "unknown"   # N-96
    assert row["state"] == "candidate"
    assert row["case_ref"].startswith("h:")     # keyed-hash fallback
    assert row["code"] == "IRB_AWARENESS"


def test_finalizer_uses_explicit_case_ref_when_present(conn):
    aid = _account(conn)
    match = DetectionMatch(
        report_class="fatal_lt", extracted_phrase="", confidence=0.9,
        account_id=aid, trigger_message_id="m2",
        clock_start_at="2026-06-01T09:00:00+00:00",
        explicit_case_ref="ABC-123", normalized_subject="x",
    )
    iid = create_clock_candidate_from_detection(conn, None, match)  # no salt needed
    case_ref = conn.execute(
        "SELECT case_ref FROM regulatory_clock_instance WHERE id=?", (iid,)
    ).fetchone()[0]
    assert case_ref == "ABC-123"
