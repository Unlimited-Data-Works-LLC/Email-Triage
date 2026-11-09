"""Punch 601 — classify-layer HIPAA decisions read the effective-HIPAA SSOT, not the raw stamp.

THE DEFECT (fail-OPEN, PHI at rest and PHI egress)
==================================================
``EmailMessage.hipaa`` defaults to ``False`` and NO provider sets it. The comment
on the field (``engine/models.py``) and on ``FlowEngine.classify`` said the
provider resolves it at fetch; a grep of ``providers/`` finds no write. At HEAD
the flag was stamped at exactly three sites (``web/triage_one.py``,
``web/digest.py``, the triage-classify Discover loop). Every other path reached
a HIPAA decision carrying the dataclass default:

* ``classify/base.py`` cache store passed ``is_hipaa=bool(message.hipaa)`` to
  ``acache_store_for_message``, whose ``_build_inner_payload`` keeps the LLM
  ``reason`` free text (it can echo body fragments) only when ``is_hipaa`` is
  False. Reached unstamped from the Test Classify paste page (system HIPAA flag
  on → the reason was cached in Redis) and the topic back-scan fallback classify
  (a per-account HIPAA mailbox → the same).
* ``engine/flow.py`` (the CLI ``run`` / ``watch`` FlowEngine) read the raw flag
  for the N-113 BAA egress gate (so a system-HIPAA install classified on a
  non-BAA external backend) and for ``state_bag["account_hipaa"]`` (so the
  ``reason`` was persisted unredacted in ``flows.classification_json``).

THE FIX
=======
The decision sites call ``triage_logging.account_hipaa_effective(message=...)``
(system flag OR message stamp); the FlowEngine stamps the effective value on the
message it fetches, so downstream action-layer reads agree; the back-scan stamps
the account-resolved value on each scanned message.

Behavioural tests here drive the real ``JsonChatClassifier.classify`` (stub Redis),
the real ``FlowEngine`` against a real ``FlowStore``, and the real back-scan job.
The structural pin is ``tests/test_punch601_hipaa_decision_ssot_pin.py``.
"""
from __future__ import annotations

import json
import sqlite3
import sys
import types
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

import email_triage.triage_logging as _tl
from email_triage.cache.classification import (
    ClassificationCache,
    set_install_classification_cache,
)
from email_triage.classify.base import JsonChatClassifier
from email_triage.engine.models import EmailMessage

from tests.test_cache.test_classification import (  # noqa: F401  (autouse fixture)
    _StubRedis,
    _reset_counters_and_singleton,
)

_PHI_REASON = "Patient Jane Roe MRN 55443322 asked to move her chemo infusion."
_CATEGORIES = {"medical": "Clinical correspondence", "other": "Everything else"}


@pytest.fixture
def stub_cache():
    s = _StubRedis()
    stub_mod = types.SimpleNamespace()

    class _Factory:
        @staticmethod
        def from_url(url, **kwargs):
            return s

    stub_mod.Redis = _Factory
    saved = sys.modules.get("redis")
    sys.modules["redis"] = stub_mod
    cache = ClassificationCache(url="redis://stub.invalid:6379/0")
    set_install_classification_cache(cache)
    try:
        yield s
    finally:
        set_install_classification_cache(None)
        if saved is None:
            sys.modules.pop("redis", None)
        else:
            sys.modules["redis"] = saved


@pytest.fixture
def system_hipaa(monkeypatch):
    monkeypatch.setattr(_tl, "_hipaa_mode", True)


@pytest.fixture
def system_hipaa_off(monkeypatch):
    monkeypatch.setattr(_tl, "_hipaa_mode", False)


class _FixedReplyClassifier(JsonChatClassifier):
    """The real template-method classify body; only the model call is canned."""

    def __init__(self) -> None:
        self._model = "stub-model"

    async def _chat(self, system_prompt: str, user_prompt: str, model: str) -> str:
        return json.dumps(
            {"category": "medical", "confidence": 0.9, "reason": _PHI_REASON},
        )


def _message(*, hipaa: bool, account_id: int = 0, msg_id: str = "m-601") -> EmailMessage:
    return EmailMessage(
        message_id=msg_id,
        provider="test",
        sender="clinic@example.com",
        recipients=["doctor@example.com"],
        subject="Infusion schedule",
        body_text="Please move my appointment.",
        date=datetime(2026, 10, 10, 12, 0, tzinfo=timezone.utc),
        headers={"Message-ID": f"<{msg_id}@example.com>"},
        raw_metadata={"account_id": account_id},
        hipaa=hipaa,
    )


def _stored_payloads(redis_stub) -> list[dict]:
    """Every inner (per-message) payload the classify path wrote to the stub
    Redis. The per-sender category distribution hash holds bare counts, so only
    dict-shaped values are payloads."""
    out: list[dict] = []
    for fields in redis_stub._hashes.values():
        for raw in fields.values():
            try:
                val = json.loads(raw)
            except (TypeError, ValueError):
                continue
            if isinstance(val, dict) and "category" in val:
                out.append(val)
    return out


# ---------------------------------------------------------------------------
# 1. The classify cache store (the site the row named, classify/base.py)
# ---------------------------------------------------------------------------

async def test_cache_store_strips_reason_under_system_flag_when_message_unstamped(
    stub_cache, system_hipaa,
):
    """System HIPAA on, message never stamped (the Test Classify / CLI shape):
    the cached payload must not carry the LLM reason. RED at HEAD."""
    clf = _FixedReplyClassifier()
    result = await clf.classify(_message(hipaa=False), _CATEGORIES)
    assert result.category == "medical"
    payloads = _stored_payloads(stub_cache)
    assert payloads, "rig: the classify path stored nothing (cannot judge the strip)"
    for p in payloads:
        assert "reason" not in p, (
            "HIPAA-effective classify cached the LLM reason (PHI free text) because "
            f"it read the raw message.hipaa stamp: {p!r}"
        )


async def test_cache_store_keeps_reason_when_not_hipaa(stub_cache, system_hipaa_off):
    """Control arm: the same rig with HIPAA off DOES store the reason, so the
    assertion above can see a reason when one is written."""
    clf = _FixedReplyClassifier()
    await clf.classify(_message(hipaa=False), _CATEGORIES)
    payloads = _stored_payloads(stub_cache)
    assert payloads and all(p.get("reason") == _PHI_REASON for p in payloads)


async def test_cache_store_strips_reason_for_a_stamped_per_account_message(
    stub_cache, system_hipaa_off,
):
    """Per-account HIPAA on a non-HIPAA install travels on the stamp; the SSOT
    honours it (most-restrictive-wins)."""
    clf = _FixedReplyClassifier()
    await clf.classify(_message(hipaa=True, account_id=7), _CATEGORIES)
    payloads = _stored_payloads(stub_cache)
    assert payloads and all("reason" not in p for p in payloads)


# ---------------------------------------------------------------------------
# 2. The CLI FlowEngine (engine/flow.py) — same root cause, two more controls
# ---------------------------------------------------------------------------

def _engine(store, *, message, classifier=None):
    from email_triage.actions.registry import ActionRegistry
    from email_triage.config import TriageConfig
    from email_triage.engine.flow import FlowEngine
    from email_triage.engine.models import Classification

    provider = AsyncMock()
    provider.name = "test"
    provider.search.return_value = [message.message_id]
    provider.fetch_message.return_value = message
    if classifier is None:
        classifier = AsyncMock()
        classifier.classify.return_value = Classification(
            category="medical", confidence=0.95, reason=_PHI_REASON, source="llm",
        )
    config = TriageConfig()
    config.routes = {}
    return FlowEngine(
        store=store, provider=provider, classifier=classifier,
        config=config, registry=ActionRegistry(),
    )


def _persisted_reason(store, flow_id: str) -> str:
    row = store._conn.execute(
        "SELECT classification_json FROM flows WHERE flow_id = ?", (flow_id,),
    ).fetchone()
    assert row is not None and row["classification_json"] is not None
    return json.loads(row["classification_json"]).get("reason", "")


async def test_flowengine_redacts_reason_at_rest_under_system_flag(tmp_path, system_hipaa):
    """CLI FlowEngine, system HIPAA on, provider returns an unstamped message:
    the persisted classification_json must not carry the PHI reason. RED at HEAD
    (state_bag['account_hipaa'] came from the raw stamp)."""
    from email_triage.engine.models import FlowStatus
    from email_triage.engine.store import FlowStore
    from _db_tracking import track

    store = FlowStore(tmp_path / "flows.db")
    track(store._conn)
    msg = _message(hipaa=False)
    engine = _engine(store, message=msg)
    # The classifier backend is a local mock; keep the BAA gate out of this arm.
    with patch("email_triage.classify.baa_gate.baa_block_status", return_value=None):
        flows = await engine.ingest("ALL")
        flow, fetched = await engine.fetch(flows[0])
        flow, _cls = await engine.classify(flow, fetched)
    assert flow.status == FlowStatus.CLASSIFIED
    assert flow.state_bag.get("account_hipaa") is True
    assert fetched.hipaa is True, "FlowEngine must stamp the effective value it fetched"
    assert _PHI_REASON not in _persisted_reason(store, flow.flow_id)


async def test_flowengine_baa_gate_engages_under_system_flag(tmp_path, system_hipaa):
    """N-113 BAA egress gate on the CLI FlowEngine: system HIPAA on, unstamped
    message, a non-BAA backend → the classify is refused, no egress. RED at HEAD
    (the gate read the raw stamp, so it never ran)."""
    from email_triage.engine.models import FlowStatus
    from email_triage.engine.store import FlowStore
    from _db_tracking import track

    store = FlowStore(tmp_path / "flows.db")
    track(store._conn)
    msg = _message(hipaa=False)
    engine = _engine(store, message=msg)
    block = {"backend": "openai", "host": "api.example.invalid"}
    with patch("email_triage.classify.baa_gate.baa_block_status", return_value=block):
        flows = await engine.ingest("ALL")
        flow = await engine.process_flow(flows[0])
    assert flow.status == FlowStatus.FAILED
    engine._classifier.classify.assert_not_awaited()


async def test_flowengine_non_hipaa_skips_baa_gate(tmp_path, system_hipaa_off):
    """Control arm: HIPAA off, the same blocking gate stub is never consulted."""
    from email_triage.engine.store import FlowStore
    from _db_tracking import track

    store = FlowStore(tmp_path / "flows.db")
    track(store._conn)
    engine = _engine(store, message=_message(hipaa=False))
    with patch(
        "email_triage.classify.baa_gate.baa_block_status",
        return_value={"backend": "openai", "host": "x.invalid"},
    ) as gate:
        flows = await engine.ingest("ALL")
        flow, fetched = await engine.fetch(flows[0])
        await engine.classify(flow, fetched)
    gate.assert_not_called()
    engine._classifier.classify.assert_awaited()


# ---------------------------------------------------------------------------
# 3. The topic back-scan (jobs/topic_backscan.py) — per-account HIPAA mailbox
# ---------------------------------------------------------------------------

def _backscan_db():
    from email_triage.web.db import init_db
    from _db_tracking import track
    return track(init_db(":memory:"))


def _seed(conn: sqlite3.Connection, *, hipaa: bool) -> tuple[int, int, str]:
    from email_triage.actions.topic_configs import TopicConfig, upsert_topic
    from email_triage.jobs.topic_backscan import enqueue_topic_backscan

    now = datetime.now(timezone.utc).isoformat()
    uid = int(conn.execute(
        "INSERT INTO users (email, name, role, created_at) VALUES (?, ?, ?, ?)",
        ("owner@example.com", "Owner", "user", now),
    ).lastrowid)
    aid = int(conn.execute(
        "INSERT INTO email_accounts (user_id, name, provider_type, config_json, "
        "hipaa, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (uid, "Clinic", "imap", "{}", int(hipaa), now, now),
    ).lastrowid)
    conn.commit()
    topic = upsert_topic(conn, TopicConfig(
        id=0, user_id=uid, name="Infusions", details="infusion scheduling",
        topic_version=1,
    ))
    job_id = enqueue_topic_backscan(
        conn, topic_id=int(topic.id), account_id=aid, actor_user_id=uid,
        window_days=30,
    )
    assert job_id is not None
    return uid, aid, job_id


async def _run_backscan(conn, job_id, messages):
    from email_triage.jobs.topic_backscan import run_topic_backscan_job

    async def _fetcher():
        yield list(messages)

    seen: list[bool] = []

    async def _capture(msg, *a, **k):
        seen.append(bool(getattr(msg, "hipaa", False)))
        return []

    app = MagicMock()
    app.state.db = conn
    app.state.config = MagicMock()
    job_row = dict(conn.execute(
        "SELECT * FROM triage_jobs WHERE job_id = ?", (job_id,),
    ).fetchone())
    with patch("email_triage.jobs.topic_backscan._build_classifier",
               return_value=MagicMock()), \
         patch("email_triage.classify.baa_gate.baa_block_status", return_value=None), \
         patch("email_triage.jobs.topic_backscan.match_topics_for_message",
               side_effect=_capture):
        await run_topic_backscan_job(app, conn, job_row, fetcher_batches=_fetcher())
    return seen


async def test_backscan_stamps_per_account_hipaa_before_topic_classify(system_hipaa_off):
    """Per-account HIPAA mailbox on a non-HIPAA install: the message handed to the
    topic classifier (whose fallback reaches the cache store) carries hipaa=True.
    RED at HEAD (the fetched message kept the dataclass default)."""
    conn = _backscan_db()
    _uid, _aid, job_id = _seed(conn, hipaa=True)
    seen = await _run_backscan(conn, job_id, [_message(hipaa=False)])
    assert seen == [True]


async def test_backscan_leaves_non_hipaa_account_unstamped(system_hipaa_off):
    """Control arm: a non-HIPAA mailbox is not over-stamped."""
    conn = _backscan_db()
    _uid, _aid, job_id = _seed(conn, hipaa=False)
    seen = await _run_backscan(conn, job_id, [_message(hipaa=False)])
    assert seen == [False]
