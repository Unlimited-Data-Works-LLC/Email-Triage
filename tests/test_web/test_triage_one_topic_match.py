""" — live Topic matching is baked into ``triage_single_message``.

The steady-state Topic match (design §1) rides the primary classify pass:
after a message is classified, it is matched against the account's active
Topics on the SAME classifier, and each positive becomes a ``topic_hits``
row (``source='live'``). These tests assert the WIRING end-to-end — a real
``triage_single_message`` call, the real matcher, the real
``insert_topic_hit`` write — using a classifier that exposes BOTH seams
(``classify`` + ``classify_with_topics_safe``), exactly as the production
``OllamaClassifier`` does.

The load-bearing assertion is that a matching live message actually persists
a hit (the spine that feeds the digest) AND that the live path threads the
REAL ``ctx.categories`` into the topic-match seam — without which the
taxonomy gate would fail every verdict open (the  categories-threading
bug, pinned at the matcher level in ``test_topic_matcher``).
"""

from __future__ import annotations
from _db_tracking import track

import sqlite3
from datetime import datetime, timezone

import pytest

from email_triage.actions import topic_configs as tc
from email_triage.actions.registry import ActionRegistry
from email_triage.classify.base import TopicMatchResult, TopicVerdict
from email_triage.engine.models import Classification, EmailMessage
from email_triage.web.db import init_db
from email_triage.web.triage_one import TriageContext, triage_single_message


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------

class _MatchClassifier:
    """A classifier exposing BOTH the bare classify seam and the topic-match
    seam (the production ``OllamaClassifier`` exposes both).

    Records the ``categories`` it was handed on each topic-match call so a
    test can assert the live path threads ``ctx.categories`` (not the broken
    ``{}`` fallback). ``raises`` makes the topic-match seam raise, to exercise
    the live path's fail-open.
    """

    def __init__(self, *, topic_id, category="invoices", raises=False):
        self._topic_id = topic_id
        self._category = category
        self._raises = raises
        self.topic_calls: list[dict] = []

    async def classify(self, message, categories, hints):
        return Classification(
            category=self._category, confidence=0.9, reason="t",
        )

    async def classify_with_topics_safe(
        self, message, categories, list_hints, *, topic_block, model=None,
    ):
        self.topic_calls.append({"categories": dict(categories or {})})
        if self._raises:
            raise RuntimeError("simulated GPU flake")
        return TopicMatchResult(
            classification=Classification(
                category=self._category, confidence=0.9, reason="",
            ),
            topic_verdicts=[TopicVerdict(
                topic_id=self._topic_id, matched=True, confidence=0.88,
                reason_terms=("lupus",),
            )],
        )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def conn() -> sqlite3.Connection:
    c = track(init_db(":memory:"))
    yield c
    c.close()


@pytest.fixture
def seeded(conn: sqlite3.Connection):
    now = datetime.now(timezone.utc).isoformat()
    cur = conn.execute(
        "INSERT INTO users (email, name, role, created_at) "
        "VALUES ('op@x.com','Op','user',?)", (now,),
    )
    uid = int(cur.lastrowid)
    cur = conn.execute(
        "INSERT INTO email_accounts "
        "(user_id, name, provider_type, config_json, created_at, updated_at)"
        " VALUES (?,?,?,?,?,?)",
        (uid, "M", "imap", "{}", now, now),
    )
    account_id = int(cur.lastrowid)
    conn.commit()
    return uid, account_id


def _make_topic(conn, uid, account_id):
    return tc.upsert_topic(conn, tc.TopicConfig(
        user_id=uid, name="Lupus", subjects=["lupus", "SELENA"],
        details="Safety of Estrogens in Lupus",
        selected_account_ids=[account_id], enabled=True,
    ))


def _msg() -> EmailMessage:
    return EmailMessage(
        message_id="42", provider="imap",
        sender="alice@example.com", recipients=["op@x.com"],
        subject="re lupus", body_text="about the lupus study",
        date=datetime.now(timezone.utc),
        headers={"Message-ID": "<m42@example.com>"},
    )


_CATEGORIES = {"invoices": "invoices", "other": "other"}


def _ctx(conn, account_id, classifier, *, dry_run=False, match_topics=True,
         fire_watches=False):
    from email_triage.web.db import get_email_account
    acct = get_email_account(conn, account_id)
    return TriageContext(
        db=conn, config=None, secrets=None, acct=acct,
        classifier=classifier, provider=None,
        registry=ActionRegistry(), categories=_CATEGORIES,
        routes_by_cat={},  # no routes → no actions; status p
        durable_dedup=False,
        fire_watches=fire_watches,
        dry_run=dry_run,
        match_topics=match_topics,
    )


def _live_hits(conn, topic_id):
    rows = conn.execute(
        "SELECT topic_id, account_id, rfc822_message_id, confidence, source, "
        "reason_terms_json FROM topic_hits WHERE topic_id=? AND source='live'",
        (int(topic_id),),
    ).fetchall()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_live_match_persists_topic_hit(conn, seeded):
    """A matching live message writes a topic_hits row (source='live') AND the
    live path threads the REAL ctx.categories into the topic-match seam."""
    uid, account_id = seeded
    topic = _make_topic(conn, uid, account_id)
    clf = _MatchClassifier(topic_id=topic.id)

    res = await triage_single_message(
        _ctx(conn, account_id, clf), _msg(), "42",
    )

    assert res.status == "p"
    # The topic-match seam ran AND received the real taxonomy (the
    # categories-threading fix — not the {} that fails the gate open).
    assert clf.topic_calls, "topic-match seam was never invoked"
    assert clf.topic_calls[0]["categories"] == _CATEGORIES

    hits = _live_hits(conn, topic.id)
    assert len(hits) == 1
    hit = hits[0]
    assert hit["account_id"] == account_id
    assert hit["rfc822_message_id"] == "<m42@example.com>"
    assert abs(hit["confidence"] - 0.88) < 1e-9
    assert "lupus" in hit["reason_terms_json"]


@pytest.mark.asyncio
async def test_no_active_topics_skips_match_and_llm(conn, seeded):
    """An account with no active Topics never invokes the matcher (no LLM
    call) and writes no hit."""
    uid, account_id = seeded
    # No topic created for this account.
    clf = _MatchClassifier(topic_id=999)

    res = await triage_single_message(
        _ctx(conn, account_id, clf), _msg(), "42",
    )

    assert res.status == "p"
    assert clf.topic_calls == [], "matcher must not run when no Topics exist"


@pytest.mark.asyncio
async def test_dry_run_does_not_fire_watches(conn, seeded, monkeypatch):
    """N-61 (Loop-5 census) — BEHAVIOURAL: a dry_run must NOT fire watches
    (real SMTP/SMS escalation + webhook POST). The structural pin
    (test_dry_run_side_effects_pin) proves the gate is PRESENT; this proves it
    WORKS at runtime (the #5 lesson — a structural pin can pass while a live
    edge is wrong). The non-dry-run contrast proves the stage is reachable
    (so the dry_run assertion isn't vacuously true)."""
    uid, account_id = seeded
    clf = _MatchClassifier(topic_id=999)  # no topic match needed here
    called: list = []

    async def _spy(**kwargs):
        called.append(kwargs)
        return []

    # fire_watches_for_message is a function-local import inside the watch-fire
    # block, so patching the source module is picked up at call time.
    monkeypatch.setattr(
        "email_triage.web.watch_runner.fire_watches_for_message", _spy,
    )

    # dry_run=True + fire_watches=True → watch-fire MUST be suppressed.
    await triage_single_message(
        _ctx(conn, account_id, clf, dry_run=True, fire_watches=True),
        _msg(), "42",
    )
    assert called == [], "dry_run fired watches — real escalation/webhook leak"

    # Contrast (non-vacuous): not dry_run + fire_watches=True → stage reached.
    await triage_single_message(
        _ctx(conn, account_id, clf, dry_run=False, fire_watches=True),
        _msg(), "43",
    )
    assert len(called) == 1, "non-dry-run must reach the watch-fire stage"


@pytest.mark.asyncio
async def test_dry_run_skips_topic_match(conn, seeded):
    """A dry-run must not match or write hits (a preview is non-persisting)."""
    uid, account_id = seeded
    topic = _make_topic(conn, uid, account_id)
    clf = _MatchClassifier(topic_id=topic.id)

    await triage_single_message(
        _ctx(conn, account_id, clf, dry_run=True), _msg(), "42",
    )

    assert clf.topic_calls == [], "dry-run must not invoke the matcher"
    assert _live_hits(conn, topic.id) == []


@pytest.mark.asyncio
async def test_match_topics_flag_off_skips(conn, seeded):
    """ctx.match_topics=False opts the path out entirely."""
    uid, account_id = seeded
    topic = _make_topic(conn, uid, account_id)
    clf = _MatchClassifier(topic_id=topic.id)

    await triage_single_message(
        _ctx(conn, account_id, clf, match_topics=False), _msg(), "42",
    )

    assert clf.topic_calls == []
    assert _live_hits(conn, topic.id) == []


@pytest.mark.asyncio
async def test_topic_match_failure_is_fail_open(conn, seeded):
    """A topic-match seam that raises degrades to no hit but NEVER breaks core
    triage (status stays 'p', no exception propagates)."""
    uid, account_id = seeded
    topic = _make_topic(conn, uid, account_id)
    clf = _MatchClassifier(topic_id=topic.id, raises=True)

    res = await triage_single_message(
        _ctx(conn, account_id, clf), _msg(), "42",
    )

    assert res.status == "p"          # core triage unaffected
    assert _live_hits(conn, topic.id) == []   # no hit on a degraded match
