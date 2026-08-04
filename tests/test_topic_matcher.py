"""Tests for the  Topic matcher orchestration + back-scan job.

Covers ``actions/topic_matcher.py`` (the band/K orchestration) and
``jobs/topic_backscan.py`` (the historical back-scan), using a **MOCK
classifier** — no live Ollama, no live IMAP. The mock implements the classify
layer's REAL seam — ``async classify_with_topics_safe(message, categories,
list_hints, *, topic_block, model=None) -> TopicMatchResult`` — recovers the
stage + topic ids from the rendered ``topic_block`` it was handed, and returns
a real :class:`TopicMatchResult`, so the test asserts the *control flow* the
design commits to (§4.1):

(a) ``≤ K`` admitted Topics  → exactly ONE ``classify_with_topics`` call at
    ``stage='single'`` (full Details, no coarse pass).
(b) ``> K`` admitted Topics  → ``stage='coarse'`` over ALL cards, then ONE
    ``stage='rerank'`` over ONLY the coarse shortlist S (two calls).
(c) a matched verdict from the back-scan writes a ``topic_hits`` row with
    ``source='backscan'`` + the verdict's ``reason_terms`` + ``confidence``
    (and a ``study_match_cache`` row).
(d) the  enqueue-idempotency guard skips a duplicate ``topic_backscan`` job.
(e) **fail-open**: a classifier whose ``classify_with_topics`` RAISES yields NO
    hit and NO exception (a flaky GPU degrades the digest, never crashes).

The DB fixture bootstraps a fresh in-memory DB on the full current schema
via ``init_db`` (it used to clip ``MIGRATIONS`` to ``<= 40``); it bootstraps a fresh
in-memory DB (the ``test_topic_configs_roundtrip`` precedent), so the v40
Topic schema is the top of the schema under test.
"""

from __future__ import annotations

import asyncio
import inspect
import re
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone

import pytest

from email_triage.web import migrations as mig_mod
from email_triage.actions import topic_configs as tc
from email_triage.actions.topic_matcher import match_topics_for_message
from email_triage.actions.topic_prefilter import K
from email_triage.classify.base import (
    Classification,
    TopicMatchResult,
    TopicVerdict,
)
from email_triage.classify.ollama import OllamaClassifier
from email_triage.jobs import topic_backscan as bs


# ---------------------------------------------------------------------------
# Fixtures + helpers
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _restore_migrations():
    saved = list(mig_mod.MIGRATIONS)
    yield
    mig_mod.MIGRATIONS.clear()
    mig_mod.MIGRATIONS.extend(saved)


def _conn_at_v40() -> sqlite3.Connection:
    # Full current schema. (Formerly clipped MIGRATIONS to <= 40; the topic
    # model now writes digests_json at v41, so a v40-clipped schema raises
    # "no such column". Pinning a schema-dependent test to one migration
    # number is a stale-schema trap — run the live schema instead.)
    from email_triage.web.db import init_db

    from _db_tracking import track
    return track(init_db(":memory:"))


def _seed_user_and_account(conn: sqlite3.Connection) -> tuple[int, int]:
    now = datetime.now(timezone.utc).isoformat()
    cur = conn.execute(
        "INSERT INTO users (email, name, role, created_at) VALUES (?, ?, ?, ?)",
        ("op@example.com", "Op", "user", now),
    )
    uid = int(cur.lastrowid)
    cur = conn.execute(
        "INSERT INTO email_accounts ("
        "  user_id, name, provider_type, config_json, created_at, updated_at"
        ") VALUES (?, ?, ?, ?, ?, ?)",
        (uid, "Mailbox", "imap", "{}", now, now),
    )
    conn.commit()
    return uid, int(cur.lastrowid)


@dataclass
class _Msg:
    """Synthetic provider-normalised message.

    Carries the fields the matcher + back-scan read (headers + message id +
    body keywords) AND the fields the REAL ``prompts.build_email_block`` reads
    when the seam-contract tests drive the actual classify layer
    (``recipients`` / ``date`` / ``body_text``) — so a synthetic message is a
    faithful stand-in for an ``EmailMessage`` on both the mock-seam path and the
    real-seam path."""
    message_id: str
    subject: str = ""
    sender: str = "sender@example.com"
    body_keywords: list[str] = field(default_factory=list)
    folder: str = "INBOX"
    provider_uid: str | None = None
    uidvalidity: int = 0
    recipients: list[str] = field(default_factory=lambda: ["me@example.com"])
    body_text: str = ""
    date: datetime = field(
        default_factory=lambda: datetime(2026, 1, 1, tzinfo=timezone.utc)
    )

    @property
    def headers(self) -> dict[str, str]:
        return {
            "Subject": self.subject,
            "From": self.sender,
            "Message-ID": self.message_id,
        }


def _Verdict(topic_id, matched=True, confidence=0.0, reason_terms=None):
    """Build a REAL classify-layer :class:`TopicVerdict` (not a stand-in).

    The matcher reads verdicts duck-typed, but the seam now returns the real
    :class:`TopicMatchResult` carrying real :class:`TopicVerdict`\\s — so the
    test exercises the production types, not a shape that drifted from them.
    """
    return TopicVerdict(
        topic_id=topic_id,
        matched=matched,
        confidence=confidence,
        reason_terms=tuple(reason_terms or ()),
    )


#: Match a Topic line in either rendered block:
#:   coarse  →  "  [<id>] Name — terms"          (build_topic_card_block)
#:   detail  →  "  [<id>] Name / subjects / det" (build_topic_detail_block)
_TOPIC_LINE_RE = re.compile(r"^\s*\[(?P<id>[^\]]+)\]", re.MULTILINE)


def _parse_topic_block(topic_block: str) -> tuple[str, list[object]]:
    """Recover ``(kind, topic_ids)`` from a rendered ``topic_block``.

    ``kind`` is ``'coarse'`` when the block is the compact-cards block
    (``build_topic_card_block`` — its header says "compact cards"), else
    ``'detail'`` (``build_topic_detail_block``). The ids are parsed from the
    ``[<id>]`` prefix on each Topic line. The mock turns ``kind`` + call order
    into the §4.1 stage (a detail block before any coarse call = ``single``;
    after a coarse call = ``rerank``) — so the control-flow assertions read the
    REAL seam input (the prompt string), not a now-removed ``stage=`` kwarg.
    """
    kind = "coarse" if "compact cards" in topic_block else "detail"
    ids: list[object] = []
    for m in _TOPIC_LINE_RE.finditer(topic_block):
        raw = m.group("id")
        try:
            ids.append(int(raw))
        except ValueError:
            ids.append(raw)
    return kind, ids


class _MockClassifier:
    """Implements the classify layer's REAL topic-match seam + scripts verdicts.

    The seam is ``async classify_with_topics_safe(message, categories,
    list_hints, *, topic_block, model=None) -> TopicMatchResult``. The mock
    recovers the stage + topic ids from the rendered ``topic_block`` (so it does
    NOT pin a now-removed ``stage=`` kwarg — the very drift this fix closes),
    records ``(stage, card_ids, detail_ids, model)`` per call for the control-
    flow assertions, and returns a real :class:`TopicMatchResult`.

    ``script`` maps a ``stage`` (``'single'`` / ``'coarse'`` / ``'rerank'``) to
    the verdict list for that stage. ``raises`` makes every call raise — but the
    REAL seam is the *safe* wrapper which never raises, so the mock mirrors that:
    a "raise" is modelled as the safe wrapper swallowing it and returning an
    empty-verdict result (exactly the production fail-open the matcher relies
    on)."""

    def __init__(self, *, script=None, raises=False):
        self.script = script or {}
        self.raises = raises
        self.calls: list[dict] = []
        self._coarse_seen = False
        # the matcher reads .categories / .list_hints off the classifier; an
        # empty dict / None are both fine for a topic-only test.
        self.categories: dict[str, str] = {}
        self.list_hints = None

    async def classify_with_topics_safe(
        self, message, categories, list_hints,
        *, topic_block, model=None,
    ):
        kind, ids = _parse_topic_block(topic_block)
        if kind == "coarse":
            stage = "coarse"
            self._coarse_seen = True
        else:
            # A detail block is the single-call band unless a coarse pass
            # already ran this message — then it's the Stage-B rerank.
            stage = "rerank" if self._coarse_seen else "single"
        self.calls.append({
            "stage": stage,
            "card_ids": ids if kind == "coarse" else [],
            "detail_ids": ids if kind == "detail" else [],
            "model": model,
        })
        # The SAFE wrapper never raises: a simulated failure falls open to an
        # empty-verdict result, just like the production wrapper.
        verdicts = [] if self.raises else list(self.script.get(stage, []))
        return TopicMatchResult(
            classification=Classification(
                category="other", confidence=0.5, reason="", source="llm",
            ),
            topic_verdicts=verdicts,
        )


def _make_topics(conn, uid, acct, n: int) -> list[tc.TopicConfig]:
    """Create ``n`` distinct Topics with their own discriminating terms."""
    out = []
    for i in range(n):
        cfg = tc.upsert_topic(conn, tc.TopicConfig(
            user_id=uid, name=f"Topic-{i}",
            subjects=[f"keyword{i}", f"acronym{i}"],
            details=f"study about subject number {i} and condition{i}",
            selected_account_ids=[acct],
        ))
        out.append(cfg)
    return out


# ---------------------------------------------------------------------------
# (a) ≤ K candidates → exactly ONE classify_with_topics call (stage='single')
# ---------------------------------------------------------------------------

class TestSingleCallBand:
    def test_le_k_runs_one_single_stage_call(self):
        conn = _conn_at_v40()
        try:
            uid, acct = _seed_user_and_account(conn)
            topics = _make_topics(conn, uid, acct, K)  # exactly K ≤ K
            t0 = topics[0]
            clf = _MockClassifier(script={
                "single": [_Verdict(topic_id=t0.id, matched=True,
                                    confidence=0.8, reason_terms=["keyword0"])],
            })
            msg = _Msg(message_id="<a@x>", subject="about keyword0",
                       body_keywords=["keyword0"])

            verdicts = asyncio.run(match_topics_for_message(
                msg, topics, clf, body_keywords=["keyword0"],
            ))

            # Exactly ONE call, at stage='single', carrying full Details (no
            # coarse cards).
            assert len(clf.calls) == 1
            assert clf.calls[0]["stage"] == "single"
            assert clf.calls[0]["card_ids"] == []
            assert len(clf.calls[0]["detail_ids"]) == K
            # The matched verdict comes back.
            assert len(verdicts) == 1
            assert verdicts[0].topic_id == t0.id
        finally:
            conn.close()

    def test_single_topic_is_single_call(self):
        conn = _conn_at_v40()
        try:
            uid, acct = _seed_user_and_account(conn)
            topics = _make_topics(conn, uid, acct, 1)
            clf = _MockClassifier(script={"single": [
                _Verdict(topic_id=topics[0].id, matched=True, confidence=0.5),
            ]})
            msg = _Msg(message_id="<b@x>")
            asyncio.run(match_topics_for_message(
                msg, topics, clf, body_keywords=[],
            ))
            assert [c["stage"] for c in clf.calls] == ["single"]
        finally:
            conn.close()


# ---------------------------------------------------------------------------
# (a2) The matcher returns EVERY matched verdict with its confidence — it does
# NOT apply the digest confidence floor (that is a SURFACE-time gate in
# gather_live_topic_hits, kept reversible). It DOES fail closed on a verdict
# with no explicit ``matched`` flag.
# ---------------------------------------------------------------------------

class TestMatcherPersistsAllMatched:
    def test_low_confidence_match_is_still_returned(self):
        conn = _conn_at_v40()
        try:
            uid, acct = _seed_user_and_account(conn)
            topics = _make_topics(conn, uid, acct, K)
            low, high = topics[0], topics[1]
            clf = _MockClassifier(script={"single": [
                _Verdict(topic_id=low.id, matched=True, confidence=0.1),
                _Verdict(topic_id=high.id, matched=True, confidence=0.9),
            ]})
            msg = _Msg(message_id="<persist@x>", body_keywords=[])

            # BOTH matched verdicts come back (no match-time floor) — the floor
            # lives at the digest surface, so the 0.1 hit is still persisted and
            # recoverable by lowering the floor.
            verdicts = asyncio.run(match_topics_for_message(
                msg, topics, clf, body_keywords=[],
            ))
            assert {v.topic_id for v in verdicts} == {low.id, high.id}
        finally:
            conn.close()


# ---------------------------------------------------------------------------
# (b) > K candidates → coarse then rerank (rerank only on the shortlist)
# ---------------------------------------------------------------------------

class TestTwoStageBand:
    def test_gt_k_runs_coarse_then_rerank_on_shortlist_only(self):
        conn = _conn_at_v40()
        try:
            uid, acct = _seed_user_and_account(conn)
            n = K + 3  # > K → two-stage
            topics = _make_topics(conn, uid, acct, n)
            # Coarse shortlist S = two of the Topics (matched=True); the rest
            # are matched=False and must NOT reach the rerank Details.
            short_a, short_b = topics[1].id, topics[4].id
            clf = _MockClassifier(script={
                "coarse": [
                    _Verdict(topic_id=short_a, matched=True, confidence=0.6),
                    _Verdict(topic_id=short_b, matched=True, confidence=0.7),
                    _Verdict(topic_id=topics[2].id, matched=False),
                ],
                "rerank": [
                    _Verdict(topic_id=short_a, matched=True, confidence=0.9,
                             reason_terms=["keyword1"]),
                    _Verdict(topic_id=short_b, matched=False),
                ],
            })
            msg = _Msg(message_id="<c@x>", body_keywords=[])

            verdicts = asyncio.run(match_topics_for_message(
                msg, topics, clf, body_keywords=[],
            ))

            # TWO calls: coarse over ALL admitted cards, then rerank.
            assert [c["stage"] for c in clf.calls] == ["coarse", "rerank"]
            # Coarse carried CARDS for every admitted Topic, no details.
            assert len(clf.calls[0]["card_ids"]) == n
            assert clf.calls[0]["detail_ids"] == []
            # Rerank carried DETAILS for ONLY the shortlist S (the matched
            # coarse verdicts), no cards.
            assert clf.calls[1]["card_ids"] == []
            assert set(clf.calls[1]["detail_ids"]) == {short_a, short_b}
            # Final matched verdicts = the rerank's matched set (short_a only).
            assert {v.topic_id for v in verdicts} == {short_a}
        finally:
            conn.close()

    def test_gt_k_empty_shortlist_skips_rerank(self):
        conn = _conn_at_v40()
        try:
            uid, acct = _seed_user_and_account(conn)
            topics = _make_topics(conn, uid, acct, K + 2)
            # Coarse returns nothing matched → no rerank, no verdicts.
            clf = _MockClassifier(script={"coarse": [], "rerank": [
                _Verdict(topic_id=topics[0].id, matched=True),  # never used
            ]})
            msg = _Msg(message_id="<d@x>")
            verdicts = asyncio.run(match_topics_for_message(
                msg, topics, clf, body_keywords=[],
            ))
            assert [c["stage"] for c in clf.calls] == ["coarse"]
            assert verdicts == []
        finally:
            conn.close()


# ---------------------------------------------------------------------------
# (c) a matched verdict writes a topic_hit (source='backscan' + terms + conf)
# ---------------------------------------------------------------------------

class _AppState:
    def __init__(self, classifier):
        self.classifier = classifier
        self.config = object()
        self.secrets = object()


class _App:
    def __init__(self, classifier):
        self.state = _AppState(classifier)


async def _one_batch_fetcher(messages):
    """An injectable fetcher async-generator yielding ONE batch."""
    yield list(messages)


def _claim_job(conn, job_id):
    """Flip a queued job to running + return its row as a plain dict (the
    shape the bulk-runner hands the worker)."""
    conn.execute(
        "UPDATE triage_jobs SET status='running' WHERE job_id=?", (job_id,),
    )
    conn.commit()
    row = conn.execute(
        "SELECT * FROM triage_jobs WHERE job_id=?", (job_id,),
    ).fetchone()
    return {k: row[k] for k in row.keys()}


class TestBackscanWritesHit:
    def test_matched_verdict_writes_backscan_hit(self):
        conn = _conn_at_v40()
        try:
            uid, acct = _seed_user_and_account(conn)
            topic = tc.upsert_topic(conn, tc.TopicConfig(
                user_id=uid, name="Lupus", subjects=["SELENA", "lupus"],
                details="Safety of Estrogens in Lupus", selected_account_ids=[acct],
            ))
            clf = _MockClassifier(script={"single": [
                _Verdict(topic_id=topic.id, matched=True, confidence=0.91,
                         reason_terms=["lupus", "SELENA"]),
            ]})
            app = _App(clf)
            job_id = bs.enqueue_topic_backscan(
                conn, topic_id=topic.id, account_id=acct,
                actor_user_id=uid, window_days=30,
            )
            job = _claim_job(conn, job_id)
            msg = _Msg(message_id="<hit@x>", subject="re lupus",
                       body_keywords=["lupus"], folder="INBOX",
                       provider_uid="42", uidvalidity=7)

            asyncio.run(bs.run_topic_backscan_job(
                app, conn, job,
                fetcher_batches=_one_batch_fetcher([msg]),
            ))

            row = conn.execute(
                "SELECT source, reason_terms_json, confidence, folder, "
                "       provider_uid, uidvalidity FROM topic_hits "
                "WHERE topic_id=? AND rfc822_message_id=?",
                (topic.id, "<hit@x>"),
            ).fetchone()
            assert row is not None
            assert row["source"] == "backscan"
            assert row["confidence"] == 0.91
            assert "lupus" in row["reason_terms_json"]
            assert "SELENA" in row["reason_terms_json"]
            assert row["folder"] == "INBOX"
            assert row["provider_uid"] == "42"
            assert row["uidvalidity"] == 7

            # And a matched study_match_cache row was written.
            crow = conn.execute(
                "SELECT matched, confidence FROM study_match_cache "
                "WHERE topic_id=? AND rfc822_message_id=?",
                (topic.id, "<hit@x>"),
            ).fetchone()
            assert crow is not None
            assert crow["matched"] == 1
            assert crow["confidence"] == 0.91

            # The job finished done.
            jrow = conn.execute(
                "SELECT status FROM triage_jobs WHERE job_id=?", (job_id,),
            ).fetchone()
            assert jrow["status"] == "done"
        finally:
            conn.close()

    def test_no_match_writes_cache_but_no_hit(self):
        conn = _conn_at_v40()
        try:
            uid, acct = _seed_user_and_account(conn)
            topic = tc.upsert_topic(conn, tc.TopicConfig(
                user_id=uid, name="Lupus", subjects=["lupus"],
                selected_account_ids=[acct],
            ))
            # classifier returns no matched verdict.
            clf = _MockClassifier(script={"single": []})
            app = _App(clf)
            job_id = bs.enqueue_topic_backscan(
                conn, topic_id=topic.id, account_id=acct,
                actor_user_id=uid, window_days=30,
            )
            job = _claim_job(conn, job_id)
            msg = _Msg(message_id="<nomatch@x>", body_keywords=[])
            asyncio.run(bs.run_topic_backscan_job(
                app, conn, job,
                fetcher_batches=_one_batch_fetcher([msg]),
            ))
            # No hit row.
            assert conn.execute(
                "SELECT COUNT(*) FROM topic_hits WHERE topic_id=?", (topic.id,),
            ).fetchone()[0] == 0
            # A matched=0 cache row so a re-preview skips this message.
            crow = conn.execute(
                "SELECT matched FROM study_match_cache "
                "WHERE topic_id=? AND rfc822_message_id=?",
                (topic.id, "<nomatch@x>"),
            ).fetchone()
            assert crow is not None and crow["matched"] == 0
        finally:
            conn.close()


# ---------------------------------------------------------------------------
# (d) the  enqueue-idempotency guard skips a duplicate
# ---------------------------------------------------------------------------

class TestEnqueueIdempotencyGuard:
    def test_second_enqueue_is_skipped_while_one_in_flight(self):
        conn = _conn_at_v40()
        try:
            uid, acct = _seed_user_and_account(conn)
            topic = tc.upsert_topic(conn, tc.TopicConfig(
                user_id=uid, name="T", selected_account_ids=[acct],
            ))

            first = bs.enqueue_topic_backscan(
                conn, topic_id=topic.id, account_id=acct,
                actor_user_id=uid, window_days=30,
            )
            assert first is not None

            # A second enqueue while the first is still queued is SKIPPED.
            second = bs.enqueue_topic_backscan(
                conn, topic_id=topic.id, account_id=acct,
                actor_user_id=uid, window_days=60,
            )
            assert second is None

            # Exactly one topic_backscan job exists.
            n = conn.execute(
                "SELECT COUNT(*) FROM triage_jobs WHERE kind='topic_backscan'",
            ).fetchone()[0]
            assert n == 1

            # Once the first reaches a terminal status, a new one CAN queue.
            conn.execute(
                "UPDATE triage_jobs SET status='done' WHERE job_id=?", (first,),
            )
            conn.commit()
            third = bs.enqueue_topic_backscan(
                conn, topic_id=topic.id, account_id=acct,
                actor_user_id=uid, window_days=30,
            )
            assert third is not None
            assert conn.execute(
                "SELECT COUNT(*) FROM triage_jobs WHERE kind='topic_backscan'",
            ).fetchone()[0] == 2
        finally:
            conn.close()


# ---------------------------------------------------------------------------
# (e) fail-open — a classifier that raises yields NO hit + no exception
# ---------------------------------------------------------------------------

class TestFailOpen:
    def test_matcher_raising_classifier_yields_no_verdicts(self):
        conn = _conn_at_v40()
        try:
            uid, acct = _seed_user_and_account(conn)
            topics = _make_topics(conn, uid, acct, 2)
            clf = _MockClassifier(raises=True)
            msg = _Msg(message_id="<e@x>", body_keywords=["keyword0"])
            # No exception propagates; empty result.
            verdicts = asyncio.run(match_topics_for_message(
                msg, topics, clf, body_keywords=["keyword0"],
            ))
            assert verdicts == []
        finally:
            conn.close()

    def test_backscan_raising_classifier_writes_no_hit_and_finishes(self):
        conn = _conn_at_v40()
        try:
            uid, acct = _seed_user_and_account(conn)
            topic = tc.upsert_topic(conn, tc.TopicConfig(
                user_id=uid, name="T", subjects=["lupus"],
                selected_account_ids=[acct],
            ))
            clf = _MockClassifier(raises=True)
            app = _App(clf)
            job_id = bs.enqueue_topic_backscan(
                conn, topic_id=topic.id, account_id=acct,
                actor_user_id=uid, window_days=30,
            )
            job = _claim_job(conn, job_id)
            msg = _Msg(message_id="<fo@x>", body_keywords=["lupus"])

            # Must NOT raise — the back-scan drains cleanly despite the flaky
            # classifier.
            asyncio.run(bs.run_topic_backscan_job(
                app, conn, job,
                fetcher_batches=_one_batch_fetcher([msg]),
            ))

            # No hit written (fail-closed on the match).
            assert conn.execute(
                "SELECT COUNT(*) FROM topic_hits WHERE topic_id=?", (topic.id,),
            ).fetchone()[0] == 0
            # The scanned message got a matched=0 cache row (we still scanned it).
            crow = conn.execute(
                "SELECT matched FROM study_match_cache "
                "WHERE topic_id=? AND rfc822_message_id=?",
                (topic.id, "<fo@x>"),
            ).fetchone()
            assert crow is not None and crow["matched"] == 0
            # The job still finished 'done' (the matcher's fail-open means the
            # drain itself never errored).
            jrow = conn.execute(
                "SELECT status FROM triage_jobs WHERE job_id=?", (job_id,),
            ).fetchone()
            assert jrow["status"] == "done"
        finally:
            conn.close()


# ---------------------------------------------------------------------------
# (f) + (g) — DRIFT CATCHERS against the REAL classify-layer seam.
#
# These are the tests that would have CAUGHT the  production bug: the matcher
# called ``classify_with_topics(... topic_cards=, topic_details=, stage=)``
# SYNCHRONOUSLY against a signature that does not exist, the un-awaited coroutine
# was swallowed by fail-open as "zero verdicts", and the SYNC mock with the wrong
# signature passed green while production matched nothing. The mock-the-boundary
# rule (pattern_parallel_build_mock_the_boundary_not_the_seam): mock the LOWEST
# external boundary (``_chat_topics`` / the HTTP transport) and drive the REAL
# cross-module seam — plus an ``inspect.signature`` contract check — so the
# caller's kwargs are proven accepted and a verdict flows end-to-end.
# ---------------------------------------------------------------------------

#: Raw JSON an Ollama would return for a topic-match call: the classification
#: object PLUS the optional ``topic_verdicts`` array. Drives the REAL
#: ``_parse_llm_json`` + ``_parse_topic_verdicts`` path inside the real seam.
def _topic_match_json(topic_id, *, matched=True, confidence=0.9,
                      reason_terms=("lupus",)):
    import json
    return json.dumps({
        "category": "newsletter",
        "confidence": 0.8,
        "reason": "concerns the user's research topic",
        "topic_verdicts": [{
            "topic_id": topic_id,
            "matched": matched,
            "confidence": confidence,
            "reason_terms": list(reason_terms),
        }],
    })


class _StubChatOllama(OllamaClassifier):
    """A REAL OllamaClassifier with ONLY the lowest external boundary stubbed.

    The whole topic-match seam — ``classify_with_topics_safe`` →
    ``classify_with_topics`` → ``build_topic_match_prompt`` → ``_parse_llm_json``
    → ``_parse_topic_verdicts`` → ``TopicMatchResult`` — runs FOR REAL; only the
    HTTP ``_chat_topics`` transport (the network) is replaced by a canned
    response. This exercises the production seam end-to-end with no live Ollama.
    ``categories`` must be non-empty + contain the JSON's category, else the real
    method fails the taxonomy gate and falls open (no verdicts)."""

    def __init__(self, response_json: str):
        super().__init__(prefer_loaded=False, base_url="http://localhost:11434")
        self._response_json = response_json
        self.topic_prompts: list[str] = []
        self.categories = {"newsletter": "newsletters", "other": "other"}
        self.list_hints = None

    async def _resolve_model(self) -> str:  # no network probe in the test
        return self._model

    async def _chat_topics(self, prompt: str, model: str) -> str:
        # The lowest external boundary — the only thing stubbed.
        self.topic_prompts.append(prompt)
        return self._response_json


class TestSeamContract:
    def test_matcher_kwargs_are_accepted_by_real_safe_seam(self):
        """CONTRACT: the exact kwargs the matcher passes to the seam are
        accepted by the REAL ``OllamaClassifier.classify_with_topics_safe``.

        This is the signature-level guard the SYNC mock defeated: if the matcher
        ever again passes ``topic_cards=/topic_details=/stage=`` (or drops the
        keyword-only ``topic_block``), ``bind()`` raises here — green-on-broken
        becomes red."""
        sig = inspect.signature(OllamaClassifier.classify_with_topics_safe)
        # The kwargs the matcher actually passes (see _safe_classify_with_topics).
        sig.bind(
            object(),            # self
            object(),            # message
            {},                  # categories
            None,                # list_hints
            topic_block="Topics (full details ...):",
            model=None,
        )
        # And the OLD (buggy) kwargs must NOT bind — proving the drift is gone.
        with pytest.raises(TypeError):
            sig.bind(
                object(), object(), {}, None,
                topic_cards=[], topic_details=[], stage="single",
            )
        # The seam is a coroutine function (must be awaited, not called sync —
        # the un-awaited call was the production bug).
        assert inspect.iscoroutinefunction(
            OllamaClassifier.classify_with_topics_safe
        )

    def test_matcher_drives_real_seam_end_to_end(self):
        """The matcher, driving the REAL OllamaClassifier seam (only the HTTP
        transport stubbed), runs the single-call band and a verdict flows all
        the way back through the real ``TopicMatchResult``."""
        conn = _conn_at_v40()
        try:
            uid, acct = _seed_user_and_account(conn)
            topics = _make_topics(conn, uid, acct, 1)
            tid = topics[0].id
            clf = _StubChatOllama(_topic_match_json(tid))
            msg = _Msg(message_id="<seam@x>", subject="lupus study",
                       body_keywords=["lupus"])

            verdicts = asyncio.run(match_topics_for_message(
                msg, topics, clf, body_keywords=["lupus"],
            ))

            # The REAL seam produced a single matched verdict for the Topic.
            assert len(verdicts) == 1
            assert verdicts[0].topic_id == tid
            assert verdicts[0].matched is True
            # The real topic-match prompt was assembled + carried the Topic id.
            assert clf.topic_prompts and f"[{tid}]" in clf.topic_prompts[0]
        finally:
            conn.close()


class TestSeamHappyPath:
    def test_matching_message_yields_nonempty_verdict_via_real_method(self):
        """HAPPY PATH against the REAL method path: a matching message produces
        a NON-EMPTY verdict — so fail-open is NOT the only behaviour exercised.

        The original bug hid precisely because only fail-open (→ empty) paths
        were tested; a real match returning verdicts is the load-bearing
        assertion that the seam actually carries data through."""
        conn = _conn_at_v40()
        try:
            uid, acct = _seed_user_and_account(conn)
            topic = tc.upsert_topic(conn, tc.TopicConfig(
                user_id=uid, name="Lupus", subjects=["lupus", "SELENA"],
                details="Safety of Estrogens in Lupus",
                selected_account_ids=[acct],
            ))
            clf = _StubChatOllama(_topic_match_json(
                topic.id, confidence=0.93, reason_terms=["lupus", "SELENA"],
            ))
            msg = _Msg(message_id="<hp@x>", subject="re lupus",
                       body_keywords=["lupus"])

            verdicts = asyncio.run(match_topics_for_message(
                msg, [topic], clf, body_keywords=["lupus"],
            ))

            assert verdicts, "real-method happy path must yield a verdict"
            v = verdicts[0]
            assert v.topic_id == topic.id
            assert v.matched is True
            assert v.confidence == 0.93
            assert "lupus" in v.reason_terms and "SELENA" in v.reason_terms
        finally:
            conn.close()


class _ProdShapedOllama(OllamaClassifier):
    """A REAL OllamaClassifier built the way PRODUCTION builds it — with NO
    ``.categories`` attribute.

    ``_build_classifier_from_config`` (``web/routers/ui/_shared.py``) never
    stamps ``.categories`` on the instance: categories are a classify *call
    argument*, not an instance attr. ``_StubChatOllama`` hand-sets
    ``self.categories`` and so MASKED the  categories-threading bug — the
    real classifier carries none, the matcher's classifier-resolution fallback
    yields ``{}``, and the topic-match taxonomy gate fails every match open
    (zero verdicts on every path). This fixture reproduces that production
    shape; only the network boundary is stubbed.
    """

    def __init__(self, response_json: str):
        super().__init__(prefer_loaded=False, base_url="http://localhost:11434")
        self._response_json = response_json
        # DELIBERATELY no self.categories / self.list_hints — mirrors prod.

    async def _resolve_model(self) -> str:  # no network probe
        return self._model

    async def _chat_topics(self, prompt: str, model: str) -> str:
        return self._response_json

    async def classify(self, message, categories, list_hints=None):
        # The fail-open fallback inside ``classify_with_topics_safe`` re-derives
        # a bare classification via this method. In the no-categories repro the
        # real classify would ALSO trip the empty-taxonomy gate; stub it to
        # raise (no network / no Redis) so the test stays hermetic. The matcher
        # fail-opens to [] regardless, which is the production behaviour the
        # repro asserts. On the WITH-categories path the topic gate passes, so
        # this fallback is never reached.
        raise RuntimeError("classify stubbed in test")


class TestCategoriesThreadingProdShape:
    """ categories-threading regression — driven by the PRODUCTION-shaped
    classifier (no ``.categories``), not a stub that hand-sets it.

    The matcher re-classifies inside the topic-match seam. Pre-2026-06-11 that
    seam's taxonomy gate DROPPED every verdict when the parsed core category was
    off-taxonomy, and production's classifier carries NO ``.categories`` → the
    fallback resolved to ``{}`` → every category off-taxonomy → ZERO verdicts on
    every path. The §4.4 DECOUPLE (2026-06-11) removed that coupling: an
    off-taxonomy core category now keeps the verdicts (neutral sentinel), so
    matching no longer DEPENDS on the taxonomy. Threading the real
    ``categories=`` is still correct (it yields a real in-taxonomy core
    category — sibling test), just no longer load-bearing for matching. These
    two tests pin both directions post-decouple.
    """

    def test_no_categories_arg_prod_classifier_still_yields_verdicts(self):
        """POST-DECOUPLE (§4.4, 2026-06-11): a prod-shaped classifier (no
        ``.categories``) + no ``categories=`` arg resolves to ``{}``, so the core
        category is off-taxonomy — but the decouple no longer DROPS the verdicts
        for that. They survive with a neutral sentinel core category.

        (Pre-decouple this yielded ZERO — the  categories-threading symptom
        that made matching dead on every path. Threading ``categories=`` is
        still correct for the in-taxonomy core category — see the sibling test —
        but topic MATCHING no longer DEPENDS on it.)"""
        conn = _conn_at_v40()
        try:
            uid, acct = _seed_user_and_account(conn)
            topics = _make_topics(conn, uid, acct, 1)
            tid = topics[0].id
            clf = _ProdShapedOllama(_topic_match_json(tid))
            msg = _Msg(message_id="<noc@x>", subject="lupus study",
                       body_keywords=["lupus"])

            verdicts = asyncio.run(match_topics_for_message(
                msg, topics, clf, body_keywords=["lupus"],
            ))

            # DECOUPLE: the canned category ("newsletter") is off-taxonomy
            # against {}, but the verdicts are KEPT (neutral sentinel), not
            # dropped — the matcher is now robust to a missing/empty taxonomy.
            assert len(verdicts) == 1
            assert verdicts[0].topic_id == tid
            assert verdicts[0].matched is True
        finally:
            conn.close()

    def test_categories_arg_threads_through_prod_classifier(self):
        """FIX: the SAME prod-shaped classifier, now handed the real
        ``categories=`` (the canned category is a member), carries the verdict
        all the way through the real seam."""
        conn = _conn_at_v40()
        try:
            uid, acct = _seed_user_and_account(conn)
            topics = _make_topics(conn, uid, acct, 1)
            tid = topics[0].id
            clf = _ProdShapedOllama(_topic_match_json(tid))
            msg = _Msg(message_id="<wc@x>", subject="lupus study",
                       body_keywords=["lupus"])

            verdicts = asyncio.run(match_topics_for_message(
                msg, topics, clf, body_keywords=["lupus"],
                categories={"newsletter": "newsletters", "other": "other"},
            ))

            assert len(verdicts) == 1
            assert verdicts[0].topic_id == tid
            assert verdicts[0].matched is True
        finally:
            conn.close()


class TestOffTaxonomyDecouple:
    """§4.4 DECOUPLE (2026-06-11): an off-taxonomy CORE category must NOT discard
    valid topic_verdicts on the topic-match path. The core category is incidental
    here (consumers read only verdicts) and the LLM free-forms generic core slugs
    on this prompt (live: 225 off-taxonomy/2h). RED before the fix (verdicts
    dropped → "topic digest finds no matches"), GREEN after. Drives the REAL seam
    via _StubChatOllama (only the HTTP boundary stubbed)."""

    @staticmethod
    def _offtax_json(topic_id, *, matched=True):
        import json
        return json.dumps({
            "category": "security_alert",   # NOT in the stub taxonomy
            "confidence": 0.8,
            "reason": "a generic core slug the LLM free-forms on this prompt",
            "topic_verdicts": [{
                "topic_id": topic_id, "matched": matched,
                "confidence": 0.9, "reason_terms": ["lupus"],
            }],
        })

    def test_off_taxonomy_category_keeps_verdicts(self):
        conn = _conn_at_v40()
        try:
            uid, acct = _seed_user_and_account(conn)
            topics = _make_topics(conn, uid, acct, 1)
            tid = topics[0].id
            clf = _StubChatOllama(self._offtax_json(tid))
            # 'security_alert' is NOT in clf.categories — pre-fix this tripped
            # the gate (raise → fail-open → 0 verdicts). Post-decouple the
            # verdicts survive with a neutral sentinel core category.
            assert "security_alert" not in clf.categories
            msg = _Msg(message_id="<offtax@x>", subject="lupus study",
                       body_keywords=["lupus"])
            verdicts = asyncio.run(match_topics_for_message(
                msg, topics, clf, body_keywords=["lupus"],
                categories=clf.categories,
            ))
            assert len(verdicts) == 1
            assert verdicts[0].topic_id == tid
            assert verdicts[0].matched is True
        finally:
            conn.close()

    def test_parse_failure_still_drops_verdicts(self):
        """A genuine JSON-parse failure STILL drops (fail-closed on match) —
        the decouple only changed the off-taxonomy-CATEGORY branch."""
        conn = _conn_at_v40()
        try:
            uid, acct = _seed_user_and_account(conn)
            topics = _make_topics(conn, uid, acct, 1)
            clf = _StubChatOllama("not json at all {{{ <<<")
            msg = _Msg(message_id="<garble@x>", subject="lupus",
                       body_keywords=["lupus"])
            verdicts = asyncio.run(match_topics_for_message(
                msg, topics, clf, body_keywords=["lupus"],
                categories=clf.categories,
            ))
            assert verdicts == []
        finally:
            conn.close()


class _ScriptedChatOllama(OllamaClassifier):
    """REAL OllamaClassifier with ONLY ``_chat_topics`` scripted per-call.

    Each script item is a response STRING (returned) or an Exception (raised);
    the last item repeats. ``calls`` counts the boundary so the 2026-06-14
    retry invariants are pinned BEHAVIORALLY, not just by reasoning (db-sme NIT):
    the retry is bounded at exactly one extra call, and a transport failure is
    never retried as a parse failure.
    """

    def __init__(self, script):
        super().__init__(prefer_loaded=False, base_url="http://localhost:11434")
        self._script = list(script)
        self.calls = 0
        self.categories = {"other": "other", "newsletter": "newsletters"}
        self.list_hints = None

    async def _resolve_model(self) -> str:
        return self._model

    async def _chat_topics(self, prompt: str, model: str) -> str:
        item = self._script[min(self.calls, len(self._script) - 1)]
        self.calls += 1
        if isinstance(item, Exception):
            raise item
        return item


_VALID_TM = (
    '{"category": "other", "confidence": 0.8, "reason": "r", '
    '"topic_verdicts": [{"topic_id": 1, "matched": true, '
    '"confidence": 0.9, "reason_terms": ["lupus"]}]}'
)
_GARBLE_TM = "not json at all {{{ <<<"


class TestTopicMatchParseRetry:
    """The bounded single retry on a topic-match parse failure (2026-06-14
    'rtx 5090' fix). qwen3.x under ``format:json`` intermittently stops
    mid-object (``done_reason='stop'``); ONE re-roll at temp 0.3 usually returns
    clean JSON. Pins the invariants the db-sme certified by reasoning."""

    @staticmethod
    def _msg():
        return _Msg(message_id="<retry@x>", subject="lupus study",
                    body_keywords=["lupus"], body_text="lupus nephritis cohort")

    def test_retry_after_parse_failure_then_success(self):
        clf = _ScriptedChatOllama([_GARBLE_TM, _VALID_TM])
        res = asyncio.run(clf.classify_with_topics(
            self._msg(), clf.categories, None, topic_block="Topics: [1] Lupus",
        ))
        assert clf.calls == 2          # one failure + one successful retry
        assert [v.topic_id for v in res.topic_verdicts] == [1]

    def test_retry_bounded_at_two_calls_then_raises(self):
        clf = _ScriptedChatOllama([_GARBLE_TM, _GARBLE_TM])
        with pytest.raises(Exception):
            asyncio.run(clf.classify_with_topics(
                self._msg(), clf.categories, None,
                topic_block="Topics: [1] Lupus",
            ))
        assert clf.calls == 2          # bounded — exactly one retry, never a loop

    def test_transport_failure_on_first_call_is_not_retried(self):
        from email_triage.llm_health import LLMBackendUnreachableError
        clf = _ScriptedChatOllama(
            [LLMBackendUnreachableError("ollama", "localhost", 11434), _VALID_TM]
        )
        with pytest.raises(LLMBackendUnreachableError):
            asyncio.run(clf.classify_with_topics(
                self._msg(), clf.categories, None,
                topic_block="Topics: [1] Lupus",
            ))
        assert clf.calls == 1          # transport error propagates, NO parse retry

    def test_counters_track_retry_outcomes(self):
        # N-93 F1: the §4.4 fail-open valve's open-rate is a NUMBER, not a
        # log-grep. Delta-based (the counter is a process singleton other tests
        # may also touch).
        from email_triage.classify.base import get_topic_match_counters
        c = get_topic_match_counters()
        before = c.snapshot()
        # garble -> valid: parse_retried + retry_recovered both +1, no drop.
        asyncio.run(_ScriptedChatOllama([_GARBLE_TM, _VALID_TM]).classify_with_topics(
            self._msg(), {"other": "other"}, None, topic_block="Topics: [1] Lupus",
        ))
        mid = c.snapshot()
        assert mid["parse_retried"] == before["parse_retried"] + 1
        assert mid["retry_recovered"] == before["retry_recovered"] + 1
        assert mid["retry_failed_dropped"] == before["retry_failed_dropped"]
        # garble -> garble: parse_retried + retry_failed_dropped both +1.
        with pytest.raises(Exception):
            asyncio.run(_ScriptedChatOllama([_GARBLE_TM, _GARBLE_TM]).classify_with_topics(
                self._msg(), {"other": "other"}, None, topic_block="Topics: [1] Lupus",
            ))
        after = c.snapshot()
        assert after["parse_retried"] == mid["parse_retried"] + 1
        assert after["retry_failed_dropped"] == mid["retry_failed_dropped"] + 1
        assert after["retry_recovered"] == mid["retry_recovered"]

    def test_salvage_recovered_counts_first_try_recovery(self):
        # DA N-93 canary: a response that recovers on the FIRST parse via the
        # lenient/salvage tier (here a raw newline inside `reason`) bumps
        # salvage_recovered WITHOUT a retry -> the schema-degradation signal is
        # visible even when parse_retried stays flat.
        from email_triage.classify.base import get_topic_match_counters
        c = get_topic_match_counters()
        before = c.snapshot()
        salvageable = (
            '{"category": "other", "confidence": 0.8, "reason": "a\nb", '
            '"topic_verdicts": [{"topic_id": 1, "matched": true, '
            '"confidence": 0.9, "reason_terms": ["lupus"]}]}'
        )
        res = asyncio.run(_ScriptedChatOllama([salvageable]).classify_with_topics(
            self._msg(), {"other": "other"}, None, topic_block="Topics: [1] Lupus",
        ))
        after = c.snapshot()
        assert after["salvage_recovered"] == before["salvage_recovered"] + 1
        assert after["parse_retried"] == before["parse_retried"]   # no retry needed
        assert [v.topic_id for v in res.topic_verdicts] == [1]      # verdicts kept
