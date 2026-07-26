""" digest confidence floor — surface-time gate, pins + behaviour (2026-06-15).

The floor is applied at SURFACE time in
:func:`topic_configs.gather_live_topic_hits` (NOT at match time), reading the
persisted ``topic_hits.confidence``. This keeps it REVERSIBLE: every match is
persisted, and lowering the floor re-surfaces previously hidden hits on the next
render — where a match-time drop would cache ``matched=0`` and make the drop
permanent for already-scanned mail (operator 2026-06-15, option "reversible").

Pinned here:
* **SSOT (count-agnostic):** the ``ET_TOPIC_MATCH_CONFIDENCE_FLOOR`` env key is
  read in exactly ONE src module — no second drift-prone copy of the floor logic
  (PD#1/PD#5). Keyed on the env-key string across an AST/text walk of every src
  module, not ``len==N``.
* **Behaviour:** the surface gate drops sub-floor hits, keeps at/above, is
  reversible by re-reading at a lower floor, and fail-closes a NULL-confidence
  (legacy) row. The matcher's ``_verdict_matched`` fails closed on an absent
  flag.
"""

from __future__ import annotations

import ast

from _pin_harness import walk_src

from email_triage.actions import topic_configs as tc
from email_triage.actions.topic_configs import (
    TOPIC_MATCH_CONFIDENCE_FLOOR,
    _resolve_confidence_floor,
    count_topic_hits_below_floor,
    gather_live_topic_hits,
)
from email_triage.actions.topic_matcher import _verdict_matched

_ENV_KEY = "ET_TOPIC_MATCH_CONFIDENCE_FLOOR"


# ---------------------------------------------------------------------------
# DB helpers (full current schema; topic + hits).
# ---------------------------------------------------------------------------

def _conn():
    from _db_tracking import track
    from email_triage.web.db import init_db
    return track(init_db(":memory:"))


def _seed_user_and_account(conn) -> tuple[int, int]:
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    uid = int(conn.execute(
        "INSERT INTO users (email, name, role, created_at) VALUES (?,?,?,?)",
        ("op@x.com", "Op", "user", now),
    ).lastrowid)
    acct = int(conn.execute(
        "INSERT INTO email_accounts (user_id, name, provider_type, config_json,"
        " created_at, updated_at) VALUES (?,?,?,?,?,?)",
        (uid, "A", "imap", "{}", now, now),
    ).lastrowid)
    return uid, acct


def _seed_topic_with_hits(conn, hits: list[tuple[str, float]]) -> int:
    uid, acct = _seed_user_and_account(conn)
    topic = tc.upsert_topic(
        conn, tc.TopicConfig(user_id=uid, name="T", selected_account_ids=[acct]),
    )
    for mid, conf in hits:
        tc.insert_topic_hit(
            conn, topic_id=topic.id, account_id=acct,
            rfc822_message_id=mid, confidence=conf,
            seen_at="2026-06-14T00:00:00+00:00",
        )
    return topic.id


# ---------------------------------------------------------------------------
# Behaviour — the surface gate.
# ---------------------------------------------------------------------------

def test_gather_drops_below_floor_keeps_at_or_above():
    conn = _conn()
    try:
        tid = _seed_topic_with_hits(conn, [
            ("<hi@x>", 0.9), ("<mid@x>", 0.5), ("<lo@x>", 0.4),
        ])
        ids = {h["rfc822_message_id"]
               for h in gather_live_topic_hits(conn, tid, confidence_floor=0.5)}
        # 0.5 is inclusive; 0.4 is dropped.
        assert ids == {"<hi@x>", "<mid@x>"}
    finally:
        conn.close()


def test_gather_default_floor_is_the_ssot():
    conn = _conn()
    try:
        tid = _seed_topic_with_hits(conn, [("<hi@x>", 0.9), ("<lo@x>", 0.1)])
        # No explicit floor → the module SSOT (0.5 default) drops the 0.1 hit.
        ids = {h["rfc822_message_id"] for h in gather_live_topic_hits(conn, tid)}
        assert ids == {"<hi@x>"}
        assert TOPIC_MATCH_CONFIDENCE_FLOOR == 0.5
    finally:
        conn.close()


def test_floor_is_reversible_same_rows_lower_floor_resurfaces():
    """The reversibility guarantee: a hit hidden at 0.5 is STILL persisted and
    re-appears when the floor is lowered — no re-scan, no cache poisoning."""
    conn = _conn()
    try:
        tid = _seed_topic_with_hits(conn, [("<weak@x>", 0.3)])
        assert gather_live_topic_hits(conn, tid, confidence_floor=0.5) == []
        recovered = gather_live_topic_hits(conn, tid, confidence_floor=0.0)
        assert {h["rfc822_message_id"] for h in recovered} == {"<weak@x>"}
    finally:
        conn.close()


def test_floor_zero_disables_and_returns_all():
    conn = _conn()
    try:
        tid = _seed_topic_with_hits(conn, [("<a@x>", 0.1), ("<b@x>", 0.9)])
        ids = {h["rfc822_message_id"]
               for h in gather_live_topic_hits(conn, tid, confidence_floor=0.0)}
        assert ids == {"<a@x>", "<b@x>"}
    finally:
        conn.close()


def test_unquantified_zero_confidence_hit_fails_closed():
    """An unquantified hit lands as the schema default confidence 0.0
    (``topic_hits.confidence`` is NOT NULL, so a real NULL can't occur) →
    suppressed by any positive floor, recoverable at floor 0.0."""
    conn = _conn()
    try:
        # 0.0 = the insert_topic_hit default (an unquantified match), 0.9 = a
        # confident one.
        tid = _seed_topic_with_hits(conn, [("<zero@x>", 0.0), ("<keep@x>", 0.9)])
        ids = {h["rfc822_message_id"]
               for h in gather_live_topic_hits(conn, tid, confidence_floor=0.5)}
        assert ids == {"<keep@x>"}          # the 0.0 hit is suppressed
        ids0 = {h["rfc822_message_id"]
                for h in gather_live_topic_hits(conn, tid, confidence_floor=0.0)}
        assert "<zero@x>" in ids0           # recoverable at floor 0
    finally:
        conn.close()


def test_count_below_floor_is_the_suppressed_set():
    """Operator-visibility count: how many LIVE hits the floor hides. It is the
    exact complement of gather (gather keeps >= floor; count is < floor)."""
    conn = _conn()
    try:
        tid = _seed_topic_with_hits(conn, [
            ("<a@x>", 0.9), ("<b@x>", 0.5), ("<c@x>", 0.4), ("<d@x>", 0.1),
        ])
        # floor 0.5 surfaces {0.9, 0.5}=2, suppresses {0.4, 0.1}=2.
        surfaced = gather_live_topic_hits(conn, tid, confidence_floor=0.5)
        suppressed = count_topic_hits_below_floor(conn, tid, confidence_floor=0.5)
        assert len(surfaced) == 2
        assert suppressed == 2
        # Disabled floor hides nothing.
        assert count_topic_hits_below_floor(conn, tid, confidence_floor=0.0) == 0
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Matcher fails closed on an absent matched flag (independent of the floor).
# ---------------------------------------------------------------------------

class _Duck:
    def __init__(self, **kw):
        for k, v in kw.items():
            setattr(self, k, v)


def test_verdict_matched_fails_closed_on_absent_flag():
    assert _verdict_matched({"topic_id": 1}) is False
    assert _verdict_matched(_Duck(topic_id=1)) is False
    assert _verdict_matched({"matched": True}) is True
    assert _verdict_matched({"matched": False}) is False


# ---------------------------------------------------------------------------
# Config — env override.
# ---------------------------------------------------------------------------

def test_default_floor_value():
    assert _resolve_confidence_floor() == 0.5


def test_env_override_parsed_clamped_and_falls_back(monkeypatch):
    monkeypatch.setenv(_ENV_KEY, "0.75")
    assert _resolve_confidence_floor() == 0.75
    for bad in ("1.5", "-0.1", "high", "   "):
        monkeypatch.setenv(_ENV_KEY, bad)
        assert _resolve_confidence_floor() == 0.5


# ---------------------------------------------------------------------------
# SSOT pin — the env key is read in exactly ONE src module (no drift copy).
# ---------------------------------------------------------------------------

def _reads_env_key(tree: ast.AST) -> bool:
    """True if the module READS the env key — the key string literal passed to a
    call (``os.environ.get(KEY)`` / ``os.getenv(KEY)``) or an ``environ[KEY]``
    subscript. A bare mention in a COMMENT (not in the AST) or a DOCSTRING (an
    ``Expr`` value, not a call arg) does NOT count — only the resolution logic
    does, which is the SSOT the pin protects."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and node.value == _ENV_KEY:
            parent = getattr(node, "_ph_parent", None)
            if isinstance(parent, (ast.Call, ast.Subscript)):
                return True
    return False


def _modules_reading_env_key() -> list[str]:
    return [rel for _path, rel, tree in walk_src() if _reads_env_key(tree)]


def test_env_key_has_single_source():
    refs = _modules_reading_env_key()
    assert refs == ["actions/topic_configs.py"], (
        "the topic-match confidence-floor env key must be READ in exactly ONE "
        f"module (the SSOT resolver); found reads in: {refs}. A second copy WILL "
        "drift — import TOPIC_MATCH_CONFIDENCE_FLOOR instead."
    )


def test_env_key_pin_has_teeth():
    # Anti-vacuous: the detector flags a real read, and does NOT flag a bare
    # mention (comment/docstring/string that isn't a call arg).
    from _pin_harness import parse_source
    reads = parse_source(
        "import os\nx = os.environ.get('ET_TOPIC_MATCH_CONFIDENCE_FLOOR')\n"
    )
    mentions = parse_source(
        "'mentions ET_TOPIC_MATCH_CONFIDENCE_FLOOR in a docstring'\n"
    )
    assert _reads_env_key(reads)
    assert not _reads_env_key(mentions)
    # And the real SSOT module is detected.
    assert "actions/topic_configs.py" in _modules_reading_env_key()
