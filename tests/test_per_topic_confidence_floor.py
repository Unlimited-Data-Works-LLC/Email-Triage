"""Per-Topic confidence floor (operator 2026-06-15) — model + wiring + pins.

A Topic may override the global ET_TOPIC_MATCH_CONFIDENCE_FLOOR with a per-Topic
``confidence_floor`` (NULL = inherit). The override is applied at SURFACE time in
gather_live_topic_hits (reversible). This pins:
 * the model round-trip incl. the POSITIONAL-bind tripwire (the float must land
   in confidence_floor, not a swapped column — db-sme);
 * NULL stays None (never 0.0) — the load-bearing inherit-vs-disable distinction;
 * validate() bounds [0,1];
 * PD#18 lockstep: _fire_topic_digest threads ONE effective floor into gather +
   count + the operator log (a third surface that previously hardcoded the
   global — the set-broad/log-narrow class PD#18 forbids).
"""

from __future__ import annotations

import ast

from _pin_harness import walk_src

from email_triage.actions import topic_configs as tc


def _conn():
    from _db_tracking import track
    from email_triage.web.db import init_db
    return track(init_db(":memory:"))


def _seed_user(conn) -> int:
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    return int(conn.execute(
        "INSERT INTO users (email, name, role, created_at) VALUES (?,?,?,?)",
        ("op@x.com", "Op", "user", now),
    ).lastrowid)


# ---------------------------------------------------------------------------
# Model round-trip — the positional-bind tripwire + NULL-stays-None.
# ---------------------------------------------------------------------------

def test_floor_round_trips_into_the_right_column():
    """A per-Topic floor persists + hydrates to the SAME value, in
    confidence_floor specifically (a positional-tuple swap would land it in a
    neighbour column — assert retention_days is untouched alongside)."""
    conn = _conn()
    try:
        uid = _seed_user(conn)
        saved = tc.upsert_topic(conn, tc.TopicConfig(
            user_id=uid, name="Lupus", confidence_floor=0.6, retention_days=45,
        ))
        # Raw row: the float is in confidence_floor, retention_days is distinct.
        row = conn.execute(
            "SELECT confidence_floor, retention_days FROM topics WHERE id=?",
            (saved.id,),
        ).fetchone()
        assert row["confidence_floor"] == 0.6
        assert row["retention_days"] == 45
        # Hydrated model round-trips.
        hydrated = tc.row_to_topic(conn.execute(
            "SELECT * FROM topics WHERE id=?", (saved.id,)).fetchone())
        assert hydrated.confidence_floor == 0.6
    finally:
        conn.close()


def test_blank_floor_persists_null_and_hydrates_none():
    """No per-Topic floor => SQL NULL => None on read (inherit the global
    default). MUST NOT coerce NULL to 0.0 (0.0 would surface everything)."""
    conn = _conn()
    try:
        uid = _seed_user(conn)
        saved = tc.upsert_topic(conn, tc.TopicConfig(user_id=uid, name="T"))
        raw = conn.execute(
            "SELECT confidence_floor FROM topics WHERE id=?", (saved.id,)
        ).fetchone()["confidence_floor"]
        assert raw is None                       # SQL NULL, not 0.0
        hydrated = tc.row_to_topic(conn.execute(
            "SELECT * FROM topics WHERE id=?", (saved.id,)).fetchone())
        assert hydrated.confidence_floor is None
    finally:
        conn.close()


def test_floor_update_preserves_then_clears():
    conn = _conn()
    try:
        uid = _seed_user(conn)
        t = tc.upsert_topic(conn, tc.TopicConfig(
            user_id=uid, name="T", confidence_floor=0.7))
        assert tc.row_to_topic(conn.execute(
            "SELECT * FROM topics WHERE id=?", (t.id,)).fetchone()
        ).confidence_floor == 0.7
        # Clear it back to inherit.
        t.confidence_floor = None
        tc.upsert_topic(conn, t)
        assert tc.row_to_topic(conn.execute(
            "SELECT * FROM topics WHERE id=?", (t.id,)).fetchone()
        ).confidence_floor is None
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# validate() bounds.
# ---------------------------------------------------------------------------

def test_validate_bounds_the_floor():
    base = dict(user_id=1, name="T")
    assert tc.validate(tc.TopicConfig(**base, confidence_floor=None)) == []
    assert tc.validate(tc.TopicConfig(**base, confidence_floor=0.0)) == []
    assert tc.validate(tc.TopicConfig(**base, confidence_floor=0.5)) == []
    assert tc.validate(tc.TopicConfig(**base, confidence_floor=1.0)) == []
    for bad in (1.5, -0.1, 2.0):
        errs = tc.validate(tc.TopicConfig(**base, confidence_floor=bad))
        assert any("between 0 and 1" in e for e in errs), bad


# ---------------------------------------------------------------------------
# gather honours the per-Topic value (end-to-end over persisted hits).
# ---------------------------------------------------------------------------

def test_gather_uses_the_persisted_per_topic_floor():
    conn = _conn()
    try:
        uid = _seed_user(conn)
        acct = int(conn.execute(
            "INSERT INTO email_accounts (user_id, name, provider_type, "
            "config_json, created_at, updated_at) VALUES (?,?,?,?,?,?)",
            (uid, "A", "imap", "{}", "2026-06-14T00:00:00+00:00",
             "2026-06-14T00:00:00+00:00"),
        ).lastrowid)
        topic = tc.upsert_topic(conn, tc.TopicConfig(
            user_id=uid, name="T", selected_account_ids=[acct],
            confidence_floor=0.7))
        for mid, conf in [("<a@x>", 0.9), ("<b@x>", 0.6), ("<c@x>", 0.8)]:
            tc.insert_topic_hit(conn, topic_id=topic.id, account_id=acct,
                                rfc822_message_id=mid, confidence=conf,
                                seen_at="2026-06-14T00:00:00+00:00")
        hy = tc.row_to_topic(conn.execute(
            "SELECT * FROM topics WHERE id=?", (topic.id,)).fetchone())
        ids = {h["rfc822_message_id"] for h in tc.gather_live_topic_hits(
            conn, topic.id, confidence_floor=hy.confidence_floor)}
        assert ids == {"<a@x>", "<c@x>"}        # 0.6 dropped by the 0.7 floor
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# PD#18 lockstep pin — gather + count + the suppressed log share ONE floor.
# ---------------------------------------------------------------------------

_FN = "_fire_topic_digest"


def _fire_topic_digest_floor_surfaces():
    """Return (effective_uses, hardcoded_global_uses) inside _fire_topic_digest:
    how many of the floor-bearing surfaces (gather confidence_floor=, count
    confidence_floor=, the suppressed-log confidence_floor=) reference the
    resolved per-Topic value vs the raw global SSOT constant."""
    for _p, rel, tree in walk_src():
        if rel != "web/topic_digest_sender.py":
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.AsyncFunctionDef) and node.name == _FN:
                effective = global_const = 0
                for kw in ast.walk(node):
                    if isinstance(kw, ast.keyword) and kw.arg == "confidence_floor":
                        v = kw.value
                        if isinstance(v, ast.Name) and v.id == "effective_floor":
                            effective += 1
                        elif (isinstance(v, ast.Name)
                              and v.id == "TOPIC_MATCH_CONFIDENCE_FLOOR"):
                            global_const += 1
                return effective, global_const
    return None


def test_fire_digest_threads_one_effective_floor_to_all_surfaces():
    res = _fire_topic_digest_floor_surfaces()
    assert res is not None, f"{_FN} not found in topic_digest_sender.py"
    effective, global_const = res
    # gather + count + the suppressed-log all pass effective_floor (>=3). The
    # ONLY legitimate raw-global use is the loosening-baseline count (vs default),
    # so the global constant may appear AT MOST once as a confidence_floor=.
    assert effective >= 3, (
        f"expected gather+count+log to pass effective_floor; saw {effective}"
    )
    assert global_const <= 1, (
        "a digest surface still hardcodes the GLOBAL floor instead of the "
        f"per-Topic effective_floor ({global_const} raw-global uses) — PD#18: "
        "the delivered set, the hidden-count, and the log must share one floor."
    )
