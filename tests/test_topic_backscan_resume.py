""" — the back-scan incremental-resume cache (study_match_cache READ) +
 — the category/model fingerprint that scopes its validity.

Pins the load-bearing mechanics the verdict identified as missing: the back-scan
WROTE study_match_cache rows but nothing READ them, so a re-run re-classified
every message. ``_load_scan_cache`` is the read the drain now consults before the
LLM. These tests prove the write<->read roundtrip, the topic_version
invalidation, AND the match_fingerprint invalidation — a category
delete/rename or model swap (neither bumps topic_version) changes the fingerprint
so the read misses the stale rows and they re-scan, instead of re-emitting a
now-stale cached matched=1 hit (the  SCOPED CONTRACT gap, now closed).
"""
from __future__ import annotations

import pytest

from email_triage.jobs.topic_backscan import (
    _apply_write_batch,
    _load_scan_cache,
    _match_fingerprint,
)
from email_triage.web.db import init_db


@pytest.fixture
def conn():
    from _db_tracking import track
    c = track(init_db(":memory:"))
    c.execute("PRAGMA foreign_keys=OFF")  # exercise the cache table in isolation
    yield c
    c.close()


_FP = "fp_test_00000000"  # a fixed fingerprint for the version-scoping tests


def _write_cache(conn, *, topic_id, topic_version, account_id, rows, fp=_FP):
    _apply_write_batch(
        conn, topic_id, topic_version, account_id,
        [("cache", r) for r in rows], fp,
    )


def test_load_scan_cache_roundtrips_what_was_written(conn):
    _write_cache(
        conn, topic_id=5, topic_version=2, account_id=3,
        rows=[
            {"rfc_id": "<a@x>", "matched": 1, "confidence": 0.91,
             "reason_terms": ["foo", "bar"]},
            {"rfc_id": "<b@x>", "matched": 0, "confidence": 0.0,
             "reason_terms": []},
        ],
    )
    loaded = _load_scan_cache(conn, 5, 2, 3, _FP)
    assert set(loaded) == {"<a@x>", "<b@x>"}
    assert loaded["<a@x>"]["matched"] == 1
    assert loaded["<a@x>"]["confidence"] == pytest.approx(0.91)
    assert loaded["<a@x>"]["reason_terms"] == ["foo", "bar"]
    assert loaded["<b@x>"]["matched"] == 0
    assert loaded["<b@x>"]["reason_terms"] == []


def test_load_scan_cache_is_scoped_by_topic_version(conn):
    """The invalidation contract: a re-run at the SAME version sees the cache
    (skip already-scanned mail); an EDITED topic (bumped version) sees an EMPTY
    cache (re-scan). Without this, 's 're-run' banner advice would be a lie."""
    _write_cache(
        conn, topic_id=5, topic_version=2, account_id=3,
        rows=[{"rfc_id": "<a@x>", "matched": 1, "confidence": 0.5,
               "reason_terms": []}],
    )
    # same version → present
    assert "<a@x>" in _load_scan_cache(conn, 5, 2, 3, _FP)
    # bumped version → invalidated (empty) → full re-scan
    assert _load_scan_cache(conn, 5, 3, 3, _FP) == {}
    # different account / topic → also scoped out
    assert _load_scan_cache(conn, 5, 2, 999, _FP) == {}
    assert _load_scan_cache(conn, 999, 2, 3, _FP) == {}


def test_load_scan_cache_empty_when_nothing_written(conn):
    assert _load_scan_cache(conn, 1, 1, 1, _FP) == {}


# ---------------------------------------------------------------------------
#  — match_fingerprint (category taxonomy + model) invalidation
# ---------------------------------------------------------------------------

def test_v45_adds_match_fingerprint_column(conn):
    """The  migration (v45) adds the tag column the read/write now use."""
    cols = {
        r[1] for r in conn.execute(
            "PRAGMA table_info(study_match_cache)"
        ).fetchall()
    }
    assert "match_fingerprint" in cols


def test_load_scan_cache_is_scoped_by_fingerprint(conn):
    """ — the cache is ALSO scoped by the match fingerprint. A category
    delete/rename or model swap changes the fingerprint, so the read MISSES the
    now-stale rows → they re-scan, instead of re-emitting a stale matched=1 hit
    (the  SCOPED-CONTRACT gap, closed)."""
    _write_cache(
        conn, topic_id=5, topic_version=2, account_id=3,
        rows=[{"rfc_id": "<a@x>", "matched": 1, "confidence": 0.9,
               "reason_terms": []}],
        fp="fp_categories_A",
    )
    # same fingerprint → present
    assert "<a@x>" in _load_scan_cache(conn, 5, 2, 3, "fp_categories_A")
    # changed fingerprint (category edit / model swap) → invalidated → re-scan
    assert _load_scan_cache(conn, 5, 2, 3, "fp_categories_B") == {}


def test_rescan_under_new_fingerprint_overwrites_stale_row(conn):
    """ — the rfc_id-keyed UPSERT overwrites the fingerprint, so after a
    re-scan under the new taxonomy the row carries the NEW fingerprint (and a
    subsequent same-fingerprint re-run resumes). ONE row per message per
    version — the UNIQUE key is unchanged, no duplicate accumulates."""
    _write_cache(
        conn, topic_id=5, topic_version=2, account_id=3,
        rows=[{"rfc_id": "<a@x>", "matched": 1, "confidence": 0.9,
               "reason_terms": ["old"]}],
        fp="fp_A",
    )
    # re-scan the SAME message under a NEW fingerprint with a fresh verdict
    _write_cache(
        conn, topic_id=5, topic_version=2, account_id=3,
        rows=[{"rfc_id": "<a@x>", "matched": 0, "confidence": 0.1,
               "reason_terms": ["new"]}],
        fp="fp_B",
    )
    # the old fingerprint now misses (the row was overwritten to fp_B)
    assert _load_scan_cache(conn, 5, 2, 3, "fp_A") == {}
    # the new fingerprint sees the fresh verdict
    loaded = _load_scan_cache(conn, 5, 2, 3, "fp_B")
    assert set(loaded) == {"<a@x>"}
    assert loaded["<a@x>"]["matched"] == 0
    assert loaded["<a@x>"]["reason_terms"] == ["new"]
    # still exactly ONE row — no duplicate
    n = conn.execute(
        "SELECT COUNT(*) FROM study_match_cache WHERE rfc822_message_id='<a@x>'"
    ).fetchone()[0]
    assert n == 1


def test_pre_60_empty_fingerprint_rows_rescan_once(conn):
    """ — pre-migration rows default to '' fingerprint. A non-empty current
    fingerprint never matches them, so they re-scan exactly once (the one-time
    self-healing invalidation the v45 migration documents)."""
    _write_cache(
        conn, topic_id=5, topic_version=2, account_id=3,
        rows=[{"rfc_id": "<legacy@x>", "matched": 1, "confidence": 0.7,
               "reason_terms": []}],
        fp="",  # simulate a pre-#60 row
    )
    assert _load_scan_cache(conn, 5, 2, 3, "fp_real") == {}
    # an explicit empty-fingerprint read still finds it (legacy resume path)
    assert "<legacy@x>" in _load_scan_cache(conn, 5, 2, 3, "")


def test_match_fingerprint_stable_and_sensitive():
    """ — the fingerprint is order-independent (stable) and changes on a
    category description change, a category delete, OR a model swap."""
    cats_a = {"to-respond": "needs reply", "fyi": "info"}
    # stable: same inputs, reordered → same fp
    reordered = dict(reversed(list(cats_a.items())))
    assert _match_fingerprint(cats_a, "qwen3.6") == _match_fingerprint(reordered, "qwen3.6")
    # sensitive: a category DESCRIPTION change → different fp
    cats_desc = {"to-respond": "needs reply", "fyi": "info CHANGED"}
    assert _match_fingerprint(cats_a, "qwen3.6") != _match_fingerprint(cats_desc, "qwen3.6")
    # sensitive: a category DELETE → different fp
    assert _match_fingerprint(cats_a, "m") != _match_fingerprint({"to-respond": "needs reply"}, "m")
    # sensitive: a MODEL swap → different fp
    assert _match_fingerprint(cats_a, "qwen3.6") != _match_fingerprint(cats_a, "gpt-4o")
    # None taxonomy is tolerated (degrades to the model-only fingerprint)
    assert _match_fingerprint(None, "m") == _match_fingerprint({}, "m")


def test_sender_suppression_precedes_cache_skip_in_drain():
    """hipaa-sme impl-review guard: the live sender-feedback (thumbs-DOWN)
    suppression MUST run BEFORE the  cache skip in the drain loop. A sender
    thumbs-downed AFTER a scan must still be suppressed on a re-run — and sender
    feedback does NOT bump topic_version, so the cache key can't protect this;
    only the ordering does. Reordering these two guards would silently re-emit a
    now-down sender's cached hit (a digest PHI-completeness regression)."""
    import inspect

    from email_triage.jobs import topic_backscan

    src = inspect.getsource(topic_backscan.run_topic_backscan_job)
    sender_idx = src.find("sender_signals.get(_sender_key) == -1")
    cache_idx = src.find("cached_verdicts.get(rfc_id)")
    assert sender_idx != -1 and cache_idx != -1, (
        "drain markers drifted — could not locate the sender-suppression or the "
        "#295 cache-skip site in run_topic_backscan_job."
    )
    assert sender_idx < cache_idx, (
        "the live sender-feedback (thumbs-down) suppression must PRECEDE the "
        "#295 cache skip — else a newly-thumbs-down sender's cached hit is "
        "wrongly re-emitted on a re-run (the cache key cannot protect this "
        "because sender feedback does not bump topic_version)."
    )
