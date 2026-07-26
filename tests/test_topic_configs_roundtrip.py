"""Tests for the  Topic / Study Digest DB layer.

Covers the v40 migration + ``actions/topic_configs.py``:

* **CRUD roundtrip** — create → read → update → soft-delete, asserting
  every field survives serialization/hydration through the JSON-blob
  columns (subjects, account multiselect, composed digest
  schedule/window/format).
* **topic_version bump** — :func:`bump_topic_version` increments
  monotonically and returns the new value.
* **topic_hit UPSERT first_seen_at = MIN pin** (design §8 B3) — the
  make-or-break invariant: a second insert of the same
  ``(topic_id, account_id, rfc822_message_id)`` keeps the EARLIER
  ``first_seen_at`` (a later one corrupts the Differential digest). Pinned
  two ways: (a) two ordered inserts asserting MIN regardless of insert
  order, and (b) a ``threading.Barrier(2)`` concurrent-collision test
  per ``pattern_barrier_concurrency_test`` (overlap forced by a barrier,
  not a wall-clock sleep).

The fixture bootstraps a fresh in-memory DB on the FULL current schema via
``init_db`` (it used to clip ``MIGRATIONS`` to ``<= 40``, but the topic
model grew to need v41's ``digests_json`` — pinning a schema-dependent test
to one migration number is a stale-schema trap).
"""

from __future__ import annotations

import sqlite3
import threading
from datetime import datetime, timezone

import pytest

from email_triage.web import migrations as mig_mod
from email_triage.web.migrations import schema_version
from email_triage.actions.digest_configs import (
    DigestFormat,
    DigestSchedule,
    DigestWindow,
)
from email_triage.actions import topic_configs as tc


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _restore_migrations():
    """Snapshot + restore the module-level MIGRATIONS list."""
    saved = list(mig_mod.MIGRATIONS)
    yield
    mig_mod.MIGRATIONS.clear()
    mig_mod.MIGRATIONS.extend(saved)


def _conn_topic_schema() -> sqlite3.Connection:
    """Fresh in-memory DB on the FULL current schema.

    Formerly clipped ``MIGRATIONS`` to ``<= 40`` (v40 created the topic
    tables). That pin became a stale-schema trap the moment the topic
    model grew past v40: ``upsert_topic`` now writes ``digests_json``
    (v41), so a v40-clipped schema raises ``no such column``. Pinning a
    schema-dependent test to a single migration number means every new
    topic migration silently breaks it — the count-agnostic lesson. Run
    the full current schema instead; these tests exercise ``topic_configs``
    against whatever the live schema is, which is the realistic target.
    """
    from email_triage.web.db import init_db

    from _db_tracking import track
    return track(init_db(":memory:"))


def _seed_user_and_account(conn: sqlite3.Connection) -> tuple[int, int]:
    """Insert a user + an email account; return ``(user_id, account_id)``."""
    now = datetime.now(timezone.utc).isoformat()
    cur = conn.execute(
        "INSERT INTO users (email, name, role, created_at) "
        "VALUES (?, ?, ?, ?)",
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


# ---------------------------------------------------------------------------
# Migration smoke
# ---------------------------------------------------------------------------

class TestV40Migration:
    def test_topic_schema_has_digests_json(self):
        # The topic model writes ``digests_json`` (v41), so the live schema
        # must carry that column. Was a brittle ``schema_version == 40``
        # canary; made version-agnostic (>= 41 + the actual column) so the
        # next topic migration doesn't silently break it.
        conn = _conn_topic_schema()
        try:
            cols = {
                r[1] for r in conn.execute(
                    "PRAGMA table_info(topics)"
                ).fetchall()
            }
            assert "digests_json" in cols
            assert schema_version(conn) >= 41
        finally:
            conn.close()

    def test_four_tables_created(self):
        conn = _conn_topic_schema()
        try:
            names = {
                r[0] for r in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()
            }
            assert {
                "topics", "topic_hits",
                "study_match_cache", "study_digest_state",
            } <= names
        finally:
            conn.close()

    def test_topic_hits_unique_constraint(self):
        """The B3 UPSERT key — UNIQUE(topic_id, account_id,
        rfc822_message_id) — exists so the ON CONFLICT clause has a
        conflict target to resolve on."""
        conn = _conn_topic_schema()
        try:
            idx_list = conn.execute(
                "PRAGMA index_list(topic_hits)"
            ).fetchall()
            found = False
            for idx in idx_list:
                name = idx["name"] if hasattr(idx, "keys") else idx[1]
                is_unique = idx["unique"] if hasattr(idx, "keys") else idx[2]
                if not is_unique:
                    continue
                cols = [
                    r["name"] if hasattr(r, "keys") else r[2]
                    for r in conn.execute(
                        f"PRAGMA index_info('{name}')"
                    ).fetchall()
                ]
                if cols == ["topic_id", "account_id", "rfc822_message_id"]:
                    found = True
                    break
            assert found, "missing UNIQUE(topic_id,account_id,rfc822_message_id)"
        finally:
            conn.close()

    def test_v40_idempotent_rerun(self):
        """Re-running the v40 body against an already-migrated DB is a
        clean no-op (CREATE TABLE/INDEX IF NOT EXISTS)."""
        conn = _conn_topic_schema()
        try:
            v40 = next(m for m in mig_mod.MIGRATIONS if m.version == 40)
            v40.body(conn)
            conn.commit()
            # Still exactly the four tables, no error.
            names = {
                r[0] for r in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()
            }
            assert {"topics", "topic_hits"} <= names
        finally:
            conn.close()


# ---------------------------------------------------------------------------
# CRUD roundtrip
# ---------------------------------------------------------------------------

class TestTopicCrudRoundtrip:
    def test_create_read_update_softdelete(self):
        conn = _conn_topic_schema()
        try:
            uid, acct = _seed_user_and_account(conn)

            # --- create ---
            cfg = tc.TopicConfig(
                user_id=uid,
                name="SELENA lupus study",
                subjects=["SELENA", "estrogen lupus", "NCT00000419"],
                details="Safety of Estrogens in Lupus, Phase 3.",
                details_source="nct",
                selected_account_ids=[acct],
                mode="both",
                retention_days=45,
                schedule=DigestSchedule(cadence="weekly", time_local="09:30",
                                        days_of_week=[0, 3]),
                window=DigestWindow(kind="last_7d"),
                format=DigestFormat(render_as="table", group_by="sender"),
            )
            assert tc.validate(cfg) == []
            saved = tc.upsert_topic(conn, cfg)
            assert saved.id > 0
            assert saved.created_at and saved.updated_at

            # --- read (full hydration roundtrip) ---
            got = tc.get_topic(conn, saved.id)
            assert got is not None
            assert got.user_id == uid
            assert got.name == "SELENA lupus study"
            assert got.subjects == ["SELENA", "estrogen lupus", "NCT00000419"]
            assert got.details_source == "nct"
            assert got.selected_account_ids == [acct]
            assert got.mode == "both"
            assert got.retention_days == 45
            # composed digest dataclasses survive the JSON-blob roundtrip
            assert got.schedule.cadence == "weekly"
            assert got.schedule.time_local == "09:30"
            assert got.schedule.days_of_week == [0, 3]
            assert got.window.kind == "last_7d"
            assert got.format.render_as == "table"
            assert got.format.group_by == "sender"
            assert got.enabled is True
            assert got.topic_version == 1

            # --- update (in place, id preserved, created_at preserved) ---
            got.name = "SELENA (renamed)"
            got.enabled = False
            got.selected_account_ids = [acct]
            updated = tc.upsert_topic(conn, got)
            assert updated.id == saved.id
            reread = tc.get_topic(conn, saved.id)
            assert reread is not None
            assert reread.name == "SELENA (renamed)"
            assert reread.enabled is False
            assert reread.created_at == saved.created_at  # not clobbered

            # appears in the user's list
            listed = tc.list_topics(conn, uid)
            assert [t.id for t in listed] == [saved.id]

            # --- soft-delete ---
            assert tc.soft_delete_topic(conn, saved.id) is True
            assert tc.get_topic(conn, saved.id) is None      # hidden by default
            assert tc.list_topics(conn, uid) == []           # off the list
            # still there with include_deleted
            tomb = tc.get_topic(conn, saved.id, include_deleted=True)
            assert tomb is not None
            assert tomb.deleted_at

            # idempotent re-delete is a no-op (returns False, no flip)
            assert tc.soft_delete_topic(conn, saved.id) is False
        finally:
            conn.close()

    def test_list_scoped_to_user(self):
        conn = _conn_topic_schema()
        try:
            uid_a, acct_a = _seed_user_and_account(conn)
            now = datetime.now(timezone.utc).isoformat()
            cur = conn.execute(
                "INSERT INTO users (email, name, role, created_at) "
                "VALUES (?, ?, ?, ?)",
                ("other@example.com", "Other", "user", now),
            )
            uid_b = int(cur.lastrowid)
            conn.commit()

            tc.upsert_topic(conn, tc.TopicConfig(user_id=uid_a, name="A-topic"))
            tc.upsert_topic(conn, tc.TopicConfig(user_id=uid_b, name="B-topic"))

            names_a = {t.name for t in tc.list_topics(conn, uid_a)}
            names_b = {t.name for t in tc.list_topics(conn, uid_b)}
            assert names_a == {"A-topic"}
            assert names_b == {"B-topic"}
        finally:
            conn.close()


# ---------------------------------------------------------------------------
# topic_version bump
# ---------------------------------------------------------------------------

class TestTopicVersionBump:
    def test_bump_increments_monotonically(self):
        conn = _conn_topic_schema()
        try:
            uid, _acct = _seed_user_and_account(conn)
            saved = tc.upsert_topic(
                conn, tc.TopicConfig(user_id=uid, name="Versioned"),
            )
            assert saved.topic_version == 1

            assert tc.bump_topic_version(conn, saved.id) == 2
            assert tc.bump_topic_version(conn, saved.id) == 3
            reread = tc.get_topic(conn, saved.id)
            assert reread is not None and reread.topic_version == 3
        finally:
            conn.close()

    def test_bump_missing_topic_returns_zero(self):
        conn = _conn_topic_schema()
        try:
            assert tc.bump_topic_version(conn, 999_999) == 0
        finally:
            conn.close()


# ---------------------------------------------------------------------------
# topic_hit UPSERT — first_seen_at = MIN pin (design §8 B3)
# ---------------------------------------------------------------------------

class TestTopicHitUpsertMinPin:
    def _seed_topic(self, conn: sqlite3.Connection) -> tuple[int, int]:
        uid, acct = _seed_user_and_account(conn)
        topic = tc.upsert_topic(
            conn, tc.TopicConfig(user_id=uid, name="Hit-topic",
                                 selected_account_ids=[acct]),
        )
        return topic.id, acct

    def _first_seen(self, conn, topic_id, acct, msgid) -> str:
        row = conn.execute(
            "SELECT first_seen_at, last_confirmed_at FROM topic_hits "
            "WHERE topic_id=? AND account_id=? AND rfc822_message_id=?",
            (topic_id, acct, msgid),
        ).fetchone()
        assert row is not None
        return row["first_seen_at"], row["last_confirmed_at"]

    def test_second_insert_keeps_earlier_first_seen(self):
        """Two ORDERED inserts: the EARLIER first_seen_at wins regardless
        of which insert carried it. Inserting the later timestamp SECOND
        must NOT push first_seen_at forward; inserting the later timestamp
        FIRST and the earlier SECOND must PULL it back to the min."""
        conn = _conn_topic_schema()
        try:
            topic_id, acct = self._seed_topic(conn)
            msgid = "<abc@example.com>"
            t_early = "2026-01-01T00:00:00+00:00"
            t_late = "2026-06-01T00:00:00+00:00"

            # Case 1: early first, late second → first_seen stays early,
            # last_confirmed advances to late.
            tc.insert_topic_hit(
                conn, topic_id=topic_id, account_id=acct,
                rfc822_message_id=msgid, seen_at=t_early,
            )
            tc.insert_topic_hit(
                conn, topic_id=topic_id, account_id=acct,
                rfc822_message_id=msgid, seen_at=t_late,
            )
            first, last = self._first_seen(conn, topic_id, acct, msgid)
            assert first == t_early       # NOT pushed forward
            assert last == t_late         # confirmation advanced

            # exactly one row (UPSERT, not a second insert)
            n = conn.execute(
                "SELECT COUNT(*) FROM topic_hits WHERE rfc822_message_id=?",
                (msgid,),
            ).fetchone()[0]
            assert n == 1

            # Case 2 (separate message): late first, early second →
            # first_seen PULLED BACK to early.
            msgid2 = "<def@example.com>"
            tc.insert_topic_hit(
                conn, topic_id=topic_id, account_id=acct,
                rfc822_message_id=msgid2, seen_at=t_late,
            )
            tc.insert_topic_hit(
                conn, topic_id=topic_id, account_id=acct,
                rfc822_message_id=msgid2, seen_at=t_early,
            )
            first2, last2 = self._first_seen(conn, topic_id, acct, msgid2)
            assert first2 == t_early      # pulled back to the min
            assert last2 == t_late        # max confirmation preserved
        finally:
            conn.close()

    def test_upsert_refreshes_fetch_key_and_terms(self):
        """A re-confirm refreshes the (folder, uid, uidvalidity) fetch
        key + matched terms, but never first_seen_at."""
        conn = _conn_topic_schema()
        try:
            topic_id, acct = self._seed_topic(conn)
            msgid = "<ghi@example.com>"
            tc.insert_topic_hit(
                conn, topic_id=topic_id, account_id=acct,
                rfc822_message_id=msgid, folder="INBOX", provider_uid="10",
                uidvalidity=111, reason_terms=["lupus"],
                confidence=0.4, source="live",
                seen_at="2026-02-01T00:00:00+00:00",
            )
            # uidvalidity rolled, message relocated to a new UID/folder.
            tc.insert_topic_hit(
                conn, topic_id=topic_id, account_id=acct,
                rfc822_message_id=msgid, folder="Archive", provider_uid="77",
                uidvalidity=222, reason_terms=["lupus", "estrogen"],
                confidence=0.9, source="backscan",
                seen_at="2026-03-01T00:00:00+00:00",
            )
            row = conn.execute(
                "SELECT folder, provider_uid, uidvalidity, reason_terms_json, "
                "       confidence, source, first_seen_at FROM topic_hits "
                "WHERE rfc822_message_id=?",
                (msgid,),
            ).fetchone()
            assert row["folder"] == "Archive"
            assert row["provider_uid"] == "77"
            assert row["uidvalidity"] == 222
            assert '"estrogen"' in row["reason_terms_json"]
            assert row["confidence"] == 0.9          # refreshed on re-confirm
            assert row["source"] == "backscan"       # refreshed on re-confirm
            assert row["first_seen_at"] == "2026-02-01T00:00:00+00:00"
        finally:
            conn.close()

    def test_concurrent_barrier_collision_keeps_min(self):
        """Barrier(2) concurrent-collision test (pattern_barrier_concurrency
        _test): two threads UPSERT the same hit at the same instant, one
        with an earlier first_seen_at and one with a later one. Overlap is
        forced by a ``threading.Barrier(2)`` (NOT a wall-clock sleep), and
        the surviving row must carry the MIN first_seen_at no matter which
        thread's write commits last. The @db_write lock serializes the two
        writes on the shared connection; the assertion proves the MIN
        clause — not lock ordering — decides first_seen_at."""
        conn = _conn_topic_schema()
        try:
            topic_id, acct = self._seed_topic(conn)
            msgid = "<race@example.com>"
            t_early = "2026-01-15T00:00:00+00:00"
            t_late = "2026-09-15T00:00:00+00:00"
            barrier = threading.Barrier(2)
            errors: list[Exception] = []

            def _worker(ts: str) -> None:
                try:
                    barrier.wait(timeout=5)  # force overlap at the write
                    tc.insert_topic_hit(
                        conn, topic_id=topic_id, account_id=acct,
                        rfc822_message_id=msgid, seen_at=ts,
                    )
                except Exception as exc:  # pragma: no cover - surfaced below
                    errors.append(exc)

            threads = [
                threading.Thread(target=_worker, args=(t_late,)),
                threading.Thread(target=_worker, args=(t_early,)),
            ]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=10)

            assert not errors, f"worker error(s): {errors}"
            # exactly one row survived the collision
            n = conn.execute(
                "SELECT COUNT(*) FROM topic_hits WHERE rfc822_message_id=?",
                (msgid,),
            ).fetchone()[0]
            assert n == 1
            first, last = self._first_seen(conn, topic_id, acct, msgid)
            assert first == t_early   # MIN wins regardless of commit order
            assert last == t_late     # MAX confirmation preserved
        finally:
            conn.close()


# ---------------------------------------------------------------------------
# Digest-name PHI gate
# ---------------------------------------------------------------------------

class TestDigestNamePhiScrub:
    """Per-digest names are operator free text that lands at rest in
    digests_json — they MUST pass the same fail-closed HIPAA-18 gate as
    Details + Subjects, or a PHI-shaped digest name persists unscanned."""

    def test_phi_digest_name_blocks_save(self):
        conn = _conn_topic_schema()
        try:
            uid, _ = _seed_user_and_account(conn)
            cfg = tc.TopicConfig(
                user_id=uid, name="Lupus", subjects=["SELENA"],
                digests=[tc.TopicDigest(name="MRN 12345678 follow-up")],
            )
            with pytest.raises(tc.TopicScrubBlocked):
                tc.upsert_topic(conn, cfg)
            # Nothing persisted on the fail-closed block.
            assert conn.execute("SELECT COUNT(*) FROM topics").fetchone()[0] == 0
        finally:
            conn.close()

    def test_clean_digest_name_saves(self):
        conn = _conn_topic_schema()
        try:
            uid, _ = _seed_user_and_account(conn)
            cfg = tc.TopicConfig(
                user_id=uid, name="Lupus", subjects=["SELENA"],
                digests=[tc.TopicDigest(name="Daily incremental")],
            )
            saved = tc.upsert_topic(conn, cfg)
            assert saved.id > 0
            assert tc.get_topic(conn, saved.id).digests[0].name == "Daily incremental"
        finally:
            conn.close()


# ---------------------------------------------------------------------------
#  v3 — operator feedback (thumbs) + learned sender reinforcement
# ---------------------------------------------------------------------------

class TestTopicFeedback:
    """Operator 2026-06-12 'curation + reinforcement loop': a thumbs vote
    curates the message (topic_hits.source) AND learns a per-Topic sender
    signal the matcher honors on future matches."""

    def _topic_and_hit(self, conn, uid, acct):
        from email_triage.actions.topic_configs import TopicConfig
        topic = tc.upsert_topic(conn, TopicConfig(
            user_id=uid, name="MemPalace", subjects=["MemPalace"],
            selected_account_ids=[acct], mode="full",
        ))
        tc.insert_topic_hit(
            conn, topic_id=topic.id, account_id=acct,
            rfc822_message_id="<m1@x>", source="live",
        )
        return topic

    def test_normalize_feedback_sender(self):
        assert tc.normalize_feedback_sender("Fred <fred@x.com>") == "fred@x.com"
        assert tc.normalize_feedback_sender("FRED@X.com") == "fred@x.com"
        assert tc.normalize_feedback_sender("") == ""
        assert tc.normalize_feedback_sender(None) == ""

    def test_thumbs_down_learns_sender_and_excludes_message(self):
        conn = _conn_topic_schema()
        uid, acct = _seed_user_and_account(conn)
        topic = self._topic_and_hit(conn, uid, acct)
        r = tc.record_topic_feedback(
            conn, topic_id=topic.id, account_id=acct, vote=-1,
            sender="Fred <fred@fireflies.ai>", rfc822_message_id="<m1@x>",
        )
        assert r == {"sender_key": "fred@fireflies.ai", "vote": -1}
        assert tc.get_topic_sender_signals(conn, topic.id) == {"fred@fireflies.ai": -1}
        # Thumbs-down soft-removes the stored hit (the existing curation model).
        row = conn.execute(
            "SELECT removed_at FROM topic_hits "
            "WHERE topic_id=? AND rfc822_message_id='<m1@x>'",
            (topic.id,),
        ).fetchone()
        assert row["removed_at"] is not None

    def test_revote_flips_sign_and_source_no_duplicate(self):
        conn = _conn_topic_schema()
        uid, acct = _seed_user_and_account(conn)
        topic = self._topic_and_hit(conn, uid, acct)
        tc.record_topic_feedback(conn, topic_id=topic.id, account_id=acct,
                                 vote=-1, sender="fred@x.com",
                                 rfc822_message_id="<m1@x>")
        tc.record_topic_feedback(conn, topic_id=topic.id, account_id=acct,
                                 vote=1, sender="fred@x.com",
                                 rfc822_message_id="<m1@x>")
        # UPSERT flips, never duplicates (UNIQUE(topic_id, signal_type, value)).
        assert tc.get_topic_sender_signals(conn, topic.id) == {"fred@x.com": 1}
        n = conn.execute(
            "SELECT COUNT(*) FROM topic_feedback WHERE topic_id=? AND signal_type='sender'",
            (topic.id,),
        ).fetchone()[0]
        assert n == 1
        # Up-vote promotes to 'included' AND clears the prior soft-remove.
        row = conn.execute(
            "SELECT source, removed_at FROM topic_hits "
            "WHERE topic_id=? AND rfc822_message_id='<m1@x>'",
            (topic.id,),
        ).fetchone()
        assert row["source"] == "included"
        assert row["removed_at"] is None

    def test_clear_feedback_removes_signal(self):
        conn = _conn_topic_schema()
        uid, acct = _seed_user_and_account(conn)
        topic = self._topic_and_hit(conn, uid, acct)
        tc.record_topic_feedback(conn, topic_id=topic.id, account_id=acct,
                                 vote=-1, sender="fred@x.com")
        tc.clear_topic_feedback(conn, topic_id=topic.id,
                                signal_type="sender", signal_value="fred@x.com")
        assert tc.get_topic_sender_signals(conn, topic.id) == {}

    def test_sender_only_vote_skips_message_curation(self):
        conn = _conn_topic_schema()
        uid, acct = _seed_user_and_account(conn)
        topic = self._topic_and_hit(conn, uid, acct)
        # No rfc822_message_id ⇒ only the sender signal, hit source untouched.
        tc.record_topic_feedback(conn, topic_id=topic.id, account_id=acct,
                                 vote=-1, sender="fred@x.com")
        assert tc.get_topic_sender_signals(conn, topic.id) == {"fred@x.com": -1}
        src = conn.execute(
            "SELECT source FROM topic_hits WHERE topic_id=? AND rfc822_message_id='<m1@x>'",
            (topic.id,),
        ).fetchone()["source"]
        assert src == "live"
