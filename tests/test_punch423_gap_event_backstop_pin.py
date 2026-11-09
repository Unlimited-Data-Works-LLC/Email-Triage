"""Punch  (register N-467 + N-468) — the audit gap-event backstop.

``audit_gap_events`` is the control of last resort for every ``@audit_emitter``
helper: when an emit fails, the ``db_write`` wrapper records a gap row.

N-467: the gap writer chose HMAC whenever a key VERSION was set. In the window
where the version is set but its key is not provisioned (the commonest reason an
emitter fails at all), the gap write raised too, the wrapper swallowed it, and
nothing recorded the failed emit. The writer now degrades to the secretless
SHA-256 form with a NULL key version on ANY HMAC failure, and logs at ERROR.

N-468: the gap chain was built on every write and verified by nothing.
``verify_gap_chain`` now walks it with the writer's own canonical form, and
``verify_all_audit_chains`` (the /compliance surface) includes it.

This file pins, through the real code paths:
- END TO END: a real ``@audit_emitter`` helper failing in the rotation window
  still leaves a gap row, and the original exception still propagates.
- The writer's choice: HMAC when the key is present, SHA-256 + NULL version when
  it is not (both the no-version and the version-without-key shapes), with a
  distinguishable ERROR log on the degraded path.
- The verifier: a mixed HMAC / SHA-256 chain verifies intact and reports its
  keyless row; editing a hashed field or deleting a middle row is reported at
  the right row; a missing or unreadable table, and a row with no chain hash,
  are reported NOT intact (the gap table alone; registry tables keep their
  pre-chain rows).
- STRUCTURE (count-agnostic): every table in a fresh schema that carries the
  four chain columns is verified by ``verify_all_audit_chains``, except
  ``log_entries``, which has ``verify_log_chain``. Teeth: the same predicate
  reports the gap table when its verifier is removed.

What this file does NOT prove: that a SHA-256 gap row resists forgery. It does
not; it is keyless by design, the price of a backstop that still writes when
the key is missing. The ``hash_alg`` column says which rows are keyed.
"""

from __future__ import annotations

import logging

import pytest

import email_triage.db.audit as A
from email_triage.web.db import init_db

KEY_1 = b"\x11" * 32
CHAIN_COLS = {"prev_hash", "row_hash", "hash_alg", "master_key_version"}


@pytest.fixture
def conn(tmp_path):
    from _db_tracking import track

    c = track(init_db(str(tmp_path / "t.db")))
    yield c


def _rotation_window():
    """Key 1 installed, current version forced to 2, which has no key."""
    A._set_hmac_key_for_test(KEY_1, version=1)
    with A._hmac_keys_lock:
        A._HMAC_CURRENT_VERSION = 2


def _no_version():
    with A._hmac_keys_lock:
        A._HMAC_KEYS.clear()
        A._HMAC_CURRENT_VERSION = None


def _gap_rows(conn):
    return conn.execute(
        "SELECT id, helper_name, hash_alg, master_key_version, row_hash "
        "FROM audit_gap_events ORDER BY id"
    ).fetchall()


def _write_gap(conn, helper="record_auth_event", exc=None, args=()):
    A._write_audit_gap_event(
        conn, helper_name=helper, args=args, kwargs={"event_type": "x"},
        exc=exc if exc is not None else RuntimeError("emit failed"),
    )


def _exc_msgs(conn):
    return [r[0] for r in conn.execute("SELECT exc_msg FROM audit_gap_events ORDER BY id")]


def _fail_tail(monkeypatch, exc=None):
    """Make the writer's chain-tail read raise (punch )."""
    def boom(_conn):
        raise exc if exc is not None else RuntimeError("tail read failed")

    monkeypatch.setattr(A, "_read_gap_chain_tail", boom)


def _errors(caplog):
    return [r.getMessage() for r in caplog.records if r.levelno >= logging.ERROR]


MARKER = A.GAP_TAIL_UNREADABLE_MARKER


class TestWriterChoosesByKeyAvailability:
    def test_key_present_writes_hmac(self, conn):
        A._set_hmac_key_for_test(KEY_1, version=1)
        _write_gap(conn)
        (row,) = _gap_rows(conn)
        assert (row["hash_alg"], row["master_key_version"]) == ("hmac-sha256-v2", 1)

    @pytest.mark.parametrize("window", [_rotation_window, _no_version], ids=["version_without_key", "no_version"])
    def test_key_absent_degrades_and_says_so(self, conn, window, caplog):
        window()
        with caplog.at_level(logging.ERROR, logger="email_triage.db.audit"):
            _write_gap(conn)
        (row,) = _gap_rows(conn)
        assert (row["hash_alg"], row["master_key_version"]) == ("sha256", None)
        assert row["row_hash"]
        assert any("DEGRADED to secretless sha256 (N-467)" in r.getMessage() for r in caplog.records), (
            "the degraded write must be distinguishable from a healthy one at the time it happens"
        )


class TestChainTailReadCannotCostTheRow:
    """Punch : when the chain-tail read fails (any class, OperationalError
    included), the row is still written, its exc_msg starts with the writer's
    marker, and an ERROR names the class. NOT proven here, because it is not
    true: a DROPPED table keeps no row (the INSERT itself raises); punch 
    stays open for that."""

    def test_row_written_marked_and_break_visible(self, conn, monkeypatch, caplog):
        A._set_hmac_key_for_test(KEY_1, version=1)
        _write_gap(conn, "h1")
        _fail_tail(monkeypatch)
        with caplog.at_level(logging.ERROR, logger="email_triage.db.audit"):
            _write_gap(conn, "h2")
        rows = _gap_rows(conn)
        assert [r["helper_name"] for r in rows] == ["h1", "h2"]
        assert _exc_msgs(conn)[1].startswith(f"{MARKER}RuntimeError] "), _exc_msgs(conn)
        prevs = [r[0] for r in conn.execute("SELECT prev_hash FROM audit_gap_events ORDER BY id")]
        # Fold 3 removed the verifier's exclusion rule; the empty prev is still
        # the writer's contract after a failed tail read, and the marker on an
        # empty-prev keyed row is what EVIDENCES the cause.
        assert prevs[1] == "", prevs
        assert any("chain tail unreadable (RuntimeError)" in m for m in _errors(caplog))
        res = A.verify_gap_chain(conn)
        assert not res["intact"] and res["first_break_id"] == rows[1]["id"], res
        reason = res["first_break_reason"]
        assert "self-consistent under HMAC key version 1" in reason, reason
        assert f"{MARKER}RuntimeError]" in reason, reason

    def test_operational_error_is_marked_too(self, conn, monkeypatch, caplog):
        """da-529 M3: a lock between the tail SELECT and the INSERT used to give
        the same empty-prev break with no ERROR at all."""
        import sqlite3

        A._set_hmac_key_for_test(KEY_1, version=1)
        _write_gap(conn, "h1")
        _fail_tail(monkeypatch, sqlite3.OperationalError("database is locked"))
        with caplog.at_level(logging.ERROR, logger="email_triage.db.audit"):
            _write_gap(conn, "h2")
        assert _exc_msgs(conn)[1].startswith(f"{MARKER}OperationalError] ")
        assert any("chain tail unreadable (OperationalError)" in m for m in _errors(caplog))

    def test_first_row_verifies_intact_and_only_the_marker_shows_it(self, conn, monkeypatch, caplog):
        """hipaa-529 F2: on an empty table the empty prev_hash is the correct
        genesis value, so the verifier reports intact. The in-row marker is the
        only record, and the ERROR must not promise a break."""
        A._set_hmac_key_for_test(KEY_1, version=1)
        _fail_tail(monkeypatch)
        with caplog.at_level(logging.ERROR, logger="email_triage.db.audit"):
            _write_gap(conn, "h1")
        assert len(_gap_rows(conn)) == 1
        assert _exc_msgs(conn)[0].startswith(f"{MARKER}RuntimeError] ")
        (msg,) = [m for m in _errors(caplog) if "chain tail unreadable" in m]
        assert "unless it is the first row" in msg, msg
        assert A.verify_gap_chain(conn)["intact"]

    def test_marker_survives_a_long_exception(self, conn, monkeypatch):
        """db-529 + hipaa-529: prepend, then truncate; the marker is never the
        part that is cut."""
        A._set_hmac_key_for_test(KEY_1, version=1)
        _fail_tail(monkeypatch)
        _write_gap(conn, "h1", exc=RuntimeError("x" * 2000))
        (msg,) = _exc_msgs(conn)
        assert msg.startswith(f"{MARKER}RuntimeError] ") and len(msg) == 500, (len(msg), msg[:60])


class TestMarkerCannotBeForgedThroughExceptionText:
    """Two arms (hipaa-529): exception text that starts with the marker is
    escaped and does not read as degraded, AND a genuinely degraded row still
    does. Either arm alone passes a broken implementation."""

    FAKE = f"{MARKER}RuntimeError] not really"

    def test_exception_text_starting_with_the_marker_is_escaped(self, conn):
        A._set_hmac_key_for_test(KEY_1, version=1)
        _write_gap(conn, "h1", exc=RuntimeError(self.FAKE))
        (msg,) = _exc_msgs(conn)
        assert msg == "\\" + self.FAKE, msg
        assert A.gap_row_tail_unreadable_class(msg, "hmac-sha256-v1") is None

    def test_a_genuine_degraded_row_still_reads_as_degraded(self, conn, monkeypatch):
        A._set_hmac_key_for_test(KEY_1, version=1)
        _fail_tail(monkeypatch)
        _write_gap(conn, "h1", exc=RuntimeError(self.FAKE))
        (msg,) = _exc_msgs(conn)
        assert msg == f"{MARKER}RuntimeError] " + "\\" + self.FAKE, msg
        assert A.gap_row_tail_unreadable_class(msg, "hmac-sha256-v1") == "RuntimeError"

    def test_escape_keeps_every_byte_of_already_escaped_text(self, conn):
        A._set_hmac_key_for_test(KEY_1, version=1)
        _write_gap(conn, "h1", exc=RuntimeError("\\" + self.FAKE))
        (msg,) = _exc_msgs(conn)
        assert msg == "\\\\" + self.FAKE, msg

    def test_reader_is_prefix_only_and_keyed_only(self):
        marked = f"{MARKER}RuntimeError] boom"
        assert A.gap_row_tail_unreadable_class(marked, "hmac-sha256-v1") == "RuntimeError"
        assert A.gap_row_tail_unreadable_class("x " + marked, "hmac-sha256-v1") is None
        assert A.gap_row_tail_unreadable_class(marked, "sha256") is None
        assert A.gap_row_tail_unreadable_class(marked, None) is None


class _Unprintable:
    def __repr__(self):
        raise ValueError("no repr")

    __str__ = __repr__


class TestRowBuildCannotCostTheRow:
    """da-529 M2 + db-529 NEW-3: each ENUMERATED step before the INSERT that
    can raise on caller input degrades to a stored, self-describing value, and
    the ERROR names the step and class (class name only, never the text). The
    exception text is also coerced to encodable UTF-8. This proves those
    steps, not that nothing else before the INSERT can raise."""

    def test_unreprable_argument(self, conn, caplog):
        A._set_hmac_key_for_test(KEY_1, version=1)
        with caplog.at_level(logging.ERROR, logger="email_triage.db.audit"):
            _write_gap(conn, "h1", args=(None, _Unprintable()))
        row = conn.execute("SELECT original_args_hash FROM audit_gap_events").fetchone()
        assert row["original_args_hash"] == ""
        assert any("args_hash:ValueError" in m for m in _errors(caplog)), _errors(caplog)

    def test_unprintable_exception(self, conn, caplog):
        class Weird(Exception):
            def __str__(self):
                raise ValueError("no str")

        A._set_hmac_key_for_test(KEY_1, version=1)
        with caplog.at_level(logging.ERROR, logger="email_triage.db.audit"):
            _write_gap(conn, "h1", exc=Weird())
        assert _exc_msgs(conn) == ["<exception text unavailable: ValueError>"]
        assert any("exc_text:ValueError" in m for m in _errors(caplog)), _errors(caplog)

    @pytest.mark.parametrize("attr,step", [("_redact_args", "redact_args"), ("now_utc_iso", "timestamp")])
    def test_failing_step(self, conn, monkeypatch, caplog, attr, step):
        def boom(*_a, **_k):
            raise TypeError("boom")

        A._set_hmac_key_for_test(KEY_1, version=1)
        monkeypatch.setattr(A, attr, boom)
        with caplog.at_level(logging.ERROR, logger="email_triage.db.audit"):
            _write_gap(conn, "h1")
        assert len(_gap_rows(conn)) == 1
        assert any(f"{step}:TypeError" in m for m in _errors(caplog)), _errors(caplog)
        assert A.verify_gap_chain(conn)["intact"]
        row = conn.execute("SELECT ts, original_args_redacted FROM audit_gap_events").fetchone()
        if step == "timestamp":
            assert row["ts"] == ""
        else:  # distinguishable from "{}", which an unknown emitter legitimately writes
            import json

            assert json.loads(row["original_args_redacted"]) == {"redaction_failed": "TypeError"}

    @pytest.mark.parametrize("text,stored", [
        ("boom \ud800 tail", "boom \\ud800 tail"),
        ("\ud800 lead", "\\\\ud800 lead"),
    ], ids=["mid", "leading"])
    def test_a_lone_surrogate_does_not_cost_the_row(self, conn, text, stored):
        """db-529 NEW-3: the hash and the INSERT bind both raised on a lone
        surrogate, and the keyless fallback hashed the same text. Coerced before
        the escape, so a leading surrogate becomes a backslash that is escaped."""
        A._set_hmac_key_for_test(KEY_1, version=1)
        _write_gap(conn, "h1", exc=RuntimeError(text))
        assert _exc_msgs(conn) == [stored]
        assert A.verify_gap_chain(conn)["intact"]


class TestEndToEndThroughARealEmitter:
    def test_failed_emit_in_rotation_window_still_leaves_a_gap_row(self, conn):
        """The N-467 scenario itself: a real @audit_emitter helper fails because
        the current key version has no key. Before the fix the gap write failed
        the same way and no row landed."""
        _rotation_window()
        assert _gap_rows(conn) == []
        with pytest.raises(RuntimeError, match="H-02a"):
            A.record_auth_event(conn, event_type="login_success", user_id=None, email="a@b.c")
        rows = _gap_rows(conn)
        assert [r["helper_name"] for r in rows] == ["record_auth_event"], rows
        assert rows[0]["hash_alg"] == "sha256"

    def test_tail_read_failure_through_the_wrapper(self, conn, monkeypatch):
        """da-529 M6: the row survives a failed tail read when the db_write
        wrapper is the caller, not only when the helper is called directly.
        Both degradations compose here: keyless AND unlinked, and a keyless
        row's marker is not evidence."""
        _rotation_window()
        _fail_tail(monkeypatch)
        with pytest.raises(RuntimeError, match="H-02a"):
            A.record_auth_event(conn, event_type="login_success", user_id=None, email="a@b.c")
        rows = _gap_rows(conn)
        assert [(r["helper_name"], r["hash_alg"]) for r in rows] == [("record_auth_event", "sha256")]
        (msg,) = _exc_msgs(conn)
        assert msg.startswith(f"{MARKER}RuntimeError] ")
        assert A.gap_row_tail_unreadable_class(msg, rows[0]["hash_alg"]) is None


class TestVerifier:
    def test_mixed_chain_verifies_intact(self, conn):
        A._set_hmac_key_for_test(KEY_1, version=1)
        _write_gap(conn, "h1")
        _rotation_window()
        _write_gap(conn, "h2")
        A._set_hmac_key_for_test(KEY_1, version=1)
        _write_gap(conn, "h3")
        assert [r["hash_alg"] for r in _gap_rows(conn)] == ["hmac-sha256-v2", "sha256", "hmac-sha256-v2"]
        res = A.verify_gap_chain(conn)
        assert res["intact"] and res["rows_checked"] == 3, res
        assert res["keyless_count"] == 1, res

    def test_edited_hashed_field_is_reported(self, conn):
        A._set_hmac_key_for_test(KEY_1, version=1)
        for h in ("h1", "h2", "h3"):
            _write_gap(conn, h)
        ids = [r["id"] for r in _gap_rows(conn)]
        conn.execute("UPDATE audit_gap_events SET exc_msg = 'edited' WHERE id = ?", (ids[1],))
        conn.commit()
        res = A.verify_gap_chain(conn)
        assert not res["intact"] and res["first_break_id"] == ids[1], res

    def test_deleted_middle_row_is_reported(self, conn):
        A._set_hmac_key_for_test(KEY_1, version=1)
        for h in ("h1", "h2", "h3"):
            _write_gap(conn, h)
        ids = [r["id"] for r in _gap_rows(conn)]
        conn.execute("DELETE FROM audit_gap_events WHERE id = ?", (ids[1],))
        conn.commit()
        res = A.verify_gap_chain(conn)
        assert not res["intact"] and res["first_break_id"] == ids[2], res
        assert "self-consistent under HMAC key version 1" in res["first_break_reason"], res
        assert MARKER not in res["first_break_reason"], res

    def test_edited_row_reason_says_content(self, conn):
        A._set_hmac_key_for_test(KEY_1, version=1)
        for h in ("h1", "h2"):
            _write_gap(conn, h)
        ids = [r["id"] for r in _gap_rows(conn)]
        conn.execute("UPDATE audit_gap_events SET exc_msg = 'edited' WHERE id = ?", (ids[1],))
        conn.commit()
        reason = A.verify_gap_chain(conn)["first_break_reason"]
        assert "content does not match" in reason and "self-consistent" not in reason, reason

    def test_keyless_self_consistency_is_not_offered_as_evidence(self, conn):
        _no_version()
        for h in ("h1", "h2", "h3"):
            _write_gap(conn, h)
        ids = [r["id"] for r in _gap_rows(conn)]
        conn.execute("DELETE FROM audit_gap_events WHERE id = ?", (ids[1],))
        conn.commit()
        reason = A.verify_gap_chain(conn)["first_break_reason"]
        assert "keyless" in reason and "proves nothing" in reason, reason

    def test_every_break_is_counted_not_only_the_first(self, conn):
        """da-529 M5: one standing break must not hide a later one."""
        A._set_hmac_key_for_test(KEY_1, version=1)
        for h in ("h1", "h2", "h3", "h4", "h5"):
            _write_gap(conn, h)
        ids = [r["id"] for r in _gap_rows(conn)]
        conn.execute("DELETE FROM audit_gap_events WHERE id = ?", (ids[1],))
        conn.execute("UPDATE audit_gap_events SET exc_msg = 'edited' WHERE id = ?", (ids[3],))
        conn.commit()
        res = A.verify_gap_chain(conn)
        assert res["first_break_id"] == ids[2] and res["break_count"] == 2, res

    def test_missing_table_is_not_intact(self, conn):
        conn.execute("DROP TABLE audit_gap_events")
        res = A.verify_gap_chain(conn)
        assert not res["intact"] and "table missing" in res["first_break_reason"], res

    def test_unreadable_table_is_not_intact(self, conn):
        conn.execute("DROP TABLE audit_gap_events")
        conn.execute("CREATE TABLE audit_gap_events (id INTEGER PRIMARY KEY)")
        res = A.verify_gap_chain(conn)
        assert not res["intact"] and "could not be read" in res["first_break_reason"], res

    def test_row_without_a_chain_hash_is_a_break(self, conn):
        A._set_hmac_key_for_test(KEY_1, version=1)
        _write_gap(conn, "h1")
        conn.execute(
            "INSERT INTO audit_gap_events (ts, helper_name, original_args_redacted, "
            "original_args_hash, exc_type, exc_msg, prev_hash, row_hash) "
            "VALUES ('t', 'forged', '', '', '', '', '', '')"
        )
        conn.commit()
        res = A.verify_gap_chain(conn)
        assert not res["intact"] and "born chained" in res["first_break_reason"], res

    def test_registry_chains_still_treat_empty_hash_as_prechain(self, conn):
        """The prechain-as-break rule is the gap table's alone; the registry
        tables have real pre-v43 rows."""
        A._set_hmac_key_for_test(KEY_1, version=1)
        conn.execute(
            "INSERT INTO user_status_events (ts, target_user_id, event, reason, row_hash) "
            "VALUES ('t', 1, 'x', 'y', '')"
        )
        conn.commit()
        res = A.verify_audit_chain(conn, "user_status_events")
        assert res["intact"] and res["prechain_count"] == 1, res

    def test_compliance_aggregate_includes_the_gap_chain(self, conn):
        A._set_hmac_key_for_test(KEY_1, version=1)
        _write_gap(conn)
        chains = A.verify_all_audit_chains(conn)
        assert chains[A.GAP_CHAIN_TABLE]["rows_checked"] == 1


def _unverified_chain_tables(conn, verified: set[str]) -> set[str]:
    """Tables carrying all four chain columns that no verifier walks.
    ``log_entries`` is walked by verify_log_chain, outside the aggregate."""
    live = set()
    for (name,) in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall():
        cols = {r[1] for r in conn.execute(f"PRAGMA table_info({name})").fetchall()}
        if CHAIN_COLS <= cols:
            live.add(name)
    return live - verified - {"log_entries"}


class TestEveryChainHasAVerifier:
    def test_no_chain_without_a_verifier(self, conn):
        A._set_hmac_key_for_test(KEY_1, version=1)
        verified = set(A.verify_all_audit_chains(conn))
        assert _unverified_chain_tables(conn, verified) == set()

    def test_predicate_has_teeth(self, conn):
        A._set_hmac_key_for_test(KEY_1, version=1)
        verified = set(A.verify_all_audit_chains(conn)) - {A.GAP_CHAIN_TABLE}
        assert _unverified_chain_tables(conn, verified) == {A.GAP_CHAIN_TABLE}
