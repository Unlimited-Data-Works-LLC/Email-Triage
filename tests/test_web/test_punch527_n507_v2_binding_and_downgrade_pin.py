"""Punch  / N-507, options A + D (operator 2026-10-12, conditional on hipaa-sme).

A. Every chain writer stamps ``hmac-sha256-v2`` (``CHAIN_HASH_ALG_CURRENT``),
   whose keyed preimage binds the row's own ``hash_alg`` and
   ``master_key_version``. Prospective only: v1 and sha256 rows keep verifying
   under their stored form (the byte-identity freeze is untouched). Once a chain
   holds a v2 row, a v1 row after it has no current producer: each verifier
   counts it as ``downgrade_count``.
D. ``audit verify`` FAILS on a keyless ``log_entries`` row after the first keyed
   row (as the ten registry chains already do for any keyless row) and on any
   chain's ``downgrade_count``.

What each class proves:

* the writers stamp v2 and their rows verify (a v2 bug would fail every chained
  write closed, so the round trip is the guard);
* relabelling a v2 row's alg or key version breaks it (the binding), where the
  same relabel on a v1 row verifies (why the binding was needed);
* a v1 row after the first v2 row is counted on every chain shape, survives the
  log_entries watermark cache, FAILS ``audit verify`` and is shown on
  /compliance (PD-17); v1 history BEFORE the first v2 row is not;
* the structural pin: no src module stamps a keyed alg as a string literal, so
  ``CHAIN_HASH_ALG_CURRENT`` stays the one source of the writer stamp.
"""
from __future__ import annotations

import ast
from types import SimpleNamespace

import pytest

import email_triage.db.audit as A
from _pin_harness import parse_source, walk_src

V1 = "hmac-sha256-v1"
V2 = "hmac-sha256-v2"
KEY = b"\x52" * 32


def _log_tail(db):
    return db.execute(
        "SELECT * FROM log_entries WHERE row_hash != '' ORDER BY id DESC LIMIT 1"
    ).fetchone()


def _insert_log(db, alg: str, ts: str, message: str, mkv: int = 0) -> int:
    """A log row hashed under ``alg`` and chained off the current tail."""
    prev = A.get_last_log_row_hash(db)
    if alg == "sha256":
        h = A._compute_log_row_hash_sha256(prev, ts, "INFO", "t", message, "{}")
        ver = 0
    else:
        h = A.compute_log_row_hash(
            prev, ts, "INFO", "t", message, "{}", hash_alg=alg, master_key_version=mkv,
        )
        ver = mkv
    cur = db.execute(
        "INSERT INTO log_entries (ts, level, logger, message, extra_json, "
        "created_at, prev_hash, row_hash, hash_alg, master_key_version) "
        "VALUES (?, 'INFO', 't', ?, '{}', ?, ?, ?, ?, ?)",
        (ts, message, ts, prev, h, alg, ver),
    )
    db.commit()
    return cur.lastrowid


def _boundary(db, i: int) -> int:
    return A.record_hipaa_boundary(
        db, scope=f"account:{i}", direction="on", actor_id=None, reason=f"r{i}",
    )


def _rehash_registry_tail_as(db, alg: str, table: str = "hipaa_boundary_events"):
    """Re-hash the newest registry row under ``alg`` (with the key): the shape an
    old writer, or a key holder, leaves. The tail has no successor to re-link."""
    fields = A._AUDIT_CHAIN_CANONICAL_FIELDS[table]
    row = db.execute(
        f"SELECT id, prev_hash, master_key_version, {', '.join(fields)} "
        f"FROM {table} WHERE row_hash != '' ORDER BY id DESC LIMIT 1"
    ).fetchone()
    h = A.compute_audit_row_hash(
        row["prev_hash"], tuple(row[n] for n in fields),
        hash_alg=alg, master_key_version=row["master_key_version"],
    )
    db.execute(
        f"UPDATE {table} SET hash_alg = ?, row_hash = ? WHERE id = ?",
        (alg, h, row["id"]),
    )
    db.commit()
    return row["id"]


# ── A: writers stamp v2, and their rows verify ─────────────────────────────

class TestWritersStampTheCurrentAlg:
    def test_the_current_alg_is_v2_and_keyed(self):
        assert A.CHAIN_HASH_ALG_CURRENT == V2
        assert A.CHAIN_HASH_ALG_CURRENT in A.KEYED_CHAIN_HASH_ALGS
        assert A._SUPERSEDED_KEYED_ALG in A.KEYED_CHAIN_HASH_ALGS
        assert A._SUPERSEDED_KEYED_ALG != A.CHAIN_HASH_ALG_CURRENT

    def test_log_writer_round_trip(self, db):
        A.insert_log_entry(db, "2026-10-13T00:00:00Z", "INFO", "t", "a")
        A.insert_log_entry(db, "2026-10-13T00:00:01Z", "INFO", "t", "b")
        db.commit()
        assert {r[0] for r in db.execute(
            "SELECT hash_alg FROM log_entries WHERE row_hash != ''")} == {V2}
        v = A.verify_log_chain(db)
        assert v["first_break_id"] is None
        assert v["hmac_chain_length"] == v["chain_length"] == 2
        assert v["current_alg_from_id"] is not None
        assert v["downgrade_count"] == 0

    def test_registry_writer_round_trip(self, db):
        _boundary(db, 1)
        _boundary(db, 2)
        res = A.verify_audit_chain(db, "hipaa_boundary_events")
        assert res["intact"], res
        assert res["downgrade_count"] == 0 and res["keyless_count"] == 0
        assert {r[0] for r in db.execute(
            "SELECT hash_alg FROM hipaa_boundary_events WHERE row_hash != ''")} == {V2}

    def test_gap_writer_round_trip(self, db):
        A._write_audit_gap_event(
            db, helper_name="record_auth_event", args=(), kwargs={},
            exc=RuntimeError("emit failed"),
        )
        res = A.verify_gap_chain(db)
        assert res["intact"], res
        (alg,) = db.execute("SELECT hash_alg FROM audit_gap_events").fetchone()
        assert alg == V2


# ── A: the binding ─────────────────────────────────────────────────────────

class TestTheLabelsAreInsideTheKeyedHash:
    def test_relabelling_a_v2_row_as_v1_breaks_it(self, db):
        A.insert_log_entry(db, "2026-10-13T00:00:00Z", "INFO", "t", "a")
        A.insert_log_entry(db, "2026-10-13T00:00:01Z", "INFO", "t", "b")
        db.commit()
        first = db.execute("SELECT MIN(id) FROM log_entries").fetchone()[0]
        db.execute("UPDATE log_entries SET hash_alg = ? WHERE id = ?", (V1, first))
        db.commit()
        v = A.verify_log_chain(db)
        assert v["first_break_id"] == first, v

    def test_relabelling_a_v2_key_version_breaks_it_where_v1_did_not(self, db):
        """Same key bytes under versions 0 and 1: v1 cannot tell them apart,
        v2 can, because the version is inside the preimage."""
        A.set_hmac_keys({0: KEY, 1: KEY}, current_version=1)
        for alg in (V1, V2):
            h = A.compute_audit_row_hash("", ("x",), hash_alg=alg, master_key_version=1)
            relabelled = A.compute_audit_row_hash(
                "", ("x",), hash_alg=alg, master_key_version=0,
            )
            assert (h == relabelled) is (alg == V1), alg

    def test_registry_v2_row_with_a_nulled_key_version_breaks(self, db):
        """Panel E db F-1: ``_apply_chain_hmac`` resolves a None version to
        the CURRENT one, so without the verifier guard a NULLed label verifies
        while that version is current (it is here: the autouse key is v0)."""
        _boundary(db, 1)
        rid = _boundary(db, 2)
        db.execute(
            "UPDATE hipaa_boundary_events SET master_key_version = NULL WHERE id = ?",
            (rid,),
        )
        db.commit()
        res = A.verify_audit_chain(db, "hipaa_boundary_events")
        assert not res["intact"] and res["first_break_id"] == rid, res
        assert res["first_break_reason"] == "v2 row has no key version"

    def test_gap_v2_row_with_a_nulled_key_version_breaks(self, db):
        A._write_audit_gap_event(
            db, helper_name="h1", args=(), kwargs={}, exc=RuntimeError("x"),
        )
        (gid,) = db.execute("SELECT MAX(id) FROM audit_gap_events").fetchone()
        db.execute(
            "UPDATE audit_gap_events SET master_key_version = NULL WHERE id = ?", (gid,),
        )
        db.commit()
        res = A.verify_gap_chain(db)
        assert not res["intact"] and res["first_break_id"] == gid, res
        assert res["first_break_reason"] == "v2 row has no key version"

    def test_registry_row_relabelled_v2_to_v1_breaks(self, db):
        _boundary(db, 1)
        rid = _boundary(db, 2)
        db.execute(
            "UPDATE hipaa_boundary_events SET hash_alg = ? WHERE id = ?", (V1, rid),
        )
        db.commit()
        res = A.verify_audit_chain(db, "hipaa_boundary_events")
        assert not res["intact"] and res["first_break_id"] == rid, res


# ── A: the downgrade signal ────────────────────────────────────────────────

class TestDowngradeIsCounted:
    def test_v1_history_before_the_first_v2_row_is_not_a_downgrade(self, db):
        _insert_log(db, V1, "2026-01-01T00:00:00Z", "old")
        A.insert_log_entry(db, "2026-10-13T00:00:00Z", "INFO", "t", "new")
        db.commit()
        v = A.verify_log_chain(db)
        assert v["first_break_id"] is None
        assert v["downgrade_count"] == 0
        assert v["hmac_chain_length"] == 2

    def test_log_v1_row_after_v2_is_counted(self, db):
        A.insert_log_entry(db, "2026-10-13T00:00:00Z", "INFO", "t", "new")
        db.commit()
        first_v2 = _log_tail(db)["id"]
        _insert_log(db, V1, "2026-10-13T00:00:01Z", "downgraded")
        v = A.verify_log_chain(db)
        assert v["first_break_id"] is None  # it verifies: a signal, not a break
        assert v["downgrade_count"] == 1
        assert v["current_alg_from_id"] == first_v2

    def test_log_downgrade_count_survives_the_cache(self, db):
        """The first v2 row sits in the trusted prefix; the v1 row is walked
        above the watermark. Both the seed and the prefix restore are needed."""
        A.insert_log_entry(db, "2026-10-13T00:00:00Z", "INFO", "t", "new")
        db.commit()
        state = SimpleNamespace(audit_chain_verified=None)
        assert A.verify_log_chain(db, app_state=state)["downgrade_count"] == 0
        assert state.audit_chain_verified is not None
        _insert_log(db, V1, "2026-10-13T00:00:01Z", "downgraded")
        walked = A.verify_log_chain(db, app_state=state)
        assert walked["downgrade_count"] == 1, walked
        # Third load: the downgraded row is now inside the cached prefix.
        _insert_log(db, V2, "2026-10-13T00:00:02Z", "later")
        cached = A.verify_log_chain(db, app_state=state)
        assert cached["downgrade_count"] == 1, cached
        assert cached["current_alg_from_id"] == walked["current_alg_from_id"]

    def test_registry_v1_row_after_v2_is_counted(self, db):
        first = _boundary(db, 1)
        _boundary(db, 2)
        _rehash_registry_tail_as(db, V1)
        res = A.verify_audit_chain(db, "hipaa_boundary_events")
        assert res["intact"], res
        assert res["downgrade_count"] == 1
        assert res["current_alg_from_id"] == first

    def test_gap_degrade_is_keyless_not_a_downgrade(self, db):
        A._write_audit_gap_event(
            db, helper_name="h1", args=(), kwargs={}, exc=RuntimeError("x"),
        )
        with A._hmac_keys_lock:  # rotation window: current version has no key
            A._HMAC_CURRENT_VERSION = 7
        A._write_audit_gap_event(
            db, helper_name="h2", args=(), kwargs={}, exc=RuntimeError("y"),
        )
        res = A.verify_gap_chain(db)
        assert res["intact"], res
        assert res["keyless_count"] == 1
        assert res["downgrade_count"] == 0


# ── D + A at the deploy gate: ``audit verify`` ─────────────────────────────

class TestAuditVerifyFailsOnTheSignals:
    def _verify(self, db_path, capsys, *extra):
        from email_triage.cli import build_parser, cmd_audit_verify
        args = build_parser().parse_args(
            ["audit", "verify", "--db", str(db_path), "--all-chains", *extra]
        )
        rc = cmd_audit_verify(args)
        return rc, capsys.readouterr()

    def _db(self, tmp_path, build):
        from _db_tracking import track
        from email_triage.web.db import init_db

        db_path = tmp_path / "triage.db"
        conn = track(init_db(db_path))
        try:
            build(conn)
            conn.commit()
        finally:
            conn.close()
        return db_path

    def test_v1_history_then_v2_passes(self, tmp_path, capsys):
        def build(c):
            _insert_log(c, V1, "2026-01-01T00:00:00Z", "old")
            A.insert_log_entry(c, "2026-10-13T00:00:00Z", "INFO", "t", "new")
            _boundary(c, 1)

        rc, cap = self._verify(self._db(tmp_path, build), capsys)
        assert rc == 0, cap.err
        assert "audit verify: PASS" in cap.out

    def test_log_downgrade_fails(self, tmp_path, capsys):
        def build(c):
            A.insert_log_entry(c, "2026-10-13T00:00:00Z", "INFO", "t", "new")
            _insert_log(c, V1, "2026-10-13T00:00:01Z", "downgraded")

        db_path = self._db(tmp_path, build)
        rc, cap = self._verify(db_path, capsys)
        assert rc == 1, cap.out
        assert (
            "FAIL — log_entries chain: 1 hmac-sha256-v1 row(s) after the first "
            "hmac-sha256-v2 row"
        ) in cap.err
        rc, cap = self._verify(db_path, capsys, "--quiet")
        assert rc == 1
        assert "FAIL log_entries downgrade=1" in cap.err

    def test_registry_downgrade_fails(self, tmp_path, capsys):
        def build(c):
            _boundary(c, 1)
            _boundary(c, 2)
            _rehash_registry_tail_as(c, V1)

        db_path = self._db(tmp_path, build)
        rc, cap = self._verify(db_path, capsys)
        assert rc == 1, cap.out
        assert (
            "FAIL — hipaa_boundary_events chain: 1 hmac-sha256-v1 row(s) after "
            "the first hmac-sha256-v2 row"
        ) in cap.err
        rc, cap = self._verify(db_path, capsys, "--quiet")
        assert rc == 1
        assert "FAIL hipaa_boundary_events downgrade=1" in cap.err


# ── PD-17: the rendered VIEW ───────────────────────────────────────────────

class TestComplianceShowsTheDowngrade:
    def test_log_and_registry_downgrades_are_in_the_banner(
        self, client, admin_cookies, db,
    ):
        _boundary(db, 1)
        _boundary(db, 2)
        _rehash_registry_tail_as(db, V1)
        A.insert_log_entry(db, "2026-10-13T00:00:00Z", "INFO", "t", "new")
        db.commit()
        _insert_log(db, V1, "2026-10-13T00:00:01Z", "downgraded")
        for load in (1, 2):  # load 2 walks log_entries from the watermark cache
            resp = client.get("/compliance", cookies=admin_cookies)
            assert resp.status_code == 200, load
            body = resp.text
            assert "after their first hmac-sha256-v2 row" in body, load
            assert "<code>hipaa_boundary_events</code>: 1 row(s) after id" in body, load
            assert "<code>log_entries</code>: 1 row(s) after id" in body, load

    def test_no_banner_without_a_downgrade(self, client, admin_cookies, db):
        _boundary(db, 1)
        A.insert_log_entry(db, "2026-10-13T00:00:00Z", "INFO", "t", "new")
        db.commit()
        resp = client.get("/compliance", cookies=admin_cookies)
        assert resp.status_code == 200
        assert "after their first hmac-sha256-v2 row" not in resp.text


# ── Structural pin: the writer stamp has one source ────────────────────────

def _literal_keyed_stamps(modules):
    """``[(relpath, lineno)]`` for every ``hash_alg = "hmac-..."`` assignment
    and every ``hash_alg="hmac-..."`` keyword in a call. A writer must stamp
    ``CHAIN_HASH_ALG_CURRENT``; a literal is a second copy that drifts."""
    def keyed(node):
        return (
            isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and node.value.startswith("hmac-")
        )

    hits = []
    for rel, tree in modules:
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and keyed(node.value):
                for tgt in node.targets:
                    if isinstance(tgt, ast.Name) and tgt.id == "hash_alg":
                        hits.append((rel, node.lineno))
            elif isinstance(node, ast.Call):
                for kw in node.keywords:
                    if kw.arg == "hash_alg" and keyed(kw.value):
                        hits.append((rel, node.lineno))
    return sorted(hits)


def _src_modules():
    return [(rel, tree) for _path, rel, tree in walk_src()]


def test_scan_sees_the_chain_writers():
    """Positive control: the scan reaches every module that stamps a row."""
    rels = {rel for rel, _tree in _src_modules()}
    for needed in ("db/audit.py", "triage_logging.py"):
        assert any(r.endswith(needed) for r in rels), needed


def test_no_src_module_stamps_a_keyed_alg_literal():
    assert _literal_keyed_stamps(_src_modules()) == []


@pytest.mark.parametrize("src, flagged", [
    ('hash_alg = "hmac-sha256-v1"\n', True),
    ('f(x, hash_alg="hmac-sha256-v2")\n', True),
    ('hash_alg = CHAIN_HASH_ALG_CURRENT\n', False),
    ('hash_alg = r["hash_alg"] or "hmac-sha256-v1"\n', False),
    ('hash_alg, version = "sha256", None\n', False),
])
def test_stamp_pin_has_teeth(src, flagged):
    hits = _literal_keyed_stamps([("planted.py", parse_source(src))])
    assert bool(hits) is flagged, hits
