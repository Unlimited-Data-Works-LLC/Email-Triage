"""Punch 625 (register N-609): a keyless log row with no keyed boundary after it.

The keyless boundary is derived ONLY from the chain (the smallest keyed row
id). A DB writer can rewrite every retained row as keyless SHA-256 (no key
needed): no keyed row is left, the derived boundary disappears, and
``post_boundary_keyless_count`` is 0, so ``audit verify`` passed.

The fix is a fixed rule with no setting (operator 2026-10-22, panel P; the
config floor was rejected): no sha256 ``log_entries`` row is legitimate unless a
keyed boundary follows it, and even then it is unprovable history, not proof.

(a) a row with id < 1 is a break (the id is outside the row hash);
(b) a sha256 row above the derived first-keyed boundary FAILs (N-507);
(c) any other sha256 row is UNVERIFIABLE: ``audit verify`` exits 3 and the bake
    refuses (a legacy row and a substitution cannot be told apart until the
    punch 669 legacy seal);
(d) zero sha256 rows PASS.

Each rule is pinned on a fresh walk AND on a watermark-seeded walk (the counts
are computed in two places), through ``audit verify`` (``--db`` too), and on the
rendered /compliance page.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from email_triage.db.audit import (
    _compute_log_row_hash_sha256,
    get_last_log_row_hash,
    insert_log_entry,
    verify_log_chain,
)


def _insert_keyless(db, ts: str, message: str, row_id: int | None = None) -> int:
    prev = get_last_log_row_hash(db)
    h = _compute_log_row_hash_sha256(prev, ts, "INFO", "t", message, "{}")
    cur = db.execute(
        "INSERT INTO log_entries (id, ts, level, logger, message, extra_json, "
        "created_at, prev_hash, row_hash, hash_alg, master_key_version) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'sha256', 0)",
        (row_id, ts, "INFO", "t", message, "{}", ts, prev, h),
    )
    return int(cur.lastrowid)


def _wholesale_rewritten_chain(db, n: int = 3) -> int:
    """The N-609 end state: every retained row keyless. Returns the first id."""
    assert db.execute(
        "SELECT COUNT(*) FROM log_entries WHERE row_hash != ''").fetchone()[0] == 0
    first = _insert_keyless(db, "2026-06-01T00:00:00Z", "r0")
    for i in range(1, n):
        _insert_keyless(db, f"2026-06-01T00:00:0{i}Z", f"r{i}")
    db.commit()
    return first


def _keyed(db, n: int = 2) -> None:
    for i in range(n):
        insert_log_entry(db, f"2026-05-23T00:00:0{i}Z", "INFO", "t", f"keyed{i}")
    db.commit()


class TestRuleC_NoKeyedBoundaryAfter:
    def test_a_wholesale_rewrite_is_unverifiable_not_a_pass(self, db):
        _wholesale_rewritten_chain(db, n=3)
        v = verify_log_chain(db)
        assert v["first_break_id"] is None  # it still verifies: that is N-507
        assert v["hash_alg_boundary_id"] is None
        assert v["post_boundary_keyless_count"] == 0
        assert v["unverifiable_keyless_count"] == 3

    def test_the_watermark_seeded_walk_counts_them_too(self, db):
        _wholesale_rewritten_chain(db, n=3)
        state = SimpleNamespace(audit_chain_verified=None)
        verify_log_chain(db, app_state=state)
        assert state.audit_chain_verified is not None  # the cache was primed
        _insert_keyless(db, "2026-06-02T00:00:00Z", "after")
        db.commit()
        v = verify_log_chain(db, app_state=state)
        assert v["unverifiable_keyless_count"] == 4
        assert v["post_boundary_keyless_count"] == 0


class TestRuleB_AboveTheBoundaryStillFails:
    @pytest.mark.parametrize("cached", [False, True])
    def test_above_fails_and_below_is_unverifiable(self, db, cached):
        """The derived-boundary FAIL keeps precedence; only the rows it cannot
        place are UNVERIFIABLE."""
        _insert_keyless(db, "2026-01-01T00:00:00Z", "legacy")
        _keyed(db, n=2)
        state = SimpleNamespace(audit_chain_verified=None) if cached else None
        if cached:
            verify_log_chain(db, app_state=state)
            assert state.audit_chain_verified is not None
        _insert_keyless(db, "2026-06-01T00:00:00Z", "forged")
        db.commit()
        v = verify_log_chain(db, app_state=state)
        assert v["first_break_id"] is None
        assert v["post_boundary_keyless_count"] == 1
        assert v["unverifiable_keyless_count"] == 1


class TestRuleD_ZeroKeylessPasses:
    def test_zero_keyless_rows_pass(self, db):
        _keyed(db, n=3)
        v = verify_log_chain(db)
        assert v["first_break_id"] is None
        assert v["post_boundary_keyless_count"] == 0
        assert v["unverifiable_keyless_count"] == 0


class TestRuleA_BelowIdOne:
    @pytest.mark.parametrize("row_id", [0, -7])
    def test_a_fresh_walk_breaks(self, db, row_id):
        _insert_keyless(db, "2026-01-01T00:00:00Z", "below", row_id=row_id)
        _keyed(db, n=2)
        v = verify_log_chain(db)
        assert v["first_break_id"] == row_id
        assert "below 1" in v["first_break_reason"]

    def test_a_cached_walk_breaks_and_drops_the_cache(self, db):
        _keyed(db, n=2)
        state = SimpleNamespace(audit_chain_verified=None)
        assert verify_log_chain(db, app_state=state)["first_break_id"] is None
        assert state.audit_chain_verified is not None
        _insert_keyless(db, "2026-01-01T00:00:00Z", "below", row_id=0)
        db.commit()
        v = verify_log_chain(db, app_state=state)
        assert v["first_break_id"] == 0
        assert state.audit_chain_verified is None


def test_no_config_floor_survives():
    """The operator rejected the config floor (2026-10-22): no setting, no
    resolver, no CLI flag. A knob that came back would reopen the question
    the fixed rule settled."""
    from _pin_harness import iter_src_files
    import email_triage.config as config_mod
    assert not hasattr(config_mod.AuditConfig(), "log_keyed_from_id")
    assert not hasattr(config_mod, "resolve_log_keyed_floor")
    paths = list(iter_src_files())
    assert paths, "the src walk sees nothing"
    for path in paths:
        text = path.read_text(encoding="utf-8")
        for needle in ("log_keyed_from_id", "keyed_floor", "--keyed-floor"):
            assert needle not in text, f"{path.name} still carries {needle!r}"


# ---------------------------------------------------------------------------
# audit verify: exit 3, --db, the state on the quiet line
# ---------------------------------------------------------------------------

class TestCliVerdicts:
    def _verify(self, capsys, *argv):
        from email_triage.cli import build_parser, cmd_audit_verify
        args = build_parser().parse_args(["audit", "verify", *argv])
        rc = cmd_audit_verify(args)
        return rc, capsys.readouterr()

    def _db(self, tmp_path, *, legacy: int = 0, keyed: int = 0, forged: int = 0,
            below_one: bool = False):
        from _db_tracking import track
        from email_triage.web.db import init_db
        path = tmp_path / "triage.db"
        conn = track(init_db(path))
        try:
            if below_one:
                _insert_keyless(conn, "2025-12-31T00:00:00Z", "below", row_id=0)
            for i in range(legacy):
                _insert_keyless(conn, f"2026-01-01T00:00:0{i}Z", f"legacy{i}")
            _keyed(conn, n=keyed)
            for i in range(forged):
                _insert_keyless(conn, f"2026-06-01T00:00:0{i}Z", f"forged{i}")
            conn.commit()
        finally:
            conn.close()
        return path

    def test_unverifiable_exits_3(self, tmp_path, capsys):
        path = self._db(tmp_path, legacy=2)
        rc, cap = self._verify(capsys, "--db", str(path))
        assert rc == 3, cap
        assert "PASS" not in cap.out
        assert ("2 sha256 row(s) with no keyed boundary after them: pre-H-02a legacy "
                "rows or a substitution (N-609) cannot be told apart; see punch 669 "
                "(legacy seal)") in cap.err
        rc, cap = self._verify(capsys, "--db", str(path), "--quiet")
        assert rc == 3
        assert cap.err.strip() == "UNVERIFIABLE log_entries keyless=2 blank=0 gap_sentinels=0"
        assert cap.out.strip() == ""

    def test_legacy_rows_before_a_keyed_boundary_are_still_unverifiable(
            self, tmp_path, capsys):
        path = self._db(tmp_path, legacy=1, keyed=2)
        rc, cap = self._verify(capsys, "--db", str(path), "--quiet")
        assert rc == 3
        assert cap.err.strip() == "UNVERIFIABLE log_entries keyless=1 blank=0 gap_sentinels=0"

    def test_a_tamper_signal_outranks_unverifiable(self, tmp_path, capsys):
        path = self._db(tmp_path, legacy=1, keyed=1, forged=1)
        rc, cap = self._verify(capsys, "--db", str(path), "--quiet")
        assert rc == 1
        assert "FAIL log_entries keyless=1" in cap.err

    def test_zero_keyless_passes(self, tmp_path, capsys):
        path = self._db(tmp_path, keyed=2)
        rc, cap = self._verify(capsys, "--db", str(path), "--quiet")
        assert rc == 0, cap.err
        assert cap.out.strip() == "PASS 2 gap_sentinels=0"

    def test_a_row_below_id_one_fails(self, tmp_path, capsys):
        path = self._db(tmp_path, keyed=2, below_one=True)
        rc, cap = self._verify(capsys, "--db", str(path))
        assert rc == 1
        assert "row id=0" in cap.err

    def test_the_keyed_floor_flag_is_gone(self):
        from email_triage.cli import build_parser
        with pytest.raises(SystemExit):
            build_parser().parse_args(["audit", "verify", "--keyed-floor", "5"])


# ---------------------------------------------------------------------------
# Rendered /compliance: the four states, no floor wording (PD-17)
# ---------------------------------------------------------------------------

class TestRenderedStates:
    def _page(self, client, admin_cookies):
        # A fresh walk every load: the watermark cache is per-app.
        client.app.state.audit_chain_verified = None
        resp = client.get("/compliance", cookies=admin_cookies)
        assert resp.status_code == 200
        assert "keyed floor" not in resp.text.lower()
        return resp.text

    def test_pass(self, client, admin_cookies, db):
        _keyed(db, n=2)
        body = self._page(client, admin_cookies)
        assert "Chain intact" in body
        assert "UNVERIFIABLE" not in body

    def test_unverifiable_shows_the_red_banner(self, client, admin_cookies, db):
        _wholesale_rewritten_chain(db, n=2)
        body = self._page(client, admin_cookies)
        assert "chain is UNVERIFIABLE" in body
        assert "2 sha256 row(s) with no keyed boundary after them" in body
        assert "see punch 669 (legacy seal)" in body

    def test_a_row_above_the_boundary_fails_in_the_banner(self, client, admin_cookies, db):
        _keyed(db, n=1)
        _insert_keyless(db, "2026-06-01T00:00:00Z", "forged")
        db.commit()
        body = self._page(client, admin_cookies)
        assert "<code>log_entries</code>: 1 keyless row(s) after the first keyed row" in body

    def test_a_row_at_id_zero_renders_as_a_break(self, client, admin_cookies, db):
        _insert_keyless(db, "2026-01-01T00:00:00Z", "below", row_id=0)
        db.commit()
        body = self._page(client, admin_cookies)
        assert "Chain break detected" in body
        assert "First break at log_entries.id = <code>0</code>" in body


# ---------------------------------------------------------------------------
# Panel P G1/G1b: blank-row_hash rows (DA round 3; hipaa-sme r3b)
# ---------------------------------------------------------------------------

def _blank(db, ts: str, message: str = "FORGED admin login", *, sentinel: bool = False,
           row_id: int | None = None) -> int:
    """A blank-hash row. ``sentinel=True`` uses the writer's own constants."""
    import json
    from email_triage import triage_logging as tl
    if sentinel:
        # The writer stamps now_utc_iso() (the "+00:00" form); fold 3 pins it.
        ts = ts.replace("Z", "+00:00")
        vals = (row_id, ts, tl.GAP_SENTINEL_LEVEL, tl.GAP_SENTINEL_LOGGER,
                tl.GAP_SENTINEL_MESSAGE, json.dumps(tl.GAP_SENTINEL_EXTRA), ts,
                tl.GAP_SENTINEL_HASH_ALG, tl.GAP_SENTINEL_KEY_VERSION)
    else:
        vals = (row_id, ts, "INFO", "t", message, "{}", ts, "sha256", 0)
    cur = db.execute(
        "INSERT INTO log_entries (id, ts, level, logger, message, extra_json, "
        "created_at, prev_hash, row_hash, hash_alg, master_key_version) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, '', '', ?, ?)", vals)
    return int(cur.lastrowid)


def _walk(db, cached: bool, prime=None):
    """A fresh walk, or a watermark-seeded one primed before ``prime`` runs."""
    if not cached:
        if prime:
            prime()
            db.commit()
        return verify_log_chain(db)
    state = SimpleNamespace(audit_chain_verified=None)
    verify_log_chain(db, app_state=state)
    if prime:
        prime()
        db.commit()
    return verify_log_chain(db, app_state=state)


@pytest.mark.parametrize("cached", [False, True])
class TestBlankRows:
    def test_forged_blank_rows_with_no_hashed_row_are_not_a_pass(self, db, cached):
        for i in range(3):
            _blank(db, f"2026-06-01T00:00:0{i}Z", f"FORGED admin login {i}")
        db.commit()
        v = _walk(db, cached)
        assert v["verdict"] == "unverifiable"
        assert v["unverifiable_blank_count"] == 3

    def test_a_forged_blank_row_between_keyed_rows_fails(self, db, cached):
        _keyed(db, n=2)
        v = _walk(db, cached, prime=lambda: (
            _blank(db, "2026-06-01T00:00:00Z", "FORGED: admin@x approved PHI export"),
            insert_log_entry(db, "2026-06-01T00:00:01Z", "INFO", "t", "keyed-after")))
        assert v["verdict"] == "fail"
        assert v["first_break_id"] is not None
        assert "blank row_hash" in v["first_break_reason"]

    def test_a_real_sentinel_mid_chain_passes_and_is_counted(self, db, cached):
        _keyed(db, n=2)
        v = _walk(db, cached, prime=lambda: (
            _blank(db, "2026-06-01T00:00:00Z", sentinel=True),
            insert_log_entry(db, "2026-06-01T00:00:01Z", "INFO", "t", "keyed-after")))
        assert v["first_break_id"] is None, v["first_break_reason"]
        assert v["verdict"] == "pass"
        assert v["gap_sentinel_count"] == 1

    def test_a_non_sentinel_blank_row_below_the_first_hashed_row_is_unverifiable(self, db, cached):
        _blank(db, "2026-01-01T00:00:00Z", "pre-chain history")
        _keyed(db, n=2)
        v = _walk(db, cached)
        assert v["first_break_id"] is None
        assert v["verdict"] == "unverifiable"
        assert v["unverifiable_blank_count"] == 1

    def test_a_sentinel_only_chain_is_unverifiable(self, db, cached):
        _blank(db, "2026-06-01T00:00:00Z", sentinel=True)
        db.commit()
        v = _walk(db, cached)
        assert v["verdict"] == "unverifiable"
        assert v["unverifiable_blank_count"] == 1 and v["gap_sentinel_count"] == 0


def test_a_sentinel_planted_over_a_deleted_keyed_row_fails(db):
    """No resync at a sentinel (G1b): expected_prev carries across it, so the
    excision is caught at the next row's link."""
    _keyed(db, n=3)
    middle = db.execute("SELECT id FROM log_entries ORDER BY id LIMIT 1 OFFSET 1").fetchone()[0]
    db.execute("DELETE FROM log_entries WHERE id = ?", (middle,))
    _blank(db, "2026-05-23T00:00:01Z", sentinel=True, row_id=middle)
    db.commit()
    v = verify_log_chain(db)
    assert v["verdict"] == "fail"
    assert v["first_break_id"] is not None


@pytest.mark.parametrize("field,value", [
    ("level", "INFO"), ("logger", "x"), ("message", "a forged sentinel with content"),
    ("extra_json", '{"error_kind": "log_handler_drop", "who": "admin"}'),
    ("hash_alg", "hmac-sha256-v2"), ("master_key_version", 1),
    ("created_at", "2026-06-01T00:00:09Z"),
])
def test_changing_any_sentinel_field_makes_it_a_forged_blank_row(db, field, value):
    _keyed(db, n=1)
    sid = _blank(db, "2026-06-01T00:00:00Z", sentinel=True)
    db.execute(f"UPDATE log_entries SET {field} = ? WHERE id = ?", (value, sid))
    insert_log_entry(db, "2026-06-01T00:00:01Z", "INFO", "t", "keyed-after")
    db.commit()
    v = verify_log_chain(db)
    assert v["verdict"] == "fail", field


def test_the_writer_and_the_predicate_share_one_shape():
    """PD-5: the sentinel writer builds its row from the predicate's constants."""
    import inspect
    from email_triage import triage_logging as tl
    src = inspect.getsource(tl.SQLiteLogHandler)
    for const in ("GAP_SENTINEL_LEVEL", "GAP_SENTINEL_LOGGER", "GAP_SENTINEL_MESSAGE",
                  "GAP_SENTINEL_EXTRA", "GAP_SENTINEL_HASH_ALG", "GAP_SENTINEL_KEY_VERSION"):
        assert const in src, const
    assert "log_handler_drop" not in src and "SQLiteLogHandler write error" not in src


class TestBlankRowCli:
    def _verify(self, capsys, path, *extra):
        from email_triage.cli import build_parser, cmd_audit_verify
        rc = cmd_audit_verify(build_parser().parse_args(
            ["audit", "verify", "--db", str(path), "--quiet", *extra]))
        return rc, capsys.readouterr()

    def _db(self, tmp_path, build):
        from _db_tracking import track
        from email_triage.web.db import init_db
        path = tmp_path / "triage.db"
        conn = track(init_db(path))
        try:
            build(conn)
            conn.commit()
        finally:
            conn.close()
        return path

    def test_forged_blank_rows_exit_3_not_pass_0(self, tmp_path, capsys):
        path = self._db(tmp_path, lambda c: [
            _blank(c, f"2026-06-01T00:00:0{i}Z") for i in range(3)])
        rc, cap = self._verify(capsys, path)
        assert rc == 3, cap
        assert cap.out.strip() == ""
        assert cap.err.strip() == "UNVERIFIABLE log_entries keyless=0 blank=3 gap_sentinels=0"

    def test_a_sentinel_is_printed_on_the_pass_line(self, tmp_path, capsys):
        def build(c):
            _keyed(c, n=1)
            _blank(c, "2026-06-01T00:00:00Z", sentinel=True)
            insert_log_entry(c, "2026-06-01T00:00:01Z", "INFO", "t", "after")
        rc, cap = self._verify(capsys, self._db(tmp_path, build))
        assert rc == 0, cap.err
        assert cap.out.strip() == "PASS 2 gap_sentinels=1"


def test_reconcile_does_not_pass_a_sha256_rewrite(db):
    """Panel P G2: reconcile reads the one verdict field."""
    from email_triage.db.reconciliation import verify_phi_table_against_audit_log
    _wholesale_rewritten_chain(db, n=2)
    report = verify_phi_table_against_audit_log(db)
    assert report.chain_verify_passed is False
    assert "verdict=unverifiable" in (report.chain_break_reason or "")


def test_the_shared_walker_breaks_on_a_blank_row_above_the_first_hashed_row(db):
    """G1b (R11): the other chains' walker. A blanked row above a table's first
    hashed row used to count as prechain, so the chain read intact."""
    from email_triage.db.audit import verify_audit_chain
    from email_triage.web.db import record_auth_event
    for i in range(2):
        record_auth_event(db, event_type="login", email=f"u{i}@x", user_id=None,
                          ip=None, outcome="success", detail="t")
    assert verify_audit_chain(db, "auth_events")["intact"] is True
    db.execute("UPDATE auth_events SET row_hash = '' WHERE id = "
               "(SELECT MAX(id) FROM auth_events)")
    db.commit()
    r = verify_audit_chain(db, "auth_events")
    assert r["intact"] is False
    assert "above the table's first hashed row" in r["first_break_reason"]


# ---------------------------------------------------------------------------
# Panel P fold 3 H1: the sentinel's ts is shape-pinned (no free text field)
# ---------------------------------------------------------------------------

_FORGED_TS = "2026-10-22T00:00:05Z | FORGED: admin@x approved PHI export of MRN 1234"


@pytest.mark.parametrize("cached", [False, True])
def test_a_sentinel_with_content_in_ts_fails(db, cached):
    """The DA's fold-2 probe: a sentinel built from the shared constants with
    content in ts (created_at mirroring it) between keyed rows used to PASS."""
    import json
    from email_triage import triage_logging as tl

    def forge():
        db.execute(
            "INSERT INTO log_entries (ts, level, logger, message, extra_json, created_at, "
            "prev_hash, row_hash, hash_alg, master_key_version) "
            "VALUES (?, ?, ?, ?, ?, ?, '', '', ?, ?)",
            (_FORGED_TS, tl.GAP_SENTINEL_LEVEL, tl.GAP_SENTINEL_LOGGER, tl.GAP_SENTINEL_MESSAGE,
             json.dumps(tl.GAP_SENTINEL_EXTRA), _FORGED_TS, tl.GAP_SENTINEL_HASH_ALG,
             tl.GAP_SENTINEL_KEY_VERSION))
        insert_log_entry(db, "2026-10-22T00:00:06Z", "INFO", "t", "keyed-after")

    _keyed(db, n=2)
    v = _walk(db, cached, prime=forge)
    assert v["verdict"] == "fail", v
    assert v["gap_sentinel_count"] == 0
    assert "blank row_hash" in v["first_break_reason"]


@pytest.mark.parametrize("ts", [
    _FORGED_TS,
    "2026-06-01T00:00:00Z",                      # Z, not the writer's +00:00
    "2026-06-01T00:00:00.123+00:00",             # 3 fraction digits
    "2026-06-01 00:00:00+00:00",                 # space, not T
    "２０２６-06-01T00:00:00+00:00",               # non-ASCII digits
    "2026-06-01T00:00:00+00:00\nFORGED",         # trailing content
])
def test_the_predicate_rejects_every_ts_the_writer_cannot_produce(ts):
    from email_triage import triage_logging as tl
    import json
    row = {"row_hash": "", "prev_hash": "", "level": tl.GAP_SENTINEL_LEVEL,
           "logger": tl.GAP_SENTINEL_LOGGER, "message": tl.GAP_SENTINEL_MESSAGE,
           "extra_json": json.dumps(tl.GAP_SENTINEL_EXTRA), "hash_alg": tl.GAP_SENTINEL_HASH_ALG,
           "master_key_version": tl.GAP_SENTINEL_KEY_VERSION, "ts": ts, "created_at": ts}
    assert tl.is_gap_sentinel_row(row) is False
    good = dict(row, ts="2026-06-01T00:00:00.123456+00:00",
                created_at="2026-06-01T00:00:00.123456+00:00")
    assert tl.is_gap_sentinel_row(good) is True


def test_now_utc_iso_and_the_regex_cannot_drift():
    from datetime import datetime, timezone
    from email_triage._isotime import NOW_UTC_ISO_RE, now_utc_iso, to_utc_iso
    assert NOW_UTC_ISO_RE.fullmatch(now_utc_iso())
    # isoformat() drops the fraction when the microsecond is 0.
    assert NOW_UTC_ISO_RE.fullmatch(to_utc_iso(datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)))
    assert NOW_UTC_ISO_RE.fullmatch(to_utc_iso(datetime(2026, 1, 2, 3, 4, 5, 7, tzinfo=timezone.utc)))


def test_a_sentinel_the_writer_actually_writes_matches_the_predicate(db, monkeypatch):
    """Drive SQLiteLogHandler's real error path, so the writer and the
    predicate are checked against each other, not against a copy."""
    import logging
    import email_triage.web.db as web_db
    from email_triage._isotime import NOW_UTC_ISO_RE
    from email_triage.triage_logging import SQLiteLogHandler, is_gap_sentinel_row

    def boom(*a, **kw):
        raise RuntimeError("forced write failure")

    monkeypatch.setattr(web_db, "compute_log_row_hash", boom)
    handler = SQLiteLogHandler(db, flush_interval=1)
    handler.handleError = lambda record: None  # keep stderr quiet
    log = logging.getLogger("fold3.sentinel")
    log.addHandler(handler)
    log.setLevel(logging.INFO)
    try:
        log.info("this row is dropped")
    finally:
        log.removeHandler(handler)
        handler.close()
    rows = db.execute(
        "SELECT id, ts, level, logger, message, extra_json, prev_hash, row_hash, hash_alg, "
        "master_key_version, created_at FROM log_entries WHERE row_hash = ''").fetchall()
    assert rows, "the writer wrote no sentinel: the guard tests nothing"
    for r in rows:
        assert NOW_UTC_ISO_RE.fullmatch(r["ts"]), r["ts"]
        assert is_gap_sentinel_row(r)
