"""Punch  (display half) — keyless rows in ``log_entries`` must be visible.

``verify_log_chain`` has always counted its secretless SHA-256 rows as
``legacy_chain_length``, but /compliance rendered neither that count nor any
warning, so the one chain that demonstrably holds keyless rows was the one the
keyless banner left out (da-423). Register N-507: ``hash_alg`` is outside the
hashed canonical form, so a keyed row rewritten as a keyless one still verifies.
This file pins the disclosure; option A (hmac-sha256-v2) and option D (``audit
verify`` FAILS on a post-boundary keyless row) are pinned in
``tests/test_web/test_punch527_n507_v2_binding_and_downgrade_pin.py`` and the CLI class below.

Three properties, each tested on the rendered VIEW (PD-17) and on the verifier:

1. a pre-boundary legacy row is counted and shown, and stays shown on the next
   page load (``/compliance`` passes ``app_state``, so the second walk is
   seeded from the watermark cache and used to report a false zero);
2. a keyless row AFTER the first keyed row is the N-507 substitution signature
   (both log writers stamp a keyed alg unconditionally) and is named in
   the keyless warning banner with ``log_entries``;
3. the same holds for a keyed row rewritten in place as keyless.
"""
from types import SimpleNamespace

import pytest

from email_triage.db.audit import (
    KEYED_CHAIN_HASH_ALGS,
    _compute_log_row_hash_sha256,
    compute_log_row_hash,
    get_last_log_row_hash,
    insert_log_entry,
    verify_log_chain,
)

# Panel E DA FIX-2: the D tests run on a boundary of EVERY keyed alg. The first
# post-E prod bake sees a v1 boundary (no v2 row exists yet), while the writers
# now stamp v2, so a test seeded only through ``insert_log_entry`` would never
# exercise the prod shape.
keyed_alg = pytest.mark.parametrize("keyed_alg", KEYED_CHAIN_HASH_ALGS)


def _chained_rows(db) -> int:
    return db.execute(
        "SELECT COUNT(*) FROM log_entries WHERE row_hash != ''"
    ).fetchone()[0]


def _insert_keyless(db, ts: str, message: str) -> None:
    """A secretless SHA-256 row chained off the current tail, the shape a
    pre-H-02a writer produced and the shape an N-507 substitution forges."""
    prev = get_last_log_row_hash(db)
    h = _compute_log_row_hash_sha256(prev, ts, "INFO", "t", message, "{}")
    db.execute(
        "INSERT INTO log_entries (ts, level, logger, message, extra_json, "
        "created_at, prev_hash, row_hash, hash_alg, master_key_version) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'sha256', 0)",
        (ts, "INFO", "t", message, "{}", ts, prev, h),
    )


def _insert_keyed(db, ts: str, message: str, alg: str) -> None:
    """A keyed row under ``alg`` (key version 0) chained off the current tail."""
    prev = get_last_log_row_hash(db)
    h = compute_log_row_hash(
        prev, ts, "INFO", "t", message, "{}", hash_alg=alg, master_key_version=0,
    )
    db.execute(
        "INSERT INTO log_entries (ts, level, logger, message, extra_json, "
        "created_at, prev_hash, row_hash, hash_alg, master_key_version) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0)",
        (ts, "INFO", "t", message, "{}", ts, prev, h, alg),
    )


def _seed_legacy_then_keyed(
    db, n_legacy: int = 2, n_keyed: int = 2, keyed_alg: str | None = None,
) -> None:
    """``keyed_alg=None`` writes the keyed rows through the real writer."""
    assert _chained_rows(db) == 0, "fixture DB already holds chained log rows"
    for i in range(n_legacy):
        _insert_keyless(db, f"2026-01-01T00:00:0{i}Z", f"legacy{i}")
    for i in range(n_keyed):
        if keyed_alg is None:
            insert_log_entry(db, f"2026-05-23T00:00:0{i}Z", "INFO", "t", f"keyed{i}")
        else:
            _insert_keyed(db, f"2026-05-23T00:00:0{i}Z", f"keyed{i}", keyed_alg)
    db.commit()


class TestVerifierCounts:
    def test_pre_boundary_legacy_rows_are_not_post_boundary(self, db):
        _seed_legacy_then_keyed(db)
        v = verify_log_chain(db)
        assert v["first_break_id"] is None
        assert v["legacy_chain_length"] == 2
        assert v["post_boundary_keyless_count"] == 0

    def test_cache_seeded_walk_keeps_the_legacy_counts(self, db):
        """The second call resumes above the watermark. Its counts must still
        describe the whole chain, like ``chain_length`` already does."""
        _seed_legacy_then_keyed(db)
        state = SimpleNamespace(audit_chain_verified=None)
        first = verify_log_chain(db, app_state=state)
        assert state.audit_chain_verified is not None  # the cache was primed
        second = verify_log_chain(db, app_state=state)
        for key in (
            "chain_length", "legacy_chain_length", "hmac_chain_length",
            "hash_alg_boundary_id", "post_boundary_keyless_count",
        ):
            assert second[key] == first[key], key
        assert second["legacy_chain_length"] == 2

    @keyed_alg
    def test_keyless_row_after_the_boundary_is_counted(self, db, keyed_alg):
        _seed_legacy_then_keyed(db, keyed_alg=keyed_alg)
        _insert_keyless(db, "2026-06-01T00:00:00Z", "forged")
        db.commit()
        v = verify_log_chain(db)
        # It verifies: that is N-507. What changed is that it is now counted.
        assert v["first_break_id"] is None
        assert v["legacy_chain_length"] == 3
        assert v["post_boundary_keyless_count"] == 1

    @keyed_alg
    def test_post_boundary_count_survives_the_cache(self, db, keyed_alg):
        _seed_legacy_then_keyed(db, keyed_alg=keyed_alg)
        _insert_keyless(db, "2026-06-01T00:00:00Z", "forged")
        db.commit()
        state = SimpleNamespace(audit_chain_verified=None)
        verify_log_chain(db, app_state=state)
        # A new keyed row above the watermark, then the cached walk.
        insert_log_entry(db, "2026-06-01T00:00:01Z", "INFO", "t", "after")
        db.commit()
        v = verify_log_chain(db, app_state=state)
        assert v["post_boundary_keyless_count"] == 1
        assert v["legacy_chain_length"] == 3

    def test_keyed_row_rewritten_as_keyless_verifies_and_is_counted(self, db):
        """The N-507 rewrite itself, on the tail keyed row (no successor to
        re-link): it still verifies, and the post-boundary count reports it."""
        _seed_legacy_then_keyed(db, n_legacy=1, n_keyed=3)
        tail = db.execute(
            "SELECT * FROM log_entries WHERE row_hash != '' ORDER BY id DESC LIMIT 1"
        ).fetchone()
        forged = _compute_log_row_hash_sha256(
            tail["prev_hash"], tail["ts"], tail["level"], tail["logger"],
            "FORGED", tail["extra_json"],
        )
        db.execute(
            "UPDATE log_entries SET message = 'FORGED', row_hash = ?, "
            "hash_alg = 'sha256', master_key_version = 0 WHERE id = ?",
            (forged, tail["id"]),
        )
        db.commit()
        v = verify_log_chain(db)
        assert v["first_break_id"] is None
        assert v["post_boundary_keyless_count"] == 1


class TestRenderedLogChainKeylessSurface:
    def test_legacy_rows_are_shown_on_every_load(self, client, admin_cookies, db):
        _seed_legacy_then_keyed(db)
        for load in (1, 2):  # load 2 walks from the watermark cache
            resp = client.get("/compliance", cookies=admin_cookies)
            assert resp.status_code == 200, load
            assert "Chain intact" in resp.text, load
            assert "Keyless (SHA-256) rows: 2" in resp.text, load
        # Pre-boundary legacy rows are expected history, not the N-507 signal.
        assert "log_entries</code>: " not in resp.text

    def test_post_boundary_keyless_row_is_in_the_warning_banner(
        self, client, admin_cookies, db,
    ):
        _seed_legacy_then_keyed(db)
        _insert_keyless(db, "2026-06-01T00:00:00Z", "forged")
        db.commit()
        for load in (1, 2):
            resp = client.get("/compliance", cookies=admin_cookies)
            assert resp.status_code == 200, load
            body = resp.text
            assert "Chain intact" in body, load
            assert "hashed without the HMAC key" in body, load
            assert "<code>log_entries</code>: 1 keyless row(s) after the first keyed row" in body, load


class TestCliNamesLogEntriesKeylessRows:
    """``audit verify`` names log_entries' keyless rows on its PASS line, as it
    does for every other chain. Pre-boundary legacy rows stay a PASS. A keyless
    row AFTER the first keyed row FAILS (N-507 option D, operator 2026-10-12),
    matching the ten registry chains; this is step 2 of the deploy bake gate."""

    def _verify(self, db_path, capsys, *extra):
        from email_triage.cli import build_parser, cmd_audit_verify
        args = build_parser().parse_args(["audit", "verify", "--db", str(db_path), *extra])
        rc = cmd_audit_verify(args)
        return rc, capsys.readouterr()

    def _db(self, tmp_path, *, forged: bool, keyed_alg: str):
        from _db_tracking import track
        from email_triage.web.db import init_db

        db_path = tmp_path / "triage.db"
        conn = track(init_db(db_path))
        try:
            _seed_legacy_then_keyed(conn, n_legacy=1, n_keyed=2, keyed_alg=keyed_alg)
            if forged:
                _insert_keyless(conn, "2026-06-01T00:00:00Z", "forged")
            conn.commit()
        finally:
            conn.close()
        return db_path

    @keyed_alg
    def test_pre_boundary_legacy_rows_are_unverifiable(self, tmp_path, capsys, keyed_alg):
        """Punch 625 (panel P, the fixed rule) changed this test: it was
        ``..._are_named_and_pass``. A legacy row below the derived boundary used
        to PASS (exit 0, "1 keyless"); it now exits 3 UNVERIFIABLE, since a
        pre-H-02a row and a substitution look the same until the punch 669
        legacy seal."""
        db_path = self._db(tmp_path, forged=False, keyed_alg=keyed_alg)
        rc, cap = self._verify(db_path, capsys)
        assert rc == 3, cap
        assert "PASS" not in cap.out
        assert "1 sha256 row(s) with no keyed boundary after them" in cap.err
        rc, cap = self._verify(db_path, capsys, "--quiet")
        assert rc == 3
        assert cap.err.strip() == "UNVERIFIABLE log_entries keyless=1 blank=0 gap_sentinels=0"

    @keyed_alg
    def test_post_boundary_keyless_row_fails(self, tmp_path, capsys, keyed_alg):
        db_path = self._db(tmp_path, forged=True, keyed_alg=keyed_alg)
        rc, cap = self._verify(db_path, capsys)
        assert rc == 1, cap.out
        assert "PASS" not in cap.out
        assert "FAIL — log_entries chain: 1 keyless (sha256) row(s) after the first keyed row" in cap.err
        assert "N-507" in cap.err

        rc, cap = self._verify(db_path, capsys, "--quiet")
        assert rc == 1
        assert "FAIL log_entries keyless=1" in cap.err
        assert cap.out.strip() == ""
