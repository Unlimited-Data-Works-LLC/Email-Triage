"""Tests for the ``email-triage audit verify`` CLI subcommand (#93).

Covers the hash-chain integrity verifier surface — HIPAA §164.312(c)(1)
Integrity addressable spec. The handler wraps
:func:`email_triage.web.db.verify_log_chain`; tests exercise the
clean-chain path, tampered-row path, ``--since`` cutoff filtering,
``--db`` override, and ``--quiet`` shape.
"""

from __future__ import annotations

import logging
import sqlite3
from pathlib import Path

import pytest

from email_triage.cli import build_parser, cmd_audit_verify
from email_triage.triage_logging import SQLiteLogHandler
from email_triage.web.db import init_db


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _seed_chain(db_path: Path, count: int = 3, logger_name: str = "test.audit") -> None:
    """Create a triage DB at ``db_path`` and emit ``count`` chain-aware
    log rows via the production SQLiteLogHandler. Closes the connection
    so the file-on-disk chain is fully flushed before verification.
    """
    conn = init_db(db_path)
    handler = SQLiteLogHandler(conn, flush_interval=1)
    log = logging.getLogger(logger_name)
    log.addHandler(handler)
    log.setLevel(logging.INFO)
    try:
        for i in range(count):
            log.info("entry %d", i)
        handler.flush()
        conn.commit()
    finally:
        log.removeHandler(handler)
        handler.close()
        conn.close()


def _tamper_row_message(db_path: Path, row_id: int, new_message: str = "TAMPERED") -> None:
    """Mutate the ``message`` field of a row in-place. Breaks the row's
    stored row_hash relative to recomputation."""
    conn = sqlite3.connect(str(db_path))
    conn.execute(
        "UPDATE log_entries SET message = ? WHERE id = ?",
        (new_message, row_id),
    )
    conn.commit()
    conn.close()


def _row_count(db_path: Path) -> int:
    conn = sqlite3.connect(str(db_path))
    n = conn.execute(
        "SELECT COUNT(*) FROM log_entries WHERE row_hash != ''"
    ).fetchone()[0]
    conn.close()
    return n


def _row_ts(db_path: Path, row_id: int) -> str:
    conn = sqlite3.connect(str(db_path))
    ts = conn.execute(
        "SELECT ts FROM log_entries WHERE id = ?", (row_id,)
    ).fetchone()[0]
    conn.close()
    return ts


def _parse(argv: list[str]):
    """Run ``argv`` through the CLI parser; return the Namespace."""
    return build_parser().parse_args(argv)


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------

class TestVerifyHappyPath:
    def test_clean_chain_exits_zero(self, tmp_path, capsys):
        db_path = tmp_path / "triage.db"
        _seed_chain(db_path, count=4)

        args = _parse(["audit", "verify", "--db", str(db_path)])
        rc = cmd_audit_verify(args)

        captured = capsys.readouterr()
        assert rc == 0
        assert "PASS" in captured.out
        assert "audit verify:" in captured.out
        # Row count surfaced.
        assert str(_row_count(db_path)) in captured.out
        # Nothing on stderr for the success path.
        assert captured.err == ""

    def test_clean_chain_quiet_prints_pass_n(self, tmp_path, capsys):
        db_path = tmp_path / "triage.db"
        _seed_chain(db_path, count=2)

        args = _parse([
            "audit", "verify", "--db", str(db_path), "--quiet",
        ])
        rc = cmd_audit_verify(args)

        captured = capsys.readouterr()
        assert rc == 0
        # Single line of shape "PASS <N>".
        out = captured.out.strip()
        assert out.startswith("PASS ")
        assert out == f"PASS {_row_count(db_path)}"
        assert "\n" not in out  # Single line.


# ---------------------------------------------------------------------------
# Tamper detection
# ---------------------------------------------------------------------------

class TestVerifyTamper:
    def test_tampered_row_exits_one_and_names_id_ts_on_stderr(
        self, tmp_path, capsys,
    ):
        db_path = tmp_path / "triage.db"
        _seed_chain(db_path, count=4)

        # Find a chain-aware row to tamper. Pick the second one so
        # there's both a predecessor (chain anchor) and a successor.
        conn = sqlite3.connect(str(db_path))
        rows = conn.execute(
            "SELECT id FROM log_entries WHERE row_hash != '' ORDER BY id"
        ).fetchall()
        conn.close()
        target_id = rows[1][0]
        target_ts = _row_ts(db_path, target_id)

        _tamper_row_message(db_path, target_id)

        args = _parse(["audit", "verify", "--db", str(db_path)])
        rc = cmd_audit_verify(args)

        captured = capsys.readouterr()
        assert rc == 1
        assert captured.out == ""
        assert "FAIL" in captured.err
        assert f"id={target_id}" in captured.err
        assert f"ts={target_ts}" in captured.err
        # Both expected + found hashes appear (full hex, not truncated).
        assert "expected hash" in captured.err
        assert "found" in captured.err

    def test_tampered_row_quiet_prints_fail_id(self, tmp_path, capsys):
        db_path = tmp_path / "triage.db"
        _seed_chain(db_path, count=3)

        conn = sqlite3.connect(str(db_path))
        rows = conn.execute(
            "SELECT id FROM log_entries WHERE row_hash != '' ORDER BY id"
        ).fetchall()
        conn.close()
        target_id = rows[1][0]
        _tamper_row_message(db_path, target_id)

        args = _parse([
            "audit", "verify", "--db", str(db_path), "--quiet",
        ])
        rc = cmd_audit_verify(args)

        captured = capsys.readouterr()
        assert rc == 1
        assert captured.out == ""
        # Single line of shape "FAIL <id>".
        err = captured.err.strip()
        assert err == f"FAIL {target_id}"
        assert "\n" not in err  # Single line.


# ---------------------------------------------------------------------------
# --since cutoff
# ---------------------------------------------------------------------------

class TestVerifySince:
    def test_break_before_cutoff_does_not_trigger(self, tmp_path, capsys):
        db_path = tmp_path / "triage.db"
        _seed_chain(db_path, count=4)

        conn = sqlite3.connect(str(db_path))
        rows = conn.execute(
            "SELECT id, ts FROM log_entries WHERE row_hash != '' ORDER BY id"
        ).fetchall()
        conn.close()

        # Tamper an early row.
        early_id, early_ts = rows[0][0], rows[0][1]
        _tamper_row_message(db_path, early_id)

        # Cutoff strictly after the tampered row.
        cutoff_ts = rows[-1][1]  # Newest row's ts.
        # The tampered early row has ts < cutoff_ts (strictly), so it
        # should be tolerated.
        assert early_ts < cutoff_ts

        args = _parse([
            "audit", "verify", "--db", str(db_path),
            "--since", cutoff_ts,
        ])
        rc = cmd_audit_verify(args)

        captured = capsys.readouterr()
        assert rc == 0, (
            f"expected pre-cutoff break to be tolerated, got rc={rc} "
            f"out={captured.out!r} err={captured.err!r}"
        )
        assert "PASS" in captured.out

    def test_break_at_or_after_cutoff_does_trigger(self, tmp_path, capsys):
        db_path = tmp_path / "triage.db"
        _seed_chain(db_path, count=5)

        conn = sqlite3.connect(str(db_path))
        rows = conn.execute(
            "SELECT id, ts FROM log_entries WHERE row_hash != '' ORDER BY id"
        ).fetchall()
        conn.close()

        # Pick the second-to-last row to tamper.
        target_id, target_ts = rows[-2][0], rows[-2][1]
        _tamper_row_message(db_path, target_id)

        # Cutoff at or before the tampered row.
        cutoff_ts = rows[0][1]
        assert cutoff_ts <= target_ts

        args = _parse([
            "audit", "verify", "--db", str(db_path),
            "--since", cutoff_ts,
        ])
        rc = cmd_audit_verify(args)

        captured = capsys.readouterr()
        assert rc == 1
        assert f"id={target_id}" in captured.err


# ---------------------------------------------------------------------------
# --db override
# ---------------------------------------------------------------------------

class TestVerifyDbOverride:
    def test_db_flag_targets_override_path(self, tmp_path, capsys, monkeypatch):
        # Two side-by-side DBs.
        good_db = tmp_path / "good.db"
        bad_db = tmp_path / "bad.db"
        _seed_chain(good_db, count=3, logger_name="test.audit.good")
        _seed_chain(bad_db, count=3, logger_name="test.audit.bad")

        # Tamper only the "bad" DB.
        conn = sqlite3.connect(str(bad_db))
        rows = conn.execute(
            "SELECT id FROM log_entries WHERE row_hash != '' ORDER BY id"
        ).fetchall()
        conn.close()
        _tamper_row_message(bad_db, rows[1][0])

        # Sentinel: load_config must not be reached when --db is set.
        # If the handler ever falls back to config, this raises.
        from email_triage import cli as cli_mod

        def _explode(*a, **kw):
            raise AssertionError(
                "cmd_audit_verify must not call load_config when --db is set",
            )
        monkeypatch.setattr(cli_mod, "load_config", _explode)

        # Verify good DB → PASS.
        args = _parse(["audit", "verify", "--db", str(good_db)])
        rc = cmd_audit_verify(args)
        captured = capsys.readouterr()
        assert rc == 0, captured.err
        assert "PASS" in captured.out

        # Verify bad DB → FAIL, regardless of any config-loaded path.
        args = _parse(["audit", "verify", "--db", str(bad_db)])
        rc = cmd_audit_verify(args)
        captured = capsys.readouterr()
        assert rc == 1
        assert "FAIL" in captured.err

    def test_missing_db_path_returns_exit_code_two(self, tmp_path, capsys):
        nonexistent = tmp_path / "no-such.db"
        args = _parse(["audit", "verify", "--db", str(nonexistent)])
        rc = cmd_audit_verify(args)
        captured = capsys.readouterr()
        # Exit 2 is reserved for "could not open DB" — not a chain
        # break. Operator scripts can disambiguate.
        assert rc == 2
        assert "not found" in captured.err.lower()
