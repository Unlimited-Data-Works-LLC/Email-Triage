"""Tests for the ``email-triage audit verify`` CLI subcommand.

Covers the hash-chain integrity verifier surface — HIPAA §164.312(c)(1)
Integrity addressable spec. The handler wraps
:func:`email_triage.web.db.verify_log_chain`; tests exercise the
clean-chain path, tampered-row path, ``--since`` cutoff filtering,
``--db`` override, and ``--quiet`` shape.
"""

from __future__ import annotations
from _db_tracking import track

import logging
import sqlite3
from pathlib import Path

import pytest

# Full-tree `-n auto` hardening: these file-DB / audit-global suites flake when
# co-resident on a worker (SQLite file-lock contention + load-amplified async-audit
# timing). Each passes in isolation. Pin them to one xdist worker so they run
# serially, not concurrently — the project-sanctioned facet-2 fix (testinfra drawer).
pytestmark = pytest.mark.xdist_group("file_db_audit_serial")

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
    conn = track(init_db(db_path))
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


# ===========================================================================
# H-03-auto — CLI audit auto-emit (defense-in-depth, §164.312(b))
# ===========================================================================
#
# Tests the auto-emission of log_entries chain rows at every DB-mutating CLI
# admin op. Covers:
#   - happy-path: HIPAA mode ON → row emits with correct structured fields
#   - error-path: handler raises → row still emits with error context
#   - HIPAA-OFF gating: no rows emit (matches H-03 procedural-mechanism scope)
#   - fail-soft: emission failure logs WARNING but does NOT block the CLI op
#   - audit-pattern: every DB-mutating handler carries the @_cli_audit
#     decorator (catches regression: a new admin op added without the
#     wrapper)
#
# Per dispatch H-03-auto + operator policy `project_hipaa_asap_policy.md`:
# HIPAA findings ship ASAP + audit-trail; defense-in-depth upgrade lands
# in Cycle 6.

import contextlib

from email_triage.config import (
    LoggingConfig,
    PersistenceConfig,
    SecretsConfig,
    TriageConfig,
)


@contextlib.contextmanager
def _hipaa_install(tmp_path, *, hipaa: bool = True):
    """Stand up a minimal HIPAA-mode install with a master key + DbSecrets.

    Yields a ``TriageConfig`` whose ``persistence.db_path`` points at a
    fresh tmp_path SQLite DB and whose ``secrets`` are bootstrapped via a
    keyfile backend (deterministic + side-effect-free; no container
    secret, no env var).

    Mirrors the cmd_secrets bootstrap pattern at cli.py:431-436 so the
    HMAC registry is wired identically to a real CLI run. Tears down by
    clearing the HMAC registry (autouse conftest fixture restores the
    test key).
    """
    import sqlite3

    from email_triage.secrets import (
        DbSecrets,
        bootstrap_secrets_from_config,
        create_secrets_provider,
        wire_audit_chain_hmac_keys,
    )
    from email_triage.web.db import init_db

    from cryptography.fernet import Fernet
    keyfile = tmp_path / "wrap.key"
    db_path = tmp_path / "triage.db"

    # Keyfile backend uses the FILE as the Fernet-wrapping key for an
    # encrypted store on disk. Write a wrap key first, then `bootstrap.set()`
    # serialises the master key into the store. This mirrors the operator
    # workflow: generate a wrap key, then `email-triage secrets
    # init-master-key` populates the master inside the wrapped store.
    keyfile.write_text(Fernet.generate_key().decode())

    cfg = TriageConfig()
    cfg.logging = LoggingConfig(level="INFO", format="json", hipaa=hipaa)
    cfg.persistence = PersistenceConfig(db_path=str(db_path))
    cfg.secrets = SecretsConfig(
        backend="keyfile",
        keyfile_path=str(keyfile),
        master_key_name="ET_MASTER_KEY",
        external={},
    )

    # Generate + save the master key into the wrapped keyfile store
    # (mirrors `email-triage secrets init-master-key`).
    bootstrap = create_secrets_provider(
        cfg.secrets.backend,
        keyfile_path=cfg.secrets.keyfile_path,
        external_config=cfg.secrets.external,
        master_key_name=cfg.secrets.master_key_name,
    )
    bootstrap.set(cfg.secrets.master_key_name, DbSecrets.generate_master_key())

    # Init the DB schema so log_entries exists for the emitter.
    conn = track(init_db(db_path))
    provider = bootstrap_secrets_from_config(conn, cfg)
    wire_audit_chain_hmac_keys(provider, cfg)
    conn.close()

    yield cfg


def _read_audit_rows(db_path) -> list[dict]:
    """Pull every cli.audit log_entries row from disk, oldest-first."""
    import json as _json
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            "SELECT id, ts, level, logger, message, extra_json "
            "FROM log_entries WHERE logger = 'email_triage.cli.audit' "
            "ORDER BY id"
        ).fetchall()
    finally:
        conn.close()
    out = []
    for r in rows:
        d = dict(r)
        try:
            d["extra"] = _json.loads(d["extra_json"]) if d["extra_json"] else {}
        except Exception:
            d["extra"] = {}
        out.append(d)
    return out


@pytest.fixture
def _hipaa_config_file(tmp_path):
    """Build a HIPAA-mode install + write a YAML pointing at it.

    Returns (yaml_path, db_path, cfg). The yaml_path can be passed via
    ``--config`` to any CLI handler; the inner _cli_audit decorator
    re-loads from disk so the config must be on disk, not just an
    in-memory TriageConfig.
    """
    with _hipaa_install(tmp_path) as cfg:
        yaml_path = tmp_path / "email-triage.yaml"
        # Minimal YAML mirroring the SecretsConfig + PersistenceConfig +
        # LoggingConfig fields the decorator reads.
        yaml_path.write_text(
            f"""\
logging:
  level: INFO
  format: json
  hipaa: true

secrets:
  backend: keyfile
  keyfile_path: {cfg.secrets.keyfile_path}
  master_key_name: ET_MASTER_KEY

persistence:
  db_path: {cfg.persistence.db_path}
"""
        )
        yield yaml_path, Path(cfg.persistence.db_path), cfg


# ---------------------------------------------------------------------------
# Happy path — HIPAA mode ON
# ---------------------------------------------------------------------------

class TestCliAuditAutoEmit:
    def test_user_create_emits_start_and_end_rows(
        self, _hipaa_config_file, capsys,
    ):
        from email_triage.cli import cmd_user

        yaml_path, db_path, _cfg = _hipaa_config_file
        args = _parse([
            "--config", str(yaml_path),
            "user", "create",
            "--email", "alice@example.com",
            "--name", "Alice",
            "--role", "admin",
        ])
        rc = cmd_user(args)
        # Drain stdout — handler prints the create-success block.
        capsys.readouterr()
        assert rc == 0

        rows = _read_audit_rows(db_path)
        # Exactly two rows: start + end.
        assert len(rows) == 2, [r["message"] for r in rows]
        start, end = rows
        assert start["extra"]["cli_phase"] == "start"
        assert start["extra"]["cli_command"] == "user"
        assert end["extra"]["cli_phase"] == "end"
        assert end["extra"]["exit_code"] == 0
        # Subcommand surfaces via args.user_cmd in the allowlisted args.
        assert start["extra"]["args"].get("user_cmd") == "create"
        assert start["extra"]["args"].get("email") == "alice@example.com"
        assert start["extra"]["args"].get("role") == "admin"
        # Actor format matches the existing cmd_apikey pattern.
        assert start["extra"]["actor"].startswith("cli:")
        # Duration recorded on end row.
        assert isinstance(end["extra"]["duration_ms"], int)
        assert end["extra"]["duration_ms"] >= 0

    def test_audit_rows_are_chained_with_hmac(
        self, _hipaa_config_file, capsys,
    ):
        """Auto-emitted rows must participate in the H-02a HMAC chain —
        verify_log_chain over the resulting rows must PASS."""
        from email_triage.cli import cmd_user
        from email_triage.web.db import verify_log_chain

        yaml_path, db_path, _cfg = _hipaa_config_file
        args = _parse([
            "--config", str(yaml_path),
            "user", "create",
            "--email", "bob@example.com",
        ])
        cmd_user(args)
        capsys.readouterr()

        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        try:
            result = verify_log_chain(conn)
        finally:
            conn.close()
        assert result["first_break_id"] is None, (
            f"chain break at id={result['first_break_id']} "
            f"ts={result['first_break_ts']}"
        )
        # At least the two auto-emit rows are present.
        assert result["rows_checked"] >= 2


class TestCliAuditAutoEmitErrorPath:
    def test_handler_raise_still_emits_end_row_with_error_fields(
        self, _hipaa_config_file, capsys, monkeypatch,
    ):
        """If the wrapped handler raises, the decorator must still emit
        an 'end' row carrying error_class + error fields, then re-raise.
        This preserves the forensic context of CLI failures (a silent
        drop would hide the very evidence §164.312(b) audit controls
        exist to preserve)."""
        from email_triage import cli as cli_mod

        yaml_path, db_path, _cfg = _hipaa_config_file

        # Monkeypatch the inner work to raise a known exception.
        class _Boom(RuntimeError):
            pass

        def _explode(*a, **kw):
            raise _Boom("synthetic failure under test")

        # cmd_apikey reads init_db then dispatches; patch init_db so the
        # handler raises BEFORE doing any work.
        monkeypatch.setattr(
            "email_triage.web.auth.get_user_by_email", _explode,
        )

        args = _parse([
            "--config", str(yaml_path),
            "apikey", "create",
            "--name", "ci-key",
            "--user", "nobody@example.com",
        ])
        with pytest.raises(_Boom):
            cli_mod.cmd_apikey(args)
        capsys.readouterr()

        rows = _read_audit_rows(db_path)
        assert len(rows) == 2
        start, end = rows
        assert start["extra"]["cli_phase"] == "start"
        assert end["extra"]["cli_phase"] == "end"
        assert end["extra"]["error_class"] == "_Boom"
        assert "synthetic failure under test" in end["extra"]["error"]
        # exit_code is absent (handler never returned).
        assert "exit_code" not in end["extra"]
        # Duration still recorded.
        assert isinstance(end["extra"]["duration_ms"], int)

    def test_handler_returns_nonzero_emits_end_row_with_that_code(
        self, _hipaa_config_file, capsys,
    ):
        """When a handler returns 1 (e.g., user-already-exists), the
        end row records exit_code=1 so operators can grep for failed
        CLI ops."""
        from email_triage.cli import cmd_user

        yaml_path, db_path, _cfg = _hipaa_config_file

        # First create succeeds.
        args = _parse([
            "--config", str(yaml_path),
            "user", "create",
            "--email", "dupe@example.com",
        ])
        assert cmd_user(args) == 0
        capsys.readouterr()

        # Second create returns 1 ("user already exists").
        args = _parse([
            "--config", str(yaml_path),
            "user", "create",
            "--email", "dupe@example.com",
        ])
        assert cmd_user(args) == 1
        capsys.readouterr()

        rows = _read_audit_rows(db_path)
        # Two ops × two rows = four; the LAST row carries the rc=1.
        assert len(rows) == 4
        assert rows[-1]["extra"]["cli_phase"] == "end"
        assert rows[-1]["extra"]["exit_code"] == 1


class TestCliAuditAutoEmitHipaaGating:
    def test_non_hipaa_mode_emits_no_audit_rows(self, tmp_path, capsys):
        """HIPAA-mode-gated design Q decision: non-HIPAA installs
        produce ZERO auto-emit rows. Rationale (per cli.py H-03-auto
        design block): §164.312(b) only applies in HIPAA mode; H-02a
        D1 fail-closed RuntimeErrors on log_entries write without HMAC
        wiring, which non-HIPAA installs may not have; the non-HIPAA
        posture matches the H-03 procedural-mechanism scope."""
        from email_triage.cli import cmd_user

        with _hipaa_install(tmp_path, hipaa=False) as cfg:
            yaml_path = tmp_path / "email-triage.yaml"
            yaml_path.write_text(
                f"""\
logging:
  level: INFO
  format: json
  hipaa: false

secrets:
  backend: keyfile
  keyfile_path: {cfg.secrets.keyfile_path}
  master_key_name: ET_MASTER_KEY

persistence:
  db_path: {cfg.persistence.db_path}
"""
            )

            args = _parse([
                "--config", str(yaml_path),
                "user", "create",
                "--email", "noaudit@example.com",
            ])
            rc = cmd_user(args)
            capsys.readouterr()
            assert rc == 0

            # No cli.audit rows landed.
            rows = _read_audit_rows(Path(cfg.persistence.db_path))
            assert rows == [], (
                f"non-HIPAA mode must not emit CLI audit rows; got "
                f"{len(rows)} rows: {[r['message'] for r in rows]}"
            )


class TestCliAuditAutoEmitFailLoudGate:
    """N-157 (2026-07-09) — fail-loud gate default + `--allow-unaudited`
    recovery flag.  Alex-directed close per AskUserQuestion 2026-07-08
    ("Fail-loud with recovery flag").

    DEFAULT: an emit failure at handler ENTRY (phase='start') raises
    `CliAuditGateClosed` so the CLI exits non-zero with a specific
    message naming the recovery lever.  The pre-N-157 fail-SOFT posture
    is now the opt-in `--allow-unaudited` mode, preserving the
    procedural H-03 closure (break-glass actions_taken) for legitimate
    mid-incident break-glass use.
    """

    def test_emission_failure_default_fail_loud_at_start(
        self, _hipaa_config_file, capsys, caplog, monkeypatch,
    ):
        """DEFAULT (--allow-unaudited NOT set): a phase='start' emit
        failure raises ``CliAuditGateClosed`` so the handler NEVER runs
        + the CLI exits non-zero — operator sees an obvious audit-gate
        error instead of a silent WARN + successful op (§164.312(b)
        Audit Controls anchor).
        """
        from email_triage import cli as cli_mod
        from email_triage.cli import CliAuditGateClosed

        yaml_path, _db_path, _cfg = _hipaa_config_file

        # Sabotage the emit path — `record_cli_admin_op` internally
        # calls the chain-primitive `insert_log_entry`; patching the
        # primitive turns every emit into a raise, which
        # `safe_audit_write` surfaces as a None return, which the
        # actuator gate turns into `CliAuditGateClosed` at phase='start'.
        from email_triage.db import audit as _audit_mod

        def _explode(*a, **kw):
            raise RuntimeError("synthetic emit failure")

        monkeypatch.setattr(_audit_mod, "insert_log_entry", _explode)

        args = _parse([
            "--config", str(yaml_path),
            "user", "create",
            "--email", "loud@example.com",
        ])
        # Verify the default state matches the fail-CLOSED contract.
        assert args.allow_unaudited is False, (
            "N-157 default MUST be `--allow-unaudited=False` (fail-CLOSED)"
        )

        # Fail-CLOSED: handler MUST NOT run + exception MUST propagate.
        with pytest.raises(CliAuditGateClosed) as excinfo:
            cli_mod.cmd_user(args)
        capsys.readouterr()

        # The exception message names the recovery lever.
        assert "--allow-unaudited" in str(excinfo.value), (
            "N-157 fail-CLOSED exception MUST name --allow-unaudited as "
            "the recovery lever so the operator sees how to unblock."
        )

    def test_emission_failure_with_allow_unaudited_preserves_fail_soft(
        self, _hipaa_config_file, capsys, caplog, monkeypatch,
    ):
        """`--allow-unaudited` reverts to pre-N-157 fail-SOFT: WARN
        logged, handler still runs, procedural H-03 break-glass closure
        remains in force per §164.312(b)'s 'and/or procedural' reading.
        """
        import logging as _logging
        from email_triage import cli as cli_mod

        yaml_path, _db_path, _cfg = _hipaa_config_file

        from email_triage.db import audit as _audit_mod

        def _explode(*a, **kw):
            raise RuntimeError("synthetic emit failure")

        monkeypatch.setattr(_audit_mod, "insert_log_entry", _explode)

        args = _parse([
            "--config", str(yaml_path),
            "--allow-unaudited",
            "user", "create",
            "--email", "soft@example.com",
        ])
        assert args.allow_unaudited is True

        with caplog.at_level(_logging.WARNING, logger="email_triage.cli"):
            rc = cli_mod.cmd_user(args)
        capsys.readouterr()

        # Handler still runs to completion under the recovery flag.
        assert rc == 0
        # WARNING surfaces the auto-emit failure so the operator can
        # investigate the audit gap after the break-glass op finishes.
        warn_msgs = [
            r.getMessage() for r in caplog.records
            if r.levelno >= _logging.WARNING
        ]
        assert any("H-03-auto" in m for m in warn_msgs), (
            f"expected H-03-auto warning under --allow-unaudited, "
            f"got: {warn_msgs}"
        )


class TestCliMainSurfacesFailLoudGateAsCleanError:
    """N-157 (2026-07-09) — DA fold Fix #1.  ``main()`` MUST catch
    ``CliAuditGateClosed`` from a wrapped handler + surface a CLEAN CLI
    error on stderr — no Python traceback — with a dedicated exit code
    (3) an operator's shell script can discriminate.  Without this the
    fail-loud gate reaches the operator as a Python stack trace, which
    is a break-glass usability defect on the audit-recovery path.
    """

    def test_main_surfaces_clean_error_and_returns_3(
        self, _hipaa_config_file, capsys, monkeypatch,
    ):
        """Sabotage the emit path + invoke `main()` directly.  The exit
        code MUST be 3 (dedicated), stderr MUST name the recovery lever
        `--allow-unaudited` verbatim, and Fix #1's clean-print line
        MUST appear on stderr.  The Fix #1 contract is "no raw
        `CliAuditGateClosed` traceback reaches the operator" — verified
        via absence of the `RuntimeError: CLI audit emit failed` shape
        that Python's default uncaught-exception handler would write
        as the FINAL line if `main()` did NOT catch (the fingerprint
        is scoped to that specific text so stdlib logging's own
        `--- Logging error ---` self-diagnostic dumps that pytest
        aggregates from earlier tests do NOT false-fire this check).
        """
        import logging as _logging
        from email_triage import cli as cli_mod

        yaml_path, _db_path, _cfg = _hipaa_config_file

        from email_triage.db import audit as _audit_mod

        def _explode(*a, **kw):
            raise RuntimeError("synthetic emit failure")

        monkeypatch.setattr(_audit_mod, "insert_log_entry", _explode)

        # Silence the stdlib logging module's own I/O-error self-
        # diagnostic (the "--- Logging error ---" block) — that fires
        # when pytest's stderr-capture teardown leaves earlier tests'
        # StreamHandler pointing at a closed file, and it pollutes
        # `err` with an unrelated traceback that has nothing to do
        # with N-157's fail-loud path.  This flag ONLY suppresses the
        # logging module's meta-diagnostic; real exceptions from our
        # code still propagate normally.
        monkeypatch.setattr(_logging, "raiseExceptions", False)

        # Drive `main()` end-to-end so the wrapping `@_cli_audit` +
        # top-level `try/except CliAuditGateClosed` are BOTH exercised.
        rc = cli_mod.main([
            "--config", str(yaml_path),
            "user", "create",
            "--email", "clean@example.com",
        ])
        _out, err = capsys.readouterr()

        # Dedicated exit code — an operator's shell script MUST be able
        # to discriminate this class from a generic handler error.
        assert rc == 3, f"N-157 fail-loud MUST return rc=3; got {rc}"

        # Recovery lever named verbatim on stderr.
        assert "--allow-unaudited" in err, (
            f"N-157 fail-loud MUST name --allow-unaudited on stderr; "
            f"got stderr={err!r}"
        )

        # Fix #1's clean-print line MUST land — the try/except in main()
        # produces exactly this shape via `print(f"error: {e}", ...)`.
        assert "error: CLI audit emit failed" in err, (
            f"N-157 fail-loud MUST surface the clean 'error: CLI audit "
            f"emit failed …' line via main()'s try/except; got "
            f"stderr={err!r}"
        )

        # NO raw-exception traceback shape — if Fix #1 were missing,
        # Python's default uncaught-exception handler would write
        # `RuntimeError: CLI audit emit failed …` as the FINAL stderr
        # line (that's how base RuntimeError subclasses print).  This
        # exact shape is what discriminates a clean-caught error from
        # a bubbled-out exception, independent of any stdlib-logging
        # noise pytest aggregates from earlier tests.
        assert "RuntimeError: CLI audit emit failed" not in err, (
            f"N-157 fail-loud MUST NOT surface the raw exception "
            f"traceback shape; got stderr={err!r}"
        )


# ---------------------------------------------------------------------------
# Audit-pattern test — every DB-mutating CLI handler carries the wrapper
# ---------------------------------------------------------------------------

class TestCliAuditPattern:
    """Regression guard: if a new DB-mutating CLI subcommand lands
    without ``@_cli_audit(...)``, this test fails so the operator
    notices the H-03-auto coverage gap in the same PR.

    Per dispatch §4 principle 3 (audit the pattern before fixing): the
    enumeration below is the authoritative list of admin CLI handlers
    that must be wrapped. Read-only handlers (status, config validate,
    audit verify, version-check, embedding-bits {verify,status}) are
    intentionally EXCLUDED — they do not mutate persistent state and
    fall outside the §164.312(b) audit-control surface.

    Adding a new admin CLI handler? Add the wrapper AND extend the list
    below (the test is the schelling-point that ensures both halves of
    the change land in the same commit).
    """

    REQUIRED_WRAPPED_HANDLERS = {
        "cmd_secrets": "secrets",
        "cmd_apikey": "apikey",
        "cmd_user": "user",
        "cmd_restore": "restore",
        "cmd_style_profile": "style-profile",
        "cmd_sent_mail_index": "sent-mail-index",
        "cmd_embedding_bits_install": "embedding-bits.install",
        "cmd_embedding_bits_sideload": "embedding-bits.sideload",
        "cmd_tls_bootstrap": "tls.bootstrap",
        "cmd_tls_fetch_tailscale": "tls.fetch-tailscale",
        "cmd_auth_dev_login": "auth.dev-login",
    }

    def test_every_admin_handler_carries_cli_audit_decorator(self):
        from email_triage import cli as cli_mod

        missing = []
        wrong_label = []
        for handler_name, expected_command in (
            self.REQUIRED_WRAPPED_HANDLERS.items()
        ):
            fn = getattr(cli_mod, handler_name, None)
            assert fn is not None, (
                f"handler not found in cli module: {handler_name}"
            )
            label = getattr(fn, "_h03_auto_command", None)
            if label is None:
                missing.append(handler_name)
            elif label != expected_command:
                wrong_label.append((handler_name, label, expected_command))
        assert not missing, (
            "H-03-auto coverage gap — admin CLI handlers missing the "
            "@_cli_audit decorator:\n  " + "\n  ".join(missing)
        )
        assert not wrong_label, (
            "H-03-auto label mismatch — fix the decorator argument:\n  "
            + "\n  ".join(
                f"{h}: got {got!r}, expected {exp!r}"
                for h, got, exp in wrong_label
            )
        )
