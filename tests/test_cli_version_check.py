"""Tests for the ``email-triage version-check`` CLI subcommand (#125 partial).

Exit codes are the load-bearing surface (Nagios + future deploy.sh
pre-flight will read them):

* 0 = up_to_date
* 1 = update_available
* 2 = incompatible_rollback / downgrade / DB-not-readable
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from email_triage.cli import build_parser, cmd_version_check
from email_triage.version import read_target_schema_caps


def _parse(argv: list[str]):
    return build_parser().parse_args(argv)


def _seed_db_at_version(path: Path, version: int) -> None:
    """Create the schema_migrations bookkeeping row at ``version``."""
    conn = sqlite3.connect(str(path))
    conn.execute(
        "CREATE TABLE schema_migrations ("
        "version INTEGER PRIMARY KEY, name TEXT, "
        "applied_at TEXT, checksum TEXT)"
    )
    conn.execute(
        "INSERT INTO schema_migrations VALUES (?, ?, ?, ?)",
        (version, "synthetic", "ts", "x"),
    )
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# Exit-code matrix
# ---------------------------------------------------------------------------

class TestExitCodes:
    """Each exit code is independently asserted — Nagios / deploy.sh
    rely on the contract."""

    def test_up_to_date_exits_zero(
        self, tmp_path, capsys, monkeypatch,
    ):
        target = read_target_schema_caps()
        db_path = tmp_path / "live.db"
        _seed_db_at_version(db_path, target)
        monkeypatch.delenv("EMAIL_TRIAGE_PREVIOUS_SCHEMA_CAPS", raising=False)

        args = _parse(["version-check", "--db", str(db_path)])
        rc = cmd_version_check(args)

        out = capsys.readouterr().out
        assert rc == 0
        assert "up_to_date" in out

    def test_update_available_exits_one(
        self, tmp_path, capsys, monkeypatch,
    ):
        target = read_target_schema_caps()
        # Seed the DB one behind target -> update_available.
        db_path = tmp_path / "live.db"
        _seed_db_at_version(db_path, max(1, target - 1))
        monkeypatch.delenv("EMAIL_TRIAGE_PREVIOUS_SCHEMA_CAPS", raising=False)

        args = _parse(["version-check", "--db", str(db_path)])
        rc = cmd_version_check(args)

        out = capsys.readouterr().out
        assert rc == 1
        assert "update_available" in out

    def test_incompatible_rollback_exits_two(
        self, tmp_path, capsys, monkeypatch,
    ):
        target = read_target_schema_caps()
        # Live DB one behind target; :previous two behind target ->
        # previous_caps < db -> incompat.
        db_path = tmp_path / "live.db"
        _seed_db_at_version(db_path, max(2, target - 1))
        monkeypatch.setenv(
            "EMAIL_TRIAGE_PREVIOUS_SCHEMA_CAPS", str(max(1, target - 2)),
        )

        args = _parse(["version-check", "--db", str(db_path)])
        rc = cmd_version_check(args)

        out = capsys.readouterr().out
        assert rc == 2
        assert "incompatible_rollback" in out

    def test_downgrade_not_supported_exits_two(
        self, tmp_path, capsys, monkeypatch,
    ):
        # DB at a version higher than the binary knows about.
        target = read_target_schema_caps()
        db_path = tmp_path / "live.db"
        _seed_db_at_version(db_path, target + 5)
        monkeypatch.delenv("EMAIL_TRIAGE_PREVIOUS_SCHEMA_CAPS", raising=False)

        args = _parse(["version-check", "--db", str(db_path)])
        rc = cmd_version_check(args)

        out = capsys.readouterr().out
        assert rc == 2
        assert "downgrade_not_supported" in out

    def test_missing_db_exits_two(
        self, tmp_path, capsys, monkeypatch,
    ):
        monkeypatch.delenv("EMAIL_TRIAGE_PREVIOUS_SCHEMA_CAPS", raising=False)
        args = _parse(["version-check", "--db", str(tmp_path / "no.db")])
        rc = cmd_version_check(args)
        err = capsys.readouterr().err
        assert rc == 2
        assert "not found" in err.lower()


# ---------------------------------------------------------------------------
# Output shape
# ---------------------------------------------------------------------------

class TestOutputShape:
    def test_default_human_output_names_app_version_and_caps(
        self, tmp_path, capsys, monkeypatch,
    ):
        target = read_target_schema_caps()
        db_path = tmp_path / "live.db"
        _seed_db_at_version(db_path, target)
        monkeypatch.delenv("EMAIL_TRIAGE_PREVIOUS_SCHEMA_CAPS", raising=False)

        args = _parse(["version-check", "--db", str(db_path)])
        cmd_version_check(args)

        out = capsys.readouterr().out
        from email_triage import __version__ as appv
        assert f"v{appv}" in out
        assert f"target_schema={target}" in out
        assert f"db_schema={target}" in out
        # Explanation line is rendered (second line).
        assert "up to date" in out.lower()

    def test_json_output_is_parseable(
        self, tmp_path, capsys, monkeypatch,
    ):
        target = read_target_schema_caps()
        db_path = tmp_path / "live.db"
        _seed_db_at_version(db_path, target)
        monkeypatch.delenv("EMAIL_TRIAGE_PREVIOUS_SCHEMA_CAPS", raising=False)

        args = _parse(["version-check", "--db", str(db_path), "--json"])
        cmd_version_check(args)

        out = capsys.readouterr().out
        payload = json.loads(out)
        assert payload["status"] == "up_to_date"
        assert payload["target_schema_caps"] == target
        assert payload["db_schema_version"] == target
        # previous caps is null in the JSON (None -> null).
        assert payload["previous_schema_caps"] is None

    def test_human_output_names_previous_caps_when_set(
        self, tmp_path, capsys, monkeypatch,
    ):
        target = read_target_schema_caps()
        db_path = tmp_path / "live.db"
        _seed_db_at_version(db_path, target)
        monkeypatch.setenv(
            "EMAIL_TRIAGE_PREVIOUS_SCHEMA_CAPS", str(max(1, target - 1)),
        )

        args = _parse(["version-check", "--db", str(db_path)])
        cmd_version_check(args)

        out = capsys.readouterr().out
        assert "previous=" in out


# ---------------------------------------------------------------------------
# --print-target-schema-only — used by scripts/deploy.sh to extract the
# :previous image's schema cap before swapping.
# ---------------------------------------------------------------------------

class TestPrintTargetSchemaOnly:
    """The flag is the bridge that lets deploy.sh auto-inject
    EMAIL_TRIAGE_PREVIOUS_SCHEMA_CAPS — must produce a single
    parseable integer and exit 0 even without a DB."""

    def test_prints_target_schema_caps_as_single_int(self, capsys):
        target = read_target_schema_caps()
        args = _parse(["version-check", "--print-target-schema-only"])
        rc = cmd_version_check(args)

        out = capsys.readouterr().out
        assert rc == 0
        # Stdout is a single line containing exactly the integer.
        assert out.strip() == str(target)
        assert int(out.strip()) == target

    def test_does_not_read_db_or_config(
        self, tmp_path, capsys, monkeypatch,
    ):
        """The flag short-circuits BEFORE the DB / config load. Pass a
        DB path that doesn't exist; with the flag set the helper still
        exits 0 and prints the cap. Without the flag the same path
        would yield exit 2 ("not found").
        """
        monkeypatch.delenv("EMAIL_TRIAGE_PREVIOUS_SCHEMA_CAPS", raising=False)
        bogus = tmp_path / "does-not-exist.db"
        args = _parse([
            "version-check",
            "--db", str(bogus),
            "--print-target-schema-only",
        ])
        rc = cmd_version_check(args)

        out = capsys.readouterr().out
        err = capsys.readouterr().err
        assert rc == 0
        assert out.strip() == str(read_target_schema_caps())
        # No "not found" error because the DB read never happened.
        assert "not found" not in err.lower()

    def test_output_is_safe_to_capture_in_shell(self, capsys):
        """deploy.sh captures the output with `$(... | tr -d '[:space:]')`
        then regex-matches `^[1-9][0-9]*$`. Make sure the output is a
        bare integer — no leading whitespace, no decimals, no surrounding
        quotes.
        """
        args = _parse(["version-check", "--print-target-schema-only"])
        cmd_version_check(args)
        out = capsys.readouterr().out
        # Allow a single trailing newline (print() default).
        assert out.endswith("\n")
        # Strip the trailing newline and verify it's a positive integer.
        stripped = out.rstrip("\n")
        assert stripped.isdigit()
        assert int(stripped) >= 1
