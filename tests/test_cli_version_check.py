"""Tests for the ``email-triage version-check`` CLI subcommand.

Exit codes are the load-bearing surface (the monitoring system + future deploy.sh
pre-flight will read them):

* 0 = up_to_date
* 1 = update_available
* 2 = incompatible_rollback / downgrade / DB-not-found (``--db``) / config error
* 5 = db_unreadable: the DB file exists but could not be opened or read
  (2026-10-18; it used to read as schema 0, exit 1)
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from email_triage.cli import build_parser, cmd_version_check
from email_triage.version import (
    DbSchemaUnreadableError,
    _read_db_schema_version_strict,
    read_target_schema_caps,
)


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
    """Each exit code is independently asserted — the monitoring system / deploy.sh
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

        args = _parse(["version-check", "--db", str(db_path),
                       "--previous-schema-caps", str(max(1, target - 2))])
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

        args = _parse(["version-check", "--db", str(db_path),
                       "--previous-schema-caps", str(max(1, target - 1))])
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


# ---------------------------------------------------------------------------
# An unreadable DB is a refusal, never "schema 0" (2026-10-18, PD-8)
# ---------------------------------------------------------------------------

import contextlib  # noqa: E402
import getpass  # noqa: E402
import os  # noqa: E402
import subprocess  # noqa: E402
import sys  # noqa: E402

import email_triage.cli as cli_mod  # noqa: E402


def _seed_wal_db_without_sidecars(path: Path, version: int) -> None:
    """A WAL-mode DB at ``version``, closed cleanly: SQLite folds the WAL back
    and deletes ``-wal`` and ``-shm`` on the last close, the state punch 636's
    clean stop leaves the live DB in."""
    conn = sqlite3.connect(str(path))
    assert conn.execute("PRAGMA journal_mode=WAL").fetchone()[0] == "wal"
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
    for suffix in ("-wal", "-shm"):
        assert not Path(str(path) + suffix).exists(), f"{suffix} survived a clean close"


@contextlib.contextmanager
def _read_only_dir(d: Path):
    """Make ``d`` refuse file creation for this process (chmod 0555 on POSIX, an
    icacls deny of write-data/append-data on Windows), as a ``:ro`` mount does.
    Skips, naming why, when the process can still create a file there (root
    ignores the mode), so the test can never pass on a rig that did not build
    the read-only shape."""
    if sys.platform == "win32":
        user = os.environ.get("USERNAME") or getpass.getuser()
        subprocess.run(
            ["icacls", str(d), "/deny", f"{user}:(WD,AD)"],
            check=True, capture_output=True,
        )

        def undo() -> None:
            subprocess.run(["icacls", str(d), "/remove:d", user], capture_output=True)
    else:
        mode = d.stat().st_mode

        def undo() -> None:
            d.chmod(mode)

        d.chmod(0o555)
    try:
        probe = d / ".create-probe"
        try:
            probe.touch()
        except OSError:
            pass
        else:
            probe.unlink()
            pytest.skip(
                "this process can create a file in a directory made read-only "
                "(running as root?), so the no-sidecar read-only shape cannot be built"
            )
        yield
    finally:
        undo()


class TestUnreadableDbFailsClosed:
    """The deploy of 8661fddb (2026-10-18) printed ``"db_schema_version": 0``
    beside ``previous_schema_caps 53`` and proceeded: punch 636's clean stop left
    the WAL-mode live DB with no ``-wal``/``-shm``, the pre-flight mounted the
    data dir ``:ro``, SQLite cannot create its ``-wal`` sidecar there (the first
    file it needs), the open failed with "unable to open database file"
    (SQLITE_CANTOPEN), and ``read_db_schema_version`` returned 0 for
    it. 0 reads as "older than every image", so ``downgrade_not_supported`` and
    ``incompatible_rollback`` could never fire on that read. A version-check that
    could not read the DB must say so with its own exit code, which
    ``scripts/deploy.sh`` refuses."""

    def test_wal_db_without_sidecars_in_a_read_only_dir_is_refused(
        self, tmp_path, capsys,
    ):
        target = read_target_schema_caps()
        d = tmp_path / "data"
        d.mkdir()
        db = d / "triage.db"
        _seed_wal_db_without_sidecars(db, target)
        argv = ["version-check", "--db", str(db), "--json",
                f"--previous-schema-caps={target}"]

        with _read_only_dir(d):
            rc = cmd_version_check(_parse(argv))
        captured = capsys.readouterr()
        js = json.loads(captured.out)
        assert (js["status"], js["db_schema_version"]) == ("db_unreadable", None), captured
        assert rc not in (0, 1, 2)
        assert rc == cli_mod._VERSION_CHECK_DB_UNREADABLE
        # The refusal names its cause in the parts OUR code writes: the status
        # word, the DB path and a non-empty reason after them. SQLite's wording is
        # not asserted: it differs across OSes and versions (CI run 39333311135:
        # Linux printed "attempt to write a readonly database" where Windows
        # printed "unable to open database file"; operator 2026-10-19, decide on
        # codes and status fields, read the text only to diagnose).
        line = captured.err.strip().splitlines()[-1]
        assert line.startswith("version-check: db_unreadable -- "), captured.err
        assert str(db) in line, captured.err
        assert line.rsplit(": ", 1)[-1].strip(), captured.err

        # The cause as a CODE, on the chained exception. SQLite fails creating
        # the `-wal` sidecar, the first file it needs: EACCES (a 0555 directory,
        # non-root) gives SQLITE_READONLY_DIRECTORY; EROFS (a `:ro` mount, the
        # 8661fddb deploy) and Windows give SQLITE_CANTOPEN (panel F r4: measured
        # by db-sme and devils-advocate on Linux, by the lead on Windows). A plain
        # SQLITE_READONLY would be a real write on the read-only handle, so it is
        # not in the set.
        with _read_only_dir(d):
            with pytest.raises(DbSchemaUnreadableError) as ei:
                _read_db_schema_version_strict(db)
        cause = ei.value.__cause__
        assert getattr(cause, "sqlite_errorname", None) in (
            "SQLITE_CANTOPEN", "SQLITE_READONLY_DIRECTORY",
        ), repr(cause)

        # Positive control: the same file, its directory writable again, reads
        # its real version, so the refusal above was the read-only shape.
        rc = cmd_version_check(_parse(argv))
        js = json.loads(capsys.readouterr().out)
        assert rc == 0
        assert js["db_schema_version"] == target

    @pytest.mark.parametrize("where", ["at_connect", "at_first_query"])
    def test_an_open_error_at_the_opener_is_refused(
        self, tmp_path, capsys, monkeypatch, where,
    ):
        """The encrypted opener raises at connect (it probes sqlite_master); the
        plaintext one connects lazily and raises at the first query, which
        ``read_schema_version`` used to swallow as "table absent"."""
        import email_triage.db._engine as engine

        db = tmp_path / "triage.db"
        _seed_db_at_version(db, read_target_schema_caps())

        class _LazyFailConn:
            def execute(self, *a, **k):
                raise sqlite3.OperationalError("unable to open database file")

            def close(self):
                pass

        def _opener(_path):
            if where == "at_connect":
                raise sqlite3.OperationalError("unable to open database file")
            return _LazyFailConn()

        monkeypatch.setattr(engine, "open_dedicated_conn_readish", _opener)
        rc = cmd_version_check(_parse(["version-check", "--db", str(db), "--json"]))
        captured = capsys.readouterr()
        assert json.loads(captured.out)["status"] == "db_unreadable", captured
        assert rc == cli_mod._VERSION_CHECK_DB_UNREADABLE

    def test_human_output_names_the_refusal(self, tmp_path, capsys, monkeypatch):
        import email_triage.db._engine as engine

        db = tmp_path / "triage.db"
        _seed_db_at_version(db, read_target_schema_caps())

        def _opener(_path):
            raise sqlite3.OperationalError("unable to open database file")

        monkeypatch.setattr(engine, "open_dedicated_conn_readish", _opener)
        rc = cmd_version_check(_parse(["version-check", "--db", str(db)]))
        captured = capsys.readouterr()
        assert "db_unreadable" in captured.out, captured
        assert rc == cli_mod._VERSION_CHECK_DB_UNREADABLE
        assert "unable to open database file" in captured.err


class TestRequireDb:
    """Panel F (F2, 2026-10-18): the config branch turned a DB this process
    cannot see into ``db_path=None`` BEFORE the strict read, so a mount or
    ``db_path`` mismatch inside the new image read as schema 0 (a fresh
    install), exit 1 ``update_available``, and ``scripts/deploy.sh`` proceeded:
    the 638 fail-open again. deploy.sh checks the host file first and passes
    ``--require-db``; under it a missing file is ``db_unreadable`` (exit 5)."""

    @staticmethod
    def _config_branch(monkeypatch, db: Path) -> None:
        from types import SimpleNamespace

        monkeypatch.setattr(
            cli_mod, "load_config",
            lambda _p: SimpleNamespace(persistence=SimpleNamespace(db_path=str(db))),
        )
        monkeypatch.setattr(cli_mod, "_cli_stamp_db_encryption", lambda _c: False)

    def test_config_path_db_missing_with_require_db_is_refused(
        self, tmp_path, capsys, monkeypatch,
    ):
        self._config_branch(monkeypatch, tmp_path / "data" / "triage.db")
        rc = cmd_version_check(_parse(["version-check", "--json", "--require-db"]))
        out = capsys.readouterr().out
        assert rc == cli_mod._VERSION_CHECK_DB_UNREADABLE, out
        assert json.loads(out)["status"] == "db_unreadable", out

    def test_config_path_db_missing_without_the_flag_keeps_the_fresh_install_contract(
        self, tmp_path, capsys, monkeypatch,
    ):
        self._config_branch(monkeypatch, tmp_path / "data" / "triage.db")
        rc = cmd_version_check(_parse(["version-check", "--json"]))
        out = capsys.readouterr().out
        assert rc in (0, 1), out
        assert json.loads(out)["db_schema_version"] == 0, out

    def test_db_flag_missing_with_require_db_is_refused(self, tmp_path, capsys):
        rc = cmd_version_check(_parse(
            ["version-check", "--db", str(tmp_path / "no.db"), "--json", "--require-db"]))
        out = capsys.readouterr().out
        assert rc == cli_mod._VERSION_CHECK_DB_UNREADABLE, out
        assert json.loads(out)["status"] == "db_unreadable", out

    @pytest.mark.parametrize("flag", [True, False])
    def test_an_unmigrated_file_with_require_db_is_refused(self, tmp_path, capsys, flag):
        """Panel F r2 (DA-4): a 0-byte file opens and reads schema 0; under
        --require-db that is not the migrated live DB, so exit 5, never
        update_available rc 1. Without the flag the fresh-install 0 stays."""
        empty = tmp_path / "empty.db"
        empty.write_bytes(b"")
        argv = ["version-check", "--db", str(empty), "--json", "--previous-schema-caps=53"]
        rc = cmd_version_check(_parse(argv + (["--require-db"] if flag else [])))
        out = json.loads(capsys.readouterr().out)
        if flag:
            assert rc == cli_mod._VERSION_CHECK_DB_UNREADABLE and out["status"] == "db_unreadable", out
        else:
            assert rc == 1 and out["db_schema_version"] == 0, out
