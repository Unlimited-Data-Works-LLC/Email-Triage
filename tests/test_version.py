"""Tests for the version + schema-compatibility helper (#125 partial).

Covers ``compute_version_status`` exhaustively across:

* forward-compat happy path (target > db)
* identical-version (target == db)
* downgrade-not-supported (target < db)
* schema-ahead rollback escalation (previous_caps < db)
* rollback-safe ``update_available`` (previous_caps >= db)
* no-previous-caps fallback (env var unset)

Also smokes the live introspection wrappers
(``read_target_schema_caps``, ``read_db_schema_version``,
``read_previous_schema_caps``) so a regression in the env-var hook or
the read-only DB open path surfaces in CI.
"""

from __future__ import annotations

import os
import sqlite3
from pathlib import Path
from unittest import mock

import pytest

from email_triage.version import (
    APP_VERSION,
    STATUS_DOWNGRADE_NOT_SUPPORTED,
    STATUS_INCOMPATIBLE_ROLLBACK,
    STATUS_UP_TO_DATE,
    STATUS_UPDATE_AVAILABLE,
    VersionStatus,
    compute_version_status,
    describe_status,
    gather_version_status,
    read_db_schema_version,
    read_previous_schema_caps,
    read_target_schema_caps,
)


# ---------------------------------------------------------------------------
# compute_version_status — the pure-function core
# ---------------------------------------------------------------------------

class TestComputeVersionStatusForwardCompat:
    """Compare DB schema vs. target binary, no `:previous` info."""

    def test_identical_versions_is_up_to_date(self):
        s = compute_version_status(
            db_schema_version=25,
            target_schema_caps=25,
        )
        assert s.status == STATUS_UP_TO_DATE
        assert s.app_version == APP_VERSION
        assert s.db_schema_version == 25
        assert s.target_schema_caps == 25
        assert s.previous_schema_caps is None
        assert "up to date" in s.explanation.lower()

    def test_target_ahead_is_update_available(self):
        s = compute_version_status(
            db_schema_version=24,
            target_schema_caps=25,
        )
        assert s.status == STATUS_UPDATE_AVAILABLE
        # No previous info, so we don't escalate to incompat-rollback
        # even though we technically don't know rollback safety.
        # Banner is strictly less alarming than the true rollback case.
        assert "update is available" in s.explanation.lower()
        assert "previous image" in s.explanation.lower()

    def test_target_ahead_by_many_is_still_update_available(self):
        s = compute_version_status(
            db_schema_version=1,
            target_schema_caps=25,
        )
        assert s.status == STATUS_UPDATE_AVAILABLE

    def test_target_behind_db_is_downgrade_not_supported(self):
        s = compute_version_status(
            db_schema_version=25,
            target_schema_caps=24,
        )
        assert s.status == STATUS_DOWNGRADE_NOT_SUPPORTED
        assert "newer than this version" in s.explanation.lower()

    def test_zero_zero_is_up_to_date(self):
        """Fresh install before any migration has run. Both sides 0."""
        s = compute_version_status(
            db_schema_version=0,
            target_schema_caps=0,
        )
        assert s.status == STATUS_UP_TO_DATE


class TestComputeVersionStatusRollbackEscalation:
    """When `:previous` schema cap is known, escalate update_available
    -> incompatible_rollback if the live DB is past `:previous`."""

    def test_previous_below_db_escalates_to_incompat(self):
        # The 2026-05-09 scenario: live DB at 14, target at 15,
        # previous image only knows up to 13.
        s = compute_version_status(
            db_schema_version=14,
            target_schema_caps=15,
            previous_schema_caps=13,
        )
        assert s.status == STATUS_INCOMPATIBLE_ROLLBACK
        assert "rolling back" in s.explanation.lower()
        assert "snapshot" in s.explanation.lower()
        assert s.previous_schema_caps == 13

    def test_previous_equal_to_db_stays_safe(self):
        # previous == db means re-tag previous is fine: the previous
        # image can open the live DB unchanged. Only the new
        # migrations on the target image would re-apply.
        s = compute_version_status(
            db_schema_version=14,
            target_schema_caps=15,
            previous_schema_caps=14,
        )
        assert s.status == STATUS_UPDATE_AVAILABLE

    def test_previous_above_db_stays_safe(self):
        # Unusual but possible: previous was rolled forward (then we
        # rolled back to today's running image) -- previous still
        # opens fine.
        s = compute_version_status(
            db_schema_version=14,
            target_schema_caps=15,
            previous_schema_caps=16,
        )
        assert s.status == STATUS_UPDATE_AVAILABLE

    def test_previous_below_db_with_target_equal_db_is_up_to_date(self):
        # No update available -> rollback safety doesn't matter.
        # incompat-rollback never fires from up_to_date.
        s = compute_version_status(
            db_schema_version=14,
            target_schema_caps=14,
            previous_schema_caps=13,
        )
        assert s.status == STATUS_UP_TO_DATE

    def test_previous_irrelevant_for_downgrade_not_supported(self):
        # Downgrade-not-supported overrides any rollback consideration.
        s = compute_version_status(
            db_schema_version=20,
            target_schema_caps=15,
            previous_schema_caps=10,
        )
        assert s.status == STATUS_DOWNGRADE_NOT_SUPPORTED


class TestVersionStatusShape:
    def test_to_dict_serialisable(self):
        s = compute_version_status(
            db_schema_version=14,
            target_schema_caps=15,
            previous_schema_caps=13,
        )
        d = s.to_dict()
        assert d["status"] == STATUS_INCOMPATIBLE_ROLLBACK
        assert d["db_schema_version"] == 14
        assert d["target_schema_caps"] == 15
        assert d["previous_schema_caps"] == 13
        assert d["app_version"] == APP_VERSION
        assert "rolling back" in d["explanation"].lower()


class TestDescribeStatus:
    """Plain-English copy belongs to the audience-rule. Sanity-smoke
    that the strings exist and don't mention forbidden jargon
    ('migration v15', 'schema_version table'). Per
    feedback_audience_per_page.md: admin pages may carry richer
    technical detail, but version-set jargon stays out."""

    def test_all_known_statuses_have_explanations(self):
        for st in (
            STATUS_UP_TO_DATE,
            STATUS_UPDATE_AVAILABLE,
            STATUS_INCOMPATIBLE_ROLLBACK,
            STATUS_DOWNGRADE_NOT_SUPPORTED,
        ):
            text = describe_status(st)
            assert text
            assert "migration v" not in text.lower()
            assert "schema_version table" not in text.lower()

    def test_unknown_status_returns_marker(self):
        assert "Unknown status" in describe_status("garbage_state")


# ---------------------------------------------------------------------------
# Live-introspection wrappers
# ---------------------------------------------------------------------------

class TestReadTargetSchemaCaps:
    def test_returns_positive_int_for_live_registry(self):
        # 25 registered today; the test would need to update only if
        # someone wanted to assert an exact value. We assert >= 1 so
        # the test survives new migrations landing on main.
        v = read_target_schema_caps()
        assert isinstance(v, int)
        assert v >= 1


class TestReadDbSchemaVersion:
    def test_missing_file_returns_zero(self, tmp_path):
        assert read_db_schema_version(tmp_path / "no-such.db") == 0

    def test_fresh_db_without_bookkeeping_table_returns_zero(self, tmp_path):
        p = tmp_path / "fresh.db"
        conn = sqlite3.connect(str(p))
        conn.execute("CREATE TABLE unrelated (id INTEGER)")
        conn.commit()
        conn.close()
        assert read_db_schema_version(p) == 0

    def test_empty_schema_migrations_returns_zero(self, tmp_path):
        p = tmp_path / "empty.db"
        conn = sqlite3.connect(str(p))
        conn.execute(
            "CREATE TABLE schema_migrations ("
            "version INTEGER PRIMARY KEY, name TEXT, "
            "applied_at TEXT, checksum TEXT)"
        )
        conn.commit()
        conn.close()
        assert read_db_schema_version(p) == 0

    def test_populated_returns_max_version(self, tmp_path):
        p = tmp_path / "live.db"
        conn = sqlite3.connect(str(p))
        conn.execute(
            "CREATE TABLE schema_migrations ("
            "version INTEGER PRIMARY KEY, name TEXT, "
            "applied_at TEXT, checksum TEXT)"
        )
        conn.executemany(
            "INSERT INTO schema_migrations "
            "(version, name, applied_at, checksum) "
            "VALUES (?, ?, ?, ?)",
            [
                (1, "first", "ts", "abc"),
                (12, "middle", "ts", "abc"),
                (14, "latest", "ts", "abc"),
            ],
        )
        conn.commit()
        conn.close()
        assert read_db_schema_version(p) == 14


class TestReadPreviousSchemaCaps:
    def test_unset_env_returns_none(self, monkeypatch):
        monkeypatch.delenv("EMAIL_TRIAGE_PREVIOUS_SCHEMA_CAPS", raising=False)
        assert read_previous_schema_caps() is None

    def test_blank_string_returns_none(self, monkeypatch):
        monkeypatch.setenv("EMAIL_TRIAGE_PREVIOUS_SCHEMA_CAPS", "")
        assert read_previous_schema_caps() is None

    def test_zero_string_returns_none(self, monkeypatch):
        # "0" is ambiguous (could mean "no previous image" or "version
        # 0"). Treat as "no info available".
        monkeypatch.setenv("EMAIL_TRIAGE_PREVIOUS_SCHEMA_CAPS", "0")
        assert read_previous_schema_caps() is None

    def test_garbage_returns_none(self, monkeypatch):
        monkeypatch.setenv("EMAIL_TRIAGE_PREVIOUS_SCHEMA_CAPS", "not-a-number")
        assert read_previous_schema_caps() is None

    def test_positive_int_returned(self, monkeypatch):
        monkeypatch.setenv("EMAIL_TRIAGE_PREVIOUS_SCHEMA_CAPS", "13")
        assert read_previous_schema_caps() == 13


class TestGatherVersionStatus:
    def test_none_db_path_returns_target_vs_zero(self, monkeypatch):
        monkeypatch.delenv("EMAIL_TRIAGE_PREVIOUS_SCHEMA_CAPS", raising=False)
        s = gather_version_status(None)
        # target_caps >= 1, db = 0 => update_available
        assert s.status == STATUS_UPDATE_AVAILABLE
        assert s.db_schema_version == 0
        assert s.app_version == APP_VERSION

    def test_reads_db_when_path_provided(self, tmp_path, monkeypatch):
        # Build a DB whose schema cap matches target -> up_to_date.
        target = read_target_schema_caps()
        p = tmp_path / "live.db"
        conn = sqlite3.connect(str(p))
        conn.execute(
            "CREATE TABLE schema_migrations ("
            "version INTEGER PRIMARY KEY, name TEXT, "
            "applied_at TEXT, checksum TEXT)"
        )
        conn.execute(
            "INSERT INTO schema_migrations VALUES (?, ?, ?, ?)",
            (target, "synthetic", "ts", "x"),
        )
        conn.commit()
        conn.close()
        monkeypatch.delenv("EMAIL_TRIAGE_PREVIOUS_SCHEMA_CAPS", raising=False)
        s = gather_version_status(p)
        assert s.status == STATUS_UP_TO_DATE
        assert s.db_schema_version == target
