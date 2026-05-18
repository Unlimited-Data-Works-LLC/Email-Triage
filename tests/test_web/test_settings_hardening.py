"""Tests for Bundle D #140.1 + #140.2 + #145.7 — settings-layer hardening.

Covers:
    * ``get_setting`` defensive on a corrupt ``settings.value_json`` row
      (returns None + emits a structured WARNING with the key only —
      not the value, which is suspect / potentially sensitive).
    * In-process TTL cache around ``get_setting`` (#140.2): repeated
      reads under TTL hit the cache; expiry triggers a fresh SELECT;
      ``set_setting`` invalidates the cached entry.
    * Cache is process-local (in-memory dict; tests verify the
      isolation by mutating the DB directly under a held cache entry
      and confirming the read still returns the cached value until
      the cache is invalidated).
    * ``set_bool_setting`` / ``get_bool_setting`` round-trip
      (#145.7); default applied when the row is absent; legacy
      ``{"enabled": True}`` blobs remain readable.
"""

from __future__ import annotations

import json
import logging
import time
from datetime import datetime, timezone

import pytest

from email_triage.web import db as db_module
from email_triage.web.db import (
    delete_setting,
    get_bool_setting,
    get_setting,
    init_db,
    invalidate_setting_cache,
    set_bool_setting,
    set_setting,
)


@pytest.fixture
def conn():
    """Fresh in-memory DB + a clean settings cache."""
    c = init_db(":memory:")
    invalidate_setting_cache()
    yield c
    invalidate_setting_cache()


# ---------------------------------------------------------------------------
# #140.1 — corrupt-row defensive
# ---------------------------------------------------------------------------

class TestCorruptRowDefensive:
    def test_corrupt_json_returns_none(self, conn, caplog):
        """A row with mangled JSON returns None instead of raising."""
        now = datetime.now(timezone.utc).isoformat()
        conn.execute(
            "INSERT INTO settings (key, value_json, updated_at) "
            "VALUES (?, ?, ?)",
            ("corrupt:42", "{not valid json", now),
        )
        conn.commit()

        with caplog.at_level(logging.WARNING, logger="email_triage.web.db.settings"):
            result = get_setting(conn, "corrupt:42")

        assert result is None

    def test_corrupt_json_emits_warning_with_key(self, conn, caplog):
        """The WARNING log carries the key (not the value)."""
        now = datetime.now(timezone.utc).isoformat()
        conn.execute(
            "INSERT INTO settings (key, value_json, updated_at) "
            "VALUES (?, ?, ?)",
            ("corrupt:rspamd-token", '{"a": <oops>}', now),
        )
        conn.commit()

        with caplog.at_level(logging.WARNING, logger="email_triage.web.db.settings"):
            get_setting(conn, "corrupt:rspamd-token")

        records = [
            r for r in caplog.records
            if r.name == "email_triage.web.db.settings"
            and "settings_row_corrupt_json" in r.getMessage()
        ]
        assert len(records) == 1
        # Key MUST appear in the structured extra.
        assert getattr(records[0], "_extra", {}).get("key") == "corrupt:rspamd-token"

    def test_corrupt_log_does_not_leak_value(self, conn, caplog):
        """The suspect value never appears in the log line."""
        secret_value = "PARTIAL-WRITE-SECRET-XYZZY"
        now = datetime.now(timezone.utc).isoformat()
        # Truncated JSON that looks like an interrupted write.
        broken = '{"token": "' + secret_value
        conn.execute(
            "INSERT INTO settings (key, value_json, updated_at) "
            "VALUES (?, ?, ?)",
            ("auth:somekey", broken, now),
        )
        conn.commit()

        with caplog.at_level(logging.WARNING, logger="email_triage.web.db.settings"):
            get_setting(conn, "auth:somekey")

        for r in caplog.records:
            if r.name != "email_triage.web.db.settings":
                continue
            extras = getattr(r, "_extra", {})
            for v in extras.values():
                assert secret_value not in str(v)
            assert secret_value not in r.getMessage()

    def test_corrupt_row_does_not_pollute_cache(self, conn):
        """A subsequent valid set+get for the same key works after corrupt read."""
        now = datetime.now(timezone.utc).isoformat()
        conn.execute(
            "INSERT INTO settings (key, value_json, updated_at) "
            "VALUES (?, ?, ?)",
            ("flap:1", "{nope", now),
        )
        conn.commit()

        assert get_setting(conn, "flap:1") is None

        # An operator fixes the row via set_setting → cache invalidated.
        set_setting(conn, "flap:1", {"ok": True})
        assert get_setting(conn, "flap:1") == {"ok": True}


# ---------------------------------------------------------------------------
# #140.2 — TTL cache
# ---------------------------------------------------------------------------

class TestTTLCache:
    def test_cache_hit_avoids_select(self, conn):
        """100 reads of the same key under TTL = 1 SELECT."""
        set_setting(conn, "hot:1", {"v": 1})
        invalidate_setting_cache()  # clear write-side seed

        select_calls: list[str] = []

        def trace(sql):
            if "SELECT value_json FROM settings" in sql:
                select_calls.append(sql)

        conn.set_trace_callback(trace)
        try:
            for _ in range(100):
                assert get_setting(conn, "hot:1") == {"v": 1}
        finally:
            conn.set_trace_callback(None)

        assert len(select_calls) == 1, (
            f"expected 1 SELECT under TTL, got {len(select_calls)}"
        )

    def test_cache_expiry_triggers_fresh_select(self, conn, monkeypatch):
        """After TTL expires the next read re-queries SQLite."""
        # Tiny TTL so the test doesn't sleep for a minute.
        monkeypatch.setattr(db_module, "_SETTINGS_CACHE_TTL_SECONDS", 0.05)
        set_setting(conn, "hot:2", {"v": 2})
        invalidate_setting_cache()

        select_calls: list[str] = []

        def trace(sql):
            if "SELECT value_json FROM settings" in sql:
                select_calls.append(sql)

        conn.set_trace_callback(trace)
        try:
            get_setting(conn, "hot:2")
            get_setting(conn, "hot:2")
            time.sleep(0.07)
            get_setting(conn, "hot:2")
        finally:
            conn.set_trace_callback(None)

        # Two SELECTs total: one before sleep, one after expiry.
        assert len(select_calls) == 2, (
            f"expected 2 SELECTs (pre + post-expiry), got {len(select_calls)}"
        )

    def test_set_setting_invalidates_cache(self, conn):
        """A subsequent set_setting forces the next read to re-SELECT."""
        set_setting(conn, "hot:3", {"v": 3})
        # Prime the cache.
        assert get_setting(conn, "hot:3") == {"v": 3}

        select_calls: list[str] = []

        def trace(sql):
            if "SELECT value_json FROM settings" in sql:
                select_calls.append(sql)

        conn.set_trace_callback(trace)
        try:
            # Cached read — no SELECT.
            get_setting(conn, "hot:3")
            assert len(select_calls) == 0

            # Write invalidates → next read SELECTs.
            set_setting(conn, "hot:3", {"v": 4})
            assert get_setting(conn, "hot:3") == {"v": 4}
            assert len(select_calls) == 1
        finally:
            conn.set_trace_callback(None)

    def test_delete_setting_invalidates_cache(self, conn):
        """delete_setting clears the cached value so the next read returns None."""
        set_setting(conn, "ephemeral:1", {"x": True})
        assert get_setting(conn, "ephemeral:1") == {"x": True}
        delete_setting(conn, "ephemeral:1")
        assert get_setting(conn, "ephemeral:1") is None

    def test_negative_cache_for_missing_key(self, conn):
        """Repeat reads of a missing key under TTL hit the cache."""
        select_calls: list[str] = []

        def trace(sql):
            if "SELECT value_json FROM settings" in sql:
                select_calls.append(sql)

        conn.set_trace_callback(trace)
        try:
            for _ in range(10):
                assert get_setting(conn, "absent:1") is None
        finally:
            conn.set_trace_callback(None)

        assert len(select_calls) == 1

    def test_cache_is_process_local(self, conn):
        """Cache is in-memory only — not shared with bypass writes.

        We cannot literally fork a process in a unit test; instead this
        test confirms the in-memory contract: a direct DB write that
        bypasses ``set_setting`` is NOT observed by ``get_setting``
        until the cache is explicitly invalidated. This is the
        single-writer assumption that the design depends on.
        """
        set_setting(conn, "shared:1", {"v": "first"})
        # Prime cache.
        assert get_setting(conn, "shared:1") == {"v": "first"}

        # Direct write that bypasses set_setting → cache stays stale.
        now = datetime.now(timezone.utc).isoformat()
        conn.execute(
            "UPDATE settings SET value_json = ?, updated_at = ? WHERE key = ?",
            (json.dumps({"v": "second"}), now, "shared:1"),
        )
        conn.commit()

        # Cache still serves the original value.
        assert get_setting(conn, "shared:1") == {"v": "first"}

        # Explicit invalidation → fresh read picks up the bypass write.
        invalidate_setting_cache("shared:1")
        assert get_setting(conn, "shared:1") == {"v": "second"}


# ---------------------------------------------------------------------------
# #145.7 — bool-setting helpers
# ---------------------------------------------------------------------------

class TestBoolSettingHelpers:
    def test_round_trip_true(self, conn):
        set_bool_setting(conn, "bool:1", True)
        assert get_bool_setting(conn, "bool:1") is True

    def test_round_trip_false(self, conn):
        set_bool_setting(conn, "bool:2", False)
        assert get_bool_setting(conn, "bool:2") is False

    def test_default_when_row_absent(self, conn):
        # default=False (the documented default)
        assert get_bool_setting(conn, "missing:1") is False
        # default=True override
        assert get_bool_setting(conn, "missing:2", default=True) is True

    def test_legacy_enabled_dict_blob_readable(self, conn):
        """A legacy ``{"enabled": True}`` row written via raw set_setting
        is still read correctly by get_bool_setting."""
        set_setting(conn, "legacy:1", {"enabled": True})
        assert get_bool_setting(conn, "legacy:1") is True

        set_setting(conn, "legacy:2", {"enabled": False})
        assert get_bool_setting(conn, "legacy:2") is False

    def test_set_writes_canonical_shape(self, conn):
        """set_bool_setting persists the ``{"enabled": ...}`` wrapper."""
        set_bool_setting(conn, "shape:1", True)
        invalidate_setting_cache("shape:1")
        raw = get_setting(conn, "shape:1")
        assert raw == {"enabled": True}

    def test_legacy_bare_bool_value(self, conn):
        """Pre-#145.7 rows that stored bare ``true`` are still readable
        (some early code paths used ``set_setting(..., True)`` directly)."""
        # Write a bare bool directly via the raw setter.
        set_setting(conn, "barebool:1", True)
        assert get_bool_setting(conn, "barebool:1") is True
        set_setting(conn, "barebool:2", False)
        assert get_bool_setting(conn, "barebool:2") is False

    def test_dict_without_enabled_key_falls_back_to_default(self, conn):
        """A dict row missing the ``enabled`` key uses the default."""
        set_setting(conn, "shape:malformed", {"foo": "bar"})
        invalidate_setting_cache("shape:malformed")
        assert get_bool_setting(conn, "shape:malformed", default=False) is False
        assert get_bool_setting(conn, "shape:malformed", default=True) is True
