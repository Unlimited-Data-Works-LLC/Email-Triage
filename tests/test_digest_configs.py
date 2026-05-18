"""Tests for digest_configs storage + migration.

Covers:
- Schema dataclass round-trip (from_dict / to_dict).
- list_digest_configs fresh-account path: returns the preset card
  even when nothing is stored.
- Legacy migration: ``recipient_digest_enabled`` flag promotes to
  the preset entry; ``digest_schedules:<id>`` rows promote to
  ``custom`` entries with category preserved.
- upsert_digest_config: insert + update, preset id is locked to
  ``preset_daily_activity`` kind regardless of incoming kind.
- delete_digest_config: refuses preset deletion; removes custom
  entries cleanly.
- validate(): catches bad enums, missing required fields, bad
  HH:MM, weekly without days, max_rows out of range.
"""

from __future__ import annotations

import pytest


from email_triage.actions.digest_configs import (  # noqa: E402
    DigestConfig, DigestFilter, DigestFormat, DigestSchedule,
    DigestWindow,
    PRESET_ID,
    delete_digest_config,
    from_dict,
    get_digest_config,
    list_digest_configs,
    to_dict,
    upsert_digest_config,
    validate,
)


@pytest.fixture
def db(tmp_path):
    """Init-DB fixture — sqlite file per test, settings table ready."""
    from email_triage.web.db import init_db
    db_path = tmp_path / "triage.db"
    conn = init_db(str(db_path))
    yield conn
    conn.close()


@pytest.fixture
def account(db):
    """A minimal IMAP account row to anchor digest configs against."""
    from datetime import datetime, timezone
    from email_triage.web.db import create_email_account
    now = datetime.now(timezone.utc).isoformat()
    cur = db.execute(
        "INSERT INTO users (email, name, role, created_at) "
        "VALUES (?, ?, ?, ?)",
        ("t@t.test", "T", "user", now),
    )
    user_id = int(cur.lastrowid)
    db.commit()
    acct_id = create_email_account(
        db, user_id, "Test", "imap",
        {
            "host": "x.test", "port": 993, "username": "u",
            "use_ssl": True,
        },
    )
    return acct_id


# ---------------------------------------------------------------------------
# Schema round-trip
# ---------------------------------------------------------------------------


def test_from_dict_round_trip():
    raw = {
        "id": "digest_abc",
        "kind": "custom",
        "name": "AI News",
        "enabled": True,
        "schedule": {"cadence": "weekly", "time_local": "06:30",
                     "days_of_week": [0, 1, 2, 3, 4]},
        "window": {"kind": "since_last_sent"},
        "filter": {
            "read_state": "unread",
            "folders": ["INBOX", "Newsletters"],
            "categories": ["Newsletter", "AI-Newsletters"],
            "tags": ["$EmailTriaged"],
            "from_addr": "x@y", "subject": "", "list_id": "",
            "has_attachment": None, "actions": [], "advanced": "",
        },
        "format": {
            "render_as": "grouped_list", "group_by": "category",
            "include_body_preview": True, "max_rows": 50,
        },
    }
    cfg = from_dict(raw)
    assert cfg.id == "digest_abc"
    assert cfg.kind == "custom"
    assert cfg.schedule.cadence == "weekly"
    assert cfg.filter.categories == ["Newsletter", "AI-Newsletters"]
    assert cfg.format.render_as == "grouped_list"

    # Round-trip via to_dict reproduces a comparable shape.
    out = to_dict(cfg)
    assert out["filter"]["folders"] == ["INBOX", "Newsletters"]
    assert out["window"]["kind"] == "since_last_sent"


def test_from_dict_partial_defaults_safely():
    """A stored config that only carries a few keys still hydrates.
    Custom-digest defaults: cadence=daily, render_as=table, default
    column set [datetime, sender, headline, link]."""
    cfg = from_dict({"name": "minimal"})
    assert cfg.name == "minimal"
    assert cfg.kind == "custom"  # default
    assert cfg.schedule.cadence == "daily"
    assert cfg.format.render_as == "table"
    keys = [c.key for c in cfg.format.columns]
    assert keys == ["datetime", "sender", "headline", "link"]


def test_from_dict_unknown_kind_falls_back_to_custom():
    cfg = from_dict({"kind": "totally_made_up"})
    assert cfg.kind == "custom"


# ---------------------------------------------------------------------------
# Fresh-account path
# ---------------------------------------------------------------------------


def test_list_returns_preset_for_fresh_account(db, account):
    """No legacy fields, no stored configs → list = [preset only],
    preset disabled by default."""
    configs = list_digest_configs(db, account)
    assert len(configs) == 1
    assert configs[0].id == PRESET_ID
    assert configs[0].kind == "preset_daily_activity"
    assert configs[0].enabled is False


# ---------------------------------------------------------------------------
# Legacy migration
# ---------------------------------------------------------------------------


def test_migration_preserves_recipient_digest_enabled(db, account):
    """Legacy ``recipient_digest_enabled`` flag promotes the preset
    to enabled=True with the legacy send time."""
    from email_triage.web.db import (
        get_email_account, update_email_account,
    )
    acct = get_email_account(db, account)
    cfg = dict(acct["config"])
    cfg["recipient_digest_enabled"] = True
    cfg["recipient_digest_send_at"] = "09:10"
    update_email_account(
        db, account, name=acct["name"], provider_type=acct["provider_type"],
        config=cfg, is_active=True,
    )
    configs = list_digest_configs(db, account)
    preset = configs[0]
    assert preset.id == PRESET_ID
    assert preset.enabled is True
    assert preset.schedule.time_local == "09:10"


def test_migration_promotes_legacy_digest_schedules(db, account):
    """Legacy ``digest_schedules:<id>`` rows become ``custom`` entries
    with the category promoted to a single-element categories list."""
    from email_triage.web.db import set_setting
    set_setting(db, f"digest_schedules:{account}", [
        {
            "time_utc": "07:00",
            "category": "newsletters",
            "cadence": "daily",
            "enabled": True,
        },
        {
            "time_utc": "08:00",
            "category": "promotions",
            "cadence": "weekly",
            "days_of_week": [0, 1, 2, 3, 4],
            "enabled": False,
        },
    ])
    configs = list_digest_configs(db, account)
    assert configs[0].id == PRESET_ID  # preset always first
    customs = [c for c in configs if c.kind == "custom"]
    assert len(customs) == 2
    cat_one = customs[0]
    assert cat_one.filter.categories == ["newsletters"]
    assert cat_one.schedule.time_local == "07:00"
    assert cat_one.enabled is True
    cat_two = customs[1]
    assert cat_two.filter.categories == ["promotions"]
    assert cat_two.schedule.cadence == "weekly"
    assert cat_two.schedule.days_of_week == [0, 1, 2, 3, 4]
    assert cat_two.enabled is False


def test_migration_persists_unified_format(db, account):
    """First read writes the unified ``digest_configs:<id>`` row so
    subsequent reads don't redo migration work."""
    from email_triage.web.db import get_setting, set_setting
    set_setting(db, f"digest_schedules:{account}", [
        {"time_utc": "07:00", "category": "newsletters", "enabled": True},
    ])
    list_digest_configs(db, account)  # triggers migration
    stored = get_setting(db, f"digest_configs:{account}")
    assert isinstance(stored, list)
    assert any(s.get("kind") == "preset_daily_activity" for s in stored)
    assert any(s.get("kind") == "custom" for s in stored)


# ---------------------------------------------------------------------------
# CRUD
# ---------------------------------------------------------------------------


def test_upsert_inserts_new_custom_digest(db, account):
    cfg = DigestConfig(
        kind="custom", name="AI News", enabled=True,
        filter=DigestFilter(categories=["Newsletter"]),
    )
    saved = upsert_digest_config(db, account, cfg)
    assert saved.id  # minted
    configs = list_digest_configs(db, account)
    assert any(c.id == saved.id for c in configs)


def test_upsert_updates_existing_custom_digest(db, account):
    cfg = DigestConfig(kind="custom", name="orig")
    saved = upsert_digest_config(db, account, cfg)
    saved.name = "renamed"
    upsert_digest_config(db, account, saved)
    found = get_digest_config(db, account, saved.id)
    assert found is not None
    assert found.name == "renamed"


def test_upsert_locks_preset_id_to_preset_kind(db, account):
    """Caller can't demote the preset to ``custom`` by re-saving it
    with a wrong kind — the writer normalises."""
    bad = DigestConfig(
        id=PRESET_ID, kind="custom", name="should not stick",
    )
    saved = upsert_digest_config(db, account, bad)
    assert saved.kind == "preset_daily_activity"
    assert saved.name == "Daily Activity"
    assert saved.format.render_as == "table"


def test_delete_removes_custom_digest(db, account):
    cfg = DigestConfig(kind="custom", name="to delete")
    saved = upsert_digest_config(db, account, cfg)
    assert delete_digest_config(db, account, saved.id) is True
    assert get_digest_config(db, account, saved.id) is None


def test_delete_refuses_preset(db, account):
    list_digest_configs(db, account)  # ensure preset exists
    assert delete_digest_config(db, account, PRESET_ID) is False
    # Preset still present.
    assert get_digest_config(db, account, PRESET_ID) is not None


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def test_validate_clean_config_returns_no_errors():
    cfg = DigestConfig(
        kind="custom", name="ok",
        schedule=DigestSchedule(cadence="daily", time_local="08:10"),
    )
    assert validate(cfg) == []


def test_validate_catches_missing_name_on_custom():
    cfg = DigestConfig(kind="custom", name="")
    errors = validate(cfg)
    assert any("name" in e for e in errors)


def test_validate_catches_bad_time():
    cfg = DigestConfig(kind="custom", name="x")
    cfg.schedule.time_local = "bad-time"
    errors = validate(cfg)
    assert any("time_local" in e for e in errors)


def test_validate_catches_weekly_without_days():
    cfg = DigestConfig(kind="custom", name="x")
    cfg.schedule.cadence = "weekly"
    cfg.schedule.days_of_week = []
    errors = validate(cfg)
    assert any("day_of_week" in e for e in errors)


def test_validate_catches_unknown_action_key():
    cfg = DigestConfig(kind="custom", name="x")
    cfg.filter.actions = ["moved", "made-up-action"]
    errors = validate(cfg)
    assert any("action" in e for e in errors)


def test_validate_catches_max_rows_out_of_range():
    cfg = DigestConfig(kind="custom", name="x")
    cfg.format.max_rows = 0
    errors = validate(cfg)
    assert any("max_rows" in e for e in errors)


def test_validate_catches_unknown_column_key():
    from email_triage.actions.digest_configs import DigestColumn
    cfg = DigestConfig(kind="custom", name="x")
    cfg.format.columns = [
        DigestColumn(key="totally-made-up"),
    ]
    errors = validate(cfg)
    assert any("columns[0].key" in e for e in errors)


def test_validate_catches_bad_sort_direction():
    from email_triage.actions.digest_configs import DigestColumn
    cfg = DigestConfig(kind="custom", name="x")
    cfg.format.columns = [
        DigestColumn(key="datetime", sort_direction="sideways"),
    ]
    errors = validate(cfg)
    assert any("sort_direction" in e for e in errors)


def test_validate_catches_duplicate_column_keys():
    """A digest with two ``sender`` columns is operator confusion;
    reject so the editor surfaces the mistake instead of rendering
    a degenerate table."""
    from email_triage.actions.digest_configs import DigestColumn
    cfg = DigestConfig(kind="custom", name="x")
    cfg.format.columns = [
        DigestColumn(key="datetime"),
        DigestColumn(key="sender"),
        DigestColumn(key="sender"),
    ]
    errors = validate(cfg)
    assert any("duplicates" in e for e in errors)


def test_validate_table_render_requires_non_empty_columns():
    cfg = DigestConfig(kind="custom", name="x")
    cfg.format.render_as = "table"
    cfg.format.columns = []
    errors = validate(cfg)
    assert any("columns" in e and "table" in e for e in errors)


# ---------------------------------------------------------------------------
# Newsletter render_as enum + backfill (2026-05-06)
# ---------------------------------------------------------------------------


def test_validate_accepts_newsletter_render_as():
    cfg = DigestConfig(kind="custom", name="news")
    cfg.format.render_as = "newsletter"
    assert validate(cfg) == []


def test_validate_accepts_newsletter_classic_render_as():
    cfg = DigestConfig(kind="custom", name="news")
    cfg.format.render_as = "newsletter_classic"
    assert validate(cfg) == []


def test_backfill_flips_category_newsletter_grouped_list():
    import sqlite3
    from email_triage.web.db import init_db, set_setting, get_setting
    from email_triage.actions.digest_configs import (
        _backfill_newsletter_render_as,
    )

    conn = init_db(":memory:")
    conn.execute(
        "INSERT INTO users (email, name, role, created_at) "
        "VALUES ('u@x', 'u', 'user', '2026-01-01')",
    )
    conn.execute(
        "INSERT INTO email_accounts (name, provider_type, config_json, "
        " is_active, created_at, updated_at, user_id) "
        "VALUES ('a', 'imap', '{}', 1, '2026-01-01', '2026-01-01', 1)",
    )
    conn.commit()
    set_setting(conn, "digest_configs:1", [
        {
            "id": "d1", "kind": "custom", "name": "newsletter",
            "enabled": True,
            "schedule": {"cadence": "daily", "time_local": "08:10",
                         "days_of_week": []},
            "window": {"kind": "rolling_24h"},
            "filter": {"categories": ["newsletters"]},
            "format": {"render_as": "grouped_list", "group_by": "none"},
        },
    ])

    flipped = _backfill_newsletter_render_as(conn)
    assert flipped == 1
    cfg = get_setting(conn, "digest_configs:1")
    assert cfg[0]["format"]["render_as"] == "newsletter"


def test_backfill_idempotent_on_second_run():
    from email_triage.web.db import init_db, set_setting, get_setting
    from email_triage.actions.digest_configs import (
        _backfill_newsletter_render_as,
    )

    conn = init_db(":memory:")
    conn.execute(
        "INSERT INTO users (email, name, role, created_at) "
        "VALUES ('u@x', 'u', 'user', '2026-01-01')",
    )
    conn.execute(
        "INSERT INTO email_accounts (name, provider_type, config_json, "
        " is_active, created_at, updated_at, user_id) "
        "VALUES ('a', 'imap', '{}', 1, '2026-01-01', '2026-01-01', 1)",
    )
    conn.commit()
    set_setting(conn, "digest_configs:1", [
        {
            "id": "d1", "kind": "custom", "name": "newsletter",
            "enabled": True,
            "schedule": {"cadence": "daily", "time_local": "08:10",
                         "days_of_week": []},
            "window": {"kind": "rolling_24h"},
            "filter": {"categories": ["newsletters"]},
            "format": {"render_as": "grouped_list", "group_by": "none"},
        },
    ])
    _backfill_newsletter_render_as(conn)
    second = _backfill_newsletter_render_as(conn)
    assert second == 0


def test_backfill_skips_table_render():
    """Operator-set table render is preserved — only configs still
    on the migration default (grouped_list / plain_list) flip."""
    from email_triage.web.db import init_db, set_setting, get_setting
    from email_triage.actions.digest_configs import (
        _backfill_newsletter_render_as,
    )

    conn = init_db(":memory:")
    conn.execute(
        "INSERT INTO users (email, name, role, created_at) "
        "VALUES ('u@x', 'u', 'user', '2026-01-01')",
    )
    conn.execute(
        "INSERT INTO email_accounts (name, provider_type, config_json, "
        " is_active, created_at, updated_at, user_id) "
        "VALUES ('a', 'imap', '{}', 1, '2026-01-01', '2026-01-01', 1)",
    )
    conn.commit()
    set_setting(conn, "digest_configs:1", [
        {
            "id": "d1", "kind": "custom", "name": "newsletter table",
            "enabled": True,
            "schedule": {"cadence": "daily", "time_local": "08:10",
                         "days_of_week": []},
            "window": {"kind": "rolling_24h"},
            "filter": {"categories": ["newsletters"]},
            "format": {"render_as": "table", "group_by": "none"},
        },
    ])
    flipped = _backfill_newsletter_render_as(conn)
    assert flipped == 0
    cfg = get_setting(conn, "digest_configs:1")
    assert cfg[0]["format"]["render_as"] == "table"


def test_backfill_skips_non_newsletter_categories():
    """Configs filtering on non-newsletter categories don't flip."""
    from email_triage.web.db import init_db, set_setting, get_setting
    from email_triage.actions.digest_configs import (
        _backfill_newsletter_render_as,
    )

    conn = init_db(":memory:")
    conn.execute(
        "INSERT INTO users (email, name, role, created_at) "
        "VALUES ('u@x', 'u', 'user', '2026-01-01')",
    )
    conn.execute(
        "INSERT INTO email_accounts (name, provider_type, config_json, "
        " is_active, created_at, updated_at, user_id) "
        "VALUES ('a', 'imap', '{}', 1, '2026-01-01', '2026-01-01', 1)",
    )
    conn.commit()
    set_setting(conn, "digest_configs:1", [
        {
            "id": "d1", "kind": "custom", "name": "vip senders",
            "enabled": True,
            "schedule": {"cadence": "daily", "time_local": "08:10",
                         "days_of_week": []},
            "window": {"kind": "rolling_24h"},
            "filter": {"categories": ["personal"]},
            "format": {"render_as": "grouped_list", "group_by": "none"},
        },
    ])
    flipped = _backfill_newsletter_render_as(conn)
    assert flipped == 0
