""" — regulatory_clock_def seed-catalog pins.

The base policy catalog is version-controlled DATA re-asserted idempotently on
every boot (``seed_regulatory_clock_catalog``, called from ``_bootstrap_schema``).
These pins hold the regulatory invariants the design + hipaa-sme ruling require:
sponsor FDA/EU rows are non-escalating, non-overridable INFORMATIONAL receipts;
the IRB row is the escalating SITE obligation shipped candidate-only-until-
configured (D5 — duration sentinel 0, no ladder); the re-assert self-heals a
corrupted regulatory field WITHOUT clobbering the operator's ``enabled`` toggle
or a per-account override row.
"""
from __future__ import annotations

import pytest

from email_triage.db.regulatory_clock import (
    _REGULATORY_CLOCK_SEED_CATALOG,
    seed_regulatory_clock_catalog,
)
from email_triage.web.db import create_email_account, init_db

from _db_tracking import track


@pytest.fixture
def conn():
    c = track(init_db(":memory:"))
    yield c
    c.close()


def _base_rows(conn):
    return {
        r["code"]: r
        for r in conn.execute(
            "SELECT * FROM regulatory_clock_def "
            "WHERE config_owner_account_id IS NULL"
        ).fetchall()
    }


def test_catalog_seeded_on_init(conn):
    rows = _base_rows(conn)
    assert set(rows) == {
        "FDA_IND_7D_INFO", "FDA_IND_15D_INFO",
        "EU_CTR_7D_INFO", "EU_CTR_15D_INFO",
        "IRB_AWARENESS",
        # Non-FDA IRB starting points (operator 2026-06-15) — institution-
        # agnostic duration=0 sentinels (D5), armed via per-account override.
        "IRB_CONTINUING_REVIEW", "IRB_PROTOCOL_DEVIATION",
    }
    for r in rows.values():
        assert r["enabled"] == 1
        assert r["created_at"]


def test_sponsor_rows_are_locked_informational_receipts(conn):
    rows = _base_rows(conn)
    for code in ("FDA_IND_7D_INFO", "FDA_IND_15D_INFO",
                 "EU_CTR_7D_INFO", "EU_CTR_15D_INFO"):
        r = rows[code]
        assert r["clock_kind"] == "informational"   # never escalated
        assert r["duration_overridable"] == 0       # federally fixed
        assert r["ack_required"] == 0               # a receipt, no ack
        assert r["escalation_lead_pcts"] == "[]"    # no ladder
        assert r["clock_start_kind"] == "on_receipt"
    # durations match the regulation (7d fatal/LT, 15d other serious)
    assert rows["FDA_IND_7D_INFO"]["duration_value"] == 7
    assert rows["FDA_IND_15D_INFO"]["duration_value"] == 15
    assert rows["EU_CTR_7D_INFO"]["duration_value"] == 7
    assert rows["EU_CTR_15D_INFO"]["duration_value"] == 15
    assert rows["FDA_IND_7D_INFO"]["citation"] == "21 CFR 312.32(c)(2)"
    assert rows["FDA_IND_15D_INFO"]["citation"] == "21 CFR 312.32(c)(1)(i)"
    assert "536/2014" in rows["EU_CTR_7D_INFO"]["citation"]


def test_irb_row_is_escalating_candidate_only_until_configured(conn):
    r = _base_rows(conn)["IRB_AWARENESS"]
    assert r["regime"] == "IRB"
    assert r["clock_kind"] == "escalating"          # the site's real obligation
    assert r["clock_start_kind"] == "on_awareness"  # anchored to PI awareness
    assert r["duration_unit"] == "working_day"
    assert r["duration_overridable"] == 1           # institution-configurable
    assert r["duration_value"] == 0                 # UNCONFIGURED sentinel (D5)
    assert r["escalation_lead_pcts"] == "[]"        # no ladder until configured
    # we never invent an IRB number — the citation points the operator at policy
    assert "policy" in r["citation"].lower()


def test_unconfigured_sentinel_never_carries_a_ladder(conn):
    """DA Phase-2-trap guard: any base row whose duration is the UNCONFIGURED
    sentinel (<= 0) MUST carry an empty escalation ladder, so a future deadline
    computation can never do `anchor + 0` and chain a false `breached` into the
    immutable log. Count-agnostic over the whole catalog constant."""
    for entry in _REGULATORY_CLOCK_SEED_CATALOG:
        if entry["duration_value"] <= 0:
            assert entry["escalation_lead_pcts"] == "[]", (
                f"{entry['code']}: unconfigured (duration<=0) but carries a "
                f"ladder {entry['escalation_lead_pcts']!r} — Phase-2 could "
                f"compute anchor+0 = instant false breach"
            )
    # and the same invariant must hold on the SEEDED rows in the live DB
    for r in _base_rows(conn).values():
        if r["duration_value"] <= 0:
            assert r["escalation_lead_pcts"] == "[]"


def test_reseed_is_idempotent_no_duplicates(conn):
    before = conn.execute(
        "SELECT COUNT(*) FROM regulatory_clock_def"
    ).fetchone()[0]
    seed_regulatory_clock_catalog(conn)
    seed_regulatory_clock_catalog(conn)
    after = conn.execute(
        "SELECT COUNT(*) FROM regulatory_clock_def"
    ).fetchone()[0]
    assert before == after == len(_REGULATORY_CLOCK_SEED_CATALOG)


def test_reseed_reasserts_regulatory_field_but_preserves_enabled_toggle(conn):
    # operator disables a row AND a corrupted/stale citation sneaks in
    conn.execute(
        "UPDATE regulatory_clock_def "
        "SET enabled = 0, citation = 'WRONG' WHERE code = 'FDA_IND_7D_INFO'"
    )
    conn.commit()
    seed_regulatory_clock_catalog(conn)
    r = _base_rows(conn)["FDA_IND_7D_INFO"]
    assert r["citation"] == "21 CFR 312.32(c)(2)"   # regulatory fact self-healed
    assert r["enabled"] == 0                        # operator toggle PRESERVED


def test_reseed_never_clobbers_a_per_account_override_row(conn):
    # seed an IRB per-account override (distinct code, owner set, real duration)
    conn.execute(
        "INSERT INTO users (email, name, role, created_at) "
        "VALUES ('u@x','U','admin','now')"
    )
    uid = conn.execute("SELECT id FROM users").fetchone()[0]
    aid = create_email_account(
        conn, user_id=uid, name="A", provider_type="imap",
        config={"account": "a@x"}, hipaa=False,
    )
    conn.execute(
        "INSERT INTO regulatory_clock_def "
        "(code, regime, citation, title, severity_class, clock_kind, "
        " duration_value, duration_unit, clock_start_kind, duration_overridable,"
        " config_owner_account_id, enabled, created_at) "
        "VALUES ('IRB_AWARENESS@a', 'IRB', 'site SOP', 't', 'irb_up', "
        " 'escalating', 10, 'working_day', 'on_awareness', 1, ?, 1, 'now')",
        (aid,),
    )
    conn.commit()
    seed_regulatory_clock_catalog(conn)
    ov = conn.execute(
        "SELECT duration_value, citation FROM regulatory_clock_def "
        "WHERE config_owner_account_id = ?",
        (aid,),
    ).fetchone()
    assert ov["duration_value"] == 10      # operator's institutional duration intact
    assert ov["citation"] == "site SOP"    # untouched by the seed re-assert
