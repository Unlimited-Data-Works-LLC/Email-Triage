"""N-363 R31 — atomic check-and-consume for HMAC clobber bypass.

Trust-repair fix-forward per SME panel 2026-07-05 DA F1 residual +
the backlog N-349b item 2 (TASK ). Replaces the non-atomic
`is_hmac_clobber_bypass_armed(...) → … → clear_hmac_clobber_bypass(...)`
sequence with a single `consume_hmac_clobber_bypass(...)` that uses
SQL `DELETE ... RETURNING` for race-safety against two concurrent
unreadable-reads with `armed=True` (both workers observed armed=True,
both minted — the SME panel's original F1 residual).
"""
from __future__ import annotations

import sqlite3

from email_triage.web.db import (
    HMAC_CLOBBER_BYPASS_KEY,
    arm_hmac_clobber_bypass,
    consume_hmac_clobber_bypass,
    is_hmac_clobber_bypass_armed,
)


def _fresh_conn() -> sqlite3.Connection:
    """A fresh in-memory conn with the `settings` table + row-factory
    the module expects. Schema mirrors `web/db.py::_SETTINGS_DDL`."""
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute(
        "CREATE TABLE settings ("
        "  key        TEXT PRIMARY KEY,"
        "  value_json TEXT NOT NULL,"
        "  updated_at TEXT NOT NULL"
        ")"
    )
    conn.commit()
    return conn


def test_consume_returns_false_when_not_armed():
    conn = _fresh_conn()
    assert consume_hmac_clobber_bypass(conn) is False


def test_consume_returns_true_and_deletes_row_when_armed():
    conn = _fresh_conn()
    arm_hmac_clobber_bypass(conn)
    assert is_hmac_clobber_bypass_armed(conn) is True

    consumed = consume_hmac_clobber_bypass(conn)
    assert consumed is True
    assert is_hmac_clobber_bypass_armed(conn) is False


def test_consume_is_idempotent_on_absent():
    conn = _fresh_conn()
    assert consume_hmac_clobber_bypass(conn) is False
    assert consume_hmac_clobber_bypass(conn) is False
    assert is_hmac_clobber_bypass_armed(conn) is False


def test_consume_atomic_single_row_returned_after_arm():
    """Rounding out the atomicity contract: after `arm` then one
    `consume`, a SECOND `consume` MUST return False (the row is
    gone). Regressions where consume left a stale row would return
    True twice."""
    conn = _fresh_conn()
    arm_hmac_clobber_bypass(conn)
    first = consume_hmac_clobber_bypass(conn)
    second = consume_hmac_clobber_bypass(conn)
    assert first is True
    assert second is False


def test_arm_then_arm_then_consume_still_consumes_once():
    """Double-arm is idempotent (set_setting upserts). Consume returns
    True once, then False."""
    conn = _fresh_conn()
    arm_hmac_clobber_bypass(conn)
    arm_hmac_clobber_bypass(conn)  # second arm — should be idempotent
    assert consume_hmac_clobber_bypass(conn) is True
    assert consume_hmac_clobber_bypass(conn) is False


def test_consume_survives_row_present_with_armed_false_edge_case():
    """Edge-case teeth: an inconsistent row (`{"armed": false}`)
    shouldn't stall the mechanism — the consume removes it (the arm
    helper is the SOLE writer and never writes False; this is a
    defence-in-depth teeth against a hand-written row)."""
    conn = _fresh_conn()
    conn.execute(
        "INSERT INTO settings (key, value_json, updated_at) "
        "VALUES (?, '{\"armed\": false}', '2026-07-05T00:00:00Z')",
        (HMAC_CLOBBER_BYPASS_KEY,),
    )
    conn.commit()
    # Present row with armed=false — is_armed returns False.
    assert is_hmac_clobber_bypass_armed(conn) is False
    # But consume still removes the inconsistent row (fail-safe).
    consumed = consume_hmac_clobber_bypass(conn)
    assert consumed is True
    # After consume, is_armed remains False (row gone).
    assert is_hmac_clobber_bypass_armed(conn) is False
