"""N-69 — ``office365_subscriptions.status`` lifecycle pin.

The subscription ``status`` column is a lifecycle flag (PD#18): SET to
``'errored'`` on any failure, CLEARED to ``'active'`` on any live success.
Before N-69 it was only cleared during renewal (``record_o365_subscription_renewal``);
a subscription that errored and then received a successful notification or
delta-walk stayed stuck as ``'errored'`` on /health until the next renewal.

The fix introduces ``record_o365_subscription_outcome(db, account_id,
error_text)`` as the status lifecycle funnel:

  * ``error_text is None``   → clear to ``'active'``, reset error bookkeeping
  * ``error_text is not None`` → set to ``'errored'``, bump error_count

This pin asserts:
1. ``record_o365_subscription_outcome`` exists and has the correct DB
   semantics (teeth — the behaviour we rely on).
2. The push-consumer success path (delta-walk) calls it.
3. The renewer failure path calls it (replacing the direct
   ``record_o365_subscription_error`` call).
4. Count-agnostic raw-SQL write guard: no module outside db.py writes
   ``status`` directly to ``office365_subscriptions`` (such a write would
   bypass the funnel and re-introduce the set-broad/clear-narrow shape).

PD#1: the pin ships in the same change as the SSOT.
PD#2: the guard is interprocedural — it catches a raw UPDATE in any
      module, not just the direct call sites the fix touched.
PD#18: both edges (set AND clear) must be wired.
"""

from __future__ import annotations

import ast
import sqlite3

from _db_tracking import track
from _pin_harness import SRC_ROOT, walk_src

SRC = SRC_ROOT


# ---------------------------------------------------------------------------
# Invariant 1 — raw SQL UPDATE of office365_subscriptions.status lives only
# in db.py (the SSOT module for this table).
# ---------------------------------------------------------------------------

_DB_PY = SRC_ROOT / "web" / "db.py"
_STATUS_COL_PATTERN = "status"
_TABLE = "office365_subscriptions"


def _has_raw_status_update(tree: ast.AST) -> list[int]:
    """Lines with a string constant that looks like a direct UPDATE of the
    office365_subscriptions table's status column."""
    hits: list[int] = []
    for n in ast.walk(tree):
        if isinstance(n, ast.Constant) and isinstance(n.value, str):
            v = n.value
            if (
                _TABLE in v
                and "UPDATE" in v
                and "status" in v
                and "SET" in v
            ):
                hits.append(getattr(n, "lineno", 0))
    return hits


def test_raw_status_update_only_in_db_py():
    """Only db.py may contain raw UPDATE office365_subscriptions...SET status...
    SQL strings — any other module doing this bypasses the funnel."""
    offenders = []
    for p, rel, tree in walk_src():
        if p == _DB_PY:
            continue
        locs = _has_raw_status_update(tree)
        if locs:
            offenders.append(f"{rel}:{locs}")
    assert not offenders, (
        "A raw UPDATE office365_subscriptions...SET status SQL literal "
        f"was found OUTSIDE web/db.py: {offenders}. Route status changes "
        "through record_o365_subscription_outcome(db, account_id, error_text) "
        "so set and clear stay symmetric across all code paths."
    )


def test_db_py_still_has_the_status_update():
    """Guard: db.py must still contain the status UPDATE (pin is non-vacuous)."""
    db_text = _DB_PY.read_text(encoding="utf-8")
    assert _TABLE in db_text and "status" in db_text, (
        "web/db.py no longer contains office365_subscriptions status management"
    )


# ---------------------------------------------------------------------------
# Invariant 2 — the push-consumer (ingestion_push.py) imports and calls the
# funnel on its delta-walk success path.
# ---------------------------------------------------------------------------
_PUSH = SRC / "web" / "ingestion_push.py"
_FUNNEL = "record_o365_subscription_outcome"


def test_push_consumer_calls_outcome_funnel():
    """ingestion_push.py must call record_o365_subscription_outcome on the
    delta-walk success path (N-69: the missing clear edge)."""
    push_text = _PUSH.read_text(encoding="utf-8")
    assert _FUNNEL in push_text, (
        "web/ingestion_push.py does NOT reference record_o365_subscription_outcome "
        "— the N-69 fix must call it after a successful Graph delta walk to clear "
        "a prior 'errored' status. Add: "
        "await db_call(record_o365_subscription_outcome, db, account_id=..., "
        "error_text=None)"
    )


# ---------------------------------------------------------------------------
# Invariant 3 — the renewer (o365_renewer.py) routes failures through the
# funnel (replacing the direct record_o365_subscription_error call).
# ---------------------------------------------------------------------------
_RENEWER = SRC / "web" / "o365_renewer.py"


def test_renewer_calls_outcome_funnel():
    """o365_renewer.py must call record_o365_subscription_outcome for failure
    outcomes (N-69: unify the set path with the new funnel)."""
    renewer_text = _RENEWER.read_text(encoding="utf-8")
    assert _FUNNEL in renewer_text, (
        "web/o365_renewer.py does NOT reference record_o365_subscription_outcome "
        "— the N-69 fix must route renewal failure through the funnel so the "
        "error and clear edges are both wired through one SSOT."
    )


# ---------------------------------------------------------------------------
# Teeth — behavioural DB tests for the funnel semantics
# ---------------------------------------------------------------------------

def _make_db_with_sub(account_id: int = 1) -> sqlite3.Connection:
    """In-memory DB with one office365_subscriptions row (status='errored')."""
    conn = track(sqlite3.connect(":memory:", check_same_thread=False))
    conn.row_factory = sqlite3.Row
    # Minimal schema matching the migration.
    conn.execute("""
        CREATE TABLE office365_subscriptions (
            account_id          INTEGER PRIMARY KEY,
            subscription_id     TEXT    NOT NULL DEFAULT '',
            expiration_at       TEXT    NOT NULL DEFAULT '',
            last_renewed_at     TEXT    NOT NULL DEFAULT '',
            last_notification_at TEXT,
            status              TEXT    NOT NULL DEFAULT 'active',
            error_count         INTEGER NOT NULL DEFAULT 0,
            error_last          TEXT,
            delta_link          TEXT,
            created_at          TEXT    NOT NULL DEFAULT '',
            updated_at          TEXT    NOT NULL DEFAULT ''
        )
    """)
    conn.execute(
        "INSERT INTO office365_subscriptions (account_id, status, error_count) "
        "VALUES (?, 'errored', 3)",
        (account_id,),
    )
    conn.commit()
    return conn


def _get_sub(conn: sqlite3.Connection, account_id: int) -> dict:
    row = conn.execute(
        "SELECT * FROM office365_subscriptions WHERE account_id = ?",
        (account_id,),
    ).fetchone()
    return dict(row) if row else {}


def test_funnel_success_clears_errored_status():
    """record_o365_subscription_outcome(error_text=None) clears a stuck
    'errored' status back to 'active' and resets error_count."""
    from email_triage.web.db import record_o365_subscription_outcome

    conn = _make_db_with_sub(account_id=1)
    sub = _get_sub(conn, 1)
    assert sub["status"] == "errored"
    assert sub["error_count"] == 3

    record_o365_subscription_outcome(conn, account_id=1, error_text=None)

    sub_after = _get_sub(conn, 1)
    assert sub_after["status"] == "active", (
        "N-69: record_o365_subscription_outcome(error_text=None) must set "
        "status='active' — the clear edge was missing before this fix."
    )
    assert sub_after["error_count"] == 0
    assert sub_after["error_last"] is None


def test_funnel_failure_sets_errored_status():
    """record_o365_subscription_outcome(error_text=...) sets status='errored'
    and bumps the error counter."""
    from email_triage.web.db import record_o365_subscription_outcome
    conn = _make_db_with_sub(account_id=2)
    # Reset to active first.
    conn.execute(
        "UPDATE office365_subscriptions SET status='active', error_count=0 "
        "WHERE account_id=2"
    )
    conn.commit()

    record_o365_subscription_outcome(
        conn, account_id=2, error_text="Graph 401: token expired"
    )

    sub = _get_sub(conn, 2)
    assert sub["status"] == "errored", (
        "N-69: record_o365_subscription_outcome(error_text!=None) must set "
        "status='errored'."
    )
    assert sub["error_count"] == 1


def test_funnel_clear_idempotent():
    """Calling the clear path when already active is a no-op (idempotent)."""
    from email_triage.web.db import record_o365_subscription_outcome
    conn = _make_db_with_sub(account_id=3)
    # Set to active.
    conn.execute(
        "UPDATE office365_subscriptions SET status='active', error_count=0 "
        "WHERE account_id=3"
    )
    conn.commit()

    # Call clear again — should not error, status stays active.
    record_o365_subscription_outcome(conn, account_id=3, error_text=None)
    sub = _get_sub(conn, 3)
    assert sub["status"] == "active"
    assert sub["error_count"] == 0


def test_funnel_secrets_scrubbed_in_error():
    """The failure path scrubs token-shaped secrets from the error text
    before persisting (reuses the _scrub_secrets logic from db.py)."""
    from email_triage.web.db import record_o365_subscription_outcome
    conn = _make_db_with_sub(account_id=4)
    conn.execute(
        "UPDATE office365_subscriptions SET status='active' WHERE account_id=4"
    )
    conn.commit()

    # A Graph error response that carries a secret-shaped token.
    error_with_token = (
        "Graph API error: {'access_token': 'eyJhbGciOiJSUzI1NiJ9.secret', "
        "'error': 'token_expired'}"
    )
    record_o365_subscription_outcome(
        conn, account_id=4, error_text=error_with_token
    )
    sub = _get_sub(conn, 4)
    assert sub["status"] == "errored"
    # The raw token must not be stored verbatim (the scrub replaces
    # the token value with a placeholder).
    assert "eyJhbGciOiJSUzI1NiJ9.secret" not in (sub["error_last"] or "")


# ---------------------------------------------------------------------------
# N-352b R31 (2026-07-04) — the funnel itself must NOT duplicate the
# ``status='errored'`` UPDATE inline. Extends N-69's existing "no raw
# UPDATE outside db.py" guard with a companion "no raw UPDATE inside the
# funnel body" invariant. The original guard walked EVERY module except
# db.py; drift-twin writes INSIDE `record_o365_subscription_outcome`
# (the SSOT itself) slipped past. This invariant walks db.py + uses
# ``enclosing_qualified_name`` from the pin harness to reject any raw
# ``UPDATE office365_subscriptions ... status='errored'`` string constant
# whose enclosing fn is ``record_o365_subscription_outcome``. Only
# ``record_o365_subscription_error`` may carry the errored-UPDATE.
# ---------------------------------------------------------------------------

from _pin_harness import enclosing_qualified_name, parse_module


def test_funnel_body_does_not_duplicate_errored_update():
    """N-352b: `record_o365_subscription_outcome` MUST NOT contain a raw
    `UPDATE office365_subscriptions ... status='errored'` string. The
    failure path MUST delegate to `record_o365_subscription_error` per
    the funnel's docstring. Fails LOUD if a future refactor unrolls the
    delegation back to an inline UPDATE (recreating the drift-twin the
    N-352 fix collapsed).
    """
    tree = parse_module(_DB_PY)
    assert tree is not None, "parse_module returned None for db.py"
    violations: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Constant) and isinstance(node.value, str)):
            continue
        v = node.value
        if _TABLE not in v or "UPDATE" not in v.upper():
            continue
        if "status" not in v.lower() or "errored" not in v.lower():
            continue
        qname = enclosing_qualified_name(node)
        if qname == "record_o365_subscription_outcome":
            violations.append((node.lineno, qname))
    if violations:
        lines = ", ".join(f"line {ln}" for ln, _ in violations)
        raise AssertionError(
            "N-352b: `record_o365_subscription_outcome` contains a raw "
            f"``UPDATE office365_subscriptions ... status='errored'`` at {lines}. "
            "The funnel's docstring promises delegation to "
            "`record_o365_subscription_error` on the failure path — "
            "unroll defeats the SSOT and reopens the drift-twin class "
            "(N-352). Restore the delegation."
        )
