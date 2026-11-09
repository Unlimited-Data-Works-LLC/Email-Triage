"""Regression tests for  — skip no-op JSON column UPDATEs.

Pre-#274 every ``update_flow`` call serialized + re-wrote all 4 JSON
columns (``classification_json``, ``actions_completed_json``,
``actions_pending_json``, ``state_bag_json``) regardless of whether
they had changed. Post-#274 the UPDATE only includes the columns
whose serialized form differs from the baseline captured on the
flow's last successful load/persist.

Tests pin:
* no-op update (load → no changes → update) skips all 4 JSON columns
* every mutation shape is caught (scalar reassign, in-place
  ``.append``, item-set, ``.update``)
* baseline is rebased after each persist so a second-update no-op
  doesn't false-positive-dirty

The pin uses ``sqlite3.Connection.set_trace_callback`` to inspect
the SQL that hits the engine — that's the only contract we care
about (which columns get written). Asserting on ``cur.rowcount``
or post-update ``get_flow()`` values is downstream of correctness;
the column-list is what proves the SQLite I/O was actually skipped.
"""

from __future__ import annotations

import re

from email_triage.engine.models import (
    Classification,
    FlowState,
    FlowStatus,
)
from email_triage.engine.store import FlowStore

from _db_tracking import track


def _trace(conn):
    """Attach a per-test SQL trace; returns the list it appends to."""
    captured: list[str] = []
    conn.set_trace_callback(captured.append)
    return captured


def _new_flow(store: FlowStore, *, classification=None) -> FlowState:
    """Insert a fresh flow + return the loaded form (post-_row_to_flow,
    so ``_baseline`` is stamped)."""
    flow = store.create_flow(message_id="m-274", provider="test")
    if classification is not None:
        flow.classification = classification
        flow = store.update_flow(flow, expected_revision=flow.revision)
    return store.get_flow(flow.flow_id)


def _last_update_sql(captured: list[str]) -> str:
    """Return the most recent UPDATE statement seen by the trace
    (the BEGIN/COMMIT events from the commit path are also captured;
    filter them out)."""
    updates = [s for s in captured if s.strip().upper().startswith("UPDATE FLOWS")]
    assert updates, f"expected UPDATE flows statement, got: {captured}"
    return updates[-1]


# -followup-A hardening (2026-07-11): Python 3.13's ``sqlite3.set_trace_callback``
# INLINES bound parameter values into the rendered SQL string. Substring
# assertions like ``"classification_json" in sql`` false-positive when a
# bound value happens to contain the column-name string (e.g. a JSON blob
# whose keys look like column names). Column-membership checks now route
# through ``_written_columns(sql)`` which parses the SET clause and
# returns the set of left-hand-side names — a bound value on the RHS
# cannot pollute it.
_SET_LHS_RE = re.compile(r"(?:^\s*|,\s*)(\w+)\s*=", re.MULTILINE)


def _written_columns(sql: str) -> set[str]:
    """Extract the set of column names on the LEFT-HAND side of an
    UPDATE statement's ``SET`` clause. Robust against bound values that
    happen to contain a column-name substring."""
    m = re.search(r"\bSET\b(.*?)(?:\bWHERE\b|$)", sql, re.IGNORECASE | re.DOTALL)
    if not m:
        return set()
    return set(_SET_LHS_RE.findall(m.group(1).strip()))


class TestDirtyColumnSkip:
    def test_no_op_update_skips_all_4_json_columns(self, tmp_path):
        """Load a flow, change nothing, ``update_flow`` — SQL must
        NOT contain any of the 4 JSON column names. Pre-#274 all 4
        were always present."""
        store = track(FlowStore(":memory:"))
        flow = _new_flow(store)

        captured = _trace(store._conn)
        store.update_flow(flow, expected_revision=flow.revision)
        sql = _last_update_sql(captured)
        written = _written_columns(sql)

        for col in (
            "classification_json",
            "actions_completed_json",
            "actions_pending_json",
            "state_bag_json",
        ):
            assert col not in written, (
                f"no-op update should NOT write {col}; SQL was:\n{sql}"
            )
        # Sanity: status / revision / error / updated_at always write.
        assert "status" in written
        # revision uses a scalar RHS expression (revision + 1), which
        # is checked as a literal — the SET-clause parser above only
        # tracks LHS column names.
        assert "revision = revision + 1" in sql

    def test_classification_scalar_reassign_caught(self, tmp_path):
        """Reassigning ``flow.classification`` (None → real value)
        must include classification_json in the UPDATE."""
        store = track(FlowStore(":memory:"))
        flow = _new_flow(store)
        flow.classification = Classification(
            category="to-respond", confidence=0.9,
            reason="urgent", source="ai",
        )

        captured = _trace(store._conn)
        store.update_flow(flow, expected_revision=flow.revision)
        sql = _last_update_sql(captured)
        written = _written_columns(sql)
        assert "classification_json" in written
        # Other 3 unchanged → not in the SET clause.
        assert "actions_completed_json" not in written
        assert "actions_pending_json" not in written
        assert "state_bag_json" not in written

    def test_actions_completed_in_place_append_caught(self, tmp_path):
        """In-place ``.append()`` is the failure mode dirty-flag-on-
        __setattr__ would miss. Baseline-compare catches it because
        the serialized form changes."""
        store = track(FlowStore(":memory:"))
        flow = _new_flow(store)
        flow.actions_completed.append("labeled")

        captured = _trace(store._conn)
        store.update_flow(flow, expected_revision=flow.revision)
        sql = _last_update_sql(captured)
        written = _written_columns(sql)
        assert "actions_completed_json" in written
        # Sibling columns unchanged.
        assert "classification_json" not in written
        assert "state_bag_json" not in written

    def test_state_bag_in_place_setitem_caught(self, tmp_path):
        """``flow.state_bag["k"] = "v"`` is the most common mutation
        shape — every action's ``record_action_output`` does it.
        Must be caught."""
        store = track(FlowStore(":memory:"))
        flow = _new_flow(store)
        flow.state_bag["action_results"] = {"label": "ok"}

        captured = _trace(store._conn)
        store.update_flow(flow, expected_revision=flow.revision)
        sql = _last_update_sql(captured)
        assert "state_bag_json" in _written_columns(sql)

    def test_state_bag_update_in_place_caught(self, tmp_path):
        """``flow.state_bag.update(other_dict)`` — the engine/flow.py
        precedent at line 183."""
        store = track(FlowStore(":memory:"))
        flow = _new_flow(store)
        flow.state_bag.update({"foo": "bar", "baz": 42})

        captured = _trace(store._conn)
        store.update_flow(flow, expected_revision=flow.revision)
        sql = _last_update_sql(captured)
        assert "state_bag_json" in _written_columns(sql)

    def test_baseline_rebased_after_update(self, tmp_path):
        """Two updates in a row: first mutates state_bag (column
        dirty), second changes nothing (column clean). The second
        update must NOT re-write state_bag — proves the baseline was
        rebased after the first persist."""
        store = track(FlowStore(":memory:"))
        flow = _new_flow(store)

        # First update: dirties state_bag.
        flow.state_bag["round_1"] = True
        store.update_flow(flow, expected_revision=flow.revision)

        # Second update: no JSON-column changes. Status flip only
        # (status is a scalar column, always in SQL).
        flow.status = FlowStatus.FETCHED

        captured = _trace(store._conn)
        store.update_flow(flow, expected_revision=flow.revision)
        sql = _last_update_sql(captured)
        written = _written_columns(sql)

        # state_bag was dirtied in the FIRST update but NOT the
        # second; baseline must have rebased so it's clean now.
        assert "state_bag_json" not in written, (
            f"baseline did not rebase post-write — second update "
            f"falsely re-wrote state_bag_json. SQL:\n{sql}"
        )
        assert "status" in written

    def test_no_baseline_safe_fails_to_all_dirty(self, tmp_path):
        """A FlowState whose ``_baseline`` attr is absent (e.g. a
        hand-built FlowState passed to update_flow, NOT one loaded
        via get_flow / _row_to_flow). ``update_flow`` must still
        work — falling back to "treat every column as dirty" — to
        preserve the pre-fix contract for test-constructed flows
        AND for any external code path that hand-builds a FlowState
        (e.g. cycle 6's ingestion path before the round-trip)."""
        store = track(FlowStore(":memory:"))
        flow = store.create_flow(message_id="m-baseline", provider="test")
        # Strip the baseline that create_flow stamped to simulate a
        # hand-built path.
        if hasattr(flow, "_baseline"):
            del flow._baseline
        assert not hasattr(flow, "_baseline")  # invariant for the test

        # Mutate something, then update. With no baseline the
        # safe-fail is "treat all 4 JSON columns as dirty".
        flow.state_bag["new"] = "value"

        captured = _trace(store._conn)
        store.update_flow(flow, expected_revision=flow.revision)
        sql = _last_update_sql(captured)
        written = _written_columns(sql)

        # All 4 JSON columns should be in the UPDATE — safe-fail to
        # pre-fix behavior.
        for col in (
            "classification_json",
            "actions_completed_json",
            "actions_pending_json",
            "state_bag_json",
        ):
            assert col in written, (
                f"no-baseline safe-fail should write {col} (treat "
                f"all-dirty); SQL was:\n{sql}"
            )
