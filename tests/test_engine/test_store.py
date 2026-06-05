"""Tests for FlowStore — SQLite persistence with revision-checked mutations."""

import logging
import sqlite3

import pytest

from email_triage.engine.models import Classification, FlowStatus
from email_triage.engine.store import (
    DuplicateFlow,
    FlowNotFound,
    FlowStore,
    RevisionConflict,
)


class TestCreateFlow:
    def test_creates_flow_with_defaults(self, memory_store: FlowStore):
        flow = memory_store.create_flow("msg-1", "gmail_api")
        assert flow.message_id == "msg-1"
        assert flow.provider == "gmail_api"
        assert flow.status == FlowStatus.CREATED
        assert flow.revision == 0
        assert flow.classification is None
        assert flow.actions_completed == []
        assert flow.actions_pending == []

    def test_duplicate_raises(self, memory_store: FlowStore):
        memory_store.create_flow("msg-1", "gmail_api")
        with pytest.raises(DuplicateFlow):
            memory_store.create_flow("msg-1", "gmail_api")

    def test_same_message_different_provider_ok(self, memory_store: FlowStore):
        f1 = memory_store.create_flow("msg-1", "gmail_api")
        f2 = memory_store.create_flow("msg-1", "imap")
        assert f1.flow_id != f2.flow_id


class TestGetOrCreate:
    def test_creates_when_new(self, memory_store: FlowStore):
        flow, created = memory_store.get_or_create_flow("msg-1", "gmail_api")
        assert created is True
        assert flow.status == FlowStatus.CREATED

    def test_returns_existing(self, memory_store: FlowStore):
        first, _ = memory_store.get_or_create_flow("msg-1", "gmail_api")
        second, created = memory_store.get_or_create_flow("msg-1", "gmail_api")
        assert created is False
        assert second.flow_id == first.flow_id


class TestGetFlow:
    def test_found(self, memory_store: FlowStore):
        original = memory_store.create_flow("msg-1", "gmail_api")
        loaded = memory_store.get_flow(original.flow_id)
        assert loaded.flow_id == original.flow_id
        assert loaded.message_id == "msg-1"

    def test_not_found(self, memory_store: FlowStore):
        with pytest.raises(FlowNotFound):
            memory_store.get_flow("nonexistent-id")


class TestUpdateFlow:
    def test_basic_update(self, memory_store: FlowStore):
        flow = memory_store.create_flow("msg-1", "gmail_api")
        flow.status = FlowStatus.FETCHED
        updated = memory_store.update_flow(flow, expected_revision=0)
        assert updated.revision == 1
        assert updated.status == FlowStatus.FETCHED

    def test_revision_increments(self, memory_store: FlowStore):
        flow = memory_store.create_flow("msg-1", "gmail_api")
        flow.status = FlowStatus.FETCHED
        flow = memory_store.update_flow(flow, expected_revision=0)
        assert flow.revision == 1

        flow.status = FlowStatus.CLASSIFYING
        flow = memory_store.update_flow(flow, expected_revision=1)
        assert flow.revision == 2

    def test_revision_conflict(self, memory_store: FlowStore):
        flow = memory_store.create_flow("msg-1", "gmail_api")
        flow.status = FlowStatus.FETCHED
        memory_store.update_flow(flow, expected_revision=0)

        # Try to update with stale revision
        flow.status = FlowStatus.CLASSIFYING
        with pytest.raises(RevisionConflict) as exc_info:
            memory_store.update_flow(flow, expected_revision=0)
        assert exc_info.value.expected == 0
        assert exc_info.value.actual == 1

    def test_update_not_found(self, memory_store: FlowStore):
        from email_triage.engine.models import FlowState
        ghost = FlowState(
            flow_id="ghost-id",
            message_id="msg-x",
            provider="test",
            status=FlowStatus.FETCHED,
        )
        with pytest.raises(FlowNotFound):
            memory_store.update_flow(ghost, expected_revision=0)

    def test_classification_persists(self, memory_store: FlowStore):
        flow = memory_store.create_flow("msg-1", "gmail_api")
        flow.status = FlowStatus.CLASSIFIED
        flow.classification = Classification(
            category="invoices",
            confidence=0.95,
            reason="Contains invoice reference number.",
        )
        memory_store.update_flow(flow, expected_revision=0)

        loaded = memory_store.get_flow(flow.flow_id)
        assert loaded.classification is not None
        assert loaded.classification.category == "invoices"
        assert loaded.classification.confidence == 0.95

    def test_actions_persist(self, memory_store: FlowStore):
        flow = memory_store.create_flow("msg-1", "gmail_api")
        flow.status = FlowStatus.ACTING
        flow.actions_completed = ["notify"]
        flow.actions_pending = ["label", "draft_reply"]
        memory_store.update_flow(flow, expected_revision=0)

        loaded = memory_store.get_flow(flow.flow_id)
        assert loaded.actions_completed == ["notify"]
        assert loaded.actions_pending == ["label", "draft_reply"]

    def test_state_bag_persists(self, memory_store: FlowStore):
        flow = memory_store.create_flow("msg-1", "gmail_api")
        flow.status = FlowStatus.WAITING
        flow.state_bag = {"draft_id": "draft-abc", "waiting_for": "approval"}
        memory_store.update_flow(flow, expected_revision=0)

        loaded = memory_store.get_flow(flow.flow_id)
        assert loaded.state_bag["draft_id"] == "draft-abc"


class TestFindFlows:
    def test_find_by_status(self, memory_store: FlowStore):
        f1 = memory_store.create_flow("msg-1", "test")
        f2 = memory_store.create_flow("msg-2", "test")
        f1.status = FlowStatus.FETCHED
        memory_store.update_flow(f1, expected_revision=0)

        fetched = memory_store.find_flows(status=FlowStatus.FETCHED)
        created = memory_store.find_flows(status=FlowStatus.CREATED)
        assert len(fetched) == 1
        assert len(created) == 1
        assert fetched[0].flow_id == f1.flow_id

    def test_find_by_provider(self, memory_store: FlowStore):
        memory_store.create_flow("msg-1", "gmail_api")
        memory_store.create_flow("msg-2", "imap")
        results = memory_store.find_flows(provider="imap")
        assert len(results) == 1
        assert results[0].provider == "imap"

    def test_find_all(self, memory_store: FlowStore):
        memory_store.create_flow("msg-1", "test")
        memory_store.create_flow("msg-2", "test")
        memory_store.create_flow("msg-3", "test")
        assert len(memory_store.find_flows()) == 3


class TestCountByStatus:
    def test_counts(self, memory_store: FlowStore):
        f1 = memory_store.create_flow("msg-1", "test")
        memory_store.create_flow("msg-2", "test")
        f1.status = FlowStatus.FINISHED
        memory_store.update_flow(f1, expected_revision=0)

        counts = memory_store.count_by_status()
        assert counts.get("created") == 1
        assert counts.get("finished") == 1


# ---------------------------------------------------------------------------
# .4 — canonical connection injection
# ---------------------------------------------------------------------------

class TestConnectionInjection:
    """Verify the injected-connection path matches the doc contract."""

    def test_injected_connection_skips_sqlite3_connect(self, monkeypatch):
        """When ``connection`` is provided, FlowStore must NOT call
        ``sqlite3.connect``. Spy on the module-level binding the
        store reaches for."""
        import email_triage.engine.store as store_mod

        calls: list[tuple] = []
        real_connect = sqlite3.connect

        def spy(*args, **kwargs):  # pragma: no cover - hit only on regression
            calls.append((args, kwargs))
            return real_connect(*args, **kwargs)

        monkeypatch.setattr(store_mod.sqlite3, "connect", spy)

        # Caller opens the canonical connection.
        canonical = real_connect(":memory:")
        canonical.row_factory = sqlite3.Row

        store = FlowStore(connection=canonical)
        try:
            assert calls == [], (
                "FlowStore opened a second connection despite "
                f"injection (calls={calls!r})"
            )
            # Sanity check that the injected connection actually drives
            # store mutations.
            flow = store.create_flow("msg-inject-1", "test")
            assert flow.flow_id
        finally:
            store.close()
            canonical.close()

    def test_legacy_path_logs_warning_and_works(self, tmp_path, caplog):
        """``FlowStore(db_path)`` (no injection) must still function
        end-to-end AND emit a deprecation WARNING naming the entry
        point."""
        db_path = tmp_path / "legacy.db"
        # The TriageLogger wraps the stdlib logger; caplog hooks the
        # underlying logging.Logger, so capture at the root logger
        # under the email_triage namespace.
        with caplog.at_level(logging.WARNING, logger="email_triage.engine.store"):
            store = FlowStore(db_path)
            try:
                flow = store.create_flow("msg-legacy-1", "test")
                # End-to-end mutation works on the legacy path.
                flow.status = FlowStatus.FETCHED
                store.update_flow(flow, expected_revision=0)
                loaded = store.get_flow(flow.flow_id)
                assert loaded.status == FlowStatus.FETCHED
            finally:
                store.close()

        warnings = [
            r for r in caplog.records
            if r.levelno == logging.WARNING
            and "FlowStore opened its own SQLite connection" in r.getMessage()
        ]
        assert len(warnings) == 1, (
            "Legacy path must emit exactly one deprecation warning; "
            f"got {len(warnings)}"
        )

    def test_injected_connection_close_is_noop(self, tmp_path):
        """``FlowStore.close()`` must NOT close an injected
        connection — the caller (web-app lifespan) owns it.
        Closing it would orphan every other handler sharing the
        canonical connection."""
        canonical = sqlite3.connect(str(tmp_path / "shared.db"))
        canonical.row_factory = sqlite3.Row

        store = FlowStore(connection=canonical)
        store.create_flow("msg-1", "test")
        store.close()

        # Canonical conn must still be usable after store.close().
        row = canonical.execute(
            "SELECT COUNT(*) AS n FROM flows"
        ).fetchone()
        assert row["n"] == 1
        canonical.close()

    def test_shared_connection_no_expected_revision_regress(self, tmp_path):
        """Concurrent-writes regression. The @skip=tests/* architecture
        sweep flagged that TWO connections per process let an updater
        observe a stale revision. With both ``FlowStore`` and the
        ad-hoc web.db caller sharing ONE connection, revisions stay
        monotonic — no stale-read across the connection boundary."""
        canonical = sqlite3.connect(str(tmp_path / "shared.db"))
        canonical.row_factory = sqlite3.Row

        store = FlowStore(connection=canonical)
        flow = store.create_flow("msg-shared-1", "test")

        # Simulate a "web.db helper" updating the same row via the
        # shared connection (raw UPDATE — mirrors how non-FlowStore
        # code talks to the same DB).
        canonical.execute(
            "UPDATE flows SET revision = revision + 1, "
            "status = ?, updated_at = updated_at "
            "WHERE flow_id = ?",
            (FlowStatus.FETCHED.value, flow.flow_id),
        )
        canonical.commit()

        # FlowStore reading via the shared connection sees the
        # advanced revision (no stale-read). Attempting to update
        # against the now-stale local copy must surface as a
        # RevisionConflict instead of silently regressing.
        flow.status = FlowStatus.CLASSIFYING
        with pytest.raises(RevisionConflict) as exc_info:
            store.update_flow(flow, expected_revision=0)
        assert exc_info.value.actual == 1, (
            "Shared-connection update should observe the row "
            "revised by the sibling helper; got "
            f"actual={exc_info.value.actual!r}"
        )

        store.close()
        canonical.close()


# ---------------------------------------------------------------------------
#  / H-01 — HIPAA redact-at-write for ``Classification.reason``
# ---------------------------------------------------------------------------

class TestClassificationReasonHipaaRedaction:
    """``_cls_to_json`` must strip ``Classification.reason`` when
    ``is_hipaa_mode()`` is True (45 CFR §164.306(d)(3)(ii)(B) equivalent
    alternative measure to §164.312(a)(2)(iv)). See ``engine/store.py``
    ``_cls_to_json`` for the documented rationale + reg cite.
    """

    def _set_hipaa(self, value: bool) -> bool:
        """Set the process-wide HIPAA flag, return the prior value so
        the test can restore on teardown — mirrors the disciplined
        save-and-restore pattern at tests/test_log_no_token_leak.py:
        410-426 (avoids the test-contamination class that hipaa-sme
        flagged for Cycle 6)."""
        from email_triage import triage_logging
        prior = triage_logging._hipaa_mode
        triage_logging._hipaa_mode = value
        return prior

    def test_reason_stripped_in_hipaa_mode(self):
        """Unit (hipaa-sme C2): in HIPAA mode, the serialised JSON must
        carry an empty ``reason`` field — no PHI lands at rest."""
        import json as _json
        from email_triage.engine.store import _cls_to_json

        prior = self._set_hipaa(True)
        try:
            cls = Classification(
                category="medical",
                confidence=0.92,
                reason="Email cites chemotherapy dosage for patient John Doe",
                source="llm",
            )
            blob = _cls_to_json(cls)
            assert blob is not None
            parsed = _json.loads(blob)
            assert parsed["category"] == "medical"
            assert parsed["confidence"] == 0.92
            assert parsed["source"] == "llm"
            assert parsed["reason"] == "", (
                f"In HIPAA mode the LLM reason MUST be redacted; "
                f"got reason={parsed['reason']!r}"
            )
        finally:
            self._set_hipaa(prior)

    def test_reason_preserved_outside_hipaa_mode(self):
        """Negative control: with HIPAA off, ``reason`` round-trips
        verbatim. Without this we couldn't tell whether the strip is
        actually predicate-driven or accidentally always-on."""
        import json as _json
        from email_triage.engine.store import _cls_to_json

        prior = self._set_hipaa(False)
        try:
            cls = Classification(
                category="action-required",
                confidence=0.85,
                reason="Email requests review by EOD; non-PHI install context.",
                source="llm",
            )
            blob = _cls_to_json(cls)
            assert blob is not None
            parsed = _json.loads(blob)
            assert parsed["reason"] == cls.reason, (
                f"Outside HIPAA mode reason must round-trip verbatim; "
                f"got reason={parsed['reason']!r}"
            )
        finally:
            self._set_hipaa(prior)

    def test_none_classification_returns_none(self):
        """Boundary: a None Classification serialises to None
        regardless of HIPAA mode."""
        from email_triage.engine.store import _cls_to_json

        prior = self._set_hipaa(True)
        try:
            assert _cls_to_json(None) is None
        finally:
            self._set_hipaa(prior)

    def test_integration_persisted_column_has_no_reason_in_hipaa_mode(
        self, memory_store: FlowStore,
    ):
        """Integration (DA Gate 3): round-trip a HIPAA-mode flow through
        ``FlowStore.update_flow`` and read the raw
        ``classification_json`` column back via SQL. The column MUST
        carry an empty ``reason`` — the at-rest content carries no PHI.

        Belt-and-suspenders against the unit test: catches any future
        refactor that bypasses ``_cls_to_json`` (e.g. a sibling
        serializer) by exercising the actual write path."""
        import json as _json

        # Create a flow + advance it to CLASSIFIED with a PHI-bearing
        # reason; this mimics what FlowEngine.classify() does.
        flow = memory_store.create_flow("msg-hipaa-1", "gmail_api")
        flow.status = FlowStatus.CLASSIFIED
        flow.classification = Classification(
            category="medical",
            confidence=0.99,
            reason="patient X reports symptom Y after dose Z",
            source="llm",
        )

        prior = self._set_hipaa(True)
        try:
            memory_store.update_flow(flow, expected_revision=0)
        finally:
            self._set_hipaa(prior)

        # Read the raw column via SQL — bypass _cls_from_json so we see
        # exactly what landed on disk.
        row = memory_store._conn.execute(
            "SELECT classification_json FROM flows WHERE flow_id = ?",
            (flow.flow_id,),
        ).fetchone()
        assert row is not None, "flow row missing after update"
        persisted = _json.loads(row["classification_json"])
        assert persisted["category"] == "medical"
        assert persisted["confidence"] == 0.99
        assert persisted["source"] == "llm"
        assert persisted["reason"] == "", (
            f"flows.classification_json must carry empty reason in "
            f"HIPAA mode; got reason={persisted['reason']!r}"
        )

    def test_integration_persisted_column_keeps_reason_outside_hipaa(
        self, memory_store: FlowStore,
    ):
        """Negative-control integration: outside HIPAA mode the
        persisted column retains ``reason`` verbatim. Pins the
        predicate-driven behaviour of the persistence path."""
        import json as _json

        flow = memory_store.create_flow("msg-nonhipaa-1", "gmail_api")
        flow.status = FlowStatus.CLASSIFIED
        flow.classification = Classification(
            category="action-required",
            confidence=0.7,
            reason="Email asks for a meeting next Tuesday; non-PHI.",
            source="llm",
        )

        prior = self._set_hipaa(False)
        try:
            memory_store.update_flow(flow, expected_revision=0)
        finally:
            self._set_hipaa(prior)

        row = memory_store._conn.execute(
            "SELECT classification_json FROM flows WHERE flow_id = ?",
            (flow.flow_id,),
        ).fetchone()
        persisted = _json.loads(row["classification_json"])
        assert persisted["reason"] == flow.classification.reason
