"""N-192 R20_20 — safe_audit_write's failure path bumps app.state.audit_failures.

Before N-192, a swallowed audit-write failure was WARNING-logged but never
reached the counter that /health reads. /health's `audit_failures > 0` gate
therefore couldn't flip degraded on a swallowed emit — the failure was
invisible to the counter-based drift check.

Fix landed 2026-07-01: `web/_audit.py::_audit_failure_sink` is a module-
level indirection; `web/app.py::lifespan` registers a callback that bumps
`app.state.audit_failures`. On sink=None (CLI, tests before lifespan runs),
the failure log is unchanged.
"""
from __future__ import annotations

import pytest

from email_triage.web import _audit


class TestAuditFailureSink:

    def teardown_method(self):
        _audit.register_audit_failure_sink(None)

    def test_sink_fires_on_sync_failure(self):
        hits = []
        _audit.register_audit_failure_sink(lambda: hits.append(1))
        result = _audit.safe_audit_write(
            lambda: (_ for _ in ()).throw(RuntimeError("boom")),
            description="sync_test",
        )
        assert result is None
        assert hits == [1]

    def test_sink_silent_on_sync_success(self):
        hits = []
        _audit.register_audit_failure_sink(lambda: hits.append(1))
        result = _audit.safe_audit_write(lambda: "ok", description="sync_ok")
        assert result == "ok"
        assert hits == []

    @pytest.mark.asyncio
    async def test_sink_fires_on_async_failure(self):
        hits = []
        _audit.register_audit_failure_sink(lambda: hits.append(1))

        async def _boom():
            raise RuntimeError("async boom")

        result = await _audit.safe_audit_write_async(_boom, description="async_test")
        assert result is None
        assert hits == [1]

    def test_none_sink_is_safe(self):
        """CLI + pre-lifespan callers: no sink registered → failure still
        logged but no bump attempted (must not raise)."""
        _audit.register_audit_failure_sink(None)
        result = _audit.safe_audit_write(
            lambda: (_ for _ in ()).throw(RuntimeError("no sink")),
            description="no_sink_test",
        )
        assert result is None  # swallowed, no exception

    def test_sink_swallows_own_error(self):
        """A failing sink must NOT turn an audit-write failure into a
        caller exception (belt-and-suspenders)."""
        def _bad_sink():
            raise RuntimeError("sink itself throws")
        _audit.register_audit_failure_sink(_bad_sink)
        # Should not raise despite bad sink.
        result = _audit.safe_audit_write(
            lambda: (_ for _ in ()).throw(RuntimeError("audit-write boom")),
            description="bad_sink_test",
        )
        assert result is None
