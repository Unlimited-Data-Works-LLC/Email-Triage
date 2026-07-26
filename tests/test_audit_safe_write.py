"""run17 #3 — `web._audit.safe_audit_write` / `safe_audit_write_async` contract.

Best-effort audit-row writing: run it, never raise, log a WARNING on failure (so
/health's audit-failure drift check sees the miss). The async sibling shipped
2026-06-27 WITH a real caller (watcher.py `account_purged`); this exercises its
success + failure-logs-no-raise contract directly — an un-exercised audit helper
is a latent-bug host (the "Topic Digest shipped DEAD in prod" lesson; db-sme + DA
run17 #3).
"""
from __future__ import annotations

import logging

import pytest

from email_triage.web._audit import safe_audit_write, safe_audit_write_async

_AUDIT_LOGGER = "email_triage.web.audit"


def _capture():
    """Attach a WARNING handler to the audit logger; return (handler, records)."""
    records: list[logging.LogRecord] = []

    class _H(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            records.append(record)

    h = _H(level=logging.WARNING)
    lg = logging.getLogger(_AUDIT_LOGGER)
    prior = lg.level
    lg.setLevel(logging.WARNING)
    lg.addHandler(h)
    return h, records, lg, prior


def _boom() -> None:
    raise RuntimeError("audit write blew up")


def test_safe_audit_write_runs_the_write_on_success():
    ran: list[int] = []
    safe_audit_write(lambda: ran.append(1), description="ok-write")
    assert ran == [1]


def test_safe_audit_write_returns_the_write_value():
    # capture-and-finalise sites (e.g. triage_runner audit_event_id) rely on the
    # inserted row id flowing back; failure → None (the unset-on-except value).
    assert safe_audit_write(lambda: 4242, description="row-id") == 4242
    assert safe_audit_write(_boom, description="row-id-fail") is None


def test_safe_audit_write_swallows_and_logs_on_failure():
    h, records, lg, prior = _capture()
    try:
        # must NOT raise
        safe_audit_write(_boom, description="bad-write")
    finally:
        lg.removeHandler(h)
        lg.setLevel(prior)
    assert any(r.msg == "audit_write_failed" for r in records), (
        "a failed safe_audit_write must log the audit_write_failed WARNING"
    )


@pytest.mark.asyncio
async def test_safe_audit_write_async_runs_the_write_on_success():
    ran: list[int] = []

    async def _ok() -> None:
        ran.append(1)

    await safe_audit_write_async(lambda: _ok(), description="ok-async")
    assert ran == [1]


@pytest.mark.asyncio
async def test_safe_audit_write_async_returns_the_awaited_value():
    # The 6 capture-and-finalise sites (triage_runner audit_event_id, etc.)
    # depend on the async sibling returning the awaited row id on success and
    # None on failure — the §164.312(b) finalise flow (hipaa-sme run17 #3).
    async def _row_id() -> int:
        return 7

    async def _boom_async() -> int:
        raise RuntimeError("boom")

    assert await safe_audit_write_async(lambda: _row_id(), description="row") == 7
    assert await safe_audit_write_async(lambda: _boom_async(), description="row-fail") is None


@pytest.mark.asyncio
async def test_safe_audit_write_async_swallows_and_logs_on_failure():
    async def _boom_async() -> None:
        raise RuntimeError("async audit write blew up")

    h, records, lg, prior = _capture()
    try:
        # must NOT raise (the account-purge op must not be masked)
        await safe_audit_write_async(lambda: _boom_async(), description="bad-async")
    finally:
        lg.removeHandler(h)
        lg.setLevel(prior)
    assert any(r.msg == "audit_write_failed" for r in records), (
        "a failed safe_audit_write_async must log the audit_write_failed WARNING"
    )
