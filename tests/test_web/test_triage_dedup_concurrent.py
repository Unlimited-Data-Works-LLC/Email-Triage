"""Concurrent triage on the same UID short-circuits at the in-flight gate (#114).

When two triage paths fire on the same (account, UID) within a few
seconds — push delivery + IMAP poll cycle being the canonical case —
the persistent RFC-Message-Id dedup table can't help: it isn't
written until AFTER the action chain, so both cycles see
``is_triaged() == False``.

The volatile ``app.state.triage_inflight`` set fires before the
fetch and short-circuits the second cycle without paying for the
fetch + classify + action.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest

from email_triage.web.triage_inflight import (
    claim, is_inflight, mark_inflight, release_inflight,
)


class TestInflightHelper:
    def test_mark_then_check(self):
        state = SimpleNamespace()
        assert is_inflight(state, 1, "u1") is False
        assert mark_inflight(state, 1, "u1") is True
        assert is_inflight(state, 1, "u1") is True

    def test_double_mark_returns_false(self):
        state = SimpleNamespace()
        assert mark_inflight(state, 1, "u1") is True
        assert mark_inflight(state, 1, "u1") is False

    def test_release_clears(self):
        state = SimpleNamespace()
        mark_inflight(state, 1, "u1")
        release_inflight(state, 1, "u1")
        assert is_inflight(state, 1, "u1") is False
        # Re-claim succeeds after release.
        assert mark_inflight(state, 1, "u1") is True

    def test_isolation_across_accounts(self):
        state = SimpleNamespace()
        assert mark_inflight(state, 1, "u1") is True
        # Same UID on a different account is independent.
        assert mark_inflight(state, 2, "u1") is True

    def test_release_idempotent(self):
        state = SimpleNamespace()
        # Releasing a slot that was never claimed is a no-op, not an
        # error — required so the entry-point ``finally`` clause is
        # safe even when the gate above short-circuited.
        release_inflight(state, 1, "u1")
        assert is_inflight(state, 1, "u1") is False

    def test_int_str_uid_collide(self):
        """Push consumer hands UIDs as strings; the watcher hands them
        as ints. Both must produce the same in-flight key so cross-
        path concurrency is gated."""
        state = SimpleNamespace()
        assert mark_inflight(state, 1, 42) is True
        assert mark_inflight(state, 1, "42") is False

    def test_claim_context_releases_on_exit(self):
        state = SimpleNamespace()
        with claim(state, 1, "u1") as won:
            assert won is True
            assert is_inflight(state, 1, "u1") is True
        assert is_inflight(state, 1, "u1") is False

    def test_claim_context_concurrent_returns_false(self):
        state = SimpleNamespace()
        with claim(state, 1, "u1"):
            with claim(state, 1, "u1") as won2:
                assert won2 is False


class TestRaceShortCircuit:
    """Two coroutines firing simultaneously on the same (account, UID).

    Asserts the second one observes ``in_flight`` and returns
    immediately without paying for the (simulated) fetch + classify.
    """

    @pytest.mark.asyncio
    async def test_concurrent_only_one_proceeds(self):
        state = SimpleNamespace()
        slow_fetches: list[str] = []

        async def cycle(label: str, hold: float) -> str:
            with claim(state, 7, "uid-abc") as won:
                if not won:
                    return "skipped"
                # Simulate the fetch + classify + action delay.
                slow_fetches.append(label)
                await asyncio.sleep(hold)
                return "processed"

        # Fire both simultaneously; the first claims, the second is
        # forced to short-circuit because the slot is held.
        result_a, result_b = await asyncio.gather(
            cycle("a", 0.05),
            cycle("b", 0.05),
        )
        outcomes = sorted([result_a, result_b])
        assert outcomes == ["processed", "skipped"]
        # Only ONE fetch ran — the volatile gate fired.
        assert len(slow_fetches) == 1

    @pytest.mark.asyncio
    async def test_sequential_after_release_succeeds(self):
        """A second cycle AFTER the first releases must NOT be blocked
        — the gate is only a same-instant race guard, not a permanent
        dedup. Persistent dedup belongs to triaged_messages."""
        state = SimpleNamespace()

        async def cycle() -> str:
            with claim(state, 7, "uid-abc") as won:
                if not won:
                    return "skipped"
                await asyncio.sleep(0.01)
                return "processed"

        first = await cycle()
        second = await cycle()
        assert first == "processed"
        assert second == "processed"
