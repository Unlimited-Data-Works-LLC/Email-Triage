""" pin — supervised_interval_loop rotates request_id per tick.

Pre-#390, ``task_supervisor._run_supervised`` bound
``new_request_context`` ONCE per outer factory-restart iteration; a
long-lived interval-loop factory's inner ``while: await sleep(interval):``
loop shared that request_id across every tick. Prod evidence 2026-07-10
(the deploy host): ``sent-mail-capture-loop`` sweeps at 00:56, 02:01, 08:05, 14:03
EDT all logged ``request_id=30a7d3ecac4c`` — same rid, four different
sweeps — breaking log correlation.

Post-#390: ``supervised_interval_loop`` wraps each tick in its own
``new_request_context(f"tick.{name}")`` so per-tick log lines get a
fresh rid; the outer factory-restart rid is preserved via contextvar
nesting.

The pin captures the ``request_id_var`` value inside two consecutive
ticks and asserts they differ. Structural + count-agnostic.
"""

from __future__ import annotations

import asyncio

import pytest

from email_triage.triage_logging import request_id_var
from email_triage.web.task_supervisor import supervised_interval_loop


class TestTickRidRotation:
    """Each tick of ``supervised_interval_loop`` runs under a fresh
    request_id — the fix for  (sticky rid across sent-mail-capture-
    loop sweeps observed on the deploy host 2026-07-10)."""

    @pytest.mark.asyncio
    async def test_two_consecutive_ticks_see_distinct_request_ids(self):
        seen_rids: list[str | None] = []

        async def _tick() -> None:
            seen_rids.append(request_id_var.get(None))
            if len(seen_rids) >= 2:
                # Signal the loop to stop by raising CancelledError so
                # the test doesn't hang on the outer sleep.
                raise asyncio.CancelledError()

        with pytest.raises(asyncio.CancelledError):
            await supervised_interval_loop(
                name="test-loop-390",
                interval_secs=0.0,  # no wait between ticks
                tick=_tick,
                warmup_secs=0.0,
            )

        # We collected exactly the tick this raised on plus (possibly)
        # a prior tick. Because the CancelledError re-raises out of the
        # loop before ``asyncio.sleep`` on the second tick, we should
        # see exactly two rids captured.
        assert len(seen_rids) == 2, (
            f"expected 2 tick rids, got {len(seen_rids)}: {seen_rids}"
        )
        rid1, rid2 = seen_rids
        assert rid1 is not None and rid2 is not None, (
            f"tick body saw None for request_id: {seen_rids}"
        )
        # THE PIN — two ticks MUST see different rids.
        assert rid1 != rid2, (
            f" regression — supervised_interval_loop bound the SAME "
            f"request_id ({rid1}) across two consecutive ticks. The "
            f"per-tick ``new_request_context`` wrap in task_supervisor.py "
            f"has drifted."
        )
