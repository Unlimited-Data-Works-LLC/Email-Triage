""" writer queue-full audit-durability BAKE-GATE — unified harness.

Closes the backlog "writer queue-full audit-durability" item (MED, Phase-6
bake-gate). The 4-leg + 5th-HMAC proof previously existed only PIECEMEAL across
``tests/test_db_writer.py`` (genuine ``maxsize=1`` saturation → 503) and
``tests/test_web/test_288_phase3_d3_audit_gap.py`` (gap-row/HMAC via a SYNTHETIC
``sqlite3.OperationalError`` — NOT the real queue-full shed path). This binds all
five into ONE harness driven by GENUINE ``WriterQueueFull`` saturation:

  (a) 503 surfaces                  — web/app.py:1286 `_writer_queue_full_handler`
  (b) gap-event row lands           — db/audit.py:2135 `_write_audit_gap_event`
  (c) gap-on-gap → loud ERROR       — web/db_threadpool.py:227 (db_threadpool path)
  (d) composite ZERO-SILENT-LOSS    — N sheds == N gap rows == N loud-ERROR lines
  (e) HMAC chain continuity         — `audit_gap_events` row_hash recomputed in order

§-anchor (hipaa-sme-2): §164.312(b) Audit Controls PRIMARY +
§164.308(a)(7)(ii)(B)/(C) Disaster-Recovery/Emergency-Mode CO-PRIMARY (the control
holds UNDER backpressure-degraded mode). Companion to N-13/N-14 (same cutover gate).

SATURATION DESIGN NOTE (load-bearing): the worker runs every queued fn UNDER the
 write lock (``_writer.py:188 with lock: fn()``). The shed's gap-row write
(``_record_shed_audit_write`` → ``_write_gap``) ALSO takes that lock
(``db_threadpool.py:205``). So a fn that blocks the worker to keep the queue full
HOLDS the lock, and the gap-row write can only land once the worker is released.
We therefore drive ONE saturated shed at a time: block the worker, fill the slot,
dispatch the shed (it sheds + then parks in the gap-write on the lock), RELEASE
the worker so the gap row lands, then re-saturate for the next shed. N cycles ⇒
N gap rows. (The existing single-shed test got away with one block-and-release;
an N-shed loop cannot hold the lock across all N.)

MUST live under ``tests/test_web/`` so the root ``tests/conftest.py`` autouse
``_provision_audit_chain_hmac_key_for_tests`` fixture is in scope — it seeds the
HMAC key at version 0, so the gap chain stamps ``hash_alg='hmac-sha256-v1'``
(degrades to ``sha256`` without it, which would fail leg (b)'s alg assertion).
"""

from __future__ import annotations

import asyncio
import logging
import sqlite3
import threading

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from email_triage.db import audit as _audit
from email_triage.db._writer import (
    SqliteWriterThread,
    WriterQueueFull,
    _reset_writer_for_tests,
    set_writer,
)
from email_triage.db.audit import audit_emitter, compute_gap_row_hash
from email_triage.web.app import _register_auth_error_handler
from email_triage.web.db import init_db
from email_triage.web.db_threadpool import db_call
from email_triage.web.db_writelock import db_write

_THREADPOOL_LOGGER = "email_triage.web.db_threadpool"


@pytest.fixture(autouse=True)
def _clean_singleton():
    _reset_writer_for_tests()
    yield
    _reset_writer_for_tests()


# A real @db_write @audit_emitter PHI-access emitter. Its body never runs (it
# sheds at the queue boundary); the gap-event records that it WOULD have.
# Production analogue: db/audit.py:1008 record_hipaa_access_event.
@db_write
@audit_emitter
def _record_phi_event(_conn, *, subject):  # pragma: no cover - sheds before body
    return subject


def test_writer_queuefull_503_mapping():
    """Leg (a) — the WriterQueueFull→HTTP mapping, in isolation.

    Genuine saturation through a TestClient is fragile (the client drives its
    own event loop; threading the worker-block Event across that boundary races
    — see the spec caveat). The existing suite, and we, prove the 503 MAPPING
    separately by raising WriterQueueFull in a route (mirrors
    tests/test_db_writer.py:242-251); the legs below prove the GENUINE shed.
    """
    app = FastAPI()
    _register_auth_error_handler(app)

    @app.get("/phi-write")
    async def _phi_write():  # pragma: no cover - exercised via TestClient
        raise WriterQueueFull("genuine saturation (mapping proof)")

    client = TestClient(app, raise_server_exceptions=False)
    resp = client.get("/phi-write")
    assert resp.status_code == 503, f"expected 503, got {resp.status_code}"
    assert resp.headers.get("Retry-After") == "1"


async def _saturate_and_shed(writer, conn, *, subject):
    """Drive exactly ONE genuine queue-full shed of ``_record_phi_event``.

    Blocks the single worker (holding the  lock), fills the one queue slot,
    dispatches the audit-emitter write so it sheds (then parks in the gap-write
    waiting for the lock), then RELEASES the worker so the gap-event row lands.
    Returns once the shed has fully raised ``WriterQueueFull``.
    """
    release = threading.Event()
    entered = threading.Event()

    def _block(_):
        entered.set()
        release.wait(timeout=30.0)  # safety net; released within ~0.1s below
        return "blocking"

    blocking = asyncio.ensure_future(writer.submit_write(_block, None))
    for _ in range(200):
        if entered.is_set():
            break
        await asyncio.sleep(0.02)
    assert entered.is_set(), "worker never picked up the blocking write"

    filler = asyncio.ensure_future(writer.submit_write(lambda: "queued"))
    await asyncio.sleep(0.02)  # let the filler occupy the single slot

    # Dispatch the shed. It sheds immediately (put_nowait → Full), then parks in
    # Layer-1 gap-write awaiting the  lock the blocked worker holds.
    shed = asyncio.ensure_future(db_call(_record_phi_event, conn, subject=subject))
    await asyncio.sleep(0.05)  # let it reach the gap-write-on-lock point

    release.set()  # free the lock → the parked gap-write lands the row
    with pytest.raises(WriterQueueFull):
        await shed

    assert await blocking == "blocking"
    assert await filler == "queued"


async def test_writer_queuefull_audit_durability_under_genuine_saturation(
    monkeypatch, caplog
):
    """Legs (b)+(c)+(d)+(e) under genuine ``WriterQueueFull`` saturation."""
    # Post-N-13 the writer routes whenever one is installed (no env flag); the
    # `set_writer(writer)` below is what makes db_call route+shed here.
    conn = init_db(":memory:")  # real DB → audit_gap_events + HMAC chain exist
    writer = SqliteWriterThread(maxsize=1)
    writer.start()
    set_writer(writer)  # else db_call falls back to the legacy path (no shed)

    N = 5
    try:
        # ── Legs (b)+(d): N genuine sheds → N gap rows + N loud ERRORs, 0 silent loss ──
        with caplog.at_level(logging.ERROR):
            for i in range(N):
                await _saturate_and_shed(writer, conn, subject=f"phi-{i}")

        gap_rows = conn.execute(
            "SELECT exc_type, hash_alg, master_key_version FROM audit_gap_events "
            "WHERE helper_name = ? ORDER BY id",
            ("_record_phi_event",),
        ).fetchall()
        # (b) every shed landed a real gap-event row naming the emitter, tagged
        #     WriterQueueFull and chained under the HMAC key (not degraded sha256).
        assert len(gap_rows) == N, f"expected {N} gap rows, got {len(gap_rows)}"
        assert all(r["exc_type"] == "WriterQueueFull" for r in gap_rows)
        assert all(r["hash_alg"] == "hmac-sha256-v1" for r in gap_rows)
        assert all(r["master_key_version"] == 0 for r in gap_rows)

        # always-on Layer-2 loud ERROR, one per shed, naming the emitter.
        shed_errs = [
            r
            for r in caplog.records
            if "SHED an audit-emitter write" in r.getMessage()
            and "_record_phi_event" in r.getMessage()
        ]
        # (d) ZERO-SILENT-LOSS composite: N sheds == N gap rows == N loud ERRORs.
        #     The emitter body never ran, so 0 real audit rows landed — and that
        #     is exactly the point: the gap-row + loud ERROR are the §164.312(b)
        #     visibility surrogate for the write that was shed, so nothing is lost
        #     silently. N == N == N.
        assert len(shed_errs) == N, f"expected {N} loud-shed ERRORs, got {len(shed_errs)}"

        # ── Leg (e): the audit_gap_events HMAC chain stays continuous across the
        #            induced gap rows (a row that lands but breaks the chain = a
        #            §164.312(c)(1) tamper-evidence hole). Recompute, don't just
        #            link-check, to prove the stored hash IS the HMAC of the row. ──
        full = conn.execute(
            "SELECT ts, helper_name, original_args_redacted, original_args_hash, "
            "exc_type, exc_msg, prev_hash, row_hash, hash_alg, master_key_version "
            "FROM audit_gap_events ORDER BY id",
        ).fetchall()
        assert len(full) == N
        expected_prev = ""
        for idx, r in enumerate(full):
            assert r["prev_hash"] == expected_prev, f"chain break at gap row #{idx}"
            recomputed = compute_gap_row_hash(
                r["prev_hash"],
                r["ts"],
                r["helper_name"],
                r["original_args_redacted"],
                r["original_args_hash"],
                r["exc_type"],
                r["exc_msg"],
                hash_alg=r["hash_alg"],
                master_key_version=r["master_key_version"],
            )
            assert recomputed == r["row_hash"], f"HMAC mismatch at gap row #{idx}"
            expected_prev = r["row_hash"]
        assert len({r["row_hash"] for r in full}) == len(full), "duplicate gap row_hash"

        # ── Leg (c): gap-on-gap — if the gap-row write ITSELF fails, the
        #            db_threadpool path fires a distinct loud ERROR (not silent). ──
        def _gap_raises(*_a, **_k):
            raise sqlite3.OperationalError("simulated gap-write file-lock contention")

        monkeypatch.setattr(_audit, "_write_audit_gap_event", _gap_raises)
        caplog.clear()
        with caplog.at_level(logging.ERROR, logger=_THREADPOOL_LOGGER):
            await _saturate_and_shed(writer, conn, subject="gap-on-gap-probe")
        gap_on_gap = [r for r in caplog.records if "gap-on-gap" in r.getMessage()]
        assert gap_on_gap, "expected a loud gap-on-gap ERROR when the gap write fails"
        assert "helper=_record_phi_event" in gap_on_gap[0].getMessage()
        assert "OperationalError" in gap_on_gap[0].getMessage()
    finally:
        await writer.shutdown()
        conn.close()
