"""Panel T round 2 on the AUTOUPD class (2026-10-25): fold 3.

* db S-R2-A1 : draft retrieval fails fast to no examples while the boot update gate is
  armed, instead of waiting up to the 900 s cap (the indexers keep the wait).
* db R2-N1   : the automatic-attempt marker joins the claim's transaction, so a marker
  write that raises cannot strand the install row in ``downloading``.
* DA NOTE-A5 : the deferral after a boot-gate cap timeout is durable and says why
  (``cause: boot-gate-timeout``) with a real count and since.

db S-R2-A2 (the lockout-prefix pin) is ``tests/test_lockout_event_prefix_pin.py``.
"""

from __future__ import annotations

import sys
import time
from types import SimpleNamespace

import pytest

from _embedding_runtime_fixture import make_versioned_prefix

from email_triage import embedding_bits as eb
from email_triage.actions.sent_mail_index import SentMailIndex
from email_triage.web import embedding_update_runner as ru


@pytest.fixture(autouse=True)
def _isolate(monkeypatch):
    monkeypatch.setattr(eb, "_restart_pending", False)
    monkeypatch.setattr(eb, "_AUTO_UPDATE", True)
    monkeypatch.setattr(eb, "_auto_failure", None)
    monkeypatch.setattr(eb, "_auto_deferred", None)
    monkeypatch.setattr(eb, "_boot_gate_armed_at", None)
    monkeypatch.setattr(sys, "path", list(sys.path))
    eb.invalidate_runtime_ready_cache()
    yield
    eb.release_boot_update_gate()
    eb.invalidate_runtime_ready_cache()


def _app(db):
    """A FRESH app state = a fresh process (the per-process dedupe lives on it)."""
    return SimpleNamespace(state=SimpleNamespace(db=db))


# ---------------------------------------------------------------------------
# db S-R2-A1: draft retrieval does not wait on the boot gate
# ---------------------------------------------------------------------------

class _Backend:
    def __init__(self):
        self.calls = 0

    async def embed_text(self, text):
        self.calls += 1
        return [0.0, 1.0]


def _index(backend):
    return SimpleNamespace(
        _hipaa_short_circuit=lambda op: False, _backend=backend, _model="m",
    )


async def test_draft_retrieval_returns_no_examples_at_once_while_the_boot_gate_is_armed(
    monkeypatch,
):
    monkeypatch.setattr(eb, "_boot_gate_armed_at", time.monotonic())
    backend = _Backend()
    start = time.monotonic()
    got = await SentMailIndex.retrieve_similar(_index(backend), "a question")
    assert got == []
    assert time.monotonic() - start < 1.0, "the query path must not wait on the gate"
    assert backend.calls == 0, "nothing is embedded (so nothing loads) while the gate holds"


async def test_draft_retrieval_embeds_once_the_gate_is_released(monkeypatch):
    backend = _Backend()
    monkeypatch.setattr(eb, "_boot_gate_armed_at", time.monotonic())
    eb.release_boot_update_gate()
    try:
        await SentMailIndex.retrieve_similar(_index(backend), "a question")
    except Exception:  # noqa: BLE001 — the stub index has no table; the embed is the point
        pass
    assert backend.calls == 1


# ---------------------------------------------------------------------------
# db R2-N1: the marker and the flip commit together
# ---------------------------------------------------------------------------

async def test_an_automatic_claim_commits_the_marker_with_the_flip(db, tmp_path, monkeypatch):
    make_versioned_prefix(tmp_path, monkeypatch, steps=(False,))
    claim, refused = await ru._claim(_app(db), ru.UpdateActor.system(), None, None)
    assert claim is not None and refused == ""
    assert not db.in_transaction, "the claim must leave nothing uncommitted"
    assert eb.get_install_status(db)["status"] in ru._IN_FLIGHT
    assert ru.read_auto_state(db)["in_flight"], "the marker is committed with the flip"


async def test_a_marker_write_that_raises_does_not_strand_the_row_in_flight(
    db, tmp_path, monkeypatch,
):
    make_versioned_prefix(tmp_path, monkeypatch, steps=(False,))
    before = eb.get_install_status(db).get("status")

    def _boom(conn, *, target):
        raise RuntimeError("settings write failed")

    monkeypatch.setattr(ru, "mark_auto_attempt", _boom)
    with pytest.raises(RuntimeError):
        await ru._claim(_app(db), ru.UpdateActor.system(), None, None)
    assert not db.in_transaction, "the failed claim must roll back, not leave an open txn"
    after = eb.get_install_status(db).get("status")
    assert after == before and after not in ru._IN_FLIGHT, (
        "a raise after the flip must not leave the row in flight with no task to release it"
    )
    assert ru.read_auto_state(db)["in_flight"] is None


async def test_a_flip_that_raises_after_the_marker_rolls_both_back_and_clears_the_cache(
    db, tmp_path, monkeypatch,
):
    """Panel U DA S1 / db S-U-A1: the REAL marker is written, then the flip raises. The
    rollback must take the marker with it, and the settings cache must not keep it."""
    make_versioned_prefix(tmp_path, monkeypatch, steps=(False,))
    before = eb.get_install_status(db).get("status")
    real_mark = ru.mark_auto_attempt
    written = []

    def _mark(conn, *, target):
        real_mark(conn, target=target)
        written.append(ru.read_auto_state(conn)["in_flight"])  # warms the cache too

    def _flip_boom(*a, **kw):
        raise RuntimeError("flip failed")

    monkeypatch.setattr(ru, "mark_auto_attempt", _mark)
    monkeypatch.setattr(ru, "_update_state", _flip_boom)
    with pytest.raises(RuntimeError):
        await ru._claim(_app(db), ru.UpdateActor.system(), None, None)
    assert written and written[0], "the marker really was written before the flip"
    assert not db.in_transaction
    assert eb.get_install_status(db).get("status") == before
    assert ru.read_auto_state(db)["in_flight"] is None, (
        "the rolled-back marker must not survive in the settings cache"
    )


def test_the_deferral_notice_says_the_boot_window_timed_out(tmp_path, monkeypatch):
    """Panel U DA S2: the durable cause reaches the operator's notice."""
    make_versioned_prefix(tmp_path, monkeypatch, steps=(False,))
    eb.set_auto_update_deferred(
        {"target": "1->2", "count": 1, "since": "2026-10-25T19:00:00+00:00",
         "cause": eb.BOOT_GATE_TIMEOUT},
    )
    n = eb.update_notice()
    assert n["kind"] == "auto_deferred"
    assert "boot window" in str(n) and "downloads it again" in str(n)
    eb.set_auto_update_deferred({"target": "1->2", "count": 1, "since": "2026-10-25T19:00:00+00:00"})
    assert "boot window" not in str(eb.update_notice()), "no cause, no timeout sentence"


# ---------------------------------------------------------------------------
# DA NOTE-A5: a boot-gate cap timeout is recorded durably, with its cause
# ---------------------------------------------------------------------------

async def test_the_deferral_after_a_boot_gate_timeout_is_durable_and_says_why(
    db, tmp_path, monkeypatch,
):
    make_versioned_prefix(tmp_path, monkeypatch, steps=(False,))
    status = eb.runtime_status()
    # The cap ended the wait: the gate can only set the in-process mirror.
    monkeypatch.setattr(eb, "_boot_gate_armed_at", time.monotonic() - eb.BOOT_UPDATE_GATE_CAP_SECS)
    assert await eb.wait_for_boot_update_decision() is True
    assert eb.auto_update_deferred()["target"] == eb.BOOT_GATE_TIMEOUT
    # The funnel's deferral at the end of that download is the durable record.
    await ru._note_deferral(_app(db), status)
    deferred = ru.read_auto_state(db)["deferred"]
    assert deferred["cause"] == eb.BOOT_GATE_TIMEOUT
    assert deferred["count"] == 1 and deferred["since"]
    assert deferred["target"] == ru.target_of(status)
    assert eb.auto_update_deferred() == deferred, "the mirror now shows the durable record"
    # The next boot defers for the ordinary reason (the runtime was loaded): the count
    # goes on and the stale cause is cleared.
    eb.set_auto_update_deferred(None)
    await ru._note_deferral(_app(db), status)
    deferred = ru.read_auto_state(db)["deferred"]
    assert deferred["count"] == 2 and "cause" not in deferred
