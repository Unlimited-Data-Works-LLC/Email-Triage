"""Walk — RegulatoryClockAction (the clock-START action) — Actions sketch .

Feature: ``email_triage.actions.regulatory_clock.RegulatoryClockAction`` — the
operator-configured ROUTE ACTION that, when mail is routed to a category
carrying ``actions: [clock]``, creates a regulatory-clock CANDIDATE (the
human-driven "propose" step; a human later confirms it on /clocks to arm the
deadline + escalation ladder). The def + responsibility come from the ROUTE
CONFIG — the ONLY sanctioned source of ``responsibility`` per N-96.

This is the ACTION-SIDE walk (create/tick), distinct from Drive-5's UI
dashboard/editor/delete walks. It drives ``execute`` end-to-end against the
seeded in-memory DB (no live provider — the clock action never calls it):

  * a routed mail with a valid ``template`` creates a persisted candidate
    (COMPLETED + a real ``regulatory_clock_instance`` row — the auditable
    §164.316 record the register row is filed against);
  * a RE-run of the SAME message is idempotent (SKIPPED, no duplicate clock —
    the route fires on every matching mail);
  * no ``template`` configured → SKIPPED (nothing to create);
  * no db/account in flow scope → SKIPPED (a bare FlowEngine path can't persist).

``create_clock_candidate_from_route`` runs OFF-loop via ``db_call``; with no
single-writer installed in the lifespan-off e2e harness, ``db_call`` falls
through to the shared-conn RLock path, so ``asyncio.run`` drives it directly.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

pytestmark = pytest.mark.e2e


@pytest.fixture
def clock_ctx(e2e_server):
    """Expose (conn, secrets, account_id) + whether the IRB_AWARENESS system
    def is seeded; scrub only the instances this walk creates."""
    conn = e2e_server["conn"]
    row = conn.execute(
        "SELECT id FROM regulatory_clock_def WHERE code='IRB_AWARENESS' "
        "AND enabled=1 AND config_owner_account_id IS NULL"
    ).fetchone()
    created: list[int] = []

    yield {
        "conn": conn,
        "secrets": e2e_server["app"].state.secrets,
        "account_id": e2e_server["research_account_id"],
        "def_seeded": row is not None,
        "created": created,
    }

    for iid in created:
        conn.execute(
            "DELETE FROM regulatory_clock_event WHERE instance_id=?", (iid,)
        )
        conn.execute(
            "DELETE FROM regulatory_clock_instance WHERE id=?", (iid,)
        )
    conn.commit()


def _message(message_id: str, *, subject="IRB SAE — serious adverse event report",
             body="A serious adverse event occurred at the site."):
    from email_triage.engine.models import EmailMessage

    return EmailMessage(
        message_id=message_id,
        provider="imap",
        sender="pi@lab.test",
        recipients=["coordinator@lab.test"],
        subject=subject,
        body_text=body,
        date=datetime.now(timezone.utc),
    )


def _flow(ctx, message, *, with_context=True):
    from email_triage.engine.models import FlowState, FlowStatus

    bag = (
        {"db": ctx["conn"], "secrets": ctx["secrets"], "account_id": ctx["account_id"]}
        if with_context
        else {}
    )
    return FlowState(
        flow_id=FlowState.new_id(),
        message_id=message.message_id,
        provider="imap",
        status=FlowStatus.ACTING,
        state_bag=bag,
    )


def _classification():
    from email_triage.engine.models import Classification

    return Classification(category="safety-reports", confidence=0.95, reason="e2e walk")


# Helper drives the async action via ``sync_run_in_thread`` (see _helpers.py):
# the e2e session's outer loop makes ``asyncio.run`` (sync) and ``await``
# (async test) both raise "another loop is running" once fixtures have
# executed; a private loop in a fresh thread is the robust shape.
from tests.e2e.walk._helpers import sync_run_in_thread


def _run(action, flow, message, config):
    provider = SimpleNamespace(name="imap")
    return sync_run_in_thread(
        action.execute(flow, message, _classification(), provider, config)
    )


def _instance_count(conn, account_id: int) -> int:
    return int(
        conn.execute(
            "SELECT COUNT(*) AS n FROM regulatory_clock_instance WHERE account_id=?",
            (account_id,),
        ).fetchone()["n"]
    )


def test_clock_action_creates_candidate(clock_ctx):
    """PRIMARY — a routed mail with a valid template creates a persisted clock
    candidate (COMPLETED + a real regulatory_clock_instance row)."""
    from email_triage.actions.regulatory_clock import RegulatoryClockAction
    from email_triage.engine.models import ActionResult

    if not clock_ctx["def_seeded"]:
        pytest.xfail(
            "IRB_AWARENESS system regulatory-clock def not seeded in this e2e "
            "harness — the create path needs a seeded template def (feature-work: "
            "seed the system reg-clock defs at init_db)."
        )

    conn = clock_ctx["conn"]
    msg = _message("<walk-clock-create@test.local>")
    flow = _flow(clock_ctx, msg)
    out = _run(RegulatoryClockAction(), flow, msg, {
        "template": "IRB_AWARENESS", "responsibility": "i_submit",
    })

    assert out.result == ActionResult.COMPLETED, out
    iid = out.data.get("instance_id")
    assert isinstance(iid, int) and iid > 0, out.data
    clock_ctx["created"].append(iid)

    exists = conn.execute(
        "SELECT 1 FROM regulatory_clock_instance WHERE id=?", (iid,)
    ).fetchone()
    assert exists is not None, "action returned an instance_id with no DB row"


def test_clock_action_idempotent_on_rerun(clock_ctx):
    """IDEMPOTENCY — the route fires on every matching mail, so a RE-run of the
    SAME message must NOT spawn a second clock (durable action_idempotency)."""
    from email_triage.actions.regulatory_clock import RegulatoryClockAction
    from email_triage.engine.models import ActionResult

    if not clock_ctx["def_seeded"]:
        pytest.xfail(
            "IRB_AWARENESS system regulatory-clock def not seeded — the "
            "idempotency path needs the create path to succeed first."
        )

    conn = clock_ctx["conn"]
    msg = _message("<walk-clock-idem@test.local>")
    config = {"template": "IRB_AWARENESS", "responsibility": "i_submit"}

    first = _run(RegulatoryClockAction(), _flow(clock_ctx, msg), msg, config)
    assert first.result == ActionResult.COMPLETED, first
    iid = first.data.get("instance_id")
    if isinstance(iid, int):
        clock_ctx["created"].append(iid)

    before = _instance_count(conn, clock_ctx["account_id"])
    second = _run(RegulatoryClockAction(), _flow(clock_ctx, msg), msg, config)
    after = _instance_count(conn, clock_ctx["account_id"])

    assert second.result == ActionResult.SKIPPED, second
    # Idempotency can surface via EITHER shape: (a) the base
    # ``check_idempotent_already_done`` short-circuit sets
    # ``skipped_idempotent=True``, OR (b) the reg-clock action's OWN
    # "already tracked" early-return sets ``reason='already tracked
    # or template disabled'``. Both are valid idempotency shapes; the
    # LOAD-BEARING invariant is ``after == before`` (no duplicate row).
    data = second.data or {}
    idempotent_shape = (
        data.get("skipped_idempotent") is True
        or "already tracked" in str(data.get("reason", "")).lower()
    )
    assert idempotent_shape, (
        f"SKIPPED but neither idempotency shape present in data={data!r}"
    )
    assert after == before, (
        f"re-run created a duplicate clock (before={before}, after={after})"
    )


def test_clock_action_no_template_skips(clock_ctx):
    """No ``template`` configured — nothing to create, cleanly SKIPPED."""
    from email_triage.actions.regulatory_clock import RegulatoryClockAction
    from email_triage.engine.models import ActionResult

    msg = _message("<walk-clock-notmpl@test.local>")
    out = _run(RegulatoryClockAction(), _flow(clock_ctx, msg), msg, {})

    assert out.result == ActionResult.SKIPPED
    assert "template" in (out.data or {}).get("reason", "").lower(), out.data


def test_clock_action_no_db_context_skips(clock_ctx):
    """No db/account in the flow scope (a bare FlowEngine path) — SKIPPED, can't
    persist a clock without a DB + account."""
    from email_triage.actions.regulatory_clock import RegulatoryClockAction
    from email_triage.engine.models import ActionResult

    msg = _message("<walk-clock-nodb@test.local>")
    flow = _flow(clock_ctx, msg, with_context=False)
    out = _run(RegulatoryClockAction(), flow, msg, {"template": "IRB_AWARENESS"})

    assert out.result == ActionResult.SKIPPED
    assert "db" in (out.data or {}).get("reason", "").lower(), out.data
