"""Walk — provider-label egress SSOT + the HIPAA label-apply audit row — Actions sketch .

Two surfaces, one feature ("apply a label"):

1. ``email_triage.actions.provider_labels.push_provider_labels`` — the SINGLE
   §164.502(e) egress gate for writing provider-native labels (Gmail label /
   O365 category) UP to the upstream mailbox (divergence census 2026-06-09
   class #5). In HIPAA mode the whole provider write is SKIPPED so a
   PHI-adjacent label string never leaves the perimeter to a mailbox that may
   not be under a BAA. This is the core of the feature and is exercised
   directly (pure async, no DB): apply round-trip, HIPAA skip, whole-provider
   ``NotImplementedError``, and per-label error isolation.

2. ``POST /messages/{account_id}/{message_id}/labels/add`` (web/routers/ui/
   labels.py) — the browser surface that, on a HIPAA account touched by a
   NON-owner actor, fires the PD#14 §164.312(b) ``hipaa_access_events`` row via
   the ``audit_phi_access`` emitter SSOT (never a raw INSERT). The walk drives
   the real route and asserts the audit row lands (Directive 14).

No live provider / no live Ollama: the egress SSOT takes an injected fake
provider; the route runs against the seeded in-memory DB.
"""

from __future__ import annotations

import asyncio

import pytest

pytestmark = pytest.mark.e2e


# ---------------------------------------------------------------------------
# Egress-gate SSOT — pure async, injected fake provider (no DB, no network).
# ---------------------------------------------------------------------------

class _FakeProvider:
    """Records every ``apply_label`` that actually reaches the provider.

    ``self.applied`` is the ground-truth egress log: in HIPAA mode it MUST
    stay empty (nothing leaves the perimeter). ``fail_labels`` raises a
    per-label error (tests per-label isolation); ``not_implemented`` raises
    ``NotImplementedError`` on the first apply (whole-provider skip).
    """

    def __init__(self, *, fail_labels=None, not_implemented: bool = False):
        self.applied: list[tuple[str, str]] = []
        self._fail = set(fail_labels or [])
        self._ni = not_implemented

    async def apply_label(self, message_id: str, label: str) -> None:
        if self._ni:
            raise NotImplementedError("provider has no label support")
        if label in self._fail:
            raise RuntimeError(f"provider rejected {label}")
        self.applied.append((message_id, label))


# Tests are SYNC ``def`` and drive the async product function via
# ``sync_run_in_thread(coro)`` — see _helpers.py::sync_run_in_thread for the
# full "outer loop is reachable on the main thread" story. Neither
# ``asyncio.run(coro)`` nor ``async def test + await`` works reliably in the
# full walk suite (both hit different flavors of the "another loop is
# running" RuntimeError once several fixtures have executed).

from tests.e2e.walk._helpers import goto_or_fail, sync_run_in_thread


def test_push_labels_non_hipaa_applies_all():
    """PRIMARY — a non-HIPAA account egresses every label to the provider."""
    from email_triage.actions.provider_labels import push_provider_labels

    prov = _FakeProvider()
    applied, skipped, errors = sync_run_in_thread(
        push_provider_labels(prov, "msg-1", ["Urgent", "Study"], hipaa=False)
    )
    assert applied == ["Urgent", "Study"], applied
    assert skipped == []
    assert errors == []
    # Ground truth: both labels actually reached the provider.
    assert prov.applied == [("msg-1", "Urgent"), ("msg-1", "Study")]


def test_push_labels_hipaa_skips_whole_provider():
    """§164.502(e) GATE — in HIPAA mode NOTHING is written upstream; every
    name lands in ``skipped`` and the provider egress log stays empty."""
    from email_triage.actions.provider_labels import push_provider_labels

    prov = _FakeProvider()
    applied, skipped, errors = sync_run_in_thread(
        push_provider_labels(prov, "msg-1", ["Urgent", "Study"], hipaa=True)
    )
    assert applied == []
    assert skipped == ["Urgent", "Study"], skipped
    assert errors == []
    # The load-bearing PHI assertion: no label string ever left the perimeter.
    assert prov.applied == [], (
        "HIPAA egress gate leaked: a label reached the provider despite the "
        "§164.502(e) skip."
    )


def test_push_labels_not_implemented_skips_all():
    """FAIL-CLOSED — a provider with no label support skips ALL names and
    stops (the remaining names would raise identically)."""
    from email_triage.actions.provider_labels import push_provider_labels

    prov = _FakeProvider(not_implemented=True)
    applied, skipped, errors = sync_run_in_thread(
        push_provider_labels(prov, "msg-1", ["A", "B"], hipaa=False)
    )
    assert applied == []
    assert set(skipped) == {"A", "B"}, skipped
    assert errors == []


def test_push_labels_per_label_error_isolated():
    """PER-LABEL ISOLATION — one label's failure is captured in ``errors``;
    its siblings still apply (the apply loop continues past a single fault)."""
    from email_triage.actions.provider_labels import push_provider_labels

    prov = _FakeProvider(fail_labels=["B"])
    applied, skipped, errors = sync_run_in_thread(
        push_provider_labels(prov, "msg-1", ["A", "B", "C"], hipaa=False)
    )
    assert "A" in applied and "C" in applied, applied
    assert "B" not in applied
    assert [label for (label, _detail, _exc) in errors] == ["B"], errors


# ---------------------------------------------------------------------------
# Browser surface — the actor≠owner §164.312(b) label-apply audit row.
# ---------------------------------------------------------------------------

@pytest.fixture
def foreign_hipaa_account(e2e_server):
    """Seed a FOREIGN-owned HIPAA account (the admin manages it via role, but
    is not its owner) + a label the apply route can attach.

    The actor≠owner audit gate (PD#14) fires only when the acting user is NOT
    the account owner AND the account is HIPAA-flagged — the seeded e2e admin
    owns both default accounts, so this walk needs a foreign owner.
    """
    from datetime import datetime, timezone

    from email_triage.web.db import create_email_account, create_label

    conn = e2e_server["conn"]
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "INSERT INTO users (email, name, role, created_at) VALUES (?, ?, ?, ?)",
        ("foreign-labels@test.local", "Foreign Labels", "user", now),
    )
    conn.commit()
    other_uid = int(
        conn.execute(
            "SELECT id FROM users WHERE email=?", ("foreign-labels@test.local",)
        ).fetchone()["id"]
    )
    acct_id = create_email_account(
        conn, user_id=other_uid, name="Foreign HIPAA Inbox",
        provider_type="imap",
        config={"push_enabled": False, "poll_enabled": False,
                "account": "foreign@test.local"},
        hipaa=True,
    )
    # Make the label-add route's apply a clean 200 (the label exists).
    try:
        create_label(conn, "walk-egress", "Walk Egress", "#6c757d", other_uid)
    except Exception:  # noqa: BLE001 — a pre-existing label is fine
        pass

    yield {"account_id": acct_id, "owner_id": other_uid}

    # Many tables FK email_accounts.id (some with ON DELETE CASCADE, some
    # without), and the label-add POST route above may have written rows into
    # any of them via product code we don't want to enumerate here. If ANY
    # non-cascading FK-referencing row survives, DELETE FROM email_accounts
    # raises sqlite3.IntegrityError and poisons the sqlite connection state,
    # which cascades into ~14 FAILED tests across the walk suite via
    # `error::RuntimeWarning` on orphaned coroutines.
    #
    # Fix: drop FK enforcement for the teardown span. The test-run DB is
    # ephemeral (per-session e2e uvicorn conn), so leaving a dangling row is
    # harmless; a broken transaction is NOT harmless.
    try:
        conn.execute("PRAGMA foreign_keys=OFF")
        conn.execute("DELETE FROM email_accounts WHERE id=?", (acct_id,))
        conn.execute("DELETE FROM users WHERE id=?", (other_uid,))
        conn.commit()
    finally:
        conn.execute("PRAGMA foreign_keys=ON")


def _audit_count(conn, account_id: int) -> int:
    return int(
        conn.execute(
            "SELECT COUNT(*) AS n FROM hipaa_access_events "
            "WHERE account_id=? AND operation='label_apply'",
            (account_id,),
        ).fetchone()["n"]
    )


def test_label_apply_foreign_hipaa_fires_access_event(
    authed_page, base_url, e2e_server, foreign_hipaa_account,
):
    """PD#14 — a non-owner applying a label to a HIPAA account emits ONE
    ``hipaa_access_events`` (operation=label_apply) row through the
    ``audit_phi_access`` emitter SSOT (never a raw INSERT)."""
    conn = e2e_server["conn"]
    aid = foreign_hipaa_account["account_id"]

    # Prime a session so /api/csrf-token binds to it.
    goto_or_fail(authed_page, f"{base_url}/labels")
    tok = authed_page.request.get(f"{base_url}/api/csrf-token").json()["token"]

    before = _audit_count(conn, aid)

    resp = authed_page.request.post(
        f"{base_url}/messages/{aid}/walk-msg-1/labels/add",
        form={"label_slug": "walk-egress", "csrf_input": tok},
        headers={"X-CSRF-Token": tok},
    )
    # DA-batch3 MF1-sibling fold: distinguish "route not yet implemented" (404 —
    # honest feature-work xfail) from any other non-200 (regression — fail LOUD
    # so a 500/401/403 CANNOT silently mask the PD#14 §164.312(b) audit-fire
    # assertion below). Batch xfail-on-any-non-200 was the anti-pattern the
    # panel flagged as HIPAA-critical: a route regression would convert to
    # SKIPPED-test, silently voiding the audit-gate coverage claim.
    if resp.status == 404:
        pytest.xfail(
            "label-add route not exposed for role-manageable foreign account "
            "(got 404) — feature-work: expose the per-message label-apply "
            "surface."
        )
    assert resp.status == 200, (
        f"label-add returned {resp.status} (expected 200); the PD#14 "
        "audit-fire assertion below is not exercisable — this is a route "
        "regression, NOT missing-feature. Fail LOUD (do not xfail). "
        f"body={resp.text()[:200]!r}"
    )

    after = _audit_count(conn, aid)
    assert after == before + 1, (
        "actor≠owner label_apply on a HIPAA account did NOT emit a "
        "§164.312(b) hipaa_access_events row — the PD#14 audit gate did not "
        f"fire (before={before}, after={after})."
    )
