"""Walk — Digest resend idempotence gate (resend_too_soon) — Actions sketch .

Feature: ``email_triage.actions.digest_resend.resend_too_soon`` — the SSOT
duplicate-suppression gate on the digest DELIVERY path (divergence census
run15 #1, HIGH). A digest must not RE-send within ``MIN_RESEND_INTERVAL_HOURS``
of its last send. Two drifted copies each normalized the OPPOSITE operand, so a
naive-vs-aware subtraction RAISED ``TypeError``; this funnel normalizes BOTH
operands to aware-UTC before subtracting, so neither side can crash.

This walk exercises the gate end-to-end (pure logic — no DB, no network):

  * within the window → suppress (True);
  * past the window → allow (False);
  * no prior send / unparseable timestamp → allow (unknown last-send must not
    block a send);
  * a NAIVE ``last_sent`` vs an AWARE ``now`` → no ``TypeError`` (the run15 #1
    crash class).

On "resend button/route + actor≠owner audit fire" (the sketch's assumed
surface): digest resend is a SCHEDULED-delivery gate, consumed by
``recipient_digest`` / ``digest_filter`` on the send path — there is NO
user-triggered resend button/route in the codebase (grep-verified). The last
test is an HONEST xfail asserting that missing surface (Directive 16 /
DA MF1 discipline), not a cargo-cult skip.
"""

from __future__ import annotations

import inspect
from datetime import datetime, timedelta, timezone

import pytest

pytestmark = pytest.mark.e2e


def test_resend_within_window_suppresses():
    """PRIMARY — a send 1h after the last one is a premature duplicate."""
    from email_triage.actions.digest_resend import resend_too_soon

    now = datetime.now(timezone.utc)
    last = (now - timedelta(hours=1)).isoformat()
    assert resend_too_soon(last, now) is True


def test_resend_after_window_allows():
    """Past ``MIN_RESEND_INTERVAL_HOURS`` (default 23) the send is allowed."""
    from email_triage.actions.digest_resend import resend_too_soon

    now = datetime.now(timezone.utc)
    last = (now - timedelta(hours=25)).isoformat()
    assert resend_too_soon(last, now) is False


def test_resend_no_prior_send_or_unparseable_allows():
    """No recorded prior send — or an unparseable timestamp — must NOT block a
    send (unknown last-send is not a duplicate)."""
    from email_triage.actions.digest_resend import resend_too_soon

    now = datetime.now(timezone.utc)
    assert resend_too_soon(None, now) is False
    assert resend_too_soon("", now) is False
    assert resend_too_soon("not-a-timestamp", now) is False


def test_resend_naive_last_sent_aware_now_no_crash():
    """census run15 #1 — a NAIVE ``last_sent`` vs an AWARE ``now`` must NOT
    raise (aware - naive TypeError). Both operands are normalized to aware-UTC;
    a naive stamp is interpreted as UTC, so 1h-ago still suppresses."""
    from email_triage.actions.digest_resend import resend_too_soon

    now = datetime.now(timezone.utc)
    naive_last = (now.replace(tzinfo=None) - timedelta(hours=1)).isoformat()
    # The assertion is BOTH "no crash" (the call returns) AND the right verdict.
    assert resend_too_soon(naive_last, now) is True


@pytest.mark.xfail(
    reason="digest resend has NO interactive browser button/route — it is a "
    "SCHEDULED-delivery duplicate-suppression gate (resend_too_soon), consumed "
    "by recipient_digest / digest_filter on the send path. The user-triggered "
    "'resend' button + its actor≠owner audit event the sketch assumes are NOT "
    "implemented; this walk asserts the missing surface so the xfail flips to "
    "XPASS if the route is ever added.",
    strict=False,
)
def test_interactive_digest_resend_route_exists():
    """HONEST missing-surface marker — currently fails because no
    ``/digest/resend`` (or equivalent) route is registered on the profile
    router. Names concrete feature-work, not a flaky-CI rationale."""
    profile = __import__(
        "email_triage.web.routers.ui.profile", fromlist=["_"]
    )
    src = inspect.getsource(profile)
    assert (
        "/digest/resend" in src
        or "hits/resend" in src
        or "digest-resend" in src
    ), "no interactive digest-resend route is registered on the profile router"
