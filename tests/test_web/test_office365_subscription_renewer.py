"""Tests for the Office 365 / Microsoft Graph subscription renewer.

Bundle F-followup F-2: cron-anchored hourly sweep that refreshes any
subscription whose ``expiration_at`` falls within the configured
window (default 24h). Mirrors the role of ``_run_watch_renewal_sweep``
for the Gmail watch table.

Tests drive ``_run_o365_renewal_sweep`` directly (the cron-anchored
loop is just a sleep wrapper) plus the standalone
``_seconds_until_next_tick`` helper. The cron loop's wall-clock
behaviour is implicit in the helper's contract.
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from email_triage.web.db import (
    get_o365_subscription,
    list_auth_events,
    upsert_o365_subscription,
)
from email_triage.web.o365_renewer import (
    _run_o365_renewal_sweep,
    _seconds_until_next_tick,
)


# ---------------------------------------------------------------------------
# Fixtures + helpers
# ---------------------------------------------------------------------------


def _make_account(db, *, account_id=1, email="user@contoso.com"):
    now = datetime.now(timezone.utc).isoformat()
    db.execute(
        "INSERT OR IGNORE INTO users (id, email, name, role, created_at) "
        "VALUES (1, 'seed@test.com', 'Seed', 'user', ?)",
        (now,),
    )
    db.execute(
        "INSERT OR REPLACE INTO email_accounts "
        "(id, user_id, name, provider_type, config_json, is_active, "
        " created_at, updated_at) "
        "VALUES (?, 1, 'Test O365', 'office365', ?, 1, ?, ?)",
        (
            account_id,
            json.dumps({
                "account": email,
                "client_id": "client-fixture-1",
                "tenant_id": "tenant-fixture-1",
            }),
            now, now,
        ),
    )
    db.commit()


@pytest.fixture
def renewer_app(app, db, admin_user):
    """Configure the test app for the renewer."""
    app.state.db = db
    return app


@pytest.fixture
def fake_provider():
    """Office365Provider with renew_subscription + close mocked."""
    from email_triage.providers import office365 as o365_mod
    from email_triage.providers.office365 import Office365Provider

    o365_mod.HAS_MSAL = True
    provider = Office365Provider(
        client_id="client-fixture-1",
        tenant_id="tenant-fixture-1",
        token_cache_path="/tmp/test_renewer_cache.json",
    )
    provider.renew_subscription = AsyncMock()
    provider.close = AsyncMock()
    return provider


# ---------------------------------------------------------------------------
# _seconds_until_next_tick — wall-clock helper
# ---------------------------------------------------------------------------


class TestSecondsUntilNextTick:
    def test_mid_hour_returns_remainder_to_next_hour(self):
        """At 12:30, next tick is 13:00 + jitter — between 1800 and 1860s."""
        now = datetime(2026, 5, 8, 12, 30, 0, tzinfo=timezone.utc)
        s = _seconds_until_next_tick(now=now)
        # 30 min = 1800s; jitter adds 0-60s.
        assert 1800 <= s <= 1860 + 0.001  # tiny float tolerance

    def test_exactly_on_boundary_pushes_to_next_hour(self):
        """At 12:00:00 we don't schedule a 0s sleep — push to 13:00."""
        now = datetime(2026, 5, 8, 12, 0, 0, tzinfo=timezone.utc)
        s = _seconds_until_next_tick(now=now)
        # Should push to 13:00 (3600s) + jitter.
        assert 3600 <= s <= 3660 + 0.001

    def test_minimum_floor(self):
        """Returned value never goes below 1.0s even with extreme inputs."""
        now = datetime(2026, 5, 8, 12, 59, 59, 999999, tzinfo=timezone.utc)
        s = _seconds_until_next_tick(now=now)
        assert s >= 1.0


# ---------------------------------------------------------------------------
# _run_o365_renewal_sweep — happy path + edge cases
# ---------------------------------------------------------------------------


class TestRunO365RenewalSweep:
    @pytest.mark.asyncio
    async def test_renews_expiring_subscription(
        self, renewer_app, db, fake_provider,
    ):
        """A subscription expiring inside the 24h window gets renewed."""
        _make_account(db)
        soon = (
            datetime.now(timezone.utc) + timedelta(hours=12)
        ).isoformat()
        upsert_o365_subscription(
            db, account_id=1,
            subscription_id="subscription-fixture-1",
            expiration_at=soon,
        )

        new_exp = (
            datetime.now(timezone.utc) + timedelta(days=2)
        ).strftime("%Y-%m-%dT%H:%M:%S.0000000Z")
        fake_provider.renew_subscription.return_value = {
            "id": "subscription-fixture-1",
            "expirationDateTime": new_exp,
        }

        with patch(
            "email_triage.web.routers.ui._create_provider_from_account",
            return_value=fake_provider,
        ):
            counters = await _run_o365_renewal_sweep(
                renewer_app, window_hours=24,
            )

        fake_provider.renew_subscription.assert_awaited_once_with(
            "subscription-fixture-1",
        )
        assert counters == {"considered": 1, "renewed": 1, "failed": 0}
        row = get_o365_subscription(db, 1)
        assert row["expiration_at"] == new_exp
        assert row["status"] == "active"
        assert row["error_count"] == 0
        # Audit row written.
        events = list_auth_events(
            db, event_type="o365_subscription_renewed",
        )
        assert len(events) == 1
        assert events[0]["outcome"] == "success"

    @pytest.mark.asyncio
    async def test_skips_subscriptions_outside_window(
        self, renewer_app, db, fake_provider,
    ):
        """A subscription expiring well past the window is NOT touched."""
        _make_account(db)
        far = (
            datetime.now(timezone.utc) + timedelta(days=2)
        ).isoformat()
        upsert_o365_subscription(
            db, account_id=1,
            subscription_id="subscription-fixture-1",
            expiration_at=far,
        )

        with patch(
            "email_triage.web.routers.ui._create_provider_from_account",
            return_value=fake_provider,
        ):
            counters = await _run_o365_renewal_sweep(
                renewer_app, window_hours=24,
            )

        fake_provider.renew_subscription.assert_not_awaited()
        assert counters == {"considered": 0, "renewed": 0, "failed": 0}
        row = get_o365_subscription(db, 1)
        assert row["expiration_at"] == far  # unchanged

    @pytest.mark.asyncio
    async def test_per_row_failure_does_not_halt_sweep(
        self, renewer_app, db, fake_provider,
    ):
        """One subscription's renew failure must not poison the others.

        Two accounts both expiring soon: the first PATCH raises, the
        second succeeds. Counters must show one renewed + one failed,
        and the failed row must be flipped to status='errored'.
        """
        _make_account(db, account_id=1, email="a@contoso.com")
        _make_account(db, account_id=2, email="b@contoso.com")
        soon = (
            datetime.now(timezone.utc) + timedelta(hours=2)
        ).isoformat()
        upsert_o365_subscription(
            db, account_id=1,
            subscription_id="subscription-fixture-1",
            expiration_at=soon,
        )
        upsert_o365_subscription(
            db, account_id=2,
            subscription_id="subscription-fixture-2",
            expiration_at=soon,
        )

        new_exp_b = (
            datetime.now(timezone.utc) + timedelta(days=2)
        ).strftime("%Y-%m-%dT%H:%M:%S.0000000Z")

        async def _renew(sub_id):
            if sub_id == "subscription-fixture-1":
                raise RuntimeError("Graph 503 transient")
            return {"id": sub_id, "expirationDateTime": new_exp_b}

        fake_provider.renew_subscription.side_effect = _renew

        with patch(
            "email_triage.web.routers.ui._create_provider_from_account",
            return_value=fake_provider,
        ):
            counters = await _run_o365_renewal_sweep(
                renewer_app, window_hours=24,
            )

        assert counters["considered"] == 2
        assert counters["renewed"] == 1
        assert counters["failed"] == 1

        row1 = get_o365_subscription(db, 1)
        assert row1["status"] == "errored"
        assert row1["error_count"] == 1
        assert "Graph 503" in (row1["error_last"] or "")

        row2 = get_o365_subscription(db, 2)
        assert row2["status"] == "active"
        assert row2["expiration_at"] == new_exp_b

        # Both renewals get audit rows — success and failure.
        events = list_auth_events(
            db, event_type="o365_subscription_renewed",
        )
        outcomes = sorted(e["outcome"] for e in events)
        assert outcomes == ["failure", "success"]

    @pytest.mark.asyncio
    async def test_concurrency_cap_respected(
        self, renewer_app, db, fake_provider,
    ):
        """With 6 expiring subscriptions and a semaphore size of 4,
        no more than 4 renew_subscription calls should be in flight
        concurrently. Verified via a counter under a sentinel
        AsyncMock that records max-in-flight."""
        # Seed 6 accounts + subscriptions, all in the 24h window.
        soon = (
            datetime.now(timezone.utc) + timedelta(hours=2)
        ).isoformat()
        new_exp = (
            datetime.now(timezone.utc) + timedelta(days=2)
        ).strftime("%Y-%m-%dT%H:%M:%S.0000000Z")
        for i in range(1, 7):
            _make_account(
                db, account_id=i, email=f"user{i}@contoso.com",
            )
            upsert_o365_subscription(
                db, account_id=i,
                subscription_id=f"subscription-fixture-{i}",
                expiration_at=soon,
            )

        # Track concurrent in-flight calls.
        in_flight = 0
        max_in_flight = 0
        lock = asyncio.Lock()

        async def _slow_renew(sub_id):
            nonlocal in_flight, max_in_flight
            async with lock:
                in_flight += 1
                max_in_flight = max(max_in_flight, in_flight)
            # Yield long enough for other tasks to pile up if cap
            # weren't enforced.
            await asyncio.sleep(0.05)
            async with lock:
                in_flight -= 1
            return {"id": sub_id, "expirationDateTime": new_exp}

        fake_provider.renew_subscription.side_effect = _slow_renew

        with patch(
            "email_triage.web.routers.ui._create_provider_from_account",
            return_value=fake_provider,
        ):
            counters = await _run_o365_renewal_sweep(
                renewer_app, window_hours=24,
            )

        assert counters["considered"] == 6
        assert counters["renewed"] == 6
        # Cap is 4 (per _RENEW_CONCURRENCY).
        assert max_in_flight <= 4

    @pytest.mark.asyncio
    async def test_orphaned_subscription_logs_and_skips(
        self, renewer_app, db,
    ):
        """A subscription row whose account_id no longer exists must
        not crash the sweep. (Should be impossible with the FK
        ON DELETE CASCADE, but we belt-and-brace it.)"""
        # Insert an account, seed a subscription, then bypass the FK
        # cascade by deleting the row via a direct query that
        # disables foreign keys for the duration.
        _make_account(db, account_id=1)
        soon = (
            datetime.now(timezone.utc) + timedelta(hours=2)
        ).isoformat()
        upsert_o365_subscription(
            db, account_id=1,
            subscription_id="subscription-fixture-1",
            expiration_at=soon,
        )
        db.execute("PRAGMA foreign_keys = OFF")
        db.execute("DELETE FROM email_accounts WHERE id = 1")
        db.execute("PRAGMA foreign_keys = ON")
        db.commit()

        # No provider needed — the orphan check short-circuits.
        counters = await _run_o365_renewal_sweep(
            renewer_app, window_hours=24,
        )
        # The row was considered but skipped (counted as neither
        # renewed nor failed — silent skip).
        assert counters["considered"] == 1
        assert counters["renewed"] == 0
        assert counters["failed"] == 0

    @pytest.mark.asyncio
    async def test_no_subscriptions_no_op(self, renewer_app, db):
        """Empty table → returns zero counters without instantiating
        a provider."""
        counters = await _run_o365_renewal_sweep(
            renewer_app, window_hours=24,
        )
        assert counters == {"considered": 0, "renewed": 0, "failed": 0}

    @pytest.mark.asyncio
    async def test_window_hours_controls_eligibility(
        self, renewer_app, db, fake_provider,
    ):
        """Tightening the window excludes subscriptions that would
        otherwise have been picked up. Operator knob in action.
        """
        _make_account(db)
        # Expires in 12 hours — picked up by 24h window, NOT by 6h.
        soon = (
            datetime.now(timezone.utc) + timedelta(hours=12)
        ).isoformat()
        upsert_o365_subscription(
            db, account_id=1,
            subscription_id="subscription-fixture-1",
            expiration_at=soon,
        )

        with patch(
            "email_triage.web.routers.ui._create_provider_from_account",
            return_value=fake_provider,
        ):
            tight = await _run_o365_renewal_sweep(
                renewer_app, window_hours=6,
            )
            fake_provider.renew_subscription.assert_not_awaited()

        new_exp = (
            datetime.now(timezone.utc) + timedelta(days=2)
        ).strftime("%Y-%m-%dT%H:%M:%S.0000000Z")
        fake_provider.renew_subscription.return_value = {
            "id": "subscription-fixture-1",
            "expirationDateTime": new_exp,
        }
        with patch(
            "email_triage.web.routers.ui._create_provider_from_account",
            return_value=fake_provider,
        ):
            wide = await _run_o365_renewal_sweep(
                renewer_app, window_hours=24,
            )
            fake_provider.renew_subscription.assert_awaited_once()

        assert tight == {"considered": 0, "renewed": 0, "failed": 0}
        assert wide["considered"] == 1
        assert wide["renewed"] == 1
