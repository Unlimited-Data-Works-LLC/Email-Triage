""" — live-path watch-fire delivery failure must enqueue a retry.

Before this fix
---------------
``triage_one.py::triage_single_message`` called ``fire_watches_for_message``
and rebuilt ``entry["watches_fired"]`` from the result, but never
inspected ``escalate.ok`` / ``webhook.ok`` for a NON-delivered fire.
A pager/SMS escalation that returned ``{ok: False}`` (a swallowed SMTP
error from ``_send_escalate`` or a 5xx/timeout from ``_post_webhook``)
flowed straight through to a ``status="p"`` triage outcome:

  * the message was NEVER enqueued to ``watcher_retry_queue`` (only
    ``status="e"`` enqueues happened at the live-path call sites);
  * the ``watch_fire_idempotency`` table correctly held NO row
    for it (``_record_watch_fired`` is ``_delivered``-gated);
  * net: a failed live-path escalation was silently dropped — no
    retrier, no idempotency row, no trace beyond a log line.

This fix
--------
``triage_single_message`` now returns the count of non-delivered fires
on :attr:`TriageMessageResult.unretried_watch_failures`, computed with
the SAME ``_delivered`` predicate the recording-gate uses (DRY — the
retry-enqueue check is bit-identical to the "do not record this fire"
check). Each of the 5 live-path call sites in ``app.py`` (IMAP watcher,
Gmail push, O365 push, O365 unified poll, IMAP poll-once) consumes the
count and, if non-zero, calls :func:`enqueue_watch_delivery_retry` —
a thin shim around the existing :func:`enqueue_watcher_retry` that
stamps ``failure_kind='watch_delivery_failure'`` and a PHI-free
synthetic :class:`WatchDeliveryFailed` exception. The drainer
(``_recover_one_retry_row``) re-fires with ``fire_watches=True``; 
idempotency skips the already-delivered watches and re-attempts only
the not-yet-delivered ones.

The drainer's OWN call site (the 6th, ``app.py:3786`` /
``res = await triage_single_message(...)``) deliberately does NOT
consume the count — that would loop: a still-failing delivery in the
re-fire would re-enqueue itself.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone

import pytest

from email_triage.web.db import init_db
from email_triage.web.watch_runner import _delivered
from email_triage.web.watcher_retry import (
    WatchDeliveryFailed,
    enqueue_watch_delivery_retry,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def db() -> sqlite3.Connection:
    conn = init_db(":memory:")
    yield conn
    conn.close()


@pytest.fixture
def _imap_account(db: sqlite3.Connection) -> dict:
    """Insert one IMAP account row + return the dict shape app.py uses.

    The retry-queue enqueue requires a real ``email_accounts`` row
    (FK from ``watcher_retry_queue.account_id``).
    """
    now = datetime.now(timezone.utc).isoformat()
    db.execute(
        "INSERT INTO users (email, name, role, created_at) "
        "VALUES (?, ?, ?, ?)",
        ("op@example.com", "Op", "user", now),
    )
    user_id = db.execute(
        "SELECT id FROM users WHERE email='op@example.com'"
    ).fetchone()["id"]
    db.execute(
        "INSERT INTO email_accounts "
        "(id, user_id, name, provider_type, config_json, hipaa, "
        "created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (
            1, user_id, "acct1", "imap",
            '{"host":"m.example.com","username":"u@example.com"}',
            0, now, now,
        ),
    )
    db.commit()
    return {"id": 1, "provider_type": "imap", "name": "acct1"}


# ---------------------------------------------------------------------------
# Predicate (sanity-pin the borrowed _delivered semantics)
# ---------------------------------------------------------------------------

class TestDeliveredPredicateUsedByCount:
    """Sanity guard — these are the SAME shapes
    :func:`triage_single_message` will use ``_delivered`` to classify.
    A future change to ``_delivered`` that re-defines a config-skip as
    a failure (or vice versa) would silently change the count semantics
    on the live path; pinning the shapes here makes that change
    visible.
    """

    def test_all_success_is_delivered(self):
        assert _delivered({
            "escalate": {"ok": True, "mode": "standard"},
            "webhook": {"ok": True, "status_code": 200},
        }) is True

    def test_escalate_skip_is_delivered(self):
        # Config skip — no SMTP relay / no notify_email. Re-firing
        # would skip identically — NOT a delivery failure.
        assert _delivered({
            "escalate": {"ok": False, "mode": "skipped"},
            "webhook": None,
        }) is True

    def test_escalate_genuine_failure_is_not_delivered(self):
        assert _delivered({
            "escalate": {"ok": False, "mode": "standard"},
            "webhook": None,
        }) is False

    def test_webhook_failure_is_not_delivered(self):
        assert _delivered({
            "escalate": None,
            "webhook": {"ok": False, "status_code": 503},
        }) is False

    def test_both_failed_is_not_delivered(self):
        assert _delivered({
            "escalate": {"ok": False, "mode": "hipaa"},
            "webhook": {"ok": False, "status_code": 500},
        }) is False


# ---------------------------------------------------------------------------
# enqueue_watch_delivery_retry helper
# ---------------------------------------------------------------------------

class TestEnqueueWatchDeliveryRetry:
    """The thin shim that produces a ``watcher_retry_queue`` row keyed
    on the live-path watch-delivery-failure cause.
    """

    def test_imap_enqueue_writes_row_with_failure_kind(
        self, db, _imap_account,
    ):
        rid = enqueue_watch_delivery_retry(
            db,
            account_id=1,
            provider_type="imap",
            failed_count=2,
            total_count=3,
            mailbox="INBOX",
            uid=42,
            uidvalidity=1234567,
        )
        assert isinstance(rid, int) and rid > 0, (
            "enqueue must return the new row id"
        )
        row = db.execute(
            "SELECT * FROM watcher_retry_queue WHERE id=?", (rid,),
        ).fetchone()
        assert row is not None
        assert row["provider_type"] == "imap"
        assert row["mailbox"] == "INBOX"
        assert row["uid"] == 42
        assert row["uidvalidity"] == 1234567
        # New failure_kind — surfaces in operator UI as distinct from
        # ordinary fetch/process retries.
        assert row["failure_kind"] == "watch_delivery_failure"
        # State starts pending so the drainer picks it up.
        assert row["state"] == "pending"
        # The error text is PHI-free — failure count and total only.
        assert "watch fire(s) did not deliver" in (
            row["last_error_msg"] or ""
        )
        # Synthetic class name lands in the error_class column so
        # operators see the cause type in /admin/retry-queue.
        assert row["last_error_class"] == "WatchDeliveryFailed"

    def test_gmail_enqueue_uses_gmail_msg_id(self, db, _imap_account):
        # Even though the account is IMAP in the fixture, the enqueue
        # helper is per-call — it accepts whatever provider_type the
        # caller passes (the live-path call site picks the right one
        # from acct.provider_type). Sanity-pin the addressing flow.
        rid = enqueue_watch_delivery_retry(
            db,
            account_id=1,
            provider_type="gmail_api",
            failed_count=1,
            total_count=1,
            gmail_msg_id="m-deadbeef",
        )
        assert rid is not None and rid > 0
        row = db.execute(
            "SELECT provider_type, gmail_msg_id FROM watcher_retry_queue "
            "WHERE id=?", (rid,),
        ).fetchone()
        # enqueue_watcher_retry normalises gmail_api -> gmail per the
        # v30 schema's addressing-tuple slug set.
        assert row["provider_type"] == "gmail"
        assert row["gmail_msg_id"] == "m-deadbeef"

    def test_o365_enqueue_uses_o365_msg_id(self, db, _imap_account):
        rid = enqueue_watch_delivery_retry(
            db,
            account_id=1,
            provider_type="office365",
            failed_count=1,
            total_count=2,
            o365_msg_id="AQMkA-graph-msg-id",
        )
        assert rid is not None and rid > 0
        row = db.execute(
            "SELECT provider_type, o365_msg_id FROM watcher_retry_queue "
            "WHERE id=?", (rid,),
        ).fetchone()
        assert row["provider_type"] == "office365"
        assert row["o365_msg_id"] == "AQMkA-graph-msg-id"

    def test_error_message_contains_no_phi(
        self, db, _imap_account,
    ):
        # PHI-free contract: the synthetic error MUST NOT carry
        # subject / sender / body text. Only the failure-count
        # arithmetic. This is enforced by the helper constructing the
        # exception itself — the caller cannot inject PHI.
        rid = enqueue_watch_delivery_retry(
            db,
            account_id=1,
            provider_type="imap",
            failed_count=1,
            total_count=1,
            mailbox="INBOX",
            uid=99,
        )
        row = db.execute(
            "SELECT last_error_msg FROM watcher_retry_queue WHERE id=?",
            (rid,),
        ).fetchone()
        msg = row["last_error_msg"] or ""
        # The message structure is fixed; PHI-bearing tokens never
        # have a path into it.
        assert msg.startswith("WatchDeliveryFailed: ") or (
            "1 of 1 watch fire(s)" in msg
        )

    def test_synthetic_exception_class_is_distinct(self):
        # The synthetic exception is used to differentiate this retry
        # cause from ordinary fetch/process exceptions in the operator
        # surface. Future changes that fold it into a generic
        # ``RuntimeError`` would lose that distinction.
        exc = WatchDeliveryFailed("3 of 5 watch fire(s) did not deliver")
        assert type(exc).__name__ == "WatchDeliveryFailed"
        assert "did not deliver" in str(exc)


# ---------------------------------------------------------------------------
# TriageMessageResult — unretried_watch_failures field shape
# ---------------------------------------------------------------------------

class TestTriageMessageResultField:
    """Sanity-pin the field exists with the documented default. The
    live-path call sites read this attribute directly; a rename or
    type change would silently disable the retry path on every
    ingestion route."""

    def test_default_is_zero(self):
        from email_triage.web.triage_one import TriageMessageResult
        r = TriageMessageResult(entry={}, status="p")
        assert r.unretried_watch_failures == 0

    def test_field_accepts_a_count(self):
        from email_triage.web.triage_one import TriageMessageResult
        r = TriageMessageResult(
            entry={}, status="p", unretried_watch_failures=3,
        )
        assert r.unretried_watch_failures == 3


# ---------------------------------------------------------------------------
# call-site wiring — every live-path caller acts on the count
# ---------------------------------------------------------------------------

class TestLivePathCallSiteWiring:
    """ structural pin — every live-path call site that invokes
    ``triage_single_message`` MUST inspect
    ``_res.unretried_watch_failures`` and enqueue on a positive count.
    The drainer (the non-live-path callers) must NOT.

    A future refactor that adds a new ingestion path is forced to wire
    the same check by this guard, exactly as 's ``triage_one.py``
    refactor was forced by the drift the docstring describes.

    Carve-proof by GLOB: the live-path callers no longer
    all live in ``app.py`` — the watcher cluster moved to
    ``web/watcher.py`` and the push/webhook consumers moved to
    ``web/ingestion_push.py``. The guard STRUCTURALLY DISCOVERS the
    surface — globs ``src/email_triage/web/**/*.py`` rather than naming
    a module list — so the next carve (poll-ingestion / sweeper) is
    auto-covered with nothing to append. A hardcoded module roll-call
    re-arms the §164.308(a)(8) dark-guard the moment a future author
    forgets to add a relocated caller's new home; the glob can't rot.
    Counting by marker (``_res =`` live vs bare ``res =`` drainer), not
    by file, per the count-agnostic structural-drift rule
    (``pattern_count_agnostic_structural_drift_catch.md``) — the SAME
    glob discipline as the  ``enqueue_watcher_retry`` pin in
    ``tests/test_retry_failure_kind_all_paths.py``.
    """

    def _web_sources(self):
        """GLOB the whole ``web/`` tree → ``{relative_name: source}``.

        Structural discovery, not a module roll-call: every ``web/*.py``
        is scanned, so a future ingestion module that hosts a
        ``triage_single_message`` caller is covered automatically. The
        marker match (``_res =`` / bare ``res =``) below naturally
        selects only the modules that actually contain a caller.
        """
        from pathlib import Path
        web = (
            Path(__file__).resolve().parents[2]
            / "src" / "email_triage" / "web"
        )
        return {
            p.relative_to(web).as_posix(): p.read_text(encoding="utf-8")
            for p in sorted(web.glob("**/*.py"))
        }

    def test_live_path_callers_check_the_field(self):
        import re

        # Every call site assigning ``_res = await triage_single_message``
        # is a live-path caller. The drainer assigns bare ``res = ...``
        # (no underscore prefix) — a deliberate marker.
        live_calls = []  # (module, match)
        for name, src in self._web_sources().items():
            for m in re.finditer(
                r"_res\s*=\s*await\s+triage_single_message", src
            ):
                live_calls.append((name, src, m))

        # Tripwire: at least ONE live-path caller must exist. An empty
        # result means the marker/glob broke (or every caller was
        # renamed) — fail loud rather than vacuously pass. The invariant
        # below is cardinality-independent: it checks EVERY discovered
        # caller, however many there are.
        assert len(live_calls) >= 1, (
            "found ZERO live-path `_res = await triage_single_message` "
            "callers across the web/ tree — the glob or the `_res=` "
            "marker has drifted; the  retry-wiring guard is now "
            "vacuous. Re-anchor the discovery."
        )

        # Within ~80 lines after each live call, the
        # `unretried_watch_failures` field must be inspected. 80-line
        # window covers the per-message try/except + result-append
        # block that lives between the call and the next message.
        for name, src, m in live_calls:
            start = m.start()
            window = src[start: start + 4000]
            assert "unretried_watch_failures" in window, (
                f"live-path triage_single_message call in {name} "
                f"(around line {src.count(chr(10), 0, start) + 1}) "
                f"does not inspect _res.unretried_watch_failures within "
                f"80 lines. Every live-path caller must enqueue a "
                f"watch-delivery retry on a positive count."
            )
            # And the enqueue helper must be the one invoked — not a
            # hand-rolled enqueue_watcher_retry call, which would lose
            # the consistent failure_kind label.
            assert "enqueue_watch_delivery_retry" in window, (
                f"live-path caller in {name} inspects the count but "
                f"does not invoke `enqueue_watch_delivery_retry`. Use "
                f"the helper so the failure_kind label stays consistent "
                f"across call sites."
            )

    def test_drainer_call_does_NOT_act_on_the_field(self):
        # The drainer assigns ``res = await triage_single_message(...)``
        # (bare ``res``, no underscore). It MUST NOT consume
        # unretried_watch_failures — a still-failing delivery in the
        # re-fire would re-enqueue itself and loop. Scanned across the
        # SAME glob-discovered web/ surface as the live-path pin.
        import re

        drainer_calls = []  # (module, src, match)
        for name, src in self._web_sources().items():
            for m in re.finditer(
                r"(?<![\w_])res\s*=\s*await\s+triage_single_message", src
            ):
                drainer_calls.append((name, src, m))

        assert len(drainer_calls) >= 1, (
            "drainer's call to triage_single_message not found"
        )
        for name, src, m in drainer_calls:
            start = m.start()
            window = src[start: start + 800]
            assert "unretried_watch_failures" not in window, (
                f"drainer caller in {name} (around line "
                f"{src.count(chr(10), 0, start) + 1}) inspects "
                "unretried_watch_failures — that would loop on a "
                "still-failing delivery. Only the live-path callers "
                "(`_res = ...`) act on the count."
            )
