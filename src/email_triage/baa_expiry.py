"""BAA expiry tracking for admin-curated AI backends (#169 Wave 2-α — I7).

The :func:`ai_backends.id`-keyed catalog (migration v26) tracks a
``baa_certified`` flag + optional ``baa_expires_at`` date per row.
This module owns the *time-based* surface: bucket every BAA-certified
backend by days-until-expiry, drive the admin-page banner severity,
and auto-disable expired backends for any HIPAA-flagged account that
currently selects them.

Buckets
-------
The bucket math is pure (``compute_expiry_buckets``) so tests can pin
the math without needing a daily-task harness:

* **fresh**        — ``baa_expires_at`` more than 30 days out, OR no
                     expiry date set. No surface attention; the
                     selector still allows the backend.
* **expiring_soon**— 8-30 days. Soft banner on admin pages + the
                     daily-health email picks the bucket up so the
                     operator gets a once-a-day push.
* **expiring_urgent**— 1-7 days. Loud banner on EVERY admin page.
* **expired**      — 0 or fewer days. Loud banner + auto-disable for
                     any HIPAA-flagged account that has the backend
                     selected (FK → NULL, fall back to install
                     default; per-account audit row).

Auto-disable on expiry
----------------------
Per the operator decision, BAA expiration is a HIPAA-only gate.
Non-HIPAA accounts may continue to use a backend whose BAA expired
(the certification was never required for them). HIPAA-flagged
accounts (per ``is_account_hipaa(acct)`` — i.e. the per-account flag
OR the install-wide HIPAA mode) have their FK cleared so the
classifier / style-learning path falls through to the install default
(Ollama, local, BAA-not-required).

The auto-disable runs idempotently — re-running on a day where the
sweep already happened (FK is already NULL) is a no-op. Re-running
after the operator picks a new BAA-certified backend just leaves the
new FK alone (the sweep only clears FKs pointing at *expired*
backends).

Surface integration
-------------------
* ``/health/detail`` adds a ``baa_status`` field with the bucket
  counts + the number of HIPAA accounts auto-disabled in this
  process's lifetime (in-memory counter on ``app.state``).
* The admin banner is rendered template-side from
  :func:`build_banner_context` so the banner colour + severity
  string come from one source of truth.
* The daily-health email picks up the ``expiring_soon`` +
  ``expired`` rows via :func:`gather_for_daily_email` and appends a
  "BAA expirations" section.

Background-task pattern
-----------------------
The supervised loop lives in ``web/app.py`` (single source of truth
for every supervised task). This module exposes the worker function
:func:`baa_expiry_daily_sweep` so app.py's lifespan handler can wrap
it in a tick-every-N-hours loop. The sweep itself is fully
synchronous + idempotent — safe to run multiple times per day.
"""

from __future__ import annotations

import logging
import sqlite3
from dataclasses import dataclass
from datetime import date, datetime, timezone
from typing import Any

logger = logging.getLogger("email_triage.baa_expiry")


# ---------------------------------------------------------------------------
# Bucket math (pure, testable)
# ---------------------------------------------------------------------------

# Bucket thresholds (days). expiring_soon = (URGENT_DAYS, SOON_DAYS].
SOON_DAYS: int = 30
URGENT_DAYS: int = 7


@dataclass
class BackendBucketRow:
    """One ``ai_backends`` row, classified by BAA expiry bucket."""

    id: int
    name: str
    type: str
    baa_certified: bool
    baa_expires_at: str | None
    days_until_expiry: int | None
    bucket: str  # "fresh" | "expiring_soon" | "expiring_urgent" | "expired"


def _parse_expiry(date_str: str | None) -> date | None:
    if not date_str:
        return None
    try:
        # Accept either ``YYYY-MM-DD`` (the canonical form documented
        # in the v26 migration) or full ISO datetimes.
        return datetime.fromisoformat(str(date_str)).date()
    except (TypeError, ValueError):
        try:
            return date.fromisoformat(str(date_str)[:10])
        except (TypeError, ValueError):
            return None


def classify_bucket(
    *,
    baa_certified: bool,
    baa_expires_at: str | None,
    today: date | None = None,
) -> tuple[str, int | None]:
    """Classify a backend row into a bucket.

    Returns ``(bucket_name, days_until_expiry)``. ``days_until_expiry``
    is ``None`` when the backend isn't BAA-certified or has no expiry.

    Pure — no DB access. Used by both the sweep + the test pins.
    """
    if not baa_certified:
        return ("fresh", None)
    parsed = _parse_expiry(baa_expires_at)
    if parsed is None:
        # baa_certified=1 with NULL expiry: schema CHECK should prevent
        # this, but be defensive — treat as fresh so we don't ban a
        # backend over a schema invariant we can't fix from this path.
        return ("fresh", None)
    # ``baa_expires_at`` is an operator-entered calendar date (no tz)
    # — the legal document this column tracks expires on a wall-clock
    # date in the operator's local jurisdiction, not at a UTC instant.
    # Anchor "today" to the local date so the bucket math (and the
    # ``days_until_expiry`` integer surfaced to UI) lines up with
    # what the operator sees on their calendar. Using
    # ``datetime.now(timezone.utc).date()`` here previously caused an
    # off-by-one on every host west of UTC after roughly 20:00 local
    # (UTC date had already rolled to tomorrow). The HIPAA-disable
    # boundary (``days < 0``) is unaffected — it's still triggered the
    # moment the local calendar passes the stored expiry date.
    today = today or date.today()
    days = (parsed - today).days
    if days < 0:
        return ("expired", days)
    if days <= URGENT_DAYS:
        return ("expiring_urgent", days)
    if days <= SOON_DAYS:
        return ("expiring_soon", days)
    return ("fresh", days)


def compute_expiry_buckets(
    conn: sqlite3.Connection,
    *,
    today: date | None = None,
) -> dict[str, list[BackendBucketRow]]:
    """Bucket every ``ai_backends`` row by days-until-expiry.

    Returns ``{"fresh": [...], "expiring_soon": [...],
    "expiring_urgent": [...], "expired": [...]}``. The lists are
    ordered by soonest-to-expire first within each bucket so the UI
    can render "X expires in 3 days, Y expires in 12 days" without
    re-sorting.
    """
    rows = conn.execute(
        "SELECT id, name, type, baa_certified, baa_expires_at "
        "FROM ai_backends ORDER BY name"
    ).fetchall()
    buckets: dict[str, list[BackendBucketRow]] = {
        "fresh": [],
        "expiring_soon": [],
        "expiring_urgent": [],
        "expired": [],
    }
    for row in rows:
        rid = row["id"] if hasattr(row, "keys") else row[0]
        name = row["name"] if hasattr(row, "keys") else row[1]
        type_ = row["type"] if hasattr(row, "keys") else row[2]
        bcert = int(
            (row["baa_certified"] if hasattr(row, "keys") else row[3]) or 0,
        )
        bexp = row["baa_expires_at"] if hasattr(row, "keys") else row[4]
        bucket, days = classify_bucket(
            baa_certified=bool(bcert),
            baa_expires_at=bexp,
            today=today,
        )
        buckets[bucket].append(BackendBucketRow(
            id=int(rid),
            name=str(name),
            type=str(type_),
            baa_certified=bool(bcert),
            baa_expires_at=bexp,
            days_until_expiry=days,
            bucket=bucket,
        ))
    # Sort within each bucket: soonest-to-expire first.
    for key in ("expired", "expiring_urgent", "expiring_soon"):
        buckets[key].sort(
            key=lambda r: r.days_until_expiry
            if r.days_until_expiry is not None else 9999,
        )
    return buckets


# ---------------------------------------------------------------------------
# Auto-disable on expiry (HIPAA accounts only)
# ---------------------------------------------------------------------------

def auto_disable_expired_for_hipaa_accounts(
    conn: sqlite3.Connection,
    *,
    today: date | None = None,
    actor_user_id: int | None = None,
) -> list[dict[str, Any]]:
    """Clear ``email_accounts.style_learning_backend_id`` for every
    HIPAA-flagged account whose selected backend has expired.

    Returns the list of disabled rows ``[{"account_id": int,
    "account_name": str, "backend_id": int, "backend_name": str,
    "expired_at": str}, ...]`` for caller-side logging + audit.

    Idempotent: subsequent runs against the same state return an
    empty list (rows whose FK is already NULL skip the sweep).

    Non-HIPAA accounts are deliberately NOT touched — the BAA
    requirement is HIPAA-only. The operator may keep using an
    expired-BAA backend on a non-HIPAA account if they want.

    Per-account audit row uses the existing ``record_hipaa_access_event``
    helper so the BAA-driven downgrade lives in the same audit trail
    as the §164.312(b) PHI-access path.
    """
    from email_triage.web.db import (
        record_hipaa_access_event,
        set_account_style_learning_backend,
    )

    buckets = compute_expiry_buckets(conn, today=today)
    expired_ids = {r.id: r for r in buckets["expired"]}
    if not expired_ids:
        return []

    # JOIN to find accounts pointing at any expired backend AND
    # carrying a per-account HIPAA flag (system HIPAA mode counts via
    # is_account_hipaa on the row — handled below). We need account
    # name + owner email for audit / log clarity.
    rows = conn.execute(
        "SELECT ea.id AS account_id, ea.name AS account_name, "
        "       ea.user_id, ea.hipaa, "
        "       ea.style_learning_backend_id AS backend_id, "
        "       u.email AS owner_email, "
        "       ab.name AS backend_name "
        "FROM email_accounts ea "
        "JOIN ai_backends ab "
        "  ON ab.id = ea.style_learning_backend_id "
        "JOIN users u ON u.id = ea.user_id "
        "WHERE ea.style_learning_backend_id IS NOT NULL"
    ).fetchall()

    disabled: list[dict[str, Any]] = []
    # The HIPAA-mode check is the system-wide flag; per-account is the
    # row's own column. ``is_account_hipaa`` does both — we want any
    # account on a system that's in HIPAA mode to fall under the BAA
    # gate even if the per-account flag happens to be 0.
    from email_triage.triage_logging import is_hipaa_mode
    system_hipaa = is_hipaa_mode()
    for row in rows:
        row_d = dict(row) if hasattr(row, "keys") else None
        if row_d is None:
            continue
        backend_id = int(row_d["backend_id"])
        if backend_id not in expired_ids:
            continue
        is_hipaa = bool(row_d.get("hipaa")) or system_hipaa
        if not is_hipaa:
            continue
        # Clear the FK + record an audit row.
        expired = expired_ids[backend_id]
        set_account_style_learning_backend(
            conn, int(row_d["account_id"]), None,
        )
        disabled.append({
            "account_id": int(row_d["account_id"]),
            "account_name": row_d["account_name"],
            "owner_email": row_d["owner_email"],
            "backend_id": backend_id,
            "backend_name": expired.name,
            "expired_at": expired.baa_expires_at,
        })
        try:
            record_hipaa_access_event(
                conn,
                actor_user_id=actor_user_id,
                account_id=int(row_d["account_id"]),
                operation="style_learning_backend_baa_expired",
                outcome="auto_disabled",
                detail=(
                    f"backend_id={backend_id} "
                    f"name={expired.name!r} "
                    f"expired_at={expired.baa_expires_at}"
                ),
            )
        except Exception as exc:
            logger.warning(
                "BAA-expiry audit row failed: %s",
                exc,
                extra={"_extra": {
                    "account_id": row_d["account_id"],
                    "backend_id": backend_id,
                }},
            )
    if disabled:
        logger.warning(
            "BAA-expired backends auto-disabled on HIPAA accounts",
            extra={"_extra": {"count": len(disabled)}},
        )
    return disabled


# ---------------------------------------------------------------------------
# Daily sweep — called from the supervised loop in web/app.py
# ---------------------------------------------------------------------------

def baa_expiry_daily_sweep(
    conn: sqlite3.Connection,
    *,
    today: date | None = None,
    actor_user_id: int | None = None,
) -> dict[str, Any]:
    """Run the daily sweep + return a summary dict.

    Combines the bucket count + the auto-disable for HIPAA accounts.
    Idempotent. Returns:

    ``{"expiring_soon": int, "expiring_urgent": int, "expired": int,
       "auto_disabled": [<dict>, ...], "swept_at": "<ISO>"}``

    Caller (background loop in app.py) typically logs the summary +
    stamps ``app.state.baa_expiry_status`` with the latest result so
    the admin banner + health endpoint can read it without re-running
    the sweep.
    """
    buckets = compute_expiry_buckets(conn, today=today)
    disabled = auto_disable_expired_for_hipaa_accounts(
        conn, today=today, actor_user_id=actor_user_id,
    )
    return {
        "expiring_soon": len(buckets["expiring_soon"]),
        "expiring_urgent": len(buckets["expiring_urgent"]),
        "expired": len(buckets["expired"]),
        "auto_disabled": disabled,
        "buckets": buckets,
        "swept_at": datetime.now(timezone.utc).isoformat(),
    }


# ---------------------------------------------------------------------------
# Banner / health-endpoint surface helpers
# ---------------------------------------------------------------------------

def build_banner_context(
    conn: sqlite3.Connection,
    *,
    today: date | None = None,
) -> dict[str, Any]:
    """Render data for the admin-page BAA expiry banner.

    Returns ``{"severity": <"silent"|"soft"|"loud">, "expired": [...],
    "expiring_urgent": [...], "expiring_soon": [...]}``. Templates
    branch on ``severity`` for colour + show/hide.
    """
    buckets = compute_expiry_buckets(conn, today=today)
    if buckets["expired"] or buckets["expiring_urgent"]:
        severity = "loud"
    elif buckets["expiring_soon"]:
        severity = "soft"
    else:
        severity = "silent"
    return {
        "severity": severity,
        "expired": buckets["expired"],
        "expiring_urgent": buckets["expiring_urgent"],
        "expiring_soon": buckets["expiring_soon"],
    }


def health_status_block(
    conn: sqlite3.Connection,
    *,
    today: date | None = None,
    auto_disabled_count: int = 0,
) -> dict[str, int]:
    """Return the ``baa_status`` block for ``/health/detail``.

    Shape (per the I7 spec): ``{"expiring_soon": int, "expired": int,
    "expired_hipaa_accounts_disabled": int}``. ``expiring_urgent``
    rolls into ``expiring_soon`` for the health endpoint — Nagios
    only needs the two-bucket signal "renew soon" vs "renew now".
    The admin banner + UI surfaces the three-bucket distinction
    separately.
    """
    buckets = compute_expiry_buckets(conn, today=today)
    return {
        "expiring_soon": (
            len(buckets["expiring_soon"]) + len(buckets["expiring_urgent"])
        ),
        "expired": len(buckets["expired"]),
        "expired_hipaa_accounts_disabled": int(auto_disabled_count),
    }


def banner_from_cached_status(
    cached: dict[str, Any] | None,
) -> dict[str, Any] | None:
    """Derive the banner-shape dict from a cached daily-sweep summary.

    ``cached`` is the dict written to ``app.state.baa_expiry_status`` by
    the hourly sweeper (see ``baa_expiry_daily_sweep``). Returns a dict
    matching the :func:`build_banner_context` shape, or ``None`` when
    the cache is missing / malformed (caller should suppress the
    banner — same outcome as severity="silent" on a clean DB).

    Used by the admin context-injection path so every admin page render
    reads from the in-memory cache rather than re-running the SELECT +
    bucket math. The sweeper refreshes the cache hourly; the worst-case
    staleness is 1 hour, which is well inside the day-resolution
    semantics of the buckets.
    """
    if not isinstance(cached, dict):
        return None
    buckets = cached.get("buckets")
    if not isinstance(buckets, dict):
        return None
    expired = buckets.get("expired") or []
    urgent = buckets.get("expiring_urgent") or []
    soon = buckets.get("expiring_soon") or []
    if expired or urgent:
        severity = "loud"
    elif soon:
        severity = "soft"
    else:
        severity = "silent"
    return {
        "severity": severity,
        "expired": expired,
        "expiring_urgent": urgent,
        "expiring_soon": soon,
    }


def gather_for_daily_email(
    conn: sqlite3.Connection,
    *,
    today: date | None = None,
) -> dict[str, list[BackendBucketRow]] | None:
    """Return the buckets the daily-health email should mention.

    Returns ``None`` when nothing is in scope — caller suppresses the
    "BAA expirations" section entirely on a clean day. Otherwise
    returns ``{"expired": [...], "expiring_urgent": [...],
    "expiring_soon": [...]}`` — same shape as the banner, minus the
    severity decoration.
    """
    buckets = compute_expiry_buckets(conn, today=today)
    if (
        not buckets["expired"]
        and not buckets["expiring_urgent"]
        and not buckets["expiring_soon"]
    ):
        return None
    return {
        "expired": buckets["expired"],
        "expiring_urgent": buckets["expiring_urgent"],
        "expiring_soon": buckets["expiring_soon"],
    }
