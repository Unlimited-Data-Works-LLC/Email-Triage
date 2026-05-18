"""Login-attempt rate limiting for the OTP / WebAuthn / dev-keypair surfaces.

Punch-list #92. Counts recent ``auth_events`` failure rows by email
and by client IP within a sliding window; raises ``LoginLocked`` when
the running count tips over the configured threshold. Combined with
the existing ``web/ratelimit.py`` token bucket (which protects the
OpenClaw API, a different surface), the two together cover both
patient brute force (rotate codes against one email) and credential
stuffing (rotate emails behind one IP).

Design notes:

* No new schema. Rolling-window ``COUNT(*)`` against
  ``auth_events`` (which already records every credential-use
  attempt) is the source of truth. A successful login does not
  reset the window — it just falls outside it as time advances.
  Acceptable because the window is short (default 10 min) and a
  legitimate user typing the wrong code 10 times in 10 minutes is
  flagged for the same window length.

* No in-process state. The function is a pure SQLite read; safe
  for multi-process deployments and survives process restart.

* Failure-row writes happen at the call sites — this module
  doesn't know what surfaces look like. ``record_login_failure``
  is the canonical helper.

* ``check_login_allowed`` runs BEFORE the credential check. If
  the threshold has tipped, the actual credential is never
  evaluated — that's the point. Guards against timing-based
  enumeration (was this a real account? is this code valid?) by
  returning the same lockout response regardless of whether the
  email exists.

* ``record_login_lockout`` writes a separate ``login_lockout``
  audit row when the threshold trips, so an admin scanning
  ``auth_events`` can distinguish "user fat-fingered" from "we
  refused the request."

HIPAA §164.312(a)(2)(i) "Unique User Identification" — brute-force
protection is part of the access-control safeguard family. Lockout
events are auditable on the same ``auth_events`` trail as the
underlying failures.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Any


class LoginLocked(Exception):
    """Raised by ``check_login_allowed`` when the threshold has tipped.

    ``scope`` ∈ {``"email"``, ``"ip"``} names which counter
    triggered. ``retry_after_secs`` is the configured window for
    that counter — a conservative wait that guarantees the count
    will have decayed below the threshold by the time the operator
    retries (it might decay sooner if oldest failures fall off
    earlier, but the operator-visible message is the worst case).
    """

    def __init__(self, scope: str, retry_after_secs: int):
        self.scope = scope
        self.retry_after_secs = retry_after_secs
        super().__init__(
            f"login_locked scope={scope} retry_after_secs={retry_after_secs}"
        )


def _auth_tunables(config: Any) -> dict[str, int]:
    """Pull the four #92 tunables off config.auth with safe defaults.

    Defaults match ``AuthConfig`` field defaults so an install that
    has never written its YAML (fresh dev install) still gets the
    protection.
    """
    auth = getattr(config, "auth", None)
    return {
        "per_email_max": int(getattr(auth, "login_per_email_max", 10)),
        "per_email_window_secs": int(getattr(
            auth, "login_per_email_window_secs", 600,
        )),
        "per_ip_max": int(getattr(auth, "login_per_ip_max", 30)),
        "per_ip_window_secs": int(getattr(
            auth, "login_per_ip_window_secs", 600,
        )),
    }


def _count_failures_since(
    db: sqlite3.Connection, *, column: str, value: str, since_iso: str,
) -> int:
    """Count auth_events failure rows for a given column / value since
    a cutoff timestamp. Includes the ``login_lockout`` rows themselves
    (a locked-out attacker who keeps probing should stay locked).
    """
    return int(db.execute(
        f"SELECT COUNT(*) FROM auth_events "
        f"WHERE {column} = ? AND outcome = 'failure' AND ts >= ?",
        (value, since_iso),
    ).fetchone()[0])


def check_login_allowed(
    db: sqlite3.Connection,
    *,
    email: str | None,
    ip: str | None,
    config: Any,
    now: datetime | None = None,
) -> None:
    """Raise ``LoginLocked`` when the guard threshold has tipped.

    Both per-email and per-ip counters are evaluated; the first one
    over its limit raises. ``email=None`` skips the email check
    (passkey discoverable-credential flow doesn't supply email
    upfront — only the IP guard applies). ``ip=None`` skips the IP
    check (rare; e.g. tests with no client info).

    A ``*_max`` of 0 disables the corresponding scope. ``now`` is
    test-injectable; otherwise UTC clock.
    """
    tun = _auth_tunables(config)
    now = now or datetime.now(timezone.utc)

    if email and tun["per_email_max"] > 0:
        cutoff = (now - timedelta(seconds=tun["per_email_window_secs"]))
        count = _count_failures_since(
            db,
            column="email",
            value=email.strip().lower(),
            since_iso=cutoff.isoformat(),
        )
        if count >= tun["per_email_max"]:
            raise LoginLocked(
                scope="email",
                retry_after_secs=tun["per_email_window_secs"],
            )

    if ip and tun["per_ip_max"] > 0:
        cutoff = (now - timedelta(seconds=tun["per_ip_window_secs"]))
        count = _count_failures_since(
            db, column="ip", value=ip, since_iso=cutoff.isoformat(),
        )
        if count >= tun["per_ip_max"]:
            raise LoginLocked(
                scope="ip",
                retry_after_secs=tun["per_ip_window_secs"],
            )


def record_login_failure(
    db: sqlite3.Connection,
    *,
    surface: str,
    email: str | None,
    ip: str | None,
    user_agent: str | None,
    reason: str,
    user_id: int | None = None,
    key_id: int | None = None,
) -> None:
    """Best-effort: write an ``auth_events`` failure row for a login attempt.

    ``surface`` ∈ {``otp``, ``webauthn``, ``passkey``,
    ``dev_keypair``, ``otp_request``}. ``reason`` is a short slug
    (``invalid_code``, ``expired_code``, ``key_revoked``,
    ``signature_invalid``, ``account_disabled``,
    ``email_not_in_allowlist``) that lands in the ``detail``
    column for forensic review. NEVER surface ``reason`` back to
    the caller — it would expose a side-channel (account exists vs.
    code wrong).

    Audit-write failures are swallowed: the running auth flow has
    already rejected the request, and a missing audit row is a
    degraded-but-not-broken condition. The ``audit_failures``
    counter on ``/health`` would be the right place to flag drift.
    """
    try:
        from email_triage.web.db import record_auth_event
        record_auth_event(
            db,
            event_type=f"login_{surface}",
            email=email or "",
            user_id=user_id,
            key_id=key_id,
            ip=ip,
            user_agent=user_agent,
            outcome="failure",
            detail=reason,
        )
    except Exception:
        pass


def record_login_lockout(
    db: sqlite3.Connection,
    *,
    surface: str,
    email: str | None,
    ip: str | None,
    user_agent: str | None,
    scope: str,
    threshold: int,
) -> None:
    """Best-effort: write a ``login_lockout`` audit row.

    Distinct event_type so an admin scanning ``auth_events`` can
    separate "user fat-fingered" from "guard tripped." ``scope``
    + ``threshold`` land in ``detail`` so a forensic reader can
    reconstruct which counter fired.
    """
    try:
        from email_triage.web.db import record_auth_event
        record_auth_event(
            db,
            event_type="login_lockout",
            email=email or "",
            user_id=None,
            key_id=None,
            ip=ip,
            user_agent=user_agent,
            outcome="failure",
            detail=f"surface={surface} scope={scope} threshold={threshold}",
        )
    except Exception:
        pass
